#!/usr/bin/env python3
"""Continuous fixed-channel BFI capture; rotating PCAP, independent link series."""
import fcntl
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import struct
import subprocess
import sys
import time

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / 'live'))
import server
from engine import FIELDS, SeriesVariance, decode_line
from feedback import report_kind
from monitoring import MonitoringStore

import policy
import atexit
AUTHORIZATION_LEASE = policy.acquire_lease()
atexit.register(AUTHORIZATION_LEASE.close)
policy.authorization()
CLIENT = policy.settings()['TARGET_CLIENT']
AP = policy.settings()['TARGET_BSSID']
RADIO = policy.radio_config()
BPF = policy.capture_filter()
RESERVE = 10 * 1024**3


class RotatingPcap:
    """Split only on complete packet boundaries, without restarting acquisition."""
    def __init__(self, first, directory, limit=256*1024**2):
        self.file, self.directory, self.limit = first, Path(directory), limit
        self.buffer = bytearray(); self.header = None; self.size = 0; self.part = 1
        self.total = 0; self.packets = 0

    def write(self, data):
        self.buffer.extend(data)
        if self.header is None:
            if len(self.buffer) < 24: return
            self.header = bytes(self.buffer[:24]); del self.buffer[:24]
            magic = self.header[:4]
            if magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1'): self.endian = '<'
            elif magic in (b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\x4d'): self.endian = '>'
            else: raise ValueError('Formato PCAP no reconocido')
            self.file.write(self.header); self.size = 24; self.total = 24
        offset = 0
        while len(self.buffer)-offset >= 16:
            length = struct.unpack_from(self.endian+'I', self.buffer, offset+8)[0]
            if length > 16*1024**2: raise ValueError('Longitud PCAP inválida')
            n = 16+length
            if len(self.buffer)-offset < n: break
            if self.size+n > self.limit and self.size > 24:
                self.file.flush()
                if self.part > 1: self.file.close()
                self.part += 1
                self.file = (self.directory / ('capture-%05d.pcap' % self.part)).open('wb')
                self.file.write(self.header); self.size = 24; self.total += 24
            self.file.write(self.buffer[offset:offset+n]); self.size += n
            self.total += n; self.packets += 1; offset += n
        if offset: del self.buffer[:offset]
        self.file.flush()

    def close(self):
        self.file.flush()
        if self.part > 1: self.file.close()
        if self.buffer: raise ValueError('La captura terminó con un registro PCAP incompleto')


class Processes:
    def __init__(self, owner): self.owner = owner
    def __getattr__(self, name): return getattr(subprocess, name)
    def Popen(self, args, **kwargs):
        args = list(args)
        if args[0] == 'tcpdump':
            args[-1] = BPF
            args[1:1] = ['-Z', self.owner.pw_name]
        if args[0] == 'tshark':
            kwargs.update(user=self.owner.pw_uid, group=self.owner.pw_gid,
                          extra_groups=os.getgrouplist(self.owner.pw_name, self.owner.pw_gid))
        return subprocess.Popen(args, **kwargs)


class ChannelManager(server.Manager):
    def __init__(self, store):
        super().__init__()
        self.store = store; self.links = {}; self.all_bfi = 0; self.unassigned = 0
        self.rotator = None

    def feed(self, raw_file):
        self.rotator = RotatingPcap(raw_file, self.output)
        try:
            while True:
                data = os.read(self.capture.stdout.fileno(), 65536)
                if not data: break
                self.rotator.write(data); self.received_bytes += len(data)
                self.decoder.stdin.write(data); self.decoder.stdin.flush()
        except Exception as exc:
            if not self.stop_event.is_set():
                self.error = 'Flujo de captura: '+str(exc); self.stop_event.set()
        finally:
            try: self.rotator.close()
            except Exception as exc: self.error = self.error or str(exc)
            try: self.decoder.stdin.close()
            except (OSError, ValueError): pass

    def register(self, client, ap):
        key = server.target_key(client, ap, self.radio['frequency'])
        if key in self.links: return self.links[key]
        target = dict(server.identity(client), **self.radio, ap=ap, key=key)
        # Register every observed BFI link; do not impose the interactive UI's 12-link cap.
        with self.store.lock:
            self.store.db.execute('INSERT INTO watches VALUES(?,?,1,?,NULL) ON CONFLICT(key) DO UPDATE SET target=excluded.target,enabled=1',
                                  (key, json.dumps(target), time.time()))
            self.store.db.commit(); self.store._reload()
        name = 'variance.jsonl' if (client,ap)==(CLIENT,AP) else 'variance-'+client.replace(':','')+'-'+ap.replace(':','')+'.jsonl'
        item = dict(target=target, filename=name, bfi=0, errors=0, engine=SeriesVariance())
        with self.cv: self.links[key] = item
        self.manifest()
        return item

    def manifest(self):
        with self.cv:
            server.atomic_json(self.output/'concurrent-targets.json', dict(
                targets=[v['target'] for v in self.links.values()],
                files={k:v['filename'] for k,v in self.links.items()},
                shared_pcap='capture*.pcap', method='Independent SeriesVariance per link, format and direction',
                position='Configured locally; not published'))

    def decode_stream(self, result_file):
        handles = {'variance.jsonl': result_file}
        errors = (self.output/'feedback-errors.jsonl').open('a')
        self.register(CLIENT, AP)
        try:
            for line in self.decoder.stdout:
                parts = line.rstrip('\r\n').split('|')
                try:
                    self.protocol_observations.consume(line)
                    if len(parts) < len(FIELDS)+1: continue
                    core = server.core_line(parts)
                    fields = dict(zip(FIELDS,core.split('|')))
                    if self.origin is None: self.origin = float(parts[0])
                    if parts[1].split(',')[0].lower()==AP and int(parts[13] or '0',0)==8:
                        try: self.ap_rssi=max(float(x) for x in parts[2].split(',') if x)
                        except ValueError: pass
                    if not report_kind(fields): continue
                    tx, rx = parts[1].split(',')[0].lower(), parts[12].split(',')[0].lower()
                    ap = parts[len(FIELDS)].split(',')[0].lower()
                    if not server.unicast(ap) or ap not in (tx,rx):
                        candidates = [a for a in (tx,rx) if a in self.protocol_observations.aps]
                        if len(candidates)!=1:
                            self.unassigned += 1
                            errors.write(json.dumps(dict(ts=parts[0],tx=tx,rx=rx,error='BSSID sin resolver; informe conservado en PCAP'))+'\n'); errors.flush()
                            continue
                        ap = candidates[0]
                    client = rx if tx==ap else tx
                    if ap != AP or client not in policy.client_addresses(): continue
                    item = self.register(client,ap)
                    try:
                        row = decode_line(core,client,ap)
                        if 'psi' not in row: continue
                        point = item['engine'].push(row['ts']-self.origin,row['psi'],row['config'],row.get('phi'))
                        point.update(ts=row['ts'],rssi=row['rssi'],series_id=row['series_id'],feedback=row['feedback'],config=list(row['config']))
                    except (ValueError,KeyError,IndexError) as exc:
                        item['errors'] += 1; item['engine'].reset()
                        errors.write(json.dumps(dict(ts=parts[0],client=client,ap=ap,error=str(exc)))+'\n'); errors.flush()
                        continue
                    if item['filename'] not in handles: handles[item['filename']] = (self.output/item['filename']).open('a')
                    out = handles[item['filename']]; out.write(json.dumps(point,allow_nan=False)+'\n'); out.flush()
                    with self.store.lock:
                        self.store._point(item['target']['key'],self.session,point); self.store.db.commit()
                    with self.cv:
                        item['bfi'] += 1; self.all_bfi += 1
                        if (client,ap)==(CLIENT,AP):
                            self.bfi_count += 1; self.valid_scores += point['quality']=='valid'
                            self.last_point = point; self.last_bfi_clock = time.monotonic()
                            self.points.append(point); self.recent.append(point['t'])
                except (ValueError,KeyError,IndexError) as exc:
                    self.decode_errors += 1
                    errors.write(json.dumps(dict(error=str(exc)))+'\n'); errors.flush()
        except Exception as exc:
            self.error = 'Decodificador multienlace: '+str(exc); self.stop_event.set()
        finally:
            errors.close()
            for name,f in handles.items():
                if name!='variance.jsonl': f.close()


def main():
    if os.geteuid()!=0: raise SystemExit('Usa bash bin/monitor.sh')
    owner = pwd.getpwuid(BASE.stat().st_uid)
    os.setgid(owner.pw_gid); os.umask(0o007)
    state = BASE/'state'; state.mkdir(exist_ok=True); guard = (state/'continuous-monitor.lock').open('a')
    try: fcntl.flock(guard,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError: raise SystemExit('Ya hay otra monitorización continua')
    if shutil.disk_usage(BASE).free < RESERVE: raise SystemExit('Se requieren al menos 10 GiB libres')
    stop = state/'continuous-monitor.stop'; stop.unlink(missing_ok=True)
    server.subprocess = Processes(owner)
    original_atomic = server.atomic_json
    def atomic(path,data):
        if Path(path).name=='session.json':
            data = dict(data,filter=BPF,channel_scope='configured AP and consented clients only',
                        pcap_parts='capture*.pcap',pcap_rotation_bytes=256*1024**2,
                        threshold=None,sha256_scope='capture.pcap only; additional parts retained separately',
                        position='Configured locally; not published')
        original_atomic(path,data)
    server.atomic_json = atomic
    store = MonitoringStore(state/'monitoring.sqlite3')
    store.disable()  # Disable prior radio watches, retaining every historical point.
    manager = ChannelManager(store)
    manager.client,manager.ap,manager.radio = CLIENT,AP,dict(RADIO)
    began = time.time()
    signal.signal(signal.SIGTERM,lambda *_: manager.stop())
    signal.signal(signal.SIGINT,lambda *_: manager.stop())
    manager.start('silueta-multilink',None,server.target_key(CLIENT,AP,RADIO['frequency']))
    def save():
        free = shutil.disk_usage(BASE).free
        with manager.cv:
            elapsed = max(time.time()-began,1)
            rate = manager.received_bytes/elapsed
            record = dict(updated=time.time(),started=began,state=manager.state,
                target=manager.current_target(),session=manager.session,output=str(manager.output),
                bfi=manager.bfi_count,total_bfi=manager.all_bfi,error=manager.error,pid=os.getpid(),
                links={k:{a:b for a,b in v.items() if a!='engine'} for k,v in manager.links.items()},
                unassigned_feedback=manager.unassigned,radio_verification=manager.radio_verification,
                mode='authorized-links-unlimited',stopped=not manager.thread.is_alive(),
                storage=dict(free_bytes=free,raw_bytes=manager.received_bytes,raw_estimated_bytes_day=rate*86400,
                    reserve_bytes=RESERVE,parts=manager.rotator.part if manager.rotator else 0),
                position='Configured locally; not published')
        atomic(state/'continuous-monitor.json',record); os.chown(state/'continuous-monitor.json',owner.pw_uid,owner.pw_gid)
        store.heartbeat(manager.session,dict(manager.radio),began)
        if free<RESERVE and manager.thread.is_alive():
            manager.error='Parada con guardado: quedan menos de 10 GiB libres'; manager.stop()
    print('SILUETA: enlaces autorizados, búsqueda automática del AP al iniciar, sin límite.',flush=True)
    try:
        while manager.thread.is_alive():
            if stop.exists(): manager.stop()
            save(); manager.thread.join(5)
    finally:
        manager.stop(); manager.thread.join(45); save()
        if manager.output and manager.output.exists():
            for p in [manager.output,*manager.output.iterdir()]: os.chown(p,owner.pw_uid,owner.pw_gid)
        guard.close()
    if manager.error: raise SystemExit(manager.error)

if __name__=='__main__': main()
