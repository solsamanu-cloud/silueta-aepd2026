#!/usr/bin/env python3
"""Panel local de BFI en streaming. La captura privilegiada es un proceso separado."""
import argparse
from collections import deque
from datetime import datetime, timezone
import fcntl
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import threading
import time
from urllib.parse import parse_qs, urlsplit

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from engine import SeriesVariance, RollingVariance, decode_line, tshark_command, THRESHOLD, MAX_GAP
from history import read_history
from session_archive import list_sessions, read_session, session_file
from discovery import Discovery, Observations, identity, unicast, target_key, core_line, tshark_discovery_command
import radio
import policy
import autotune
import service_view

CLIENT = policy.settings().get('TARGET_CLIENT', '02:00:00:00:00:01')
ACTIVE = {'starting', 'capturing', 'stopping'}
MAX_HISTORY_POINTS = 12000


def read_settings():
    values = {}
    for line in policy.settings_text().splitlines():
        key, sep, val = line.partition('=')
        if sep and key.strip() in {'IFACE', 'TARGET_BSSID', 'CHANNEL_WIDTH', 'FREQ_CONTROL'}:
            bits = shlex.split(val, comments=True)
            if len(bits) == 1:
                values[key.strip()] = bits[0]
    iface, ap = values.get('IFACE', ''), values.get('TARGET_BSSID', '').lower()
    if not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,32}', iface) or not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', ap):
        raise ValueError('Configura IFACE y TARGET_BSSID en session.env')
    return iface, ap


def stamp():
    return datetime.now(timezone.utc).isoformat()


def atomic_json(path, data):
    temp = path.with_suffix('.tmp')
    temp.write_text(json.dumps(data, ensure_ascii=False, indent=2, allow_nan=False))
    temp.replace(path)


def read_exact(stream, n):
    buf = bytearray()
    while len(buf) < n:
        more = stream.read(n - len(buf))
        if not more:
            if not buf:
                return None
            raise ValueError('PCAP incompleto')
        buf.extend(more)
    return bytes(buf)


def replay_chunks(path, stop, speed):
    """Reproduce paquetes con sus tiempos; no genera datos de radio ficticios."""
    with path.open('rb') as f:
        header = read_exact(f, 24)
        types = {b'\xd4\xc3\xb2\xa1': ('<', 1e6), b'\x4d\x3c\xb2\xa1': ('<', 1e9), b'\xa1\xb2\xc3\xd4': ('>', 1e6), b'\xa1\xb2\x3c\x4d': ('>', 1e9)}
        if not header or header[:4] not in types:
            raise ValueError('La reproducción necesita un PCAP clásico')
        endian, scale = types[header[:4]]
        yield header
        origin = None
        begin = time.monotonic()
        while not stop.is_set():
            rec = read_exact(f, 16)
            if rec is None:
                break
            sec, sub, length, _ = struct.unpack(endian + 'IIII', rec)
            if length > 1024 * 1024:
                raise ValueError('Longitud PCAP no válida')
            body = read_exact(f, length)
            if body is None:
                raise ValueError('Registro PCAP incompleto')
            ts = sec + sub / scale
            if origin is None:
                origin = ts
            if stop.wait(max(0, (ts - origin) / speed - (time.monotonic() - begin))):
                break
            yield rec + body


class Manager:
    def __init__(self, replay=None, speed=1.0):
        self.replay, self.speed = replay, speed
        self.cv = threading.Condition(threading.RLock())
        self.event_log = deque(maxlen=3000)
        self.version = 0
        self.token = secrets.token_urlsafe(32)
        self.thread = None
        self.stop_event = threading.Event()
        self.points, self.markers = deque(maxlen=MAX_HISTORY_POINTS), []
        self.recent = deque()
        self.state = 'idle'
        self.error = None
        self.output = None
        self.session = None
        self.label = 'c01-directo'
        self.duration = None
        self.elapsed = 0.0
        self.last_bfi_clock = None
        self.last_point = None
        self.ap_rssi = None
        self.bfi_count = self.decode_errors = self.received_bytes = 0
        self.valid_scores = 0
        self.engine = SeriesVariance()
        self.origin = None
        self.clock_start = None
        self.capture = self.decoder = None
        self.completed = False
        self.capture_lock = None
        self.client = CLIENT
        self.ap = read_settings()[1]
        self.radio = policy.radio_config()
        self.radio_verification = None
        self.radio_detection = None
        self.switching = False
        self.switch_cancel = False
        self.discovery = Discovery(self.emit, read_settings,
                                   BASE/'state/live-discovery.json' if replay is None else None)
        self.protocol_observations=Observations(self.ap, policy.client_addresses())
        self.restored_protocol=None
        if self.replay is None:
            self.restore_latest()

    def configure_authorization(self, data=None, revoke=False):
        with self.cv:
            if self.replay:
                raise ValueError('La demo no configura ni autoriza la radio')
            if self.state in ACTIVE or self.switching or self.discovery.snapshot()['scanning'] or (self.thread and self.thread.is_alive()):
                raise ValueError('Detén la captura o el barrido antes de cambiar la autorización')
            if service_view.protected(BASE):
                raise ValueError('Monitorización activa: autorización protegida')
            if revoke:
                policy.revoke()
            else:
                policy.save(data)
            self.client = policy.settings()['TARGET_CLIENT']
            self.ap = policy.settings()['TARGET_BSSID']
            self.radio = policy.radio_config()
            self.emit('authorization', policy.status())

    def restore_latest(self):
        """Mostrar la última captura cerrada tras reiniciar; nunca reanudar la radio."""
        folder = BASE / 'captures/live'
        if not folder.exists():
            return
        for manifest in sorted(folder.glob('*/session.json'), key=lambda p: p.stat().st_mtime, reverse=True):
            try:
                info = json.loads(manifest.read_text())
                if info.get('mode') != 'live' or not info.get('ended'):
                    continue
                with (manifest.parent / 'variance.jsonl').open() as stream:
                    points = deque((json.loads(line) for line in stream if line.strip()), maxlen=MAX_HISTORY_POINTS)
                markers = json.loads((manifest.parent / 'markers.json').read_text())
                self.output = manifest.parent
                self.session = manifest.parent.name
                self.label = re.sub(r'-\d{8}T\d{6}-[0-9a-f]{4}$', '', self.session)
                self.points, self.markers = points, markers
                self.last_point = points[-1] if points else None
                self.elapsed = info.get('elapsed_s', self.last_point['t'] if self.last_point else 0)
                self.duration = info.get('duration_s')
                self.client = info.get('client', CLIENT)
                self.ap = info.get('ap', self.ap)
                self.radio = info.get('radio', self.radio)
                self.bfi_count = info.get('BFI', len(points))
                self.valid_scores = info.get('valid_scores', 0)
                self.decode_errors = info.get('decode_errors', 0)
                self.completed = info.get('completed', False)
                self.state = info.get('state', 'finished')
                self.error = info.get('error')
                self.received_bytes = (self.output / 'capture.pcap').stat().st_size
                self.restored_protocol=info.get('protocol')
                return
            except (OSError, ValueError, KeyError, TypeError):
                continue

    def emit(self, kind, payload):
        with self.cv:
            self.version += 1
            self.event_log.append((self.version, kind, payload))
            self.cv.notify_all()

    def metrics(self):
        now = time.monotonic()
        age = None if self.last_bfi_clock is None else (now - self.last_bfi_clock) * self.speed
        if self.state not in ACTIVE:
            age = None if self.last_point is None else max(0, self.elapsed - self.last_point['t'])
        while self.recent and self.elapsed - self.recent[0] > 10:
            self.recent.popleft()
        denominator = min(10.0, max(1.0, self.elapsed))
        quality = self.last_point['quality'] if self.last_point else 'warming_up'
        if self.state in ACTIVE and (age is not None and age > MAX_GAP or age is None and self.elapsed > 6):
            quality = 'no_bfi'
        variance = self.last_point['variance'] if self.last_point else None
        return {'elapsed': self.elapsed, 'bfi': self.bfi_count, 'rate': len(self.recent) / denominator, 'last_age': age, 'quality': quality,
                'variance_phi': self.last_point.get('variance_phi') if self.last_point else None,
                'variance': variance, 'rssi': (self.protocol_details() or {}).get('client_rssi'),
                'ap_rssi': self.ap_rssi, 'decode_errors': self.decode_errors, 'bytes': self.received_bytes,
                'protocol':self.protocol_details(), 'radio_verification':self.radio_verification}

    def protocol_details(self):
        return self.protocol_observations.details(self.client,self.ap) or self.restored_protocol

    def snapshot(self):
        with self.cv:
            return {'version': self.version, 'state': self.state, 'error': self.error, 'session': self.session, 'label': self.label, 'duration': self.duration,
                    'replay': self.replay is not None, 'speed': self.speed, 'threshold': THRESHOLD, 'points': list(self.points),
                    'markers': list(self.markers), 'metrics': self.metrics(), 'csrf': self.token, 'output': str(self.output) if self.output else None,
                    'complete': self.completed, 'iface': read_settings()[0], 'history_limit': MAX_HISTORY_POINTS,
                    'history_truncated': self.bfi_count > len(self.points), 'client': self.current_target(),
                    'discovery': self.discovery.snapshot(), 'switching': self.switching,
                    'authorization': policy.status(), 'radio_detection':self.radio_detection, 'threshold_client': CLIENT, 'threshold_ap':read_settings()[1], 'ap': self.ap, 'radio': self.radio}

    def start(self, label, duration, client=None, _switch=False):
        target = self.resolve_target(client or self.current_target()['key'])
        if not self.replay: policy.require_target(target)
        if not isinstance(label, str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,59}', label):
            raise ValueError('Usa un nombre de 1–60 letras, números, guiones o guiones bajos')
        if duration is not None and (isinstance(duration, bool) or not isinstance(duration, int) or not 10 <= duration <= 7200):
            raise ValueError('Elige Sin límite o una duración entre 10 y 7200 segundos')
        with self.cv:
            if self.switching and not _switch:
                raise ValueError('Se está cambiando de cliente')
            if self.discovery.snapshot()['scanning']:
                raise ValueError('Espera a que termine la actualización de clientes')
            if self.state in ACTIVE or self.thread and self.thread.is_alive():
                raise ValueError('Ya hay una captura en curso')
            self.client, self.ap = target['mac'],target['ap']
            self.radio = {k:target[k] for k in ('frequency','channel','width','center')}
            self.radio_verification = None
            self.radio_detection = None
            self.detected_ap = None
            self.state, self.error, self.completed = 'starting', None, False
            self.duration = duration
            self.label = label
            self.session = label + '-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S') + '-' + secrets.token_hex(2)
            self.output = BASE / 'captures' / 'live' / self.session
            self.points, self.markers, self.recent = deque(maxlen=MAX_HISTORY_POINTS), [], deque()
            self.protocol_observations=Observations(self.ap, policy.client_addresses());self.restored_protocol=None
            self.engine = SeriesVariance()
            self.origin = self.last_point = self.last_bfi_clock = self.ap_rssi = None
            self.elapsed = 0.0
            self.bfi_count = self.decode_errors = self.received_bytes = 0
            self.valid_scores = 0
            self.stop_event = threading.Event()
            self.emit('reset', self.snapshot())
            self.thread = threading.Thread(target=self.run, daemon=True)
            self.thread.start()

    def stop(self):
        with self.cv:
            if self.switching:self.switch_cancel = True
            if self.discovery.snapshot()['scanning']:self.discovery.cancel.set()
            if self.state in ACTIVE:
                self.state = 'stopping'
                self.stop_event.set()
                self.emit('status', {'state': self.state})

    def current_target(self):
        return {**identity(self.client),**self.radio,'ap':self.ap,
                'key':target_key(self.client,self.ap,self.radio['frequency'])}

    def resolve_target(self, value):
        if not isinstance(value,str):raise ValueError('Selecciona un cliente observado')
        value=value.lower()
        observed=self.discovery.snapshot()['clients']
        observed += [{**identity(mac), **policy.radio_config(), 'ap':policy.settings()['TARGET_BSSID'],
                      'key':target_key(mac,policy.settings()['TARGET_BSSID'],policy.radio_config()['frequency'])}
                     for mac in policy.client_addresses() if not any(p.get('mac')==mac and p.get('ap')==policy.settings()['TARGET_BSSID'] for p in observed)]
        for item in observed:
            if value==item.get('key'):
                return self.checked_target(item)
        current=self.current_target()
        if value==current['key']:return self.checked_target(current)
        matches=[p for p in observed if p['mac']==value]
        if not matches and value==current['mac']:return self.checked_target(current)
        if len(matches)!=1:raise ValueError('Actualiza el listado y selecciona el enlace y canal del cliente')
        item=dict(matches[0])
        if not unicast(item['mac']) or not unicast(item['ap']) or item['mac']==item['ap']:
            raise ValueError('Enlace no válido')
        return self.checked_target(item)

    def checked_target(self, item):
        if not unicast(item.get('mac')) or not unicast(item.get('ap')) or item['mac']==item['ap']:
            raise ValueError('Enlace no válido')
        normalized={**item, **radio.validate_target(item)}
        # A legacy frame heard on a secondary 20 MHz channel does not establish
        # the AP primary channel. Prefer recent advertised operation for this BSSID.
        if item.get('channel_source')=='receiver_only':
            candidates=[]
            for peer in self.discovery.snapshot()['clients']:
                if peer.get('ap')!=item['ap'] or peer.get('channel_source')!='AP beacon / probe response':continue
                ts=(peer.get('advertised') or {}).get('ts',0)
                if not isinstance(ts,(int,float)) or not 0<=time.time()-ts<=3600:continue
                try:config=radio.validate_target(peer)
                except ValueError:continue
                # Only use operation covering the frequency actually observed.
                if abs(normalized['frequency']-config['center'])>config['width']/2-10:continue
                candidates.append((ts,config))
            if candidates:
                ts,config=max(candidates,key=lambda candidate:candidate[0])
                normalized.update(config,channel_source='AP beacon / probe response',
                                  tuning_resolution={'observed_frequency':item['frequency'],
                                                     'ap_beacon_ts':ts,'reason':'AP primary channel from beacon'})
        normalized['key']=target_key(normalized['mac'],normalized['ap'],normalized['frequency'])
        return normalized

    def validate_client(self, value):return self.resolve_target(value)['mac']

    def refresh_clients(self):
        policy.authorization()
        with self.cv:
            if self.switching or self.discovery.snapshot()['scanning']:raise ValueError('Espera a que termine la operación actual')
            self.switching,self.switch_cancel=True,False
            previous=self.thread
            if self.state in ACTIVE:self.state='stopping';self.stop_event.set()
            self.emit('status',{'state':self.state,'switching':True})
        try:
            if previous:previous.join(timeout=25)
            with self.cv:
                if previous and previous.is_alive():raise ValueError('La sesión anterior todavía se está guardando')
                if not self.switch_cancel:self.discovery.start()
        finally:
            with self.cv:
                self.switching=False;self.emit('status',{'state':self.state,'switching':False})

    def select_client(self, client):
        target = self.resolve_target(client)
        if not self.replay: policy.require_target(target)
        with self.cv:
            if self.switching:raise ValueError('Ya se está cambiando de cliente')
            if self.discovery.snapshot()['scanning']:raise ValueError('Espera a que termine el barrido')
            same = target.get('key') == self.current_target()['key'] and all(target[k]==self.radio[k] for k in ('frequency','channel','width','center'))
            if same and self.state=='starting':return
            if same and self.state=='capturing':
                if self.replay:return
                try:
                    self.check_radio(read_settings()[0])
                    return
                except ValueError:pass  # Save and restart if the actual radio drifted.
            self.switching, self.switch_cancel = True, False
            duration = self.duration if self.state in ACTIVE else None
            old_thread = self.thread
            if self.state in ACTIVE:
                self.state = 'stopping';self.stop_event.set()
            self.emit('status', {'state': self.state, 'switching': True})
        try:
            if old_thread and old_thread.is_alive():old_thread.join(timeout=25)
            with self.cv:
                if old_thread and old_thread.is_alive():raise ValueError('La captura anterior sigue guardándose; espera a que termine')
                if self.switch_cancel:return
                item = identity(target['mac'])
                label = (item['id'].lower() or 'cliente-' + target['mac'].replace(':', '')[-6:]) + '-directo'
                self.start(label, duration, client, _switch=True)
        finally:
            with self.cv:
                self.switching = False
                self.emit('status', {'state': self.state, 'switching': False})

    def mark(self, kind):
        if kind not in {'movement', 'still'}:
            raise ValueError('Marca desconocida')
        with self.cv:
            if self.state != 'capturing':
                raise ValueError('Inicia una captura para guardar marcas')
            item = {'t': self.elapsed, 'kind': kind, 'utc': stamp(), 'source': 'botón manual del navegador'}
            self.markers.append(item)
            atomic_json(self.output / 'markers.json', self.markers)
            self.emit('marker', item)

    def preflight(self, iface):
        if self.replay:
            return
        # Bloqueo entre instancias de esta app, además de comprobar capturadores externos.
        (BASE / 'state').mkdir(exist_ok=True)
        self.capture_lock = (BASE / 'state/live-app.lock').open('a')
        try:
            fcntl.flock(self.capture_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('Otra instancia está capturando con la ALFA')
        info = subprocess.run(['iw', 'dev', iface, 'info'], text=True, capture_output=True)
        if info.returncode or 'type monitor' not in info.stdout:
            raise ValueError('La ALFA debe estar en monitor. Ejecuta sudo .venv/bin/python bin/monitor-mode.py')
        for entry in Path('/proc').iterdir():
            if not entry.name.isdigit():
                continue
            try:
                args = (entry / 'cmdline').read_bytes().split(b'\0')
                if args and Path(os.fsdecode(args[0])).name in {'tcpdump', 'dumpcap'} and os.fsencode(iface) in args:
                    raise ValueError('Ya hay otra captura usando la ALFA; termínala antes de iniciar esta')
            except (PermissionError, FileNotFoundError, ProcessLookupError):
                pass
        active = subprocess.run(['systemctl', 'list-units', '--state=active', '--no-legend', 'wifi-sensing-dia-normal-*.service'], text=True, capture_output=True)
        if active.returncode == 0 and active.stdout.strip():
            raise ValueError('Hay una monitorización diaria activa o programada; no se inicia una captura simultánea')
        if os.geteuid() != 0:
            check = subprocess.run(['sudo', '-n', '-v'], capture_output=True)
            if check.returncode:
                raise ValueError('Falta permiso de captura. Arranca desde el terminal con bash bin/gui.sh; sudo pedirá la contraseña allí')
        if shutil.disk_usage(BASE).free < 512 * 1024 ** 2:
            raise ValueError('Quedan menos de 512 MiB de espacio libre')
        if policy.authorization().get('radio_mode') == 'auto':
            def progress(message):
                self.radio_detection = message
                self.emit('status',dict(state='starting',radio_detection=message))
            found = autotune.discover(iface,self.stop_event,progress)
            self.radio = {k:found[k] for k in ('frequency','channel','width','center')}
            self.detected_ap = found
            autotune.remember(found)
            self.radio_detection = 'Red detectada: '+(found.get('ssid') or 'SSID oculto')
        # Every start explicitly tunes, even when the previous session used this channel.
        actual=radio.tune(iface,self.radio)
        self.radio_verification={'actual':actual,'checked_at':stamp(),'ok':True}

    def check_radio(self, iface):
        try:
            actual=radio.verify(iface,self.radio)
            self.radio_verification={'actual':actual,'checked_at':stamp(),'ok':True}
        except (ValueError,OSError,subprocess.TimeoutExpired) as exc:
            self.radio_verification={'checked_at':stamp(),'ok':False,'error':str(exc)}
            raise ValueError('Captura detenida: no se puede confirmar el canal de la ALFA. '+str(exc)) from exc

    def decode_stream(self, result_file):
        try:
            for line in self.decoder.stdout:
                try:
                    self.protocol_observations.consume(line)
                    row = decode_line(core_line(line.rstrip('\r\n').split('|')), self.client, self.ap)
                    with self.cv:
                        if self.origin is None:
                            self.origin = row['ts']
                        if row['ap_rssi'] is not None:
                            self.ap_rssi = row['ap_rssi']
                        t = row['ts'] - self.origin
                        if 'psi' not in row or t < 0 or (self.duration is not None and t >= self.duration):
                            continue
                        point = self.engine.push(t, row['psi'], row['config'], row.get('phi'))
                        point.update(rssi=row['rssi'], ts=row['ts'], config=list(row['config']),series_id=row['series_id'],feedback=row['feedback'])
                        self.elapsed = max(self.elapsed, t)
                        self.last_point = point
                        self.last_bfi_clock = time.monotonic()
                        self.points.append(point)
                        self.recent.append(t)
                        self.bfi_count += 1
                        self.valid_scores += point['quality']=='valid'
                        result_file.write(json.dumps(point, allow_nan=False) + '\n')
                        result_file.flush()
                        self.emit('point', {'point': point, 'metrics': self.metrics()})
                except (ValueError, KeyError, IndexError) as exc:
                    with self.cv:
                        self.decode_errors += 1
                        self.engine.reset()
                        self.engine.segment_start = self.elapsed
                        self.emit('warning', {'message': 'Informe descartado: ' + str(exc)})
        except Exception as exc:
            self.error = 'Decodificador: ' + str(exc)
            self.stop_event.set()

    def feed(self, raw_file):
        try:
            if self.replay:
                chunks = replay_chunks(self.replay, self.stop_event, self.speed)
            else:
                chunks = iter(lambda: os.read(self.capture.stdout.fileno(), 65536), b'')
            for data in chunks:
                raw_file.write(data)
                raw_file.flush()
                self.received_bytes += len(data)
                self.decoder.stdin.write(data)
                self.decoder.stdin.flush()
        except Exception as exc:
            if not self.stop_event.is_set():
                self.error = 'Flujo de captura: ' + str(exc)
                self.stop_event.set()
        finally:
            try:
                self.decoder.stdin.close()
            except (OSError, ValueError):
                pass

    def run(self):
        start = stamp()
        feed_thread = decode_thread = None
        files = []
        finished_by = 'error'
        authorization_lease = None
        try:
            if not self.replay: authorization_lease = policy.acquire_lease()
            iface, _ = read_settings()
            policy.require_target(self.current_target()) if not self.replay else None
            self.preflight(iface)
            if self.stop_event.is_set():
                finished_by='stopped'
                return
            self.output.mkdir(parents=True, mode=0o750)
            bpf = policy.capture_filter([self.client]) if not self.replay else 'synthetic replay; no radio'
            self.plan = {'session': self.session, 'started': start, 'interface': iface, 'client': self.client, 'client_identity': identity(self.client), 'ap': self.ap, 'radio':self.radio,'duration_s': self.duration,
                         'filter': bpf, 'mode': 'replay' if self.replay else 'live', 'threshold': THRESHOLD, 'threshold_reference_client': CLIENT,
                         'stop_mode': 'manual' if self.duration is None else 'timed',
                         'method': 'Un punto por informe decodificado. Varianza causal 6 s por formato y sentido. Una muestra: 0 descriptivo, no evidencia de quietud. Calidad marcada por >=4 informes y hueco <=2.8 s, sin ocultar puntos. Sin interpolación.',
                         'origin': 'first retained PCAP packet', 'source_pcap': str(self.replay) if self.replay else None,
                         'radio_verification':self.radio_verification,
                         'authorization': policy.authorization() if not self.replay else None,
                         'detected_ap': getattr(self,'detected_ap',None),
                         'authorization_sha256': policy.fingerprint(policy.authorization()) if not self.replay else None}
            atomic_json(self.output / 'session.json', self.plan)
            atomic_json(self.output / 'markers.json', [])
            raw = (self.output / 'capture.pcap').open('wb');files.append(raw)
            results = (self.output / 'variance.jsonl').open('w');files.append(results)
            caperr = (self.output / 'capture.log').open('w+');files.append(caperr)
            decerr = (self.output / 'decoder.log').open('w+');files.append(decerr)
            self.decoder = subprocess.Popen(tshark_discovery_command('-'), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=decerr, text=False, start_new_session=True)
            # Solo stdout se interpreta como texto; stdin mantiene el PCAP binario.
            import io
            self.decoder.stdout = io.TextIOWrapper(self.decoder.stdout, encoding='utf-8')
            if not self.replay:
                command = policy.capture_command(iface, [self.client])
                if os.geteuid() != 0:
                    command = ['sudo', '-n', '--'] + command
                # Conserva el terminal para reutilizar la autorización sudo del lanzador.
                # sudo transmite las señales al capturador; no se mata el grupo del terminal.
                self.capture = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=caperr)
            self.clock_start = time.monotonic()
            with self.cv:
                self.state = 'capturing'
                self.emit('status', {'state': self.state, 'radio':self.radio, 'client':self.current_target(), 'radio_detection':self.radio_detection})
            decode_thread = threading.Thread(target=self.decode_stream, args=(results,), daemon=True)
            feed_thread = threading.Thread(target=self.feed, args=(raw,), daemon=True)
            decode_thread.start();feed_thread.start()
            disk_check = time.monotonic()
            radio_check = time.monotonic()
            while not self.stop_event.wait(.2):
                self.elapsed = (time.monotonic() - self.clock_start) * self.speed
                if self.duration is not None and self.elapsed >= self.duration:
                    self.elapsed = self.duration
                    finished_by = 'duration';break
                if not self.replay and time.monotonic()-radio_check>=2:
                    radio_check=time.monotonic()
                    self.check_radio(iface)
                if time.monotonic() - disk_check >= 30:
                    disk_check = time.monotonic()
                    with self.cv:
                        checkpoint = {**self.plan, 'state':'capturing', 'checkpoint':stamp(),
                                      'elapsed_s':self.elapsed, 'BFI':self.bfi_count,
                                      'decode_errors':self.decode_errors, 'protocol':self.protocol_details(),
                                      'radio_verification':self.radio_verification}
                    atomic_json(self.output / 'session.json', checkpoint)
                    if shutil.disk_usage(BASE).free < 128 * 1024 ** 2:
                        self.error = 'Captura detenida por falta de espacio: quedan menos de 128 MiB';break
                if self.decoder.poll() is not None:
                    if self.replay and not feed_thread.is_alive() and self.decoder.returncode == 0:
                        finished_by = 'replay_end';break
                    decerr.flush();self.error = 'tshark terminó: ' + (self.output / 'decoder.log').read_text()[-1200:];break
                if self.capture and self.capture.poll() is not None:
                    caperr.flush();self.error = 'Captura terminada antes de tiempo: ' + (self.output / 'capture.log').read_text()[-1200:];break
                with self.cv:
                    self.emit('heartbeat', self.metrics())
            else:
                finished_by = 'stopped' if not self.error else 'error'
        except Exception as exc:
            self.error = str(exc)
        finally:
            self.stop_event.set()
            if self.capture and self.capture.poll() is None:
                try:
                    self.capture.send_signal(signal.SIGINT)
                except ProcessLookupError:
                    pass
                try:
                    self.capture.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.capture.terminate();self.capture.wait(timeout=5)
            if feed_thread:
                feed_thread.join(timeout=5)
            if self.decoder:
                try:
                    self.decoder.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    self.decoder.kill();self.decoder.wait(timeout=3)
                    self.error = self.error or 'El decodificador no terminó a tiempo'
                if self.decoder.returncode != 0:
                    self.error = self.error or 'Fallo del decodificador; consulta decoder.log'
            if decode_thread:
                decode_thread.join(timeout=3)
            if self.decoder and self.decoder.stdout:
                self.decoder.stdout.close()
            if self.capture and self.capture.stdout:
                self.capture.stdout.close()
            for f in files:
                f.close()
            self.capture = self.decoder = None
            if self.capture_lock:
                self.capture_lock.close();self.capture_lock = None
            if authorization_lease: authorization_lease.close()
            with self.cv:
                self.completed = not self.error and (finished_by in {'duration', 'replay_end'} or (self.duration is None and finished_by == 'stopped'))
                self.state = 'error' if self.error else 'finished'
                if self.output and self.output.exists():
                    raw_path = self.output / 'capture.pcap'
                    log = (self.output / 'capture.log').read_text() if (self.output / 'capture.log').exists() else ''
                    drops = re.search(r'(\d+) packets dropped by kernel', log)
                    digest = None
                    if raw_path.exists():
                        with raw_path.open('rb') as source:
                            digest = hashlib.file_digest(source, 'sha256').hexdigest()
                    summary = {**getattr(self, 'plan', {}), 'ended': stamp(), 'state': self.state, 'completed': self.completed,
                               'elapsed_s': self.elapsed,
                               'end_reason': finished_by, 'error': self.error, 'BFI': self.bfi_count, 'valid_scores': self.valid_scores,
                               'decode_errors': self.decode_errors, 'kernel_drops': int(drops[1]) if drops else None,
                               'sha256': digest,'protocol':self.protocol_details(),
                               'radio_verification':self.radio_verification}
                    atomic_json(self.output / 'session.json', summary)
                    if not self.replay and summary['protocol']:
                        try:self.discovery.remember_protocol(self.current_target(),summary['protocol'],self.session)
                        except (OSError,ValueError):pass  # La ficha de sesión ya conserva el protocolo.
                self.emit('done', self.snapshot())


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, fmt, *args):
        if str(args[0]).find('/events') < 0:
            super().log_message(fmt, *args)

    @property
    def manager(self):
        return self.server.manager

    def allowed_host(self):
        host = self.headers.get('Host', '')
        return host in {f'localhost:{self.server.server_port}', f'127.0.0.1:{self.server.server_port}'}

    def send(self, code, body, kind='application/json; charset=utf-8'):
        if isinstance(body, dict):body = json.dumps(body, ensure_ascii=False, allow_nan=False).encode()
        elif isinstance(body, str):body = body.encode()
        self.send_response(code)
        if code >= 400:
            self.close_connection = True
            self.send_header('Connection', 'close')
        self.send_header('Content-Type', kind)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
        self.end_headers();self.wfile.write(body)

    def do_GET(self):
        if not self.allowed_host():return self.send(403, {'error': 'Accede mediante localhost o el túnel SSH'})
        path = urlsplit(self.path).path
        if path == '/api/authorization':return self.send(200, {**policy.status(), 'csrf':self.manager.token, 'replay':bool(self.manager.replay)})
        if path == '/' and not self.manager.replay and not policy.status()['authorized']:
            path = '/authorization'
        if path == '/api/services':return self.send(200, service_view.status(BASE))
        if path == '/api/services/series':
            try:
                q=parse_qs(urlsplit(self.path).query)
                return self.send(200,service_view.series(BASE,q.get('session',[''])[0],q.get('key',[''])[0],q.get('start',['0'])[0],q.get('end',['0'])[0],q.get('stream',[None])[0]))
            except (ValueError,TypeError,OSError) as exc:return self.send(400,{'error':str(exc)})
        if path in {'/api/archive', '/api/archive/session', '/api/archive/download'}:
            try:
                q = parse_qs(urlsplit(self.path).query)
                root = BASE / 'captures/live'
                current = self.manager.session if self.manager.state in ACTIVE else None
                if path == '/api/archive':return self.send(200, list_sessions(root, current))
                session = q.get('session',[''])[0]
                if path == '/api/archive/session':return self.send(200, read_session(root, session, current))
                if session == current:return self.send(409, {'error':'Descarga los archivos al finalizar; la consulta de la gráfica sigue disponible.'})
                return self.send_file(session_file(root, session, q.get('kind',[''])[0]))
            except FileNotFoundError:return self.send(404, {'error':'Archivo no disponible'})
            except (ValueError,TypeError,OSError) as exc:return self.send(400, {'error':str(exc)})
        if path == '/api/history':
            try:
                q = parse_qs(urlsplit(self.path).query)
                return self.send(200, read_history(BASE / 'captures/live', q.get('session', [''])[0],
                                                  q.get('cursor', ['0'])[0], q.get('limit', ['4000'])[0]))
            except FileNotFoundError:
                return self.send(404, {'error': 'El registro aún no está disponible'})
            except (ValueError, TypeError) as exc:
                return self.send(400, {'error': str(exc)})
        if path == '/api/state':return self.send(200, self.manager.snapshot())
        if path == '/api/clients':return self.send(200, self.manager.discovery.snapshot())
        if path == '/events':return self.events()
        static = {'/': ('index.html', 'text/html; charset=utf-8'), '/app.js': ('app.js', 'application/javascript'), '/style.css': ('style.css', 'text/css')}
        static.update({'/services':('services.html','text/html; charset=utf-8'), '/services.js':('services.js','application/javascript'), '/services.css':('services.css','text/css'), '/service-guard.js':('service-guard.js','application/javascript')})
        static.update({'/archive':('archive.html','text/html; charset=utf-8'),
                       '/archive.js':('archive.js','application/javascript'),
                       '/archive.css':('archive.css','text/css')})
        static.update({'/authorization':('authorization.html','text/html; charset=utf-8'),
                       '/authorization.js':('authorization.js','application/javascript'),
                       '/authorization.css':('authorization.css','text/css')})
        if path in static:
            name, mime = static[path]
            return self.send(200, (Path(__file__).parent / 'static' / name).read_bytes(), mime)
        downloads = {'/download/pcap': 'capture.pcap', '/download/variance': 'variance.jsonl', '/download/session': 'session.json', '/download/markers': 'markers.json'}
        if path in downloads and self.manager.output:
            if self.manager.state in ACTIVE:return self.send(409, {'error': 'Espera a que finalice la captura'})
            f = self.manager.output / downloads[path]
            if f.is_file():return self.send_file(f)
        self.send(404, {'error': 'No encontrado'})

    def send_file(self, path):
        # Los registros largos se descargan por bloques, sin cargarlos en RAM.
        with path.open('rb') as source:
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Length', str(os.fstat(source.fileno()).st_size))
            self.send_header('Content-Disposition', f'attachment; filename="{path.name}"')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.end_headers()
            try:
                shutil.copyfileobj(source, self.wfile, length=1024 * 1024)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def do_POST(self):
        if not self.allowed_host():return self.send(403, {'error': 'Host no permitido'})
        origin = self.headers.get('Origin')
        if origin and origin != 'http://' + self.headers.get('Host', ''):
            return self.send(403, {'error': 'Origen no permitido'})
        if not secrets.compare_digest(self.headers.get('X-Live-Token', ''), self.manager.token):
            return self.send(403, {'error': 'Recarga la página para renovar la sesión'})
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 <= size <= 4096:raise ValueError('Petición demasiado grande')
            data = json.loads(self.rfile.read(size) or b'{}')
            if not isinstance(data, dict):raise ValueError('Petición no válida')
            path = urlsplit(self.path).path
            if path in {'/api/start','/api/stop','/api/client','/api/clients/refresh','/api/mark'} and service_view.protected(BASE):
                return self.send(409,{'error':'Monitorización como servicio activa: radio protegida. Abre Monitorizaciones activas para consultar sin interrumpir.'})
            if path == '/api/authorization':self.manager.configure_authorization(data)
            elif path == '/api/authorization/revoke':self.manager.configure_authorization(revoke=True)
            elif path == '/api/start':self.manager.start(data.get('label'), data.get('duration'), data.get('client'))
            elif path == '/api/stop':self.manager.stop()
            elif path == '/api/mark':self.manager.mark(data.get('kind'))
            elif path == '/api/clients/refresh':
                if self.manager.replay:raise ValueError('El descubrimiento requiere radio en directo')
                self.manager.refresh_clients()
            elif path == '/api/client':self.manager.select_client(data.get('client'))
            else:return self.send(404, {'error': 'No encontrado'})
            self.send(200, {'ok': True})
        except (ValueError, TypeError, json.JSONDecodeError) as exc:self.send(400, {'error': str(exc)})
        except OSError:self.send(500, {'error':'No se pudo guardar la declaración local; comprueba los permisos'})

    def events(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream')
        self.send_header('Cache-Control', 'no-cache')
        self.send_header('Connection', 'keep-alive')
        self.end_headers()
        m = self.manager
        def write(kind, payload, number):
            message = f'id: {number}\nevent: {kind}\ndata: {json.dumps(payload, ensure_ascii=False, allow_nan=False)}\n\n'
            self.wfile.write(message.encode());self.wfile.flush()
        try:
            snap = m.snapshot();cursor = snap['version'];write('reset', snap, cursor)
            while True:
                with m.cv:
                    if m.version == cursor:m.cv.wait(timeout=1)
                    if m.event_log and cursor < m.event_log[0][0] - 1:
                        snap = m.snapshot();pending = [(snap['version'], 'reset', snap)]
                    else:pending = [e for e in m.event_log if e[0] > cursor]
                if not pending:
                    self.wfile.write(b': heartbeat\n\n');self.wfile.flush()
                for num, kind, payload in pending:
                    write(kind, payload, num);cursor = num
        except (BrokenPipeError, ConnectionResetError, TimeoutError):pass


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--port', type=int, default=8798)
    p.add_argument('--replay', type=Path, help='Modo de prueba: reproducir un PCAP, sin usar radio')
    p.add_argument('--speed', type=float, default=1)
    a = p.parse_args()
    if not 1024 <= a.port <= 65535 or not math.isfinite(a.speed) or not .1 <= a.speed <= 100:p.error('Puerto o velocidad no válidos')
    if not a.replay and a.speed != 1:p.error('La velocidad solo cambia en reproducción')
    if a.replay and not a.replay.is_file():p.error('PCAP no encontrado')
    os.umask(0o077)
    manager = Manager(a.replay, a.speed)
    try:
        server = ThreadingHTTPServer(('127.0.0.1', a.port), Handler)
    except OSError as exc:
        p.exit(2, f'No se puede abrir el puerto {a.port}: {exc}. Usa otro puerto con --port.\n')
    server.daemon_threads = True;server.manager = manager
    print(f'SILUETA en http://127.0.0.1:{a.port} · ' + ('REPRODUCCIÓN DE PCAP' if a.replay else 'LISTO PARA CAPTURA AUTORIZADA' if policy.status()['authorized'] else 'CAPTURA BLOQUEADA · declara AP, clientes y consentimiento'), flush=True)
    def quit_app(*_):
        manager.discovery.cancel.set()
        manager.stop()
        threading.Thread(target=server.shutdown, daemon=True).start()
    signal.signal(signal.SIGINT, quit_app);signal.signal(signal.SIGTERM, quit_app)
    try:server.serve_forever()
    finally:
        manager.discovery.cancel.set()
        manager.stop()
        if manager.thread:manager.thread.join(timeout=20)
        if manager.discovery.thread:manager.discovery.thread.join(timeout=12)
        server.server_close()

if __name__ == '__main__':main()
