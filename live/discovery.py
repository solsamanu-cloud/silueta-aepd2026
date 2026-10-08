"""Barrido pasivo de todos los canales permitidos, limitado al AP y clientes autorizados."""
from collections import deque
from copy import deepcopy
import fcntl
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import threading
import time
from engine import FIELDS, decode_line
from feedback import report_kind, PRESERVE_MULTIPLE
from discovery_history import DiscoveryHistory
import protocol
import radio
import policy

DWELL_SECONDS=3
# libpcap on Fedora rejects `type ctl subtype 5` (NDPA is a newer subtype).
# Match frame-control type/subtype directly; wlan[] skips the radiotap header.
DISCOVERY_BPF='type mgt or type data or (wlan[0] & 0xfc = 0x54)'
EXTRA_FIELDS=['wlan.bssid','wlan.fc.type','radiotap.channel.freq',
              'wlan.ht.info.primarychannel','wlan.ds.current_channel','wlan.ht.info.secchanoffset',
              'wlan.vht.op.channelwidth','wlan.vht.op.channelcenter0']+protocol.FIELDS
NAMES=policy.clients()

def unicast(value):
    return bool(isinstance(value,str) and re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',value)
                and not int(value[:2],16)&1 and value!='00:00:00:00:00:00')

def identity(mac):
    item=policy.clients().get(mac,{'id':'','name':'Cliente observado'})
    return {'mac':mac,**item,'label':f'{item["id"]} · {item["name"]}' if item['id'] else item['name']}

def target_key(mac,ap,frequency):return f'{mac}|{ap}|{frequency}'

def frequency(channel):return 2484 if channel==14 else 2407+5*channel if 1<=channel<=13 else 5000+5*channel

def channel(freq):return 14 if freq==2484 else (freq-2407)//5 if freq<2500 else (freq-5000)//5

def number(value,default=0):
    try:return int(value.split(',')[0],0) if value else default
    except ValueError:return default

class Observations:
    def __init__(self,ap=None,allowed_clients=None):
        # Scope is mandatory at live acquisition entry points. Unscoped parsing is for synthetic tests.
        self.scope_ap=ap;self.scope_clients=set(allowed_clients) if allowed_clients is not None else None
        self.peers={};self.aps={};self.pending=deque(maxlen=4096);self.lock=threading.RLock()

    def consume(self,line):
        with self.lock:self._consume(line)

    def _consume(self,line,retry=False):
        parts=line.rstrip('\r\n').split('|')
        if len(parts)!=len(FIELDS)+len(EXTRA_FIELDS):return
        tx,rx=parts[1].split(',')[0].lower(),parts[12].split(',')[0].lower()
        bssid,kind,freq,primary,ds,offset,vwidth,vcenter=parts[len(FIELDS):len(FIELDS)+8]
        fields=dict(zip(protocol.FIELDS,parts[len(FIELDS)+8:]))
        bssid=bssid.split(',')[0].lower();kind=number(kind,-1);freq=number(freq)
        subtype=number(parts[13],-1)
        if self.scope_clients is not None and not policy.frame_allowed(tx,rx,kind,subtype,self.scope_ap,self.scope_clients):return
        try:rssi=max(float(v) for v in parts[2].split(',') if v)
        except ValueError:rssi=None
        try:ts=float(parts[0])
        except ValueError:return
        if not math.isfinite(ts) or not (2400<=freq<=2500 or 5000<=freq<5900):return
        if kind==0 and subtype in (5,8) and unicast(tx):
            primary=number(primary) or number(ds)
            if primary:freq=frequency(primary)
            width,center=20,freq
            off=number(offset)
            if off in (1,3):width,center=40,freq+(10 if off==1 else -10)
            if number(vwidth)>0 and freq>=5000:
                vc=frequency(number(vcenter))
                if abs(vc-freq) in (10,30):width,center=80,vc
                else:
                    for c in (42,58,106,122,138,155,171):
                        if abs(frequency(c)-freq) in (10,30):width,center=80,frequency(c);break
            old=self.aps.get(tx,{})
            self.aps[tx]={**old,**dict(ap=tx,frequency=freq,channel=channel(freq),width=width,center=center,channel_source='AP beacon / probe response')}
            apstats=self.aps[tx].setdefault('ap_stats',{})
            apstats['beacons']=apstats.get('beacons',0)+int(subtype==8)
            protocol.record_signal(apstats,'ap',rssi,ts)
            self.aps[tx]['advertised']=dict(security=protocol.security(fields),capabilities=protocol.capabilities(fields),ssid=protocol.ssid(fields.get('wlan.ssid')),ts=ts)
            for peer in self.peers.values():
                if peer['ap']==tx and peer.get('protocol'):
                    peer['protocol']['ap_advertised']=self.aps[tx]['advertised']
            waiting=list(self.pending);self.pending.clear()
            for old in waiting:self._consume(old,retry=True)
            return
        if kind==1 and subtype==21:
            if tx in self.aps:
                apstats=self.aps[tx].setdefault('ap_stats',{})
                label=protocol.NDPA_VARIANTS.get(protocol.number(fields.get('wlan.ndp.token.variant')),'Sin variante')
                counts=apstats.setdefault('ndpa_all',{});counts[label]=counts.get(label,0)+1
                if not unicast(rx):return  # No atribuir NDPA multicast a cada cliente del AP.
            elif not retry:
                self.pending.append(line);return
        if kind not in (0,1,2) or (kind==0 and subtype in (4,5,8)):return
        if unicast(bssid) and bssid in (tx,rx):ap=bssid
        elif (kind==1 or kind==0 and subtype in (13,14)) and not unicast(bssid):
            candidates=[m for m in (tx,rx) if m in self.aps]
            if len(candidates)!=1:
                if not retry:self.pending.append(line)
                return
            ap=candidates[0]
        else:return
        mac=rx if tx==ap else tx
        if not unicast(mac) or mac==ap or mac in self.aps:return
        link=self.aps.get(ap,dict(ap=ap,frequency=freq,channel=channel(freq),width=20,center=freq,channel_source='receiver_only'))
        link={k:v for k,v in link.items() if k!='ap_stats'}
        key=target_key(mac,ap,link['frequency'])
        item=self.peers.get(key)
        if item is None:
            item={**identity(mac),**link,'key':key,'tx_frames':0,'rx_frames':0,'vht_bfi':0,
                  'compatible_bfi':0,'unsupported_bfi':0,'reverse_vht_bfi':0,'rssi':None,'last_seen':ts,'protocol':protocol.fresh()}
            self.peers[key]=item
        item.update(link);item['last_seen']=max(item['last_seen'],ts)
        stats=item['protocol']
        protocol.observe(stats,fields,kind,subtype,ts,tx==mac,link.get('advertised'),length=number(parts[3]),rssi=rssi)
        item['tx_frames' if tx==mac else 'rx_frames']+=1
        if tx==mac and rssi is not None and math.isfinite(rssi):item['rssi']=rssi
        feedback_fields=dict(zip(FIELDS,parts[:len(FIELDS)]))
        report=report_kind(feedback_fields)
        if report:
            good=False;reason=None;decoded=None
            if report=='VHT':item['reverse_vht_bfi' if tx==ap else 'vht_bfi']+=1
            item['bfi_reports']=item.get('bfi_reports',0)+1
            try:
                decoded=decode_line(core_line(parts),mac,ap)
                good='psi' in decoded
                item['compatible_bfi']+=good
            except (ValueError,KeyError,IndexError) as exc:
                item['unsupported_bfi']+=1;reason=str(exc)
            protocol.record_bfi(stats,parts,tx==mac,good,reason,
                                description=decoded.get('feedback') if decoded else None,kind=report)

    def details(self,client,ap):
        with self.lock:
            peer=next((p for p in self.peers.values() if p['mac']==client and p['ap']==ap),None)
            context=self.aps.get(ap,{})
            if not peer and not context:return None
            p=deepcopy(peer['protocol']) if peer else protocol.fresh()
            if context.get('advertised'):p['ap_advertised']=deepcopy(context['advertised'])
            if context.get('ap_stats'):p['ap_context']=deepcopy(context['ap_stats'])
            return p

    def result(self):
        with self.lock:
            return sorted(({**deepcopy(p),'protocol':self.details(p['mac'],p['ap'])} for p in self.peers.values() if p['mac'] not in self.aps),
                          key=lambda p:(-p['compatible_bfi'],p['id'] or 'Z',p['mac'],p['ap'],p['frequency']))

def core_line(parts):
    return '|'.join(v if i==2 or FIELDS[i] in PRESERVE_MULTIPLE else v.split(',')[0] for i,v in enumerate(parts[:len(FIELDS)]))

def tshark_discovery_command(source):
    cmd=['tshark','-n','-l','-r',str(source),'-T','fields','-E','separator=|','-E','occurrence=a','-E','aggregator=,']
    for field in FIELDS+EXTRA_FIELDS:cmd+=['-e',field]
    return cmd

def stop_process(process,interrupt=False):
    if process and process.poll() is None:
        try:
            process.send_signal(signal.SIGINT if interrupt else signal.SIGTERM);process.wait(timeout=4)
        except subprocess.TimeoutExpired:process.kill();process.wait(timeout=3)
        except ProcessLookupError:pass

class Discovery:
    def __init__(self,emit,settings,history_path=None):
        self.emit,self.settings=emit,settings;self.lock=threading.RLock();self.thread=None
        self.cancel=threading.Event()
        self.data={'scanning':False,'clients':[],'updated':None,'error':None,'seconds':None,
                   'channel_index':0,'channel_total':0,'channel':None,'skipped':[]}
        self.history=DiscoveryHistory(history_path)
        # Recuperación de metadatos desde PCAP, sin alterar sus tramas ni las series.
        if history_path:
            enriched=Path(history_path).with_name('live-protocol-enriched.json')
            if enriched.exists() and not self.history.error:
                try:
                    for key,item in json.loads(enriched.read_text()).items():
                        if key not in self.history.catalog:continue
                        old=self.history.catalog[key]
                        records={r['session']:r for r in item.get('protocol_records',[])}
                        records.update({r['session']:r for r in old.get('protocol_records',[])})
                        old['protocol_records']=list(records.values())
                        old['channel_source']=item.get('channel_source',old.get('channel_source'))
                        if (item.get('protocol_followup',{}).get('last_seen') or 0)>=(old.get('protocol_followup',{}).get('last_seen') or 0):
                            old.update({k:v for k,v in item.items() if k!='protocol_records'})
                    self.history.save()
                except (OSError,ValueError,KeyError,TypeError):pass
        self.data.update(self.history.snapshot())
        if self.history.current:
            last=self.history.current
            self.data.update(updated=last.get('ended'),cancelled=last['status'] in ('cancelled','scanning'),
                             channel_index=last['channel_index'],channel_total=last['channel_total'])

    def snapshot(self):
        with self.lock:return {**self.data,'clients':list(self.data['clients'])}

    def remember_protocol(self,target,details,session):
        with self.lock:
            key=target['key']
            old=self.history.catalog.get(key,{**target,'first_seen':details.get('first_seen'),'last_seen':details.get('last_seen')})
            records={r['session']:r for r in old.get('protocol_records',[])}
            records[session]={'session':session,'protocol':deepcopy(details)}
            self.history.catalog[key]={**old,'protocol_followup':deepcopy(details),'protocol_session':session,'protocol_records':list(records.values())}
            self.history.save()
            self.data.update(self.history.snapshot())
        self.emit('clients',self.snapshot())

    def publish(self,**changes):
        with self.lock:
            observed=changes.pop('clients',None)
            self.data.update(changes)
            try:
                self.history.update(observed,ended=time.time(),cancelled=self.data.get('cancelled',False),
                                    **{k:v for k,v in changes.items() if k!='cancelled'})
            except (OSError,ValueError) as exc:
                self.data['history_error']='No se pudo guardar el histórico: '+str(exc)
            saved=self.history.snapshot()
            if self.data.get('history_error') and not saved['history_error']:
                saved['history_error']=self.data['history_error']
            self.data.update(saved)
        self.emit('clients',self.snapshot())

    def start(self):
        policy.authorization()
        with self.lock:
            if self.data['scanning']:raise ValueError('Ya se está actualizando el listado')
            self.history.begin(time.time())
            self.data.update(scanning=True,error=None,cancelled=False,channel_index=0,channel_total=0,skipped=[])
            self.data.update(self.history.snapshot())
            self.cancel.clear();self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start()
        self.emit('clients',self.snapshot())

    def run(self):
        capture=decoder=reader=original=lockfile=authorization_lease=None
        try:
            authorization_lease=policy.acquire_lease()
            policy.authorization()
            iface,authorized_ap=self.settings()
            lockpath=Path(__file__).resolve().parents[1]/'state/live-app.lock'
            lockpath.parent.mkdir(exist_ok=True)
            lockfile=lockpath.open('a')
            try:fcntl.flock(lockfile,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise ValueError('Otra sesión está usando la ALFA')
            radio.ensure_free(iface);original=radio.monitor_info(iface)
            targets=radio.channels(iface)
            targets.sort(key=lambda p:(p['frequency']!=original['frequency'],p['frequency']<5000,p['frequency']))
            self.publish(seconds=len(targets)*DWELL_SECONDS,channel_total=len(targets))
            observations=Observations(authorized_ap,policy.client_addresses())
            cmd=policy.capture_command(iface,buffer=4096)
            if os.geteuid()!=0:cmd=['sudo','-n','--']+cmd
            with tempfile.TemporaryFile() as caperr,tempfile.TemporaryFile() as decerr:
                capture=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=caperr)
                fields=tshark_discovery_command('-')
                decoder=subprocess.Popen(fields,stdin=capture.stdout,stdout=subprocess.PIPE,stderr=decerr,text=True)
                capture.stdout.close();failures=[];skipped=[];heard=0
                def consume():
                    try:
                        for line in decoder.stdout:observations.consume(line)
                    except Exception as exc:failures.append(str(exc))
                reader=threading.Thread(target=consume,daemon=True);reader.start()
                for index,target in enumerate(targets,1):
                    if self.cancel.is_set():break
                    try:radio.tune(iface,target)
                    except ValueError as exc:
                        skipped.append({'channel':target['channel'],'reason':str(exc)})
                        self.publish(skipped=list(skipped));continue
                    heard+=1
                    self.publish(channel_index=index,channel=target['channel'],clients=observations.result())
                    if self.cancel.wait(DWELL_SECONDS):break
                    if capture.poll() is not None or decoder.poll() is not None:break
                ended_early=capture.poll() is not None or decoder.poll() is not None
                stop_process(capture,interrupt=True)
                try:decoder.wait(timeout=5)
                except subprocess.TimeoutExpired:stop_process(decoder)
                reader.join(timeout=2)
                if ended_early or decoder.returncode!=0 or failures or reader.is_alive():
                    caperr.seek(0);decerr.seek(0)
                    detail=(caperr.read()+decerr.read()).decode(errors='replace')[-800:]
                    raise ValueError('No se pudo escuchar la ALFA. '+detail+'; '.join(failures))
                if not heard:raise ValueError('El controlador no permitió escuchar ningún canal')
                self.publish(clients=observations.result(),updated=time.time(),error=None,skipped=skipped,
                             cancelled=self.cancel.is_set(),channel_index=len(targets) if not self.cancel.is_set() else self.data['channel_index'])
        except (OSError,ValueError,subprocess.SubprocessError) as exc:self.publish(error=str(exc))
        finally:
            stop_process(capture,interrupt=True);stop_process(decoder)
            if reader:reader.join(timeout=2)
            if decoder and decoder.stdout:decoder.stdout.close()
            if original:
                try:radio.tune(iface,original)
                except (ValueError,OSError,subprocess.SubprocessError) as exc:
                    self.publish(error=(self.data.get('error') or '')+' No se pudo restaurar el canal inicial: '+str(exc))
            if lockfile:lockfile.close()
            if authorization_lease:authorization_lease.close()
            self.publish(scanning=False,channel=None)
