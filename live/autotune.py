"""Find the consented AP passively. Only its beacons reach this parser."""
import json
import os
import queue
import subprocess
import tempfile
import threading
import time
import policy
import protocol
import radio

DWELL_SECONDS = 1.0

FIELDS = ['wlan.ta','wlan.bssid','wlan.ssid','radiotap.channel.freq',
          'wlan.ht.info.primarychannel','wlan.ds.current_channel',
          'wlan.ht.info.secchanoffset','wlan.vht.op.channelwidth',
          'wlan.vht.op.channelcenter0','wlan.vht.op.channelcenter1']

def decoder_command():
    return ['tshark','-n','-l','-r','-','-T','fields','-E','separator=\t','-E','occurrence=f'] + [v for f in FIELDS for v in ('-e',f)]

def number(value):
    try: return int(value,0) if value else 0
    except ValueError: return 0

def frequency(channel): return 2484 if channel==14 else 2407+5*channel if 1<=channel<=13 else 5000+5*channel

def parse_beacon(line, declaration):
    values=line.rstrip('\r\n').split('\t')
    if len(values)!=len(FIELDS): return None
    tx,bssid,raw_ssid,heard,primary,ds,offset,vwidth,center0,center1=values
    if tx.lower()!=declaration['ap'] or bssid.lower()!=declaration['ap']: return None
    ssid=protocol.ssid(raw_ssid)
    if declaration.get('ssid') and ssid and ssid!=declaration['ssid']:
        raise ValueError('El BSSID declarado anuncia otro SSID. Revisa tu declaración; no se captura.')
    ch=number(primary) or number(ds)
    freq=frequency(ch) if ch else number(heard)
    if not ch:ch=14 if freq==2484 else (freq-2407)//5 if freq<2500 else (freq-5000)//5
    width,center=20,freq
    if number(offset) in (1,3): width,center=40,freq+(10 if number(offset)==1 else -10)
    vw,c0,c1=number(vwidth),number(center0),number(center1)
    if vw:
        if vw!=1 or c1:
            raise ValueError('El AP anuncia 160 MHz o 80+80 MHz; esta versión no ajusta ese formato automáticamente')
        center=frequency(c0);width=80
        if not c0:raise ValueError('La baliza no proporciona un centro de canal VHT válido')
    result=radio.validate_target(dict(frequency=freq,channel=ch,width=width,center=center))
    return dict(result,ssid=ssid,ap=tx.lower(),source='baliza del AP declarado',observed_at=time.time())

def stop_process(process):
    if not process:return
    if process.poll() is None:
        process.terminate()
        try:process.wait(timeout=4)
        except subprocess.TimeoutExpired:process.kill();process.wait(timeout=2)

def discover(iface, cancel, progress=lambda message:None):
    """Caller holds radio and authorization locks. No packet file is created."""
    declaration=policy.authorization()
    if iface!=declaration['interface']:raise ValueError('Interfaz no autorizada')
    from dependencies import require_fields
    require_fields(FIELDS)
    original=radio.monitor_info(iface)
    targets=radio.channels(iface)
    targets.sort(key=lambda target:(target['frequency']!=original['frequency'],target['frequency']))
    capture=decoder=reader=None;found=None;messages=queue.Queue(maxsize=256)
    reader_stop=threading.Event()
    with tempfile.TemporaryFile() as capture_error, tempfile.TemporaryFile() as decode_error:
        try:
            command=policy.capture_command(iface,buffer=4096,beacons_only=True)
            if os.geteuid()!=0:command=['sudo','-n','--']+command
            capture=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=capture_error)
            decoder=subprocess.Popen(decoder_command(),stdin=capture.stdout,stdout=subprocess.PIPE,stderr=decode_error,text=True)
            capture.stdout.close()
            def consume():
                for line in decoder.stdout:
                    if reader_stop.is_set():break
                    try:messages.put_nowait(line)
                    except queue.Full:pass
            reader=threading.Thread(target=consume,daemon=True);reader.start()
            skipped=[]
            for target in targets:
                if cancel.is_set():raise ValueError('Búsqueda del AP cancelada')
                progress(f"Buscando tu AP · canal {target['channel']}")
                try:radio.tune(iface,target)
                except ValueError as exc:skipped.append(str(exc));continue
                deadline=time.monotonic()+DWELL_SECONDS
                while time.monotonic()<deadline:
                    if cancel.is_set():raise ValueError('Búsqueda del AP cancelada')
                    if capture.poll() is not None or decoder.poll() is not None:
                        capture_error.seek(0);decode_error.seek(0)
                        reason=(capture_error.read()+decode_error.read()).decode(errors='replace')[-600:]
                        raise ValueError('No se pudo leer la baliza autorizada: '+reason)
                    try:line=messages.get(timeout=.1)
                    except queue.Empty:continue
                    found=parse_beacon(line,declaration)
                    if found:return found
            raise ValueError('No se ha encontrado una baliza del AP declarado. Revisa BSSID, señal y modo monitor; no se inicia la captura.' + (f' {len(skipped)} canales rechazados por el controlador.' if skipped else ''))
        finally:
            reader_stop.set();stop_process(capture);stop_process(decoder)
            if capture and capture.stdout:capture.stdout.close()
            if reader:reader.join(timeout=2)
            if decoder and decoder.stdout:decoder.stdout.close()
            if not found:radio.tune(iface,original)

def remember(result):
    path=policy.BASE/'local/radio-detected.json'
    data=dict(authorization_sha256=policy.fingerprint(policy.authorization()),radio=result)
    fd,name=tempfile.mkstemp(prefix='.radio-',dir=path.parent)
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as stream:json.dump(data,stream,ensure_ascii=False)
        os.replace(name,path)
    finally:
        if os.path.exists(name):os.unlink(name)
