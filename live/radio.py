"""Sintonía pasiva: canales anunciados por el controlador, sin alterar regulación."""
import os
from pathlib import Path
import re
import subprocess
import time


def run(args, privileged=False):
    if privileged and os.geteuid()!=0:args=['sudo','-n','--']+args
    return subprocess.run(args,capture_output=True,text=True,timeout=8,env={**os.environ,'LC_ALL':'C'})


def monitor_info(iface):
    p=run(['iw','dev',iface,'info'])
    if p.returncode or 'type monitor' not in p.stdout:
        raise ValueError('Pon la ALFA en modo monitor antes de escuchar')
    channel=re.search(r'channel (\d+) \((\d+) MHz\), width: (\d+) MHz.*?center1: (\d+) MHz',p.stdout)
    phy=re.search(r'wiphy (\d+)',p.stdout)
    if not channel or not phy:raise ValueError('No se pudo leer el canal de la ALFA')
    ch,freq,width,center=map(int,channel.groups())
    return dict(channel=ch,frequency=freq,width=width,center=center,phy='phy'+phy[1])


def parse_channels(text):
    found={}
    for line in text.splitlines():
        m=re.search(r'\*\s+(\d+(?:\.\d+)?) MHz \[(\d+)\](.*)',line)
        if not m or 'disabled' in m[3]:continue
        freq,ch=int(float(m[1])),int(m[2])
        if 2400<=freq<=2500 or 5000<=freq<5900:
            found[freq]=dict(frequency=freq,channel=ch,width=20,center=freq)
    if not found:raise ValueError('El controlador no anuncia canales utilizables de 2,4/5 GHz')
    return list(found.values())


def channels(iface):
    p=run(['iw','dev',iface,'info'])
    phy=re.search(r'wiphy (\d+)',p.stdout)
    if p.returncode or not phy:raise ValueError('No se puede consultar la radio de la interfaz')
    p=run(['iw','phy','phy'+phy[1],'info'])
    if p.returncode:raise ValueError(p.stderr.strip() or 'No se pudieron consultar los canales')
    return parse_channels(p.stdout)


def validate_target(target):
    try:
        fields={k:int(target[k]) for k in ('frequency','channel','width','center')}
        if any(isinstance(target[k],bool) or str(fields[k])!=str(target[k]) for k in fields):raise ValueError()
    except (ValueError,TypeError,KeyError):raise ValueError('Faltan datos válidos de canal del cliente; actualiza el barrido')
    freq,width,center=(fields[k] for k in ('frequency','width','center'))
    if width not in (20,40,80) or not (2400<=freq<=2500 or 5000<=freq<5900):
        raise ValueError('Canal o ancho incompatible con la ALFA')
    channel=14 if freq==2484 else (freq-2407)//5 if freq<2500 else (freq-5000)//5
    if fields['channel']!=channel or (freq<2500 and freq!=2484 and (freq<2412 or freq>2472 or (freq-2407)%5)) or (freq>=5000 and freq%5):
        raise ValueError('Canal y frecuencia del cliente no coinciden; actualiza el barrido')
    if freq<2500 and width==80:raise ValueError('80 MHz no es válido en 2,4 GHz')
    if width==20 and center!=freq or width==40 and abs(center-freq)!=10 or width==80 and abs(center-freq) not in (10,30):
        raise ValueError('Centro de canal no válido')
    return fields


def verify(iface, target):
    expected=validate_target(target)
    actual=monitor_info(iface)
    if any(actual[k]!=v for k,v in expected.items()):
        raise ValueError(f"Sintonía incorrecta: solicitado canal {expected['channel']} / {expected['frequency']} MHz / ancho {expected['width']} / centro {expected['center']}; ALFA en canal {actual['channel']} / {actual['frequency']} MHz / ancho {actual['width']} / centro {actual['center']}")
    return actual


def tune(iface, target):
    target=validate_target(target)
    freq,width,center=(target[k] for k in ('frequency','width','center'))
    setting=['HT20'] if width==20 else ['HT40+' if center>freq else 'HT40-'] if width==40 else [str(width),str(center)]
    p=run(['iw','dev',iface,'set','freq',str(freq)]+setting,privileged=True)
    if p.returncode:raise ValueError(p.stderr.strip() or p.stdout.strip()[:200] or 'El controlador rechazó el canal')
    for attempt in range(3):
        try:return verify(iface,target)
        except ValueError:
            if attempt==2:raise
            time.sleep(.15)


def ensure_free(iface):
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():continue
        try:args=(entry/'cmdline').read_bytes().split(b'\0')
        except (PermissionError,FileNotFoundError,ProcessLookupError):continue
        if args and Path(os.fsdecode(args[0])).name in {'tcpdump','dumpcap'} and os.fsencode(iface) in args:
            raise ValueError('Otra captura está usando la ALFA; no se cambia su canal')
    p=run(['systemctl','list-units','--state=active','--no-legend','wifi-sensing-dia-normal-*.service'])
    if p.returncode==0 and p.stdout.strip():raise ValueError('Hay una monitorización diaria activa o programada')
