"""Fail-closed local consent and libpcap acquisition allowlist (Linux)."""
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

BASE = Path(__file__).resolve().parents[1]
MAC = re.compile(r'^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$')
NOTICE = 'own-ap-authorized-clients-informed-consent-v1'
DEFAULTS = dict(IFACE='wlan1', TARGET_BSSID='02:00:00:00:00:06',
                TARGET_CLIENT='02:00:00:00:00:01', FREQ_CONTROL='5180',
                CHANNEL_WIDTH='80', CENTER_FREQ='5210', AUTHORIZED_CAPTURE='no')

def validate_mac(value):
    if not isinstance(value, str): raise ValueError('Dirección unicast inválida')
    value = value.strip().lower()
    if not MAC.fullmatch(value) or int(value[:2], 16) & 1 or value == '00:00:00:00:00:00':
        raise ValueError('Dirección unicast inválida')
    return value

def validate(data):
    if not isinstance(data, dict) or data.get('consent') is not True:
        raise ValueError('Se requiere consentimiento expreso para el AP propio y todos los clientes y personas autorizados')
    interface = data.get('interface', '')
    if not isinstance(interface, str) or not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,32}', interface):
        raise ValueError('Interfaz inválida')
    ap = validate_mac(data.get('ap'))
    entries = data.get('clients')
    if not isinstance(entries, list) or not 1 <= len(entries) <= 32:
        raise ValueError('Declara entre 1 y 32 clientes autorizados')
    clients, ids, addresses = [], set(), {ap}
    for item in entries:
        if not isinstance(item, dict): raise ValueError('Cliente inválido')
        code = item.get('id', ''); mac = validate_mac(item.get('mac'))
        if not isinstance(code, str) or not re.fullmatch(r'C[0-9]{2}', code) or code == 'C00' or code in ids or mac in addresses:
            raise ValueError('Usa C01–C99 únicos, sin duplicar direcciones ni el AP')
        ids.add(code); addresses.add(mac); clients.append(dict(id=code, mac=mac))
    ssid = data.get('ssid', '')
    if not isinstance(ssid, str) or len(ssid.encode('utf-8')) > 32 or any(ord(c)<32 for c in ssid):
        raise ValueError('SSID inválido: máximo 32 bytes, sin caracteres de control')
    if data.get('radio_mode') == 'auto' or not all(k in data for k in ('frequency','width','center')):
        return dict(interface=interface, ap=ap, clients=clients, consent=True, radio_mode='auto', ssid=ssid)
    try: from . import radio
    except ImportError: import radio
    try:
        frequency = int(data['frequency'])
        channel = 14 if frequency == 2484 else (frequency-2407)//5 if frequency < 2500 else (frequency-5000)//5
        config = radio.validate_target(dict(frequency=data['frequency'], channel=channel,
                                            width=data['width'], center=data['center']))
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError('Frecuencia, ancho o centro de canal no válidos') from exc
    return dict(interface=interface, ap=ap, clients=clients, consent=True, **config)

def authorization():
    try:
        data = json.loads((BASE/'local/authorization.json').read_text(encoding='utf-8'))
        validated = validate(data)
        if data.get('notice') != NOTICE or data.get('schema') != 1 or not isinstance(data.get('accepted_at'), str):
            raise ValueError('Declaración incompatible; confirma de nuevo el consentimiento')
        return dict(validated, schema=1, notice=NOTICE, accepted_at=data['accepted_at'])
    except (OSError, ValueError, TypeError) as exc:
        raise ValueError('Captura bloqueada: declara el AP propio, los clientes y el consentimiento en /authorization') from exc

def fingerprint(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

def status():
    try:
        data = authorization()
        return dict(authorized=True, declaration=data, filter=build_filter(data), fingerprint=fingerprint(data))
    except ValueError as exc:
        return dict(authorized=False, declaration=None, filter=None, error=str(exc))

def acquire_lease(exclusive=False):
    directory = BASE/'local'
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(directory/'authorization.lock', os.O_RDWR | os.O_CREAT, 0o600)
    lease = os.fdopen(fd, 'a')
    try:
        fcntl.flock(lease, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
    except BlockingIOError:
        lease.close()
        raise ValueError('Autorización en uso: detén la captura o el barrido antes de cambiarla')
    return lease

def save(data):
    """Only an explicit boolean true authorizes; replace atomically, private file."""
    validated = validate(data)
    validated.update(schema=1, notice=NOTICE, accepted_at=datetime.now(timezone.utc).isoformat())
    with acquire_lease(exclusive=True):
        path = BASE/'local/authorization.json'
        fd, name = tempfile.mkstemp(prefix='.authorization-', dir=path.parent)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                json.dump(validated, stream, ensure_ascii=False, indent=2)
                stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
            os.replace(name, path)
        finally:
            if os.path.exists(name): os.unlink(name)
    return validated

def revoke():
    with acquire_lease(exclusive=True):
        (BASE/'local/authorization.json').unlink(missing_ok=True)

def settings():
    try: data = authorization()
    except ValueError: return DEFAULTS.copy()
    config = data
    if data.get('radio_mode') == 'auto':
        config = dict(frequency=5180, width=20, center=5180)  # UI placeholder, never a capture decision.
        try:
            cached = json.loads((BASE/'local/radio-detected.json').read_text(encoding='utf-8'))
            if cached.get('authorization_sha256') == fingerprint(data): config = cached['radio']
        except (OSError, ValueError, KeyError, TypeError): pass
    return dict(IFACE=data['interface'], TARGET_BSSID=data['ap'], TARGET_CLIENT=data['clients'][0]['mac'],
                FREQ_CONTROL=str(config['frequency']), CHANNEL_WIDTH=str(config['width']),
                CENTER_FREQ=str(config['center']), AUTHORIZED_CAPTURE='yes')

def settings_text():
    return ''.join(f'{key}={value}\n' for key, value in settings().items())

def clients():
    try: entries = authorization()['clients']
    except ValueError: entries = [dict(id='C01', mac=DEFAULTS['TARGET_CLIENT'])]
    return {item['mac']:dict(id=item['id'], name='Cliente autorizado '+item['id']) for item in entries}

def client_addresses(): return set(clients())

def radio_config():
    s = settings(); f = int(s['FREQ_CONTROL'])
    return dict(frequency=f, channel=14 if f==2484 else (f-2407)//5 if f<2500 else (f-5000)//5,
                width=int(s['CHANNEL_WIDTH']), center=int(s['CENTER_FREQ']))

def require_target(target):
    data = authorization()
    if target.get('ap') != data['ap'] or target.get('mac') not in {c['mac'] for c in data['clients']}:
        raise ValueError('Enlace fuera de la lista autorizada')

def frame_allowed(tx, rx, kind, subtype, ap, allowed):
    return (kind == 0 and subtype == 8 and tx == ap) or (tx == ap and rx in allowed) or (rx == ap and tx in allowed)

def build_filter(data, selected=None):
    ap = data['ap']; allowed = {item['mac'] for item in data['clients']}
    addresses = sorted(allowed if selected is None else {validate_mac(m) for m in selected})
    if not addresses or not set(addresses) <= allowed: raise ValueError('Enlace fuera de la lista autorizada')
    clauses = []
    for mac in addresses:
        up = f'(wlan addr1 {ap} and wlan addr2 {mac})'
        down = f'(wlan addr1 {mac} and wlan addr2 {ap})'
        pair = f'({up} or {down})'
        # No broadcast probes, group data, ACK/CTS without transmitter, or WDS.
        clauses.append(f'((type mgt and wlan addr3 {ap} and {pair}) or '
                       f'(type data and (((wlan[1] & 3 = 1) and {up}) or ((wlan[1] & 3 = 2) and {down}))) or '
                       f'(type ctl and {pair}))')
    return '('+' or '.join(clauses)+f') or (type mgt subtype beacon and wlan addr1 ff:ff:ff:ff:ff:ff and wlan addr2 {ap} and wlan addr3 {ap})'

def capture_filter(selected=None): return build_filter(authorization(), selected)

def capture_command(iface, selected=None, buffer=8192, beacons_only=False):
    data = authorization()
    if iface != data['interface']: raise ValueError('Interfaz fuera de la declaración autorizada')
    bpf = build_filter(data, selected)
    if beacons_only:
        bpf = f"type mgt subtype beacon and wlan addr1 ff:ff:ff:ff:ff:ff and wlan addr2 {data['ap']} and wlan addr3 {data['ap']}"
    return ['tcpdump', '-i', iface, '-n', '-U', '--immediate-mode', '-B', str(buffer),
            '-s', '0', '-w', '-', bpf]
