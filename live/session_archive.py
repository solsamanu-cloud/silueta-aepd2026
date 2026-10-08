"""Read-only inventory of retained live captures; no expiry or pruning."""
import json
from pathlib import Path
import re

FILES = {'pcap': 'capture.pcap', 'variance': 'variance.jsonl',
         'session': 'session.json', 'markers': 'markers.json'}


def session_folder(root, session):
    if not isinstance(session, str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}', session):
        raise ValueError('Sesión no válida')
    root = Path(root).resolve()
    folder = root / session
    if folder.is_symlink() or folder.resolve().parent != root:
        raise ValueError('Sesión fuera del archivo')
    return folder


def session_file(root, session, kind):
    if kind not in FILES:
        raise ValueError('Archivo no válido')
    path = session_folder(root, session) / FILES[kind]
    if path.is_symlink():
        raise ValueError('Archivo no válido')
    if not path.is_file():
        raise FileNotFoundError(path.name)
    return path


def read_session(root, session, active_session=None):
    data = json.loads(session_file(root, session, 'session').read_text(encoding='utf-8'))
    data['session'] = session
    data['archive_status'] = ('En curso' if session == active_session else
                              'Error' if data.get('error') else
                              'Finalizada' if data.get('ended') else 'Sin cierre registrado')
    data['files'] = [k for k in FILES if (session_folder(root, session)/FILES[k]).is_file()
                     and not (session_folder(root, session)/FILES[k]).is_symlink()]
    try:
        data['markers'] = json.loads(session_file(root, session, 'markers').read_text(encoding='utf-8'))
    except FileNotFoundError:
        data['markers'] = []
    return data


def list_sessions(root, active_session=None):
    rows, errors = [], []
    for manifest in Path(root).glob('*/session.json'):
        try:
            d = read_session(root, manifest.parent.name, active_session)
            p = d.get('protocol') or {}
            adv = p.get('ap_advertised') or {}
            row = {k: d.get(k) for k in ('session','started','ended','client','client_identity','ap','radio',
                'elapsed_s','BFI','decode_errors','mode','archive_status','files')}
            row.update(ssid=adv.get('ssid'), frames=p.get('total'),
                       observed_bfi=sum(x.get('total',0) for x in (p.get('bfi') or {}).values()) + sum((p.get('he_feedback') or {}).values()),
                       pcap_bytes=(session_file(root,d['session'],'pcap').stat().st_size if 'pcap' in d['files'] else 0))
            rows.append(row)
        except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
            errors.append({'session':manifest.parent.name,'error':str(exc)})
    rows.sort(key=lambda r:r.get('started') or '', reverse=True)
    return {'sessions':rows,'errors':errors,'retention':'Sin borrado automático'}
