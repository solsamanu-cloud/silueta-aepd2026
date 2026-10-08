"""Export completed, authorized controlled tests; never copy original packets.

The private map stays outside the repository. Public timestamps are relative.
"""
import argparse
import csv
import json
import re
import subprocess
from pathlib import Path
import numpy as np
from .export import META, sha256
from engine import decode_line, tshark_command


def write_csv(path, fields, rows):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator='\n')
        writer.writeheader()
        writer.writerows(rows)


def export_one(spec, out):
    """Return catalogue entry and two manifest rows, angles and protocol only."""
    cid, code = spec['capture_id'], spec['client']
    if not re.fullmatch(r'CAP\d{4}', cid) or not re.fullmatch(r'C0[1-5]', code):
        raise ValueError('Invalid public alias')
    client, ap = spec['client_mac'].lower(), spec['ap_mac'].lower()
    mac = r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}'
    if not re.fullmatch(mac, client) or not re.fullmatch(mac, ap) or client == ap:
        raise ValueError('Invalid link in private map')
    path = Path(spec['source'])
    before = path.stat()
    origin = float(subprocess.check_output(['tshark', '-n', '-r', str(path), '-c', '1',
        '-T', 'fields', '-e', 'frame.time_epoch'], text=True, stderr=subprocess.DEVNULL).strip())
    origin = float(spec.get('origin_epoch', origin))
    command = tshark_command(path, client, ap) + ['-Y',
        f'(wlan.ta=={client} && wlan.ra=={ap}) || (wlan.ta=={ap} && wlan.ra=={client})']
    text = subprocess.check_output(command, text=True, stderr=subprocess.DEVNULL)
    rows, rejected = [], 0
    for line in text.splitlines():
        try:
            r = decode_line(line, client, ap)
        except (ValueError, KeyError, IndexError):
            rejected += 1
            continue
        if 'psi' not in r:
            continue
        f = r['feedback']
        if not np.isfinite(r['psi']).all() or not np.isfinite(r['phi']).all():
            raise ValueError('Nonfinite decoded angles')
        values = [format(r['ts']-origin, '.9f'), code, 'AP01', f['direction'], f['kind'],
            f['nr'], f['nc'], f['grouping'], f['width'], f['feedback'], f['codebook'],
            f['bits_psi'], f['subcarriers'], r['series_id']]
        row = dict(zip(META, values))
        for family in ('psi', 'phi'):
            row.update({f'{family}_{i:04d}_rad': format(float(v), '.9g') for i,v in enumerate(r[family])})
        row['rssi_dbm'] = r['rssi']
        row['bits_phi'] = f.get('bits_phi', '')
        rows.append(row)
    psi = sorted({k for r in rows for k in r if k.startswith('psi_')})
    phi = sorted({k for r in rows for k in r if k.startswith('phi_')})
    derived = Path(out)/'captures'/f'{cid}.csv'
    write_csv(derived, META + ['bits_phi','rssi_dbm'] + psi + phi, rows)

    # Extract only own beacons, the declared pair's BFI and unicast NDPA.
    fields = ['frame.time_epoch','wlan.fc.type_subtype','wlan.ta','wlan.ra',
        'radiotap.dbm_antsignal','wlan.vht.compressed_beamforming_report','wlan.seq',
        'wlan.fc.retry','radiotap.datarate']
    display = f'(wlan.ta=={ap} && wlan.fc.type_subtype==8) || (wlan.ta=={ap} && wlan.ra=={client} && wlan.fc.type_subtype==21) || (wlan.ta=={client} && wlan.ra=={ap} && wlan.vht.compressed_beamforming_report)'
    cmd = ['tshark','-n','-r',str(path),'-Y',display,'-T','fields','-E','separator=|','-E','occurrence=a']
    cmd += [v for field in fields for v in ('-e',field)]
    packets = []
    for line in subprocess.check_output(cmd,text=True,stderr=subprocess.DEVNULL).splitlines():
        values = line.split('|')
        if len(values) != len(fields): raise ValueError('Invalid packet export')
        ts, subtype, ta, ra, rss, report, seq, retry, rate = values
        subtype = int(subtype,0)
        if ta==ap and subtype==8: kind, transmitter, receiver = 'beacon','AP01','broadcast'
        elif ta==ap and ra==client and subtype==21: kind, transmitter, receiver = 'ndpa','AP01',code
        elif ta==client and ra==ap and report: kind, transmitter, receiver = 'bfi',code,'AP01'
        else: raise ValueError('Unexpected packet outside selected scope')
        packets.append(dict(t_rel_s=format(float(ts)-origin,'.9f'),kind=kind,transmitter=transmitter,
            receiver=receiver,rssi_dbm=max(map(float,rss.split(','))) if rss else '',
            retry=retry,rate_mbps=rate))
    packet_file = Path(out)/'protocol'/f'{cid}.csv'
    write_csv(packet_file,['t_rel_s','kind','transmitter','receiver','rssi_dbm','retry','rate_mbps'],packets)
    after=path.stat()
    if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):
        raise ValueError('Source changed during export')
    digest=sha256(path)
    catalog=dict(capture_id=cid,client=code,ap='AP01',protocol=spec['protocol'],condition=spec['condition'],
        preparation_s=spec['preparation_s'],planned_duration_s=spec['duration_s'],decoded_rows=len(rows),
        observed_reports=sum(r['kind']=='bfi' for r in packets),rejected_reports=rejected)
    manifest=[dict(capture_id=cid,pcap_sha256=digest,derived_file=str(p.relative_to(out)).replace('\\','/'),
                   derived_sha256=sha256(p)) for p in (derived,packet_file)]
    return catalog, manifest


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--private-map',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    catalog,manifest=[],[]
    for spec in json.loads(a.private_map.read_text()):
        entry,hashes=export_one(spec,a.out)
        catalog.append(entry);manifest.extend(hashes)
        print(entry['capture_id'],entry['decoded_rows'],flush=True)
    write_csv(a.out/'catalog.csv',list(catalog[0]),catalog)
    write_csv(a.out/'MANIFEST.csv',list(manifest[0]),manifest)

if __name__=='__main__':main()
