#!/usr/bin/env python3
"""Verify derived files and optionally privately supplied original PCAP."""
import argparse,csv,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from silueta.export import sha256
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--private-map',type=Path);a=p.parse_args()
mapping={s['capture_id']:s['source'] for s in json.loads(a.private_map.read_text())} if a.private_map else {}
with (ROOT/'data/MANIFEST.csv').open() as f:entries=list(csv.DictReader(f))
for e in entries:
 source=(ROOT/'data'/e['derived_file']).resolve()
 if ROOT/'data' not in source.parents:raise SystemExit('Invalid manifest path')
 if sha256(source)!=e['derived_sha256']:raise SystemExit('Derived hash mismatch: '+e['capture_id'])
 if a.private_map:
  if e['capture_id'] not in mapping or sha256(mapping[e['capture_id']])!=e['pcap_sha256']:raise SystemExit('Original hash mismatch: '+e['capture_id'])
print('Verified',len(entries),'derived files'+(' and private originals' if a.private_map else '; originals not supplied'))
