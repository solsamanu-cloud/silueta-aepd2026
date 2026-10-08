"""Capability checks: distinguish missing tools/fields from decoder failures."""
from functools import lru_cache
import shutil
import subprocess
import struct

@lru_cache(maxsize=1)
def available_tshark_fields():
    if not shutil.which('tshark'):
        raise RuntimeError('tshark is not installed; packet integration unavailable')
    r = subprocess.run(['tshark','-G','fields'],capture_output=True,text=True,timeout=60)
    if r.returncode:
        raise RuntimeError('Cannot query tshark fields: '+r.stderr.strip())
    return {parts[2] for line in r.stdout.splitlines()
            if len(parts:=line.split('\t'))>2 and parts[0] in ('F','P')}

def missing_fields(required):
    fields=available_tshark_fields()
    return sorted({f.lstrip('@') for f in required if f not in ('_ws.col.Protocol',)}-fields)

def require_fields(required):
    missing=missing_fields(required)
    if missing:
        raise RuntimeError('Installed tshark lacks fields: '+', '.join(missing)+
                           '. Full HT/VHT/HE integration validated with TShark 4.6.7; update Wireshark.')
    _check_extraction(tuple(required))

@lru_cache(maxsize=8)
def _check_extraction(required):
    # Older releases list the base field but reject the raw-byte @field syntax.
    # An empty synthetic radiotap PCAP tests the actual extraction command offline.
    command=['tshark','-n','-r','-','-T','fields']
    for field in required:
        command += ['-e',field]
    header=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,127)
    r=subprocess.run(command,input=header,capture_output=True,timeout=30)
    if r.returncode:
        raise RuntimeError('Installed tshark cannot extract required fields/syntax: '+
                           r.stderr.decode(errors='replace').strip()+
                           ' Full integration validated with TShark 4.6.7; update Wireshark.')
