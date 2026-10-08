"""Exercise the installed libpcap compiler and packet filter, not just strings."""
from pathlib import Path
import struct,subprocess,sys,tempfile,unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'live'))
from discovery import DISCOVERY_BPF

class DiscoveryBpfTests(unittest.TestCase):
 def setUp(self):
  from dependency_support import require_command
  require_command("tcpdump")
 def test_compiles_for_radiotap_without_privileges(self):
  subprocess.run(['tcpdump','-y','IEEE802_11_RADIO','-ddd',DISCOVERY_BPF],check=True,capture_output=True)
 def test_management_data_ndpa_and_excluded_other_control(self):
  # Exhaust all frame types/subtypes; filtering uses FC, not the following body.
  with tempfile.TemporaryDirectory() as folder:
   source=Path(folder)/'all.pcap';dest=Path(folder)/'kept.pcap'
   header=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,127)
   radiotap=b'\x00\x00\x08\x00\x00\x00\x00\x00'
   with source.open('wb') as f:
    f.write(header)
    for kind in range(4):
     for subtype in range(16):
      fc=(subtype<<4)|(kind<<2);frame=radiotap+bytes([fc,0])+bytes(30)
      f.write(struct.pack('<IIII',fc+1,0,len(frame),len(frame))+frame)
   subprocess.run(['tcpdump','-n','-r',str(source),'-w',str(dest),DISCOVERY_BPF],check=True,capture_output=True)
   data=dest.read_bytes();offset=24;got=[]
   while offset<len(data):
    _,_,n,_=struct.unpack_from('<IIII',data,offset);offset+=16;got.append(data[offset+8]);offset+=n
   expected=[(subtype<<4)|(kind<<2) for kind in range(4) for subtype in range(16) if kind in (0,2) or (kind==1 and subtype==5)]
   self.assertEqual(got,expected)

if __name__=='__main__':unittest.main()
