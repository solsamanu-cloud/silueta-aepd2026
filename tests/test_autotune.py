"""Automatic tuning from owned-AP beacons; no physical radio in tests."""
import io
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'live')]
import autotune,policy,server
from silueta.synthetic import AP,CLIENT,mac
from dependency_support import require_tshark

def declaration():
 return dict(interface='alfa',ap=AP,clients=[dict(id='C01',mac=CLIENT)],ssid='Own network',radio_mode='auto',consent=True)
def beacon(primary=36,offset=1,width=1,c0=42,c1=0,ssid='Own network',ap=AP):
 return '\t'.join(map(str,[ap,ap,ssid.encode().hex(),5180,primary,'',offset,width,c0,c1]))+'\n'

class AutoTuneTests(unittest.TestCase):
 def setUp(self):
  tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.root=Path(tmp.name)
  guard=patch('policy.BASE',self.root);guard.start();self.addCleanup(guard.stop)
 def test_authorization_needs_no_radio_parameters(self):
  d=policy.save(declaration());self.assertEqual(d['radio_mode'],'auto')
  for key in ('frequency','channel','center','width'):self.assertNotIn(key,d)
  self.assertTrue(policy.status()['authorized']);self.assertEqual(policy.settings()['IFACE'],'alfa')
 def test_20_40_80_from_beacons(self):
  for args,expected in [((1,0,0,0,0),(2412,20,2412)),((6,1,0,0,0),(2437,40,2447)),((100,1,1,106,0),(5500,80,5530))]:
   r=autotune.parse_beacon(beacon(*args),declaration())
   self.assertEqual((r['frequency'],r['width'],r['center']),expected)
 def test_other_ap_same_ssid_is_not_accepted(self):
  self.assertIsNone(autotune.parse_beacon(beacon(ap='02:00:00:00:00:99'),declaration()))
 def test_mismatch_ssid_or_unsupported_width_stops(self):
  with self.assertRaisesRegex(ValueError,'SSID'):autotune.parse_beacon(beacon(ssid='Another network'),declaration())
  with self.assertRaisesRegex(ValueError,'160'):autotune.parse_beacon(beacon(c1=50),declaration())
  with self.assertRaises(ValueError):autotune.parse_beacon(beacon(c0=0),declaration())
 def test_hidden_ssid_uses_only_declared_bssid(self):
  self.assertEqual(autotune.parse_beacon(beacon(ssid=''),declaration())['ap'],AP)
 def test_saved_radio_is_scoped_and_no_consent_is_created(self):
  policy.save(declaration());r=autotune.parse_beacon(beacon(primary=100,c0=106),declaration());autotune.remember(r)
  self.assertEqual(policy.radio_config()['frequency'],5500)
  policy.save(dict(declaration(),ap='02:00:00:00:00:99'))
  self.assertNotEqual(policy.radio_config()['frequency'],5500)
 def test_discovery_captures_only_own_beacons_and_cleans_up(self):
  policy.save(declaration());commands=[];processes=[]
  class Proc:
   def __init__(self,cmd,**kwargs):
    commands.append(cmd);self.returncode=None;self.stdout=io.StringIO(beacon(primary=100,c0=106)) if cmd[0]=='tshark' else io.BytesIO();processes.append(self)
   def poll(self):return self.returncode
   def terminate(self):self.returncode=0
   def wait(self,**kwargs):return self.returncode
  original=dict(channel=36,frequency=5180,width=80,center=5210)
  with patch('dependencies.require_fields'),patch('autotune.os.geteuid',return_value=0),patch('radio.monitor_info',return_value=original),patch('radio.channels',return_value=[original]),patch('radio.tune'),patch('autotune.subprocess.Popen',side_effect=Proc):
   found=autotune.discover('alfa',threading.Event())
  self.assertEqual(found['channel'],100)
  self.assertIn('subtype beacon',commands[0][-1]);self.assertIn(AP,commands[0][-1]);self.assertNotIn(CLIENT,commands[0][-1])
  self.assertTrue(all(p.poll()==0 for p in processes));self.assertFalse((self.root/'captures').exists())
 def test_cancellation_restores_channel(self):
  policy.save(declaration());cancel=threading.Event();cancel.set();thread_errors=[]
  class Proc:
   def __init__(self):
    self.stdout=io.StringIO('');self.returncode=None
   def poll(self):return self.returncode
   def terminate(self):self.returncode=0
   def wait(self,**kwargs):return self.returncode
  original=dict(channel=36,frequency=5180,width=80,center=5210)
  with patch('threading.excepthook',side_effect=thread_errors.append),patch('dependencies.require_fields'),patch('radio.monitor_info',return_value=original),patch('radio.channels',return_value=[original]),patch('radio.tune') as tune,patch('autotune.subprocess.Popen',side_effect=lambda *a,**kw:Proc()):
   with self.assertRaisesRegex(ValueError,'cancelada'):autotune.discover('alfa',cancel)
   tune.assert_called_once_with('alfa',original)
  self.assertEqual(thread_errors,[])
 def test_real_tshark_beacon_fields(self):
  require_tshark(autotune.decoder_command())
  # One synthetic beacon with HT/VHT operation IEs, not a captured packet.
  body=struct.pack('<BBHI',0,0,8,0)+struct.pack('<HH',0x80,0)+b'\xff'*6+mac(AP)+mac(AP)+b'\0\0'
  ssid=b'Own network';body+=b'\0'*8+struct.pack('<HH',100,0x11)+bytes([0,len(ssid)])+ssid
  body+=bytes([61,22,36,1])+b'\0'*20+bytes([192,5,1,42,0,0,0])
  source=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,127)+struct.pack('<IIII',1000,0,len(body),len(body))+body
  result=subprocess.run(autotune.decoder_command(),input=source,capture_output=True)
  self.assertEqual(result.returncode,0,result.stderr)
  found=autotune.parse_beacon(result.stdout.decode(),declaration())
  self.assertEqual((found['frequency'],found['width'],found['center']),(5180,80,5210))
 def test_preflight_overrides_placeholder_with_fresh_beacon(self):
  from types import SimpleNamespace
  policy.save(declaration())
  with patch('server.BASE',self.root):
   m=server.Manager();m.radio=dict(channel=36,frequency=5180,width=20,center=5180)
   found=autotune.parse_beacon(beacon(primary=100,c0=106),declaration())
   with patch('server.os.geteuid',return_value=0),patch('server.Path.iterdir',return_value=[]),patch('server.shutil.disk_usage',return_value=SimpleNamespace(free=2**30)),patch('server.subprocess.run',side_effect=[SimpleNamespace(returncode=0,stdout='type monitor'),SimpleNamespace(returncode=0,stdout='')]),patch('autotune.discover',return_value=found),patch('radio.tune',return_value=found) as tune:
    try:
     m.preflight('alfa');self.assertEqual(m.radio['channel'],100);tune.assert_called_once_with('alfa',m.radio)
    finally:m.capture_lock.close()

if __name__=='__main__':unittest.main()
