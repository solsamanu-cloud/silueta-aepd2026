"""End-to-end synthetic decoding, streaming and publication controls."""
import csv,json,math,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
import numpy as np
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'live')]
from silueta.synthetic import generate,packet,CLIENT,AP
from silueta.export import export_capture
from silueta.analyze import spectrum
import policy,server
class ReleaseTests(unittest.TestCase):
 def test_legacy_helper_matches_independent_4x2_wire_vector(self):
  from test_live_vht4x2 import report,CLIENT as C,AP as A
  from engine import FIELDS,decode_line
  from lib.bfi_decode import unpack_indices,pack_indices,dequantize_psi
  from lib.vht_mimo_control import VhtMimoControl
  parts=report().split('|');body=np.frombuffer(bytes.fromhex(parts[11]),dtype=np.uint8)[None,:]
  cfg=VhtMimoControl(2,4,0,0,1,0,0,1,0);phi,psi=unpack_indices(body,cfg)
  np.testing.assert_allclose(dequantize_psi(psi,4).reshape(-1),decode_line(report(),C,A)['psi'])
  np.testing.assert_array_equal(pack_indices(phi,psi,cfg)[:,2:],body[:,2:])
 def test_default_configuration_cannot_capture(self):
  with patch('policy.settings',return_value={'AUTHORIZED_CAPTURE':'no'}):
   with self.assertRaisesRegex(ValueError,'consent'):policy.require_target(dict(mac=CLIENT,ap=AP))
 def test_scope_denies_foreign_peer_and_wrong_ap(self):
  from dependency_support import require_command
  require_command("tcpdump")
  with patch('policy.authorization',return_value=dict(ap=AP,clients=[dict(id='C01',mac=CLIENT)])):
   for target in (dict(mac='02:00:00:00:00:33',ap=AP),dict(mac=CLIENT,ap='02:00:00:00:00:34')):
    with self.assertRaises(ValueError):policy.require_target(target)
   bpf=policy.capture_filter()
   with tempfile.TemporaryDirectory() as d:
    source=generate(Path(d)/'synthetic.pcap',30)
    # Real libpcap compiler/parser, offline only.
    result=subprocess.run(['tcpdump','-n','-r',str(source),bpf],capture_output=True)
    self.assertEqual(result.returncode,0,result.stderr)
    result=subprocess.run(['tcpdump','-n','-r',str(source),bpf.replace(CLIENT,'02:00:00:00:00:33')],capture_output=True)
    self.assertEqual(result.returncode,0);self.assertEqual(result.stdout,b'')
 def test_export_relative_origin_aliases_and_known_frequency(self):
  from dependency_support import require_tshark
  from engine import tshark_command
  require_tshark(tshark_command("synthetic.pcap",CLIENT,AP))
  with tempfile.TemporaryDirectory() as d:
   p=generate(Path(d)/'input.pcap',120);dest=Path(d)/'derived.csv'
   result=export_capture(p,dest,CLIENT,AP,'C01');self.assertEqual(result['rows'],600);self.assertEqual(result['rejected'],0)
   with dest.open() as f:rows=list(csv.DictReader(f))
   self.assertEqual(float(rows[0]['t_rel_s']),0)
   self.assertNotIn(CLIENT,dest.read_text());self.assertEqual(rows[0]['Nr'],'2');self.assertEqual(rows[0]['Ng'],'1')
   f,power=spectrum([float(r['t_rel_s']) for r in rows],[float(r['psi_0000_rad']) for r in rows]);self.assertAlmostEqual(float(f[np.argmax(power)]),.23,places=3)
 def test_incremental_variance_before_replay_finishes(self):
  from dependency_support import require_tshark
  from engine import tshark_command
  require_tshark(tshark_command("synthetic.pcap",CLIENT,AP))
  with tempfile.TemporaryDirectory() as d:
   base=Path(d);(base/'captures/live').mkdir(parents=True);(base/'state').mkdir()
   source=generate(base/'synthetic.pcap',30)
   with patch('server.BASE',base):
    m=server.Manager(replay=source,speed=10);m.start('synthetic',None,None)
    try:
     deadline=time.monotonic()+10
     while m.bfi_count<5 and m.thread.is_alive() and time.monotonic()<deadline:time.sleep(.05)
     self.assertGreater(m.bfi_count,0,m.error);self.assertTrue(m.thread.is_alive(),'All results buffered until close')
     m.thread.join(12);self.assertFalse(m.thread.is_alive());self.assertIsNone(m.error)
     self.assertEqual(m.bfi_count,150);self.assertEqual(len((m.output/'variance.jsonl').read_text().splitlines()),150)
    finally:m.stop();m.thread.join(10)
if __name__=='__main__':unittest.main()
