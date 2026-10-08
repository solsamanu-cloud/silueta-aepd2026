"""Numerical and synthetic export checks for the controlled-test supplement."""
import csv
import sys
import tempfile
import unittest
from pathlib import Path
import numpy as np
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from silueta.controlled import robot_scores, summarize_robot, angles


class ControlledTests(unittest.TestCase):
    def test_circular_phase_does_not_turn_wrap_into_large_motion(self):
        t=np.arange(20.)
        phi=np.where(np.arange(20)%2,.01,2*np.pi-.01)[:,None]
        psi=np.ones((20,1))*.3
        score,_=robot_scores(t,psi,phi)
        self.assertLess(score[-1,1],.0001)
        self.assertAlmostEqual(score[-1,0],0)

    def test_gap_invalidates_window_but_does_not_become_zero(self):
        t=np.array([0.,1.,2.,3.,4.,10.,11.,12.,13.,14.,15.,16.])
        score,_=robot_scores(t,np.ones((len(t),1)),np.ones((len(t),1)))
        self.assertTrue(np.isnan(score[5,0]))
        self.assertTrue(np.isfinite(score[-1,0]))

    def test_phase_boundary_excludes_six_seconds_before_comparison(self):
        t=np.arange(721.)
        y=np.zeros((721,1));phi=y.copy()
        y[420:426]=100
        r,_,_,compare=summarize_robot(t,y,phi,420,720)
        self.assertEqual(r['n_bfi_300s'],300)
        self.assertEqual(t[compare][0],426)
        self.assertEqual(r['valid'],294)

    def test_reject_configuration_mix(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'angles.csv'
            p.write_text('t_rel_s,series_id,psi_0000_rad,phi_0000_rad\n0,one,0.1,0.2\n1,two,0.2,0.3\n')
            with self.assertRaisesRegex(ValueError,'one configuration'):angles(p)

    def test_extended_export_is_relative_and_contains_only_public_aliases(self):
        from dependency_support import require_tshark
        from silueta.synthetic import generate,CLIENT,AP
        from silueta.controlled_export import export_one
        from engine import tshark_command
        require_tshark(tshark_command('synthetic.pcap',CLIENT,AP))
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp);pcap=generate(folder/'original.pcap',12)
            row,manifest=export_one(dict(capture_id='CAP0001',client='C01',client_mac=CLIENT,ap_mac=AP,
                source=str(pcap),protocol='robot',condition='synthetic',preparation_s=0,duration_s=12),folder/'data')
            self.assertEqual(row['decoded_rows'],60)
            self.assertEqual(len(manifest),2)
            for item in manifest:
                text=(folder/'data'/item['derived_file']).read_text()
                self.assertNotIn(CLIENT,text);self.assertNotIn(AP,text)
                rows=list(csv.DictReader(text.splitlines()))
                self.assertEqual(float(rows[0]['t_rel_s']),0)
            self.assertIn('phi_0000_rad',(folder/'data/captures/CAP0001.csv').read_text())

if __name__=='__main__':unittest.main()
