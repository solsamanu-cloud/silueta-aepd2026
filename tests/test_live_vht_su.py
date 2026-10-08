"""VHT SU matrix layouts: fixed bit vectors and strict length validation."""
from pathlib import Path
import sys
import unittest
import numpy as np
sys.path[:0] = [str(Path(__file__).resolve().parents[1]), str(Path(__file__).resolve().parents[1] / 'live')]
from engine import decode_line, FIELDS, RollingVariance
from lib.vht_mimo_control import VhtMimoControl as OriginalConfig
from feedback import VHT_NSC
class VhtMimoControl(OriginalConfig):
    @property
    def n_subcarriers(self):return VHT_NSC[self.chanwidth][self.grouping]
from test_live_vht4x2 import report as report_4x2

CLIENT = '02:00:00:00:00:23'
AP = '02:00:00:00:00:21'


def report(nr=4, nc=4, cb=1, bw=0, ng=0, word=None, bits_per_carrier=None):
    cfg = VhtMimoControl(nc, nr, bw, ng, cb, 0, 0, 1, 0)
    # Independent fixed vectors for IEEE 802.11ac Table 8-53d, 4x3 and 4x4.
    if word is None:
        word, bits_per_carrier = ((0xb1aa45121d83081, 60) if cb else (0x5b9524321, 36))
    packed = sum(word << (bits_per_carrier*k) for k in range(cfg.n_subcarriers))
    body = bytes([0x55]*nc) + packed.to_bytes((cfg.n_subcarriers*bits_per_carrier+7)//8, 'little')
    p = ['']*len(FIELDS)
    for i,v in {0:'100',1:CLIENT,2:'-84',5:str(bw),6:str(ng),7:str(cb),8:'0',
                9:str(nc-1),10:str(nr-1),11:body.hex(),12:AP,13:'0x000e',14:'0'}.items():p[i]=v
    return '|'.join(p), cfg


class VhtSuTests(unittest.TestCase):
    def test_four_by_four_and_four_by_three_all_bandwidths_and_groupings(self):
        for nc in (3,4):
            for cb in (0,1):
                for bw in range(4):
                    for ng in range(3):
                        with self.subTest(nc=nc,cb=cb,bw=bw,ng=ng):
                            text,cfg=report(nc=nc,cb=cb,bw=bw,ng=ng)
                            row=decode_line(text,CLIENT,AP)
                            phi=np.array([1,2,3,4,5,6])
                            psi=np.array([6,7,8,9,10,11] if cb else [0,1,2,2,3,1])
                            np.testing.assert_allclose(row['phi'].reshape(-1,6),np.tile(np.pi*(1/2**cfg.bits_phi+phi/2**(cfg.bits_phi-1)),(cfg.n_subcarriers,1)))
                            np.testing.assert_allclose(row['psi'].reshape(-1,6),np.tile(np.pi*(1/2**(cfg.bits_psi+2)+psi/2**(cfg.bits_psi+1)),(cfg.n_subcarriers,1)))

    def test_three_by_one_order(self):
        # Four-bit fields phi11=1, phi21=2, then two-bit psi21=2, psi31=3.
        text,cfg=report(nr=3,nc=1,cb=0,word=0xe21,bits_per_carrier=12)
        r=decode_line(text,CLIENT,AP)
        np.testing.assert_allclose(r['phi'].reshape(-1,2),np.tile(np.pi*(1/16+np.array([1,2])/8),(52,1)))
        np.testing.assert_allclose(r['psi'].reshape(-1,2),np.tile(np.pi*(1/16+np.array([2,3])/8),(52,1)))

    def test_all_supported_dimensions_lengths_and_ranges(self):
        for nr in (2,3,4):
            for nc in range(1,nr+1):
                for cb in (0,1):
                    cfg=VhtMimoControl(nc,nr,0,0,cb,0,0,1,0)
                    text,_=report(nr=nr,nc=nc,cb=cb,word=0,bits_per_carrier=cfg.bits_per_subcarrier)
                    r=decode_line(text,CLIENT,AP)
                    self.assertEqual(len(r['phi']),52*cfg.n_angles_each)
                    self.assertTrue(np.all(r['phi']>0));self.assertTrue(np.all(r['psi']<np.pi/2))

    def test_truncated_four_by_four_not_accepted(self):
        text,_=report();p=text.split('|');p[11]=p[11][:-2]
        with self.assertRaisesRegex(ValueError,'longitud'):decode_line('|'.join(p),CLIENT,AP)

    def test_four_by_two_to_four_by_four_does_not_mix_dimensions(self):
        e=RollingVariance()
        from test_live_vht4x2 import CLIENT as C2,AP as A2
        r=decode_line(report_4x2(),C2,A2)
        for t in range(8):e.push(t,r['psi'],r['config'],r['phi'])
        r=decode_line(report()[0],CLIENT,AP)
        p=e.push(8,r['psi'],r['config'],r['phi'])
        self.assertTrue(p['config_changed']);self.assertEqual(p['variance'],0);self.assertTrue(p['single_sample'])
        for t in range(9,15):p=e.push(t,r['psi'],r['config'],r['phi'])
        self.assertAlmostEqual(p['variance'],0);self.assertAlmostEqual(p['variance_phi'],0)


if __name__=='__main__': unittest.main()
