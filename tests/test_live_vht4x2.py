"""Fixed bit vectors for VHT 4x2, not a pack/unpack self-consistency test."""
from pathlib import Path
import sys
import unittest
import numpy as np
sys.path[:0] = [str(Path(__file__).resolve().parents[1]), str(Path(__file__).resolve().parents[1] / 'live')]
from engine import decode_line, FIELDS, RollingVariance

CLIENT = '02:00:00:00:00:1b'
AP = '02:00:00:00:00:20'


def report(codebook=1, body=None, remaining='0', nr='3', nc='1', feedback='0'):
    # 52 subcarriers, 2 SNR bytes. Fixed on-wire words are supplied below.
    if body is None:
        word, width = ((0x2a45121d83081, 50) if codebook else (0x39524321, 30))
        packed = sum(word << (width * k) for k in range(52))
        body = b'\x7f\x81' + packed.to_bytes((52 * width + 7) // 8, 'little')
    p = [''] * len(FIELDS)
    for i, v in {0:'100', 1:CLIENT, 2:'-81', 5:'0', 6:'0', 7:str(codebook),
                 8:feedback, 9:nc, 10:nr, 11:body.hex(), 12:AP,
                 13:'0x000e', 14:remaining}.items():
        p[i] = v
    return '|'.join(p)


class FourByTwoTests(unittest.TestCase):
    def test_codebook_one_fixed_vector_and_shape(self):
        r = decode_line(report(), CLIENT, AP)
        self.assertEqual(r['psi'].shape, (260,))
        self.assertEqual(r['phi'].shape, (260,))
        np.testing.assert_allclose(r['phi'].reshape(52, 5),
            np.tile(np.pi * (1/64 + np.array([1,2,3,4,5])/32), (52, 1)))
        np.testing.assert_allclose(r['psi'].reshape(52, 5),
            np.tile(np.pi * (1/64 + np.array([6,7,8,9,10])/32), (52, 1)))

    def test_codebook_zero_fixed_vector_and_shape(self):
        r = decode_line(report(0), CLIENT, AP)
        np.testing.assert_allclose(r['phi'].reshape(52, 5),
            np.tile(np.pi * (1/16 + np.array([1,2,3,4,5])/8), (52, 1)))
        np.testing.assert_allclose(r['psi'].reshape(52, 5),
            np.tile(np.pi * (1/16 + np.array([0,1,2,2,3])/8), (52, 1)))

    def test_bad_length_and_fragment_rejected(self):
        with self.assertRaisesRegex(ValueError, 'longitud'):
            decode_line(report(body=b'\x00'*326), CLIENT, AP)
        with self.assertRaisesRegex(ValueError, 'fragmentado'):
            decode_line(report(remaining='1'), CLIENT, AP)

    def test_invalid_geometries_and_mu_not_silently_accepted(self):
        for kw in ({'nr':'0'}, {'nc':'4'}, {'feedback':'1'}):
            with self.subTest(kw=kw), self.assertRaises(ValueError):
                decode_line(report(**kw), CLIENT, AP)

    def test_selected_direction_only(self):
        self.assertIn('psi', decode_line(report(), AP, CLIENT))
        self.assertNotEqual(decode_line(report(), AP, CLIENT)['series_id'],decode_line(report(),CLIENT,AP)['series_id'])

    def test_geometry_change_restarts_window(self):
        e = RollingVariance()
        for t in range(8):
            e.push(t, np.ones(122), (2,1,1,0,1,1), np.ones(122))
        r = decode_line(report(), CLIENT, AP)
        p = e.push(8, r['psi'], r['config'], r['phi'])
        self.assertTrue(p['config_changed']); self.assertEqual(p['variance'],0); self.assertTrue(p['single_sample'])
        for t in range(9,15):
            p = e.push(t, r['psi'], r['config'], r['phi'])
        self.assertAlmostEqual(p['variance'], 0)
        self.assertAlmostEqual(p['variance_phi'], 0)


if __name__ == '__main__': unittest.main()
