"""Synthetic vectors and analytical reference tests. No real captures."""

import os
import subprocess
import sys
import unittest

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lib import bfi_decode, bfi_parser  # noqa: E402
from lib.he_mimo_control import HeMimoControl, parse as parse_he_mimo  # noqa: E402

AP = "02:00:00:00:00:06"
XIAOMI = "02:00:00:00:00:04"

# Configuración real observada del Xiaomi: 2x2, 80 MHz, grouping 0 (Ng=4 HE),
# codebook 1 (SU), body 315 B.
CFG_HE = HeMimoControl(nc=2, nr=2, chanwidth=2, grouping=0,
                       codebookinfo=1, feedbacktype=0,
                       remaining_segments=0, first_segment=1,
                       ru_start=0, ru_end=36, sounding_token=0)


class TestHeMimoControl(unittest.TestCase):
    def test_parse_5_bytes_reales(self):
        # Bytes reales de la primera trama del Xiaomi.
        cfg = parse_he_mimo(bytes.fromhex("8982001206"))
        self.assertEqual((cfg.nc, cfg.nr), (2, 2))
        self.assertEqual(cfg.chanwidth, 2)          # 80 MHz
        self.assertEqual(cfg.grouping, 0)           # Ng=4 en HE
        self.assertEqual((cfg.codebookinfo, cfg.feedbacktype), (1, 0))
        self.assertEqual(cfg.ru_start, 0)
        self.assertEqual(cfg.ru_end, 0x24)
        self.assertEqual(cfg.sounding_token, 24)

    def test_mismos_bits_que_vht_su(self):
        self.assertEqual((CFG_HE.bits_phi, CFG_HE.bits_psi), (6, 4))
        self.assertEqual(CFG_HE.n_subcarriers, 250)
        self.assertEqual(CFG_HE.n_angles_each, 1)
        self.assertEqual(CFG_HE.expected_body_bytes(), 315)

    def test_grouping_he_invertido(self):
        # En HE grouping=1 significa Ng=1 (en VHT sería al revés).
        cfg1 = HeMimoControl(nc=2, nr=2, chanwidth=2, grouping=1,
                             codebookinfo=1, feedbacktype=0,
                             remaining_segments=0, first_segment=1,
                             ru_start=0, ru_end=36, sounding_token=0)
        self.assertEqual(cfg1.ng, 1)
        self.assertEqual(CFG_HE.ng, 4)

    def test_longitud_truncada_falla(self):
        with self.assertRaises(ValueError):
            CFG_HE.check_body_length(200)
        self.assertTrue(CFG_HE.check_body_length(315))


class TestSintetico(unittest.TestCase):
    def test_identidad_codificar_decodificar(self):
        rng = np.random.default_rng(42)
        n = 5
        phi = rng.integers(0, 2**CFG_HE.bits_phi,
                           (n, CFG_HE.n_subcarriers, CFG_HE.n_angles_each))
        psi = rng.integers(0, 2**CFG_HE.bits_psi,
                           (n, CFG_HE.n_subcarriers, CFG_HE.n_angles_each))
        bodies = bfi_decode.pack_indices(phi, psi, CFG_HE)
        CFG_HE.check_body_length(bodies.shape[1])
        phi2, psi2 = bfi_decode.unpack_indices(bodies, CFG_HE)
        np.testing.assert_array_equal(phi, phi2)
        np.testing.assert_array_equal(psi, psi2)




if __name__ == "__main__":
    unittest.main()
