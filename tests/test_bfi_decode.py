"""Synthetic vectors and analytical reference tests. No real captures."""

import os
import sys
import unittest

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lib import bfi_decode  # noqa: E402
from lib.vht_mimo_control import VhtMimoControl  # noqa: E402

PORTATIL = "02:00:00:00:00:01"

CFG_2X2 = VhtMimoControl(nc=2, nr=2, chanwidth=2, grouping=1,
                         codebookinfo=1, feedbacktype=0,
                         remaining_segments=0, first_segment=0,
                         sounding_token=0)
CFG_2X1 = VhtMimoControl(nc=1, nr=2, chanwidth=2, grouping=0,
                         codebookinfo=1, feedbacktype=0,
                         remaining_segments=0, first_segment=0,
                         sounding_token=0)




class TestSintetico(unittest.TestCase):
    def test_identidad_codificar_decodificar(self):
        rng = np.random.default_rng(42)
        for cfg in (CFG_2X2, CFG_2X1):
            n = 5
            phi = rng.integers(0, 2**cfg.bits_phi,
                               (n, cfg.n_subcarriers, cfg.n_angles_each))
            psi = rng.integers(0, 2**cfg.bits_psi,
                               (n, cfg.n_subcarriers, cfg.n_angles_each))
            bodies = bfi_decode.pack_indices(phi, psi, cfg)
            cfg.check_body_length(bodies.shape[1])
            phi2, psi2 = bfi_decode.unpack_indices(bodies, cfg)
            np.testing.assert_array_equal(phi, phi2)
            np.testing.assert_array_equal(psi, psi2)

    def test_codebook_se_lee_de_cabecera(self):
        # Mismo índice, codebook distinto -> longitud de cuerpo distinta.
        cfg_cb0 = VhtMimoControl(**{**CFG_2X2.__dict__, "codebookinfo": 0})
        self.assertNotEqual(cfg_cb0.expected_body_bytes(),
                            CFG_2X2.expected_body_bytes())
        self.assertEqual((cfg_cb0.bits_phi, cfg_cb0.bits_psi), (4, 2))
        self.assertEqual((CFG_2X2.bits_phi, CFG_2X2.bits_psi), (6, 4))

    def test_longitud_truncada_falla(self):
        # cliente2: 2x1, 80 MHz, Ng=1 -> 294 B teóricos; 193 B = truncado.
        with self.assertRaises(ValueError):
            CFG_2X1.check_body_length(193)

    def test_dequantize(self):
        self.assertAlmostEqual(bfi_decode.dequantize_psi(0, 4),
                               np.pi / 64, places=12)
        self.assertAlmostEqual(bfi_decode.dequantize_phi(0, 6),
                               np.pi / 64, places=12)
        self.assertAlmostEqual(bfi_decode.dequantize_psi(15, 4),
                               np.pi * (1 / 64 + 15 / 32), places=12)


if __name__ == "__main__":
    unittest.main()
