"""Tests de lib/vht_mimo_control.py: parseo, derivados y verificación de
longitud con los valores reales observados en las capturas del proyecto."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lib.vht_mimo_control import parse, NSC_TABLE  # noqa: E402

# Valores reales del campo (uint24 LE de tshark) en viab04:
# portátil 28:cd…: 0xc48589 — 2x2, 80 MHz, Ng=2, cb=1, SU
# cliente2 d4:5e…: 0xac8488 — 2x1, 80 MHz, Ng=1, cb=1, SU
RAW_PORTATIL = (0xC48589).to_bytes(3, "little")
RAW_CLIENTE2 = (0xAC8488).to_bytes(3, "little")


class TestParse(unittest.TestCase):
    def test_portatil(self):
        c = parse(RAW_PORTATIL)
        self.assertEqual((c.nc, c.nr, c.chanwidth, c.grouping,
                          c.codebookinfo, c.feedbacktype),
                         (2, 2, 2, 1, 1, 0))

    def test_cliente2(self):
        c = parse(RAW_CLIENTE2)
        self.assertEqual((c.nc, c.nr, c.chanwidth, c.grouping,
                          c.codebookinfo, c.feedbacktype),
                         (1, 2, 2, 0, 1, 0))

    def test_longitud_incorrecta(self):
        with self.assertRaises(ValueError):
            parse(b"\x00\x00")


class TestDerivados(unittest.TestCase):
    def test_bits_codebook(self):
        c = parse(RAW_PORTATIL)
        self.assertEqual((c.bits_phi, c.bits_psi), (6, 4))
        c0 = parse((0xC48589 & ~(1 << 10)).to_bytes(3, "little"))
        self.assertEqual((c0.bits_phi, c0.bits_psi), (4, 2))

    def test_angulos_por_subportadora(self):
        self.assertEqual(parse(RAW_PORTATIL).n_angles_each, 1)   # 2x2
        self.assertEqual(parse(RAW_CLIENTE2).n_angles_each, 1)   # 2x1

    def test_tabla_nsc(self):
        self.assertEqual(NSC_TABLE[(2, 0)], 234)   # 80 MHz Ng=1
        self.assertEqual(NSC_TABLE[(2, 1)], 122)   # 80 MHz Ng=2
        self.assertEqual(NSC_TABLE[(0, 0)], 52)    # 20 MHz Ng=1

    def test_cuerpo_teorico(self):
        # portátil: 16 bits SNR + 122 subc * 10 bits = 1236 bits = 155 B
        self.assertEqual(parse(RAW_PORTATIL).expected_body_bytes(), 155)
        # cliente2: 8 bits SNR + 234 subc * 10 bits = 2348 bits = 294 B
        self.assertEqual(parse(RAW_CLIENTE2).expected_body_bytes(), 294)


class TestVerificacionLongitud(unittest.TestCase):
    def test_verificada(self):
        self.assertTrue(parse(RAW_PORTATIL).check_body_length(155))

    def test_falla_ruidosamente(self):
        with self.assertRaises(ValueError):
            parse(RAW_CLIENTE2).check_body_length(193)


if __name__ == "__main__":
    unittest.main()
