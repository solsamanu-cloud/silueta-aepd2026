"""Synthetic vectors and analytical reference tests. No real captures."""

import os
import sys
import unittest

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lib import channel_series, respiration, bfi_decode  # noqa: E402

PORTATIL = "02:00:00:00:00:01"


class TestChannelSeries(unittest.TestCase):
    def test_hampel_sustituye_outliers(self):
        rng = np.random.default_rng(42)
        x = rng.normal(0, 0.01, (50, 3))
        x[10, 0] = 5.0          # outlier claro
        y, mascara = channel_series.hampel(x, window=7, n_sigmas=3)
        self.assertTrue(mascara[10, 0])
        self.assertAlmostEqual(y[10, 0], np.median(x[:, 0]), places=2)
        # el grueso de la serie no se toca (con ruido gaussiano, algunos
        # puntos superan 3·MAD por azar; lo importante es el outlier)
        self.assertLess(mascara.mean(), 0.15)

    def test_hampel_ventana_par_falla(self):
        with self.assertRaises(ValueError):
            channel_series.hampel(np.zeros((10, 1)), window=6)

    def test_pca(self):
        rng = np.random.default_rng(0)
        base = rng.normal(size=(100, 1)) * rng.normal(size=(1, 20))
        r = channel_series.select_components(base + rng.normal(0, 0.01, (100, 20)),
                                             n_components=3)
        self.assertEqual(r["scores"].shape, (100, 3))
        self.assertGreater(r["explained"][0], 0.9)


class TestRespiration(unittest.TestCase):
    def test_sinusoide_irregular(self):
        # seno de 0,2 Hz (12 rpm) muestreado irregularmente ~0,75 Hz
        rng = np.random.default_rng(42)
        ts = np.cumsum(rng.uniform(0.9, 1.8, 160)) + 1e6
        x = np.sin(2 * np.pi * 0.2 * ts) + rng.normal(0, 0.1, len(ts))
        freqs, pot = respiration.lomb_scargle_band(ts, x)
        f_pico = freqs[np.argmax(pot)]
        self.assertAlmostEqual(f_pico, 0.2, delta=0.01)

    def test_ventanas(self):
        rng = np.random.default_rng(0)
        ts = np.cumsum(rng.uniform(0.9, 1.8, 200)) + 1e6
        x = np.sin(2 * np.pi * 0.25 * ts)
        ventanas = respiration.analyze_windows(ts, x, ventana_s=60, solape=0.5)
        self.assertGreater(len(ventanas), 0)
        for v in ventanas:
            self.assertAlmostEqual(v["f_pico"], 0.25, delta=0.02)
            self.assertGreater(v["confianza"], 3.0)




if __name__ == "__main__":
    unittest.main()
