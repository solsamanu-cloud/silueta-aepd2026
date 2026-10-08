"""Tests unitarios de lib/bfi_parser.py y lib/presence.py.

Generan un pcap sintético mínimo (radiotap + 802.11 Action No Ack con
informe VHT comprimido fabricado a mano) y verifican el parser y las
métricas sin tocar la red ni capturas reales.
"""

import os
import struct
import sys
import tempfile
import unittest

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lib import bfi_parser, presence  # noqa: E402

AP = b"\x02\x00\x00\x00\x00\x06"
STA = b"\x02\x00\x00\x00\x00\x01"
# MIMO control real observado en viab04 (Nc2/Nr2, 80 MHz, Ng2, SU, codebook 1)
MIMO_A = bytes([0x89, 0x85, 0xc4])
# Misma cabecera pero grouping=3 -> configuración distinta
MIMO_B = bytes([0x89, 0x86, 0xc4])


def _radiotap(signal_dbm):
    # Cabecera radiotap mínima: present = bit5 (dbm_antsignal), longitud 9
    return struct.pack("<BBHI", 0, 0, 9, 0x20) + struct.pack("b", signal_dbm)


def _action_frame(mimo, matrix, signal_dbm=-60):
    fc = b"\xe0\x00"          # Action No Ack (subtipo 14)
    dur = b"\x00\x00"
    hdr = fc + dur + AP + STA + AP + b"\x10\x00"
    body = b"\x15\x00" + mimo + matrix   # categoría 21 (VHT), acción 0
    return _radiotap(signal_dbm) + hdr + body


def _write_pcap(path, frames_ts):
    """frames_ts: lista de (epoch_segundos, bytes_de_trama)."""
    out = [struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127)]
    for ts, frame in frames_ts:
        sec = int(ts)
        usec = int((ts - sec) * 1e6)
        out.append(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
        out.append(frame)
    with open(path, "wb") as fh:
        fh.write(b"".join(out))


def _synthetic_pcap(path):
    m1 = bytes(range(32))
    m2 = bytes(range(31, -1, -1))
    m3 = bytes(range(16))          # longitud distinta (config B)
    frames = [
        (1785000000.000, _action_frame(MIMO_A, m1, -60)),
        (1785000000.500, _action_frame(MIMO_A, m2, -61)),
        (1785000001.000, _action_frame(MIMO_B, m3, -62)),
    ]
    _write_pcap(path, frames)
    return m1, m2, m3


class TestBfiParser(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from dependency_support import require_tshark
        require_tshark(["tshark"] + [a for f in bfi_parser.FIELDS for a in ("-e",f)])
        cls.tmp = tempfile.TemporaryDirectory()
        cls.pcap = os.path.join(cls.tmp.name, "sintetico.pcap")
        cls.m1, cls.m2, cls.m3 = _synthetic_pcap(cls.pcap)
        cls.df, cls.configs = bfi_parser.parse_pcap(cls.pcap)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_cuenta_tramas(self):
        self.assertEqual(len(self.df), 3)

    def test_dos_configuraciones(self):
        self.assertEqual(len(self.configs), 2)
        longitudes = {cid: c["body_lengths"] for cid, c in self.configs.items()}
        self.assertEqual(sorted(v[0] for v in longitudes.values()), [16, 32])

    def test_cuerpo_crudo_intacto(self):
        # Las dos primeras tramas comparten longitud (32): comprobar por
        # posición, no por longitud. np.frombuffer: un array uint8 nunca es
        # "igual" a un objeto bytes para numpy.testing.
        for i, esperado in enumerate((self.m1, self.m2, self.m3)):
            np.testing.assert_array_equal(
                self.df.iloc[i]["body"],
                np.frombuffer(esperado, dtype=np.uint8))

    def test_campos_basicos(self):
        self.assertEqual(self.df.iloc[0]["ta"],
                         ":".join(f"{b:02x}" for b in STA))
        self.assertAlmostEqual(self.df.iloc[0]["rssi"], -60.0)
        self.assertAlmostEqual(self.df.iloc[1]["ts"] - self.df.iloc[0]["ts"],
                               0.5, places=3)

    def test_segmentacion_corta_en_cambio_config(self):
        segs = presence.segment_by_config(self.df)
        self.assertEqual(len(segs), 2)
        self.assertEqual(len(segs[0]), 2)
        self.assertEqual(len(segs[1]), 1)


class TestPresence(unittest.TestCase):
    def _seg(self, bodies, dts):
        ts = np.cumsum([0.0] + list(dts))
        return pd.DataFrame({
            "ts": ts,
            "ta": "02:00:00:00:00:22",
            "config_id": 0,
            "body": [np.array(b, dtype=np.uint8) for b in bodies],
        })

    def test_euclidea(self):
        seg = self._seg([[0, 0], [3, 4]], [1.0])
        d = presence.pairwise_distance(seg, "euclidean")
        self.assertAlmostEqual(d.iloc[0]["distance"], 5.0)
        # norm "divide" por defecto: 5 / 1 s
        self.assertAlmostEqual(d.iloc[0]["value"], 5.0)

    def test_coseno(self):
        seg = self._seg([[1, 0, 0], [0, 1, 0]], [0.5])
        d = presence.pairwise_distance(seg, "cosine")
        self.assertAlmostEqual(d.iloc[0]["distance"], 1.0)  # ortogonales

    def test_hamming_bits(self):
        seg = self._seg([[0b00000000], [0b00000011]], [1.0])
        d = presence.pairwise_distance(seg, "hamming")
        self.assertAlmostEqual(d.iloc[0]["distance"], 2.0)

    def test_pearson_identicos(self):
        seg = self._seg([[1, 2, 3], [1, 2, 3]], [1.0])
        d = presence.pairwise_distance(seg, "pearson")
        self.assertAlmostEqual(d.iloc[0]["distance"], 0.0)

    def test_norm_threshold_descarta(self):
        seg = self._seg([[0], [1], [2]], [0.5, 5.0])
        d = presence.pairwise_distance(seg, "euclidean",
                                       norm="threshold", max_dt=2.0)
        self.assertEqual(len(d), 1)
        self.assertEqual(d.skipped_dt, 1)

    def test_norm_band(self):
        # dts 0.02, 0.1, 0.5: la banda [0.05, 0.3] solo conserva el de 0.1
        seg = self._seg([[0], [1], [2], [3]], [0.02, 0.1, 0.5])
        d = presence.pairwise_distance(seg, "euclidean",
                                       norm="band", dt_min=0.05, max_dt=0.3)
        self.assertEqual(len(d), 1)
        self.assertAlmostEqual(d.iloc[0]["dt"], 0.1)
        self.assertEqual(d.skipped_dt, 2)
        # value = distancia cruda (sin dividir)
        self.assertAlmostEqual(d.iloc[0]["value"], d.iloc[0]["distance"])

    def test_longitudes_distintas_se_descartan(self):
        seg = self._seg([[0, 0], [1]], [1.0])
        d = presence.pairwise_distance(seg, "euclidean")
        self.assertEqual(len(d), 0)
        self.assertEqual(d.skipped_len, 1)

    def test_rolling_stats(self):
        bodies = [[i, i + 1] for i in range(20)]
        dts = [1.0] * 19
        seg = self._seg(bodies, dts)
        d = presence.pairwise_distance(seg, "euclidean")
        rs = presence.rolling_stats(d, window_s=10.0)
        self.assertEqual(len(rs), len(d))
        self.assertTrue((rs["var"] >= 0).all())
        self.assertTrue((rs["n"] >= 1).all())

    def test_metrica_desconocida(self):
        seg = self._seg([[0], [1]], [1.0])
        with self.assertRaises(ValueError):
            presence.pairwise_distance(seg, "manhattan")


if __name__ == "__main__":
    unittest.main()
