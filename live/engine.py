"""Decodificación incremental y cálculo causal, sin esperar al cierre del PCAP."""
from collections import deque
import math
import hashlib
from feedback import EXTRA_FIELDS, PRESERVE_MULTIPLE, decode as decode_feedback, report_kind
import numpy as np
from lib import bfi_decode, bfi_parser

THRESHOLD = 0.006820114055593958
WINDOW = 6.0
MAX_GAP = 2.8
FIELDS = bfi_parser.FIELDS + ["wlan.fc.type_subtype", "wlan.vht.mimo_control.remainingfeedbackseg"] + EXTRA_FIELDS


def unpack_vht_su(body, cfg):
    """VHT SU: read angle groups in matrix-column order, not phi/psi pairs.

    IEEE 802.11ac-2013 Table 8-53d (page 55):
    https://schupen.net/lib/wifi/802.11ac-2013.pdf
    The 4x2 layout was also cross-checked against
    https://github.com/kfoysalhaque/Wi-BFI/blob/master/vmatrices.py
    Each column contributes Nr-column phi, then as many psi. Thus 4x4 has
    groups of 3, 2, 1, with six phi and six psi per subcarrier; 4x2 has 3, 2.
    Keep the campaign decoder unchanged. Validate body length before reading.
    """
    bits = np.unpackbits(body, bitorder='little')[8 * cfg.nc:]
    blocks = bits[:cfg.n_subcarriers * cfg.bits_per_subcarrier].reshape(
        cfg.n_subcarriers, cfg.bits_per_subcarrier)
    offset = 0
    phi, psi = [], []
    for column in range(1, min(cfg.nc, cfg.nr - 1) + 1):
        for family, width in ((phi, cfg.bits_phi), (psi, cfg.bits_psi)):
            for _ in range(cfg.nr - column):
                family.append(blocks[:, offset:offset + width] @ (1 << np.arange(width)))
                offset += width
    return np.stack(phi, axis=-1)[None, ...], np.stack(psi, axis=-1)[None, ...]


def tshark_command(source, client, ap):
    cmd = ["tshark", "-n", "-l", "-r", str(source), "-T", "fields", "-E", "separator=|", "-E", "occurrence=a", "-E", "aggregator=,"]
    # Se conservan todos los registros filtrados para establecer el origen real.
    for field in FIELDS:
        cmd += ["-e", field]
    return cmd


def decode_line(line, client, ap):
    parts = line.rstrip("\r\n").split("|")
    if len(parts) != len(FIELDS):
        raise ValueError("Registro incompleto de tshark")
    parts = [v if i==2 or FIELDS[i] in PRESERVE_MULTIPLE else v.split(',')[0]
             for i,v in enumerate(parts)]
    ts = float(parts[0])
    if not math.isfinite(ts):
        raise ValueError("Marca temporal no válida")
    tx, rx = parts[1].lower(), parts[12].lower()
    try:
        rssi = max(float(v) for v in parts[2].split(",") if v)
        if not math.isfinite(rssi):
            rssi = None
    except ValueError:
        rssi = None
    result = {"ts": ts, "ap_rssi": rssi if tx == ap and int(parts[13] or '0', 0) == 8 else None}
    if (tx,rx) not in ((client,ap),(ap,client)):
        return result
    fields=dict(zip(FIELDS,parts))
    decoded=decode_feedback(fields,unpack_vht_su)
    if decoded is None:return result
    cfg,phi,psi,key,kind=decoded
    from feedback import describe
    direction='client_to_ap' if tx==client else 'ap_to_client'
    info=describe(cfg,kind,direction)
    stream_key=key+(direction,)
    sid=hashlib.sha256(repr(stream_key).encode()).hexdigest()[:16]
    result.update(phi=bfi_decode.dequantize_phi(phi,cfg.bits_phi)[0].reshape(-1),
                  psi=bfi_decode.dequantize_psi(psi,cfg.bits_psi)[0].reshape(-1),
                  config=stream_key,rssi=rssi,series_id=sid,feedback=info)
    return result


class RollingVariance:
    def __init__(self):
        self.window = deque()
        self.config = None
        self.segment_start = 0.0
        self.last = None

    def reset(self):
        self.window.clear()
        self.config = None
        self.last = None

    def push(self, t, psi, config, phi=None):
        if self.last is not None and t <= self.last:
            self.reset()
            raise ValueError("Marca temporal repetida o retroceso del reloj")
        changed = self.config is not None and config != self.config
        if changed:
            self.window.clear()
            self.segment_start = t
        self.config = config
        self.last = t
        self.window.append((t, psi, phi))
        while self.window and self.window[0][0] < t - WINDOW:
            self.window.popleft()
        times = [r[0] for r in self.window]
        gap = max(np.diff([t - WINDOW] + times + [t]))
        reason = "valid"
        value = None
        phi_value = None
        if t - self.segment_start < WINDOW:
            reason = "warming_up"
        elif len(times) < 4 or gap > MAX_GAP:
            reason = "insufficient_bfi"
        value = float(np.mean(np.var(np.stack([r[1] for r in self.window]), axis=0, ddof=0)))
        if all(r[2] is not None for r in self.window):
            phases = np.stack([r[2] for r in self.window])
            phi_value = float(np.mean(np.clip(1 - np.abs(np.mean(np.exp(1j * phases), axis=0)), 0, 1)))
        return {"t": float(t), "variance_phi": phi_value, "variance": value, "n_window": len(times), "gap": float(gap), "quality": reason, "config_changed": changed, "single_sample": len(times)==1, "reliable": reason=="valid"}


class SeriesVariance:
    """Independent windows for each directed feedback format. No vector mixing."""
    def __init__(self):self.streams={};self.segment_start=0.0
    def reset(self):self.streams.clear()
    def push(self,t,psi,config,phi=None):
        if config not in self.streams:
            self.streams[config]=RollingVariance()
            self.streams[config].segment_start=t
        return self.streams[config].push(t,psi,config,phi)
