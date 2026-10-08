"""VHT compressed feedback angle unpacking and dequantization.

Equations and field layout: IEEE 802.11ac and the references in README.
This legacy offline helper is kept for numerical reproducibility. The current
HT/VHT/HE dispatcher and general matrix layouts are in live/feedback.py.
Both phi and psi are available; phi requires circular statistics.
"""

import sys

import numpy as np

from lib import bfi_parser
from lib.vht_mimo_control import parse as parse_mimo

PHI, PSI = 0, 1


def _bits_por_angulo(cfg):
    """Bits por ángulo según codebook y tipo de feedback [H23] eq. (6)."""
    return cfg.bits_phi, cfg.bits_psi


def dequantize_phi(q, bits):
    """φq = π(1/2^b + q/2^(b−1)) ∈ [0, 2π)  [D26] eq. (5), [H23] eq. (6)."""
    return np.pi * (1.0 / 2**bits + q / 2.0**(bits - 1))


def dequantize_psi(q, bits):
    """ψq = π(1/2^(b+2) + q/2^(b+1)) ∈ [0, π/2]  [D26] eq. (6)."""
    return np.pi * (1.0 / 2**(bits + 2) + q / 2.0**(bits + 1))


def unpack_indices(bodies, cfg):
    """Desempaqueta los índices cuantizados de un lote de cuerpos.

    bodies: array (n, L) uint8 con SNR + matriz.
    Devuelve (phi_idx, psi_idx) con formas (n, n_subc, n_angulos_cada).
    Vectorizado: sin bucle por bit ni por trama.

    Empaquetado [EMPÍRICO/STD]: LSB por byte (np.unpackbits bitorder='little'
    es exactamente eso) y valor de campo con su primer bit como LSB.
    """
    bphi, bpsi = _bits_por_angulo(cfg)
    n_ang = cfg.n_angles_each
    n_subc = cfg.n_subcarriers
    snr_bits = 8 * cfg.nc                       # SNR: 1 byte por flujo [STD]
    bits = np.unpackbits(np.asarray(bodies, dtype=np.uint8),
                         axis=1, bitorder="little")
    por_subc = n_ang * (bphi + bpsi)
    cols = bits[:, snr_bits: snr_bits + n_subc * por_subc]
    bloques = cols.reshape(len(bits), n_subc, por_subc)
    phi,psi=[],[];offset=0
    # Per column: all phi, then all psi. Pair interleaving is valid only for 2xN.
    for column in range(1,min(cfg.nc,cfg.nr-1)+1):
        for family,width in ((phi,bphi),(psi,bpsi)):
            for _ in range(cfg.nr-column):
                family.append(bloques[...,offset:offset+width] @ (1<<np.arange(width)))
                offset+=width
    return np.stack(phi,axis=-1),np.stack(psi,axis=-1)


def pack_indices(phi_idx, psi_idx, cfg):
    """Empaquetado inverso de unpack_indices (para el test de identidad:
    codificar y decodificar debe ser la identidad)."""
    bphi, bpsi = _bits_por_angulo(cfg)
    n, n_subc, n_ang = phi_idx.shape
    snr_bits = 8 * cfg.nc
    par = bphi + bpsi
    total_bits = snr_bits + n_subc * n_ang * par
    total_bytes = (total_bits + 7) // 8
    bits = np.zeros((n, total_bytes * 8), dtype=np.uint8)
    region = bits[:,snr_bits:snr_bits+n_subc*n_ang*par].reshape(n,n_subc,n_ang*par)
    offset=0;angle=0
    for column in range(1,min(cfg.nc,cfg.nr-1)+1):
        count=cfg.nr-column
        for family,width in ((phi_idx,bphi),(psi_idx,bpsi)):
            for index in range(angle,angle+count):
                for j in range(width):region[...,offset+j]=(family[...,index]>>j)&1
                offset+=width
        angle+=count
    return np.packbits(bits[:, :total_bytes * 8], axis=1,
                       bitorder="little")[:, :total_bytes]


def _config(c, kind):
    from lib.vht_mimo_control import VhtMimoControl
    from lib.he_mimo_control import HeMimoControl
    args = dict(nc=c["ncindex"] + 1, nr=c["nrindex"] + 1,
                chanwidth=c["chanwidth"], grouping=c["grouping"],
                codebookinfo=c["codebookinfo"], feedbacktype=c["feedbacktype"],
                remaining_segments=c.get("remaining_segments", 0),
                first_segment=c.get("first_segment", 0),
                sounding_token=c.get("sounding_token", 0))
    if kind == "he":
        args.update(ru_start=c["ru_start"], ru_end=c["ru_end"])
    return (HeMimoControl if kind == "he" else VhtMimoControl)(**args)


def decode_parsed(df, configs, kind, ta=None, diagnostics=None):
    """Conserva todos los segmentos por enlace dirigido y configuración.

    Salida {TA: {segments: [...]}}. Para un único segmento se mantienen
    además las claves históricas ts/psi/cfg. Con varios segmentos no se
    ofrece una matriz agregada engañosa: usar segments o build_series.
    Un informe inválido corta el segmento de su enlace y queda registrado.
    """
    report_warnings = diagnostics is None
    diagnostics = diagnostics if diagnostics is not None else []
    out, active = {}, {}
    if df.empty:
        return out
    for _, row in df.sort_values("ts", kind="stable").iterrows():
        tx = str(row["ta"]).lower()
        rx = str(row.get("ra", "")).lower()
        if ta is not None and tx != ta.lower():
            continue
        link = (tx, rx)
        cid = int(row["config_id"])
        try:
            cfg = _config(configs[cid], kind)
            # El layout implementado está validado para Nr=2 y feedback SU.
            # Otras configuraciones se conservan como descartes, no se adivinan.
            if cfg.nr != 2 or cfg.nc not in (1, 2) or cfg.feedbacktype != 0:
                raise ValueError("configuración no soportada: se requiere Nr=2, Nc=1/2, SU")
            if cfg.remaining_segments:
                raise ValueError("feedback fragmentado no soportado")
            cfg.check_body_length(int(row["body_len"]))
            phi, psi = unpack_indices(np.asarray(row["body"])[None, :], cfg)
        except (ValueError, KeyError, IndexError) as exc:
            active.pop(link, None)
            diagnostics.append(dict(kind=kind, ts=float(row["ts"]), ta=tx, ra=rx,
                                    config_id=cid, reason=str(exc)))
            continue
        previous = active.get(link)
        if previous is None or previous[0] != cid:
            seg = dict(kind=kind, ta=tx, config_id=cid, cfg=cfg,
                       ts=[], ra=[], rssi=[], body_len=[], phi_idx=[], psi_idx=[])
            out.setdefault(tx, {"segments": []})["segments"].append(seg)
            active[link] = (cid, seg)
        else:
            seg = previous[1]
        seg["ts"].append(float(row["ts"]))
        seg["ra"].append(rx)
        seg["rssi"].append(float(row.get("rssi", np.nan)))
        seg["body_len"].append(int(row["body_len"]))
        seg["phi_idx"].append(phi[0])
        seg["psi_idx"].append(psi[0])
    for data in out.values():
        data["segments"].sort(key=lambda seg: seg["ts"][0])
        for seg in data["segments"]:
            for key in ("ts", "ra", "rssi", "body_len", "phi_idx", "psi_idx"):
                seg[key] = np.asarray(seg[key])
            seg["phi"] = dequantize_phi(seg["phi_idx"], seg["cfg"].bits_phi)
            seg["psi"] = dequantize_psi(seg["psi_idx"], seg["cfg"].bits_psi)
        if len(data["segments"]) == 1:
            data.update(data["segments"][0])
    if report_warnings and diagnostics:
        reasons = sorted({item["reason"] for item in diagnostics})
        print(f"[aviso] {len(diagnostics)} informes {kind} descartados: " + "; ".join(reasons), file=sys.stderr)
    return out


def decode_pcap(pcap_path, ta=None, diagnostics=None):
    """VHT: salida por TA con todos los segmentos; ver decode_parsed."""
    df, configs = bfi_parser.parse_pcap(pcap_path)
    return decode_parsed(df, configs, "vht", ta, diagnostics)


def decode_pcap_he(pcap_path, ta=None, diagnostics=None):
    """HE: no mezcla receptores aunque el transmisor sea el mismo AP."""
    df, configs = bfi_parser.parse_pcap_he(pcap_path)
    return decode_parsed(df, configs, "he", ta, diagnostics)


def magnitudes(psi):
    """|V| por subportadora a partir de ψ (2×2): [cos ψ, sin ψ].

    La magnitud no depende de φ (afectada por CFO), por eso el pipeline de
    estimación trabaja sobre ψ/magnitudes y no sobre φ.
    """
    return np.stack([np.cos(psi), np.sin(psi)], axis=-1)
