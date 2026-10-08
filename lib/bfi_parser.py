"""Extract VHT compressed feedback with tshark.

Preserve each frame configuration and reject inconsistent payload lengths.
Local packet identifiers are used only while reading private PCAP files.
The public exporter emits aliases and relative time only.
"""

import subprocess
import sys

import numpy as np
import pandas as pd

# Campos verificados contra tshark 3.4.16 (tshark -G fields). No asumir
# nombres: se comprueban en tiempo de ejecución antes de lanzar la lectura.
# NOTA: el subcampo '.feedback_matrix' sale vacío en tshark 3.4.16; el campo
# padre devuelve el informe completo en hex (byte SNR + matriz comprimida).
# Para las métricas de divergencia sirve tal cual: es la representación
# cruda consistente del informe (ver amenaza a la validez nº 5 de la tarea).
FIELDS = [
    "frame.time_epoch",
    "wlan.ta",
    "radiotap.dbm_antsignal",
    "frame.len",
    "wlan.vht.action",
    "wlan.vht.mimo_control.chanwidth",
    "wlan.vht.mimo_control.grouping",
    "wlan.vht.mimo_control.codebookinfo",
    "wlan.vht.mimo_control.feedbacktype",
    "wlan.vht.mimo_control.ncindex",
    "wlan.vht.mimo_control.nrindex",
    "wlan.vht.compressed_beamforming_report",
    "wlan.ra",
]

# Solo tramas con informe comprimido VHT; el display filter cubre tanto el
# subtipo Action (13) como Action No Ack (14), que es como llega el BFI de
# algunos clientes (observado en la campaña viab04/T1-T4).
DISPLAY_FILTER = "wlan.vht.compressed_beamforming_report"

CONFIG_COLUMNS = ["chanwidth", "grouping", "codebookinfo",
                  "feedbacktype", "ncindex", "nrindex"]

# Columnas de configuración del HE MIMO Control (802.11ax). Además de las
# del VHT lleva remaining/first segment y RU start/end (faltan en VHT).
HE_CONFIG_COLUMNS = ["chanwidth", "grouping", "codebookinfo", "feedbacktype",
                     "ncindex", "nrindex", "remaining_segments", "first_segment",
                     "ru_start", "ru_end", "sounding_token"]

# (bit, alineación, tamaño) de los campos radiotap (namespace estándar).
# Bits 28-31 son indicadores de namespace/NS y no campos; solo 0-27.
RADIOTAP_FIELDS = [
    (0, 8, 8), (1, 1, 1), (2, 1, 1), (3, 2, 4), (4, 1, 2), (5, 1, 1),
    (6, 1, 1), (7, 2, 2), (8, 2, 2), (9, 2, 2), (10, 1, 1), (11, 1, 1),
    (12, 1, 1), (13, 1, 1), (14, 2, 2), (15, 2, 2), (16, 1, 1), (17, 1, 1),
    (18, 1, 3), (19, 4, 8), (20, 2, 12), (21, 2, 12), (22, 2, 13),
    (23, 2, 17), (24, 2, 1), (25, 4, 4), (26, 1, 4), (27, 4, 12),
]

# Categoría HE y acción "HE Compressed Beamforming And CQI" (802.11ax).
HE_CATEGORY = 0x1E
HE_ACTION_BFI_CQI = 0


def _check_fields():
    """Verifica los nombres de campo contra la versión de tshark instalada."""
    res = subprocess.run(["tshark", "-G", "fields"],
                         capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"no se pudo obtener 'tshark -G fields': {res.stderr}")
    available = set(res.stdout.split())
    missing = [f for f in FIELDS if f not in available]
    if missing:
        raise RuntimeError(
            "campos no disponibles en esta versión de tshark: "
            + ", ".join(missing))


def _to_int(value, default=-1):
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return default


def parse_pcap(pcap_path):
    """Lee un pcap y devuelve (DataFrame, dict de configuraciones).

    DataFrame: una fila por informe, columnas
      ts (float, epoch), ta (str), rssi (float|NaN, mejor antena),
      frame_len (int), body_len (int), config_id (int), body (np.uint8).
    configs: {config_id: {chanwidth, grouping, codebookinfo, feedbacktype,
                          ncindex, nrindex, n_frames, body_lengths}}
    """
    _check_fields()
    cmd = ["tshark", "-r", str(pcap_path), "-Y", DISPLAY_FILTER,
           "-T", "fields", "-E", "separator=|", "-E", "occurrence=f"]
    for field in FIELDS:
        cmd += ["-e", field]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"tshark falló leyendo {pcap_path}: {res.stderr.strip()}")

    rows = []
    configs = {}
    config_ids = {}
    for line in res.stdout.splitlines():
        parts = line.split("|")
        if len(parts) < len(FIELDS):
            continue
        (ts, ta, rssi, flen, _action, chanw, grouping, codebook,
         fbtype, ncidx, nridx, matrix_hex, ra) = parts[:len(FIELDS)]
        try:
            ts = float(ts)
        except ValueError:
            continue
        # RSSI multi-antena ("-69,-72,-72"): nos quedamos con el mejor.
        try:
            rssi_val = max(float(v) for v in rssi.split(",") if v)
        except ValueError:
            rssi_val = np.nan
        body = (np.frombuffer(bytes.fromhex(matrix_hex.replace(":", "")),
                              dtype=np.uint8)
                if matrix_hex else np.array([], dtype=np.uint8))
        key = tuple(_to_int(v) for v in
                    (chanw, grouping, codebook, fbtype, ncidx, nridx))
        if key not in config_ids:
            config_ids[key] = len(config_ids)
            configs[config_ids[key]] = dict(
                zip(CONFIG_COLUMNS, key), n_frames=0, body_lengths=set())
        cid = config_ids[key]
        configs[cid]["n_frames"] += 1
        configs[cid]["body_lengths"].add(int(body.size))
        rows.append({"ts": ts, "ta": ta.lower(), "ra": ra.lower(), "rssi": rssi_val,
                     "frame_len": _to_int(flen), "body_len": int(body.size),
                     "config_id": cid, "body": body})

    df = pd.DataFrame(rows)
    if not df.empty:
        df = df.sort_values("ts").reset_index(drop=True)
    for cfg in configs.values():
        cfg["body_lengths"] = sorted(cfg["body_lengths"])
    return df, configs


def _read_pcap_records(pcap_path):
    """Lee un pcap (magic little o big endian) y devuelve (linktype,
    [(ts_epoch, paquete_con_radiotap), ...])."""
    import struct
    with open(pcap_path, "rb") as fh:
        data = fh.read()
    if len(data) < 24:
        return 127, []
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    else:
        raise RuntimeError(f"magic de pcap no reconocido: {magic.hex()}")
    _maj, _min, _tz, _sig, _snaplen, linktype = struct.unpack(
        endian + "HHiiii", data[4:24])
    recs = []
    off = 24
    try:
        while off + 16 <= len(data):
            ts_sec, ts_usec, incl_len, _orig = struct.unpack(
                endian + "IIII", data[off:off + 16])
            off += 16
            pkt = data[off:off + incl_len]
            off += incl_len
            recs.append((ts_sec + ts_usec / 1e6, pkt))
    except (IndexError, struct.error):
        pass
    return linktype, recs


def parse_pcap_he(pcap_path):
    """Extrae informes HE Compressed Beamforming And CQI (802.11ax)
    leyendo el pcap directamente.

    tshark no expone el cuerpo HE comprimido crudo como campo (solo la
    disección), así que este parser lee el pcap por sí mismo: cabecera
    radiotap (walker de campos, validado contra tramas reales del ALFA),
    cabecera 802.11 de gestión y el cuerpo de la acción HE.

    Devuelve (DataFrame, configs) con la MISMA estructura que parse_pcap:
      ts, ta, ra, rssi, frame_len, body_len, config_id, body
    donde body = SNR (1 byte por flujo, Nc) + matriz comprimida, SIN los
    5 bytes del HE MIMO Control (que van en la configuración).
    """
    from lib.he_mimo_control import parse as parse_he_mimo

    configs = {}
    config_ids = {}
    rows = []

    _, recs = _read_pcap_records(pcap_path)
    for ts, pkt in recs:
        row = _he_report_from_packet(ts, pkt, parse_he_mimo)
        if row is not None:
            rows.append(row)

    for row in rows:
        cfg = row["_he_cfg"]
        # sounding_token NO forma parte de la configuración: varía por
        # sondeo (es un número de diálogo). El resto sí.
        key = tuple(getattr(cfg, k) for k in
                    ("chanwidth", "grouping", "codebookinfo", "feedbacktype",
                     "nc", "nr", "remaining_segments", "first_segment",
                     "ru_start", "ru_end"))
        if key not in config_ids:
            config_ids[key] = len(config_ids)
            configs[config_ids[key]] = dict(
                zip(HE_CONFIG_COLUMNS,
                    (cfg.chanwidth, cfg.grouping, cfg.codebookinfo,
                     cfg.feedbacktype, cfg.nc - 1, cfg.nr - 1,
                     cfg.remaining_segments, cfg.first_segment,
                     cfg.ru_start, cfg.ru_end, cfg.sounding_token)),
                n_frames=0, body_lengths=set())
        row["config_id"] = config_ids[key]
        configs[row["config_id"]]["n_frames"] += 1
        configs[row["config_id"]]["body_lengths"].add(int(row["body_len"]))
        configs[row["config_id"]]["sounding_token"] = cfg.sounding_token

    df = pd.DataFrame([{k: v for k, v in r.items() if k != "_he_cfg"}
                       for r in rows])
    if not df.empty:
        df = df.sort_values("ts").reset_index(drop=True)
    for cfg in configs.values():
        cfg["body_lengths"] = sorted(cfg["body_lengths"])
    return df, configs


def _he_report_from_packet(ts, pkt, parse_he_mimo):
    """Devuelve una fila si pkt (con radiotap) contiene un informe HE BFI,
    o None. Separado para poder testearlo por unidad."""
    if len(pkt) < 8:
        return None
    if pkt[0] != 0:  # revisión de radiotap
        return None
    hlen = pkt[2] | (pkt[3] << 8)
    if hlen < 8 or hlen + 26 > len(pkt):
        return None
    f = pkt[hlen:]
    fc = f[0] | (f[1] << 8)
    ftype = (fc >> 2) & 0x3
    fsub = (fc >> 4) & 0xF
    if ftype != 0 or fsub not in (13, 14):   # gestión, Action / Action No Ack
        return None
    if f[24] != HE_CATEGORY or f[25] != HE_ACTION_BFI_CQI:
        return None
    body = f[26:]
    if len(body) < 6:
        return None
    try:
        cfg = parse_he_mimo(body[:5])
    except ValueError:
        return None
    n_snr = cfg.nc
    if len(body) < 5 + n_snr:
        return None
    snr_bytes = body[5:5 + n_snr]
    matrix = body[5 + n_snr:]
    body_bytes = np.frombuffer(snr_bytes + matrix, dtype=np.uint8)
    rssi = _radiotap_rssi(pkt)
    ta = ":".join(f"{b:02x}" for b in f[10:16])
    ra = ":".join(f"{b:02x}" for b in f[4:10])
    return {
        "ts": ts, "ta": ta, "ra": ra, "rssi": rssi,
        "frame_len": len(pkt), "body_len": int(body_bytes.size),
        "config_id": -1, "body": body_bytes, "_he_cfg": cfg,
    }


def _radiotap_fields(pkt):
    """Recorre los campos radiotap (namespace estándar, múltiples palabras
    present con bit NS/ext) y devuelve {bit: [bytes, ...]} por campo.

    Primero se leen TODAS las palabras present (encadenadas por el bit NS);
    después se caminan los campos en orden. Validado contra tramas reales
    del ALFA MT7612U (3 palabras present, 3 señales de antena)."""
    if len(pkt) < 8 or pkt[0] != 0:
        return {}
    total = pkt[2] | (pkt[3] << 8)
    if total > len(pkt) or total < 8:
        return {}
    words = []
    off = 4
    while True:
        if off + 4 > total:
            return {}
        word = (pkt[off] | (pkt[off + 1] << 8) | (pkt[off + 2] << 16)
                | (pkt[off + 3] << 24))
        words.append(word)
        off += 4
        if not (word & 0x80000000):  # bit NS: ¿hay otra palabra present?
            break
    fields = {}
    for word in words:
        for bit, align, size in RADIOTAP_FIELDS:
            if not (word & (1 << bit)):
                continue
            pad = (-off) % align
            off += pad
            if off + size > total:
                return {}
            fields.setdefault(bit, []).append(pkt[off:off + size])
            off += size
    return fields


def _radiotap_rssi(pkt):
    """Mejor RSSI (dBm) de las señales de antena del radiotap, o NaN."""
    vals = _radiotap_fields(pkt).get(5, [])  # bit 5: dBm Antenna Signal
    if not vals:
        return np.nan
    dbm = [int.from_bytes(v, "little", signed=True) for v in vals]
    return float(max(dbm))


def parse_pcap_ndpa(pcap_path):
    """NDPA VHT de control (type/subtype 0x15), disección de tshark.

    No es una acción de categoría 7. Se usa la disección independiente de
    Wireshark para interpretar cabecera, FCS, AID12, feedback de 1 bit y
    token de 6 bits. HE/EHT NDPA no se reinterpretan como VHT.
    Fuente: Wireshark packet-ieee80211.c y campos wlan.vht_ndp.sta_info.*.
    El filtro de captura de gestión/acción NO captura estas tramas.
    """
    fields = ["frame.time_epoch", "wlan.ta", "wlan.ra",
              "wlan.ndp.token.number", "wlan.vht_ndp.sta_info.aid12",
              "wlan.vht_ndp.sta_info.feedback_type",
              "wlan.vht_ndp.sta_info.nc_index"]
    cmd = ["tshark", "-r", str(pcap_path), "-Y",
           "wlan.fc.type_subtype == 0x15 && wlan.vht_ndp.sta_info.aid12 && ! _ws.malformed",
           "-T", "fields", "-E", "separator=|", "-E", "occurrence=a"]
    for field in fields:
        cmd.extend(["-e", field])
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f"tshark NDPA: {result.stderr.strip()}")
    rows = []
    for line in result.stdout.splitlines():
        values = line.split("|")
        if len(values) != len(fields):
            continue
        ts, ta, ra, token, aids, feedback, nc = values
        ids = [_to_int(x) for x in aids.split(",")]
        fb = [int(x.lower() in ("1", "true")) for x in feedback.split(",")]
        # Nc es reservado en SU y tshark no lo expone: no inventar 0.
        mu_nc = iter(_to_int(x) for x in nc.split(",") if x)
        if len(ids) != len(fb):
            raise RuntimeError("NDPA: listas STA incoherentes")
        sta = [(aid, mode, next(mu_nc, None) if mode else None)
               for aid, mode in zip(ids, fb)]
        rows.append(dict(ts=float(ts), ta=ta.lower(), ra=ra.lower(),
                         dialog_token=_to_int(token), n_sta=len(sta), sta_info=sta))
    return pd.DataFrame(rows, columns=["ts", "ta", "ra", "dialog_token", "n_sta", "sta_info"])


def main(argv):
    """Uso de depuración: bfi_parser.py <pcap> — resumen de configuraciones."""
    if len(argv) != 2:
        print(__doc__)
        return 2
    df, configs = parse_pcap(argv[1])
    print(f"informes: {len(df)}  configuraciones: {len(configs)}")
    for cid, cfg in configs.items():
        print(f"  config {cid}: {cfg['n_frames']} tramas, "
              f"longitudes {cfg['body_lengths']}, "
              f"bw={cfg['chanwidth']} ng={cfg['grouping']} "
              f"nc={cfg['ncindex']} nr={cfg['nrindex']} "
              f"fb={cfg['feedbacktype']} cb={cfg['codebookinfo']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
