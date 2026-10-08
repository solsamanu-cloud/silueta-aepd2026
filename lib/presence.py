"""Métricas de divergencia entre informes BFI consecutivos.

SIN decodificar ángulos: los cuerpos se comparan como vectores de bytes
crudos. Ver docs/METODO-presencia.md para el fundamento y la amenaza a la
validez nº 5 (la distancia entre representaciones comprimidas no es
proporcional a la distancia entre canales: sirve para discriminar, no para
cuantificar).

Decisiones documentadas (requisito de la tarea):
  - Normalización temporal: tres modos implementados.
      * "divide" (POR DEFECTO): distancia / intervalo entre informes.
        Mide velocidad de divergencia del canal por unidad de tiempo.
      * "threshold": descarta pares con intervalo > max_dt (por defecto
        2,0 s, coherente con el umbral de cobertura del proyecto).
      * "band": descarta pares con intervalo fuera de [dt_min, max_dt]
        y usa la distancia cruda. Alternativa conservadora a "divide":
        pierde muestras pero no asume linealidad distancia-intervalo.
    La relación empírica distancia-dt se caracteriza con
    bin/09-dt-dependence.py (results/presencia/dt-dependencia.*); la
    elección de modo por defecto se justifica ahí.
  - Separación por transmisor: cada cliente es un canal de observación
    distinto; segment_by_config parte por (ta, config_id) y nunca se
    mezclan cuerpos de clientes distintos en un mismo par.
"""

import numpy as np
import pandas as pd

METRICS = ("euclidean", "cosine", "pearson", "hamming")

DEFAULT_WINDOW_S = 10.0
DEFAULT_MAX_DT = 2.0
DEFAULT_NORM = "divide"


def segment_by_config(df):
    """Parte el DataFrame en segmentos homogéneos de (ta, config_id).

    Un segmento es la secuencia temporal DE UN MISMO TRANSMISOR con la misma
    configuración de MIMO control: se agrupa primero por transmisor (cada
    cliente es un canal de observación distinto) y dentro de cada línea
    temporal se corta donde cambia la configuración. NO se corta por el
    simple solapamiento temporal de dos clientes: que sus tramas se
    intercalen en el pcap no es un cambio de configuración.
    Si la configuración de un cliente cambia a mitad de captura, sus
    vectores dejan de ser comparables: el segmento se rompe ahí (requisito
    del parser: avisar, no fallar).
    """
    segments = []
    if df.empty:
        return segments
    for ta, sub in df.groupby("ta"):
        sub = sub.sort_values("ts")
        key = sub["config_id"] != sub["config_id"].shift()
        for _, seg in sub.groupby(key.cumsum()):
            segments.append(seg.reset_index(drop=True))
    # Orden temporal de aparición para una salida legible
    segments.sort(key=lambda s: (s["ts"].iloc[0], s["ta"].iloc[0]))
    return segments


def _hamming_bits(a, b):
    """Distancia de Hamming en bits entre dos vectores uint8 iguales."""
    return float(np.unpackbits(np.bitwise_xor(a, b)).sum())


def _distance(a, b, metric):
    a64 = a.astype(np.float64)
    b64 = b.astype(np.float64)
    if metric == "euclidean":
        return float(np.linalg.norm(a64 - b64))
    if metric == "cosine":
        na, nb = np.linalg.norm(a64), np.linalg.norm(b64)
        if na == 0 or nb == 0:
            return np.nan
        return float(1.0 - np.dot(a64, b64) / (na * nb))
    if metric == "pearson":
        if a64.std() == 0 or b64.std() == 0:
            return np.nan
        return float(1.0 - np.corrcoef(a64, b64)[0, 1])
    if metric == "hamming":
        return _hamming_bits(a, b)
    raise ValueError(f"métrica desconocida: {metric} (válidas: {METRICS})")


def pairwise_distance(seg, metric, norm=DEFAULT_NORM, max_dt=DEFAULT_MAX_DT,
                      dt_min=0.0):
    """Distancias entre informes consecutivos de un segmento homogéneo.

    Devuelve DataFrame con: ts (timestamp del segundo informe del par),
    dt (intervalo), distance (cruda), value (normalizada según `norm`).
    Pares con cuerpos de distinta longitud se descartan (no comparables) y
    se contabilizan en el atributo `skipped_len` del DataFrame.
    Modos de normalización:
      - "divide": value = distance / dt (POR DEFECTO; sesgo posible si la
        relación distancia-dt no es lineal — evaluado empíricamente en
        results/presencia/dt-dependencia.txt).
      - "threshold": descarta pares con dt > max_dt; value = distance cruda.
      - "band": descarta pares con dt fuera de [dt_min, max_dt]; value =
        distance cruda. Es la opción conservadora: pierde muestras pero
        evita cualquier sesgo dependiente del tráfico, porque solo compara
        pares tomados a cadencias parecidas.
    """
    if metric not in METRICS:
        raise ValueError(f"métrica desconocida: {metric} (válidas: {METRICS})")
    rows, skipped_len, skipped_dt = [], 0, 0
    bodies = seg["body"].to_numpy()
    ts = seg["ts"].to_numpy()
    for i in range(1, len(seg)):
        a, b = bodies[i - 1], bodies[i]
        dt = float(ts[i] - ts[i - 1])
        if a.size != b.size or a.size == 0:
            skipped_len += 1
            continue
        d = _distance(a, b, metric)
        if norm == "divide":
            value = d / dt if dt > 0 else np.nan
        elif norm == "threshold":
            if dt > max_dt:
                skipped_dt += 1
                continue
            value = d
        elif norm == "band":
            if dt < dt_min or dt > max_dt:
                skipped_dt += 1
                continue
            value = d
        else:
            raise ValueError(
                f"norm desconocida: {norm} (divide|threshold|band)")
        rows.append({"ts": float(ts[i]), "dt": dt,
                     "distance": d, "value": value})
    out = pd.DataFrame(rows)
    out.skipped_len = skipped_len
    out.skipped_dt = skipped_dt
    return out


def rolling_stats(dist, window_s=DEFAULT_WINDOW_S):
    """Media, varianza y percentiles (5/50/95) en ventana deslizante.

    Muestreo irregular: para cada instante de medida se calculan las
    estadísticas de los valores en [t - window/2, t + window/2]. Así no se
    asume rejilla uniforme (los informes llegan a intervalo variable).
    Devuelve DataFrame indexado por ts con columnas mean, var, p5, p50, p95,
    n (muestras en la ventana).
    """
    if dist.empty:
        return pd.DataFrame(
            columns=["ts", "mean", "var", "p5", "p50", "p95", "n"])
    ts = dist["ts"].to_numpy()
    vals = dist["value"].to_numpy(dtype=np.float64)
    half = window_s / 2.0
    rows = []
    for i, t in enumerate(ts):
        mask = (ts >= t - half) & (ts <= t + half)
        w = vals[mask]
        w = w[~np.isnan(w)]
        if w.size == 0:
            continue
        rows.append({"ts": t, "mean": float(w.mean()),
                     "var": float(w.var(ddof=1)) if w.size > 1 else 0.0,
                     "p5": float(np.percentile(w, 5)),
                     "p50": float(np.percentile(w, 50)),
                     "p95": float(np.percentile(w, 95)),
                     "n": int(w.size)})
    return pd.DataFrame(rows)
