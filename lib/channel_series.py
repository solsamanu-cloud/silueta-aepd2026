"""Series temporales de canal a partir de ángulos ψ (fase 3).

Decisiones y cambios respecto del plan inicial de la tarea:
  - SIN desenvolvimiento de fase (phase unwrap): estaba previsto para φ,
    que se descartó por CFO (docs/METODO-respiracion.md §φ/ψ). ψ vive en
    [0, π/2] y no es circular en ese sentido; desenvolverla introduciría
    artefactos. Cambio documentado aquí y en el METODO.
  - Filtro de Hampel y selección de componentes (varianza + PCA): sin
    cambios.
  - Segmentación por configuración obligatoria: si el MIMO control cambia,
    la serie se corta (los vectores no son comparables).
  - Una serie por cliente; NUNCA se agregan clientes.
"""

import numpy as np


def build_series(decoded, ta):
    """Lista de segmentos homogéneos de un cliente.

    decoded: salida de bfi_decode.decode_pcap. Devuelve lista de dicts
    {"ts", "psi", "cfg"} cortada por cambios de configuración. En la
    práctica cada cliente tiene una configuración estable (verificado en
    fase 1), pero la segmentación es obligatoria por diseño.
    """
    if ta not in decoded:
        raise KeyError(f"cliente {ta} no presente (¿truncado o ausente?)")
    d = decoded[ta]
    segments = d.get("segments", [d])
    return [{"ts": seg["ts"], "psi": seg["psi"], "cfg": seg["cfg"],
             "ra": seg.get("ra"), "segment_id": i}
            for i, seg in enumerate(segments)]


def hampel(x, window=7, n_sigmas=3.0):
    """Filtro de Hampel por subportadora: sustituye los puntos que superan
    n_sigmas · MAD respecto de la mediana de la ventana.

    x: (n_muestras, n_subc). Devuelve una copia filtrada y la máscara de
    valores reemplazados. window debe ser impar.
    """
    if window % 2 == 0:
        raise ValueError("window debe ser impar")
    x = np.asarray(x, dtype=np.float64)
    y = x.copy()
    mascara = np.zeros_like(x, dtype=bool)
    h = window // 2
    for c in range(x.shape[1]):
        s = x[:, c]
        for i in range(len(s)):
            lo, hi = max(0, i - h), min(len(s), i + h + 1)
            w = s[lo:hi]
            med = np.median(w)
            mad = np.median(np.abs(w - med)) * 1.4826
            if mad > 0 and abs(s[i] - med) > n_sigmas * mad:
                y[i, c] = med
                mascara[i, c] = True
    return y, mascara


def select_components(x, n_components=3, center=True):
    """Selección de componentes: PCA sobre subportadoras.

    Devuelve dict con scores (n_muestras, n_components), varianza explicada
    por componente y las cargas. La ordenación es por varianza (criterio de
    selección combinado varianza+PCA del plan).
    """
    X = np.asarray(x, dtype=np.float64)
    if center:
        X = X - X.mean(axis=0)
    U, S, Vt = np.linalg.svd(X, full_matrices=False)
    n = min(n_components, U.shape[1])
    var_total = float((S ** 2).sum())
    return {
        "scores": U[:, :n] * S[:n],
        "explained": (S[:n] ** 2) / var_total,
        "loadings": Vt[:n].T,
    }
