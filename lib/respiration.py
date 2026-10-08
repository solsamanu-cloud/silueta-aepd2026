"""Legacy Lomb–Scargle helpers for irregular samples.

A spectral peak or peak-to-background ratio does not establish respiration.
The band is a configurable search range, not a universal Nyquist limit.
Use silueta/spectral.py for the published multi-component estimator.
These single-component legacy helpers are not the table reproduction entry point.
"""

import numpy as np
from scipy.signal import lombscargle

BANDA = (0.05, 0.35)
VENTANA_S = 120.0
SOLAPE = 0.5


def lomb_scargle_band(ts, x, banda=BANDA, n_freq=901, detrend=True):
    """Periodograma de Lomb-Scargle normalizado en la banda.

    ts: segundos (irregulares). x: serie. Devuelve freqs (Hz), potencia.
    normalize=True: potencia adimensional en [0, 1]-escala de scipy.
    detrend: quita la componente lineal por mínimos cuadrados ANTES del
    periodograma — una deriva lenta dentro de la ventana se filtra hacia la
    banda y crea pseudo-picos (observado en p00-a: pendiente ~2e-4/s que
    generaba picos errantes de confianza 3-5). La deriva de canal lenta no
    es respiración; hay que eliminarla.
    """
    ts = np.asarray(ts, dtype=np.float64)
    x = np.asarray(x, dtype=np.float64)
    if len(ts) < 8:
        raise ValueError("serie demasiado corta para Lomb-Scargle")
    if detrend:
        A = np.vstack([ts - ts.mean(), np.ones_like(ts)]).T
        x = x - A @ np.linalg.lstsq(A, x, rcond=None)[0]
    freqs = np.linspace(banda[0], banda[1], n_freq)
    ang = 2 * np.pi * freqs
    potencia = lombscargle(ts, x - x.mean(), ang, normalize=True,
                           precenter=True)
    return freqs, potencia


def analyze_windows(ts, x, banda=BANDA, ventana_s=VENTANA_S, solape=SOLAPE):
    """Lomb-Scargle en ventanas deslizantes.

    Devuelve lista de dicts por ventana: t_inicio, freqs, potencia, f_pico,
    confianza (pico/media de banda), n_muestras. Ventanas con menos de 8
    muestras se omiten.
    """
    ts = np.asarray(ts, dtype=np.float64)
    x = np.asarray(x, dtype=np.float64)
    paso = ventana_s * (1 - solape)
    t0, t1 = ts[0], ts[-1]
    ventanas = []
    t = t0
    while t + ventana_s <= t1 + 1e-9:
        m = (ts >= t) & (ts < t + ventana_s)
        if m.sum() >= 8:
            freqs, pot = lomb_scargle_band(ts[m], x[m], banda)
            i = int(np.argmax(pot))
            ventanas.append({
                "t_inicio": float(t),
                "freqs": freqs,
                "potencia": pot,
                "f_pico": float(freqs[i]),
                "confianza": float(pot[i] / pot.mean()),
                "n_muestras": int(m.sum()),
            })
        t += paso
    return ventanas


def picos_en_banda(ventanas, umbral_confianza=3.0):
    """Lista de ventanas cuyo pico supera el umbral de confianza (pico/media
    de banda). Para el control r00/p00: NINGUNA ventana debe aparecer."""
    return [v for v in ventanas if v["confianza"] >= umbral_confianza]
