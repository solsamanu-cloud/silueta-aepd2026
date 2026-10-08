"""Paced-pilot estimator: real times, linear detrend, mean raw Lomb–Scargle.

Detrend-then-LS, not a joint trend/sinusoid GLS fit. No interpolation or
component selection. The frequency search does not use the requested pace.
"""
import numpy as np
from scipy.signal import lombscargle

BAND = (0.05, 0.35)
N_FREQ = 901

def averaged_spectrum(t, y, low=BAND[0], high=BAND[1], n_freq=N_FREQ):
    t = np.asarray(t, dtype=float)
    y = np.asarray(y, dtype=float)
    if y.ndim == 1:
        y = y[:, None]
    if t.ndim != 1 or y.ndim != 2 or len(y) != len(t) or y.shape[1] == 0:
        raise ValueError('Expected times and a nonempty samples × components matrix')
    if len(t) < 8 or not np.isfinite(t).all() or not np.isfinite(y).all():
        raise ValueError('At least 8 finite samples required')
    if np.any(np.diff(t) <= 0) or np.ptp(t) < 20:
        raise ValueError('Strictly increasing times spanning at least 20 s required')
    if not 0 < low < high or n_freq < 3:
        raise ValueError('Invalid frequency grid')
    tt = t - t[0]
    design = np.column_stack([np.ones(len(tt)), tt])
    residual = y - design @ np.linalg.lstsq(design, y, rcond=None)[0]
    freq = np.linspace(low, high, n_freq)
    power = np.mean([lombscargle(tt, residual[:,i], 2*np.pi*freq,
                               normalize=False) for i in range(y.shape[1])], axis=0)
    denominator = .5 * np.mean(np.sum(residual**2, axis=0))
    power = power / denominator if denominator > 1e-24 else np.zeros_like(power)
    return freq, power, float(np.mean(residual**2))

def spectrum(t, y, low=BAND[0], high=BAND[1]):
    """Compatibility two-array API; identical estimator for one/many components."""
    f, p, _ = averaged_spectrum(t, y, low, high)
    return f, p
