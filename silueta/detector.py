"""Frozen orange-route detector. Times are relative seconds."""
import numpy as np

THRESHOLD = 0.006820114055593958
DEPARTURES = (150., 200., 250., 300., 350.)

def scores(t, y, start=120., end=420.):
    t = np.asarray(t, dtype=float)
    y = np.asarray(y, dtype=float)
    if y.ndim == 1:
        y = y[:,None]
    if y.ndim != 2 or len(y) != len(t) or not np.isfinite(t).all() or not np.isfinite(y).all():
        raise ValueError('Finite times and sample matrix required')
    if np.any(np.diff(t) <= 0):
        raise ValueError('Times must be strictly increasing within one series')
    keep = (t >= start) & (t < end)
    t, y = t[keep], y[keep]
    result = np.full(len(t), np.nan)
    for i, now in enumerate(t):
        if now < start + 6:
            continue
        j = np.searchsorted(t, now-6, side='left')
        window = t[j:i+1]
        if len(window) >= 4 and np.max(np.diff(np.r_[now-6,window,now])) <= 2.8:
            result[i] = np.mean(np.var(y[j:i+1], axis=0, ddof=0))
    return t, result

def calibrate(valid_scores):
    x = np.asarray(valid_scores, dtype=float)
    x = x[np.isfinite(x)]
    if not len(x):
        raise ValueError('No valid calibration scores')
    return float(np.percentile(x, 99.5, method='linear'))

def events(t, score, end=420., threshold=THRESHOLD):
    """Second high activates; second low closes; missing data resets immediately."""
    active = False
    high = low = 0
    found = []
    states = []
    for now, value in zip(t, score):
        if not np.isfinite(value):
            if active:
                found[-1].update(end_s=float(now), end_reason='invalid-data')
            active = False
            high = low = 0
        else:
            if value > threshold:
                high += 1
                low = 0
            else:
                low += 1
                high = 0
            if not active and high >= 2:
                active = True
                found.append(dict(start_s=float(now)))
            elif active and low >= 2:
                active = False
                found[-1].update(end_s=float(now), end_reason='two-low-scores')
        states.append(active)
    if active:
        found[-1].update(end_s=float(end), end_reason='capture-end-censored')
    return found, states

def associate(found, departures=DEPARTURES):
    result = []
    for start in departures:
        new = [e['start_s'] for e in found if start <= e['start_s'] < start+20]
        result.append(dict(departure_s=start,
                           already_active=any(e['start_s'] < start < e['end_s'] for e in found),
                           new_activation_delay_s=new[0]-start if new else None))
    return result
