"""CSV to the published detector and detrended, averaged spectral estimator."""
import argparse
import json
from pathlib import Path
import numpy as np
import pandas as pd
from .detector import scores, events, associate, THRESHOLD
from .spectral import spectrum, averaged_spectrum

def series(source, start=0., end=float('inf')):
    df = pd.read_csv(source)
    for sid, g in df[(df.t_rel_s >= start) & (df.t_rel_s < end)].groupby('series_id'):
        g = g.sort_values('t_rel_s', kind='stable')
        cols = [c for c in g if c.startswith('psi_') and g[c].notna().all()]
        if not cols:
            continue
        t = g.t_rel_s.to_numpy(float)
        y = g[cols].to_numpy(float)
        if np.any(np.diff(t) <= 0):
            raise ValueError('Duplicate/non-increasing times; investigate before analysis')
        yield sid, t, y

def analyze(source, out, start=0., end=None):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    results = []
    for sid, t, y in series(source, start, end if end is not None else float('inf')):
        stop = end if end is not None else float(np.nextafter(t[-1], np.inf))
        tt, score = scores(t, y, start, stop)
        found, states = events(tt, score, stop)
        pd.DataFrame(dict(t_rel_s=tt, variance_psi_rad2=score,
                          valid=np.isfinite(score), active=states)).to_csv(out/f'{sid}-variance.csv', index=False)
        (out/f'{sid}-events.json').write_text(json.dumps(dict(threshold_rad2=THRESHOLD,
            events=found, departures=associate(found)), indent=2)+'\n')
        try:
            f, power, var = averaged_spectrum(t, y)
        except ValueError as exc:
            results.append(dict(series_id=sid, status=str(exc)))
            continue
        pd.DataFrame(dict(frequency_hz=f, normalized_mean_power=power)).to_csv(out/f'{sid}-spectrum.csv', index=False)
        results.append(dict(series_id=sid, status='ok', components=y.shape[1], n=len(t),
            peak_hz=float(f[np.argmax(power)]) if power.max() > 0 else None,
            normalized_power=float(power.max()), detrended_variance_rad2=var))
    pd.DataFrame(results).to_csv(out/'peaks.csv', index=False)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('csv'); p.add_argument('--out', required=True)
    p.add_argument('--start', type=float, default=0.)
    p.add_argument('--end', type=float)
    a = p.parse_args()
    analyze(a.csv, a.out, a.start, a.end)

if __name__ == '__main__':
    main()
