"""Rebuild controlled-campaign tables from public CSV, without packet tools."""
import argparse
import json
from pathlib import Path
import numpy as np
import pandas as pd
from .analyze import series
from .spectral import averaged_spectrum
from .detector import scores, events, associate, calibrate, THRESHOLD

def reproduce(data, out):
    data, out = Path(data), Path(out)
    out.mkdir(parents=True, exist_ok=True)
    catalogue = pd.read_csv(data/'catalog.csv')
    quality, movement, respiration, subwindows = [], [], [], []
    calibration = None
    details = {}
    for row in catalogue.to_dict('records'):
        cid = row['capture_id']
        start, end = row['preparation_s'], row['planned_duration_s']
        groups = list(series(data/'captures'/f'{cid}.csv', start, end))
        if not groups:
            quality.append(dict(capture_id=cid, client=row['client'], condition=row['condition'],
                                n=0, rate_per_s=0, max_gap_edges_s=end-start))
        for sid, t, y in groups:
            identity = dict(capture_id=cid, series_id=sid, client=row['client'], condition=row['condition'])
            quality.append(dict(**identity, n=len(t), rate_per_s=len(t)/(end-start),
                median_dt_s=float(np.median(np.diff(t))) if len(t)>1 else None,
                max_gap_edges_s=float(np.diff(np.r_[start,t,end]).max()),
                psi_global_variance_rad2=float(np.mean(np.var(y,axis=0)))))
            if row['protocol']=='movement' and row['condition'].startswith('b-pr03-'):
                tt, score = scores(t, y, start, end)
                found, state = events(tt, score, end)
                actual = any(x in row['condition'] for x in ('principal-', 'recorrido-', 'lateral-'))
                departures = associate(found) if actual else []
                valid = np.isfinite(score)
                after = tt >= start+6
                movement.append(dict(**identity, n=len(t), valid_scores=int(valid.sum()),
                    valid_after_warmup_pct=100*valid.sum()/after.sum() if after.sum() else None,
                    score_median_rad2=float(np.nanmedian(score)), score_p95_rad2=float(np.nanpercentile(score,95)),
                    score_max_rad2=float(np.nanmax(score)), event_count=len(found),
                    alarm_duration_s=sum(e['end_s']-e['start_s'] for e in found),
                    departures_with_new_alarm=sum(d['new_activation_delay_s'] is not None for d in departures) if actual else None))
                details[cid] = dict(series_id=sid, events=found, departures=departures)
                pd.DataFrame(dict(t_rel_s=tt, variance_psi_rad2=score, valid=valid, active=state)).to_csv(out/f'{cid}-variance.csv',index=False)
                if cid=='CAP0013':
                    calibration=calibrate(score)
            if row['protocol']=='breathing-paced':
                f, p, v = averaged_spectrum(t,y)
                respiration.append(dict(**identity, n=len(t), peak_hz=float(f[np.argmax(p)]),
                    peak_cycles_per_min=float(60*f[np.argmax(p)]), normalized_power=float(p.max()),
                    detrended_variance_rad2=v))
                pd.DataFrame(dict(frequency_hz=f,normalized_mean_power=p)).to_csv(out/f'{cid}-spectrum.csv',index=False)
                for a in range(int(start),int(end),100):
                    mask=(t>=a)&(t<min(a+100,end))
                    try:
                        ff, pp, vv=averaged_spectrum(t[mask],y[mask])
                        subwindows.append(dict(**identity,start_s=a,end_s=min(a+100,end),n=int(mask.sum()),
                            peak_hz=float(ff[np.argmax(pp)]),peak_cycles_per_min=float(60*ff[np.argmax(pp)]),
                            detrended_variance_rad2=vv))
                    except ValueError as exc:
                        subwindows.append(dict(**identity,start_s=a,status=str(exc)))
    for name, rows in [('quality',quality),('movement',movement),('respiration',respiration),('respiration-100s',subwindows)]:
        pd.DataFrame(rows).to_csv(out/f'{name}.csv',index=False)
    details['calibration'] = dict(capture_id='CAP0013',quantile=99.5,method='linear',
        recomputed_threshold_rad2=calibration,frozen_threshold_rad2=THRESHOLD,
        note='CSV angles rounded to 9 significant digits; frozen full-precision threshold is used for decisions.')
    (out/'events.json').write_text(json.dumps(details,indent=2)+'\n',encoding='utf-8')
    # Reference numbers extracted independently from the original offline reports.
    reference=data/'reference-results.json'
    checked=0
    if reference.exists():
        expected=json.loads(reference.read_text())
        indexes={name:{r['capture_id']:r for r in rows} for name,rows in [('movement',movement),('respiration',respiration),('quality',quality)]}
        for name, captures in expected.items():
            for cid, fields in captures.items():
                actual=indexes[name][cid]
                for key,value in fields.items():
                    if not np.isclose(actual[key],value,rtol=2e-6,atol=2e-6):
                        raise AssertionError(f'{name}/{cid}/{key}: {actual[key]} != original {value}')
                    checked+=1
    if calibration is None or not np.isclose(calibration,THRESHOLD,rtol=2e-6,atol=1e-10):
        raise AssertionError('Initial empty calibration differs from published threshold')
    print(f'Rebuilt {len(quality)} quality rows, {len(movement)} movement rows, {len(respiration)} spectra; {checked} independent reference values matched.')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--data',type=Path,default=Path(__file__).resolve().parents[1]/'data')
    p.add_argument('--out',type=Path,default=Path('results/reproduction'))
    a=p.parse_args();reproduce(a.data,a.out)

if __name__=='__main__':main()
