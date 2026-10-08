"""Reproduce POS02, robot controls and AP power tests from relative-time CSV."""
import argparse
import json
from pathlib import Path
import numpy as np
import pandas as pd
from .detector import scores, events, associate, THRESHOLD, DEPARTURES


def angles(path):
    frame=pd.read_csv(path)
    if len(frame) and frame.series_id.nunique()!=1:
        raise ValueError('Controlled test must contain one configuration; do not mix series')
    t=frame.t_rel_s.to_numpy(float)
    if np.any(np.diff(t)<=0):raise ValueError('Non-increasing times')
    return t,frame[[c for c in frame if c.startswith('psi_')]].to_numpy(float),frame[[c for c in frame if c.startswith('phi_')]].to_numpy(float)


def robot_scores(t,psi,phi):
    score=np.full((len(t),2),np.nan);fixed=score.copy()
    for i,now in enumerate(t):
        j=np.searchsorted(t,now-6)
        win=t[j:i+1]
        if now>=6 and len(win)>=4 and np.diff(np.r_[now-6,win,now]).max()<=2.8:
            score[i]=[np.var(psi[j:i+1],axis=0).mean(),(1-abs(np.exp(1j*phi[j:i+1]).mean(axis=0))).mean()]
        if i>=4 and now-t[i-4]<=8:
            fixed[i]=[np.var(psi[i-4:i+1],axis=0).mean(),(1-abs(np.exp(1j*phi[i-4:i+1]).mean(axis=0))).mean()]
    return score,fixed


def summarize_robot(t,psi,phi,start,end):
    score,fixed=robot_scores(t,psi,phi)
    useful=(t>=start)&(t<end)
    compare=(t>=start+6)&(t<end)
    valid=compare&np.isfinite(score[:,0])
    if not valid.any():raise ValueError('No valid robot-phase windows')
    result=dict(n_bfi_300s=int(useful.sum()),valid=int(valid.sum()),
        median=np.median(score[valid],axis=0).tolist(),p95=np.percentile(score[valid],95,axis=0).tolist(),
        maximum=np.max(score[valid],axis=0).tolist(),fixed5=np.nanmedian(fixed[compare],axis=0).tolist(),
        above_threshold=int((score[valid,0]>.006820114).sum()))
    return result,score,useful,compare


def reproduce(data,out,figures=True):
    data,out=Path(data),Path(out);out.mkdir(parents=True,exist_ok=True)
    config=json.loads((data/'controlled-tests.json').read_text())
    reference=json.loads((data/'controlled-reference-results.json').read_text())
    results={'pos02':{},'robot':{},'power':{}}
    movement=[];robot=[];power=[];curves={};all_events={}
    for spec in config:
        cid=spec['capture_id'];start=spec['start_s'];end=spec['end_s'];kind=spec['experiment']
        t,y,phi=angles(data/'captures'/f'{cid}.csv')
        if kind=='pos02':
            tt,score=scores(t,y,start,end);ev,state=events(tt,score,end)
            walking=spec['condition'].startswith(('principal','lateral'))
            departures=associate(ev) if walking else []
            result=dict(n=len(tt),valid_scores=int(np.isfinite(score).sum()),score_max_rad2=float(np.nanmax(score)),
                event_count=len(ev),departures_with_new_alarm=sum(d['new_activation_delay_s'] is not None for d in departures),
                alarm_duration_s=sum(e['end_s']-e['start_s'] for e in ev))
            results[kind][cid]=result
            movement.append(dict(capture_id=cid,session=spec['session'],condition=spec['condition'],**result))
            all_events[cid]=dict(events=ev,departures=departures)
            pd.DataFrame(dict(t_rel_s=tt,variance_psi_rad2=score,active=state)).to_csv(out/f'{cid}-variance.csv',index=False)
            curves[(spec['session'],spec['condition'])]=(tt,score,ev)
        elif kind=='robot':
            result,score,useful,compare=summarize_robot(t,y,phi,start,end)
            key=cid+'-'+spec['condition'];results[kind][key]=result
            record=dict(capture_id=cid,session=spec['session'],condition=spec['condition'],start_s=start,end_s=end,
                n=result['n_bfi_300s'],valid=result['valid'],psi_median=result['median'][0],phi_median=result['median'][1],
                psi_p95=result['p95'][0],phi_p95=result['p95'][1],above_threshold=result['above_threshold'])
            robot.append(record)
            all_events[key]=events(t[compare]-start,score[compare,0],end-start)[0]
            pd.DataFrame(dict(t_rel_s=t[useful],variance_psi_rad2=score[useful,0],variance_phi_circular=score[useful,1])).to_csv(out/f'{key}-variance.csv',index=False)
            curves[(spec['session'],spec['condition'])]=(t[useful]-start,score[useful],None)
        else:
            packets=pd.read_csv(data/'protocol'/f'{cid}.csv')
            # Near-AP reference uses the complete 300-second recorder output;
            # its last packet may fall slightly after t_rel=300.
            packets=packets[packets.t_rel_s>=start]
            if end is not None:packets=packets[packets.t_rel_s<end]
            bfi=packets[packets.kind=='bfi'];beacons=packets[packets.kind=='beacon']
            result=dict(beacons=len(beacons),ap_rssi_median=float(beacons.rssi_dbm.median()))
            if spec['location']=='P01':
                result.update(bfi=len(bfi),client_rssi_median=float(bfi.rssi_dbm.median()),ndpa=int((packets.kind=='ndpa').sum()))
            results[kind][cid]=result
            power.append(dict(capture_id=cid,location=spec['location'],antenna=spec['antenna'],level=spec['level'],**result))
    checked=0
    for kind,entries in reference.items():
        for cid,fields in entries.items():
            for key,expected in fields.items():
                actual=results[kind][cid][key]
                if not np.allclose(actual,expected,rtol=2e-6,atol=2e-9):
                    raise AssertionError(f'{kind}/{cid}/{key}: {actual} != {expected}')
                checked+=1
    for name,records in [('pos02',movement),('robot',robot),('power',power)]:
        pd.DataFrame(records).to_csv(out/(name+'.csv'),index=False)
    (out/'events.json').write_text(json.dumps(all_events,indent=2)+'\n')
    (out/'validation.json').write_text(json.dumps(dict(reference_values_matched=checked,threshold_rad2=THRESHOLD),indent=2)+'\n')
    if figures:plot(curves,robot,power,out)
    print(f'Controlled tests reproduced: {len(movement)} POS02, {len(robot)} robot phases, {len(power)} power settings; {checked} independent values matched.')


def plot(curves,robot,power,out):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    groups=[('recorridos',['principal-r01','principal-r02','lateral-r01','lateral-r02']),
            ('controles',['vacio-r01','quieto-e1-r01','vacio-r02','quieto-e2-r01','vacio-r03','vacio-r04'])]
    for name,conditions in groups:
        fig,axes=plt.subplots(len(conditions),3,figsize=(11,len(conditions)*1.9),sharex=True,sharey=True,layout='constrained')
        for row,condition in enumerate(conditions):
            for col,session in enumerate(['S01','S02','S03']):
                ax=axes[row,col];t,s,ev=curves[(session,condition)]
                ax.plot(t/60,s,lw=.8,color='#087f8c');ax.axhline(THRESHOLD,ls='--',color='#b83442',lw=.8)
                if name=='recorridos':
                    for dep in DEPARTURES:ax.axvline(dep/60,ls=':',color='#bf7b27',lw=.7)
                for event in ev:ax.axvspan(event['start_s']/60,event['end_s']/60,color='#087f8c',alpha=.1)
                ax.grid(alpha=.15);ax.set_xlim(2,7)
                if row==0:ax.set_title(session)
                if col==0:ax.set_ylabel(condition+'\nVarianza ψ (rad²)')
                if row==len(conditions)-1:ax.set_xlabel('Minutos desde inicio')
        fig.suptitle('POS02 · mismo detector en tres sesiones')
        fig.savefig(out/f'pos02-{name}.png',dpi=180);plt.close(fig)
    phases=['vacio-inicial','robot-r01','vacio-posterior','robot-r02']
    for index,family in enumerate(['psi','phi']):
        fig,axes=plt.subplots(2,4,figsize=(12,5),sharex=True,sharey=True,layout='constrained')
        for row,session in enumerate(['S01','S02']):
            for col,condition in enumerate(phases):
                t,s,_=curves[(session,condition)];ax=axes[row,col]
                ax.plot(t/60,s[:,index],color='#087f8c',lw=.7);ax.grid(alpha=.15);ax.set_xlim(0,5)
                ax.set_title(session+' · '+condition)
                if row==1:ax.set_xlabel('Minutos de fase')
                if col==0:ax.set_ylabel('Varianza ψ (rad²)' if index==0 else 'Varianza circular φ')
        fig.suptitle('Robot: vacío → limpieza → vacío → limpieza; recorridos no idénticos')
        fig.savefig(out/f'robot-{family}.png',dpi=180);plt.close(fig)
    frame=pd.DataFrame(power);levels=['alto','medio','bajo'];x=np.arange(3)
    fig,axes=plt.subplots(1,2,figsize=(10,4),layout='constrained')
    for location,label in [('1m','Balizas AP01 a 1 m'),('P01','Balizas AP01 en P01')]:
        values=frame[frame.location==location].set_index('level').loc[levels,'ap_rssi_median'].to_numpy()
        axes[0].plot(x,values-values[0],marker='o',label=label)
    p=frame[frame.location=='P01'].set_index('level').loc[levels]
    values=p.client_rssi_median.to_numpy();axes[0].plot(x,values-values[0],marker='o',label='BFI C01 en P01')
    axes[0].set_ylabel('Cambio de RSSI respecto a alto (dB)');axes[0].legend(fontsize=8)
    for offset,field,label in [(-.18,'bfi','BFI C01'),(.18,'ndpa','NDPA a C01')]:
        bars=axes[1].bar(x+offset,p[field],width=.36,label=label);axes[1].bar_label(bars,fmt='%g')
    axes[1].set_ylabel('Informes en cinco minutos');axes[1].legend()
    for ax in axes:ax.set_xticks(x,levels);ax.set_xlabel('Nivel configurado del AP')
    fig.suptitle('Potencia del AP: recepción conservada en P01; alcance máximo no medido')
    fig.savefig(out/'power.png',dpi=180);plt.close(fig)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--data',type=Path,default=Path(__file__).resolve().parents[1]/'data')
    p.add_argument('--out',type=Path,default=Path('results/controlled'))
    p.add_argument('--no-figures',action='store_true')
    a=p.parse_args();reproduce(a.data,a.out,not a.no_figures)

if __name__=='__main__':main()
