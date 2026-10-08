"""Read-only view of the independent monitor; never controls its process/radio."""
import fcntl
from contextlib import closing
import json
import math
from pathlib import Path
import sqlite3
import time


def protected(base):
    lock = Path(base)/'state/continuous-monitor.lock'
    try:
        with lock.open('rb') as f:
            try: fcntl.flock(f,fcntl.LOCK_SH|fcntl.LOCK_NB)
            except BlockingIOError: return True
    except FileNotFoundError: return False
    except PermissionError: return True  # Fail closed if ownership cannot be checked.
    return False


def status(base):
    base=Path(base); busy=protected(base)
    try: record=json.loads((base/'state/continuous-monitor.json').read_text())
    except (OSError,ValueError): record={}
    fresh=time.time()-record.get('updated',0)<30
    active=busy and fresh and not record.get('stopped',False)
    links=[]
    for key,item in record.get('links',{}).items():
        links.append(dict(item['target'],bfi=item.get('bfi',0),errors=item.get('errors',0)))
    if not links:
        for name,count in [('target','bfi'),('secondary','secondary_bfi')]:
            if record.get(name):links.append(dict(record[name],bfi=record.get(count,0)))
    return dict(protected=busy,active=active,stale=busy and not fresh,
        message=('Radio reservada por una monitorización como servicio. Consulta disponible; controles de captura bloqueados.' if busy else 'No hay un servicio de monitorización reservando la radio.'),
        service=dict(session=record.get('session'),state=record.get('state'),started=record.get('started'),
            updated=record.get('updated'),error=record.get('error'),radio=record.get('radio_verification'),
            links=links,storage=record.get('storage',{}),output=record.get('output'),
            mode=record.get('mode'),position=record.get('position')) if record else None)


def series(base,session,key,start,end,stream=None):
    start=float(start);end=float(end)
    if not all(math.isfinite(v) for v in (start,end)) or end<=start or end-start>32*86400:
        raise ValueError('Elige un intervalo entre 1 segundo y 32 días')
    if len(session)>160 or len(key)>200: raise ValueError('Identificador no válido')
    path=Path(base)/'state/monitoring.sqlite3'
    with closing(sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True,timeout=3)) as db:
        db.row_factory=sqlite3.Row
        target=db.execute('SELECT target FROM watches WHERE key=?',(key,)).fetchone()
        if not target: raise ValueError('Enlace no encontrado en el histórico')
        bounds=db.execute('SELECT MIN(ts),MAX(ts),COUNT(*) FROM points WHERE session=? AND key=?',(session,key)).fetchone()
        streams=[dict(r) for r in db.execute('SELECT series id,COUNT(*) n FROM points WHERE session=? AND key=? GROUP BY series ORDER BY n DESC',(session,key))]
        for item in streams:
            sample=db.execute('SELECT payload FROM points WHERE session=? AND key=? AND series=? LIMIT 1',(session,key,item['id'])).fetchone()
            item['feedback']=json.loads(sample[0]).get('feedback',{}) if sample else {}
        if not stream and streams:stream=streams[0]['id']
        args=(session,key,start,end,stream)
        count=db.execute('SELECT COUNT(*) FROM points WHERE session=? AND key=? AND ts>=? AND ts<? AND series=?',args).fetchone()[0]
        step=0 if end-start<=600 and count<=20000 else max(1,math.ceil((end-start)/1200))
        if step:
            rows=[dict(r) for r in db.execute('''SELECT CAST(ts/? AS INTEGER)*? ts,AVG(variance) variance,
              MIN(variance) low,MAX(variance) high,AVG(phi) variance_phi,AVG(rssi) rssi,
              COUNT(*) n,SUM(reliable) valid FROM points WHERE session=? AND key=? AND ts>=? AND ts<? AND series=?
              GROUP BY CAST(ts/? AS INTEGER) ORDER BY ts''',(step,step,*args,step))]
        else:
            rows=[dict(json.loads(r['payload']),n=1,valid=r['reliable']) for r in db.execute('SELECT payload,reliable FROM points WHERE session=? AND key=? AND ts>=? AND ts<? AND series=? ORDER BY ts',args)]
        return dict(session=session,key=key,target=json.loads(target[0]),start=start,end=end,
            first=bounds[0],last=bounds[1],total=bounds[2],streams=streams,stream=stream,
            points=rows,count=count,bucket_seconds=step,read_only=True)
