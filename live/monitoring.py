"""Persistent, per-link BFI monitoring. One radio, one verified channel.

SQLite keeps every point; plots aggregate only for display. Radio listening
coverage and received-BFI coverage are distinct. No occupancy classifier.
"""
from datetime import datetime, timedelta
import json
import math
from pathlib import Path
import sqlite3
import threading
import time
from zoneinfo import ZoneInfo
from engine import SeriesVariance, decode_line

ZONE = ZoneInfo('Europe/Madrid')
RADIO_KEYS = ('frequency', 'channel', 'width', 'center')


def same_radio(a, b):
    return all(a.get(k) == b.get(k) for k in RADIO_KEYS)


def day_bounds(day):
    dt = datetime.strptime(day, '%Y-%m-%d').replace(tzinfo=ZONE)
    return dt.timestamp(), (dt + timedelta(days=1)).timestamp()


class MonitoringStore:
    def __init__(self, path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript('''
          PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
          CREATE TABLE IF NOT EXISTS watches(key TEXT PRIMARY KEY, target TEXT NOT NULL,
            enabled INTEGER NOT NULL, added REAL NOT NULL, threshold REAL);
          CREATE TABLE IF NOT EXISTS points(key TEXT, session TEXT, ts REAL, series TEXT,
            variance REAL, phi REAL, reliable INTEGER, rssi REAL, payload TEXT,
            PRIMARY KEY(key,session,ts,series));
          CREATE INDEX IF NOT EXISTS point_time ON points(key,ts,series);
          CREATE TABLE IF NOT EXISTS coverage(key TEXT, session TEXT, start REAL, end REAL,
            PRIMARY KEY(key,session));
          CREATE TABLE IF NOT EXISTS errors(key TEXT, session TEXT, ts REAL, message TEXT);
          CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY, key TEXT, ts REAL, text TEXT);
          CREATE TABLE IF NOT EXISTS imports(path TEXT PRIMARY KEY, offset INTEGER);
        ''')
        self.db.commit()
        self.engines = {}
        self.targets = {}
        self._reload()

    def _reload(self):
        self.targets = {r['key']: json.loads(r['target']) for r in self.db.execute(
            'SELECT * FROM watches WHERE enabled=1')}

    def active(self):
        with self.lock:
            return list(self.targets.values())

    def add(self, target):
        target = {k: target.get(k) for k in ('key', 'mac', 'ap', 'name', 'label', 'id') + RADIO_KEYS}
        with self.lock:
            if self.targets and not same_radio(next(iter(self.targets.values())), target):
                raise ValueError('Una ALFA solo puede monitorizar continuamente un canal. Detén las monitorizaciones antes de cambiarlo.')
            if target['key'] not in self.targets and len(self.targets) >= 12:
                raise ValueError('Máximo 12 enlaces simultáneos por radio.')
            self.db.execute('INSERT INTO watches VALUES(?,?,1,?,NULL) ON CONFLICT(key) DO UPDATE SET target=excluded.target,enabled=1',
                            (target['key'], json.dumps(target), time.time()))
            self.db.commit()
            self._reload()
        return target

    def disable(self, key=None):
        with self.lock:
            if key is None:self.db.execute('UPDATE watches SET enabled=0')
            else:self.db.execute('UPDATE watches SET enabled=0 WHERE key=?', (key,))
            self.db.commit()
            self._reload()
            self.engines = {}

    def threshold(self, key, value):
        if value is not None and (isinstance(value, bool) or not isinstance(value, (float, int)) or not math.isfinite(value) or value < 0):
            raise ValueError('Umbral no válido; déjalo vacío para no clasificar.')
        with self.lock:
            self.db.execute('UPDATE watches SET threshold=? WHERE key=?', (value, key))
            self.db.commit()

    def note(self, key, ts, text):
        if not isinstance(text, str) or not 1 <= len(text.strip()) <= 300:
            raise ValueError('Escribe una anotación de 1 a 300 caracteres.')
        if not isinstance(ts, (int, float)) or not math.isfinite(ts):raise ValueError('Fecha no válida')
        with self.lock:
            self.db.execute('INSERT INTO notes(key,ts,text) VALUES(?,?,?)', (key, ts, text.strip()))
            self.db.commit()

    def _point(self, key, session, p):
        ts = p.get('ts')
        if not isinstance(ts, (int, float)) or not math.isfinite(ts):return
        value, phi = p.get('variance'), p.get('variance_phi')
        if any(x is not None and (not isinstance(x, (float,int)) or not math.isfinite(x)) for x in (value,phi)):return
        self.db.execute('INSERT OR IGNORE INTO points VALUES(?,?,?,?,?,?,?,?,?)',
            (key, session, ts, p.get('series_id') or 'legacy-' + json.dumps(p.get('config', [])),
             value, phi, int(p.get('quality') == 'valid'), p.get('rssi'), json.dumps(p, allow_nan=False)))

    def consume(self, line, session):
        parts = line.split('|')
        if len(parts) < 13:return
        tx, rx = parts[1].lower(), parts[12].lower()
        with self.lock:
            for key, target in self.targets.items():
                if (tx, rx) not in ((target['mac'],target['ap']), (target['ap'],target['mac'])):continue
                engine = self.engines.setdefault((session,key), SeriesVariance())
                try:
                    row = decode_line(line, target['mac'], target['ap'])
                    if 'psi' not in row:continue
                    p = engine.push(row['ts'], row['psi'], row['config'], row.get('phi'))
                    p.update(ts=row['ts'],rssi=row['rssi'],series_id=row['series_id'],feedback=row['feedback'],config=list(row['config']))
                    self._point(key, session, p)
                except (ValueError,KeyError,IndexError) as exc:
                    engine.reset()
                    self.db.execute('INSERT INTO errors VALUES(?,?,?,?)', (key,session,time.time(),str(exc)[:300]))
            self.db.commit()

    def heartbeat(self, session, radio, start, now=None):
        now = time.time() if now is None else now
        with self.lock:
            for key, target in self.targets.items():
                if not same_radio(target, radio):continue
                self.db.execute('INSERT INTO coverage VALUES(?,?,?,?) ON CONFLICT(key,session) DO UPDATE SET end=excluded.end',
                                (key,session,max(start, self.db.execute('SELECT added FROM watches WHERE key=?',(key,)).fetchone()[0]),now))
            self.db.commit()

    def import_sessions(self, root):
        """Idempotent import of complete JSONL lines; original captures untouched."""
        with self.lock:
            watches = [dict(r) for r in self.db.execute('SELECT key,target FROM watches')]
            for manifest in Path(root).glob('*/session.json'):
                try:
                    info = json.loads(manifest.read_text())
                    if info.get('mode') != 'live':continue
                    target = next((w for w in watches if json.loads(w['target'])['mac'] == info.get('client')
                                   and json.loads(w['target'])['ap'] == info.get('ap')
                                   and same_radio(json.loads(w['target']), info.get('radio',{}))), None)
                    path = manifest.parent / 'variance.jsonl'
                    if not target or not path.exists():continue
                    key, session = target['key'], manifest.parent.name
                    old = self.db.execute('SELECT offset FROM imports WHERE path=?',(str(path),)).fetchone()
                    offset = old[0] if old else 0
                    with path.open('rb') as f:
                        f.seek(offset)
                        while True:
                            line = f.readline()
                            if not line or not line.endswith(b'\n'):break
                            p = json.loads(line)
                            self._point(key,session,p)
                            offset = f.tell()
                    self.db.execute('INSERT INTO imports VALUES(?,?) ON CONFLICT(path) DO UPDATE SET offset=excluded.offset',(str(path),offset))
                    # Only confirmed elapsed capture time, never the current wall clock.
                    if info.get('started') and info.get('elapsed_s',0)>0:
                        start = datetime.fromisoformat(info['started']).timestamp()
                        end = start + info['elapsed_s']
                        self.db.execute('INSERT INTO coverage VALUES(?,?,?,?) ON CONFLICT(key,session) DO UPDATE SET start=MIN(start,excluded.start),end=MAX(end,excluded.end)',(key,session,start,end))
                except (OSError,ValueError,KeyError,StopIteration):continue
            self.db.commit()

    def status(self):
        with self.lock:
            result=[]
            for r in self.db.execute('SELECT * FROM watches ORDER BY added'):
                p=self.db.execute('SELECT COUNT(*) n, MAX(ts) last FROM points WHERE key=?',(r['key'],)).fetchone()
                result.append({**json.loads(r['target']), 'enabled':bool(r['enabled']), 'threshold':r['threshold'],
                               'points':p['n'],'last_bfi':p['last']})
            return result

    def query(self, key, day, series=None):
        start, end = day_bounds(day)
        with self.lock:
            series_rows = self.db.execute('SELECT series,COUNT(*) n,MIN(payload) payload FROM points WHERE key=? AND ts>=? AND ts<? GROUP BY series', (key,start,end)).fetchall()
            streams=[{'id':r['series'],'n':r['n'],'feedback':json.loads(r['payload']).get('feedback',{})} for r in series_rows]
            if not series and streams:series=max(streams,key=lambda s:s['n'])['id']
            watch=self.db.execute('SELECT threshold FROM watches WHERE key=?',(key,)).fetchone()
            threshold=watch[0] if watch else None
            bins=[]
            if series:
                for r in self.db.execute('''SELECT CAST(ts/60 AS INTEGER)*60 t, COUNT(*) n,
                    SUM(reliable) valid,AVG(variance) mean,MIN(variance) low,MAX(variance) high,
                    AVG(phi) phi,AVG(rssi) rssi, SUM(CASE WHEN reliable=1 AND variance>? THEN 1 ELSE 0 END) above
                    FROM points WHERE key=? AND ts>=? AND ts<? AND series=? GROUP BY CAST(ts/60 AS INTEGER) ORDER BY t''',
                    (threshold,key,start,end,series)):
                    bins.append(dict(r))
            intervals=[(max(start,r[0]),min(end,r[1])) for r in self.db.execute('SELECT start,end FROM coverage WHERE key=? AND end>? AND start<? ORDER BY start',(key,start,end))]
            merged=[]
            for a,b in intervals:
                if b<=a:continue
                if merged and a<=merged[-1][1]:merged[-1][1]=max(merged[-1][1],b)
                else:merged.append([a,b])
            hours=[]
            for t in range(int(start),int(end),3600):
                rows=[b for b in bins if t<=b['t']<t+3600]
                n=sum(b['n'] for b in rows);valid=sum(b['valid'] for b in rows)
                hours.append({'ts':t,'hour':datetime.fromtimestamp(t,ZONE).strftime('%H:%M %z'), 'n':n,'valid':valid,
                              'above_pct':100*sum(b['above'] for b in rows)/valid if threshold is not None and valid else None,
                              'radio_seconds':sum(max(0,min(b,t+3600)-max(a,t)) for a,b in merged),
                              'minutes_with_bfi':len(rows)})
            notes=[dict(r) for r in self.db.execute('SELECT id,ts,text FROM notes WHERE key=? AND ts>=? AND ts<? ORDER BY ts',(key,start,end))]
            errors=self.db.execute('SELECT COUNT(*) FROM errors WHERE key=? AND ts>=? AND ts<?',(key,start,end)).fetchone()[0]
            return dict(key=key,day=day,start=start,end=end,timezone='Europe/Madrid',series=series,streams=streams,
                        bins=bins,hours=hours,coverage=merged,notes=notes,threshold=threshold,decode_errors=errors)

    def raw(self,key,day,cursor=0):
        start,end=day_bounds(day)
        cursor=int(cursor)
        if cursor<0:raise ValueError('Cursor no válido')
        with self.lock:
            rows=self.db.execute('SELECT rowid,session,payload FROM points WHERE key=? AND ts>=? AND ts<? AND rowid>? ORDER BY rowid LIMIT 2000',(key,start,end,cursor)).fetchall()
            return {'points':[dict(session=r['session'],**json.loads(r['payload'])) for r in rows],
                    'cursor':rows[-1]['rowid'] if rows else cursor,'more':len(rows)==2000}
