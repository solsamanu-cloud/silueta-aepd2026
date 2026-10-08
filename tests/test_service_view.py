import fcntl,json,sqlite3,tempfile,time,unittest
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'live'))
import service_view as view

class ServiceViewTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.base=Path(self.tmp.name);(self.base/'state').mkdir()
 def tearDown(self):self.tmp.cleanup()
 def test_real_lock_blocks_even_stale_status(self):
  lock=(self.base/'state/continuous-monitor.lock').open('w')
  self.assertFalse(view.protected(self.base))
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  self.assertTrue(view.protected(self.base));self.assertTrue(view.status(self.base)['protected'])
  lock.close();self.assertFalse(view.protected(self.base))
 def test_link_series_separation_readonly_and_aggregation(self):
  p=self.base/'state/monitoring.sqlite3'
  with sqlite3.connect(p) as db:
   db.executescript('CREATE TABLE watches(key TEXT,target TEXT); CREATE TABLE points(key TEXT,session TEXT,ts REAL,series TEXT,variance REAL,phi REAL,rssi REAL,reliable INTEGER,payload TEXT);')
   db.execute('insert into watches values(?,?)',('c1','{"name":"C1"}'))
   for k,s,t,v in [('c1','s1',100,1),('c1','s1',101,3),('c1','s2',102,999),('other','s1',103,900)]:
    db.execute('insert into points values(?,?,?,?,?,?,?,?,?)',(k,'test',t,s,v,.2,-60,1,json.dumps(dict(ts=t,variance=v,variance_phi=.2,rssi=-60))))
  before=p.read_bytes()
  raw=view.series(self.base,'test','c1',99,110,'s1');self.assertEqual(raw['count'],2);self.assertEqual(raw['total'],3)
  self.assertEqual([p['variance'] for p in raw['points']],[1,3])
  aggregated=view.series(self.base,'test','c1',0,10000,'s1');self.assertEqual(aggregated['count'],2);self.assertGreater(aggregated['bucket_seconds'],0)
  self.assertEqual(p.read_bytes(),before)
  with self.assertRaises(ValueError):view.series(self.base,'test','c1',0,float('inf'))
 def test_status_home_and_dual(self):
  record={'updated':time.time(),'session':'a','links':{'k':{'target':{'key':'k'},'bfi':6}}}
  path=self.base/'state/continuous-monitor.json';path.write_text(json.dumps(record))
  self.assertEqual(view.status(self.base)['service']['links'][0]['bfi'],6)
  record={'target':{'key':'a'},'secondary':{'key':'b'},'bfi':10,'secondary_bfi':2};path.write_text(json.dumps(record))
  self.assertEqual(len(view.status(self.base)['service']['links']),2)

if __name__=='__main__':unittest.main()
