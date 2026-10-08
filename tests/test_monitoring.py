import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'live'))
from monitoring import MonitoringStore, day_bounds

TARGET=dict(key='02:00:00:00:00:1e|02:00:00:00:00:24|5500',mac='02:00:00:00:00:1e',ap='02:00:00:00:00:24',frequency=5500,channel=100,width=80,center=5530)

class MonitoringTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.store=MonitoringStore(self.root/'index.sqlite3');self.store.add(TARGET)
    def tearDown(self):
        self.store.db.close();self.tmp.cleanup()
    def point(self, ts, series='vht-a',value=0):
        return dict(ts=ts,series_id=series,variance=value,variance_phi=.1,quality='valid',rssi=-77)
    def test_idempotent_persistent_index_and_stream_separation(self):
        t=day_bounds('2026-10-04')[0]+60
        for _ in range(2):self.store._point(TARGET['key'],'session',self.point(t))
        self.store._point(TARGET['key'],'session',self.point(t,'he-b',9))
        self.store.db.commit()
        q=self.store.query(TARGET['key'],'2026-10-04','vht-a')
        self.assertEqual(q['bins'][0]['n'],1);self.assertEqual(q['bins'][0]['mean'],0)
        self.assertIsNone(q['threshold']);self.assertIsNone(q['hours'][0]['above_pct'])
        self.store.disable(TARGET['key'])
        self.assertEqual(self.store.status()[0]['points'],2)
    def test_coverage_union_and_no_data_is_not_quiet(self):
        t=day_bounds('2026-10-04')[0]
        self.store.db.executemany('INSERT INTO coverage VALUES(?,?,?,?)',[(TARGET['key'],'a',t,t+100),(TARGET['key'],'b',t+50,t+150)])
        q=self.store.query(TARGET['key'],'2026-10-04')
        self.assertEqual(q['hours'][0]['radio_seconds'],150)
        self.assertEqual(q['bins'],[])
    def test_dst_day_lengths(self):
        a,b=day_bounds('2026-10-25');self.assertEqual(b-a,25*3600)
        a,b=day_bounds('2026-03-29');self.assertEqual(b-a,23*3600)
    def test_wrong_channel_rejected_same_channel_allowed(self):
        other={**TARGET,'mac':'02:00:00:00:00:1a','key':'other'}
        self.store.add(other);self.assertEqual(len(self.store.active()),2)
        with self.assertRaises(ValueError):self.store.add({**other,'key':'wrong','channel':36,'frequency':5180})
    def test_import_only_complete_lines_and_no_duplicates(self):
        folder=self.root/'captures'/'example';folder.mkdir(parents=True)
        t=day_bounds('2026-10-04')[0]
        (folder/'session.json').write_text(json.dumps(dict(mode='live',client=TARGET['mac'],ap=TARGET['ap'],radio=TARGET,started='2026-10-04T00:00:00+02:00',elapsed_s=10)))
        p=folder/'variance.jsonl';p.write_text(json.dumps(self.point(t))+'\n'+json.dumps(self.point(t+1)))
        self.store.import_sessions(folder.parent);self.store.import_sessions(folder.parent)
        self.assertEqual(self.store.status()[0]['points'],1)
        with p.open('a') as f:f.write('\n')
        self.store.import_sessions(folder.parent)
        self.assertEqual(self.store.status()[0]['points'],2)
        self.assertEqual(self.store.raw(TARGET['key'],'2026-10-04')['points'][1]['ts'],t+1)
    def test_invalid_threshold(self):
        for v in (float('nan'),-1,True):
            with self.assertRaises(ValueError):self.store.threshold(TARGET['key'],v)

if __name__=='__main__':unittest.main()
