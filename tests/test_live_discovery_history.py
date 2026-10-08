"""Los barridos parciales, vacíos y reinicios no eliminan enlaces anteriores."""
from pathlib import Path
import sys
import tempfile
import unittest

BASE=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(BASE),str(BASE/'live')]
from discovery import Discovery

def peer(mac,ap,freq,channel,seen,bfi=2):
    return dict(mac=mac,ap=ap,frequency=freq,channel=channel,width=20,center=freq,
                key=f'{mac}|{ap}|{freq}',id='',label='Cliente observado',
                last_seen=seen,compatible_bfi=bfi,rssi=-60,tx_frames=3,rx_frames=1)

A=peer('02:00:00:00:00:16','02:00:00:00:00:17',5180,36,100)
B=peer('02:00:00:00:00:16','02:00:00:00:00:18',2412,1,200)

class DiscoveryHistoryTests(unittest.TestCase):
    def make(self,path):return Discovery(lambda *args:None,lambda:('test','ap'),path)
    def begin(self,d,when):
        d.history.begin(when)
        d.publish(scanning=True,cancelled=False,error=None,clients=[])

    def test_refresh_empty_and_cancel_preserve_catalog_and_scan_results(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'history.json';d=self.make(path)
            self.begin(d,90);d.publish(clients=[A]);d.publish(scanning=False)
            self.begin(d,190)
            self.assertEqual(len(d.snapshot()['clients']),1)
            self.assertFalse(d.snapshot()['clients'][0]['seen_in_latest_scan'])
            d.publish(clients=[B]);d.publish(cancelled=True,scanning=False)
            data=d.snapshot()
            self.assertEqual(len(data['clients']),2)
            self.assertEqual(data['current_count'],1)
            self.assertEqual(data['scans'][0]['clients'],[A])
            self.assertEqual(data['scans'][1]['status'],'cancelled')
            restored=self.make(path).snapshot()
            self.assertEqual(restored['clients'],data['clients'])
            self.assertEqual(restored['scans'],data['scans'])
            self.begin(d,290);d.publish(clients=[],scanning=False)
            self.assertEqual(len(self.make(path).snapshot()['clients']),2)

    def test_repeated_progress_does_not_inflate_seen_scans_or_rewrite_old_scan(self):
        d=self.make(None)
        self.begin(d,90);d.publish(clients=[A]);d.publish(clients=[{**A,'compatible_bfi':4}]);d.publish(scanning=False)
        self.assertEqual(d.snapshot()['clients'][0]['seen_scans'],1)
        self.begin(d,190);d.publish(clients=[{**A,'last_seen':201,'compatible_bfi':7}]);d.publish(scanning=False)
        p=d.snapshot()['clients'][0]
        self.assertEqual((p['first_seen'],p['last_seen'],p['seen_scans']),(100,201,2))
        self.assertEqual(d.snapshot()['scans'][0]['clients'][0]['compatible_bfi'],4)

    def test_corrupt_store_is_reported_and_not_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'history.json';path.write_text('incomplete')
            d=self.make(path);self.begin(d,90);d.publish(clients=[A],scanning=False)
            self.assertIn('No se pudo leer',d.snapshot()['history_error'])
            self.assertEqual(path.read_text(),'incomplete')

if __name__=='__main__':unittest.main()
