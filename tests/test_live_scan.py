"""Restaurar la radio incluso al cancelar; nunca saltar sobre una captura externa."""
import io
from pathlib import Path
import sys
import unittest
import tempfile
from unittest.mock import patch
BASE=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(BASE),str(BASE/'live')]
from discovery import Discovery
import policy

ORIGINAL=dict(channel=36,frequency=5180,width=80,center=5210)
TARGETS=[dict(channel=36,frequency=5180,width=20,center=5180),dict(channel=1,frequency=2412,width=20,center=2412)]

class Process:
    def __init__(self,*args,**kwargs):
        self.stdout=io.StringIO('');self.returncode=None
    def poll(self):return self.returncode
    def send_signal(self,*args):self.returncode=0
    def wait(self,*args,**kwargs):self.returncode=0;return 0
    def kill(self):self.returncode=-9

class ScanTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        guard=patch('policy.BASE',Path(tmp.name));guard.start();self.addCleanup(guard.stop)
        policy.save(dict(interface='testiface',ap='02:00:00:00:00:06',
                         clients=[dict(id='C01',mac='02:00:00:00:00:01')],
                         frequency=5180,width=80,center=5210,consent=True))
    def run_case(self,cancel=False,fail=False):
        d=Discovery(lambda *a:None,lambda:('testiface','02:00:00:00:00:06'))
        calls=[]
        def tune(iface,target):
            calls.append(dict(target))
            if cancel:d.cancel.set()
            if fail and target['width']==20:raise ValueError('canal rechazado')
            return target
        with patch('policy.capture_filter',return_value='type mgt'),patch('discovery.fcntl.flock'),patch('radio.ensure_free'),patch('radio.monitor_info',return_value=ORIGINAL),patch('radio.channels',return_value=TARGETS),patch('radio.tune',side_effect=tune),patch('discovery.subprocess.Popen',side_effect=Process),patch('discovery.DWELL_SECONDS',.001):
            d.run()
        self.assertEqual(calls[-1],ORIGINAL)
        self.assertFalse(d.data['scanning'])
        return d
    def test_completion_restores_original_width(self):
        self.assertIsNone(self.run_case().data['error'])
    def test_cancel_restores_original_channel(self):
        self.assertTrue(self.run_case(cancel=True).data['cancelled'])
    def test_rejected_channels_are_reported_and_restored(self):
        d=self.run_case(fail=True)
        self.assertEqual(len(d.data['skipped']),2)
        self.assertIn('ningún canal',d.data['error'])
    def test_external_capture_blocks_tuning(self):
        d=Discovery(lambda *a:None,lambda:('testiface','02:00:00:00:00:06'))
        with patch('policy.capture_filter',return_value='type mgt'),patch('discovery.fcntl.flock'),patch('radio.ensure_free',side_effect=ValueError('captura externa')),patch('radio.tune') as tune:
            d.run()
        tune.assert_not_called()
        self.assertEqual(d.data['error'],'captura externa')

if __name__=='__main__':unittest.main()
