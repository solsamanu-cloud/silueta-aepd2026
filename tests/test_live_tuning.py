"""Fail closed on wrong channel, including unchanged selection and stale metadata."""
from pathlib import Path
import sys,subprocess,tempfile,unittest,threading
from types import SimpleNamespace
from unittest.mock import patch,Mock
BASE=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(BASE),str(BASE/'live')]
import radio
import server
import policy
from server import Manager
P36=dict(channel=36,frequency=5180,width=80,center=5210)
P100=dict(channel=100,frequency=5500,width=80,center=5530)
P1=dict(channel=1,frequency=2412,width=20,center=2412)
C='02:00:00:00:00:05';AP='02:00:00:00:00:06'

class TuningTests(unittest.TestCase):
 def setUp(self):
  tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
  guard=patch('policy.BASE',Path(tmp.name));guard.start();self.addCleanup(guard.stop)
  policy.save(dict(interface='alfa',ap=AP,clients=[dict(id='C05',mac=C)],
                   frequency=5180,width=80,center=5210,consent=True))
 def manager(self):return Manager(replay=Path('/not-used.pcap'))
 def test_actual_channel_mismatch_rejected_even_if_iw_exits_zero(self):
  with patch('radio.run',return_value=SimpleNamespace(returncode=0)),patch('radio.monitor_info',return_value=P100),patch('radio.time.sleep'):
   with self.assertRaisesRegex(ValueError,'Sintonía incorrecta'):radio.tune('alfa',P36)
 def test_frequency_width_center_and_channel_all_verified(self):
  for key in P36:
   wrong={**P36,key:P36[key]+1}
   with self.subTest(key=key),patch('radio.monitor_info',return_value=wrong):
    with self.assertRaises(ValueError):radio.verify('alfa',P36)
 def test_commands_for_both_bands_and_ht40(self):
  for target,tail in [(P36,['5180','80','5210']),(P100,['5500','80','5530']),(P1,['2412','HT20']),({**P36,'width':40,'center':5190},['5180','HT40+'])]:
   with patch('radio.run',return_value=SimpleNamespace(returncode=0)) as run,patch('radio.monitor_info',return_value=target):
    self.assertEqual(radio.tune('alfa',target),target)
    run.assert_called_once_with(['iw','dev','alfa','set','freq']+tail,privileged=True)
 def test_no_fallback_on_invalid_target_or_permission_error(self):
  for target in [{**P36,'channel':100},{**P1,'width':80},{'frequency':5180},{**P36,'width':True}]:
   with self.subTest(target=target),patch('radio.run') as run:
    with self.assertRaises(ValueError):radio.tune('alfa',target)
    run.assert_not_called()
  with patch('radio.run',return_value=SimpleNamespace(returncode=1,stderr='Operation not permitted',stdout='')),patch('radio.monitor_info') as info:
   with self.assertRaisesRegex(ValueError,'permitted'):radio.tune('alfa',P36)
   info.assert_not_called()
 def test_driver_transition_gets_rechecked(self):
  with patch('radio.run',return_value=SimpleNamespace(returncode=0)),patch('radio.monitor_info',side_effect=[P100,P36]),patch('radio.time.sleep'):
   self.assertEqual(radio.tune('alfa',P36),P36)
 def test_preflight_always_tunes_even_if_same_channel(self):
  m=self.manager();m.replay=None;m.radio=P36
  with tempfile.TemporaryDirectory() as tmp,patch('server.BASE',Path(tmp)),patch('server.os.geteuid',return_value=0),patch('server.Path.iterdir',return_value=[]),patch('server.shutil.disk_usage',return_value=SimpleNamespace(free=2**30)),patch('server.subprocess.run',side_effect=[SimpleNamespace(returncode=0,stdout='type monitor'),SimpleNamespace(returncode=0,stdout='')]),patch('radio.tune',return_value=P36) as tune:
   try:m.preflight('alfa');tune.assert_called_once_with('alfa',P36);self.assertTrue(m.radio_verification['ok'])
   finally:m.capture_lock.close()
 def test_periodic_verification_reports_failure_and_raises(self):
  m=self.manager();m.radio=P36
  with patch('radio.verify',side_effect=ValueError('changed to 100')):
   with self.assertRaisesRegex(ValueError,'Captura detenida'):m.check_radio('alfa')
  self.assertFalse(m.radio_verification['ok'])
 def test_exact_key_cannot_bypass_validation(self):
  m=self.manager();m.discovery.data['clients']=[{'key':'bad','mac':C,'ap':AP,**P36,'channel':100}]
  with self.assertRaises(ValueError):m.resolve_target('bad')
 def test_missing_channel_not_inherited_from_previous_client(self):
  m=self.manager();m.discovery.data['clients']=[{'mac':C,'ap':AP}]
  with self.assertRaises(ValueError):m.resolve_target(C)
 def test_secondary_reception_uses_recent_primary_beacon_same_ap(self):
  m=self.manager()
  secondary={'mac':C,'ap':AP,'key':'secondary','channel_source':'receiver_only','channel':120,'frequency':5600,'width':20,'center':5600}
  primary={**secondary,'channel_source':'AP beacon / probe response','channel':116,'frequency':5580,'width':80,'center':5610,'advertised':{'ts':server.time.time()}}
  m.discovery.data['clients']=[secondary,primary]
  target=m.resolve_target('secondary')
  self.assertEqual((target['channel'],target['width'],target['center']),(116,80,5610))
  self.assertEqual(target['tuning_resolution']['observed_frequency'],5600)
 def test_secondary_not_reassigned_from_stale_or_different_ap_or_band(self):
  m=self.manager()
  secondary={'mac':C,'ap':AP,'channel_source':'receiver_only','channel':120,'frequency':5600,'width':20,'center':5600}
  primary={**secondary,'channel_source':'AP beacon / probe response','channel':116,'frequency':5580,'width':80,'center':5610,'advertised':{'ts':server.time.time()}}
  for candidate in [{**primary,'ap':'02:00:00:00:00:16'},{**primary,'advertised':{'ts':server.time.time()-7200}},{**primary,**P36}]:
   m.discovery.data['clients']=[candidate]
   self.assertEqual(m.checked_target(secondary)['channel'],120)
 def test_same_link_changed_width_restarts_after_join(self):
  m=self.manager();m.client=C;m.ap=AP;m.radio=P36;m.state='capturing';m.replay=None
  target={**m.current_target(),'width':20,'center':5180};m.discovery.data['clients']=[target]
  order=[];m.thread=Mock();m.thread.is_alive.side_effect=[True,False];m.thread.join.side_effect=lambda **kw:order.append('join')
  m.start=Mock(side_effect=lambda *a,**kw:order.append('start'))
  m.select_client(target['key']);self.assertEqual(order,['join','start']);self.assertTrue(m.stop_event.is_set())
 def test_same_active_link_is_not_trusted_without_radio_check(self):
  m=self.manager();m.client=C;m.ap=AP;m.radio=P36;m.state='capturing';m.replay=None
  m.discovery.data['clients']=[m.current_target()];m.start=Mock()
  with patch('radio.verify',side_effect=ValueError('wrong channel')):m.select_client(m.current_target()['key'])
  m.start.assert_called_once()

if __name__=='__main__':unittest.main()
