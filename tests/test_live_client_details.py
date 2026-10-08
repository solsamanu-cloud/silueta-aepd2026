import sys,unittest
from pathlib import Path
sys.path[:0]=[str(Path(__file__).resolve().parents[1]),str(Path(__file__).resolve().parents[1]/'live')]
import protocol
from discovery import Observations
from test_live_protocol import packet,CLIENT,AP

class ClientDetailsTests(unittest.TestCase):
 def test_null_traffic_and_bidirectional_signal(self):
  o=Observations();o.consume(packet(44,kind=2,**{'wlan.fc.protected':'False'}));o.consume(packet(40,kind=2,tx=AP,rx=CLIENT,**{'wlan.fc.protected':'True','wlan.fc.retry':'True'}))
  p=o.details(CLIENT,AP)
  self.assertEqual(p['directions']['tx']['null_frames'],1)
  self.assertEqual(p['directions']['rx']['data_frames'],1)
  self.assertEqual(p['protected'],1);self.assertEqual(p['retries'],1)
  self.assertEqual(p['signals']['client']['n'],1);self.assertEqual(p['signals']['ap']['n'],1)
 def test_ap_metadata_without_client_is_still_available(self):
  o=Observations();o.consume(packet(8,tx=AP,rx='ff:ff:ff:ff:ff:ff',**{'wlan.ssid':'54657374','wlan.rsn.akms':'1027074'}))
  p=o.details(CLIENT,AP);self.assertEqual(p['total'],0);self.assertEqual(p['ap_advertised']['ssid'],'Test')
  self.assertEqual(p['ap_context']['beacons'],1);self.assertIsNone(p['client_capabilities'])
 def test_multicast_ndpa_is_not_assigned_to_every_client(self):
  o=Observations();o.consume(packet(8,tx=AP,rx='ff:ff:ff:ff:ff:ff'))
  o.consume(packet(21,kind=1,tx=AP,rx=CLIENT,**{'wlan.ndp.token.variant':2}))
  o.consume(packet(21,kind=1,tx=AP,rx='ff:ff:ff:ff:ff:ff',**{'wlan.ndp.token.variant':0}))
  p=o.details(CLIENT,AP)
  self.assertEqual(p['ndpa']['ap_to_client'],{'HE':1})
  self.assertEqual(p['ap_context']['ndpa_all'],{'HE':1,'VHT':1})
  self.assertEqual(p['total'],1)
 def test_association_and_he_feedback_have_distinct_evidence(self):
  o=Observations();o.consume(packet(1,tx=AP,rx=CLIENT,**{'wlan.fixed.status_code':0,'wlan.fixed.aid':42}))
  o.consume(packet(14,tx=AP,rx=CLIENT,**{'wlan.he.action':0}))
  p=o.details(CLIENT,AP);self.assertEqual(p['association_response']['aid'],42)
  self.assertEqual(p['he_feedback']['ap_to_client'],1);self.assertIsNone(p['client_capabilities'])
 def test_signal_average_and_no_false_zero(self):
  p=protocol.fresh();protocol.record_signal(p,'client',None,1);self.assertEqual(p['signals'],{})
  for r in [-80,-70,-60]:protocol.record_signal(p,'client',r,2)
  self.assertEqual(p['signals']['client']['mean'],-70)
  self.assertEqual(p['signals']['client']['min'],-80)

if __name__=='__main__':unittest.main()
