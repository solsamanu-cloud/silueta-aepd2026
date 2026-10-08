import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

BASE=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(BASE),str(BASE/'live')]
import protocol
from discovery import Observations,EXTRA_FIELDS,tshark_discovery_command
from engine import FIELDS
from server import Manager,CLIENT
AP='02:00:00:00:00:06'


def packet(subtype,kind=0,tx=CLIENT,rx=AP,**fields):
    parts=['']*(len(FIELDS)+len(EXTRA_FIELDS))
    for i,v in {0:'1234',1:tx,2:'-70',12:rx,13:str(subtype),len(FIELDS):AP,len(FIELDS)+1:str(kind),len(FIELDS)+2:'5180'}.items():parts[i]=v
    for name,value in fields.items():parts[len(FIELDS)+8+protocol.FIELDS.index(name)]=str(value)
    return '|'.join(parts)

class ProtocolTests(unittest.TestCase):
    def test_pairwise_messages_group_updates_and_retries_are_distinct(self):
        obs=Observations()
        for msg in (1,2,2,3,4):
            obs.consume(packet(40,kind=2,**{'eapol.type':3,'wlan_rsna_eapol.keydes.msgnr':msg,'wlan_rsna_eapol.keydes.key_info.key_type':1,'wlan.fc.retry':int(msg==2)}))
        obs.consume(packet(40,kind=2,**{'eapol.type':3,'wlan_rsna_eapol.keydes.msgnr':1,'wlan_rsna_eapol.keydes.key_info.key_type':0}))
        p=obs.result()[0]['protocol']
        self.assertEqual(p['pairwise_messages'],{'M1':1,'M2':2,'M3':1,'M4':1})
        self.assertEqual(p['group_key'],1)
        self.assertEqual(p['retries'],2)
        self.assertNotIn('handshake_complete',p)

    def test_ap_advertisement_is_not_client_negotiation(self):
        obs=Observations()
        beacon=packet(8,tx=AP,rx='ff:ff:ff:ff:ff:ff',**{'wlan.rsn.akms':'0x000fac02,0x000fac08','wlan.rsn.capabilities.mfpc':1,'wlan.rsn.capabilities.mfpr':0,'wlan.vht.capabilities':'0x0'})
        obs.consume(beacon);obs.consume(packet(11,**{'wlan.fixed.auth.alg':0}))
        p=obs.result()[0]['protocol']
        self.assertEqual(len(p['ap_advertised']['security']['akm']),2)
        self.assertIsNone(p['association_security'])
        self.assertIsNone(p['client_capabilities'])
        obs.consume(packet(0,**{'wlan.rsn.akms':'0x000fac02','wlan.vht.capabilities':'0x1000','wlan.vht.capabilities.subeamformee':1}))
        p=obs.result()[0]['protocol']
        self.assertEqual(p['association_security']['akm'],['0x000fac02'])
        self.assertTrue(p['client_capabilities']['su_beamformee'])


    def test_preflight_tunes_the_selected_channel_and_width(self):
        m=Manager(Path("/synthetic-not-opened.pcap"));m.replay=None
        m.radio=dict(channel=13,frequency=2472,width=40,center=2462)
        def run(args,**kwargs):
            return subprocess.CompletedProcess(args,0,'type monitor' if args[0]=='iw' else '','')
        with tempfile.TemporaryDirectory() as folder,patch('server.BASE',Path(folder)),patch('server.Path.iterdir',return_value=iter([])),patch('server.subprocess.run',side_effect=run),patch('server.os.geteuid',return_value=0),patch('policy.authorization',return_value={'radio_mode':'manual'}),patch('radio.monitor_info',return_value=dict(channel=36,frequency=5180,width=80,center=5210)),patch('radio.tune',return_value=m.radio) as tune:
            try:m.preflight('testiface')
            finally:
                if m.capture_lock:m.capture_lock.close()
            tune.assert_called_once_with('testiface',m.radio)

if __name__=='__main__':unittest.main()
