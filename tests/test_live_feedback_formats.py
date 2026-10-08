"""Independent wire fixtures and streaming graph regression checks."""
from pathlib import Path
import sys, unittest, struct, subprocess, tempfile, io, json
import numpy as np
sys.path[:0]=[str(Path(__file__).resolve().parents[1]),str(Path(__file__).resolve().parents[1]/'live')]
from engine import decode_line,FIELDS,RollingVariance,SeriesVariance,tshark_command
from discovery import Observations,tshark_discovery_command,core_line

C='02:00:00:00:00:1c';A='02:00:00:00:00:1d'
def fields(**values):
    d={'frame.time_epoch':'100','wlan.ta':C,'wlan.ra':A,'radiotap.dbm_antsignal':'-75','wlan.fc.type_subtype':'0x0e'}
    d.update(values);return '|'.join(d.get(k,'') for k in FIELDS)

def raw_pcap(action):
    mac=lambda s:bytes.fromhex(s.replace(':',''))
    pkt=bytes.fromhex('0000080000000000')+b'\xe0\x00\x00\x00'+mac(A)+mac(C)+mac(A)+b'\x10\x00'+action
    return struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,127)+struct.pack('<IIII',100,0,len(pkt),len(pkt))+pkt

class FeedbackTests(unittest.TestCase):
    def tshark(self,action):
        from dependency_support import require_tshark
        require_tshark(tshark_discovery_command("synthetic.pcap"))
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'f.pcap';p.write_bytes(raw_pcap(action))
            r=subprocess.run(tshark_discovery_command(p),capture_output=True,text=True)
            self.assertEqual(r.returncode,0,r.stderr)
            return r.stdout

    def test_ht_all_codebooks_decoded_from_wire_by_tshark(self):
        for cb in range(4):
            # 2x1 HT, 20MHz Ng1, constant phi=1 psi=1 across 56 carriers.
            width=2*cb+4;word=1+(1<<(cb+3));packed=sum(word<<(width*i) for i in range(56))
            control=4+(cb<<9)
            action=bytes([7,6])+struct.pack('<HI',control,0)+b'\x00'+packed.to_bytes((56*width+7)//8,'little')
            line=self.tshark(action);r=decode_line(core_line(line.strip().split('|')),C,A)
            self.assertEqual(r['feedback']['kind'],'HT');self.assertEqual(len(r['psi']),56)
            np.testing.assert_allclose(r['phi'],np.pi*(1/2**(cb+3)+1/2**(cb+2)))
            np.testing.assert_allclose(r['psi'],np.pi*(1/2**(cb+3)+1/2**(cb+2)))

    def test_vht_mu_both_codebooks_and_exclusive_tail(self):
        for cb,bphi,bpsi in [(0,7,5),(1,9,7)]:
            width=bphi+bpsi;word=5+(3<<bphi);packed=sum(word<<(width*i) for i in range(52))
            control=8+(cb<<10)+(1<<11)+(1<<15)
            action=bytes([21,0])+control.to_bytes(3,'little')+b'\x00'+packed.to_bytes((52*width+7)//8,'little')+bytes(15)
            line=self.tshark(action);r=decode_line(core_line(line.strip().split('|')),C,A)
            self.assertEqual(r['feedback']['feedback'],'MU')
            np.testing.assert_allclose(r['phi'],np.pi*(1/2**bphi+5/2**(bphi-1)))
            np.testing.assert_allclose(r['psi'],np.pi*(1/2**(bpsi+2)+3/2**(bpsi+1)))
            p=core_line(line.strip().split('|')).split('|');p[11]=p[11][:-3]
            with self.assertRaises(ValueError):decode_line('|'.join(p),C,A)

    def test_vht_standard_ng4_and_eight_rows(self):
        # 8x1 => 7 phi + 7 psi, SU 4/2, 16 subcarriers for 20MHz Ng4.
        body=bytes(1+(16*42+7)//8)
        control=56+(2<<8)+(1<<15)
        line=self.tshark(bytes([21,0])+control.to_bytes(3,'little')+body)
        r=decode_line(core_line(line.strip().split('|')),C,A)
        self.assertEqual(r['feedback']['nr'],8);self.assertEqual(len(r['phi']),16*7)

    def test_he_all_angles_preserved_and_directions_separate(self):
        v=8+(1<<9)+(1<<15)
        data={'wlan.he.action.he_mimo_control':hex(v),'wlan.he.action.he_mimo_control.scidx':'-4, φ11:63, ψ21:1,4, φ11:0, ψ21:2'}
        text=fields(**data);r=decode_line(text,C,A);reverse=decode_line(text,A,C)
        self.assertEqual(len(r['phi']),2);self.assertNotEqual(r['series_id'],reverse['series_id'])
        self.assertEqual(core_line(text.split('|')),text)
        data['wlan.he.action.he_mimo_control.scidx']='-4, φ11:63'
        with self.assertRaisesRegex(ValueError,'número'):decode_line(fields(**data),C,A)

    def test_he_cqi_fragment_or_malformed_not_faked(self):
        for control,bad in [(8+(2<<10)+(1<<15),''),(8+(1<<12)+(1<<15),''),(8+(1<<15),'1')]:
            with self.assertRaises(ValueError):decode_line(fields(**{'wlan.he.action.he_mimo_control':hex(control),'_ws.malformed':bad}),C,A)

    def test_every_sample_has_point_despite_gaps(self):
        e=RollingVariance();rows=[e.push(t,np.array([v]),(1,),np.array([v])) for t,v in [(0,0),(1,1),(20,2),(21,4)]]
        self.assertEqual([r['variance'] for r in rows],[0,.25,0,1])
        self.assertTrue(rows[0]['single_sample']);self.assertTrue(rows[2]['single_sample'])
        self.assertFalse(rows[3]['reliable']);self.assertEqual(rows[3]['n_window'],2)
        self.assertTrue(all(r['variance_phi'] is not None for r in rows))

    def test_two_streams_never_mix_samples(self):
        e=SeriesVariance()
        e.push(0,np.array([0]),('SU','tx'));e.push(.1,np.array([100,100]),('HE','rx'))
        a=e.push(1,np.array([2]),('SU','tx'));b=e.push(1.1,np.array([100,100]),('HE','rx'))
        self.assertEqual(a['variance'],1);self.assertEqual(b['variance'],0)
        self.assertEqual(a['n_window'],2);self.assertEqual(b['n_window'],2)

if __name__=='__main__':unittest.main()
