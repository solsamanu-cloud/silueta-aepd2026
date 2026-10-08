"""Consent, API bypass and real libpcap/kernel filtering; synthetic packets only."""
import ctypes as C
import ctypes.util
from http.client import HTTPConnection
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'live')]
import policy, server
from discovery import Discovery
from silueta.synthetic import AP, CLIENT, mac

OTHER='02:00:00:00:00:33';AP2='02:00:00:00:00:34'
def declaration():
 return dict(interface='testiface',ap=AP,clients=[dict(id='C01',mac=CLIENT)],frequency=5180,width=80,center=5210,consent=True)

def frame(fc,ra,ta=None,bssid=None):
 rt=struct.pack('<BBHI',0,0,8,0)
 body=struct.pack('<HH',fc,0)+mac(ra)
 if ta:body+=mac(ta)
 if bssid:body+=mac(bssid)+b'\0\0'
 return rt+body+b'\0'*20

def fixtures():
 broadcast='ff:ff:ff:ff:ff:ff'
 return [
  ('BFI authorized',frame(0xe0,AP,CLIENT,AP),True),
  ('AP reverse BFI',frame(0xe0,CLIENT,AP,AP),True),
  ('second client',frame(0xe0,AP,OTHER,AP),False),
  ('wrong AP',frame(0xe0,AP2,CLIENT,AP2),False),
  ('wrong management BSSID',frame(0xe0,AP,CLIENT,AP2),False),
  ('own beacon',frame(0x80,broadcast,AP,AP),True),
  ('foreign beacon',frame(0x80,broadcast,AP2,AP2),False),
  ('broadcast probe request',frame(0x40,broadcast,CLIENT,broadcast),False),
  ('unlisted probe response',frame(0x50,OTHER,AP,AP),False),
  ('authorized uplink data',frame(0x0108,AP,CLIENT,OTHER),True),
  ('authorized downlink data',frame(0x0208,CLIENT,AP,OTHER),True),
  ('broadcast data',frame(0x0208,broadcast,AP,OTHER),False),
  ('WDS',frame(0x0308,AP,CLIENT,AP),False),
  ('unrelated ad hoc',frame(0x0008,AP,CLIENT,AP),False),
  ('unicast NDPA',frame(0x54,CLIENT,AP),True),
  ('multicast NDPA',frame(0x54,broadcast,AP),False),
  ('ACK',frame(0xd4,AP),False),
 ]

class ConsentTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
  self.p=patch('policy.BASE',self.root);self.p.start();self.addCleanup(self.p.stop);self.addCleanup(self.tmp.cleanup)
 def test_absent_legacy_corrupt_or_false_cannot_authorize(self):
  (self.root/'session.env').write_text('AUTHORIZED_CAPTURE=yes\n')
  self.assertFalse(policy.status()['authorized'])
  for operation in [policy.authorization,policy.capture_filter,lambda:policy.capture_command('testiface')]:
   with self.assertRaises(ValueError):operation()
  policy.save(declaration());(self.root/'local/authorization.json').write_text('{}')
  self.assertFalse(policy.status()['authorized'])
  (self.root/'local/authorization.json').write_text('{invalid')
  self.assertFalse(policy.status()['authorized'])
 def test_explicit_boolean_only(self):
  for value in [False,None,'true','yes',1,[],{}]:
   with self.subTest(value=value),self.assertRaises(ValueError):policy.save(dict(declaration(),consent=value))
  self.assertFalse((self.root/'local/authorization.json').exists())
 def test_invalid_peers_and_duplicates(self):
  cases=[[],[dict(id='C01',mac=AP)],[dict(id='C01',mac='ff:ff:ff:ff:ff:ff')],
         [dict(id='C01',mac=CLIENT),dict(id='C02',mac=CLIENT)],
         [dict(id='C01',mac=CLIENT),dict(id='C01',mac=OTHER)]]
  for clients in cases:
   with self.assertRaises(ValueError):policy.save(dict(declaration(),clients=clients))
  with self.assertRaises(ValueError):policy.save(dict(declaration(),interface='eth0; true'))
 def test_private_record_and_exact_scope(self):
  data=policy.save(declaration());p=self.root/'local/authorization.json'
  self.assertEqual(p.stat().st_mode & 0o777,0o600)
  self.assertEqual(p.parent.stat().st_mode & 0o777,0o700)
  self.assertTrue(policy.status()['authorized']);self.assertEqual(policy.authorization(),data)
  self.assertEqual(len(policy.fingerprint(data)),64)
  policy.require_target(dict(ap=AP,mac=CLIENT))
  for target in [dict(ap=AP2,mac=CLIENT),dict(ap=AP,mac=OTHER)]:
   with self.assertRaises(ValueError):policy.require_target(target)
  for selected in [[],[OTHER],[CLIENT,OTHER]]:
   with self.assertRaises(ValueError):policy.capture_filter(selected)
  with self.assertRaises(ValueError):policy.capture_command('anotheriface')
  command=policy.capture_command('testiface');self.assertEqual(command[-1],policy.capture_filter())
  policy.revoke();self.assertFalse(policy.status()['authorized'])
 def test_no_policy_changes_while_capture_holds_lease(self):
  policy.save(declaration())
  with policy.acquire_lease():
   with self.assertRaises(ValueError):policy.save(declaration())
   with self.assertRaises(ValueError):policy.revoke()
  policy.revoke()
 def test_second_client_expands_only_that_pair(self):
  data=declaration();data['clients'].append(dict(id='C02',mac=OTHER));policy.save(data)
  self.assertIn(OTHER,policy.capture_filter());self.assertNotIn(OTHER,policy.capture_filter([CLIENT]))
 def test_capture_and_scan_cannot_bypass_without_consent(self):
  with patch('server.BASE',self.root),patch('server.subprocess.Popen') as popen:
   m=server.Manager()
   with self.assertRaises(ValueError):m.start('blocked',None)
   with self.assertRaises(ValueError):m.refresh_clients()
   with self.assertRaises(ValueError):m.select_client(m.current_target()['key'])
   d=Discovery(lambda *args:None,server.read_settings)
   with self.assertRaises(ValueError):d.start()
   popen.assert_not_called()
   self.assertFalse((self.root/'captures').exists())
 def test_api_requires_token_and_boolean_consent(self):
  with patch('server.BASE',self.root):
   manager=server.Manager();http=server.ThreadingHTTPServer(('127.0.0.1',0),server.Handler);http.manager=manager
   thread=threading.Thread(target=http.serve_forever,daemon=True);thread.start()
   def call(path,data,token=None):
    conn=HTTPConnection('127.0.0.1',http.server_port)
    headers={'Content-Type':'application/json'}
    if token:headers['X-Live-Token']=token
    conn.request('POST',path,json.dumps(data),headers);response=conn.getresponse();body=response.read();conn.close();return response.status,body
   try:
    self.assertEqual(call('/api/authorization',declaration())[0],403)
    self.assertEqual(call('/api/authorization',dict(declaration(),consent=False),manager.token)[0],400)
    self.assertEqual(call('/api/start',dict(label='denied',duration=10),manager.token)[0],400)
    self.assertEqual(call('/api/authorization',declaration(),manager.token)[0],200)
    manager.state='capturing'
    self.assertEqual(call('/api/authorization/revoke',{},manager.token)[0],400)
    manager.state='idle'
    self.assertEqual(call('/api/authorization/revoke',{},manager.token)[0],200)
   finally:http.shutdown();http.server_close();thread.join()

class FilterTests(unittest.TestCase):
 def test_real_libpcap_and_linux_kernel_reject_unrelated_packets(self):
  if not sys.platform.startswith('linux'):self.skipTest('Linux socket filter integration')
  name=C.util.find_library('pcap')
  if not name:self.skipTest('libpcap missing')
  class Insn(C.Structure):_fields_=[('code',C.c_ushort),('jt',C.c_ubyte),('jf',C.c_ubyte),('k',C.c_uint32)]
  class Program(C.Structure):_fields_=[('length',C.c_uint),('instructions',C.POINTER(Insn))]
  class SockProgram(C.Structure):_fields_=[('length',C.c_ushort),('instructions',C.POINTER(Insn))]
  lib=C.CDLL(name);lib.pcap_open_dead.argtypes=[C.c_int,C.c_int];lib.pcap_open_dead.restype=C.c_void_p
  lib.pcap_compile.argtypes=[C.c_void_p,C.POINTER(Program),C.c_char_p,C.c_int,C.c_uint32]
  lib.pcap_close.argtypes=[C.c_void_p];lib.pcap_freecode.argtypes=[C.POINTER(Program)]
  handle=lib.pcap_open_dead(127,65535);program=Program()
  try:
   self.assertEqual(lib.pcap_compile(handle,C.byref(program),policy.build_filter(declaration()).encode(),1,0xffffffff),0)
   self.assertLessEqual(program.length,4096)
   # SO_ATTACH_FILTER evaluates exactly these compiled instructions in the kernel.
   # AF_UNIX carries synthetic radiotap bytes; no antenna, radio or privileges.
   tx,rx=socket.socketpair(socket.AF_UNIX,socket.SOCK_DGRAM)
   try:
    filt=SockProgram(program.length,program.instructions)
    rx.setsockopt(socket.SOL_SOCKET,26,bytes(filt));rx.settimeout(.02)
    for label,data,allowed in fixtures():
     with self.subTest(frame=label):
      tx.send(data)
      if allowed:self.assertEqual(rx.recv(65535),data)
      else:
       with self.assertRaises(socket.timeout):rx.recv(65535)
   finally:tx.close();rx.close()
  finally:
   lib.pcap_freecode(C.byref(program));lib.pcap_close(handle)

if __name__=='__main__':unittest.main()
