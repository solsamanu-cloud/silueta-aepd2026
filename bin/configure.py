#!/usr/bin/env python3
"""Create private, ignored receiver settings. No Wi-Fi password is needed."""
import argparse,json,os,re,sys
from pathlib import Path
BASE=Path(__file__).resolve().parents[1];sys.path.insert(0,str(BASE/'live'))
import policy,radio
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--interface',required=True);p.add_argument('--ap',required=True)
    p.add_argument('--client',action='append',required=True,help='Repeat CODE=MAC for each consenting client, e.g. C01=...')
    p.add_argument('--ssid',default='',help='Nombre esperado de tu red; opcional para SSID oculto')
    p.add_argument('--consent',action='store_true',help='Confirm that network and all persons are owned/authorized and consenting')
    a=p.parse_args()
    if not a.consent:p.error('Se requiere consentimiento explícito y solo enlaces propios/autorizados')
    if not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,32}',a.interface):p.error('Interfaz inválida')
    ap=policy.validate_mac(a.ap);clients={};ids=set()
    for value in a.client:
        code,sep,mac=value.partition('=')
        if not sep or not re.fullmatch(r'C\d{2}',code) or code in ids:p.error('Usa códigos C01–C99 únicos')
        mac=policy.validate_mac(mac)
        if mac==ap or mac in clients:p.error('Cada cliente y el AP deben ser diferentes')
        ids.add(code);clients[mac]=dict(id=code,name='Cliente autorizado '+code)
    os.umask(0o077)
    policy.save(dict(interface=a.interface, ap=ap,
                     clients=[dict(id=item['id'],mac=mac) for mac,item in clients.items()],
                     radio_mode='auto',ssid=a.ssid,consent=a.consent))
    for name in ('state','captures/live','logs'):(BASE/name).mkdir(parents=True,exist_ok=True)
    print('Declaración privada guardada en local/authorization.json. No publiques sus identificadores. Reinicia la GUI si estaba abierta.')
if __name__=='__main__':main()
