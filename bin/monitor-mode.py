#!/usr/bin/env python3
"""Configure only the dedicated USB receiver. Never change regulatory settings."""
import argparse,os,subprocess,sys,shutil
from pathlib import Path
BASE=Path(__file__).resolve().parents[1];sys.path.insert(0,str(BASE/'live'))
import policy,radio,service_view
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--dry-run',action='store_true');p.add_argument('--restore-managed',action='store_true');a=p.parse_args()
    s=policy.settings();iface=s['IFACE'];policy.require_target(dict(ap=s['TARGET_BSSID'],mac=s['TARGET_CLIENT']))
    if service_view.protected(BASE):raise SystemExit('Monitorización activa: no se modifica la radio')
    radio.ensure_free(iface)
    commands=[]
    if shutil.which('nmcli'):commands.append(['nmcli','device','set',iface,'managed','yes' if a.restore_managed else 'no'])
    commands += [['ip','link','set',iface,'down'],['iw','dev',iface,'set','type','managed' if a.restore_managed else 'monitor'],['ip','link','set',iface,'up']]
    if a.restore_managed and shutil.which('nmcli'):commands.append(commands.pop(0))
    for cmd in commands:
        print(' '.join(cmd),flush=True)
        if not a.dry_run:subprocess.run(([] if os.geteuid()==0 else ['sudo','--'])+cmd,check=True)
    if not a.restore_managed and not a.dry_run:
        initial=radio.channels(iface)[0] if policy.authorization().get('radio_mode')=='auto' else policy.radio_config()
        radio.tune(iface,initial)
        print('Modo monitor preparado. El canal del AP se detectará al iniciar la captura.')
if __name__=='__main__':main()
