"""Metadatos 802.11 observados pasivamente; no reconstruye handshakes ausentes."""
from copy import deepcopy
import math

FIELDS = ['wlan.fc.retry','wlan.fc.protected','wlan.fixed.auth.alg',
          'wlan.fixed.auth_seq','wlan.fixed.status_code','wlan.fixed.reason_code',
          'eapol.type','wlan_rsna_eapol.keydes.msgnr','wlan_rsna_eapol.keydes.key_info.key_type',
          'wlan.rsn.akms','wlan.rsn.pcs','wlan.rsn.gcs',
          'wlan.rsn.capabilities.mfpc','wlan.rsn.capabilities.mfpr',
          'wlan.fixed.capabilities.privacy','wlan.wfa.ie.wpa.version',
          'wlan.ht.capabilities','wlan.vht.capabilities','wlan.ext_tag.he_mac_caps',
          'wlan.vht.capabilities.subeamformer','wlan.vht.capabilities.subeamformee',
          'wlan.vht.capabilities.mubeamformer','wlan.vht.capabilities.mubeamformee',
          'radiotap.mcs.known','radiotap.vht.known','radiotap.he.data_1','radiotap.datarate',
          'wlan.ssid','wlan.fc.pwrmgt','wlan.ndp.token.variant','wlan.fixed.aid',
          'wlan.he.action','wlan.ext_tag.he_phy_cap.su_beamformer',
          'wlan.ext_tag.he_phy_cap.su_beamformee','wlan.ext_tag.he_phy_cap.mu_beamformer']

def number(value):
    try:return int(value.split(',')[0],0) if value else None
    except (ValueError,AttributeError):return None

def flag(value):
    v=str(value).split(",")[0].lower()
    if v in ("true","false"):return v=="true"
    n=number(value)
    return None if n is None else bool(n)

def values(value):
    return sorted(set(v for v in (value or '').split(',') if v))

def capabilities(f):
    modes=[]
    for field,name in [('wlan.ht.capabilities','HT / 802.11n'),('wlan.vht.capabilities','VHT / 802.11ac'),('wlan.ext_tag.he_mac_caps','HE / 802.11ax')]:
        if f.get(field):modes.append(name)
    return dict(modes=modes, su_beamformer=flag(f.get('wlan.vht.capabilities.subeamformer')),
                su_beamformee=flag(f.get('wlan.vht.capabilities.subeamformee')),
                mu_beamformer=flag(f.get('wlan.vht.capabilities.mubeamformer')),
                mu_beamformee=flag(f.get('wlan.vht.capabilities.mubeamformee')),
                he_su_beamformer=flag(f.get('wlan.ext_tag.he_phy_cap.su_beamformer')),
                he_su_beamformee=flag(f.get('wlan.ext_tag.he_phy_cap.su_beamformee')),
                he_mu_beamformer=flag(f.get('wlan.ext_tag.he_phy_cap.mu_beamformer')))

def security(f):
    return dict(akm=values(f.get('wlan.rsn.akms')),pairwise=values(f.get('wlan.rsn.pcs')),
                group=values(f.get('wlan.rsn.gcs')),pmf_capable=flag(f.get('wlan.rsn.capabilities.mfpc')),
                pmf_required=flag(f.get('wlan.rsn.capabilities.mfpr')),
                privacy=flag(f.get('wlan.fixed.capabilities.privacy')),wpa1=bool(f.get('wlan.wfa.ie.wpa.version')))

def fresh():
    return dict(schema=2,frames={},directions={},signals={},bfi={},ndpa={},retries=0,protected=0,total=0,eapol={},pairwise_messages={},
                group_key=0,auth_algorithms=[],status_codes=[],reason_codes=[],
                phy={},events=[],first_seen=None,last_seen=None,client_capabilities=None,
                association_security=None,ap_advertised=None)

MGMT={0:'association_request',1:'association_response',2:'reassociation_request',
      3:'reassociation_response',10:'disassociation',11:'authentication',12:'deauthentication',
      13:'action',14:'action_no_ack'}

def observe(p,f,kind,subtype,ts,from_client,advertised=None,length=0,rssi=None):
    if p['first_seen'] is None:p['first_seen']=ts
    p['last_seen']=ts;p['total']+=1
    p['retries']+=flag(f.get('wlan.fc.retry')) is True
    p['protected']+=flag(f.get('wlan.fc.protected')) is True
    name=MGMT.get(subtype,'management_other') if kind==0 else ('null_data' if subtype & 4 else 'data') if kind==2 else ('ndpa' if subtype==21 else 'control')
    direction='tx' if from_client else 'rx'
    d=p.setdefault('directions',{}).setdefault(direction,dict(frames=0,bytes=0,data_frames=0,null_frames=0,protected=0,retries=0))
    d['frames']+=1;d['bytes']+=max(0,length);d['data_frames']+=name=='data';d['null_frames']+=name=='null_data'
    d['protected']+=flag(f.get('wlan.fc.protected')) is True;d['retries']+=flag(f.get('wlan.fc.retry')) is True
    p[direction+'_frames']=d['frames'];p[direction+'_bytes']=d['bytes']
    record_signal(p,'client' if from_client else 'ap',rssi,ts)
    if from_client and flag(f.get('wlan.fc.pwrmgt')) is not None:
        p['power_save']=dict(value=flag(f.get('wlan.fc.pwrmgt')),ts=ts)
    if kind==1 and subtype==21:
        variant=number(f.get('wlan.ndp.token.variant'));label=NDPA_VARIANTS.get(variant,'Sin variante')
        key=('client_to_ap' if from_client else 'ap_to_client')
        counts=p.setdefault('ndpa',{}).setdefault(key,{})
        counts[label]=counts.get(label,0)+1
    p['frames'][name]=p['frames'].get(name,0)+1
    if advertised:p['ap_advertised']=deepcopy(advertised)
    for field,target in [('wlan.fixed.auth.alg','auth_algorithms'),('wlan.fixed.status_code','status_codes'),('wlan.fixed.reason_code','reason_codes')]:
        n=number(f.get(field))
        if n is not None and n not in p[target]:p[target].append(n)
    if kind==0 and subtype in (1,3) and not from_client:
        p['association_response']=dict(status=number(f.get('wlan.fixed.status_code')),aid=number(f.get('wlan.fixed.aid')),ts=ts,capabilities=capabilities(f))
    if kind==0 and subtype in (10,12):
        p['last_disconnect']=dict(reason=number(f.get('wlan.fixed.reason_code')),ts=ts)
    if from_client and kind==0 and subtype in (0,2):
        p['client_capabilities']=capabilities(f)
        p['association_security']=security(f)
    he_action=number(f.get('wlan.he.action'))
    if he_action==0:
        counts=p.setdefault('he_feedback',{})
        key='client_to_ap' if from_client else 'ap_to_client'
        counts[key]=counts.get(key,0)+1
    phy='HE' if f.get('radiotap.he.data_1') else 'VHT' if f.get('radiotap.vht.known') else 'HT' if f.get('radiotap.mcs.known') else 'legacy' if f.get('radiotap.datarate') else 'no_reportado'
    p['phy'][phy]=p['phy'].get(phy,0)+1
    eapol=number(f.get('eapol.type'));message=number(f.get('wlan_rsna_eapol.keydes.msgnr'))
    if eapol is not None:
        p['eapol'][str(eapol)]=p['eapol'].get(str(eapol),0)+1
        if eapol==3:
            pairwise=flag(f.get('wlan_rsna_eapol.keydes.key_info.key_type'))
            if pairwise is True and message in (1,2,3,4):
                m='M'+str(message);p['pairwise_messages'][m]=p['pairwise_messages'].get(m,0)+1
            elif pairwise is False:p['group_key']+=1
    if name in ('authentication','association_request','association_response','reassociation_request','reassociation_response','disassociation','deauthentication') or eapol is not None:
        p['events'].append(dict(ts=ts,event='EAPOL' if eapol is not None else name,
            direction='cliente → AP' if from_client else 'AP → cliente',
            status=number(f.get('wlan.fixed.status_code')),reason=number(f.get('wlan.fixed.reason_code')),
            message=message if eapol==3 and flag(f.get('wlan_rsna_eapol.keydes.key_info.key_type')) is True else None))
        p['events']=p['events'][-50:]
    return p


NDPA_VARIANTS={0:'VHT',1:'Ranging',2:'HE',3:'EHT'}

def ssid(value):
    if not value:return None
    try:
        raw=bytes.fromhex(value.split(',')[0].replace(':',''))
        return raw.decode('utf-8',errors='replace') if raw else None
    except ValueError:return None

def record_signal(p,name,rssi,ts):
    if rssi is None or not math.isfinite(rssi):return
    s=p.setdefault('signals',{}).setdefault(name,dict(n=0,mean=0,min=rssi,max=rssi))
    s['n']+=1;s['mean']+=(rssi-s['mean'])/s['n'];s['min']=min(s['min'],rssi);s['max']=max(s['max'],rssi)
    s.update(last=rssi,ts=ts)
    if name=='client':p.update(client_rssi=rssi,client_rssi_ts=ts)

def record_bfi(p,parts,from_client,compatible=False,reason=None,description=None,kind=None):
    if not parts[11] and kind is None:return
    b=p.setdefault('bfi',{}).setdefault('client_to_ap' if from_client else 'ap_to_client',dict(total=0,compatible=0,rejected={},configs={}))
    b['total']+=1;b['compatible']+=bool(compatible)
    if reason:b['rejected'][reason]=b['rejected'].get(reason,0)+1
    if description:
        d=description
        name=f"{d['kind']} {d['nr']}×{d['nc']} · {d['feedback']} · BW {d['width']} MHz · Ng {d['grouping']} · codebook {d['codebook']}"
        b['configs'][name]=b['configs'].get(name,0)+1
        return
    if kind and kind!='VHT':
        b['configs'][kind]=b['configs'].get(kind,0)+1
        return
    cfg=[number(v) for v in parts[5:11]]
    if all(v is not None for v in cfg):
        width,grouping,codebook,feedback,nc,nr=cfg
        name=f'VHT {nr+1}×{nc+1} · {"MU" if feedback else "SU"} · BW { {0:20,1:40,2:80,3:160}.get(width,"?")} MHz · Ng { {0:1,1:2,2:4}.get(grouping,"?")} · codebook {codebook}'
        b['configs'][name]=b['configs'].get(name,0)+1
