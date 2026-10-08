"""Compressed feedback adapters. Keep campaign/offline decoders unchanged.

Reference: Wireshark epan/dissectors/packet-ieee80211.c,
add_ff_vht_compressed_beamforming_report, dissect_compressed_beamforming_and_cqi,
dissect_he_feedback_matrix, get_mimo_ns. HE SCIDX/angles are dissected by tshark;
do not use the old empirical HE full-band table for RU or Ng16 reports.
"""
import hashlib
import re
from types import SimpleNamespace
import numpy as np

EXTRA_FIELDS = ['wlan.he.action.he_mimo_control',
                'wlan.he.action.he_mimo_control.scidx',
                'wlan.fixed.mimo.control', '@wlan.mimo.csimatrices.cbf',
                '_ws.malformed', 'wlan.fcs.status',
                'wlan.vht.mimo_control.firstfeedbackseg',
                'wlan.vht.exclusive_beamforming_report',
                'wlan.eht.mimo.control', 'wlan.mimo.csimatrices.bf',
                'radiotap.flags.badfcs']
PRESERVE_MULTIPLE = {'wlan.he.action.he_mimo_control.scidx'}
VHT_NSC = ((52,30,16),(108,58,30),(234,122,62),(468,244,124))
VHT_DELTA_NSC = ((30,16,10),(58,30,16),(122,62,32),(244,124,64))

def report_kind(fields):
    if fields.get('wlan.vht.compressed_beamforming_report'):return 'VHT'
    if fields.get('wlan.he.action.he_mimo_control'):return 'HE'
    if fields.get('@wlan.mimo.csimatrices.cbf'):return 'HT'
    if fields.get('wlan.eht.mimo.control'):return 'EHT'
    if fields.get('wlan.mimo.csimatrices.bf'):return 'HT no comprimido'
    return None

def config(nr,nc,bw,ng,cb,fb,bphi,bpsi,nsc,kind):
    if not (2<=nr<=8 and 1<=nc<=nr and nsc>0):
        raise ValueError(f'{kind}: dimensiones sin ángulos o inválidas ({nr}×{nc})')
    count=sum(nr-c for c in range(1,min(nc,nr-1)+1))
    return SimpleNamespace(nr=nr,nc=nc,chanwidth=bw,grouping=ng,codebookinfo=cb,
        feedbacktype=fb,bits_phi=bphi,bits_psi=bpsi,n_subcarriers=nsc,
        bits_per_subcarrier=count*(bphi+bpsi),n_angles_each=count)

def describe(cfg,kind,direction):
    ng=(1,2,4)[cfg.grouping] if kind!='HE' else (4,16)[cfg.grouping]
    return dict(kind=kind,nr=cfg.nr,nc=cfg.nc,width=20*(2**cfg.chanwidth),
        grouping=ng,codebook=cfg.codebookinfo,feedback='MU' if cfg.feedbacktype else 'SU',
        bits_phi=cfg.bits_phi,bits_psi=cfg.bits_psi,subcarriers=cfg.n_subcarriers,
        direction=direction)

def decode(fields,unpack):
    kind=report_kind(fields)
    if not kind:return None
    if fields.get('_ws.malformed') or fields.get('wlan.fcs.status')=='0' or fields.get('radiotap.flags.badfcs') in ('1','True','true'):
        raise ValueError(f'{kind}: trama malformada o FCS incorrecto')
    if kind in ('EHT','HT no comprimido'):
        raise ValueError(f'{kind}: informe conservado; conversión a ángulos no implementada')
    def n(name,default=0):return int(fields.get(name) or str(default),0)
    if kind=='VHT':
        bw,ng,cb,fb,nci,nri=(n('wlan.vht.mimo_control.'+s) for s in
                           ('chanwidth','grouping','codebookinfo','feedbacktype','ncindex','nrindex'))
        if bw not in range(4) or ng not in range(3) or cb not in (0,1) or fb not in (0,1):
            raise ValueError('VHT: control reservado o inválido')
        if n('wlan.vht.mimo_control.remainingfeedbackseg'):
            raise ValueError('BFI fragmentado: falta reunir segmentos; no se inventa una matriz')
        # A final fragment is not a complete report. Empty field supports older fixtures.
        first=fields.get('wlan.vht.mimo_control.firstfeedbackseg')
        if first and int(first,0)==0:
            raise ValueError('BFI fragmentado: segmento final sin comienzo')
        bphi,bpsi=((7,5),(9,7))[cb] if fb else ((4,2),(6,4))[cb]
        cfg=config(nri+1,nci+1,bw,ng,cb,fb,bphi,bpsi,VHT_NSC[bw][ng],kind)
        body=bytes.fromhex(fields['wlan.vht.compressed_beamforming_report'].replace(':',''))
        expected=cfg.nc+(cfg.n_subcarriers*cfg.bits_per_subcarrier+7)//8
        extra=(cfg.nc*VHT_DELTA_NSC[bw][ng]*4+7)//8 if fb else 0
        # The tshark parent field includes the MU-exclusive delta-SNR tail.
        if len(body)!=expected+extra:
            raise ValueError(f'VHT: longitud {len(body)} != {expected+extra} bytes')
        phi,psi=unpack(np.frombuffer(body[:expected],dtype=np.uint8),cfg)
        key=(bw,ng,cb,fb,nci,nri)
    elif kind=='HT':
        raw=bytes.fromhex(fields['wlan.fixed.mimo.control'].replace(':',''))
        if len(raw)!=6:raise ValueError('HT: control MIMO incompleto')
        v=int.from_bytes(raw[:2],'little');nc=(v&3)+1;nr=((v>>2)&3)+1
        bw=(v>>4)&1;ng=(v>>5)&3;cb=(v>>9)&3
        if ng==3 or (v>>11)&7:raise ValueError('HT: agrupación reservada o informe fragmentado')
        cfg=config(nr,nc,bw,ng,cb,0,cb+3,cb+1,((56,30,16),(114,58,30))[bw][ng],kind)
        matrix=bytes.fromhex(fields['@wlan.mimo.csimatrices.cbf'].replace(':',''))
        expected=(cfg.n_subcarriers*cfg.bits_per_subcarrier+7)//8
        if len(matrix)!=expected:raise ValueError('HT: longitud de matriz incorrecta')
        phi,psi=unpack(np.frombuffer(bytes(nc)+matrix,dtype=np.uint8),cfg)
        key=(bw,ng,cb,0,nc-1,nr-1,'HT')
    else:
        v=n('wlan.he.action.he_mimo_control');nc=(v&7)+1;nr=((v>>3)&7)+1
        bw=(v>>6)&3;ng=(v>>8)&1;cb=(v>>9)&1;fb=(v>>10)&3
        if fb not in (0,1):raise ValueError('HE CQI/reservado: no contiene los ángulos de esta gráfica')
        if (v>>12)&7 or not (v>>15)&1:raise ValueError('HE fragmentado: no hay informe completo')
        if fb==1 and ng==1:
            raise ValueError('HE MU Ng16: cuantificación pendiente de validar; se conserva el informe')
        bphi,bpsi=(((7,5),(9,7))[cb] if fb else ((4,2),(6,4))[cb])
        text=fields.get('wlan.he.action.he_mimo_control.scidx','')
        # All occurrences are required, including commas inside each SCIDX string.
        tokens=[s.strip() for s in text.split(',') if s.strip()]
        groups=[];indices=[];current=None
        for token in tokens:
            if re.fullmatch(r'-?\d+',token):
                current=[];groups.append(current);indices.append(int(token))
            else:
                m=re.fullmatch(r'([φψ])(\d)(\d):(\d+)',token)
                if not m or current is None:raise ValueError('HE: matriz SCIDX incompleta')
                current.append((m[1],int(m[2]),int(m[3]),int(m[4])))
        if not groups or len(indices)!=len(set(indices)) or indices!=sorted(indices):
            raise ValueError('HE: no hay subportadoras completas interpretables por tshark')
        cfg=config(nr,nc,bw,ng,cb,fb,bphi,bpsi,len(groups),kind)
        order=[]
        for c in range(1,min(nc,nr-1)+1):
            order += [('φ',r,c) for r in range(c,nr)] + [('ψ',r,c) for r in range(c+1,nr+1)]
        for g in groups:
            if [x[:3] for x in g]!=order:raise ValueError('HE: orden o número de ángulos incorrecto')
            if any(x[3]>=2**(bphi if x[0]=='φ' else bpsi) for x in g):raise ValueError('HE: ángulo fuera de rango')
        phi=np.array([[x[3] for x in g if x[0]=='φ'] for g in groups])[None,...]
        psi=np.array([[x[3] for x in g if x[0]=='ψ'] for g in groups])[None,...]
        signature=hashlib.sha256(','.join(map(str,indices)).encode()).hexdigest()[:16]
        key=(bw,ng,cb,fb,nc-1,nr-1,'HE',(v>>16)&127,(v>>23)&127,signature)
    return cfg,phi,psi,key,kind
