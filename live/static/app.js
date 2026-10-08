'use strict';
const $=id=>document.getElementById(id);
let state={state:'idle',points:[],markers:[],metrics:{elapsed:0},duration:null,threshold:.006820114055593958}, connected=false, pending=false, range='recent', geometry=null;
let smaSize=5, inspected=null, viewStart=0, viewSpan=120;
let archive={session:null,cursor:0,loading:false,complete:false,error:null};
let smaCache={source:null,size:0,points:[],values:[],last:null};
let clientsKey='', previousClient=null, discoveryHistoryKey='';
let protocolChoice=null,protocolRenderKey='';
try{const saved=Number(localStorage.getItem('silueta-sma-points'));if(Number.isInteger(saved)&&saved>=1&&saved<=120)smaSize=saved}catch{}

let clientBandFilter='all',clientBfiFilter='all';
try{const saved=JSON.parse(localStorage.getItem('silueta-client-filters')||'{}');if(['all','2.4','5'].includes(saved.band))clientBandFilter=saved.band;if(['all','any','compatible','other','none'].includes(saved.bfi))clientBfiFilter=saved.bfi}catch{}
function clientBand(peer){
 const f=Number(peer.frequency);
 if(f>=2400&&f<2500)return '2.4';
 if(f>=5000&&f<5900)return '5';
 // Only infer from a channel when no frequency was retained.
 if(!f&&Number(peer.channel)>=1&&Number(peer.channel)<=14)return '2.4';
 if(!f&&Number(peer.channel)>=32&&Number(peer.channel)<=177)return '5';
 return 'unknown';
}
function bandLabel(peer){return {'2.4':'2,4 GHz','5':'5 GHz',unknown:'Banda sin confirmar'}[clientBand(peer)]}
function bfiEvidence(peer,history=true,live=true){
 let compatible=Number(peer.compatible_bfi)>0;
 let any=compatible||Number(peer.vht_bfi)>0||Number(peer.reverse_vht_bfi)>0||Number(peer.unsupported_bfi)>0;
 const sources=[peer.protocol];
 if(history){
  sources.push(peer.protocol_followup,...(peer.protocol_records||[]).map(r=>r.protocol));
  for(const scan of state.discovery?.scans||[]){const old=scan.clients?.find(p=>(p.key||p.mac)===(peer.key||peer.mac));if(!old)continue;
   compatible ||= Number(old.compatible_bfi)>0;any ||= compatible||Number(old.vht_bfi)>0||Number(old.reverse_vht_bfi)>0||Number(old.unsupported_bfi)>0;sources.push(old.protocol);
  }
 }
 if(live&&(peer.key||peer.mac)===(state.client?.key||state.client?.mac)){
  sources.push(state.metrics?.protocol);compatible ||= Number(state.metrics?.bfi)>0;any ||= compatible;
 }
 for(const p of sources){if(!p)continue;
  compatible ||= Object.values(p.bfi||{}).some(v=>Number(v.compatible)>0);
  any ||= compatible||Object.values(p.bfi||{}).some(v=>Number(v.total)>0)||Object.values(p.he_feedback||{}).some(v=>Number(v)>0);
 }
 return {any,compatible,label:compatible?'BFI compatibles':any?'BFI de otros formatos / sentido':'Sin BFI observado'};
}
function matchesClientFilters(p,history=true,live=true){
 if(clientBandFilter!=='all'&&clientBand(p)!==clientBandFilter)return false;
 const b=bfiEvidence(p,history,live);
 return clientBfiFilter==='all'||clientBfiFilter==='any'&&b.any||clientBfiFilter==='compatible'&&b.compatible||clientBfiFilter==='other'&&b.any&&!b.compatible||clientBfiFilter==='none'&&!b.any;
}
function applyClientFilters(){
 clientBandFilter=$('client-band-filter').value;clientBfiFilter=$('client-bfi-filter').value;
 try{localStorage.setItem('silueta-client-filters',JSON.stringify({band:clientBandFilter,bfi:clientBfiFilter}))}catch{}
 clientsKey='';discoveryHistoryKey='';renderClients();renderCandidates();
}

const active=()=>['starting','capturing','stopping'].includes(state.state);
const format=(x,n=2)=>x==null?'—':Number(x).toLocaleString('es-ES',{minimumFractionDigits:n,maximumFractionDigits:n});
const clock=t=>{t=Math.floor(Math.max(0,t||0));return String(Math.floor(t/60)).padStart(2,'0')+':'+String(t%60).padStart(2,'0')};
function error(message){$('error').textContent=message||'';$('error').hidden=!message}
// Media causal de N valores consecutivos, sin mezclar segmentos ni salvar huecos.
function averagePoint(p,streams,size){
 const id=p.series_id||'legacy';
 const c=streams[id]||(streams[id]={values:[],last:null});
 if(p.config_changed||c.last!==null&&(p.t-c.last>2.8||p.t<=c.last))c.values=[];
 c.last=p.t;
 if(!Number.isFinite(p.variance))c.values=[];
 else{c.values.push(p.variance);if(c.values.length>size)c.values.shift()}
 return {...p,sma:c.values.length===size?c.values.reduce((a,b)=>a+b,0)/size:null};
}
function withMovingAverage(points,size=5){const streams={};return points.map(p=>averagePoint(p,streams,size))}
function chartPoints(){
 if(smaCache.source!==state.points||smaCache.size!==smaSize)smaCache={source:state.points,size:smaSize,points:[],streams:{}};
 const c=smaCache;
 for(let i=c.points.length;i<state.points.length;i++)c.points.push(averagePoint(state.points[i],c.streams,smaSize));
 return c.points;
}
function feedbackLabel(p){
 const f=p?.feedback;if(!f)return 'VHT histórico';
 return `${f.kind} ${f.nr}×${f.nc} ${f.feedback} · ${f.width} MHz · ${f.direction==='ap_to_client'?'AP → cliente':'cliente → AP'}`;
}
function renderSeries(){
 const select=$('feedback-series');if(!select)return;
 const old=select.value||'all',series=new Map(state.points.filter(p=>p.series_id).map(p=>[p.series_id,feedbackLabel(p)]));
 const key=JSON.stringify([...series]);if(select.dataset.key===key)return;
 select.dataset.key=key;select.replaceChildren();
 const all=document.createElement('option');all.value='all';all.textContent='Todos los informes';select.append(all);
 for(const [id,label] of series){const o=document.createElement('option');o.value=id;o.textContent=label;select.append(o)}
 select.value=series.has(old)?old:'all';
}
function mergePoints(incoming){
 if(!incoming.length)return;
 if(!state.points.length||incoming[0].t>state.points.at(-1).t){state.points.push(...incoming);return}
 const merged=new Map(state.points.map(p=>[`${p.t}|${p.series_id||'legacy'}`,p]));
 for(const p of incoming)merged.set(`${p.t}|${p.series_id||'legacy'}`,p);
 state.points=[...merged.values()].sort((a,b)=>a.t-b.t);
}
async function loadHistory(){
 const job=archive;if(!job.session||job.loading)return;
 job.loading=true;job.error=null;draw();
 try{
  while(job===archive){
   const response=await fetch(`/api/history?session=${encodeURIComponent(job.session)}&cursor=${job.cursor}`);
   const data=await response.json();
   if(!response.ok)throw Error(data.error||'No se ha podido recuperar el historial');
   if(job!==archive)return;
   if(data.session!==job.session||!Number.isSafeInteger(data.next_cursor)||data.next_cursor<job.cursor)throw Error('Página de historial no válida');
   mergePoints(data.points);job.cursor=data.next_cursor;draw();
   if(data.eof){job.complete=true;break}
  }
 }catch(e){if(job===archive)job.error=e.message}
 finally{if(job===archive){job.loading=false;draw()}}
}
function shownInterval(){
 const elapsed=Math.max(0,state.metrics.elapsed||0,state.points.at(-1)?.t||0);
 const latest=Math.max(0,elapsed-viewSpan);
 const begin=range==='all'?0:range==='recent'?latest:Math.max(0,Math.min(viewStart,latest));
 return {begin,end:range==='all'?Math.max(60,elapsed):begin+viewSpan,elapsed,latest};
}
function navigateTo(start){range='history';viewStart=Math.max(0,Math.min(start,shownInterval().latest));inspected=null;draw()}
function renderTimeline(){
 const v=shownInterval(),moving=range==='recent';
 for(const r of ['all','recent']){$('range-'+r).classList.toggle('selected',range===r);$('range-'+r).setAttribute('aria-pressed',String(range===r))}
 $('timeline').max=String(v.latest);$('timeline').value=String(range==='all'?0:v.begin);
 $('timeline').disabled=v.latest<=0;
 $('timeline').setAttribute('aria-valuetext',`Desde ${clock(v.begin)}`);
 $('view-span').disabled=range==='all';
 $('history-first').disabled=v.begin<=0&&range!=='all';
 $('history-prev').disabled=v.begin<=0;
 $('history-next').disabled=v.begin>=v.latest;
 $('view-label').textContent=`${moving?'Siguiendo el directo':range==='all'?'Captura completa':'Revisando historial'} · ${clock(v.begin)}–${clock(Math.min(v.end,v.elapsed))}`;
 $('history-note').hidden=!state.session;
 $('history-note').textContent=archive.error?`Historial: ${archive.error}. Los datos siguen guardados en Linux.`:archive.loading?'Recuperando el historial completo de Linux…':`Historial ${archive.complete?'completo':'recibido'} · ${format(state.points.length,0)} puntos · conservado en disco`;
 $('history-retry').hidden=!archive.error;
}
function render(){
 const m=state.metrics||{}, a=active();document.body.classList.toggle('busy',a);
 renderClients();
 renderSeries();
 renderProtocol();
 renderCandidates();
 $('connection').textContent=connected?'Streaming conectado':'Reconectando…';$('connection').className='pill '+(connected?'connected':'disconnected');
 $('status').textContent=({idle:'Preparado',starting:'Preparando captura',capturing:state.replay?'Reproduciendo PCAP':'Capturando en directo',stopping:'Guardando…',finished:state.complete?'Captura completada':'Captura detenida',error:'Revisar captura'})[state.state]||state.state;
 if(state.discovery?.scanning)$('status').textContent='Explorando todos los canales';
 $('status-dot').className='status-dot'+(state.state==='capturing'?' active':'');
 $('replay').hidden=!state.replay;if(state.replay)$('replay').textContent=`REPRODUCCIÓN DE PRUEBA · PCAP grabado a ${state.speed}×. No es una captura de radio en directo.`;
 $('label').disabled=a||pending;$('unlimited').disabled=a||pending;
 $('duration').disabled=a||pending||$('unlimited').checked;
 $('start').disabled=a||pending||!connected||(!state.replay&&!state.authorization?.authorized)||state.discovery?.scanning||state.switching;$('stop').disabled=(!['starting','capturing'].includes(state.state)&&!state.discovery?.scanning)||pending||!connected;
 $('stop').textContent=state.discovery?.scanning?'■ Detener barrido':'■ Detener y guardar';
 for(const id of ['movement','still'])$(id).disabled=state.state!=='capturing'||pending||!connected;
 $('variance').textContent=format(m.variance,5);$('count').textContent=format(m.bfi||0,0);$('rate').textContent=`${format(m.rate||0)} BFI/s · últimos 10 s`;
 $('rssi').textContent=m.rssi==null?'—':`${format(m.rssi,0)} dBm`;$('ap-rssi').textContent=`AP: ${format(m.ap_rssi,0)} dBm`;
 $('elapsed').textContent=clock(m.elapsed);$('remaining').textContent=state.duration==null?'Sin límite · parada manual':`de ${clock(state.duration)}`;
 $('interface').textContent=`ALFA · ${state.iface||'monitor'}`;
 const lastFeedback=state.points.at(-1)?.feedback;
 const codebook=state.points.at(-1)?.config?.[2];
 $('angle-resolution').textContent=lastFeedback?`${feedbackLabel(state.points.at(-1))} · ψ ${lastFeedback.bits_psi} bits · φ ${lastFeedback.bits_phi} bits · ${lastFeedback.subcarriers} subportadoras.`:[0,1].includes(codebook)?`Último informe: ψ ${codebook?4:2} bits (${codebook?16:4} niveles) · φ ${codebook?6:4} bits (${codebook?64:16} niveles).`:'La resolución depende del codebook anunciado en cada informe VHT SU.';
 $('capture-channel').textContent=`Canal ${state.radio?.channel??'—'} · ${state.radio?.width??'—'} MHz`;
 const rv=m.radio_verification;
 $('radio-status').textContent=state.discovery?.scanning?`Barrido: escuchando canal ${state.discovery.channel??'—'}`:state.replay?'Reproducción guardada: no modifica la ALFA':state.state==='starting'?(state.radio_detection||`Sintonizando y verificando canal ${state.radio?.channel??'—'} · ${state.radio?.width??'—'} MHz…`):state.state==='capturing'?(rv?.ok?`ALFA verificada: canal ${rv.actual.channel} · ${rv.actual.frequency} MHz · ancho ${rv.actual.width} MHz · centro ${rv.actual.center} MHz. Comprobación cada 2 s.`:'Canal de la ALFA todavía sin confirmar'):state.authorization?.declaration?.radio_mode==='auto'?'Canal automático · se detectará al iniciar desde las balizas de tu AP':`Canal del enlace: ${state.radio?.channel??'—'} · ${state.radio?.width??'—'} MHz. Se sintoniza y verifica en cada inicio.`;
 let quality=({valid:'Recibiendo BFI · ventana válida',warming_up:'Todos los puntos visibles · ventana inicial incompleta',insufficient_bfi:'Todos los puntos visibles · recepción escasa; consulta muestras y huecos',no_bfi:'Sin BFI reciente · se conserva el último valor y todo el histórico'})[m.quality]||'Esperando una captura.';
 const allReports=Object.values(m.protocol?.bfi||{});
 const reports=allReports.length?{total:allReports.reduce((a,b)=>a+(b.total||0),0),compatible:allReports.reduce((a,b)=>a+(b.compatible||0),0),configs:Object.assign({},...allReports.map(b=>b.configs||{}))}:null;
 if(a&&!m.bfi&&reports?.total>0&&reports?.compatible===0){
  const configs=Object.keys(reports.configs||{}).join('; ');
  quality=`BFI recibidos: ${reports.total} · ${configs||'formato observado'} · sin decodificación válida para la gráfica`;
 }
 if(!a)quality=state.state==='idle'?'Esperando una captura.':`Registro finalizado · ${format(m.bfi||0,0)} BFI`;
 if(!connected)quality='Conexión interrumpida · esperando reconexión';
 if(m.decode_errors)quality+=` · ${m.decode_errors} informes descartados`;
 $('quality').textContent=quality;$('age').textContent='Último BFI: '+(m.last_age==null?'—':`hace ${format(m.last_age,1)} s`);
 $('chart-empty').hidden=state.points.some(p=>p.variance!==null);
 $('downloads').hidden=a||!state.output||state.state==='error';
 $('save-title').textContent=a?'Guardando durante la captura':state.output?'Registro de esta captura':'Todo queda guardado';
 $('save-path').textContent=state.output||'PCAP original, serie de varianza, marcas y ficha de captura.';
 if(state.error)error(state.error);
 draw();
}
function renderClients(){
 const d=state.discovery||{}, client=state.client, peers=[...(d.clients||[])], select=$('client-select');
 const declaration=state.authorization?.declaration;
 if(declaration)for(const c of declaration.clients){
  if(!peers.some(p=>p.mac===c.mac&&p.ap===declaration.ap))peers.push({mac:c.mac,ap:declaration.ap,id:c.id,label:c.id+' · Declarado',frequency:declaration.frequency,channel:declaration.channel,width:declaration.width,center:declaration.center,key:`${c.mac}|${declaration.ap}|${declaration.frequency}`});
 }

 const selected=client?.key||client?.mac;
 const visible=peers.filter(p=>matchesClientFilters(p));
 const current=peers.find(p=>(p.key||p.mac)===selected)||client;
 const outside=current&&!matchesClientFilters(current);
 const key=JSON.stringify([peers,d.updated,selected,clientBandFilter,clientBfiFilter,state.metrics?.bfi,state.metrics?.protocol?.bfi,state.metrics?.protocol?.he_feedback]);
 if(key!==clientsKey){
  clientsKey=key;select.replaceChildren();
  const options=[...visible];
  if(current&&!options.some(p=>(p.key||p.mac)===selected)){
   const group=document.createElement('optgroup');group.label=outside?'Selección actual · fuera del filtro':'Selección actual';
   group.append(new Option(`${current.label||current.mac} · ${bandLabel(current)} · canal ${current.channel??'—'}`,selected));select.append(group);
  }
  if(!options.length){const empty=new Option('Ningún enlace coincide con estos filtros','');empty.disabled=true;select.append(empty)}
  for(const band of ['2.4','5','unknown']){
   const items=options.filter(p=>clientBand(p)===band);if(!items.length)continue;
   const group=document.createElement('optgroup');group.label=`${bandLabel(items[0])} · ${items.length} enlaces`;
   for(const p of items){
    const label=p.id?p.label:`Cliente · ${p.mac}`;
    const suffix=`${p.seen_in_latest_scan?'Último barrido':'Histórico'} · ${bfiEvidence(p).label}`;
    group.append(new Option(`${label} · ${bandLabel(p)} · canal ${p.channel??'—'} · AP ${p.ap||'—'} — ${suffix}`,p.key||p.mac));
   }
   select.append(group);
  }
 }
 if(client)select.value=selected;
 const counts={'2.4':0,'5':0,unknown:0};for(const p of peers)counts[clientBand(p)]++;
 $('client-filter-summary').textContent=`${visible.length} de ${peers.length} enlaces coinciden · 2,4 GHz: ${counts['2.4']} · 5 GHz: ${counts['5']}${counts.unknown?' · sin banda: '+counts.unknown:''}${outside?' · La selección actual se conserva fuera del filtro.':''}`;
 const busy=pending||!connected||state.switching||d.scanning||['starting','stopping'].includes(state.state);
 select.disabled=busy||!client&&!peers.length;
 $('clients-refresh').disabled=busy||state.replay;
 $('clients-refresh').textContent=d.scanning?'Explorando canales…':'↻ Actualizar · enlaces autorizados';
 $('clients-status').textContent=d.scanning?`Canal ${d.channel??'—'} · ${d.channel_index||0}/${d.channel_total||'—'} · ${d.current_count||0} vistos ahora · ${peers.length} conservados`:d.error?`Barrido: ${d.error} · ${peers.length} enlaces conservados`:d.updated?`${d.current_count||0} vistos en el último barrido · ${peers.length} enlaces en el histórico${d.cancelled?' · barrido parcial':''}${d.skipped?.length?` · ${d.skipped.length} canales rechazados`:''}`:`${peers.length} enlaces conservados · barrido de unos 2 minutos.`;
 const peer=peers.find(p=>(p.key||p.mac)===selected);
 $('client-detail').textContent=peer?`AP ${peer.ap} · canal ${peer.channel}. Última observación: ${discoveryDate(peer.last_seen)}. RSSI: ${format(peer.rssi,0)} dBm. ${peer.compatible_bfi?'BFI decodificable observado.':'Sin BFI decodificable en su última observación.'}${peer.seen_in_latest_scan?'':' Registro histórico; su disponibilidad actual no está confirmada.'}`:'Solo AP y clientes autorizados. Actualizar conserva el histórico.';
 renderDiscoveryHistory(d);
 const name=client?.id||'cliente seleccionado';
 $('capture-client').textContent=client?.label||'Cliente por seleccionar';
 $('client-eyebrow').textContent=`CAPTURA PASIVA · ${name.toUpperCase()}`;
 $('rssi-label').textContent=`RSSI DE ${name.toUpperCase()}`;
 if(client&&previousClient!==selected){
  if(client.mac!==state.threshold_client||client.ap!==state.threshold_ap)$('threshold').checked=false;
  previousClient=selected;
 }
}
function discoveryDate(value){return Number.isFinite(value)?new Date(value*1000).toLocaleString('es-ES'):'fecha no conservada'}
const protocolNames={null_data:'Null/QoS Null',ndpa:'NDPA',control:'Control',association_request:'Petición de asociación',association_response:'Respuesta de asociación',reassociation_request:'Petición de reasociación',reassociation_response:'Respuesta de reasociación',authentication:'Autenticación 802.11',deauthentication:'Desautenticación',disassociation:'Desasociación',action:'Action',action_no_ack:'Action sin ACK',management_other:'Otra gestión',data:'Datos',EAPOL:'EAPOL'};
function suiteNames(items,akm=false){
 const labels=akm?{1:'802.1X',2:'PSK',3:'FT/802.1X',4:'FT/PSK',5:'802.1X SHA-256',6:'PSK SHA-256',8:'SAE',9:'FT/SAE',12:'802.1X Suite-B-192',18:'OWE'}:{0:'Usar cifrado de grupo',1:'WEP-40',2:'TKIP',4:'CCMP-128',5:'WEP-104',6:'BIP-CMAC-128',8:'GCMP-128',9:'GCMP-256',10:'CCMP-256'};
 return items?.length?items.map(v=>{const n=Number(v);return (n>>>8)===0x000fac&&labels[n&255]?`${labels[n&255]} (${v})`:v}).join(', '):'No observado';
}
// Ficha basada en una sola fuente: no suma barridos y capturas ni rellena ceros desconocidos.
function clientEvidence(s,choice,source='auto'){
 const peers=[...(s.discovery?.clients||[])],current=s.client;
 if(current&&!peers.some(p=>p.key===current.key))peers.unshift(current);
 const chosen=choice&&peers.some(p=>p.key===choice)?choice:current?.key||peers[0]?.key;
 const peer=peers.find(p=>p.key===chosen)||{};
 const isCurrent=chosen===current?.key,live=isCurrent?s.metrics?.protocol:null;
 const options=[];
 if(isCurrent&&s.session)options.push({id:'capture',label:active()?'Captura actual':'Última captura de la app',p:live,session:s.session});
 if(peer.protocol_followup)options.push({id:'followup',label:'Captura guardada del enlace',p:peer.protocol_followup,session:peer.protocol_session});
 if(peer.protocol||peer.last_seen)options.push({id:'scan',label:'Último barrido del enlace',p:peer.protocol||null,session:peer.last_scan});
 for(const record of [...(peer.protocol_records||[])].reverse()){if(record.session===peer.protocol_session)continue;options.push({id:'session:'+record.session,label:'Captura · '+discoveryDate(record.protocol?.first_seen),p:record.protocol,session:record.session})}
 const selected=options.find(o=>o.id===source)||options[0]||{id:'scan',label:'Registro histórico',p:null};
 return {peers,chosen,peer,isCurrent,options,...selected};
}
// Verified with tshark -G manuf (IEEE-derived Wireshark registry), 2026-10-04.
// Registration identifies the address vendor, not a model or network owner.
const verifiedVendorPrefixes={'a4:97:33':'Askey Computer Corp','d4:7b:b0':'Askey Computer Corp','cc:d4:a1':'MitraStar Technology Corp.'};
function registeredVendor(mac){
 if(!mac)return 'No disponible';
 if(parseInt(mac.slice(0,2),16)&2)return 'Dirección local: fabricante no deducible de la MAC';
 return verifiedVendorPrefixes[mac.toLowerCase().slice(0,8)]||'No identificado en el catálogo local';
}
function apLinkEvidence(peer,p){
 const n=p?.bfi?.client_to_ap?.total;
 const response=p?.association_response;
 if(response?.status===0)return 'Respuesta de asociación aceptada observada; no garantiza que siga conectado ahora';
 if(n>0)return `${n} BFI del cliente dirigidos a este AP. Intercambio de asociación no confirmado en esta fuente`;
 return peer.ap?'BSSID atribuido por las tramas del enlace; asociación no confirmada en esta fuente':'Sin AP identificado';
}
let protocolSource='auto',protocolExport=null;
function renderProtocol(){
 const e=clientEvidence(state,protocolChoice,protocolSource),{peer,p}=e;
 const signature=JSON.stringify([e,state.state,Math.floor(state.metrics?.elapsed||0)]);
 if(signature===protocolRenderKey)return;protocolRenderKey=signature;
 const link=$('protocol-link');link.replaceChildren(...e.peers.map(p=>new Option(`${p.id?p.label:p.mac} · canal ${p.channel??'—'} · AP ${p.ap}`,p.key)));if(e.chosen)link.value=e.chosen;
 const source=$('protocol-snapshot');source.replaceChildren(...e.options.map(o=>new Option(o.label,o.id)));source.value=e.id;
 const isLive=e.id==='capture'&&active(),ts=p?.last_seen;
 $('protocol-source').textContent=`${e.label}${e.session?' · '+e.session:''}. ${ts?'Última trama del enlace: '+discoveryDate(ts):'Sin tramas del enlace en esta fuente.'}`;
 const observed=p?.total??(e.id==='scan'?(peer.tx_frames??0)+(peer.rx_frames??0):0);
 const fallbackRssi=e.id==='scan'?peer.rssi:null;
 const sig=p?.signals?.client,rssi=sig?.last??p?.client_rssi??fallbackRssi;
 const bfi=p?.bfi?.client_to_ap,reverse=p?.bfi?.ap_to_client;
 const compatible=p?.bfi?Object.values(p.bfi).reduce((n,b)=>n+(b.compatible||0),0):(e.id==='capture'?state.metrics?.bfi:e.id==='scan'?peer.compatible_bfi:null);
 const total=p?.bfi?Object.values(p.bfi).reduce((n,b)=>n+(b.total||0),0):(e.id==='scan'?peer.bfi_reports??peer.vht_bfi:null);
 const hs=p?.pairwise_messages||{},missing=['M1','M2','M3','M4'].filter(k=>!hs[k]);
 const headline=!observed?'Sin tráfico del cliente observado en esta fuente':compatible>0?'BFI compatibles disponibles':total>0?(isLive?'BFI recibidos sin decodificación válida':'BFI descartados al registrar esta fuente'):'Tráfico observado; sin BFI compatible registrado';
 $('protocol-summary').textContent=headline;
 $('protocol-diagnostic').textContent=!observed?(e.isCurrent&&isLive&&peer.channel_source!=='AP beacon / probe response'?'El canal procede de recepción o de un registro antiguo, no está confirmado por una baliza del AP. Actualiza el barrido antes de concluir que el cliente está ausente.':'La captura no ha recibido tramas de este cliente. Comprueba si el enlace sigue activo; la ausencia de tramas no confirma desconexión.'):(compatible>0?'Todos los informes decodificados se muestran, incluso con pocas muestras; la calidad se indica en cada punto.':total>0?'Revisa debajo la configuración y el motivo de descarte. Capturar BFI y poder calcular esta varianza son cosas distintas.':'El cliente puede estar conectado sin entregar BFI, responder con otro formato o no ser recibido por la sonda.');
 if(!isLive&&total>0&&compatible===0)$('protocol-diagnostic').textContent+=' Es un resultado histórico: puede proceder de una versión anterior del decodificador. No demuestra que el formato siga sin admitirse; compruébalo en una nueva captura.';
 const cards=$('protocol-cards');cards.replaceChildren();
 for(const [label,value,detail] of [['Señal del cliente',rssi==null?'Sin dato':`${format(rssi,0)} dBm`,'Medida en la sonda'],['Tramas del enlace',format(observed,0),'Fuente seleccionada'],['BFI compatibles',compatible==null?'Sin dato':format(compatible,0),total==null?'Total no conservado':`${format(total,0)} BFI en ambos sentidos`],['Handshake EAPOL',Object.keys(hs).length?`${4-missing.length}/4 tipos`:'No observado','No valida claves ni un intercambio completo']]){
  const c=document.createElement('article'),a=document.createElement('span'),b=document.createElement('strong'),d=document.createElement('small');a.textContent=label;b.textContent=value;d.textContent=detail;c.append(a,b,d);cards.append(c);
 }
 const section=id=>{const el=$(id);el.replaceChildren();return (label,value)=>{const dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=label;dd.textContent=value;el.append(dt,dd)}};
 const tri=v=>v==null?'No observado':v?'Sí':'No';
 const count=v=>v==null?'No conservado':format(v,0);
 const groups=o=>Object.entries(o||{}).map(([k,v])=>`${k}: ${v}`).join(' · ')||'No observado';
 let add=section('protocol-overview');
 add('Cliente / MAC',`${peer.id?peer.label:'Equipo sin identificar'} · ${peer.mac||'—'}`);
 add('Tipo de dirección',peer.mac?(parseInt(peer.mac.slice(0,2),16)&2?'Administrada localmente; puede ser aleatoria. No permite deducir el fabricante.':'Administrada universalmente. El modelo no se deduce de la MAC.'):'No disponible');
 add('AP / BSSID',peer.ap||'—');
 add('Fabricante registrado del AP',registeredVendor(peer.ap));
 add('Evidencia del vínculo cliente–AP',apLinkEvidence(peer,p));
 add('Fabricante registrado del cliente',registeredVendor(peer.mac));
 add('Origen de identificación', 'Prefijos de fabricante de Wireshark / IEEE. No identifican el modelo ni el propietario de la red.');
 const adv=p?.ap_advertised;
 add('Red anunciada (SSID)',adv?.ssid??(adv?'Oculta o no conservada':'Baliza del AP no observada'));
 add('Sintonía del enlace',`${peer.channel??'—'} · ${peer.frequency??'—'} MHz · ancho ${peer.width??'—'} MHz`);
 add('Evidencia del canal',peer.channel_source==='AP beacon / probe response'?'Anunciado por el AP en baliza/respuesta de sondeo':'Canal de recepción o registro anterior: sin confirmación del AP conservada');
 add('Registro seleccionado',`${e.label} · ${discoveryDate(p?.first_seen??(e.id==='scan'?peer.first_seen:null))} → ${discoveryDate(ts??(e.id==='scan'?peer.last_seen:null))}`);
 add('Balizas del AP',count(p?.ap_context?.beacons));
 add=section('protocol-signal');
 const signalText=o=>o?`último ${format(o.last,1)} · media ${format(o.mean,1)} · mín ${format(o.min,1)} · máx ${format(o.max,1)} dBm · ${o.n} muestras`:'No conservado';
 add('RSSI del cliente',sig?signalText(sig):rssi==null?'No observado':`${format(rssi,1)} dBm (último valor)`);
 add('RSSI del AP (balizas)',signalText(p?.ap_context?.signals?.ap));
 add('RSSI del AP (enlace)',signalText(p?.signals?.ap));
 add('Última señal del cliente',discoveryDate(sig?.ts??p?.client_rssi_ts));
 add('Formatos PPDU recibidos',groups(p?.phy));
 add('Bit de ahorro de energía del cliente',p?.power_save?`${tri(p.power_save.value)} · ${discoveryDate(p.power_save.ts)}. No confirma suspensión del sistema.`:'No observado');
 add=section('protocol-traffic');
 for(const [key,label] of [['tx','Cliente → AP'],['rx','AP → cliente']]){
  const d=p?.directions?.[key];
  add(label,`${count(d?.frames??p?.[key+'_frames']??(e.id==='scan'?peer[key+'_frames']:null))} tramas · ${count(d?.bytes??p?.[key+'_bytes'])} bytes capturados`);
  add(`${label} · tipo`,d?`${d.data_frames} datos · ${d.null_frames} Null/QoS Null (sin carga útil) · ${d.protected} protegidas · ${d.retries} reintentos`:'Desglose no conservado');
 }
 add('Total con bit Protected',p?`${p.protected} / ${p.total} (${format(p.total?100*p.protected/p.total:0,1)} %)`:'No observado');
 add('Reintentos marcados',p?`${p.retries} / ${p.total} (${format(p.total?100*p.retries/p.total:0,1)} %)`:'No observado');
 add=section('protocol-security');
 const sec=adv?.security,caps=p?.client_capabilities,cap=adv?.capabilities;
 add('AKM anunciado por el AP',suiteNames(sec?.akm,true));
 add('Cifrado anunciado: par / grupo',`${suiteNames(sec?.pairwise)} / ${suiteNames(sec?.group)}`);
 add('PMF anunciado por el AP',`Capaz: ${tri(sec?.pmf_capable)} · requerido: ${tri(sec?.pmf_required)}`);
 add('AKM solicitado por el cliente',suiteNames(p?.association_security?.akm,true));
 add('Cifrado solicitado por el cliente',suiteNames(p?.association_security?.pairwise));
 const auth={0:'Open System (no implica red abierta)',1:'Shared Key',2:'Fast BSS Transition',3:'SAE'};
 add('Autenticación 802.11',p?.auth_algorithms?.length?p.auth_algorithms.map(n=>auth[n]||`Algoritmo ${n}`).join(', '):'No observada');
 const response=p?.association_response;
 add('Respuesta de asociación',response?`${response.status===0?'Aceptada':'Estado '+response.status} · AID ${response.aid??'—'} · ${discoveryDate(response.ts)}`:'No observada; no se afirma que la conexión se haya establecido durante esta captura');
 add('Capacidades anunciadas del AP',cap?.modes?.join(', ')||'No observadas');
 add('Capacidades del cliente (asociación)',caps?.modes?.join(', ')||'Petición de asociación no capturada');
 add('VHT beamformee cliente / AP',`Cliente SU: ${tri(caps?.su_beamformee)}, MU: ${tri(caps?.mu_beamformee)} · AP SU: ${tri(cap?.su_beamformee)}, MU: ${tri(cap?.mu_beamformee)}`);
 add('HE beamformee cliente / AP',`Cliente SU: ${tri(caps?.he_su_beamformee)} · AP SU: ${tri(cap?.he_su_beamformee)}`);
 add=section('protocol-bfi');
 add('BFI cliente → AP',`${count(bfi?.total)} recibidos · ${count(bfi?.compatible)} compatibles`);
 add('Informes HE (Action 0) cliente → AP / AP → cliente',p?.he_feedback?`${count(p.he_feedback.client_to_ap??0)} / ${count(p.he_feedback.ap_to_client??0)}`:'No observados o no conservados');
 add('BFI AP → cliente',`${count(reverse?.total??(e.id==='scan'?peer.reverse_vht_bfi:null))} recibidos · ${count(reverse?.compatible)} compatibles`);
 add('Configuración cliente → AP',groups(bfi?.configs));
 add('Configuración AP → cliente',groups(reverse?.configs));
 add('Motivos de descarte',groups(bfi?.rejected));
 add('NDPA unicast AP → cliente',groups(p?.ndpa?.ap_to_client));
 add('NDPA unicast cliente → AP',groups(p?.ndpa?.client_to_ap));
 add('NDPA del AP, todos sus destinos',groups(p?.ap_context?.ndpa_all));
 const hh=$('protocol-handshake');hh.replaceChildren();
 for(const k of ['M1','M2','M3','M4']){const el=document.createElement('span');el.className=hs[k]?'seen':'';el.textContent=`${k} · ${hs[k]||0} observado(s)`;hh.append(el)}
 $('protocol-handshake-note').textContent=missing.length===4?'No se ha capturado el handshake. Si el cliente se conectó antes de escuchar, es normal que no aparezca.':missing.length?`No observados: ${missing.join(', ')}. Los contadores incluyen reintentos.`:'Se han observado los cuatro tipos de mensaje. No se ha comprobado que pertenezcan a una misma sesión ni se han validado claves.';
 $('protocol-counts').textContent=`${groups(p?.frames)}. EAPOL por tipo: ${groups(p?.eapol)}. Actualizaciones de clave de grupo: ${p?.group_key??0}.`;
 const events=$('protocol-events');events.replaceChildren();
 for(const v of [...(p?.events||[])].reverse()){
  const tr=document.createElement('tr');for(const val of [discoveryDate(v.ts),protocolNames[v.event]||v.event,v.direction,[v.message?`M${v.message}`:'',v.status!=null?`estado ${v.status}${v.status===0?' (aceptado)':''}`:'',v.reason!=null?`motivo ${v.reason}`:''].filter(Boolean).join(' · ')||'—']){const td=document.createElement('td');td.textContent=val;tr.append(td)}events.append(tr);
 }
 if(!p?.events?.length){const tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=4;td.textContent='Sin eventos de conexión capturados en esta fuente.';tr.append(td);events.append(tr)}
 protocolExport={client:peer.mac,ap:peer.ap,ap_registered_vendor:registeredVendor(peer.ap),ap_link_evidence:apLinkEvidence(peer,p),vendor_source:'https://www.wireshark.org/download/automated/data/manuf',channel:peer.channel,source:e.label,session:e.session,observations:p};
}

function renderCandidates(){
 const box=$('client-priorities');box.replaceChildren();const candidates=[];
 for(const peer of state.discovery?.clients||[]){
  if(!matchesClientFilters(peer))continue;
  const records=[{session:null,protocol:peer.protocol},...(peer.protocol_records||[])];
  if(peer.protocol_followup)records.push({session:peer.protocol_session,protocol:peer.protocol_followup});
  let best={score:0,reason:'',session:null};
  if(peer.vht_bfi>0)best={score:2,reason:`${peer.vht_bfi} BFI VHT en el barrido; ${peer.compatible_bfi||0} compatibles`,session:null};
  for(const r of records){const p=r.protocol;if(!p)continue;
   const messages=Object.keys(p.pairwise_messages||{}),b=p.bfi?.client_to_ap,he=p.he_feedback;
   let score=0,reason='';
   if(messages.length){score=5;reason=`Eventos EAPOL: ${messages.join(', ')}`}
   else if(b?.compatible){score=4;reason=`${b.compatible} BFI compatibles en una captura`}
   else if(he&&Object.values(he).some(Boolean)){score=3;reason=`Feedback HE observado; consulta compatibilidad de esta captura`}
   else if(b?.total){score=2;reason=`${b.total} BFI con formato no compatible`}
   if(score>best.score)best={score,reason,session:r.session};
  }
  if(best.score)candidates.push({peer,...best});
 }
 candidates.sort((a,b)=>b.score-a.score);
 for(const c of candidates.slice(0,8)){const button=document.createElement('button');button.type='button';button.textContent=`${c.peer.id||c.peer.mac} · ${c.reason}`;button.addEventListener('click',()=>{protocolChoice=c.peer.key;protocolSource=c.session===c.peer.protocol_session?'followup':c.session?'session:'+c.session:'scan';renderProtocol();$('protocol-title').scrollIntoView({behavior:'smooth'})});box.append(button)}
 if(!candidates.length)box.textContent='No hay enlaces con evidencia útil que coincidan con los filtros actuales.';
}
function renderDiscoveryHistory(d){
 const filter=$('discovery-scan'),choice=filter.value||'all',peers=d.clients||[],scans=d.scans||[];
 const signature=JSON.stringify([peers,scans,d.history_error,choice,clientBandFilter,clientBfiFilter,$('discovery-search').value]);
 if(signature===discoveryHistoryKey)return;
 discoveryHistoryKey=signature;
 const options=[new Option(`Histórico acumulado (${peers.length})`,'all')];
 const names={scanning:'en curso',complete:'completo',cancelled:'parcial',error:'con error',recovered:'recuperado'};
 for(const scan of [...scans].reverse())options.push(new Option(`${discoveryDate(scan.started)} · ${names[scan.status]||scan.status} · ${scan.clients.length} enlaces`,scan.id));
 filter.replaceChildren(...options);filter.value=scans.some(s=>s.id===choice)?choice:'all';
 const selected=scans.find(s=>s.id===filter.value),query=$('discovery-search').value.toLowerCase(),rows=(selected?selected.clients:peers).filter(p=>matchesClientFilters(p,!selected,!selected)).filter(p=>[p.mac,p.ap,p.label,p.protocol?.ap_advertised?.ssid,p.protocol_followup?.ap_advertised?.ssid].some(v=>v?.toLowerCase().includes(query)));
 $('discovery-history-status').textContent=d.history_error||`${rows.length} enlaces mostrados con los filtros · ${peers.length} conservados · ${new Set(peers.map(p=>p.channel)).size} canales · ${scans.length} barridos guardados en Linux. Actualizar y reiniciar no eliminan este histórico.`;
 $('discovery-history-status').classList.toggle('validation',Boolean(d.history_error));
 const body=$('discovery-history-rows');body.replaceChildren();
 if(!rows.length){const tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=10;td.textContent='Ningún enlace coincide con esta banda, filtro BFI, búsqueda y barrido.';tr.append(td);body.append(tr)}
 for(const p of rows){
  const tr=document.createElement('tr');
  let status=selected?'Observado en este barrido':p.seen_in_latest_scan?'Último barrido':'Histórico';
  const followup=!selected&&p.protocol_followup&&(p.protocol_followup.last_seen||0)>(p.protocol?.last_seen||0),detail=followup?p.protocol_followup:p.protocol,ssid=detail?.ap_advertised?.ssid||'—',rssi=detail?.client_rssi??(followup?null:p.rssi);if(followup)status='Captura guardada';
  for(const value of [p.id?p.label:p.mac,bandLabel(p),ssid,`${p.channel} · ${p.width} MHz`,p.ap,rssi==null?'—':`${format(rssi,0)} dBm`,discoveryDate(detail?.last_seen??p.last_seen),detail?.bfi?.client_to_ap?.compatible??(followup?'—':p.compatible_bfi??'—'),status]){
   const td=document.createElement('td');td.textContent=String(value);tr.append(td);
  }
  const cell=document.createElement('td'),button=document.createElement('button');button.type='button';button.textContent='Ver ficha';button.addEventListener('click',()=>{protocolChoice=p.key;protocolSource='auto';renderProtocol();$('protocol-title').scrollIntoView({behavior:'smooth'})});cell.append(button);tr.append(cell);
  body.append(tr);
 }
}
function renderMarkers(){const list=$('marker-list');list.replaceChildren();if(!state.markers.length){const li=document.createElement('li');li.textContent='Sin marcas todavía.';li.className='muted';list.append(li)}else for(const m of state.markers.slice(-6).reverse()){const li=document.createElement('li');li.textContent=`${clock(m.t)} · ${m.kind==='movement'?'Comienzo de movimiento':'Quietud'}`;list.append(li)}}
async function command(path,payload){pending=true;render();error(null);try{const res=await fetch('/api/'+path,{method:'POST',headers:{'Content-Type':'application/json','X-Live-Token':state.csrf||''},body:JSON.stringify(payload||{})});const data=await res.json();if(!res.ok)throw Error(data.error||'No se ha podido completar');}catch(e){error(e.message)}finally{pending=false;render()}}
$('capture-form').addEventListener('submit',e=>{e.preventDefault();command('start',{label:$('label').value.trim(),duration:$('unlimited').checked?null:Number($('duration').value)*60,client:$('client-select').value})});
$('client-band-filter').value=clientBandFilter;$('client-bfi-filter').value=clientBfiFilter;
$('client-band-filter').addEventListener('change',applyClientFilters);$('client-bfi-filter').addEventListener('change',applyClientFilters);
$('clients-refresh').addEventListener('click',()=>command('clients/refresh'));
$('discovery-scan').addEventListener('change',()=>renderDiscoveryHistory(state.discovery||{}));
$('protocol-snapshot').addEventListener('change',e=>{protocolSource=e.target.value;renderProtocol()});
$('protocol-export').addEventListener('click',()=>{if(!protocolExport)return;const url=URL.createObjectURL(new Blob([JSON.stringify(protocolExport,null,2)],{type:'application/json'})),a=document.createElement('a');a.href=url;a.download='ficha-enlace.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)});
$('discovery-search').addEventListener('input',()=>{discoveryHistoryKey='';renderDiscoveryHistory(state.discovery||{})});
$('protocol-link').addEventListener('change',e=>{protocolChoice=e.target.value;protocolSource='auto';renderProtocol()});
$('client-select').addEventListener('change',e=>{const client=e.target.value;if(client&&client!==(state.client?.key||state.client?.mac))command('client',{client})});
$('unlimited').addEventListener('change',()=>{$('duration').disabled=$('unlimited').checked;});
$('stop').addEventListener('click',()=>command('stop'));for(const k of ['movement','still'])$(k).addEventListener('click',()=>command('mark',{kind:k}));
for(const r of ['all','recent'])$('range-'+r).addEventListener('click',()=>{range=r;inspected=null;draw()});$('threshold').addEventListener('change',draw);
$('timeline').addEventListener('input',e=>navigateTo(Number(e.target.value)));
$('history-first').addEventListener('click',()=>navigateTo(0));
$('history-prev').addEventListener('click',()=>navigateTo(shownInterval().begin-viewSpan/2));
$('history-next').addEventListener('click',()=>navigateTo(shownInterval().begin+viewSpan/2));
$('history-retry').addEventListener('click',loadHistory);
$('view-span').addEventListener('change',e=>{viewSpan=Number(e.target.value);draw()});
$('sma').addEventListener('change',draw);$('phi').addEventListener('change',draw);
function updateSmaSize(){
 const input=$('sma-window'),size=Number(input.value);
 if(!Number.isInteger(size)||size<1||size>120){input.setCustomValidity('Introduce un número entero entre 1 y 120.');input.setAttribute('aria-invalid','true');$('sma-validation').hidden=false;return}
 input.setCustomValidity('');input.removeAttribute('aria-invalid');$('sma-validation').hidden=true;smaSize=size;
 try{localStorage.setItem('silueta-sma-points',String(size))}catch{}
 $('sma-label').textContent=`Media móvil (${size})`;$('sma-size-description').textContent=size;
 draw();
}
$('sma-window').addEventListener('input',updateSmaSize);
$('sma-window').addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();$('sma-window').reportValidity()}});
const events=new EventSource('/events');events.onopen=()=>{connected=true;render()};events.onerror=()=>{connected=false;render()};
for(const name of ['reset','done'])events.addEventListener(name,e=>{
 const next=JSON.parse(e.data),previous=state.points,same=state.session===next.session;
 state={...next,points:same?previous:[]};mergePoints(next.points);
 if(!same){archive={session:state.session,cursor:0,loading:false,complete:false,error:null};range='recent';viewStart=0;inspected=null}
 $('unlimited').checked=active()?state.duration==null:true;
 if(state.session){$('label').value=state.label||state.session;if(state.duration!=null)$('duration').value=state.duration/60}
 error(state.error);renderMarkers();render();loadHistory();
});
events.addEventListener('status',e=>{Object.assign(state,JSON.parse(e.data));render();if(state.state==='capturing'&&!archive.complete)loadHistory()});
events.addEventListener('point',e=>{const data=JSON.parse(e.data);mergePoints([data.point]);state.metrics=data.metrics;render()});
events.addEventListener('heartbeat',e=>{state.metrics=JSON.parse(e.data);render()});
events.addEventListener('marker',e=>{state.markers.push(JSON.parse(e.data));renderMarkers();draw()});
events.addEventListener('warning',e=>error(JSON.parse(e.data).message));
events.addEventListener('clients',e=>{state.discovery=JSON.parse(e.data);render()});
const canvas=$('chart'),ctx=canvas.getContext('2d');
function draw(){
 renderTimeline();
 if(!ctx)return;const box=canvas.getBoundingClientRect(),w=box.width,h=box.height;if(!w||!h)return;
 const dpr=window.devicePixelRatio||1;if(canvas.width!==Math.round(w*dpr)||canvas.height!==Math.round(h*dpr)){canvas.width=Math.round(w*dpr);canvas.height=Math.round(h*dpr)}ctx.setTransform(dpr,0,0,dpr,0,0);ctx.clearRect(0,0,w,h);
 const pad={l:62,r:62,t:22,b:35},pw=w-pad.l-pad.r,ph=h-pad.t-pad.b;
 const {begin,end}=shownInterval();
 // Calcular antes de recortar la vista conserva los antecedentes de los últimos 2 min.
 const all=chartPoints();
 const lowerBound=t=>{let lo=0,hi=all.length;while(lo<hi){const mid=(lo+hi)>>>1;if(all[mid].t<t)lo=mid+1;else hi=mid}return lo};
 const selection=$('feedback-series')?.value||'all';
 const pts=all.slice(lowerBound(begin),lowerBound(end+1e-8)).filter(p=>selection==='all'||p.series_id===selection);
 const top=pts.reduce((max,p)=>Math.max(max,p.variance||0,$('sma').checked?p.sma||0:0),Math.max(.01,$('threshold').checked?state.threshold*1.2:0))*1.15;
 const x=t=>pad.l+(t-begin)/(end-begin)*pw,y=v=>pad.t+ph-v/top*ph;
 const yPhi=v=>pad.t+ph-v*ph;
 geometry={x,y,yPhi,begin,end,pad,pw,ph,pts,w,h};ctx.font='11px system-ui';ctx.fillStyle='#6a8086';ctx.textAlign='right';ctx.textBaseline='middle';
 for(let i=0;i<=4;i++){const v=top*i/4,yy=y(v);ctx.strokeStyle='#edf1f1';ctx.lineWidth=1;ctx.beginPath();ctx.moveTo(pad.l,yy);ctx.lineTo(w-pad.r,yy);ctx.stroke();ctx.fillText(format(v,3),pad.l-10,yy)}
 ctx.textAlign='center';for(let i=0;i<=5;i++){const t=begin+(end-begin)*i/5,xx=x(t);ctx.strokeStyle='#f0f3f3';ctx.beginPath();ctx.moveTo(xx,pad.t);ctx.lineTo(xx,h-pad.b);ctx.stroke();ctx.fillText(clock(t),xx,h-15)}
 ctx.textAlign='left';ctx.fillText('ψ · rad²',4,9);
 ctx.fillStyle='#d15b24';ctx.fillText('φ · 0–1',w-pad.r+6,9);
 for(let i=0;i<=4;i++)ctx.fillText(format(i/4,2),w-pad.r+8,yPhi(i/4));
 ctx.save();ctx.beginPath();ctx.rect(pad.l,pad.t,pw,ph);ctx.clip();
 if($('threshold').checked){ctx.setLineDash([5,4]);ctx.lineWidth=1.2;ctx.strokeStyle='#bd7840';ctx.beginPath();ctx.moveTo(pad.l,y(state.threshold));ctx.lineTo(w-pad.r,y(state.threshold));ctx.stroke();ctx.setLineDash([])}
 for(const m of state.markers){if(m.t<begin||m.t>end)continue;ctx.setLineDash([2,4]);ctx.strokeStyle=m.kind==='movement'?'#809398':'#91aca8';ctx.beginPath();ctx.moveTo(x(m.t),pad.t);ctx.lineTo(x(m.t),h-pad.b);ctx.stroke();ctx.setLineDash([]);ctx.fillStyle='#657981';ctx.font='10px system-ui';ctx.fillText(m.kind==='movement'?'M':'Q',x(m.t)+4,pad.t+8)}
 ctx.strokeStyle='#087e80';ctx.lineWidth=2;ctx.lineJoin='round';let previous=null;ctx.beginPath();for(const p of pts){if(p.variance==null){previous=null;continue}if(!previous||p.config_changed||p.series_id!==previous.series_id||p.t-previous.t>2.8)ctx.moveTo(x(p.t),y(p.variance));else ctx.lineTo(x(p.t),y(p.variance));previous=p}ctx.stroke();
 ctx.fillStyle='#087e80';for(const p of pts){if(p.variance==null)continue;ctx.beginPath();ctx.arc(x(p.t),y(p.variance),p.single_sample?3:1.8,0,Math.PI*2);if(p.single_sample){ctx.strokeStyle='#bf8a31';ctx.stroke()}else ctx.fill()}
 const last=pts.at(-1);if(last&&last.variance!=null){ctx.beginPath();ctx.arc(x(last.t),y(last.variance),3.5,0,Math.PI*2);ctx.fill()}
 if($('sma').checked){
  ctx.strokeStyle='#7256be';ctx.lineWidth=2.6;let prev=null;ctx.beginPath();
  for(const p of pts){if(p.sma==null){prev=null;continue}if(!prev||p.config_changed||p.series_id!==prev.series_id||p.t-prev.t>2.8)ctx.moveTo(x(p.t),y(p.sma));else ctx.lineTo(x(p.t),y(p.sma));prev=p}ctx.stroke();
  if(last&&last.sma!=null){ctx.fillStyle='#7256be';ctx.beginPath();ctx.arc(x(last.t),y(last.sma),3,0,Math.PI*2);ctx.fill()}
 }
 if($('phi').checked){ctx.strokeStyle='#d15b24';ctx.lineWidth=2;ctx.beginPath();let prev=null;for(const p of pts){if(!Number.isFinite(p.variance_phi)){prev=null;continue}if(!prev||p.config_changed||p.series_id!==prev.series_id||p.t-prev.t>2.8)ctx.moveTo(x(p.t),yPhi(p.variance_phi));else ctx.lineTo(x(p.t),yPhi(p.variance_phi));prev=p}ctx.stroke();ctx.fillStyle='#d15b24';for(const p of pts){if(!Number.isFinite(p.variance_phi))continue;ctx.beginPath();ctx.arc(x(p.t),yPhi(p.variance_phi),1.6,0,Math.PI*2);ctx.fill()}}
 ctx.restore();
 drawInspection();
}
// Consultar muestras reales: no interpolar valores entre informes ni detener el stream.
function pointAtPointer(e){
 if(!geometry||!geometry.pts.length)return null;
 const g=geometry,rect=canvas.getBoundingClientRect(),px=e.clientX-rect.left,py=e.clientY-rect.top;
 if(px<g.pad.l||px>g.pad.l+g.pw||py<g.pad.t||py>g.pad.t+g.ph)return null;
 const t=g.begin+(px-g.pad.l)/g.pw*(g.end-g.begin);
 const p=g.pts.reduce((a,b)=>Math.abs(b.t-t)<Math.abs(a.t-t)?b:a);
 return Math.abs(g.x(p.t)-px)<=25?p:null;
}
function drawInspection(){
 const tip=$('tooltip'),g=geometry;
 const p=inspected&&inspected.session===state.session?g.pts.find(p=>p.t===inspected.t):null;
 if(!p){inspected=null;tip.hidden=true;return}
 const xx=g.x(p.t);
 ctx.save();ctx.strokeStyle='#658188';ctx.lineWidth=1;ctx.setLineDash([3,4]);
 ctx.beginPath();ctx.moveTo(xx,g.pad.t);ctx.lineTo(xx,g.pad.t+g.ph);ctx.stroke();ctx.setLineDash([]);
 for(const [value,color] of [[p.variance,'#087e80'],...($('sma').checked?[[p.sma,'#7256be']]:[])]){
  if(!Number.isFinite(value))continue;
  ctx.beginPath();ctx.arc(xx,g.y(value),4.5,0,Math.PI*2);ctx.fillStyle='#fff';ctx.fill();ctx.strokeStyle=color;ctx.lineWidth=2;ctx.stroke();
 }
 ctx.restore();
 const ms=Math.round(p.t*1000),time=`${clock(Math.floor(ms/1000))},${String(ms%1000).padStart(3,'0')}`;
 tip.textContent=`${inspected.pinned?'Punto fijado · ':''}${time}\nVarianza ψ: ${Number.isFinite(p.variance)?format(p.variance,8)+' rad²':'Sin dato válido'}${$('sma').checked?`\nMedia móvil (${smaSize}): ${Number.isFinite(p.sma)?format(p.sma,8)+' rad²':'Sin dato válido'}`:''}\nVarianza circular φ: ${Number.isFinite(p.variance_phi)?format(p.variance_phi,8):'Sin dato válido'}\n${feedbackLabel(p)}\n${p.single_sample?'Una sola muestra: 0 descriptivo, no demuestra quietud':p.reliable===false?'Calidad limitada; punto conservado':p.quality}\nHueco máximo: ${format(p.gap,2)} s\n${p.n_window??'—'} BFI en ventana · RSSI ${format(p.rssi,0)} dBm\n${inspected.pinned?'Clic o Esc para soltar':'Clic para fijar este punto'}`;
 tip.hidden=false;
 // Medir el tooltip permite mantenerlo dentro de la gráfica también en móvil.
 const width=tip.offsetWidth,height=tip.offsetHeight,yy=Number.isFinite(p.variance)?g.y(p.variance):g.pad.t+g.ph/2;
 const left=xx+14+width<=g.w?xx+14:xx-width-14;
 tip.style.left=Math.max(4,Math.min(left,g.w-width-4))+'px';
 tip.style.top=Math.max(4,Math.min(yy-height-14,g.h-height-4))+'px';
}
canvas.addEventListener('pointermove',e=>{
 if(e.pointerType==='touch'||inspected?.pinned)return;
 const p=pointAtPointer(e);inspected=p?{session:state.session,t:p.t,pinned:false}:null;draw();
});
canvas.addEventListener('pointerleave',()=>{if(!inspected?.pinned){inspected=null;draw()}});
canvas.addEventListener('click',e=>{
 if(inspected?.pinned)inspected=null;
 else{const p=pointAtPointer(e);inspected=p?{session:state.session,t:p.t,pinned:true}:null}
 canvas.focus({preventScroll:true});draw();
});
canvas.addEventListener('keydown',e=>{
 if(e.key==='Escape'){inspected=null;draw();return}
 if(!['ArrowLeft','ArrowRight','Home','End'].includes(e.key)||!geometry?.pts.length)return;
 e.preventDefault();const pts=geometry.pts,index=inspected?pts.findIndex(p=>p.t===inspected.t):pts.length-1;
 const next=e.key==='Home'?0:e.key==='End'?pts.length-1:Math.max(0,Math.min(pts.length-1,index+(e.key==='ArrowLeft'?-1:1)));
 inspected={session:state.session,t:pts[next].t,pinned:true};draw();
});
new ResizeObserver(draw).observe(canvas);$('sma-window').value=smaSize;updateSmaSize();render();

$('feedback-series')?.addEventListener('change',()=>{inspected=null;draw()});

events.addEventListener('authorization',e=>{state.authorization=JSON.parse(e.data);if(!state.replay&&!state.authorization.authorized)location.assign('/authorization');else render()});
