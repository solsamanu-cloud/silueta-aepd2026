'use strict';
const $=id=>document.getElementById(id);
let sessions=[],clients=[],scans=[],page=0,selected=null,points=[],job=0,geometry=null,pointIndex=0;
const day=ts=>{if(!ts)return '';const d=new Date(typeof ts==='number'?ts*1000:ts);return new Intl.DateTimeFormat('sv-SE',{timeZone:'Europe/Madrid',year:'numeric',month:'2-digit',day:'2-digit'}).format(d)};
const date=ts=>ts?new Date(typeof ts==='number'?ts*1000:ts).toLocaleString('es-ES',{timeZone:'Europe/Madrid'}):'—';
const fmt=(x,n=0)=>x==null?'—':Number(x).toLocaleString('es-ES',{maximumFractionDigits:n});
async function get(url){const r=await fetch(url);const d=await r.json();if(!r.ok)throw Error(d.error||'Error al consultar el archivo');return d}
function hasBFI(p){return (p?.vht_bfi||0)>0||(p?.reverse_vht_bfi||0)>0||[p?.protocol,p?.protocol_followup,...(p?.protocol_records||[]).map(r=>r.protocol)].some(d=>Object.values(d?.bfi||{}).some(v=>v.total>0)||Object.values(d?.he_feedback||{}).some(v=>v>0))}
function searchMatch(values){return values.filter(v=>v!=null).join(' ').toLowerCase().includes($('search').value.trim().toLowerCase())}
function bandMatch(f){return $('band').value==='all'||$('band').value==='2.4'&&f>=2400&&f<2500||$('band').value==='5'&&f>=5000&&f<5900}
function dateMatch(ts){const d=day(ts);return (!$('from').value||d&&d>=$('from').value)&&(!$('to').value||d&&d<=$('to').value)}
function sessionMatch(s){return searchMatch([s.session,s.client,s.client_identity?.label,s.ap,s.ssid,s.radio?.channel])&&bandMatch(s.radio?.frequency)&&dateMatch(s.started)&&(!$('only-bfi').checked||s.BFI>0||s.observed_bfi>0)}
function row(body,values){const tr=document.createElement('tr');for(const v of values){const td=document.createElement('td');if(typeof v==='string'||typeof v==='number')td.textContent=v;else td.append(v);tr.append(td)}body.append(tr)}
function button(text,fn){const b=document.createElement('button');b.textContent=text;b.addEventListener('click',fn);return b}
function render(){
 const body=$('sessions');body.replaceChildren();const filtered=sessions.filter(sessionMatch);page=Math.min(page,Math.max(0,Math.ceil(filtered.length/30)-1));
 for(const s of filtered.slice(page*30,page*30+30))row(body,[date(s.started),`${s.client_identity?.label||s.client||'—'} · ${s.client||''} / ${s.ap||'—'}`,fmt(s.radio?.channel),fmt(s.BFI),s.archive_status,button('Abrir',()=>openSession(s.session))]);
 if(!filtered.length)row(body,['Sin capturas para estos filtros','','','','','']);
 $('count').textContent=`${filtered.length} de ${sessions.length} sesiones conservadas`;$('page').textContent=`${page+1} / ${Math.max(1,Math.ceil(filtered.length/30))}`;$('prev').disabled=page===0;$('next').disabled=(page+1)*30>=filtered.length;
 const cb=$('clients');cb.replaceChildren();
 for(const p of clients){const ss=sessions.filter(s=>s.client===p.mac&&s.ap===p.ap);const adv=p.protocol_followup?.ap_advertised||p.protocol?.ap_advertised||p.advertised;
  const seenInRange=scans.some(scan=>dateMatch(scan.started)&&scan.clients?.some(c=>c.mac===p.mac&&c.ap===p.ap));
  if(!searchMatch([p.mac,p.ap,p.label,adv?.ssid,p.channel])||!bandMatch(p.frequency)||($('only-bfi').checked&&!hasBFI(p)&&!ss.some(s=>s.BFI>0||s.observed_bfi>0)))continue;
  if(($('from').value||$('to').value)&&!seenInRange&&!ss.some(s=>dateMatch(s.started)))continue;
  row(cb,[button(`${p.id?p.label+' · ':''}${p.mac}`,()=>openClient(p)),`${p.ap} · ${adv?.ssid||'SSID no observado'}`,fmt(p.channel),date(p.last_seen),String(ss.length)]);
 }
 if(!cb.children.length)row(cb,['Sin clientes para estos filtros','','','','']);
}
function openClient(p){
 $('search').value=p.mac;page=0;render();$('client-panel').hidden=false;$('client-title').textContent=`${p.label||'Cliente'} · ${p.mac} · AP ${p.ap}`;
 $('client-detail').textContent=JSON.stringify(p,null,2);
 $('scan-detail').textContent=JSON.stringify(scans.filter(s=>s.clients?.some(c=>c.mac===p.mac&&c.ap===p.ap)).map(s=>({fecha:date(s.started),estado:s.status,observaciones:s.clients.filter(c=>c.mac===p.mac&&c.ap===p.ap)})),null,2);
}
async function refresh(){
 $('refresh').disabled=true;$('message').textContent='Leyendo el archivo guardado…';
 try{
  const [a,d]=await Promise.all([get('/api/archive'),get('/api/clients')]);sessions=a.sessions;scans=d.scans||[];clients=[...(d.clients||[])];
  // Recover session-only clients even when an interrupted run never updated discovery.
  for(const s of sessions){if(!s.client||clients.some(p=>p.mac===s.client&&p.ap===s.ap))continue;clients.push({mac:s.client,ap:s.ap,...s.radio,label:s.client_identity?.label||'Cliente observado',last_seen:Date.parse(s.started)/1000})}
  const warnings=[d.history_error,...a.errors.map(e=>`${e.session}: ${e.error}`)].filter(Boolean);
  $('message').textContent=`${clients.length} enlaces · ${sessions.length} capturas · ${scans.length} barridos. Sin borrado automático.`+(warnings.length?'\nRegistros que requieren revisión: '+warnings.join('\n'):'');render();
 }catch(e){$('message').textContent='No se ha podido leer el archivo: '+e.message+'. Si acabas de instalar esta función, reinicia el servidor para activarla.'}
 finally{$('refresh').disabled=false}
}
async function openSession(id){
 const token=++job;selected=id;points=[];pointIndex=0;$('viewer').hidden=false;$('title').textContent=id;$('summary').textContent='';$('detail').textContent='';$('downloads').replaceChildren();$('position').value=0;$('loading').textContent='Cargando…';draw();
 try{
  const d=await get('/api/archive/session?session='+encodeURIComponent(id));if(job!==token)return;
  $('summary').textContent=`${date(d.started)} · ${d.client} → ${d.ap} · canal ${d.radio?.channel??'—'} · ${d.archive_status} · ${fmt(d.BFI)} BFI decodificados · ${fmt(d.decode_errors)} descartes registrados`;
  $('detail').textContent=JSON.stringify(d,null,2);
  if(d.archive_status!=='En curso')for(const kind of d.files){const a=document.createElement('a');a.textContent={pcap:'PCAP original',variance:'Serie completa',session:'Ficha JSON',markers:'Marcas'}[kind]||kind;a.href=`/api/archive/download?session=${encodeURIComponent(id)}&kind=${encodeURIComponent(kind)}`;$('downloads').append(a)}
  if(!d.files.includes('variance')){$('loading').textContent='Esta sesión no conserva una serie de varianza.';return}
  let cursor=0;
  while(job===token){const data=await get(`/api/history?session=${encodeURIComponent(id)}&cursor=${cursor}`);if(job!==token)return;points.push(...data.points);cursor=data.next_cursor;if(data.eof)break;$('loading').textContent=`Cargando ${points.length} puntos…`}
  $('loading').textContent=points.length?`${points.length} puntos guardados. ${d.archive_status==='En curso'?'Instantánea: pulsa Abrir otra vez para actualizar.':''}`:'Sin puntos de varianza guardados. Consulta la ficha de protocolo.';draw();$('viewer').scrollIntoView({behavior:'smooth',block:'start'});
 }catch(e){if(job===token)$('loading').textContent='No se pudo abrir: '+e.message}
}
function interval(){const end=points.at(-1)?.t||60;const span=$('span').value==='all'?Math.max(60,end):Number($('span').value);const max=Math.max(0,end-span);$('position').max=max;const begin=Math.min(Number($('position').value),max);return {begin,end:begin+span}}
function draw(){
 const canvas=$('plot'),rect=canvas.getBoundingClientRect();if(!rect.width)return;
 const dpr=window.devicePixelRatio||1,w=rect.width,h=rect.height;canvas.width=w*dpr;canvas.height=h*dpr;const c=canvas.getContext('2d');c.scale(dpr,dpr);c.clearRect(0,0,w,h);
 const v=interval(),pad={l:66,r:55,t:25,b:35};const subset=points.filter(p=>p.t>=v.begin&&p.t<=v.end);const max=subset.reduce((m,p)=>Math.max(m,p.variance||0),.001)*1.1;
 const x=t=>pad.l+(t-v.begin)/(v.end-v.begin)*(w-pad.l-pad.r),y=(a,m)=>h-pad.b-a/m*(h-pad.t-pad.b);
 c.font='11px system-ui';for(let i=0;i<=4;i++){const yy=y(i/4,1);c.strokeStyle='#e4eaea';c.beginPath();c.moveTo(pad.l,yy);c.lineTo(w-pad.r,yy);c.stroke();c.fillStyle='#087e80';c.fillText((max*i/4).toFixed(4),2,yy+4);c.fillStyle='#d15b24';c.fillText((i/4).toFixed(2),w-pad.r+5,yy+4);c.fillStyle='#657981';const t=v.begin+(v.end-v.begin)*i/4;c.fillText((t/60).toFixed(1)+' min',x(t)-15,h-8)}
 for(const [key,color,m] of [['variance','#087e80',max],['variance_phi','#d15b24',1]]){c.strokeStyle=color;c.lineWidth=1.4;c.beginPath();let last=null,lastSeries=null;for(const p of subset){if(!Number.isFinite(p[key])){last=null;continue}if(last===null||p.config_changed||p.series_id!==lastSeries||p.t-last>2.8)c.moveTo(x(p.t),y(p[key],m));else c.lineTo(x(p.t),y(p[key],m));last=p.t;lastSeries=p.series_id}c.stroke();c.fillStyle=color;for(const p of subset){if(!Number.isFinite(p[key]))continue;c.beginPath();c.arc(x(p.t),y(p[key],m),1.8,0,Math.PI*2);c.fill()}}
 geometry={...v,w,pad};
}
function showPoint(p){if(p)$('point').textContent=`${date(p.ts)} · ${(p.t/60).toFixed(3)} min · ψ ${fmt(p.variance,7)} rad² · φ ${fmt(p.variance_phi,7)} · RSSI ${fmt(p.rssi,1)} dBm · ${p.quality}`}
$('plot').addEventListener('pointermove',e=>{if(!geometry||!points.length)return;const g=geometry,t=g.begin+(e.offsetX-g.pad.l)/(g.w-g.pad.l-g.pad.r)*(g.end-g.begin);let lo=0,hi=points.length-1;while(lo<hi){const mid=(lo+hi)>>1;if(points[mid].t<t)lo=mid+1;else hi=mid}pointIndex=lo>0&&Math.abs(points[lo-1].t-t)<Math.abs(points[lo].t-t)?lo-1:lo;showPoint(points[pointIndex])});
$('plot').addEventListener('keydown',e=>{if(!['ArrowLeft','ArrowRight'].includes(e.key))return;e.preventDefault();pointIndex=Math.max(0,Math.min(points.length-1,pointIndex+(e.key==='ArrowRight'?1:-1)));showPoint(points[pointIndex])});
for(const id of ['search','from','to','band','only-bfi'])$(id).addEventListener('input',()=>{page=0;render()});
$('clear').addEventListener('click',()=>{for(const id of ['search','from','to'])$(id).value='';$('band').value='all';$('only-bfi').checked=false;page=0;render()});
$('prev').addEventListener('click',()=>{page--;render()});$('next').addEventListener('click',()=>{page++;render()});$('refresh').addEventListener('click',refresh);
$('span').addEventListener('change',draw);$('position').addEventListener('input',draw);new ResizeObserver(draw).observe($('plot'));refresh();
