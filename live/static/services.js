const $=id=>document.getElementById(id);
const time=(t,full=false)=>t==null?'—':new Intl.DateTimeFormat('es-ES',{timeZone:'Europe/Madrid',...(full?{day:'2-digit',month:'2-digit'}:{}),hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false}).format(new Date(t*1000));
const num=(v,n=5)=>v==null?'—':Number(v).toLocaleString('es-ES',{maximumFractionDigits:n});
let info=null,data=null,follow=true,end=null,session='',key='',stream='',busy=false,geometry=null,drag=null;
const C1_REFERENCE=0.006820114055593958;
const isC1=()=>data?.target?.mac==='02:00:00:00:00:01'&&data?.target?.ap==='02:00:00:00:00:06';
function options(el,items,value){el.replaceChildren(...items.map(([v,label])=>new Option(label,v)));el.value=items.some(i=>i[0]===value)?value:items[0]?.[0]||'';return el.value;}
function localInput(t){const parts=new Intl.DateTimeFormat('sv-SE',{timeZone:'Europe/Madrid',year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false}).format(new Date(t*1000));return parts.replace(' ','T');}
function madridEpoch(value){let t=Date.parse(value+'Z');for(let i=0;i<3;i++){const represented=Date.parse(localInput(t/1000)+'Z');t+=Date.parse(value+'Z')-represented;}return t/1000;}
async function get(url){const r=await fetch(url,{cache:'no-store'});const x=await r.json();if(!r.ok)throw Error(x.error||'Error de consulta');return x;}
async function refresh(){
 if(busy)return;busy=true;
 try{
  info=await get('/api/services');const s=info.service;
  $('notice').textContent=info.active?'Servicio activo · consulta en directo, captura protegida':info.protected?'Radio protegida · esperando actualización del estado':s?'Servicio detenido · puedes consultar lo guardado':'No hay monitorizaciones registradas.';
  if(!s?.session){data=null;draw();return;}
  if(session!==s.session){session=s.session;key='';stream='';follow=true;}
  options($('service'),[[session,session]],session);
  const chosen=options($('link'),s.links.map(l=>[l.key,`${l.id||l.mac} · AP ${l.ap} · ${l.bfi} BFI`]),key);
  if(chosen!==key){key=chosen;stream='';}
  $('session-info').textContent=`Inicio: ${time(s.started,true)} · canal ${s.radio?.actual?.channel??s.links[0]?.channel??'—'} · ${s.radio?.actual?.width??s.links[0]?.width??'—'} MHz · última actualización ${time(s.updated)}`;
  $('storage').textContent=s.storage.free_bytes!=null?`${num(s.storage.free_bytes/1e9,1)} GB libres · ${num(s.storage.raw_bytes/1e6,1)} MB de PCAP · estimación ${num(s.storage.raw_estimated_bytes_day/1e9,2)} GB/día (solo PCAP)`:'Información de almacenamiento no disponible para este servicio.';
  $('path').textContent=s.output||'';
  if(!key)return;
  if(follow||end==null)end=Date.now()/1000;
  const span=$('span').value==='all'?end-s.started:Number($('span').value),start=Math.max(s.started,end-span);
  const p=new URLSearchParams({session,key,start,end});if(stream)p.set('stream',stream);
  data=await get('/api/services/series?'+p);stream=data.stream||'';
  options($('stream'),data.streams.map(x=>{const f=x.feedback||{};return [x.id,`${f.kind||x.id} ${f.nr||''}×${f.nc||''} · ${f.direction==='ap_to_client'?'AP → cliente':'cliente → AP'} · ${x.n} BFI`];}),stream);
  const last=data.points.at(-1),age=data.last==null?null:Date.now()/1000-data.last;
  $('total').textContent=num(data.total,0);$('last').textContent=time(data.last);$('rssi').textContent=last?num(last.rssi,1)+' dBm':'—';
  $('quality').textContent=data.total===0?'Sin BFI observados':age>15?`Sin BFI nuevos: ${Math.floor(age)} s`:({valid:'Ventana válida',warming_up:'Ventana inicial',insufficient_bfi:'Calidad limitada'})[last?.quality]||'Datos agregados';
  $('until').value=localInput(end);
  const slider=$('timeline');slider.min=Math.floor(s.started);slider.max=Math.ceil(Date.now()/1000);slider.value=Math.floor(end);
  $('reference').disabled=!isC1();
  $('reference-note').textContent=isC1()?`Línea roja: referencia histórica C1 = ${num(C1_REFERENCE,8)} rad². Superarla es una indicación respecto a esa referencia, no una validación de movimiento en la nueva posición.`:'Este enlace no tiene referencia de movimiento calibrada; no se aplica el umbral de C1.';
  $('view-status').textContent=`${follow?'Siguiendo el directo':'Consultando histórico'} · ${time(start,true)} → ${time(end,true)} · ${num(data.count,0)} BFI en el intervalo`;
  $('method').textContent=data.bucket_seconds?`Vista resumida en bloques de ${data.bucket_seconds} s: media y mínimo–máximo de ψ; media de la varianza circular φ. Todos los puntos originales siguen guardados. La media móvil se aplica a estos bloques.`:'Cada punto corresponde a un BFI guardado. Varianzas causales en ventanas de 6 s; media móvil sobre los puntos visibles.';
  draw();
 }catch(e){$('notice').textContent='No se puede actualizar la vista: '+e.message+'. Esto no envía ninguna orden al capturador.';}
 finally{busy=false;}
}
function draw(){
 const c=$('chart'),ctx=c.getContext('2d'),dpr=devicePixelRatio||1,w=c.clientWidth,h=420;c.width=w*dpr;c.height=h*dpr;ctx.scale(dpr,dpr);ctx.clearRect(0,0,w,h);
 if(!data?.points.length){ctx.fillText('Sin muestras en este intervalo. No equivale a quietud.',30,60);geometry=null;return;}
 const pts=data.points,pad={l:70,r:65,t:22,b:48},pw=w-pad.l-pad.r,ph=h-pad.t-pad.b;
 const showReference=isC1()&&$('reference').checked;
 const high=Math.max(.0001,showReference?C1_REFERENCE:0,...pts.map(p=>p.high??p.variance??0))*1.12;
 const x=t=>pad.l+(t-data.start)/(data.end-data.start)*pw,y=v=>pad.t+ph-v/high*ph,yp=v=>pad.t+ph-v*ph;
 ctx.font='12px sans-serif';ctx.strokeStyle='#dfe7e7';ctx.fillStyle='#456';
 for(let i=0;i<=5;i++){const yy=pad.t+i*ph/5;ctx.beginPath();ctx.moveTo(pad.l,yy);ctx.lineTo(w-pad.r,yy);ctx.stroke();ctx.fillText(num(high*(1-i/5),4),3,yy+4);if($('phi').checked)ctx.fillText(num(1-i/5,1),w-pad.r+12,yy+4);}
 for(let i=0;i<=4;i++)ctx.fillText(time(data.start+(data.end-data.start)*i/4),pad.l+i*pw/4-25,h-15);
 const window=Math.max(1,Math.min(120,Number($('sma').value)||1));
 function avg(i){const p=pts.slice(Math.max(0,i-window+1),i+1).map(x=>x.variance).filter(Number.isFinite);return p.reduce((a,b)=>a+b,0)/p.length;}
 for(const [color,value,map] of [['#087e80',p=>p.variance,y],['#7256be',(_,i)=>avg(i),y],...($('phi').checked?[['#d15b24',p=>p.variance_phi,yp]]:[])]){
  ctx.strokeStyle=color;ctx.fillStyle=color;ctx.lineWidth=1.4;ctx.beginPath();let prev=null;
  pts.forEach((p,i)=>{const v=value(p,i);if(!Number.isFinite(v)){prev=null;return;}if(!prev||p.ts-prev.ts>Math.max(2.8,data.bucket_seconds*1.5))ctx.moveTo(x(p.ts),map(v));else ctx.lineTo(x(p.ts),map(v));prev=p;});ctx.stroke();
  pts.forEach((p,i)=>{const v=value(p,i);if(!Number.isFinite(v))return;ctx.beginPath();ctx.arc(x(p.ts),map(v),1.8,0,Math.PI*2);ctx.fill();});
 }
 if(data.bucket_seconds){ctx.strokeStyle='#087e8055';for(const p of pts){ctx.beginPath();ctx.moveTo(x(p.ts),y(p.low));ctx.lineTo(x(p.ts),y(p.high));ctx.stroke();}}
 if(showReference){const yy=y(C1_REFERENCE);ctx.strokeStyle='#c84242';ctx.lineWidth=1.5;ctx.setLineDash([7,5]);ctx.beginPath();ctx.moveTo(pad.l,yy);ctx.lineTo(w-pad.r,yy);ctx.stroke();ctx.setLineDash([]);ctx.fillStyle='#ab3030';ctx.fillText(`Referencia C1 · ${num(C1_REFERENCE,8)} rad²`,pad.l+8,yy-7);}
 geometry={pts,x,pad,pw};
}
$('chart').addEventListener('pointermove',e=>{if(drag){drag.dx=e.clientX-drag.x;if(Math.abs(drag.dx)>4){drag.moved=true;$('tip').hidden=true;$('view-status').textContent='Desplazando el histórico…';}return;}if(!geometry)return;const px=e.clientX-e.currentTarget.getBoundingClientRect().left;const p=geometry.pts.reduce((a,b)=>Math.abs(geometry.x(a.ts)-px)<Math.abs(geometry.x(b.ts)-px)?a:b);$('tip').hidden=false;$('tip').textContent=`${time(p.ts,true)}\nψ: ${num(p.variance,8)} rad²\nφ: ${num(p.variance_phi,8)}\nRSSI: ${num(p.rssi,1)} dBm\n${data.bucket_seconds?`${p.n} informes · ${p.valid} con ventana válida\nψ mínimo–máximo: ${num(p.low,8)}–${num(p.high,8)}`:p.quality}`;});
$('chart').addEventListener('pointerleave',()=>$('tip').hidden=true);
$('link').onchange=()=>{key=$('link').value;stream='';refresh();};$('stream').onchange=()=>{stream=$('stream').value;refresh();};$('span').onchange=()=>{if($('span').value==='all'){follow=true;end=Date.now()/1000;}refresh();};
$('until').onchange=()=>{const t=madridEpoch($('until').value);if(Number.isFinite(t)){end=t;follow=false;refresh();}};
for(const [id,direction] of [['back',-1],['forward',1]])$(id).onclick=()=>{follow=false;end=Math.max(info.service.started+1,Math.min(Date.now()/1000,end+direction*($('span').value==='all'?3600:Number($('span').value))));refresh();};
$('live').onclick=()=>{follow=true;refresh();};$('phi').onchange=draw;$('sma').oninput=draw;
$('reference').onchange=draw;
function setSpan(seconds){const select=$('span');let opt=select.querySelector('option[value="custom"]');if(opt)opt.remove();const value=String(Math.round(seconds));if(![...select.options].some(o=>o.value===value))select.add(new Option(`${num(seconds/60,1)} min · zoom`,value));select.value=value;}
function moveTo(t){const now=Date.now()/1000;follow=false;end=Math.max(info.service.started+1,Math.min(now,t));refresh();}
$('timeline').oninput=()=>{if($('span').value==='all')setSpan(Math.min(600,Math.max(30,(Date.now()/1000-info.service.started)/4)));moveTo(Number($('timeline').value));};
$('first').onclick=()=>{if(!info?.service)return;if($('span').value==='all')setSpan(600);moveTo(info.service.started+Number($('span').value));};
$('whole').onclick=()=>{$('span').value='all';follow=true;end=Date.now()/1000;refresh();};
$('chart').style.touchAction='none';
$('chart').addEventListener('pointerdown',e=>{if(!data||!geometry)return;drag={x:e.clientX,dx:0,moved:false,start:data.start,end:data.end,span:data.end-data.start};e.currentTarget.setPointerCapture(e.pointerId);});
$('chart').addEventListener('pointerup',e=>{const d=drag;drag=null;if(!d?.moved)return;setSpan(Math.max(30,d.span));moveTo(d.end-d.dx/geometry.pw*d.span);});
$('chart').addEventListener('pointercancel',()=>{drag=null;});
$('chart').addEventListener('wheel',e=>{if(!data||!geometry)return;e.preventDefault();const rect=e.currentTarget.getBoundingClientRect(),fraction=Math.max(0,Math.min(1,(e.clientX-rect.left-geometry.pad.l)/geometry.pw));const old=data.end-data.start,span=Math.max(30,Math.min(Date.now()/1000-info.service.started,old*(e.deltaY>0?1.5:1/1.5))),anchor=data.start+fraction*old;setSpan(span);moveTo(anchor+(1-fraction)*span);},{passive:false});
new ResizeObserver(draw).observe($('chart'));refresh();setInterval(refresh,2000);
