'use strict';
const el=id=>document.getElementById(id);
let token='', replay=false;
async function load(){
 const response=await fetch('/api/authorization');if(!response.ok)throw new Error('No se pudo consultar la declaración');
 const data=await response.json();token=data.csrf;replay=data.replay;
 el('explicit-consent').checked=false;
 el('authorization-status').textContent=replay?'Demo sin radio. La reproducción sintética no autoriza una captura real.':data.authorized?'Declaración guardada · adquisición limitada a tus enlaces.':'Captura bloqueada · declara los enlaces y marca el consentimiento.';
 el('declaration-summary').hidden=!data.authorized;
 if(data.authorized){
  const d=data.declaration;
  el('authorized-ap').value=d.ap;el('authorized-clients').value=d.clients.map(c=>`${c.id}=${c.mac}`).join('\n');
  el('authorized-interface').value=d.interface;el('authorized-ssid').value=d.ssid||'';
  el('declared-at').textContent='Confirmada localmente: '+new Date(d.accepted_at).toLocaleString();
  el('declared-scope').textContent=`AP ${d.ap} · ${d.clients.length} cliente(s) · ${d.interface}`;
  el('authorized-filter').textContent=data.filter;
 }
 el('save-authorization').disabled=replay;el('revoke-authorization').disabled=replay;
}
function showError(error){el('authorization-error').textContent=error.message;el('authorization-error').hidden=false;}
async function post(path,data){
 const response=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json','X-Live-Token':token},body:JSON.stringify(data)});
 const result=await response.json();if(!response.ok)throw new Error(result.error||'No se pudo guardar');
}
el('authorization-form').addEventListener('submit',async event=>{
 event.preventDefault();el('authorization-error').hidden=true;
 try{
  if(!el('explicit-consent').checked)throw new Error('Debes marcar expresamente el consentimiento.');
  const clients=el('authorized-clients').value.split(/\r?\n/).filter(line=>line.trim()).map(line=>{
   const pieces=line.trim().split('=');if(pieces.length!==2)throw new Error('Usa C01=MAC, un cliente por línea.');
   return {id:pieces[0].trim().toUpperCase(),mac:pieces[1].trim()};
  });
  el('save-authorization').disabled=true;
  await post('/api/authorization',{ap:el('authorized-ap').value.trim(),clients,interface:el('authorized-interface').value.trim(),ssid:el('authorized-ssid').value,radio_mode:'auto',consent:true});
  await load();el('declaration-summary').scrollIntoView({behavior:'smooth',block:'nearest'});
 }catch(error){showError(error);}finally{el('save-authorization').disabled=replay;}
});
el('revoke-authorization').addEventListener('click',async()=>{
 try{await post('/api/authorization/revoke',{});await load();}catch(error){showError(error);}
});
load().catch(showError);
