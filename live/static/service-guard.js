(() => {
  let locked=true;
  const ids=['start','stop','client-select','clients-refresh','movement','still'];
  const banner=document.getElementById('service-protection');
  function apply(){
    if(!locked)return;
    for(const id of ids){const el=document.getElementById(id);if(el&&!el.disabled)el.disabled=true;}
  }
  new MutationObserver(apply).observe(document.querySelector('main'),{subtree:true,attributes:true,attributeFilter:['disabled']});
  for(const type of ['click','change','submit'])document.addEventListener(type,e=>{
    if(locked&&(ids.includes(e.target.id)||e.target.id==='capture-form')){e.preventDefault();e.stopImmediatePropagation();}
  },true);
  async function poll(){
    try{
      const r=await fetch('/api/services',{cache:'no-store'});if(!r.ok)throw Error();
      const data=await r.json(),was=locked;locked=data.protected;
      banner.hidden=!locked;
      document.getElementById('service-protection-detail').textContent=data.stale?'Estado pendiente de actualización.':`${data.service?.links.length||0} enlaces registrados. Consultar no cambia el canal ni detiene el servicio.`;
      if(was&&!locked&&typeof render==='function')render();
    }catch(_){locked=true;banner.hidden=false;document.getElementById('service-protection-detail').textContent='No se puede comprobar la radio. Controles bloqueados hasta recuperar conexión.';}
    apply();setTimeout(poll,2000);
  }
  apply();poll();
})();
