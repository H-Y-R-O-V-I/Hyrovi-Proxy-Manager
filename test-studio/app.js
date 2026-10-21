'use strict';
const $=id=>document.getElementById(id);
let token=null,count=0,taps=0,current='home',lastScroll=0;
const sections={home:'Übersicht',features:'Features',about:'Info'};
async function send(kind,detail){
  if(!token)return;
  try{
    const r=await fetch('/api/event',{method:'POST',headers:{'Content-Type':'application/json','X-Test-Session':token},body:JSON.stringify({kind,detail}),cache:'no-store'});
    if(r.status===401){token=null;$('status').textContent='Testsitzung abgelaufen';return;}
    if(r.ok&&kind!=='heartbeat'&&kind!=='visible'){count++;$('counter').textContent=count+' Aktionen';}
  }catch{/* Network loss does not affect page controls */}
}
function coarseBucket(n){return n<=480?'small':n<=900?'medium':n<=1600?'large':'xlarge'}
function capabilities(){
  const ratio=Math.round(window.devicePixelRatio||1);
  const cores=Number(navigator.hardwareConcurrency||0);
  const memory=Number(navigator.deviceMemory||0);
  const touch=Number(navigator.maxTouchPoints||0);
  let timezone='';
  try{timezone=Intl.DateTimeFormat().resolvedOptions().timeZone||''}catch{}
  return {
    timezone,screen:coarseBucket(Math.max(screen.width,screen.height)),
    viewport:coarseBucket(innerWidth),touch:touch===0?'none':touch===1?'single':'multi',
    cpu:cores===0?'unknown':cores<=2?'1-2':cores<=4?'3-4':cores<=8?'5-8':'9+',
    memory:memory===0?'unknown':memory<=2?'<=2':memory<=4?'3-4':memory<=8?'5-8':'9+',
    theme:matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light',
    motion:matchMedia('(prefers-reduced-motion: reduce)').matches?'reduced':'normal',
    pixelRatio:ratio<=1?'1':ratio===2?'2':'3+',
    deviceType:/iPad|Tablet/i.test(navigator.userAgent)?'tablet':
      /iPhone|Android.*Mobile|Mobile/i.test(navigator.userAgent)?'mobile':'desktop',
    screenPixels:Math.round(screen.width)+'x'+Math.round(screen.height),
    viewportPixels:Math.round(innerWidth)+'x'+Math.round(innerHeight),
    colorDepth:[16,24,30,32].includes(screen.colorDepth)?String(screen.colorDepth):'other',
    orientation:screen.width>=screen.height?'landscape':'portrait',
    connection:['slow-2g','2g','3g','4g'].includes(navigator.connection?.effectiveType)?
      navigator.connection.effectiveType:'unknown',
    features:[
      'WebGLRenderingContext' in window?'webgl':'',
      typeof WebAssembly==='object'?'wasm':'',
      'serviceWorker' in navigator?'service-worker':'',
      'ontouchstart' in window?'touch-events':''
    ].filter(Boolean).join(',')
  };
}
$('start').onclick=async()=>{
  $('start').disabled=true;$('startError').textContent='';
  try{
    const r=await fetch('/api/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({alias:$('alias').value,diagnostics:capabilities()}),cache:'no-store'});
    if(!r.ok)throw Error('Test konnte nicht gestartet werden');
    const d=await r.json();token=d.session;$('userName').textContent=d.alias;
    $('startPanel').hidden=true;$('testPanel').hidden=false;
    send('page','home');
  }catch(e){$('startError').textContent=e.message}finally{$('start').disabled=false;}
};
for(const b of document.querySelectorAll('[data-section]'))b.addEventListener('click',()=>{
  current=b.dataset.section;$('activeSection').textContent=sections[current];
  history.pushState({section:current},'',current==='home'?'/':'/#'+current);
  send('section',current);send('page',current);
});
$('tap').onclick=()=>{taps++;$('score').textContent=taps+' Testklicks';send('button','tap')};
$('toggle').onclick=()=>{$('toggle').classList.toggle('selected');send('button','toggle')};
$('increment').onclick=()=>{taps++;$('score').textContent=taps+' Testklicks';send('button','counter')};
window.addEventListener('popstate',()=>{current=['features','about'].includes(location.hash.slice(1))?location.hash.slice(1):'home';$('activeSection').textContent=sections[current];send('page',current)});
window.addEventListener('scroll',()=>{
 if(!token)return;
 const max=document.documentElement.scrollHeight-innerHeight;
 if(max<=0)return;const p=100*scrollY/max;
 const milestone=[25,50,75,100].filter(x=>x<=p).at(-1)||0;
 if(milestone>lastScroll){lastScroll=milestone;send('scroll','scroll'+milestone)}
},{passive:true});
document.addEventListener('visibilitychange',()=>{if(token){$('status').textContent=document.hidden?'Im Hintergrund':'Browser sichtbar';send('visible',document.hidden?'hidden':'visible')}});
setInterval(()=>{if(token&&!document.hidden)send('heartbeat','visible')},12000);
