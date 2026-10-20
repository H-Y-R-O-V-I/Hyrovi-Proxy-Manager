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
$('start').onclick=async()=>{
  $('start').disabled=true;$('startError').textContent='';
  try{
    const r=await fetch('/api/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({alias:$('alias').value}),cache:'no-store'});
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
