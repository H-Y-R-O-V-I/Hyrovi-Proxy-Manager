import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import fs from "node:fs/promises";

const html = await fs.readFile(new URL("../ops/hpm-privacy-20261022/datenschutz.html", import.meta.url), "utf8");
const pageScript=html.match(/<script>([\s\S]*?)<\/script>/)?.[1];
test("privacy page has substantive content and withdrawal option",()=>{
  assert.ok(pageScript);
  for(const phrase of ["Datenschutzerklärung","Technischer Betrieb","Nutzungsanalyse","Cookies","Widerruf",
                      "Ihre Rechte","90 Tage","Verantwortliche Stelle"]){
    assert.ok(html.includes(phrase),`Missing: ${phrase}`);
  }
  assert.ok(html.includes("hyrovi_analytics_consent"));
  assert.ok(html.includes("hyrovi_visitor_id"));
  assert.ok(!html.includes("Cookie-Einstellungen"),"no floating settings affordance on privacy page");
});
function browser(initial) {
  const jar=new Map(Object.entries(initial));
  const listeners=new Map();
  const button={disabled:false,addEventListener(kind,fn){listeners.set(kind,fn)}};
  const status={textContent:""};
  const doc={
    get cookie(){return [...jar].map(([k,v])=>k+"="+v).join("; ")},
    set cookie(value){
      const [pair,...props]=value.split(";");
      const i=pair.indexOf("=");
      const key=pair.slice(0,i), val=pair.slice(i+1);
      if(props.some(p=>p.trim().toLowerCase()==="max-age=0"))jar.delete(key);
      else jar.set(key,val);
    },
    getElementById(key){return key==="withdraw"?button:key==="withdraw-status"?status:null;}
  };
  const session=new Map([["hyrovi_sid","dummy-session"]]);
  vm.runInNewContext(pageScript,{document:doc,sessionStorage:{removeItem:key=>session.delete(key)}});
  return {jar,button,status,listeners,session};
}
test("privacy page revokes accepted analytics cookie without another dialog",()=>{
  const b=browser({hyrovi_analytics_consent:"1",hyrovi_visitor_id:"abc"});
  assert.equal(b.button.disabled,false);
  b.listeners.get("click")();
  assert.equal(b.jar.get("hyrovi_analytics_consent"),"0");
  assert.equal(b.jar.has("hyrovi_visitor_id"),false);
  assert.equal(b.session.has("hyrovi_sid"),false);
  assert.equal(b.button.disabled,true);
  assert.match(b.status.textContent,/widerrufen/);
});
test("privacy page correctly reports that no acceptance is present",()=>{
  const b=browser({hyrovi_analytics_consent:"0"});
  assert.equal(b.button.disabled,true);
  assert.match(b.status.textContent,/keine aktive Einwilligung/);
});
