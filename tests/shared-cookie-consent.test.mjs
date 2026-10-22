import assert from "node:assert/strict";
import vm from "node:vm";
import { randomUUID } from "node:crypto";
import visitorScript from "../backend/internal/visitor_consent_script.js";

function client(hostname, cookies = new Map(), privacy = {}) {
  const buttons=[], elements=[], sent=[], writes=[];
  const browserDocument = {
    visibilityState:"visible", readyState:"complete",
    get cookie() { return [...cookies].map(([k,v])=>k+"="+v).join("; "); },
    set cookie(value) {
      writes.push(value);
      const [kv] = value.split(";");
      const eq=kv.indexOf("=");
      const k=kv.slice(0,eq), val=kv.slice(eq+1);
      if (/max-age=0/i.test(value)) cookies.delete(k);
      else cookies.set(k, val);
    },
    body:{append(node){elements.push(node);}},
    getElementById(id){return elements.find(x=>x.id===id)||null;},
    createElement(tag) {
      return {
        tag,style:{},children:[],setAttribute(){},
        append(node){this.children.push(node);},
        addEventListener(kind,fn){ if(tag==="button" && kind==="click") buttons.push({node:this,fn}); },
        remove(){const idx=elements.indexOf(this);if(idx>=0)elements.splice(idx,1);}
      };
    },
    addEventListener(){}
  };
  const navigator={
    doNotTrack:privacy.dnt?"1":"0",globalPrivacyControl:!!privacy.gpc,
    language:"de-DE",userAgent:"Safari/17.0",
    sendBeacon(){return false;}
  };
  const storage=new MapStorage();
  const context={
    document:browserDocument,navigator,window:{},
    crypto:{randomUUID},location:{hostname,pathname:privacy.path||"/home"},
    history:{pushState(){},replaceState(){}},console,
    sessionStorage:storage, Intl, URL,
    innerWidth:1024,innerHeight:768,scrollY:0,
    setInterval(){},addEventListener(){},queueMicrotask:fn=>fn(),
    fetch:async (endpoint, options)=>{sent.push({endpoint,body:JSON.parse(options.body)});return {ok:true}},
  };
  vm.runInNewContext(visitorScript(),context);
  return {cookies,buttons,elements,sent,writes,storage,api:context.window.hyroviAnalytics};
}
class MapStorage {
  data=new Map();
  getItem(k){return this.data.get(k)||null}
  setItem(k,v){this.data.set(k,v)}
  removeItem(k){this.data.delete(k)}
}
const jar=new Map();
const a=client("test-login.hyrovi.com",jar);
assert.equal(a.elements.length,1,"footer notice renders before activation");
assert.equal(a.elements[0].tag,"footer");
assert.match(a.elements[0].style.cssText,/position:static/);
assert.doesNotMatch(a.elements[0].style.cssText,/position:fixed/);
assert.equal(jar.size,0,"no tracking cookie before opt-in");
assert.equal(a.storage.data.size,0,"no session identifier before opt-in");
assert.equal(a.sent.length,0,"no events before opt-in");
assert.equal(a.buttons.length,0,"no allow/decline buttons in footer");
a.api.grantConsent();
assert.equal(jar.get("hyrovi_analytics_consent"),"1");
assert.match(jar.get("hyrovi_visitor_id"),/^[a-f0-9-]{16,64}$/);
assert.equal(a.sent.length,1);
assert.ok(a.writes.every(s=>s.includes("Domain=.hyrovi.com")));
const id=jar.get("hyrovi_visitor_id");
const b=client("ai.hyrovi.com",jar);
assert.equal(b.elements.length,1,"same top-level domain footer remains visible");
assert.equal(b.buttons.length,0,"no visitor choice dialog on second domain");
assert.ok(b.elements[0].children.some(x=>x.textContent==="Besucherstatistik widerrufen"),"consented visitors can revoke via footer");
assert.equal(b.sent.length,1,"new domain emits a new page view for same opted-in browser");
assert.equal(b.sent[0].body.deviceId,id,"same id across Pi and VPS sites");
assert.notEqual(b.sent[0].body.sessionId,a.sent[0].body.sessionId,"new independent browsing session");
const c=client("test-login.hyrovi.com",new Map());
assert.equal(c.buttons.length,0,"no consent buttons for first-time visitor");
c.api.revokeConsent();
assert.equal(c.sent.length,0);
assert.equal(c.cookies.has("hyrovi_visitor_id"),false);
assert.equal(c.elements.length,1,"footer remains after rejection");
const d=client("test-login.hyrovi.com",new Map(),{gpc:true});
assert.equal(d.sent.length,0);
assert.equal(d.elements.length,1,"informational footer remains visible under GPC");
assert.equal(d.buttons.length,0,"no consent toggle while GPC is active");
const login = client("test-login.hyrovi.com",jar,{path:"/login"});
assert.equal(login.sent.length,1);
assert.equal(login.sent[0].body.path,"/[restricted]","login details must not leak into cross-site analytics");
b.api.revokeConsent();
assert.equal(jar.has("hyrovi_visitor_id"),false);
assert.equal(b.elements.length,1,"footer remains after revocation");
assert.equal(b.storage.data.size,0,"revocation clears this tab session id");
console.log("PASS: informational cookie footer without consent buttons, opted-in shared identity, no pre-consent tracking, GPC, and revocation");

// Stoneapp analytics runs ONLY on server logs; no visitor-side tracker.
for(const jar of [
  new Map(),
  new Map([["hyrovi_analytics_consent","1"],["hyrovi_visitor_id",randomUUID()]]),
  new Map([["hyrovi_stoneapp_analytics_consent","1"],["hyrovi_stoneapp_visitor_id",randomUUID()]])
]){
  const stoneapp=client("stoneapp.hyrovi.com",jar);
  assert.equal(stoneapp.elements.length,0,"no banner on Stoneapp");
  assert.equal(stoneapp.sent.length,0,"no per-visitor JS requests on Stoneapp");
  assert.equal(stoneapp.writes.length,0,"no cookies read/write for analytics on Stoneapp");
  assert.equal(stoneapp.storage.data.size,0,"no analytics session on Stoneapp");
}
console.log("PASS: Stoneapp server-log analytics, no JS tracking, no banners, no cookies");
