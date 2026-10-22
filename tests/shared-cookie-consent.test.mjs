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
assert.equal(a.elements[0].tag,"section");
assert.match(a.elements[0].style.cssText,/position:fixed/);
assert.equal(a.elements[0].children[0].textContent,"Datenschutz & Nutzungsanalyse");
assert.equal(jar.size,0,"no tracking cookie before opt-in");
assert.equal(a.storage.data.size,0,"no session identifier before opt-in");
assert.equal(a.sent.length,0,"no events before opt-in");
assert.equal(a.buttons.length,2,"two equally visible consent buttons");
assert.equal(a.buttons[0].node.textContent,"Ablehnen");
assert.equal(a.buttons[1].node.textContent,"Akzeptieren");
a.buttons[1].fn(); // explicit click on accept
assert.equal(jar.get("hyrovi_analytics_consent"),"1");
assert.match(jar.get("hyrovi_visitor_id"),/^[a-f0-9-]{16,64}$/);
assert.equal(a.sent.length,1);
assert.equal(a.elements.length,1,"banner removed, only small settings control remains");
assert.equal(a.elements[0].textContent,"Cookie-Einstellungen");
assert.ok(a.writes.every(s=>s.includes("Domain=.hyrovi.com")));
const id=jar.get("hyrovi_visitor_id");
const b=client("ai.hyrovi.com",jar);
assert.equal(b.elements.length,1,"no consent banner on another subdomain");
assert.equal(b.elements[0].textContent,"Cookie-Einstellungen");
assert.equal(b.buttons.filter(b=>["Akzeptieren","Ablehnen"].includes(b.node.textContent)).length,0,"no repeat choice on second domain");
assert.equal(b.sent.length,1,"new domain emits a new page view for same opted-in browser");
assert.equal(b.sent[0].body.deviceId,id,"same id across Pi and VPS sites");
assert.notEqual(b.sent[0].body.sessionId,a.sent[0].body.sessionId,"new independent browsing session");
const c=client("test-login.hyrovi.com",new Map());
assert.equal(c.buttons.length,2,"first-time visitor sees choices");
c.api.revokeConsent();
assert.equal(c.sent.length,0);
assert.equal(c.cookies.has("hyrovi_visitor_id"),false);
assert.equal(c.elements.length,1,"after revocation only settings link remains");
const d=client("test-login.hyrovi.com",new Map(),{gpc:true});
assert.equal(d.sent.length,0);
assert.equal(d.elements.length,1,"consent banner shown under GPC");
assert.equal(d.buttons.length,2);
assert.equal(d.buttons[1].node.disabled,true,"accept disabled under GPC");
const login = client("test-login.hyrovi.com",jar,{path:"/login"});
assert.equal(login.sent.length,1);
assert.equal(login.sent[0].body.path,"/[restricted]","login details must not leak into cross-site analytics");
b.api.revokeConsent();
assert.equal(jar.has("hyrovi_visitor_id"),false);
assert.equal(b.elements.length,1,"settings link remains after revocation");
assert.equal(b.storage.data.size,0,"revocation clears this tab session id");
console.log("PASS: neutral banner, accept + decline, subdomain cookie, no pre-consent tracking, GPC, and revocation");

// A visitor who rejects is NOT tracked on any managed HYROVI domain.
const refusedCookies=new Map();
const refused=client("stoneapp.hyrovi.com",refusedCookies);
assert.equal(refused.elements[0].tag,"section","Stoneapp receives HPM banner");
assert.equal(refused.buttons.length,2);
refused.buttons[0].fn(); // decline
assert.equal(refusedCookies.get("hyrovi_analytics_consent"),"0");
assert.ok(refused.writes.some(v=>v.includes("Max-Age=7776000") &&
  v.includes("Domain=.hyrovi.com") && v.includes("SameSite=Lax") && v.includes("Secure")),
  "declined decision persists for 90 days across the domain");
assert.equal(refusedCookies.has("hyrovi_visitor_id"),false);
assert.equal(refused.sent.length,0);
assert.equal(refused.elements.length,1,"banner is gone after reject");
assert.equal(refused.elements[0].textContent,"Cookie-Einstellungen");
const refusedAgain=client("ai.hyrovi.com",refusedCookies);
assert.equal(refusedAgain.sent.length,0);
assert.equal(refusedAgain.elements.length,1);
assert.equal(refusedAgain.elements[0].textContent,"Cookie-Einstellungen");
assert.equal(refusedAgain.buttons.filter(b=>b.node.textContent==="Akzeptieren").length,0);

const stoneappAfterAccepted=client("stoneapp.hyrovi.com",jar);
assert.equal(stoneappAfterAccepted.sent.length,0,"rejected cookie after revocation prevents new tracking");
assert.equal(stoneappAfterAccepted.elements.length,1,"Stoneapp remembers cross-domain choice");

const freshJar=new Map();
const stoneappFirst=client("stoneapp.hyrovi.com",freshJar);
stoneappFirst.buttons[1].fn();
assert.equal(stoneappFirst.sent.length,1,"Stoneapp tracks after deliberate consent");
assert.equal(stoneappFirst.elements[0].textContent,"Cookie-Einstellungen");
const nextSubdomain=client("feedback.hyrovi.com",freshJar);
assert.equal(nextSubdomain.sent.length,1,"same opted-in pseudonymous browser across domains");
assert.equal(nextSubdomain.elements[0].textContent,"Cookie-Einstellungen");
assert.equal(nextSubdomain.sent[0].body.deviceId,stoneappFirst.sent[0].body.deviceId);

const settingsAfterConsent=client("hyrovi.com",freshJar);
settingsAfterConsent.api.settings();
assert.equal(settingsAfterConsent.buttons.filter(b=>b.node.textContent==="Ablehnen").length,1,
  "explicit settings reopens both choices");
console.log("PASS: Stoneapp plus other HYROVI websites share accepted/rejected preference; settings reopens choices");
