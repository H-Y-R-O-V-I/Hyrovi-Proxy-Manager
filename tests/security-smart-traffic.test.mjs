import test from "node:test";
import assert from "node:assert/strict";
import {describeRequest, emptySmartBreakdown,addSmartBreakdown,
  smartRequestEvent,smartBrowserClassification} from "../backend/internal/security_smart_traffic.js";
test("known crawler and API tools are flagged, never claim verified human",()=>{
  const samples=[
    ["Googlebot/2.1 (+http://www.google.com/bot.html)","bot"],
    ["curl/8.1.0","bot"],
    ["Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17 Safari/604","unknown"],
    ["Mozilla/5.0 (Windows NT 10.0; Win64) AppleWebKit/537 Chrome/125 Safari/537","unknown"]
  ];
  for(const [user_agent,result] of samples)assert.equal(describeRequest({user_agent}).classification,result);
  const iphone=describeRequest({user_agent:samples[2][0],accept_language:"de-DE,de;q=0.8"});
  assert.equal(iphone.device,"Smartphone");
  assert.equal(iphone.platform,"iOS/iPadOS");
  assert.equal(iphone.browser,"Safari");
  assert.equal(iphone.languageRegion,"de-DE");
});
test("separate and reversible bot distribution",()=>{
  const b=emptySmartBreakdown();
  addSmartBreakdown(b,describeRequest({user_agent:"curl/8.0"}));
  addSmartBreakdown(b,describeRequest({user_agent:"Mozilla/5.0 (Windows NT 10.0) Chrome/125"}));
  assert.equal(b.botRequests,1);
  assert.equal(b.unknownRequests,1);
  assert.equal(b.botBrowsers.Unbekannt,1);
  assert.equal(b.browsers.Chrome,1);
});
test("event removes IP, URL tokens, raw UA, precise timestamp",()=>{
  const d=describeRequest({user_agent:"curl/8.0"});
  const e=smartRequestEvent({host:"stoneapp.hyrovi.com",
     ts:"2026-10-22T07:22:43Z",path:"/login/private?key=SECRET",
     method:"GET",status:200,remote_addr:"12.34.56.78",
     user_agent:"curl/8.0",cookie:"SESSION=SECRET"},d,"Pi");
  const json=JSON.stringify(e);
  assert.ok(!json.includes("12.34.56.78"));
  assert.ok(!json.includes("SECRET"));
  assert.ok(!json.includes("curl/8.0"));
  assert.equal(e.section,"/[restricted]");
  assert.equal(e.time,"2026-10-22T07:22:00.000Z");
  assert.equal(e.classification,"bot");
});
test("interactive-looking events are not declared human",()=>{
  assert.equal(smartBrowserClassification({type:"scroll"}),"interactive");
  assert.equal(smartBrowserClassification({type:"action"}),"interactive");
  assert.equal(smartBrowserClassification({type:"page_view"}),"unknown");
});
