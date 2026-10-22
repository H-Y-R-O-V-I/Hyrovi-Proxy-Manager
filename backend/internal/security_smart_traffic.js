// HYROVI Smart: intentionally non-identifying classifications for HTTP events.
// These describe REQUESTS rather than unique clients or proof of human identity.
// No IP, raw user-agent, cookies, fingerprints, query parameters or request ID.
const BOT = /(?:googlebot|bingbot|duckduckbot|yandexbot|baiduspider|slurp|applebot|facebookexternalhit|bytespider|petalbot|crawler|spider|(?:^|[\s;/])bot(?:[\s;/]|$)|curl\/|wget\/|python-requests|python-urllib|scrapy|headlesschrome|playwright|puppeteer|selenium|aiohttp|httpx\/|go-http-client|java\/|libwww|okhttp|postmanruntime)/i;
const LA = /^[a-z]{2,3}(?:-[A-Z]{2})?$/;
const SAFE_METHOD = new Set(["GET","HEAD","POST","PUT","PATCH","DELETE","OPTIONS"]);

export function describeRequest(headers = {}) {
  const ua = String(headers.user_agent || "").slice(0,512);
  const chPlatform = String(headers.sec_ch_ua_platform || "").replace(/"/g,"").slice(0,50);
  const al = String(headers.accept_language || "").split(",")[0].split(";")[0].trim();
  const languageRegion = LA.test(al) ? al : "Unbekannt";
  const bot = BOT.test(ua);
  let browser = "Unbekannt";
  if (/Edg(?:e|A|iOS)?\//i.test(ua)) browser = "Edge";
  else if (/OPR\/|Opera\//i.test(ua)) browser = "Opera";
  else if (/SamsungBrowser\//i.test(ua)) browser = "Samsung Internet";
  else if (/Firefox\/|FxiOS\//i.test(ua)) browser = "Firefox";
  else if (/Chrome\/|CriOS\//i.test(ua)) browser = "Chrome";
  else if (/Safari\//i.test(ua) && /Version\//i.test(ua)) browser = "Safari";
  const platform = /Android/i.test(ua+chPlatform) ? "Android"
    : /iPad|iPhone|iPod/i.test(ua) || /iOS/i.test(chPlatform) ? "iOS/iPadOS"
    : /Windows/i.test(ua+chPlatform) ? "Windows"
    : /Macintosh|Mac OS X|macOS/i.test(ua+chPlatform) ? "macOS"
    : /Linux|X11/i.test(ua+chPlatform) ? "Linux" : "Unbekannt";
  const device = /iPad|Tablet|Android(?!.*Mobile)/i.test(ua) ? "Tablet"
    : /iPhone|iPod|Mobile|Android.*Mobile/i.test(ua) ||
      /\?1/.test(String(headers.sec_ch_ua_mobile || "")) ? "Smartphone"
    : browser !== "Unbekannt" ? "Desktop/Unbekannt" : "Unbekannt";
  return {classification:bot?"bot":"unknown", browser,platform,device,languageRegion,
    reason:bot?"Automations-User-Agent":"Kein eindeutiges Automationsmerkmal"};
}
export function emptySmartBreakdown() {
  return {botRequests:0,unknownRequests:0,devices:{},browsers:{},platforms:{},
    languageRegions:{},botDevices:{},botBrowsers:{},botPlatforms:{},botLanguageRegions:{}};
}
export function addSmartBreakdown(b, info) {
  if(info.classification==="bot") b.botRequests++;
  else b.unknownRequests++;
  for(const [map,key] of [["devices",info.device],["browsers",info.browser],
     ["platforms",info.platform],["languageRegions",info.languageRegion]]) {
    b[map][key] = (b[map][key]||0)+1;
    if(info.classification==="bot") {
      const botMap="bot"+map.charAt(0).toUpperCase()+map.slice(1);
      b[botMap][key] = (b[botMap][key]||0)+1;
    }
  }
}
export function smartRequestEvent(row, description, source) {
  const status = Number(row.status);
  const method = String(row.method||"").toUpperCase();
  if(!SAFE_METHOD.has(method) || !Number.isInteger(status) || status<100 || status>599) return null;
  const date=Date.parse(row.ts||row.timestamp||"");
  if(!Number.isFinite(date)) return null;
  const raw=String(row.path||"/").split(/[?#]/,1)[0];
  const part=raw.match(/^\/([a-zA-Z][a-zA-Z0-9_-]{0,35})(?:\/|$)/)?.[1]||"";
  const section = /^(?:auth|login|identity|oauth|token|session|account|user|users|admin|private|secret|password|vault|api|payment|checkout|billing|profile)$/i.test(part)
    ? "/[restricted]" : part ? "/"+part : "/";
  return {
    source,host:String(row.host||"").toLowerCase().slice(0,253),
    origin:"proxy",type:"request",time:new Date(Math.floor(date/60000)*60000).toISOString(),
    section,method,status,...description,
  };
}
export function smartBrowserClassification(row) {
  // A scripted browser can emit the same signals. Therefore the most we
  // assert is an interactive-looking event; never call it a verified human.
  return row.type === "action" || row.type === "scroll" || (row.type === "engagement" && Number(row.visibleSeconds)>0)
    ? "interactive" : "unknown";
}
