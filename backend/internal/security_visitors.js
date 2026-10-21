import fs from "node:fs";
import { createHash } from "node:crypto";
import path from "node:path";
import { analyzeAutomaticActivity } from "./security_smart.js";

const EVENT_FILE = "/data/logs/hyrovi-analytics-events.log";
const LABEL_FILE = "/data/nginx/hyrovi-security/visitor-labels.json";
const PROXY_LOG_FILE = "/data/logs/hyrovi-sec.log";
const VPS_EXPORT_FILE = "/data/vps-hpm-sync/vps-hpm-activity.json";
const READ_LIMIT = 4 * 1024 * 1024;
const ID = /^[a-f0-9]{64}$/;
const HOST = /^[a-z0-9][a-z0-9.-]{0,252}$/;
let cached = { key: "", events: [], readAt: 0 };
let trafficCache = { key: "", value: null, readAt: 0 };
let configuredPiCache = { at: 0, hosts: [] };
let queue = Promise.resolve();

const safeString = (s, max = 120) => String(s ?? "").trim().slice(0, max);
const safeId = (s) => ID.test(String(s)) ? String(s) : null;

async function readEvents() {
  let stat;
  try { stat = await fs.promises.stat(EVENT_FILE); }
  catch (err) { if (err.code === "ENOENT") return []; throw err; }
  const key = String(stat.size) + ":" + String(stat.mtimeMs);
  if (cached.key === key && Date.now() - cached.readAt < 15000) return cached.events;
  const size = Math.min(stat.size, READ_LIMIT);
  if (!size) return [];
  const f = await fs.promises.open(EVENT_FILE, "r");
  let text;
  try {
    const b = Buffer.alloc(size);
    await f.read(b, 0, size, stat.size - size);
    text = b.toString("utf8");
  } finally { await f.close(); }
  if (stat.size > size) text = text.slice(Math.max(0, text.indexOf("\n") + 1));
  const events = [];
  for (const row of text.split("\n")) {
    if (!row) continue;
    try {
      const event = JSON.parse(row);
      if (event && event.consent === true && safeId(event.deviceKey) && Number.isFinite(Date.parse(event.timestamp))) {
        events.push(event);
      }
    } catch { /* ignore a partial or corrupt log line */ }
  }
  cached = { key, events, readAt: Date.now() };
  return events;
}

async function configuredPiHosts() {
  if (Date.now() - configuredPiCache.at < 60000) return configuredPiCache.hosts;
  const dir = "/data/nginx/proxy_host";
  let names;
  try { names = await fs.promises.readdir(dir); }
  catch (e) {
    if (e.code === "ENOENT") return [];
    throw e;
  }
  const hosts = new Set();
  for (const filename of names.filter(n => /^\d+\.conf$/.test(n)).slice(0, 250)) {
    let content;
    try { content = await fs.promises.readFile(path.join(dir, filename), "utf8"); }
    catch (e) { if (e.code === "ENOENT") continue; throw e; }
    if (!content.includes("hyrovi-sec.log hyrovi_sec") ||
        !content.includes("hyrovi-analytics.js")) continue;
    for (const group of content.matchAll(/^\s*server_name\s+([^;]+);/gm)) {
      for (const name of group[1].split(/\s+/)) {
        const host = name.toLowerCase();
        if (HOST.test(host) && host.includes(".")) hosts.add(host);
      }
    }
  }
  const value = [...hosts].sort();
  configuredPiCache = { at: Date.now(), hosts: value };
  return value;
}

// HTTP request totals come from HPM proxy access logs. Deliberately
// never read or return IPs, user agents, request IDs or cookies.
// Aggregate operational traffic is not person tracking.
async function readTraffic() {
  let stat;
  try { stat = await fs.promises.stat(PROXY_LOG_FILE); }
  catch (err) {
    if (err.code === "ENOENT") return { requests: 0, websites: [], window: "recent log tail" };
    throw err;
  }
  const key = String(stat.size) + ":" + String(stat.mtimeMs);
  if (trafficCache.key === key && trafficCache.value && Date.now() - trafficCache.readAt < 60000) return trafficCache.value;
  const size = Math.min(stat.size, 2 * 1024 * 1024);
  const f = await fs.promises.open(PROXY_LOG_FILE, "r");
  let text;
  try {
    const b = Buffer.alloc(size);
    await f.read(b, 0, size, stat.size - size);
    text = b.toString("utf8");
  } finally { await f.close(); }
  if (stat.size > size) text = text.slice(Math.max(0, text.indexOf("\n") + 1));
  const websites = new Map();
  let requests = 0;
  for (const line of text.split("\n")) {
    if (!line) continue;
    let e;
    try { e = JSON.parse(line); } catch { continue; }
    const host = safeString(e.host, 253).toLowerCase();
    if (!HOST.test(host) || !host.includes(".")) continue;
    const status = Number.parseInt(e.status, 10);
    const method = safeString(e.method, 8).toUpperCase();
    if (!Number.isInteger(status) || status < 100 || status > 599 ||
        !["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"].includes(method)) continue;
    requests++;
    let w = websites.get(host);
    if (!w) {
      w = { host, requests: 0, pages: 0, writes: 0, failures: 0,
        latest: null, sections: new Map(), signatureTypes: new Set(), automationSignals: 0 };
      websites.set(host, w);
    }
    w.requests++;
    const headerTuple = ["user_agent", "accept_language", "sec_ch_ua", "sec_ch_ua_mobile", "sec_ch_ua_platform"]
      .map(k => safeString(e[k], 320).toLowerCase());
    if (headerTuple.some(Boolean)) {
      // Count technical header combination TYPES only, not identifiers.
      w.signatureTypes.add(createHash("sha256").update(headerTuple.join("\u0000")).digest("hex").slice(0, 24));
    }
    if (/bot|crawler|spider|curl\/|wget\/|python-requests|scrapy/i.test(headerTuple[0])) w.automationSignals++;
    const path = safeString(e.path, 512).split("?")[0].split("#")[0];
    const accept = safeString(e.accept, 140).toLowerCase();
    if (method === "GET" && (accept.includes("text/html") || path === "/")) w.pages++;
    if (["POST", "PUT", "PATCH", "DELETE"].includes(method)) w.writes++;
    if (status >= 400) w.failures++;
    const ts = Date.parse(e.ts || "");
    if (Number.isFinite(ts) && (!w.latest || ts > Date.parse(w.latest))) {
      w.latest = new Date(Math.floor(ts / 300000) * 300000).toISOString();
    }
    // Only FIRST route segment, never any dynamic IDs, queries or sensitive paths.
    let section = /^\/[a-zA-Z][a-zA-Z0-9_-]{0,35}(?:\/|$)/.exec(path)?.[0] || "/";
    section = section === "/" ? "/" : "/" + section.split("/")[1];
    if (/^\/(?:auth|login|identity|oauth|token|session|account|user|admin|private|secret|password|vault|api)$/i.test(section)) section = "/[restricted]";
    w.sections.set(section, (w.sections.get(section) || 0) + 1);
  }
  const configured = new Set(await configuredPiHosts());
  for (const host of configured) {
    if (!websites.has(host)) {
      websites.set(host, {host,requests:0,pages:0,writes:0,failures:0,
        latest:null,sections:new Map(),signatureTypes:new Set(),automationSignals:0});
    }
  }
  const value = {
    requests, window: "recent Pi proxy access log (up to 2 MiB)",
    websites: [...websites.values()].map(w => ({
      host: w.host, configured: configured.has(w.host),
      requests: w.requests, pages: w.pages, writes: w.writes,
      failures: w.failures, latest: w.latest,
      clientSignatures: w.signatureTypes.size, automationSignals: w.automationSignals,
      sections: [...w.sections].sort((a,b)=>b[1]-a[1]).slice(0, 6)
        .map(([section, count]) => ({section, count}))
    })).sort((a,b) => b.requests - a.requests).slice(0, 100)
  };
  trafficCache = { key, value, readAt: Date.now() };
  return value;
}

// The VPS sends only aggregates and explicitly-consented browser events.
// No raw VPS proxy log, IP address or unconsented session identifier is copied.
async function readVpsActivity() {
  let data;
  try {
    const stat = await fs.promises.stat(VPS_EXPORT_FILE);
    if (stat.size > 1_500_000) return null;
    data = JSON.parse(await fs.promises.readFile(VPS_EXPORT_FILE, "utf8"));
  } catch (err) {
    if (err.code === "ENOENT") return null;
    throw err;
  }
  const generated = Date.parse(data.generatedAt || "");
  if (data.schema !== 1 || !Number.isFinite(generated) || Date.now() - generated > 10 * 60 * 1000) return null;
  return {
    generatedAt: data.generatedAt,
    requests: Number(data.requests) || 0,
    websites: Array.isArray(data.websites) ? data.websites.slice(0, 100) : [],
    anonymousBrowserEvents: (Array.isArray(data.anonymousBrowserEvents) ? data.anonymousBrowserEvents : [])
      .filter(e => e && e.source === "VPS" && HOST.test(String(e.host || "")) &&
        ["page_view","route_change","scroll","engagement","action"].includes(e.type) &&
        Number.isFinite(Date.parse(e.time)))
      .slice(-240).map((e, index) => ({
        id: "vps-event-" + index, source: "VPS",
        host: safeString(e.host, 253), type: e.type,
        time: e.time, section: safeString(e.section, 56),
        visibleSeconds: Math.max(0, Math.min(3600, Number(e.visibleSeconds) || 0)),
        scrollDepth: Math.max(0, Math.min(100, Number(e.scrollDepth) || 0))
      })).reverse(),
    consentedEvents: (Array.isArray(data.consentedEvents) ? data.consentedEvents : [])
      .filter((e) => e && e.consent === true && safeId(e.deviceKey) && Number.isFinite(Date.parse(e.timestamp))),
    browserEvents: Number(data.browserEvents) || 0,
    window: String(data.window || "VPS 24h")
  };
}

function mergeTraffic(local, remote, piEvents) {
  const localSites = (local.websites || []).map(site => ({
    ...site, source: "Pi", browserViews: 0, browserActions: 0,
    browserScroll: 0, browserEngagementSeconds: 0, browserLastSeen: null
  }));
  const piByHost = new Map(localSites.map(s => [s.host, s]));
  for (const event of piEvents) {
    let site = piByHost.get(event.host);
    if (!site) {
      site = { host: event.host, requests: 0, pages: 0, writes: 0, failures: 0,
        latest: null, sections: [], source: "Pi", clientSignatures: 0, automationSignals: 0, browserViews: 0,
        browserActions: 0, browserScroll: 0, browserEngagementSeconds: 0, browserLastSeen: null };
      localSites.push(site);
      piByHost.set(event.host, site);
    }
    if (["page_view", "route_change"].includes(event.type)) site.browserViews++;
    if (event.type === "action") site.browserActions++;
    if (event.type === "scroll") site.browserScroll++;
    if (event.type === "engagement") site.browserEngagementSeconds += Number(event.visibleSeconds) || 0;
    if (!site.browserLastSeen || Date.parse(event.timestamp) > Date.parse(site.browserLastSeen)) {
      site.browserLastSeen = event.timestamp;
    }
  }
  const remoteSites = (remote?.websites || []).filter(site => site.source === "VPS" &&
    HOST.test(String(site.host || "")) &&
    typeof site.requests === "number").map(site => ({
      host: site.host, source: "VPS", configured: Boolean(site.configured),
      requests: site.requests, pages: site.pages || 0,
      writes: site.writes || 0, failures: site.failures || 0, latest: site.latest || null,
      clientSignatures: Math.max(0, Number(site.clientSignatures) || 0),
      automationSignals: Math.max(0, Number(site.automationSignals) || 0),
      sections: site.sections || [], browserViews: site.browserViews || 0,
      browserActions: site.browserActions || 0, browserScroll: site.browserScroll || 0,
      browserEngagementSeconds: site.browserEngagementSeconds || 0,
      browserLastSeen: site.browserLastSeen || null
    }));
  const websites = [...localSites, ...remoteSites].sort((a,b) =>
    (b.browserViews - a.browserViews) || (b.requests - a.requests));
  return {
    requests: local.requests + (remote?.requests || 0),
    browserViews: websites.reduce((sum, s) => sum + s.browserViews, 0),
    browserEvents: (remote?.browserEvents || 0) + piEvents.length,
    window: "Pi recent log tail; VPS last 24 hours",
    remoteGeneratedAt: remote?.generatedAt || null,
    anonymousBrowserEvents: remote?.anonymousBrowserEvents || [],
    websites: websites.slice(0, 200),
  };
}

async function readLabels() {
  try {
    const data = JSON.parse(await fs.promises.readFile(LABEL_FILE, "utf8"));
    return data && typeof data === "object" && !Array.isArray(data) ? data : {};
  } catch (err) {
    if (err.code === "ENOENT") return {};
    throw err;
  }
}

// Display only browser-executed, consented telemetry. HTTP-only clients,
// crawlers and backend requests cannot appear as individuals in this list.
function buildProfiles(events, labels) {
  const grouped = new Map();
  for (const event of events) {
    const id = event.deviceKey;
    if (!grouped.has(id)) grouped.set(id, {
      id, name: safeString(labels[id]?.name), notes: safeString(labels[id]?.notes, 500),
      firstSeen: event.timestamp, lastSeen: event.timestamp, count: 0, pageViews: 0,
      actions: 0, engagementSeconds: 0, lastVisibleAt: null, lastInteractiveAt: null,
      lastPage: null, lastHost: null, sessions: new Map(), sites: new Map(),
      browsers: new Set(), platforms: new Set(), languages: new Set(),
      timezones: new Set(), viewports: new Set()
    });
    const p = grouped.get(id);
    p.count++;
    if (event.type === "page_view" || event.type === "route_change") p.pageViews++;
    if (event.type === "action") p.actions++;
    if (event.type === "engagement") p.engagementSeconds += Math.max(0, Number(event.visibleSeconds) || 0);
    if (event.sessionKey) {
      const key = event.sessionKey;
      if (!p.sessions.has(key)) p.sessions.set(key, {
        id: key, host: event.host, firstSeen: event.timestamp,
        lastSeen: event.timestamp, pageViews: 0, actions: 0, visibleSeconds: 0
      });
      const session = p.sessions.get(key);
      if (Date.parse(event.timestamp) > Date.parse(session.lastSeen)) session.lastSeen = event.timestamp;
      if (Date.parse(event.timestamp) < Date.parse(session.firstSeen)) session.firstSeen = event.timestamp;
      if (event.type === "page_view" || event.type === "route_change") session.pageViews++;
      if (event.type === "action") session.actions++;
      if (event.type === "engagement") session.visibleSeconds += Math.max(0, Number(event.visibleSeconds) || 0);
    }
    if (event.host) p.sites.set(event.host, (p.sites.get(event.host) || 0) + 1);
    if (event.browser) p.browsers.add(safeString(event.browser, 30));
    if (event.platform) p.platforms.add(safeString(event.platform, 40));
    if (event.language) p.languages.add(safeString(event.language, 32));
    if (event.timezone) p.timezones.add(safeString(event.timezone, 80));
    if (event.viewport) p.viewports.add(safeString(event.viewport, 32));
    if (event.type === "engagement" && Number(event.visibleSeconds) > 0 &&
        (!p.lastVisibleAt || Date.parse(event.timestamp) >= Date.parse(p.lastVisibleAt))) {
      p.lastVisibleAt = event.timestamp;
    }
    if (["action", "scroll"].includes(event.type) &&
        (!p.lastInteractiveAt || Date.parse(event.timestamp) >= Date.parse(p.lastInteractiveAt))) {
      p.lastInteractiveAt = event.timestamp;
    }
    if (["page_view", "route_change"].includes(event.type) &&
        (!p.lastPage || Date.parse(event.timestamp) >= Date.parse(p.lastPage.at))) {
      p.lastPage = { host: event.host, path: safeString(event.path, 512), at: event.timestamp };
    }
    if (Date.parse(event.timestamp) > Date.parse(p.lastSeen)) p.lastSeen = event.timestamp;
    if (Date.parse(event.timestamp) < Date.parse(p.firstSeen)) p.firstSeen = event.timestamp;
    if (!p.lastHost || Date.parse(event.timestamp) >= Date.parse(p.lastHost.at)) {
      p.lastHost = { host: event.host, at: event.timestamp };
    }
  }
  const now = Date.now();
  return [...grouped.values()].map((p) => ({
    id: p.id, name: p.name, notes: p.notes, firstSeen: p.firstSeen, lastSeen: p.lastSeen,
    count: p.count, pageViews: p.pageViews, actions: p.actions,
    engagementSeconds: Math.round(p.engagementSeconds),
    lastVisibleAt: p.lastVisibleAt, lastInteractiveAt: p.lastInteractiveAt,
    active: Boolean(p.lastVisibleAt && now - Date.parse(p.lastVisibleAt) < 120000),
    interactive: p.actions > 0 || Boolean(p.lastInteractiveAt),
    lastPage: p.lastPage, lastHost: p.lastHost?.host || null,
    sessions: p.sessions.size,
    sessionDetails: [...p.sessions.values()].sort((a, b) => Date.parse(b.lastSeen) - Date.parse(a.lastSeen)).slice(0, 40),
    sites: [...p.sites].map(([host, count]) => ({host, count})).sort((a,b) => b.count-a.count),
    browsers: [...p.browsers].slice(0, 5),
    platforms: [...p.platforms].slice(0, 5),
    languages: [...p.languages].slice(0, 5),
    timezones: [...p.timezones].slice(0, 5),
    viewports: [...p.viewports].slice(0, 5)
  })).sort((a,b) => Date.parse(b.lastSeen) - Date.parse(a.lastSeen));
}

async function list() {
  const [piEvents, labels, localTraffic, remote] = await Promise.all([
    readEvents(), readLabels(), readTraffic(), readVpsActivity()
  ]);
  const events = [...piEvents, ...(remote?.consentedEvents || [])];
  const automaticActivity = mergeTraffic(localTraffic, remote, piEvents);
  automaticActivity.smart = analyzeAutomaticActivity(automaticActivity);
  return { automaticActivity, visitors: buildProfiles(events, labels).slice(0, 200), totalEvents: events.length,
    note: "Only opted-in HYROVI visitors. Browser hints are not used to identify people. Recent log window only." };
}

async function detail(id) {
  const visitorId = safeId(id);
  if (!visitorId) return null;
  const [piEvents, labels, remote] = await Promise.all([readEvents(), readLabels(), readVpsActivity()]);
  const selected = [...piEvents, ...(remote?.consentedEvents || [])].filter((e) => e.deviceKey === visitorId);
  if (!selected.length) return null;
  const visitor = buildProfiles(selected, labels)[0];
  return { visitor, timeline: selected.slice(-300).reverse().map((e) => ({
    id: e.id, timestamp: e.timestamp, host: safeString(e.host, 253),
    type: safeString(e.type, 32), path: safeString(e.path, 1024),
    action: safeString(e.action, 64), referrerHost: safeString(e.referrerHost, 253),
    scrollDepth: Number(e.scrollDepth) || 0, visibleSeconds: Number(e.visibleSeconds) || 0,
    language: safeString(e.language, 32), viewport: safeString(e.viewport, 32)
  })) };
}

function update(id, values) {
  const visitorId = safeId(id);
  if (!visitorId || !values || typeof values !== "object") throw new Error("invalid_visitor");
  const name = safeString(values.name, 120), notes = safeString(values.notes, 500);
  const op = queue.then(async () => {
    const [events, remote] = await Promise.all([readEvents(), readVpsActivity()]);
    if (![...events, ...(remote?.consentedEvents || [])].some((e) => e.deviceKey === visitorId)) return null;
    const labels = await readLabels();
    if (name || notes) labels[visitorId] = { name, notes };
    else delete labels[visitorId];
    await fs.promises.mkdir(path.dirname(LABEL_FILE), {recursive: true});
    const temporary = LABEL_FILE + "." + process.pid + ".tmp";
    await fs.promises.writeFile(temporary, JSON.stringify(labels), {mode: 0o600});
    await fs.promises.rename(temporary, LABEL_FILE);
    return { id: visitorId, name, notes };
  });
  queue = op.catch(() => undefined);
  return op;
}

// Isolated first-party tests.hyrovi.com lab — only user-started sessions.
const TEST_SNAPSHOT = "/data/vps-hpm-sync/tests-studio.json";
const TEST_ID = /^[a-f0-9]{64}$/;
const TEST_KIND = new Set(["page","button","scroll","heartbeat","section","visible"]);
const TEST_DETAIL = new Set(["home","features","activity","about","tap","toggle","counter","reset",
  "scroll25","scroll50","scroll75","scroll100","focus","hidden","visible","open"]);
async function readTestStudio() {
  let snapshot;
  try {
    const stat = await fs.promises.stat(TEST_SNAPSHOT);
    if (stat.size > 750_000) return {generatedAt:null, online:false, sessions:[]};
    snapshot = JSON.parse(await fs.promises.readFile(TEST_SNAPSHOT,"utf8"));
  } catch (e) {
    if (e.code === "ENOENT") return {generatedAt:null, online:false, sessions:[]};
    throw e;
  }
  const created = Date.parse(snapshot.generatedAt || "");
  if (snapshot.schema !== 1 || snapshot.scope !== "tests.hyrovi.com" ||
      !Number.isFinite(created) || Date.now()-created > 30_000 ||
      created > Date.now()+60_000) {
    return {generatedAt:null, online:false, sessions:[]};
  }
  return {generatedAt:snapshot.generatedAt, online:true,
    sessions:(Array.isArray(snapshot.sessions) ? snapshot.sessions : []).slice(0,100)
      .filter(s => s && TEST_ID.test(String(s.id || "")) && Number.isFinite(Date.parse(s.last)))
      .map(s => ({
        id:s.id, name:safeString(s.name,32),
        browser:safeString(s.browser,32), platform:safeString(s.platform,32),
        language:safeString(s.language,32),
        signature:/^[a-f0-9]{20}$/.test(String(s.signature||"")) ? s.signature : "",
        diagnostics:Object.fromEntries(Object.entries(s.diagnostics && typeof s.diagnostics === "object" &&
          !Array.isArray(s.diagnostics) ? s.diagnostics : {}).filter(([k,v]) =>
          ["timezone","screen","viewport","touch","cpu","memory","theme","motion","pixelRatio"].includes(k) &&
          typeof v==="string" && v.length<=70)),
        started:s.started, last:s.last,
        active:Boolean(s.active) && Date.now()-Date.parse(s.last)<40_000,
        buttonActions:Math.max(0,Number(s.buttonActions)||0),
        pageViews:Math.max(0,Number(s.pageViews)||0),
        sectionChanges:Math.max(0,Number(s.sectionChanges)||0),
        scrollActions:Math.max(0,Number(s.scrollActions)||0),
        heartbeats:Math.max(0,Number(s.heartbeats)||0),
        eventsCount:Math.max(0,Number(s.eventsCount)||0),
        activityScore:Math.max(0,Number(s.activityScore)||0),
        durationSeconds:Math.max(0,Number(s.durationSeconds)||0),
        events:(Array.isArray(s.events) ? s.events:[]).slice(-250)
         .filter(e=>e && TEST_KIND.has(e.kind) && TEST_DETAIL.has(e.detail) && Number.isFinite(Date.parse(e.at)))
         .map(e=>({at:e.at,kind:e.kind,detail:e.detail}))
      }))
  };
}
// Group only the scoped test-lab sessions sharing the exact same signature.
// Matching header combinations are NOT definitive evidence of same person/device.
function groupTestBrowsers(sessions) {
  const groups = new Map();
  for (const s of sessions) {
    const signature = /^[a-f0-9]{20}$/.test(s.signature) ? s.signature : "";
    // Never join sessions with missing/invalid diagnostics.
    const id = signature || s.id;
    let g = groups.get(id);
    if (!g) {
      g = { id, signature, name: s.name, browser: s.browser,
        platform: s.platform, language: s.language,
        active: false, firstSeen:s.started, last:s.last,
        buttonActions:0, pageViews:0, sectionChanges:0,
        scrollActions:0, heartbeats:0, eventsCount:0, activityScore:0,
        sessionsCount:0, aliases:[], sessionIds:[], diagnostics:s.diagnostics || {} };
      groups.set(id,g);
    }
    g.sessionsCount++;
    g.sessionIds.push(s.id);
    if (s.name && !g.aliases.includes(s.name)) g.aliases.push(s.name);
    if (Date.parse(s.last) > Date.parse(g.last)) {
      g.last = s.last;
      g.name = s.name;
      g.browser = s.browser;
      g.platform = s.platform;
      g.language = s.language;
      g.diagnostics = s.diagnostics || {};
    }
    if (Date.parse(s.started) < Date.parse(g.firstSeen)) g.firstSeen=s.started;
    g.active = g.active || s.active;
    for (const k of ["buttonActions","pageViews","sectionChanges","scrollActions",
                     "heartbeats","eventsCount","activityScore"]) g[k] += s[k];
  }
  return [...groups.values()].sort((a,b)=>
    b.activityScore-a.activityScore || Date.parse(b.last)-Date.parse(a.last));
}

async function testStudioList() {
  const snapshot = await readTestStudio();
  return {online:snapshot.online,generatedAt:snapshot.generatedAt,
    scope:"tests.hyrovi.com",
    sessions:snapshot.sessions.map(({events,...summary})=>summary),
    browsers:groupTestBrowsers(snapshot.sessions),
    total:snapshot.sessions.length,
    active:snapshot.sessions.filter(s=>s.active).length};
}
async function testStudioDetail(id) {
  if (!TEST_ID.test(String(id || ""))) return null;
  const snapshot = await readTestStudio();
  const selected = snapshot.sessions.find(s=>s.id===id);
  return selected ? {session:selected,generatedAt:snapshot.generatedAt} : null;
}

async function testStudioBrowserDetail(id) {
  const candidate = String(id || "");
  if (!/^(?:[a-f0-9]{20}|[a-f0-9]{64})$/.test(candidate)) return null;
  const snap = await readTestStudio();
  const browser = groupTestBrowsers(snap.sessions).find(b=>b.id===candidate);
  if (!browser) return null;
  const sessions = snap.sessions.filter(s=>browser.sessionIds.includes(s.id))
    .sort((a,b)=>Date.parse(b.last)-Date.parse(a.last));
  const timeline = sessions.flatMap(s=>s.events.map(e=>({
    at:e.at,kind:e.kind,detail:e.detail,sessionId:s.id,name:s.name
  }))).sort((a,b)=>Date.parse(b.at)-Date.parse(a.at)).slice(0,250);
  return {browser, sessions:sessions.map(({events,...summary})=>summary),
    timeline, generatedAt:snap.generatedAt,
    timelineTruncated:browser.eventsCount>timeline.length};
}

export default { list, detail, update, testStudioList, testStudioDetail, testStudioBrowserDetail };
