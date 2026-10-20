import fs from "node:fs";
import path from "node:path";

const EVENT_FILE = "/data/logs/hyrovi-analytics-events.log";
const LABEL_FILE = "/data/nginx/hyrovi-security/visitor-labels.json";
const READ_LIMIT = 4 * 1024 * 1024;
const ID = /^[a-f0-9]{64}$/;
let cached = { key: "", events: [], readAt: 0 };
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

async function readLabels() {
  try {
    const data = JSON.parse(await fs.promises.readFile(LABEL_FILE, "utf8"));
    return data && typeof data === "object" && !Array.isArray(data) ? data : {};
  } catch (err) {
    if (err.code === "ENOENT") return {};
    throw err;
  }
}

function buildProfiles(events, labels) {
  const grouped = new Map();
  for (const event of events) {
    const id = event.deviceKey;
    if (!grouped.has(id)) grouped.set(id, {
      id, name: safeString(labels[id]?.name), notes: safeString(labels[id]?.notes, 500),
      firstSeen: event.timestamp, lastSeen: event.timestamp, count: 0, pageViews: 0,
      actions: 0, sessions: new Set(), sites: new Map(), browsers: new Set(),
      platforms: new Set(), languages: new Set(), timezones: new Set(), viewports: new Set()
    });
    const p = grouped.get(id);
    p.count++;
    if (event.type === "page_view") p.pageViews++;
    if (event.type === "action") p.actions++;
    if (event.sessionKey) p.sessions.add(event.sessionKey);
    if (event.host) p.sites.set(event.host, (p.sites.get(event.host) || 0) + 1);
    if (event.browser) p.browsers.add(safeString(event.browser, 30));
    if (event.platform) p.platforms.add(safeString(event.platform, 40));
    if (event.language) p.languages.add(safeString(event.language, 32));
    if (event.timezone) p.timezones.add(safeString(event.timezone, 80));
    if (event.viewport) p.viewports.add(safeString(event.viewport, 32));
    if (Date.parse(event.timestamp) > Date.parse(p.lastSeen)) p.lastSeen = event.timestamp;
    if (Date.parse(event.timestamp) < Date.parse(p.firstSeen)) p.firstSeen = event.timestamp;
  }
  return [...grouped.values()].map((p) => ({
    id: p.id, name: p.name, notes: p.notes, firstSeen: p.firstSeen, lastSeen: p.lastSeen,
    count: p.count, pageViews: p.pageViews, actions: p.actions,
    sessions: p.sessions.size,
    sites: [...p.sites].map(([host, count]) => ({host, count})).sort((a,b) => b.count-a.count),
    browsers: [...p.browsers].slice(0, 5),
    platforms: [...p.platforms].slice(0, 5),
    languages: [...p.languages].slice(0, 5),
    timezones: [...p.timezones].slice(0, 5),
    viewports: [...p.viewports].slice(0, 5)
  })).sort((a,b) => Date.parse(b.lastSeen) - Date.parse(a.lastSeen));
}

async function list() {
  const [events, labels] = await Promise.all([readEvents(), readLabels()]);
  return { visitors: buildProfiles(events, labels).slice(0, 200), totalEvents: events.length,
    note: "Only opted-in HYROVI visitors. Browser hints are not used to identify people. Recent log window only." };
}

async function detail(id) {
  const visitorId = safeId(id);
  if (!visitorId) return null;
  const [events, labels] = await Promise.all([readEvents(), readLabels()]);
  const selected = events.filter((e) => e.deviceKey === visitorId);
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
    const events = await readEvents();
    if (!events.some((e) => e.deviceKey === visitorId)) return null;
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

export default { list, detail, update };
