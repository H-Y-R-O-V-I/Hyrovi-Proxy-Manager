import fs from "node:fs";
import net from "node:net";
import { createHmac, randomBytes, randomUUID } from "node:crypto";
import errs from "../lib/error.js";

const SECURITY_DIR = "/data/nginx/hyrovi-security";
const SECRET_FILE = `${SECURITY_DIR}/analytics-secret`;
const EVENT_FILE = "/data/logs/hyrovi-analytics-events.log";
const MAX_EVENT_FILE_BYTES = 8 * 1024 * 1024;
const MAX_READ_BYTES = 4 * 1024 * 1024;
const INTERNAL_HEADER = "analytics-v1";
const ALLOWED_TYPES = new Set(["page_view", "engagement", "scroll", "route_change"]);
const ID_RE = /^[A-Za-z0-9._:-]{1,96}$/;

let secret = null;
let writeQueue = Promise.resolve();

const bounded = (value, max = 240) => String(value || "").trim().slice(0, max);
const safePath = (value) => {
	const path = bounded(value || "/", 1024).split("?")[0].split("#")[0];
	return path.startsWith("/") && !path.startsWith("//") ? path : "/";
};
const safeId = (value) => {
	const text = bounded(value, 96);
	return ID_RE.test(text) ? text : null;
};

const writeSecret = async () => {
	await fs.promises.mkdir(SECURITY_DIR, { recursive: true });
	const created = randomBytes(32).toString("hex");
	try {
		await fs.promises.writeFile(SECRET_FILE, `${created}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
		return created;
	} catch (err) {
		if (err.code !== "EEXIST") throw err;
		return (await fs.promises.readFile(SECRET_FILE, "utf8")).trim();
	}
};

const prepare = async () => {
	await fs.promises.mkdir("/data/logs", { recursive: true });
	try {
		secret = (await fs.promises.readFile(SECRET_FILE, "utf8")).trim();
	} catch (err) {
		if (err.code !== "ENOENT") throw err;
		secret = await writeSecret();
	}
	if (!secret || secret.length < 32) throw new errs.ConfigurationError("HYROVI analytics secret is invalid");
	return { ready: true };
};

const hmac = (...parts) => {
	if (!secret) return null;
	return createHmac("sha256", secret).update(parts.map((part) => String(part || "")).join("\u0000")).digest("hex");
};

const fingerprintFromHeaders = (headers = {}) =>
	hmac(
		"client-v1",
		bounded(headers["user-agent"], 512).toLowerCase(),
		bounded(headers["accept-language"], 160).toLowerCase(),
		bounded(headers["sec-ch-ua"], 240).toLowerCase(),
		bounded(headers["sec-ch-ua-mobile"], 32).toLowerCase(),
		bounded(headers["sec-ch-ua-platform"], 80).toLowerCase(),
	);

const proxyContext = (headers = {}) => {
	if (headers["x-hyrovi-analytics-internal"] !== INTERNAL_HEADER) throw new errs.ItemNotFoundError();
	const ip = bounded(headers["x-hyrovi-analytics-source-ip"], 80);
	if (!net.isIP(ip)) throw new errs.ItemNotFoundError();
	const host = bounded(headers["x-hyrovi-analytics-host"], 253).toLowerCase();
	if (!host || !/^[a-z0-9.-]+$/.test(host)) throw new errs.ItemNotFoundError();
	return { ip, host };
};

const appendEvent = (event) => {
	const operation = writeQueue.then(async () => {
		try {
			const stat = await fs.promises.stat(EVENT_FILE);
			if (stat.size > MAX_EVENT_FILE_BYTES) {
				const handle = await fs.promises.open(EVENT_FILE, "r");
				const keep = Math.floor(MAX_EVENT_FILE_BYTES / 2);
				const start = Math.max(0, stat.size - keep);
				const buffer = Buffer.alloc(stat.size - start);
				await handle.read(buffer, 0, buffer.length, start);
				await handle.close();
				let text = buffer.toString("utf8");
				if (start > 0) {
					const newline = text.indexOf("\n");
					text = newline >= 0 ? text.slice(newline + 1) : "";
				}
				await fs.promises.writeFile(EVENT_FILE, text, "utf8");
			}
		} catch (err) {
			if (err.code !== "ENOENT") throw err;
		}
		await fs.promises.appendFile(EVENT_FILE, `${JSON.stringify(event)}\n`, "utf8");
	});
	writeQueue = operation.catch(() => undefined);
	return operation;
};

const normalizeBody = (body = {}) => {
	const type = bounded(body.type, 40);
	if (!ALLOWED_TYPES.has(type)) throw new errs.ValidationError("Unsupported analytics event type");
	const deviceId = safeId(body.deviceId);
	const sessionId = safeId(body.sessionId);
	const consent = body.consent === true;
	const visibleSeconds = Math.max(0, Math.min(3600, Number.parseInt(body.visibleSeconds, 10) || 0));
	const scrollDepth = Math.max(0, Math.min(100, Number.parseInt(body.scrollDepth, 10) || 0));
	return {
		type,
		path: safePath(body.path),
		referrerHost: bounded(body.referrerHost, 253).toLowerCase(),
		deviceId: consent ? deviceId : null,
		sessionId,
		consent,
		visibleSeconds,
		scrollDepth,
		language: bounded(body.language, 32),
		timezone: bounded(body.timezone, 80),
		viewport: bounded(body.viewport, 32),
	};
};

const collect = async ({ headers, body }) => {
	if (!secret) await prepare();
	const context = proxyContext(headers);
	const payload = normalizeBody(body);
	const fingerprint = fingerprintFromHeaders(headers);
	const now = new Date();
	const event = {
		id: randomUUID(),
		timestamp: now.toISOString(),
		host: context.host,
		type: payload.type,
		path: payload.path,
		referrerHost: payload.referrerHost || null,
		sessionKey: payload.sessionId ? hmac("session-v1", context.host, payload.sessionId) : null,
		deviceKey: payload.deviceId ? hmac("device-v1", payload.deviceId) : null,
		clientFingerprint: fingerprint,
		ipHash: hmac("ip-day-v1", now.toISOString().slice(0, 10), context.ip),
		consent: payload.consent,
		visibleSeconds: payload.visibleSeconds,
		scrollDepth: payload.scrollDepth,
		language: payload.language || null,
		timezone: payload.timezone || null,
		viewport: payload.viewport || null,
	};
	await appendEvent(event);
	return { accepted: true, id: event.id, timestamp: event.timestamp };
};

const readTail = async () => {
	let handle;
	try {
		handle = await fs.promises.open(EVENT_FILE, "r");
		const stat = await handle.stat();
		const size = Math.min(stat.size, MAX_READ_BYTES);
		if (!size) return "";
		const buffer = Buffer.alloc(size);
		await handle.read(buffer, 0, size, stat.size - size);
		let text = buffer.toString("utf8");
		if (stat.size > size) {
			const newline = text.indexOf("\n");
			text = newline >= 0 ? text.slice(newline + 1) : "";
		}
		return text;
	} catch (err) {
		if (err.code === "ENOENT") return "";
		throw err;
	} finally {
		if (handle) await handle.close();
	}
};

const getSummary = async ({ host = "", sinceMinutes = 60 } = {}) => {
	const since = Date.now() - Math.max(1, Math.min(43_200, Number.parseInt(sinceMinutes, 10) || 60)) * 60_000;
	const hostFilter = bounded(host, 253).toLowerCase();
	const text = await readTail();
	const events = text
		.split("\n")
		.filter(Boolean)
		.map((line) => {
			try {
				return JSON.parse(line);
			} catch {
				return null;
			}
		})
		.filter((event) => event && Date.parse(event.timestamp) >= since && (!hostFilter || event.host === hostFilter));
	const devices = new Set(events.map((event) => event.deviceKey).filter(Boolean));
	const fingerprints = new Set(events.map((event) => event.clientFingerprint).filter(Boolean));
	const sessions = new Set(events.map((event) => event.sessionKey).filter(Boolean));
	const pageViews = events.filter((event) => event.type === "page_view").length;
	const engagementSeconds = events
		.filter((event) => event.type === "engagement")
		.reduce((sum, event) => sum + Math.max(0, Number(event.visibleSeconds) || 0), 0);
	const scroll = { 25: 0, 50: 0, 75: 0, 100: 0 };
	for (const event of events.filter((entry) => entry.type === "scroll")) {
		for (const mark of [25, 50, 75, 100]) if ((Number(event.scrollDepth) || 0) >= mark) scroll[mark] += 1;
	}
	return {
		events: events.length,
		pageViews,
		consentedDevices: devices.size,
		clientFingerprints: fingerprints.size,
		sessions: sessions.size,
		engagementSeconds,
		routeChanges: events.filter((event) => event.type === "route_change").length,
		scroll,
	};
};

const script = () => `(()=>{"use strict";const E="/.well-known/hyrovi-analytics/collect",D="__hyrovi_vid",C="hyrovi_analytics_consent",S="hyrovi_sid";const uuid=()=>crypto.randomUUID?crypto.randomUUID():Array.from(crypto.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,"0")).join("");const getCookie=n=>document.cookie.split(";").map(v=>v.trim()).find(v=>v.startsWith(n+"="))?.slice(n.length+1)||"";const consent=()=>getCookie(C)==="1";const sid=(()=>{let v=sessionStorage.getItem(S);if(!v){v=uuid();sessionStorage.setItem(S,v)}return v})();const device=()=>{if(!consent())return null;let v=localStorage.getItem(D)||getCookie(D);if(!v){v=uuid();localStorage.setItem(D,v)}document.cookie=D+"="+encodeURIComponent(v)+"; Max-Age=31536000; Path=/; SameSite=Lax; Secure";return v};const bucket=n=>Math.max(200,Math.round(Number(n||0)/200)*200);const base=()=>({path:location.pathname||"/",referrerHost:(()=>{try{return document.referrer?new URL(document.referrer).hostname:""}catch{return""}})(),deviceId:device(),sessionId:sid,consent:consent(),language:(navigator.language||"").slice(0,32),timezone:(Intl.DateTimeFormat().resolvedOptions().timeZone||"").slice(0,80),viewport:bucket(innerWidth)+"x"+bucket(innerHeight)});const send=(type,extra={})=>{if(navigator.doNotTrack==="1")return;const body=JSON.stringify(Object.assign(base(),{type},extra));try{if(navigator.sendBeacon){navigator.sendBeacon(E,new Blob([body],{type:"application/json"}));return}}catch{}fetch(E,{method:"POST",headers:{"Content-Type":"application/json"},body,keepalive:true,credentials:"same-origin"}).catch(()=>{})};let visible=0,last=Date.now(),marks=new Set;const tick=()=>{const now=Date.now();if(document.visibilityState==="visible")visible+=Math.max(0,Math.min(30,Math.round((now-last)/1000)));last=now};setInterval(()=>{tick();if(visible>0){send("engagement",{visibleSeconds:visible});visible=0}},30000);document.addEventListener("visibilitychange",tick,{passive:true});addEventListener("pagehide",()=>{tick();if(visible>0)send("engagement",{visibleSeconds:visible})},{passive:true});const scroll=()=>{const max=Math.max(1,document.documentElement.scrollHeight-innerHeight),d=Math.min(100,Math.round(scrollY/max*100));for(const m of [25,50,75,100])if(d>=m&&!marks.has(m)){marks.add(m);send("scroll",{scrollDepth:m})}};addEventListener("scroll",scroll,{passive:true});const route=()=>{marks=new Set;send("route_change")};for(const k of ["pushState","replaceState"]){const f=history[k];history[k]=function(){const r=f.apply(this,arguments);queueMicrotask(route);return r}}addEventListener("popstate",route);window.hyroviAnalytics={grantConsent(){document.cookie=C+"=1; Max-Age=31536000; Path=/; SameSite=Lax; Secure";device();send("page_view")},revokeConsent(){document.cookie=C+"=; Max-Age=0; Path=/; SameSite=Lax; Secure";document.cookie=D+"=; Max-Age=0; Path=/; SameSite=Lax; Secure";localStorage.removeItem(D)},track(){send("page_view")}};send("page_view")})();`;

export default {
	prepare,
	collect,
	getSummary,
	proxyContext,
	script,
	fingerprintFromHeaders,
};
