import fs from "node:fs";
import { createHash, randomUUID } from "node:crypto";
import errs from "../lib/error.js";

const TELEMETRY_DIR = "/data/nginx/hyrovi-control-plane/telemetry";
const MAX_BATCH_EVENTS = 500;
const MAX_SECURITY_FILE_BYTES = 32 * 1024 * 1024;
const MAX_ANALYTICS_FILE_BYTES = 24 * 1024 * 1024;
const COMPACT_TO_BYTES = 12 * 1024 * 1024;
const MAX_READ_BYTES_PER_NODE = 8 * 1024 * 1024;
const MAX_READ_EVENTS = 20_000;

let mutationQueue = Promise.resolve();

const withMutation = (operation) => {
	const run = mutationQueue.then(operation, operation);
	mutationQueue = run.catch(() => undefined);
	return run;
};

const normalizeNodeId = (value) => {
	const id = String(value || "").trim();
	if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,119}$/.test(id) || id === "local") {
		throw new errs.ValidationError("Invalid remote node ID");
	}
	return id;
};

const boundedString = (value, maxLength) => {
	if (typeof value === "undefined" || value === null) return "";
	return String(value).trim().slice(0, maxLength);
};

const safeTimestamp = (value) => {
	const text = boundedString(value, 80);
	return Number.isFinite(Date.parse(text)) ? new Date(text).toISOString() : null;
};

const safeHost = (value) => {
	const host = boundedString(value, 253).toLowerCase();
	return /^[a-z0-9.-]+$/.test(host) ? host : "";
};

const safePath = (value) => {
	const text = boundedString(value || "/", 2048).split("?")[0].split("#")[0];
	return text.startsWith("/") && !text.startsWith("//") ? text : "/";
};

const safeReferrer = (value) => {
	const text = boundedString(value, 1024);
	if (!text || text === "-") return "";
	try {
		const parsed = new URL(text);
		return `${parsed.protocol}//${parsed.host}${parsed.pathname}`.slice(0, 1024);
	} catch {
		return text.split("?")[0].split("#")[0].slice(0, 1024);
	}
};

const safeInt = (value, min = 0, max = Number.MAX_SAFE_INTEGER) => {
	const parsed = Number.parseInt(value, 10);
	if (!Number.isFinite(parsed)) return 0;
	return Math.max(min, Math.min(max, parsed));
};

const safeFloat = (value, min = 0, max = Number.MAX_SAFE_INTEGER) => {
	const parsed = Number.parseFloat(value);
	if (!Number.isFinite(parsed)) return 0;
	return Math.max(min, Math.min(max, parsed));
};

const hashOpaqueId = (nodeId, value) => {
	const text = boundedString(value, 256);
	if (!text) return "";
	return createHash("sha256").update(`${nodeId}\u0000${text}`, "utf8").digest("hex");
};

const normalizeSecurityEvent = (nodeId, raw) => {
	if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
	const ts = safeTimestamp(raw.ts || raw.timestamp);
	const host = safeHost(raw.host);
	const ip = boundedString(raw.remote_addr || raw.ip, 80);
	if (!ts || !host || !ip) return null;
	return {
		node_id: nodeId,
		received_at: new Date().toISOString(),
		ts,
		request_id: boundedString(raw.request_id || raw.requestId || randomUUID(), 128),
		host,
		method: boundedString(raw.method, 16).toUpperCase(),
		path: safePath(raw.path),
		status: safeInt(raw.status, 0, 999),
		remote_addr: ip,
		user_agent: boundedString(raw.user_agent || raw.userAgent, 512),
		referer: safeReferrer(raw.referer || raw.referrer),
		accept: boundedString(raw.accept, 512),
		accept_language: boundedString(raw.accept_language || raw.acceptLanguage, 160),
		sec_ch_ua: boundedString(raw.sec_ch_ua || raw.secChUa, 240),
		sec_ch_ua_mobile: boundedString(raw.sec_ch_ua_mobile || raw.secChUaMobile, 32),
		sec_ch_ua_platform: boundedString(raw.sec_ch_ua_platform || raw.secChUaPlatform, 80),
		device_id: hashOpaqueId(nodeId, raw.device_id || raw.deviceId),
		request_length: safeInt(raw.request_length || raw.requestLength, 0, 100_000_000),
		bytes_sent: safeInt(raw.bytes_sent || raw.bytesSent, 0, 1_000_000_000),
		request_time: safeFloat(raw.request_time || raw.requestTime, 0, 3600),
		upstream_status: boundedString(raw.upstream_status || raw.upstreamStatus, 80),
	};
};

const normalizeAnalyticsEvent = (nodeId, raw) => {
	if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
	const timestamp = safeTimestamp(raw.timestamp);
	const host = safeHost(raw.host);
	const type = boundedString(raw.type, 40);
	if (!timestamp || !host || !["page_view", "engagement", "scroll", "route_change"].includes(type)) return null;
	return {
		node_id: nodeId,
		received_at: new Date().toISOString(),
		id: boundedString(raw.id, 128) || randomUUID(),
		timestamp,
		host,
		type,
		path: safePath(raw.path),
		referrerHost: safeHost(raw.referrerHost),
		sessionKey: boundedString(raw.sessionKey, 128) || null,
		deviceKey: boundedString(raw.deviceKey, 128) || null,
		clientFingerprint: boundedString(raw.clientFingerprint, 128) || null,
		ipHash: boundedString(raw.ipHash, 128) || null,
		consent: raw.consent === true,
		visibleSeconds: safeInt(raw.visibleSeconds, 0, 3600),
		scrollDepth: safeInt(raw.scrollDepth, 0, 100),
		language: boundedString(raw.language, 32) || null,
		timezone: boundedString(raw.timezone, 80) || null,
		viewport: boundedString(raw.viewport, 32) || null,
	};
};

const filePath = (nodeId, kind) => `${TELEMETRY_DIR}/${normalizeNodeId(nodeId)}.${kind}.jsonl`;

const readTail = async (path, maxBytes = MAX_READ_BYTES_PER_NODE) => {
	let handle;
	try {
		handle = await fs.promises.open(path, "r");
		const stat = await handle.stat();
		if (!stat.size) return "";
		const size = Math.min(stat.size, maxBytes);
		const buffer = Buffer.alloc(size);
		const { bytesRead } = await handle.read(buffer, 0, size, stat.size - size);
		let text = buffer.subarray(0, bytesRead).toString("utf8");
		if (stat.size > size) {
			const firstNewline = text.indexOf("\n");
			text = firstNewline >= 0 ? text.slice(firstNewline + 1) : "";
		}
		return text;
	} catch (err) {
		if (err.code === "ENOENT") return "";
		throw err;
	} finally {
		if (handle) await handle.close();
	}
};

const compactIfNeeded = async (path, maxBytes) => {
	try {
		const stat = await fs.promises.stat(path);
		if (stat.size <= maxBytes) return;
		const tail = await readTail(path, COMPACT_TO_BYTES);
		const tmp = `${path}.tmp-${process.pid}-${randomUUID()}`;
		await fs.promises.writeFile(tmp, tail, "utf8");
		await fs.promises.rename(tmp, path);
	} catch (err) {
		if (err.code !== "ENOENT") throw err;
	}
};

const appendRecords = async (path, records, maxBytes) => {
	if (records.length === 0) return 0;
	await compactIfNeeded(path, maxBytes);
	const payload = records.map((record) => JSON.stringify(record)).join("\n");
	await fs.promises.appendFile(path, `${payload}\n`, "utf8");
	return records.length;
};

const prepare = async () => {
	await fs.promises.mkdir(TELEMETRY_DIR, { recursive: true });
	return { ready: true };
};

const ingest = (nodeIdInput, input = {}) =>
	withMutation(async () => {
		const nodeId = normalizeNodeId(nodeIdInput);
		await prepare();
		const securityInput = Array.isArray(input.securityEvents) ? input.securityEvents.slice(0, MAX_BATCH_EVENTS) : [];
		const analyticsInput = Array.isArray(input.analyticsEvents) ? input.analyticsEvents.slice(0, MAX_BATCH_EVENTS) : [];
		const securityEvents = securityInput.map((event) => normalizeSecurityEvent(nodeId, event)).filter(Boolean);
		const analyticsEvents = analyticsInput.map((event) => normalizeAnalyticsEvent(nodeId, event)).filter(Boolean);
		const [acceptedSecurity, acceptedAnalytics] = await Promise.all([
			appendRecords(filePath(nodeId, "security"), securityEvents, MAX_SECURITY_FILE_BYTES),
			appendRecords(filePath(nodeId, "analytics"), analyticsEvents, MAX_ANALYTICS_FILE_BYTES),
		]);
		return {
			nodeId,
			acceptedSecurity,
			acceptedAnalytics,
			rejectedSecurity: securityInput.length - securityEvents.length,
			rejectedAnalytics: analyticsInput.length - analyticsEvents.length,
			serverTime: new Date().toISOString(),
		};
	});

const listNodeIdsForKind = async (kind) => {
	await prepare();
	const entries = await fs.promises.readdir(TELEMETRY_DIR, { withFileTypes: true });
	const suffix = `.${kind}.jsonl`;
	return entries
		.filter((entry) => entry.isFile() && entry.name.endsWith(suffix))
		.map((entry) => entry.name.slice(0, -suffix.length))
		.filter((id) => /^[A-Za-z0-9][A-Za-z0-9._:-]{0,119}$/.test(id));
};

const readEvents = async ({ kind, nodeId = "", limit = MAX_READ_EVENTS, since = 0 } = {}) => {
	const boundedLimit = Math.max(1, Math.min(MAX_READ_EVENTS, Number.parseInt(limit, 10) || MAX_READ_EVENTS));
	const ids = nodeId ? [normalizeNodeId(nodeId)] : await listNodeIdsForKind(kind);
	const result = [];
	for (const id of ids) {
		const text = await readTail(filePath(id, kind));
		for (const line of text.split("\n").filter(Boolean).reverse()) {
			try {
				const event = JSON.parse(line);
				const timestamp = Date.parse(event.ts || event.timestamp || "");
				if (since && (!Number.isFinite(timestamp) || timestamp < since)) continue;
				result.push(event);
				if (result.length >= boundedLimit * Math.max(1, ids.length)) break;
			} catch {
				// Ignore one malformed line instead of dropping the whole node.
			}
		}
	}
	return result
		.sort((left, right) => Date.parse(right.ts || right.timestamp || "") - Date.parse(left.ts || left.timestamp || ""))
		.slice(0, boundedLimit);
};

const getSecurityEvents = async (options = {}) =>
	readEvents({
		kind: "security",
		nodeId: options.nodeId,
		limit: options.limit,
		since: options.since,
	});

const getAnalyticsEvents = async (options = {}) =>
	readEvents({
		kind: "analytics",
		nodeId: options.nodeId,
		limit: options.limit,
		since: options.since,
	});

const summarizeAnalytics = (events) => {
	const devices = new Set();
	const fingerprints = new Set();
	const sessions = new Set();
	let pageViews = 0;
	let engagementSeconds = 0;
	let routeChanges = 0;
	const scroll = { 25: 0, 50: 0, 75: 0, 100: 0 };
	for (const event of events) {
		const prefix = `${event.node_id || "remote"}:`;
		if (event.deviceKey) devices.add(`${prefix}${event.deviceKey}`);
		if (event.clientFingerprint) fingerprints.add(`${prefix}${event.clientFingerprint}`);
		if (event.sessionKey) sessions.add(`${prefix}${event.sessionKey}`);
		if (event.type === "page_view") pageViews += 1;
		if (event.type === "engagement") engagementSeconds += safeInt(event.visibleSeconds, 0, 3600);
		if (event.type === "route_change") routeChanges += 1;
		if (event.type === "scroll") {
			for (const mark of [25, 50, 75, 100]) if (safeInt(event.scrollDepth, 0, 100) >= mark) scroll[mark] += 1;
		}
	}
	return {
		events: events.length,
		pageViews,
		consentedDevices: devices.size,
		clientFingerprints: fingerprints.size,
		sessions: sessions.size,
		engagementSeconds,
		routeChanges,
		scroll,
	};
};

const getAnalyticsSummary = async ({ nodeId = "", host = "", sinceMinutes = 60 } = {}) => {
	const since = Date.now() - Math.max(1, Math.min(43_200, Number.parseInt(sinceMinutes, 10) || 60)) * 60_000;
	const normalizedHost = safeHost(host);
	const events = await getAnalyticsEvents({ nodeId, since, limit: MAX_READ_EVENTS });
	return summarizeAnalytics(events.filter((event) => !normalizedHost || event.host === normalizedHost));
};

export default {
	prepare,
	ingest,
	getSecurityEvents,
	getAnalyticsEvents,
	getAnalyticsSummary,
	summarizeAnalytics,
};
