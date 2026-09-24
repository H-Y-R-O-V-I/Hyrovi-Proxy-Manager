import fs from "node:fs";
import net from "node:net";
import { createHash, randomUUID } from "node:crypto";
import errs from "../lib/error.js";
import { global as logger } from "../logger.js";
import internalNginx from "./nginx.js";
import deadHostModel from "../models/dead_host.js";
import proxyHostModel from "../models/proxy_host.js";
import redirectionHostModel from "../models/redirection_host.js";

const SECURITY_LOG_FILE = "/data/logs/hyrovi-sec.log";
const SECURITY_ACTION_LOG_FILE = "/data/logs/hyrovi-sec-actions.log";
const SECURITY_DIR = "/data/nginx/hyrovi-security";
const BLOCKS_FILE = `${SECURITY_DIR}/blocks.json`;
const BLOCKS_CONF_FILE = `${SECURITY_DIR}/blocked-ips.conf`;
const RATE_LIMITS_FILE = `${SECURITY_DIR}/rate-limits.json`;
const RATE_LIMIT_GEO_FILE = `${SECURITY_DIR}/rate-limited-ips.geo`;
const EVENT_ARCHIVE_DIR = `${SECURITY_DIR}/events`;
const INSTRUMENTATION_MARKER = `${SECURITY_DIR}/instrumentation-v2`;
const POLICY_FILE = `${SECURITY_DIR}/policy.json`;
const MAX_SCAN_BYTES = 4 * 1024 * 1024;
const MAX_ACTION_LOG_BYTES = 2 * 1024 * 1024;
const DEFAULT_EVENT_LIMIT = 250;
const MAX_EVENT_LIMIT = 2000;
const SESSION_WINDOW_MS = 5 * 60 * 1000;
const REQUEST_CONTEXT_WINDOW_MS = 60_000;
const MONITOR_INTERVAL_MS = 5_000;
const PROCESSED_EVENT_LIMIT = 5_000;
const ARCHIVED_EVENT_ID_LIMIT = 10_000;
const MAX_ARCHIVE_SCAN_BYTES_PER_DAY = 512 * 1024;
const MAX_ARCHIVE_FILE_BYTES = 8 * 1024 * 1024;
const DEFAULT_POLICY = Object.freeze({
	autoBlockEnabled: false,
	autoRateLimitThreshold: 50,
	autoRateLimitMinutes: 10,
	autoBlockThreshold: 95,
	autoBlockMinutes: 60,
	eventRetentionDays: 14,
	eventArchiveMinRisk: 20,
	trustedSources: [],
	hostPolicies: {},
});
const HOST_POLICY_MODES = new Set(["off", "observe", "protect", "strict"]);
const MAX_HOST_POLICIES = 500;

const processedEventIds = new Set();
const processedEventOrder = [];
const archivedEventIds = new Set();
const archivedEventOrder = [];
let monitorPrimed = false;
let securityConfigMutationQueue = Promise.resolve();
let eventArchiveMutationQueue = Promise.resolve();

const clamp = (value, min, max) => Math.max(min, Math.min(max, value));

const normalizeTrustedSource = (value) => {
	const entry = String(value || "").trim();
	if (!entry) return null;

	const parts = entry.split("/");
	if (parts.length > 2) return null;
	const address = parts[0];
	const version = net.isIP(address);
	if (!version) return null;
	if (parts.length === 1) return address;

	if (!/^\d+$/.test(parts[1])) return null;
	const prefix = Number.parseInt(parts[1], 10);
	const maxPrefix = version === 4 ? 32 : 128;
	if (prefix < 0 || prefix > maxPrefix) return null;
	return `${address}/${prefix}`;
};

const normalizeTrustedSources = (value) => {
	if (!Array.isArray(value)) return [];
	const normalized = value.map(normalizeTrustedSource).filter(Boolean);
	return [...new Set(normalized)].slice(0, 200);
};

const isTrustedSource = (ip, trustedSources = []) => {
	const version = net.isIP(ip);
	if (!version) return false;
	const type = version === 4 ? "ipv4" : "ipv6";
	const blockList = new net.BlockList();

	for (const entry of normalizeTrustedSources(trustedSources)) {
		const [address, prefix] = entry.split("/");
		const entryVersion = net.isIP(address);
		if (entryVersion !== version) continue;
		if (typeof prefix === "undefined") {
			blockList.addAddress(address, type);
		} else {
			blockList.addSubnet(address, Number.parseInt(prefix, 10), type);
		}
	}

	return blockList.check(ip, type);
};
const normalizeHostPolicy = (value = {}, globalPolicy = DEFAULT_POLICY) => {
	const source = value && typeof value === "object" && !Array.isArray(value) ? value : {};
	const mode = HOST_POLICY_MODES.has(source.mode) ? source.mode : "observe";
	const defaultRateLimitThreshold =
		mode === "strict"
			? Math.min(globalPolicy.autoRateLimitThreshold || DEFAULT_POLICY.autoRateLimitThreshold, 45)
			: globalPolicy.autoRateLimitThreshold || DEFAULT_POLICY.autoRateLimitThreshold;
	const defaultBlockThreshold =
		mode === "strict"
			? Math.min(globalPolicy.autoBlockThreshold || DEFAULT_POLICY.autoBlockThreshold, 90)
			: globalPolicy.autoBlockThreshold || DEFAULT_POLICY.autoBlockThreshold;
	return {
		mode,
		autoRateLimitThreshold: clamp(
			Number.parseInt(source.autoRateLimitThreshold, 10) || defaultRateLimitThreshold,
			40,
			100,
		),
		autoRateLimitMinutes: clamp(
			Number.parseInt(source.autoRateLimitMinutes, 10) ||
				globalPolicy.autoRateLimitMinutes ||
				DEFAULT_POLICY.autoRateLimitMinutes,
			1,
			43_200,
		),
		autoBlockThreshold: clamp(Number.parseInt(source.autoBlockThreshold, 10) || defaultBlockThreshold, 80, 100),
		autoBlockMinutes: clamp(
			Number.parseInt(source.autoBlockMinutes, 10) || globalPolicy.autoBlockMinutes || DEFAULT_POLICY.autoBlockMinutes,
			1,
			43_200,
		),
	};
};

const normalizeHostPolicies = (value, globalPolicy) => {
	if (!value || typeof value !== "object" || Array.isArray(value)) return {};
	const result = {};
	for (const [hostId, hostPolicy] of Object.entries(value).slice(0, MAX_HOST_POLICIES)) {
		if (!/^\d+$/.test(hostId) || Number(hostId) < 1) continue;
		result[hostId] = normalizeHostPolicy(hostPolicy, globalPolicy);
	}
	return result;
};

const normalizeHostname = (value) => String(value || "").trim().toLowerCase().replace(/\.$/, "");

const safeJsonParse = (line) => {
	try {
		return JSON.parse(line);
	} catch (_) {
		return null;
	}
};

const readTail = async (filePath, maxBytes = MAX_SCAN_BYTES) => {
	let handle;
	try {
		handle = await fs.promises.open(filePath, "r");
		const stat = await handle.stat();
		if (!stat.size) return "";
		const size = Math.min(stat.size, maxBytes);
		const buffer = Buffer.alloc(size);
		let offset = 0;
		while (offset < size) {
			const { bytesRead } = await handle.read(buffer, offset, size - offset, stat.size - size + offset);
			if (bytesRead === 0) break;
			offset += bytesRead;
		}
		let text = buffer.subarray(0, offset).toString("utf8");
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

const readSecurityEventWindow = async () => {
	const current = await readTail(SECURITY_LOG_FILE, MAX_SCAN_BYTES);
	const currentBytes = Buffer.byteLength(current, "utf8");
	if (currentBytes >= MAX_SCAN_BYTES) return current;

	const previous = await readTail(`${SECURITY_LOG_FILE}.1`, MAX_SCAN_BYTES - currentBytes);
	if (!previous) return current;
	if (!current) return previous;
	return `${previous.replace(/\n$/, "")}\n${current}`;
};

const parseTimestamp = (value) => {
	const date = new Date(value);
	return Number.isNaN(date.getTime()) ? null : date;
};

const normalizeEvent = (raw) => {
	const status = Number.parseInt(raw.status, 10) || 0;
	const requestLength = Number.parseInt(raw.request_length, 10) || 0;
	const bytesSent = Number.parseInt(raw.bytes_sent, 10) || 0;
	const requestTime = Number.parseFloat(raw.request_time) || 0;
	return {
		timestamp: raw.ts || null,
		requestId: raw.request_id || null,
		host: raw.host || "",
		method: String(raw.method || "").toUpperCase(),
		path: raw.path || "/",
		status,
		ip: raw.remote_addr || "",
		userAgent: raw.user_agent || "",
		requestLength,
		bytesSent,
		requestTime,
		upstreamStatus: raw.upstream_status || "",
	};
};

const baseSignals = (event) => {
	const signals = [];
	const path = event.path.toLowerCase();
	const ua = event.userAgent.toLowerCase();
	let risk = 0;

	const add = (id, score, label) => {
		risk += score;
		signals.push({ id, score, label });
	};

	if (/(^|\/)(\.env|\.git|\.svn|\.hg)(\/|$)|\/etc\/passwd|\/proc\/self/i.test(path)) {
		add("sensitive_file_probe", 55, "Sensitive file or repository probe");
	}
	if (/\/wp-admin|\/wp-login\.php|\/xmlrpc\.php|\/phpmyadmin|\/adminer/i.test(path)) {
		add("cms_probe", 35, "Common CMS/admin scanner path");
	}
	if (/\.\.\/|%2e%2e|%252e%252e/i.test(path)) {
		add("path_traversal", 60, "Path traversal pattern");
	}
	if (/<script|%3cscript|union(?:%20|\+)select|sleep\(|benchmark\(/i.test(path)) {
		add("injection_probe", 55, "Injection-style path pattern");
	}
	if (["TRACE", "TRACK", "CONNECT"].includes(event.method)) {
		add("unusual_method", 35, `Unusual HTTP method ${event.method}`);
	}
	if (/sqlmap|nikto|masscan|nmap|acunetix|nessus|gobuster|dirbuster|ffuf|wpscan/i.test(ua)) {
		add("scanner_user_agent", 50, "Known security scanner user-agent");
	}
	if ([401, 403].includes(event.status)) {
		add("access_denied", 10, `HTTP ${event.status}`);
	} else if (event.status === 404) {
		add("not_found", 4, "HTTP 404");
	}
	if (event.requestLength > 10 * 1024 * 1024) {
		add("large_request", 12, "Unusually large request");
	}
	if (event.requestTime > 30) {
		add("slow_request", 8, "Very long request duration");
	}

	return { risk, signals };
};

const enrichEvents = (events) => {
	const analyzed = events.map((event, index) => {
		const base = baseSignals(event);
		return {
			event,
			index,
			time: parseTimestamp(event.timestamp)?.getTime() ?? null,
			baseRisk: base.risk,
			baseSignals: base.signals,
		};
	});
	const eventsByIp = new Map();
	const contextByIndex = new Map();

	for (const item of analyzed) {
		if (!item.event.ip || item.time === null) continue;
		const list = eventsByIp.get(item.event.ip) || [];
		list.push(item);
		eventsByIp.set(item.event.ip, list);
	}

	for (const list of eventsByIp.values()) {
		list.sort((left, right) => left.time - right.time || left.index - right.index);
		let startIndex = 0;
		let denied = 0;
		let missing = 0;
		const suspiciousPathCounts = new Map();

		const addToWindow = (item) => {
			if ([401, 403].includes(item.event.status)) denied += 1;
			if (item.event.status === 404) missing += 1;
			if (item.baseRisk >= 30) {
				suspiciousPathCounts.set(item.event.path, (suspiciousPathCounts.get(item.event.path) || 0) + 1);
			}
		};

		const removeFromWindow = (item) => {
			if ([401, 403].includes(item.event.status)) denied -= 1;
			if (item.event.status === 404) missing -= 1;
			if (item.baseRisk >= 30) {
				const next = (suspiciousPathCounts.get(item.event.path) || 0) - 1;
				if (next <= 0) suspiciousPathCounts.delete(item.event.path);
				else suspiciousPathCounts.set(item.event.path, next);
			}
		};

		for (let endIndex = 0; endIndex < list.length; endIndex += 1) {
			const current = list[endIndex];
			addToWindow(current);

			while (startIndex <= endIndex && current.time - list[startIndex].time > REQUEST_CONTEXT_WINDOW_MS) {
				removeFromWindow(list[startIndex]);
				startIndex += 1;
			}

			contextByIndex.set(current.index, {
				requests: endIndex - startIndex + 1,
				denied,
				missing,
				suspiciousPaths: suspiciousPathCounts.size,
			});
		}
	}

	return analyzed.map((item) => {
		const signals = [...item.baseSignals];
		let risk = item.baseRisk;
		const recent = contextByIndex.get(item.index);

		const add = (id, score, label) => {
			if (signals.some((signal) => signal.id === id)) return;
			risk += score;
			signals.push({ id, score, label });
		};

		if (recent?.requests >= 120) add("request_burst", 25, `${recent.requests} requests from this IP in 60s`);
		if (recent?.denied >= 10) add("auth_failure_burst", 35, `${recent.denied} denied requests from this IP in 60s`);
		if (recent?.missing >= 20) add("path_enumeration", 25, `${recent.missing} missing paths requested in 60s`);
		if (recent?.suspiciousPaths >= 5) add("reconnaissance_burst", 35, "Multiple suspicious paths probed");

		risk = clamp(risk, 0, 100);
		const severity = risk >= 80 ? "critical" : risk >= 60 ? "high" : risk >= 40 ? "medium" : risk >= 20 ? "low" : "normal";
		return { ...item.event, risk, severity, signals };
	});
};

const loadLiveEvents = async (limit = DEFAULT_EVENT_LIMIT) => {
	const text = await readSecurityEventWindow();
	if (!text) return [];
	const parsed = text
		.split("\n")
		.filter(Boolean)
		.map(safeJsonParse)
		.filter(Boolean)
		.map(normalizeEvent)
		.filter((event) => event.ip && event.host);

	const enriched = enrichEvents(parsed);
	return enriched.slice(-clamp(limit, 1, MAX_EVENT_LIMIT)).reverse();
};

const rememberArchivedEvent = (event) => {
	const id = eventIdentity(event);
	if (archivedEventIds.has(id)) return false;
	archivedEventIds.add(id);
	archivedEventOrder.push(id);
	while (archivedEventOrder.length > ARCHIVED_EVENT_ID_LIMIT) {
		archivedEventIds.delete(archivedEventOrder.shift());
	}
	return true;
};

const archiveDateKey = (event) => {
	const date = parseTimestamp(event.timestamp);
	return (date || new Date()).toISOString().slice(0, 10);
};

const archivedEventRecord = (event) => ({
	timestamp: event.timestamp,
	requestId: event.requestId,
	host: event.host,
	method: event.method,
	path: event.path,
	status: event.status,
	ip: event.ip,
	userAgent: event.userAgent,
	requestLength: event.requestLength,
	bytesSent: event.bytesSent,
	requestTime: event.requestTime,
	upstreamStatus: event.upstreamStatus,
	risk: event.risk,
	severity: event.severity,
	signals: event.signals,
});

const withEventArchiveMutation = (operation) => {
	const run = eventArchiveMutationQueue.then(operation, operation);
	eventArchiveMutationQueue = run.catch(() => undefined);
	return run;
};

const persistArchivedEvents = async (events, policy) =>
	withEventArchiveMutation(async () => {
		const seen = new Set();
		const candidates = events
			.filter((event) => event.risk >= policy.eventArchiveMinRisk)
			.filter((event) => {
				const id = eventIdentity(event);
				if (archivedEventIds.has(id) || seen.has(id)) return false;
				seen.add(id);
				return true;
			})
			.sort((left, right) => {
				const leftTime = parseTimestamp(left.timestamp)?.getTime() || 0;
				const rightTime = parseTimestamp(right.timestamp)?.getTime() || 0;
				return leftTime - rightTime;
			});
		if (candidates.length === 0) return 0;

		await fs.promises.mkdir(EVENT_ARCHIVE_DIR, { recursive: true });
		const byDay = new Map();
		for (const event of candidates) {
			const key = archiveDateKey(event);
			const list = byDay.get(key) || [];
			list.push(event);
			byDay.set(key, list);
		}

		let persisted = 0;
		for (const [day, dayEvents] of byDay) {
			const filePath = `${EVENT_ARCHIVE_DIR}/${day}.jsonl`;
			try {
				const stat = await fs.promises.stat(filePath);
				if (stat.size >= MAX_ARCHIVE_FILE_BYTES) {
					const compacted = await readTail(filePath, Math.floor(MAX_ARCHIVE_FILE_BYTES / 2));
					await writeTextAtomic(filePath, compacted);
				}
			} catch (err) {
				if (err.code !== "ENOENT") throw err;
			}

			const payload = dayEvents.map((event) => JSON.stringify(archivedEventRecord(event))).join("\n");
			await fs.promises.appendFile(filePath, `${payload}\n`, "utf8");
			for (const event of dayEvents) rememberArchivedEvent(event);
			persisted += dayEvents.length;
		}
		return persisted;
	});

const persistArchivedEventsBestEffort = async (events, policy) => {
	try {
		return await persistArchivedEvents(events, policy);
	} catch (err) {
		logger.error(`HYROVI Sec event archive write failed; protection will continue: ${err.message}`);
		return 0;
	}
};

const listArchiveFiles = async (retentionDays) => {
	try {
		const entries = await fs.promises.readdir(EVENT_ARCHIVE_DIR, { withFileTypes: true });
		return entries
			.filter((entry) => entry.isFile() && /^\d{4}-\d{2}-\d{2}\.jsonl$/.test(entry.name))
			.map((entry) => entry.name)
			.sort()
			.reverse()
			.slice(0, retentionDays + 1);
	} catch (err) {
		if (err.code === "ENOENT") return [];
		throw err;
	}
};

const loadArchivedEvents = async (limit, retentionDays) => {
	const files = await listArchiveFiles(retentionDays);
	const result = [];
	for (const file of files) {
		const text = await readTail(`${EVENT_ARCHIVE_DIR}/${file}`, MAX_ARCHIVE_SCAN_BYTES_PER_DAY);
		for (const line of text.split("\n").filter(Boolean).reverse()) {
			const event = safeJsonParse(line);
			if (!event?.ip || !event?.host || !Array.isArray(event.signals)) continue;
			result.push(event);
			if (result.length >= limit) return result;
		}
	}
	return result;
};

const purgeArchivedEvents = async (retentionDays) =>
	withEventArchiveMutation(async () => {
		let entries;
		try {
			entries = await fs.promises.readdir(EVENT_ARCHIVE_DIR, { withFileTypes: true });
		} catch (err) {
			if (err.code === "ENOENT") return 0;
			throw err;
		}
		const cutoff = Date.now() - retentionDays * 24 * 60 * 60 * 1000;
		let removed = 0;
		for (const entry of entries) {
			if (!entry.isFile() || !/^\d{4}-\d{2}-\d{2}\.jsonl$/.test(entry.name)) continue;
			const timestamp = Date.parse(`${entry.name.slice(0, 10)}T23:59:59.999Z`);
			if (!Number.isFinite(timestamp) || timestamp >= cutoff) continue;
			await fs.promises.unlink(`${EVENT_ARCHIVE_DIR}/${entry.name}`);
			removed += 1;
		}
		return removed;
	});

const loadEventHistory = async (limit, policy) => {
	const [live, archived] = await Promise.all([
		loadLiveEvents(limit),
		loadArchivedEvents(limit, policy.eventRetentionDays),
	]);
	const byId = new Map();
	for (const event of archived) byId.set(eventIdentity(event), event);
	for (const event of live) byId.set(eventIdentity(event), event);
	return [...byId.values()]
		.sort((left, right) => {
			const leftTime = parseTimestamp(left.timestamp)?.getTime() || 0;
			const rightTime = parseTimestamp(right.timestamp)?.getTime() || 0;
			return rightTime - leftTime;
		})
		.slice(0, limit);
};

const readBlocksUnsafe = async () => {
	try {
		const data = JSON.parse(await fs.promises.readFile(BLOCKS_FILE, "utf8"));
		return Array.isArray(data) ? data : [];
	} catch (err) {
		if (err.code === "ENOENT") return [];
		throw err;
	}
};

const activeBlocks = (blocks) => {
	const now = Date.now();
	return blocks.filter((block) => !block.expiresAt || new Date(block.expiresAt).getTime() > now);
};

const readRateLimitsUnsafe = async () => {
	try {
		const data = JSON.parse(await fs.promises.readFile(RATE_LIMITS_FILE, "utf8"));
		return Array.isArray(data) ? data : [];
	} catch (err) {
		if (err.code === "ENOENT") return [];
		throw err;
	}
};

const ensureSecurityDir = async () => {
	await fs.promises.mkdir(SECURITY_DIR, { recursive: true });
};

const writeTextAtomic = async (path, value) => {
	const tmp = `${path}.tmp-${process.pid}-${randomUUID()}`;
	try {
		await fs.promises.writeFile(tmp, value, "utf8");
		await fs.promises.rename(tmp, path);
	} catch (err) {
		await fs.promises.unlink(tmp).catch(() => undefined);
		throw err;
	}
};

const writeJsonAtomic = (path, value) => writeTextAtomic(path, `${JSON.stringify(value, null, 2)}\n`);

const loadSecurityActions = async (limit = 500) => {
	const text = await readTail(SECURITY_ACTION_LOG_FILE, MAX_ACTION_LOG_BYTES);
	if (!text) return [];
	return text
		.split("\n")
		.filter(Boolean)
		.map(safeJsonParse)
		.filter(Boolean)
		.slice(-clamp(limit, 1, 2000));
};

const appendSecurityAction = async (entry) => {
	await fs.promises.mkdir("/data/logs", { recursive: true });
	try {
		const stat = await fs.promises.stat(SECURITY_ACTION_LOG_FILE);
		if (stat.size > MAX_ACTION_LOG_BYTES) {
			const compacted = await readTail(SECURITY_ACTION_LOG_FILE, Math.floor(MAX_ACTION_LOG_BYTES / 2));
			await writeTextAtomic(SECURITY_ACTION_LOG_FILE, compacted);
		}
	} catch (err) {
		if (err.code !== "ENOENT") throw err;
	}
	await fs.promises.appendFile(SECURITY_ACTION_LOG_FILE, `${JSON.stringify(entry)}\n`, "utf8");
};

const recordResponseAction = async (type, action, record) => {
	try {
		await appendSecurityAction({
			id: randomUUID(),
			at: new Date().toISOString(),
			type,
			action,
			responseId: record.id,
			ip: record.ip,
			source: record.source || "hyrovi-sec",
			reason: String(record.reason || "").slice(0, 300),
			createdAt: record.createdAt || null,
			expiresAt: record.expiresAt || null,
		});
	} catch (err) {
		logger.error(`HYROVI Sec response audit write failed: ${err.message}`);
	}
};

const withSecurityConfigMutation = (operation) => {
	const run = securityConfigMutationQueue.then(operation, operation);
	securityConfigMutationQueue = run.catch(() => undefined);
	return run;
};

const normalizePolicy = (value = {}) => {
	const retentionDays = Number.parseInt(value.eventRetentionDays, 10);
	const archiveMinRisk = Number.parseInt(value.eventArchiveMinRisk, 10);
	const normalized = {
		autoBlockEnabled: value.autoBlockEnabled === true,
		autoRateLimitThreshold: clamp(
			Number.parseInt(value.autoRateLimitThreshold, 10) || DEFAULT_POLICY.autoRateLimitThreshold,
			40,
			100,
		),
		autoRateLimitMinutes: clamp(
			Number.parseInt(value.autoRateLimitMinutes, 10) || DEFAULT_POLICY.autoRateLimitMinutes,
			1,
			43_200,
		),
		autoBlockThreshold: clamp(Number.parseInt(value.autoBlockThreshold, 10) || DEFAULT_POLICY.autoBlockThreshold, 80, 100),
		autoBlockMinutes: clamp(Number.parseInt(value.autoBlockMinutes, 10) || DEFAULT_POLICY.autoBlockMinutes, 1, 43_200),
		eventRetentionDays: clamp(
			Number.isInteger(retentionDays) ? retentionDays : DEFAULT_POLICY.eventRetentionDays,
			1,
			90,
		),
		eventArchiveMinRisk: clamp(
			Number.isInteger(archiveMinRisk) ? archiveMinRisk : DEFAULT_POLICY.eventArchiveMinRisk,
			0,
			100,
		),
		trustedSources: normalizeTrustedSources(value.trustedSources),
	};
	return { ...normalized, hostPolicies: normalizeHostPolicies(value.hostPolicies, normalized) };
};
const readPolicyUnsafe = async () => {
	try {
		return normalizePolicy(JSON.parse(await fs.promises.readFile(POLICY_FILE, "utf8")));
	} catch (err) {
		if (err.code === "ENOENT") return { ...DEFAULT_POLICY };
		throw err;
	}
};

const writePolicyUnsafe = async (policy) => {
	await ensureSecurityDir();
	const normalized = normalizePolicy(policy);
	await writeJsonAtomic(POLICY_FILE, normalized);
	return normalized;
};

const isPrivateOrLoopback = (ip) => {
	if (net.isIPv4(ip)) {
		const parts = ip.split(".").map(Number);
		return (
			parts[0] === 10 ||
			parts[0] === 127 ||
			(parts[0] === 169 && parts[1] === 254) ||
			(parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
			(parts[0] === 192 && parts[1] === 168)
		);
	}
	if (net.isIPv6(ip)) {
		const normalized = ip.toLowerCase();
		return normalized === "::1" || normalized.startsWith("fe8") || normalized.startsWith("fe9") || normalized.startsWith("fea") || normalized.startsWith("feb") || normalized.startsWith("fc") || normalized.startsWith("fd");
	}
	return true;
};

const eventIdentity = (event) =>
	event.requestId || [event.timestamp, event.ip, event.method, event.host, event.path, event.status].join("|");

const rememberEvent = (event) => {
	const id = eventIdentity(event);
	if (processedEventIds.has(id)) return false;
	processedEventIds.add(id);
	processedEventOrder.push(id);
	while (processedEventOrder.length > PROCESSED_EVENT_LIMIT) {
		processedEventIds.delete(processedEventOrder.shift());
	}
	return true;
};

const eventIsAutoBlockCandidate = (event, policy) => {
	if (
		event.risk < policy.autoBlockThreshold ||
		isPrivateOrLoopback(event.ip) ||
		isTrustedSource(event.ip, policy.trustedSources)
	) {
		return false;
	}
	const ids = new Set(event.signals.map((signal) => signal.id));
	return (
		ids.has("path_traversal") ||
		ids.has("injection_probe") ||
		ids.has("reconnaissance_burst") ||
		ids.has("auth_failure_burst") ||
		(ids.has("sensitive_file_probe") && ids.has("scanner_user_agent"))
	);
};

const eventIsAutoRateLimitCandidate = (event, policy) => {
	if (
		event.risk < policy.autoRateLimitThreshold ||
		isPrivateOrLoopback(event.ip) ||
		isTrustedSource(event.ip, policy.trustedSources)
	) {
		return false;
	}
	const ids = new Set(event.signals.map((signal) => signal.id));
	return (
		ids.has("path_traversal") ||
		ids.has("injection_probe") ||
		ids.has("sensitive_file_probe") ||
		ids.has("request_burst") ||
		ids.has("auth_failure_burst") ||
		ids.has("path_enumeration") ||
		ids.has("reconnaissance_burst") ||
		(ids.has("scanner_user_agent") &&
			(ids.has("cms_probe") || ids.has("access_denied") || ids.has("not_found"))) ||
		(ids.has("unusual_method") && ids.has("access_denied"))
	);
};

const renderBlockConfig = (blocks) => {
	const lines = [
		"# Managed by HYROVI Sec. Do not edit manually.",
		"# Query strings, cookies, authorization headers and request bodies are never written here.",
	];
	for (const block of activeBlocks(blocks)) {
		lines.push(`# ${block.id} | ${String(block.reason || "").replace(/[\r\n]/g, " ").slice(0, 160)}`);
		lines.push(`deny ${block.ip};`);
	}
	return `${lines.join("\n")}\n`;
};

const applyBlockConfig = async (blocks) => {
	await ensureSecurityDir();
	let previous = "";
	try {
		previous = await fs.promises.readFile(BLOCKS_CONF_FILE, "utf8");
	} catch (err) {
		if (err.code !== "ENOENT") throw err;
	}

	const next = renderBlockConfig(blocks);
	if (previous === next) return false;

	await writeTextAtomic(BLOCKS_CONF_FILE, next);

	try {
		await internalNginx.reload();
	} catch (err) {
		await writeTextAtomic(BLOCKS_CONF_FILE, previous);
		try {
			await internalNginx.reload();
		} catch (_) {
			// Preserve the original validation/reload error.
		}
		throw err;
	}

	return true;
};

const commitBlockState = async (previousBlocks, nextBlocks) => {
	await applyBlockConfig(nextBlocks);
	try {
		await writeJsonAtomic(BLOCKS_FILE, nextBlocks);
	} catch (err) {
		try {
			await applyBlockConfig(previousBlocks);
		} catch (rollbackErr) {
			logger.error(
				`HYROVI Sec could not roll back Nginx block config after state persistence failed: ${rollbackErr.message}`,
			);
		}
		throw err;
	}
};

const purgeExpiredUnsafe = async () => {
	const blocks = await readBlocksUnsafe();
	const active = activeBlocks(blocks);
	if (active.length === blocks.length) return active;
	const activeIds = new Set(active.map((block) => block.id));
	const expired = blocks.filter((block) => !activeIds.has(block.id));
	await commitBlockState(blocks, active);
	for (const block of expired) await recordResponseAction("block", "expired", block);
	return active;
};

const purgeExpired = () => withSecurityConfigMutation(purgeExpiredUnsafe);

const synchronizeBlockConfigUnsafe = async () => {
	const blocks = await readBlocksUnsafe();
	const active = activeBlocks(blocks);
	if (active.length !== blocks.length) {
		await commitBlockState(blocks, active);
	} else {
		await applyBlockConfig(active);
	}
	return active;
};

const renderRateLimitGeo = (entries) => {
	const lines = [
		"# Managed by HYROVI Sec. Do not edit manually.",
		"# Only exact source IPs listed here receive a rate-limit key.",
	];
	for (const entry of activeBlocks(entries)) {
		if (!net.isIP(entry.ip)) continue;
		lines.push(`# ${entry.id}`);
		lines.push(`${entry.ip} 1;`);
	}
	return `${lines.join("\n")}\n`;
};

const applyRateLimitConfig = async (entries) => {
	await ensureSecurityDir();
	let previous = "";
	try {
		previous = await fs.promises.readFile(RATE_LIMIT_GEO_FILE, "utf8");
	} catch (err) {
		if (err.code !== "ENOENT") throw err;
	}

	const next = renderRateLimitGeo(entries);
	if (previous === next) return false;
	await writeTextAtomic(RATE_LIMIT_GEO_FILE, next);

	try {
		await internalNginx.reload();
	} catch (err) {
		await writeTextAtomic(RATE_LIMIT_GEO_FILE, previous);
		try {
			await internalNginx.reload();
		} catch (_) {
			// Preserve the original validation/reload error.
		}
		throw err;
	}
	return true;
};

const commitRateLimitState = async (previousEntries, nextEntries) => {
	await applyRateLimitConfig(nextEntries);
	try {
		await writeJsonAtomic(RATE_LIMITS_FILE, nextEntries);
	} catch (err) {
		try {
			await applyRateLimitConfig(previousEntries);
		} catch (rollbackErr) {
			logger.error(
				`HYROVI Sec could not roll back Nginx rate-limit config after state persistence failed: ${rollbackErr.message}`,
			);
		}
		throw err;
	}
};

const purgeExpiredRateLimitsUnsafe = async () => {
	const entries = await readRateLimitsUnsafe();
	const active = activeBlocks(entries);
	if (active.length === entries.length) return active;
	const activeIds = new Set(active.map((entry) => entry.id));
	const expired = entries.filter((entry) => !activeIds.has(entry.id));
	await commitRateLimitState(entries, active);
	for (const entry of expired) await recordResponseAction("rate_limit", "expired", entry);
	return active;
};

const purgeExpiredRateLimits = () => withSecurityConfigMutation(purgeExpiredRateLimitsUnsafe);

const synchronizeRateLimitConfigUnsafe = async () => {
	const entries = await readRateLimitsUnsafe();
	const active = activeBlocks(entries);
	if (active.length !== entries.length) {
		await commitRateLimitState(entries, active);
	} else {
		await applyRateLimitConfig(active);
	}
	return active;
};

const createRateLimitRecord = ({ ip, reason, source, durationMinutes }) => {
	const now = new Date();
	return {
		id: randomUUID(),
		ip,
		reason: String(reason || "HYROVI Sec rate limit").trim().slice(0, 300),
		source: source || "manual",
		createdAt: now.toISOString(),
		expiresAt: new Date(now.getTime() + durationMinutes * 60_000).toISOString(),
	};
};

const addRateLimitUnsafe = async ({ ip, reason, source, durationMinutes }) => {
	if (!net.isIP(ip)) throw new errs.ValidationError("Invalid IP address");
	const minutes = clamp(Number.parseInt(durationMinutes, 10) || 10, 1, 43_200);
	const entries = await purgeExpiredRateLimitsUnsafe();
	const existing = entries.find((entry) => entry.ip === ip);
	if (existing) return existing;

	const entry = createRateLimitRecord({ ip, reason, source, durationMinutes: minutes });
	const next = [...entries, entry];
	await commitRateLimitState(entries, next);
	await recordResponseAction("rate_limit", "started", entry);
	return entry;
};
const createBlockRecord = ({ ip, reason, source, durationMinutes }) => {
	const now = new Date();
	return {
		id: randomUUID(),
		ip,
		reason: String(reason || "HYROVI Sec block").trim().slice(0, 300),
		source: source || "hyrovi-sec",
		createdAt: now.toISOString(),
		expiresAt: new Date(now.getTime() + durationMinutes * 60_000).toISOString(),
	};
};

const addBlockUnsafe = async ({ ip, reason, source, durationMinutes }) => {
	if (!net.isIP(ip)) throw new errs.ValidationError("Invalid IP address");
	const minutes = clamp(Number.parseInt(durationMinutes, 10) || 60, 1, 43_200);
	const blocks = await purgeExpiredUnsafe();
	const existing = blocks.find((block) => block.ip === ip);
	if (existing) return existing;

	const block = createBlockRecord({ ip, reason, source, durationMinutes: minutes });
	const next = [...blocks, block];
	await commitBlockState(blocks, next);
	await recordResponseAction("block", "started", block);
	return block;
};

const listProxyHostsForSecurity = () =>
	proxyHostModel
		.query()
		.select("id", "domain_names", "enabled")
		.where("is_deleted", 0)
		.orderBy("id", "ASC");

const createHostPolicyContext = (policy, hosts = []) => {
	const exact = new Map();
	const wildcards = [];
	const globalMode = policy.autoBlockEnabled ? "protect" : "observe";
	const globalEffective = {
		proxyHostId: null,
		mode: globalMode,
		autoBlockEnabled: policy.autoBlockEnabled,
		autoRateLimitThreshold: policy.autoRateLimitThreshold,
		autoRateLimitMinutes: policy.autoRateLimitMinutes,
		autoBlockThreshold: policy.autoBlockThreshold,
		autoBlockMinutes: policy.autoBlockMinutes,
		inherited: true,
	};

	for (const host of hosts) {
		const explicit = policy.hostPolicies[String(host.id)] || null;
		const hostEffective = explicit
			? {
					proxyHostId: host.id,
					...explicit,
					autoBlockEnabled: policy.autoBlockEnabled && ["protect", "strict"].includes(explicit.mode),
					inherited: false,
				}
			: { ...globalEffective, proxyHostId: host.id };

		for (const domain of host.domain_names || []) {
			const normalized = normalizeHostname(domain);
			if (!normalized) continue;
			if (normalized.startsWith("*.")) {
				wildcards.push({ suffix: normalized.slice(1), effective: hostEffective });
			} else {
				exact.set(normalized, hostEffective);
			}
		}
	}

	wildcards.sort((left, right) => right.suffix.length - left.suffix.length);
	return {
		resolve: (hostname) => {
			const normalized = normalizeHostname(hostname);
			const direct = exact.get(normalized);
			if (direct) return direct;
			const wildcard = wildcards.find((entry) => normalized.endsWith(entry.suffix) && normalized !== entry.suffix.slice(1));
			return wildcard?.effective || globalEffective;
		},
	};
};

const getHostPolicyContext = async (policy) => {
	if (Object.keys(policy.hostPolicies).length === 0) return createHostPolicyContext(policy);
	return createHostPolicyContext(policy, await listProxyHostsForSecurity());
};

const decorateEventsWithHostPolicy = (events, context) =>
	events
		.map((event) => {
			const effective = context.resolve(event.host);
			return { ...event, proxyHostId: effective.proxyHostId, securityMode: effective.mode };
		})
		.filter((event) => event.securityMode !== "off");
const monitorThreats = async () => {
	const events = await loadLiveEvents(MAX_EVENT_LIMIT);
	const policy = await readPolicyUnsafe();
	if (!monitorPrimed) {
		await persistArchivedEventsBestEffort(events, policy);
		for (const event of events) rememberEvent(event);
		monitorPrimed = true;
		return;
	}

	const fresh = [];
	for (const event of [...events].reverse()) {
		if (rememberEvent(event)) fresh.push(event);
	}
	if (fresh.length === 0) return;
	await persistArchivedEventsBestEffort(fresh, policy);

	if (!policy.autoBlockEnabled) return;
	const hostPolicyContext = await getHostPolicyContext(policy);

	await withSecurityConfigMutation(async () => {
		const blocks = await purgeExpiredUnsafe();
		const rateLimits = await purgeExpiredRateLimitsUnsafe();
		const blockedIps = new Set(blocks.map((block) => block.ip));
		const rateLimitedIps = new Set(rateLimits.map((entry) => entry.ip));
		const blockAdditions = [];
		const rateLimitAdditions = [];

		for (const event of fresh) {
			const effective = hostPolicyContext.resolve(event.host);
			if (!effective.autoBlockEnabled || blockedIps.has(event.ip)) continue;

			const candidatePolicy = {
				...policy,
				autoRateLimitThreshold: effective.autoRateLimitThreshold,
				autoBlockThreshold: effective.autoBlockThreshold,
			};

			if (eventIsAutoBlockCandidate(event, candidatePolicy)) {
				const block = createBlockRecord({
					ip: event.ip,
					durationMinutes: effective.autoBlockMinutes,
					source: "auto-response",
					reason: `Auto response (${effective.mode}): risk ${event.risk}; host ${event.host}; ${event.signals
						.map((signal) => signal.id)
						.join(", ")}`,
				});
				blockAdditions.push(block);
				blockedIps.add(event.ip);
				continue;
			}

			if (
				!rateLimitedIps.has(event.ip) &&
				eventIsAutoRateLimitCandidate(event, candidatePolicy)
			) {
				const entry = createRateLimitRecord({
					ip: event.ip,
					durationMinutes: effective.autoRateLimitMinutes,
					source: "auto-rate-limit",
					reason: `Auto soft restriction (${effective.mode}): risk ${event.risk}; host ${event.host}; ${event.signals
						.map((signal) => signal.id)
						.join(", ")}`,
				});
				rateLimitAdditions.push(entry);
				rateLimitedIps.add(event.ip);
			}
		}

		if (rateLimitAdditions.length > 0) {
			await commitRateLimitState(rateLimits, [...rateLimits, ...rateLimitAdditions]);
			for (const entry of rateLimitAdditions) {
				await recordResponseAction("rate_limit", "started", entry);
				logger.warn(`HYROVI Sec auto-rate-limited ${entry.ip} until ${entry.expiresAt}: ${entry.reason}`);
			}
		}

		if (blockAdditions.length > 0) {
			await commitBlockState(blocks, [...blocks, ...blockAdditions]);
			for (const block of blockAdditions) {
				await recordResponseAction("block", "started", block);
				logger.warn(`HYROVI Sec auto-blocked ${block.ip} until ${block.expiresAt}: ${block.reason}`);
			}
		}
	});
};

const attackSessionId = (ip, firstSeen) =>
	createHash("sha256").update(`${ip}|${firstSeen || ""}`).digest("hex").slice(0, 24);

const sessionRequestPatterns = (timeline) => {
	const groups = new Map();
	for (const event of timeline) {
		const key = [event.host, event.method, event.path].join("|");
		let group = groups.get(key);
		if (!group) {
			group = {
				host: event.host,
				method: event.method,
				path: event.path,
				count: 0,
				maxRisk: 0,
				statuses: new Set(),
			};
			groups.set(key, group);
		}
		group.count += 1;
		group.maxRisk = Math.max(group.maxRisk, event.risk);
		if (event.status) group.statuses.add(event.status);
	}

	return [...groups.values()]
		.map((group) => ({ ...group, statuses: [...group.statuses].sort((a, b) => a - b) }))
		.sort((a, b) => b.count - a.count || b.maxRisk - a.maxRisk)
		.slice(0, 20);
};

const buildAttackSessions = (events) => {
	const suspicious = events.filter((event) => event.risk >= 40);
	const orderedSuspicious = [...suspicious].sort((a, b) => {
		const aTime = parseTimestamp(a.timestamp)?.getTime() || 0;
		const bTime = parseTimestamp(b.timestamp)?.getTime() || 0;
		return aTime - bTime;
	});
	const sessionsByIp = new Map();
	const attackSessions = [];

	for (const event of orderedSuspicious) {
		const eventTime = parseTimestamp(event.timestamp)?.getTime() || 0;
		let session = sessionsByIp.get(event.ip);
		if (!session || eventTime - session.lastSeenMs > SESSION_WINDOW_MS) {
			const firstSeen = event.timestamp || event.requestId || "";
			session = {
				id: attackSessionId(event.ip, firstSeen),
				ip: event.ip,
				requests: 0,
				maxRisk: 0,
				signals: new Set(),
				hosts: new Set(),
				firstSeen: event.timestamp,
				lastSeen: event.timestamp,
				lastSeenMs: eventTime,
				timeline: [],
			};
			attackSessions.push(session);
			sessionsByIp.set(event.ip, session);
		}

		session.requests += 1;
		session.maxRisk = Math.max(session.maxRisk, event.risk);
		for (const signal of event.signals) session.signals.add(signal.id);
		if (event.host) session.hosts.add(event.host);
		session.timeline.push(event);
		session.lastSeen = event.timestamp;
		session.lastSeenMs = eventTime;
	}

	return attackSessions;
};

const attackSessionSummary = (session, blocks = [], rateLimits = []) => {
	const block = blocks.find((entry) => entry.ip === session.ip);
	const rateLimit = rateLimits.find((entry) => entry.ip === session.ip);
	return {
		id: session.id,
		ip: session.ip,
		requests: session.requests,
		maxRisk: session.maxRisk,
		signals: [...session.signals],
		hosts: [...session.hosts],
		firstSeen: session.firstSeen,
		lastSeen: session.lastSeen,
		activeResponse: block ? "block" : rateLimit ? "rate_limit" : null,
	};
};

const attackSessionDetail = (session, blocks = [], rateLimits = []) => {
	const activeResponses = [];
	for (const block of blocks) {
		if (block.ip === session.ip) activeResponses.push({ type: "block", ...block });
	}
	for (const rateLimit of rateLimits) {
		if (rateLimit.ip === session.ip) activeResponses.push({ type: "rate_limit", ...rateLimit });
	}
	return {
		...attackSessionSummary(session, blocks, rateLimits),
		requestPatterns: sessionRequestPatterns(session.timeline),
		activeResponses,
		timeline: session.timeline.map((event) => ({
			timestamp: event.timestamp,
			requestId: event.requestId,
			host: event.host,
			method: event.method,
			path: event.path,
			status: event.status,
			userAgent: event.userAgent,
			risk: event.risk,
			severity: event.severity,
			signals: event.signals,
			requestLength: event.requestLength,
			bytesSent: event.bytesSent,
			requestTime: event.requestTime,
			upstreamStatus: event.upstreamStatus,
			proxyHostId: event.proxyHostId,
			securityMode: event.securityMode,
		})),
	};
};

const getEnabledHosts = (model) =>
	model
		.query()
		.where("is_deleted", 0)
		.andWhere("enabled", 1)
		.groupBy("id")
		.allowGraph(model.defaultAllowGraph)
		.withGraphFetched(`[${model.defaultExpand.join(", ")}]`)
		.orderBy(...model.defaultOrder);

const internalSecurity = {
	prepare: async () => {
		await ensureSecurityDir();
		await fs.promises.mkdir(EVENT_ARCHIVE_DIR, { recursive: true });
		try {
			await fs.promises.access(BLOCKS_CONF_FILE);
		} catch (_) {
			await fs.promises.writeFile(BLOCKS_CONF_FILE, "", "utf8");
		}
		try {
			await fs.promises.access(POLICY_FILE);
		} catch (_) {
			await writePolicyUnsafe(DEFAULT_POLICY);
		}

		const startupPolicy = await readPolicyUnsafe();
		await purgeArchivedEvents(startupPolicy.eventRetentionDays);
		for (const event of await loadArchivedEvents(ARCHIVED_EVENT_ID_LIMIT, startupPolicy.eventRetentionDays)) {
			rememberArchivedEvent(event);
		}

		// blocks.json is the durable source of truth. Reconcile the generated deny
		// include on every backend start so an interrupted write/reload sequence
		// cannot leave Nginx enforcing a stale block set.
		await withSecurityConfigMutation(async () => {
			await synchronizeBlockConfigUnsafe();
			await synchronizeRateLimitConfigUnsafe();
		});

		try {
			await fs.promises.access(INSTRUMENTATION_MARKER);
			return { instrumented: true, regenerated: false };
		} catch (_) {
			// Existing NPM installations already have generated host configs. Regenerate
			// HTTP hosts once so the HYROVI Sec telemetry and location-level deny hooks
			// are present immediately after upgrading this fork.
		}

		const [proxyHosts, redirectionHosts, deadHosts] = await Promise.all([
			getEnabledHosts(proxyHostModel),
			getEnabledHosts(redirectionHostModel),
			getEnabledHosts(deadHostModel),
		]);

		await internalNginx.bulkGenerateConfigs("proxy_host", proxyHosts);
		await internalNginx.bulkGenerateConfigs("redirection_host", redirectionHosts);
		await internalNginx.bulkGenerateConfigs("dead_host", deadHosts);
		await internalNginx.test();
		await internalNginx.reload();
		await fs.promises.writeFile(INSTRUMENTATION_MARKER, `${new Date().toISOString()}\n`, "utf8");

		return {
			instrumented: true,
			regenerated: true,
			hosts: proxyHosts.length + redirectionHosts.length + deadHosts.length,
		};
	},

	initTimer: () => {
		const purge = () =>
			purgeExpired().catch((err) => logger.error("HYROVI Sec block expiry failed:", err.message));
		const purgeRateLimits = () =>
			purgeExpiredRateLimits().catch((err) => logger.error("HYROVI Sec rate-limit expiry failed:", err.message));
		const monitor = () =>
			monitorThreats().catch((err) => logger.error("HYROVI Sec monitor failed:", err.message));
		const purgeArchive = () =>
			readPolicyUnsafe()
				.then((policy) => purgeArchivedEvents(policy.eventRetentionDays))
				.catch((err) => logger.error("HYROVI Sec event retention failed:", err.message));
		purge();
		purgeRateLimits();
		purgeArchive();
		monitor();
		setInterval(purge, 60_000).unref();
		setInterval(purgeRateLimits, 60_000).unref();
		setInterval(purgeArchive, 60 * 60_000).unref();
		setInterval(monitor, MONITOR_INTERVAL_MS).unref();
	},

	getEvents: async (access, options = {}) => {
		await access.can("logs:list");
		const limit = clamp(Number.parseInt(options.limit, 10) || DEFAULT_EVENT_LIMIT, 1, MAX_EVENT_LIMIT);
		const minRisk = clamp(Number.parseInt(options.minRisk, 10) || 0, 0, 100);
		const policy = await readPolicyUnsafe();
		const events = await loadEventHistory(limit, policy);
		const hostPolicyContext = await getHostPolicyContext(policy);
		return decorateEventsWithHostPolicy(events, hostPolicyContext).filter((event) => event.risk >= minRisk);
	},
	getOverview: async (access) => {
		await access.can("logs:list");
		const [blocks, rateLimits, policy] = await Promise.all([
			purgeExpired(),
			purgeExpiredRateLimits(),
			readPolicyUnsafe(),
		]);
		const rawEvents = await loadEventHistory(MAX_EVENT_LIMIT, policy);
		const hostPolicyContext = await getHostPolicyContext(policy);
		const events = decorateEventsWithHostPolicy(rawEvents, hostPolicyContext);
		const suspicious = events.filter((event) => event.risk >= 40);
		const critical = events.filter((event) => event.risk >= 80);
		const publicSessions = buildAttackSessions(events)
			.map((session) => attackSessionSummary(session, blocks, rateLimits))
			.sort((a, b) => new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime() || b.maxRisk - a.maxRisk)
			.slice(0, 20);

		return {
			window: {
				analyzedRequests: events.length,
				maxBytes: MAX_SCAN_BYTES,
				sessionWindowMs: SESSION_WINDOW_MS,
				eventRetentionDays: policy.eventRetentionDays,
				eventArchiveMinRisk: policy.eventArchiveMinRisk,
			},
			requests: events.length,
			suspicious: suspicious.length,
			critical: critical.length,
			activeBlocks: blocks.length,
			activeRateLimits: rateLimits.length,
			automation: {
				mode: policy.autoBlockEnabled ? "enforce" : "observe",
				...policy,
				monitorIntervalMs: MONITOR_INTERVAL_MS,
			},
			attackSessions: publicSessions,
		};
	},

	getAttackSession: async (access, sessionId) => {
		await access.can("logs:list");
		const [blocks, rateLimits, actions, policy] = await Promise.all([
			purgeExpired(),
			purgeExpiredRateLimits(),
			loadSecurityActions(1000),
			readPolicyUnsafe(),
		]);
		const rawEvents = await loadEventHistory(MAX_EVENT_LIMIT, policy);
		const hostPolicyContext = await getHostPolicyContext(policy);
		const events = decorateEventsWithHostPolicy(rawEvents, hostPolicyContext);
		const session = buildAttackSessions(events).find((entry) => entry.id === sessionId);
		if (!session) throw new errs.ItemNotFoundError(sessionId);
		return {
			...attackSessionDetail(session, blocks, rateLimits),
			responseHistory: actions
				.filter((entry) => entry.ip === session.ip)
				.sort((a, b) => new Date(a.at).getTime() - new Date(b.at).getTime())
				.slice(-100),
		};
	},

	getPolicy: async (access) => {
		await access.can("logs:list");
		return readPolicyUnsafe();
	},

	updatePolicy: async (access, data) => {
		await access.can("users:list");
		const current = await readPolicyUnsafe();
		if (typeof data.trustedSources !== "undefined") {
			if (!Array.isArray(data.trustedSources)) throw new errs.ValidationError("Trusted sources must be an array");
			if (data.trustedSources.length > 200) throw new errs.ValidationError("Trusted sources are limited to 200 entries");
			const invalid = data.trustedSources.find((entry) => !normalizeTrustedSource(entry));
			if (typeof invalid !== "undefined") {
				throw new errs.ValidationError(`Invalid trusted source: ${String(invalid).slice(0, 120)}`);
			}
		}
		return writePolicyUnsafe({
			...current,
			...(typeof data.autoBlockEnabled === "boolean" ? { autoBlockEnabled: data.autoBlockEnabled } : {}),
			...(typeof data.autoRateLimitThreshold !== "undefined"
				? { autoRateLimitThreshold: data.autoRateLimitThreshold }
				: {}),
			...(typeof data.autoRateLimitMinutes !== "undefined"
				? { autoRateLimitMinutes: data.autoRateLimitMinutes }
				: {}),
			...(typeof data.autoBlockThreshold !== "undefined"
				? { autoBlockThreshold: data.autoBlockThreshold }
				: {}),
			...(typeof data.autoBlockMinutes !== "undefined" ? { autoBlockMinutes: data.autoBlockMinutes } : {}),
			...(typeof data.eventRetentionDays !== "undefined" ? { eventRetentionDays: data.eventRetentionDays } : {}),
			...(typeof data.eventArchiveMinRisk !== "undefined" ? { eventArchiveMinRisk: data.eventArchiveMinRisk } : {}),
			...(typeof data.trustedSources !== "undefined" ? { trustedSources: data.trustedSources } : {}),
		});
	},

	listHostPolicies: async (access) => {
		await access.can("logs:list");
		const [hosts, policy] = await Promise.all([listProxyHostsForSecurity(), readPolicyUnsafe()]);
		const globalMode = policy.autoBlockEnabled ? "protect" : "observe";
		return hosts.map((host) => {
			const explicit = policy.hostPolicies[String(host.id)] || null;
			return {
				id: host.id,
				domainNames: host.domain_names || [],
				enabled: host.enabled,
				policy: explicit,
				effective: explicit || {
					mode: globalMode,
					autoRateLimitThreshold: policy.autoRateLimitThreshold,
					autoRateLimitMinutes: policy.autoRateLimitMinutes,
					autoBlockThreshold: policy.autoBlockThreshold,
					autoBlockMinutes: policy.autoBlockMinutes,
				},
			};
		});
	},

	updateHostPolicy: async (access, hostId, data) => {
		await access.can("users:list");
		const id = Number.parseInt(hostId, 10);
		if (!Number.isInteger(id) || id < 1) throw new errs.ValidationError("Invalid proxy host ID");
		const host = await proxyHostModel.query().select("id").where("is_deleted", 0).andWhere("id", id).first();
		if (!host?.id) throw new errs.ItemNotFoundError(id);
		if (typeof data.mode !== "undefined" && !HOST_POLICY_MODES.has(data.mode)) {
			throw new errs.ValidationError("Security mode must be off, observe, protect or strict");
		}
		if (typeof data.autoRateLimitThreshold !== "undefined") {
			const threshold = Number.parseInt(data.autoRateLimitThreshold, 10);
			if (!Number.isInteger(threshold) || threshold < 40 || threshold > 100) {
				throw new errs.ValidationError("Auto-rate-limit threshold must be between 40 and 100");
			}
		}
		if (typeof data.autoRateLimitMinutes !== "undefined") {
			const minutes = Number.parseInt(data.autoRateLimitMinutes, 10);
			if (!Number.isInteger(minutes) || minutes < 1 || minutes > 43_200) {
				throw new errs.ValidationError("Auto-rate-limit duration must be between 1 and 43200 minutes");
			}
		}
		if (typeof data.autoBlockThreshold !== "undefined") {
			const threshold = Number.parseInt(data.autoBlockThreshold, 10);
			if (!Number.isInteger(threshold) || threshold < 80 || threshold > 100) {
				throw new errs.ValidationError("Auto-block threshold must be between 80 and 100");
			}
		}
		if (typeof data.autoBlockMinutes !== "undefined") {
			const minutes = Number.parseInt(data.autoBlockMinutes, 10);
			if (!Number.isInteger(minutes) || minutes < 1 || minutes > 43_200) {
				throw new errs.ValidationError("Auto-block duration must be between 1 and 43200 minutes");
			}
		}

		const current = await readPolicyUnsafe();
		if (Object.keys(current.hostPolicies).length >= MAX_HOST_POLICIES && !current.hostPolicies[String(id)]) {
			throw new errs.ValidationError(`Host policies are limited to ${MAX_HOST_POLICIES} entries`);
		}
		const existing = current.hostPolicies[String(id)] || {
			mode: "observe",
			autoRateLimitThreshold: current.autoRateLimitThreshold,
			autoRateLimitMinutes: current.autoRateLimitMinutes,
			autoBlockThreshold: current.autoBlockThreshold,
			autoBlockMinutes: current.autoBlockMinutes,
		};
		const draft = { ...existing, ...data };
		if (!current.hostPolicies[String(id)] && data.mode === "strict") {
			if (typeof data.autoRateLimitThreshold === "undefined") delete draft.autoRateLimitThreshold;
			if (typeof data.autoBlockThreshold === "undefined") delete draft.autoBlockThreshold;
		}
		const nextHostPolicy = normalizeHostPolicy(draft, current);
		const updated = await writePolicyUnsafe({
			...current,
			hostPolicies: { ...current.hostPolicies, [String(id)]: nextHostPolicy },
		});
		return updated.hostPolicies[String(id)];
	},

	deleteHostPolicy: async (access, hostId) => {
		await access.can("users:list");
		const id = Number.parseInt(hostId, 10);
		if (!Number.isInteger(id) || id < 1) throw new errs.ValidationError("Invalid proxy host ID");
		const current = await readPolicyUnsafe();
		if (!current.hostPolicies[String(id)]) return { success: true };
		const hostPolicies = { ...current.hostPolicies };
		delete hostPolicies[String(id)];
		await writePolicyUnsafe({ ...current, hostPolicies });
		return { success: true };
	},
	listRateLimits: async (access) => {
		await access.can("logs:list");
		return purgeExpiredRateLimits();
	},

	rateLimitIp: async (access, data) => {
		await access.can("users:list");
		return withSecurityConfigMutation(() =>
			addRateLimitUnsafe({
				ip: String(data.ip || "").trim(),
				durationMinutes: data.durationMinutes,
				reason: data.reason || "Manual HYROVI Sec rate limit",
				source: data.source || "manual",
			}),
		);
	},

	unrateLimitIp: async (access, id) => {
		await access.can("users:list");
		return withSecurityConfigMutation(async () => {
			const entries = await purgeExpiredRateLimitsUnsafe();
			const removed = entries.find((entry) => entry.id === id);
			const next = entries.filter((entry) => entry.id !== id);
			if (!removed) throw new errs.ItemNotFoundError(id);
			await commitRateLimitState(entries, next);
			await recordResponseAction("rate_limit", "removed", removed);
			return { success: true };
		});
	},
	listBlocks: async (access) => {
		await access.can("logs:list");
		return purgeExpired();
	},

	blockIp: async (access, data) => {
		await access.can("users:list");
		return withSecurityConfigMutation(() =>
			addBlockUnsafe({
				ip: String(data.ip || "").trim(),
				durationMinutes: data.durationMinutes,
				reason: data.reason || "Manual HYROVI Sec block",
				source: data.source || "manual",
			}),
		);
	},

	unblockIp: async (access, id) => {
		await access.can("users:list");
		return withSecurityConfigMutation(async () => {
			const blocks = await purgeExpiredUnsafe();
			const removed = blocks.find((block) => block.id === id);
			const next = blocks.filter((block) => block.id !== id);
			if (!removed) throw new errs.ItemNotFoundError(id);
			await commitBlockState(blocks, next);
			await recordResponseAction("block", "removed", removed);
			return { success: true };
		});
	},
};

export default internalSecurity;
