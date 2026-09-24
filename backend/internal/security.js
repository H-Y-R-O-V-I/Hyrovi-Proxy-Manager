import fs from "node:fs";
import net from "node:net";
import { randomUUID } from "node:crypto";
import errs from "../lib/error.js";
import { global as logger } from "../logger.js";
import internalNginx from "./nginx.js";
import deadHostModel from "../models/dead_host.js";
import proxyHostModel from "../models/proxy_host.js";
import redirectionHostModel from "../models/redirection_host.js";

const SECURITY_LOG_FILE = "/data/logs/hyrovi-sec.log";
const SECURITY_DIR = "/data/nginx/hyrovi-security";
const BLOCKS_FILE = `${SECURITY_DIR}/blocks.json`;
const BLOCKS_CONF_FILE = `${SECURITY_DIR}/blocked-ips.conf`;
const RATE_LIMITS_FILE = `${SECURITY_DIR}/rate-limits.json`;
const RATE_LIMIT_GEO_FILE = `${SECURITY_DIR}/rate-limited-ips.geo`;
const INSTRUMENTATION_MARKER = `${SECURITY_DIR}/instrumentation-v2`;
const POLICY_FILE = `${SECURITY_DIR}/policy.json`;
const MAX_SCAN_BYTES = 4 * 1024 * 1024;
const DEFAULT_EVENT_LIMIT = 250;
const MAX_EVENT_LIMIT = 2000;
const SESSION_WINDOW_MS = 5 * 60 * 1000;
const REQUEST_CONTEXT_WINDOW_MS = 60_000;
const MONITOR_INTERVAL_MS = 5_000;
const PROCESSED_EVENT_LIMIT = 5_000;
const DEFAULT_POLICY = Object.freeze({
	autoBlockEnabled: false,
	autoBlockThreshold: 95,
	autoBlockMinutes: 60,
	trustedSources: [],
	hostPolicies: {},
});
const HOST_POLICY_MODES = new Set(["off", "observe", "protect", "strict"]);
const MAX_HOST_POLICIES = 500;

const processedEventIds = new Set();
const processedEventOrder = [];
let monitorPrimed = false;
let securityConfigMutationQueue = Promise.resolve();

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
	const defaultThreshold = mode === "strict" ? Math.min(globalPolicy.autoBlockThreshold || 95, 90) : globalPolicy.autoBlockThreshold || 95;
	return {
		mode,
		autoBlockThreshold: clamp(Number.parseInt(source.autoBlockThreshold, 10) || defaultThreshold, 80, 100),
		autoBlockMinutes: clamp(Number.parseInt(source.autoBlockMinutes, 10) || globalPolicy.autoBlockMinutes || 60, 1, 43_200),
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

const loadEvents = async (limit = DEFAULT_EVENT_LIMIT) => {
	const text = await readTail(SECURITY_LOG_FILE);
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

const withSecurityConfigMutation = (operation) => {
	const run = securityConfigMutationQueue.then(operation, operation);
	securityConfigMutationQueue = run.catch(() => undefined);
	return run;
};

const normalizePolicy = (value = {}) => {
	const normalized = {
		autoBlockEnabled: value.autoBlockEnabled === true,
		autoBlockThreshold: clamp(Number.parseInt(value.autoBlockThreshold, 10) || DEFAULT_POLICY.autoBlockThreshold, 80, 100),
		autoBlockMinutes: clamp(Number.parseInt(value.autoBlockMinutes, 10) || DEFAULT_POLICY.autoBlockMinutes, 1, 43_200),
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
	if (event.risk < policy.autoBlockThreshold || isPrivateOrLoopback(event.ip) || isTrustedSource(event.ip, policy.trustedSources)) return false;
	const ids = new Set(event.signals.map((signal) => signal.id));
	return (
		ids.has("path_traversal") ||
		ids.has("injection_probe") ||
		ids.has("reconnaissance_burst") ||
		ids.has("auth_failure_burst") ||
		(ids.has("sensitive_file_probe") && ids.has("scanner_user_agent"))
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
	await commitBlockState(blocks, active);
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
	await commitRateLimitState(entries, active);
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
	const events = await loadEvents(750);
	if (!monitorPrimed) {
		for (const event of events) rememberEvent(event);
		monitorPrimed = true;
		return;
	}

	const fresh = [];
	for (const event of [...events].reverse()) {
		if (rememberEvent(event)) fresh.push(event);
	}
	if (fresh.length === 0) return;

	const policy = await readPolicyUnsafe();
	if (!policy.autoBlockEnabled) return;
	const hostPolicyContext = await getHostPolicyContext(policy);

	await withSecurityConfigMutation(async () => {
		const blocks = await purgeExpiredUnsafe();
		const blockedIps = new Set(blocks.map((block) => block.ip));
		const additions = [];
		for (const event of fresh) {
			const effective = hostPolicyContext.resolve(event.host);
			const candidatePolicy = { ...policy, autoBlockThreshold: effective.autoBlockThreshold };
			if (!effective.autoBlockEnabled || blockedIps.has(event.ip) || !eventIsAutoBlockCandidate(event, candidatePolicy)) continue;
			const block = createBlockRecord({
				ip: event.ip,
				durationMinutes: effective.autoBlockMinutes,
				source: "auto-response",
				reason: `Auto response (${effective.mode}): risk ${event.risk}; host ${event.host}; ${event.signals.map((signal) => signal.id).join(", ")}`,
			});
			additions.push(block);
			blockedIps.add(event.ip);
		}

		if (additions.length === 0) return;
		const next = [...blocks, ...additions];
		await commitBlockState(blocks, next);
		for (const block of additions) {
			logger.warn(`HYROVI Sec auto-blocked ${block.ip} until ${block.expiresAt}: ${block.reason}`);
		}
	});
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
		purge();
		purgeRateLimits();
		monitor();
		setInterval(purge, 60_000).unref();
		setInterval(purgeRateLimits, 60_000).unref();
		setInterval(monitor, MONITOR_INTERVAL_MS).unref();
	},

	getEvents: async (access, options = {}) => {
		await access.can("logs:list");
		const limit = clamp(Number.parseInt(options.limit, 10) || DEFAULT_EVENT_LIMIT, 1, MAX_EVENT_LIMIT);
		const minRisk = clamp(Number.parseInt(options.minRisk, 10) || 0, 0, 100);
		const [events, policy] = await Promise.all([loadEvents(limit), readPolicyUnsafe()]);
		const hostPolicyContext = await getHostPolicyContext(policy);
		return decorateEventsWithHostPolicy(events, hostPolicyContext).filter((event) => event.risk >= minRisk);
	},

	getOverview: async (access) => {
		await access.can("logs:list");
		const [rawEvents, blocks, rateLimits, policy] = await Promise.all([
			loadEvents(1000),
			purgeExpired(),
			purgeExpiredRateLimits(),
			readPolicyUnsafe(),
		]);
		const hostPolicyContext = await getHostPolicyContext(policy);
		const events = decorateEventsWithHostPolicy(rawEvents, hostPolicyContext);
		const suspicious = events.filter((event) => event.risk >= 40);
		const critical = events.filter((event) => event.risk >= 80);
		const sessionsByIp = new Map();
		const attackSessions = [];

		const orderedSuspicious = [...suspicious].sort((a, b) => {
			const aTime = parseTimestamp(a.timestamp)?.getTime() || 0;
			const bTime = parseTimestamp(b.timestamp)?.getTime() || 0;
			return aTime - bTime;
		});

		for (const event of orderedSuspicious) {
			const eventTime = parseTimestamp(event.timestamp)?.getTime() || 0;
			let session = sessionsByIp.get(event.ip);

			if (!session || eventTime - session.lastSeenMs > SESSION_WINDOW_MS) {
				session = {
					id: `${event.ip}-${event.timestamp || event.requestId || attackSessions.length}`,
					ip: event.ip,
					requests: 0,
					maxRisk: 0,
					signals: new Set(),
					firstSeen: event.timestamp,
					lastSeen: event.timestamp,
					lastSeenMs: eventTime,
				};
				attackSessions.push(session);
				sessionsByIp.set(event.ip, session);
			}

			session.requests += 1;
			session.maxRisk = Math.max(session.maxRisk, event.risk);
			for (const signal of event.signals) session.signals.add(signal.id);
			session.lastSeen = event.timestamp;
			session.lastSeenMs = eventTime;
		}

		const publicSessions = attackSessions
			.map(({ lastSeenMs: _, ...session }) => ({ ...session, signals: [...session.signals] }))
			.sort((a, b) => new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime() || b.maxRisk - a.maxRisk)
			.slice(0, 20);

		return {
			window: { analyzedRequests: events.length, maxBytes: MAX_SCAN_BYTES, sessionWindowMs: SESSION_WINDOW_MS },
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
			...(typeof data.autoBlockThreshold !== "undefined"
				? { autoBlockThreshold: data.autoBlockThreshold }
				: {}),
			...(typeof data.autoBlockMinutes !== "undefined" ? { autoBlockMinutes: data.autoBlockMinutes } : {}),
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
			autoBlockThreshold: current.autoBlockThreshold,
			autoBlockMinutes: current.autoBlockMinutes,
		};
		const draft = { ...existing, ...data };
		if (!current.hostPolicies[String(id)] && data.mode === "strict" && typeof data.autoBlockThreshold === "undefined") {
			delete draft.autoBlockThreshold;
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
			const next = entries.filter((entry) => entry.id !== id);
			if (next.length === entries.length) throw new errs.ItemNotFoundError(id);
			await commitRateLimitState(entries, next);
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
			const next = blocks.filter((block) => block.id !== id);
			if (next.length === blocks.length) throw new errs.ItemNotFoundError(id);
			await commitBlockState(blocks, next);
			return { success: true };
		});
	},
};

export default internalSecurity;
