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
const INSTRUMENTATION_MARKER = `${SECURITY_DIR}/instrumentation-v1`;
const POLICY_FILE = `${SECURITY_DIR}/policy.json`;
const MAX_SCAN_BYTES = 4 * 1024 * 1024;
const DEFAULT_EVENT_LIMIT = 250;
const MAX_EVENT_LIMIT = 2000;
const SESSION_WINDOW_MS = 5 * 60 * 1000;
const MONITOR_INTERVAL_MS = 5_000;
const PROCESSED_EVENT_LIMIT = 5_000;
const DEFAULT_POLICY = Object.freeze({
	autoBlockEnabled: false,
	autoBlockThreshold: 95,
	autoBlockMinutes: 60,
});

const processedEventIds = new Set();
const processedEventOrder = [];
let monitorPrimed = false;
let blockMutationQueue = Promise.resolve();

const clamp = (value, min, max) => Math.max(min, Math.min(max, value));

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
		await handle.read(buffer, 0, size, stat.size - size);
		let text = buffer.toString("utf8");
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
	const now = Date.now();
	const recentByIp = new Map();

	for (const event of events) {
		const date = parseTimestamp(event.timestamp);
		if (!event.ip || !date || now - date.getTime() > 60_000) continue;
		const list = recentByIp.get(event.ip) || [];
		list.push(event);
		recentByIp.set(event.ip, list);
	}

	return events.map((event) => {
		const { risk: baseRisk, signals } = baseSignals(event);
		let risk = baseRisk;
		const recent = recentByIp.get(event.ip) || [];
		const denied = recent.filter((item) => [401, 403].includes(item.status)).length;
		const missing = recent.filter((item) => item.status === 404).length;
		const suspiciousPaths = new Set(
			recent.filter((item) => baseSignals(item).risk >= 30).map((item) => item.path),
		);

		const add = (id, score, label) => {
			if (signals.some((signal) => signal.id === id)) return;
			risk += score;
			signals.push({ id, score, label });
		};

		if (recent.length >= 120) add("request_burst", 25, `${recent.length} requests from this IP in 60s`);
		if (denied >= 10) add("auth_failure_burst", 35, `${denied} denied requests from this IP in 60s`);
		if (missing >= 20) add("path_enumeration", 25, `${missing} missing paths requested in 60s`);
		if (suspiciousPaths.size >= 5) add("reconnaissance_burst", 35, "Multiple suspicious paths probed");

		risk = clamp(risk, 0, 100);
		const severity = risk >= 80 ? "critical" : risk >= 60 ? "high" : risk >= 40 ? "medium" : risk >= 20 ? "low" : "normal";
		return { ...event, risk, severity, signals };
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

const withBlockMutation = (operation) => {
	const run = blockMutationQueue.then(operation, operation);
	blockMutationQueue = run.catch(() => undefined);
	return run;
};

const normalizePolicy = (value = {}) => ({
	autoBlockEnabled: value.autoBlockEnabled === true,
	autoBlockThreshold: clamp(Number.parseInt(value.autoBlockThreshold, 10) || DEFAULT_POLICY.autoBlockThreshold, 80, 100),
	autoBlockMinutes: clamp(Number.parseInt(value.autoBlockMinutes, 10) || DEFAULT_POLICY.autoBlockMinutes, 1, 43_200),
});

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
	if (event.risk < policy.autoBlockThreshold || isPrivateOrLoopback(event.ip)) return false;
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

const purgeExpired = () => withBlockMutation(purgeExpiredUnsafe);

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

	await withBlockMutation(async () => {
		const blocks = await purgeExpiredUnsafe();
		const blockedIps = new Set(blocks.map((block) => block.ip));
		const additions = [];
		for (const event of fresh) {
			if (blockedIps.has(event.ip) || !eventIsAutoBlockCandidate(event, policy)) continue;
			const block = createBlockRecord({
				ip: event.ip,
				durationMinutes: policy.autoBlockMinutes,
				source: "auto-response",
				reason: `Auto response: risk ${event.risk}; ${event.signals.map((signal) => signal.id).join(", ")}`,
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
		await withBlockMutation(synchronizeBlockConfigUnsafe);

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
		const monitor = () =>
			monitorThreats().catch((err) => logger.error("HYROVI Sec monitor failed:", err.message));
		purge();
		monitor();
		setInterval(purge, 60_000).unref();
		setInterval(monitor, MONITOR_INTERVAL_MS).unref();
	},

	getEvents: async (access, options = {}) => {
		await access.can("logs:list");
		const limit = clamp(Number.parseInt(options.limit, 10) || DEFAULT_EVENT_LIMIT, 1, MAX_EVENT_LIMIT);
		const minRisk = clamp(Number.parseInt(options.minRisk, 10) || 0, 0, 100);
		const events = await loadEvents(limit);
		return events.filter((event) => event.risk >= minRisk);
	},

	getOverview: async (access) => {
		await access.can("logs:list");
		const events = await loadEvents(1000);
		const [blocks, policy] = await Promise.all([purgeExpired(), readPolicyUnsafe()]);
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
		return writePolicyUnsafe({
			...current,
			...(typeof data.autoBlockEnabled === "boolean" ? { autoBlockEnabled: data.autoBlockEnabled } : {}),
			...(typeof data.autoBlockThreshold !== "undefined"
				? { autoBlockThreshold: data.autoBlockThreshold }
				: {}),
			...(typeof data.autoBlockMinutes !== "undefined" ? { autoBlockMinutes: data.autoBlockMinutes } : {}),
		});
	},

	listBlocks: async (access) => {
		await access.can("logs:list");
		return purgeExpired();
	},

	blockIp: async (access, data) => {
		await access.can("users:list");
		return withBlockMutation(() =>
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
		return withBlockMutation(async () => {
			const blocks = await purgeExpiredUnsafe();
			const next = blocks.filter((block) => block.id !== id);
			if (next.length === blocks.length) throw new errs.ItemNotFoundError(id);
			await commitBlockState(blocks, next);
			return { success: true };
		});
	},
};

export default internalSecurity;
