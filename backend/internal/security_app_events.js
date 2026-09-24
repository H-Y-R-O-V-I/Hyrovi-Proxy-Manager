import fs from "node:fs";
import net from "node:net";
import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import errs from "../lib/error.js";

const SECURITY_DIR = "/data/nginx/hyrovi-security";
const APP_EVENTS_DIR = `${SECURITY_DIR}/app-events`;
const POLICY_FILE = `${SECURITY_DIR}/policy.json`;
const MAX_FILE_BYTES = 4 * 1024 * 1024;
const MAX_SCAN_BYTES_PER_DAY = 512 * 1024;
const DEFAULT_RETENTION_DAYS = 14;
const MAX_LIST_LIMIT = 1000;
const MIN_TOKEN_LENGTH = 32;

const ALLOWED_EVENT_TYPES = new Set([
	"login_success",
	"login_failed",
	"permission_denied",
	"token_created",
	"token_revoked",
	"session_created",
	"session_revoked",
	"admin_endpoint_accessed",
	"device_registered",
	"device_removed",
	"password_changed",
	"account_locked",
	"suspicious_account_action",
]);

const ALLOWED_SEVERITIES = new Set(["info", "low", "medium", "high", "critical"]);

let mutationQueue = Promise.resolve();

const clamp = (value, min, max) => Math.max(min, Math.min(max, value));

const safeJsonParse = (line) => {
	try {
		return JSON.parse(line);
	} catch (_) {
		return null;
	}
};

const boundedString = (value, maxLength) => {
	if (typeof value === "undefined" || value === null) return null;
	const normalized = String(value).trim();
	if (!normalized) return null;
	return normalized.slice(0, maxLength);
};

const configuredToken = () => String(process.env.HYROVI_SEC_INGEST_TOKEN || "").trim();

const tokenConfigured = () => configuredToken().length >= MIN_TOKEN_LENGTH;

const tokenMatches = (candidate) => {
	const expected = configuredToken();
	if (expected.length < MIN_TOKEN_LENGTH || !candidate) return false;
	const expectedDigest = createHash("sha256").update(expected).digest();
	const candidateDigest = createHash("sha256").update(candidate).digest();
	return timingSafeEqual(expectedDigest, candidateDigest);
};

const parseBearerToken = (authorization) => {
	const match = /^Bearer\s+(.+)$/i.exec(String(authorization || "").trim());
	return match?.[1]?.trim() || "";
};

const assertAuthorized = (authorization) => {
	if (!tokenConfigured()) {
		throw new errs.ConfigurationError(
			`HYROVI Sec app-event ingest is disabled; set HYROVI_SEC_INGEST_TOKEN to at least ${MIN_TOKEN_LENGTH} characters`,
		);
	}
	if (!tokenMatches(parseBearerToken(authorization))) {
		throw new errs.TokenRevokedError("Invalid HYROVI Sec ingest token");
	}
};

const readRetentionDays = async () => {
	try {
		const policy = JSON.parse(await fs.promises.readFile(POLICY_FILE, "utf8"));
		const value = Number.parseInt(policy.eventRetentionDays, 10);
		return clamp(Number.isInteger(value) ? value : DEFAULT_RETENTION_DAYS, 1, 90);
	} catch (err) {
		if (err.code === "ENOENT" || err instanceof SyntaxError) return DEFAULT_RETENTION_DAYS;
		throw err;
	}
};

const readTail = async (filePath, maxBytes) => {
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

const writeTextAtomic = async (filePath, value) => {
	const tmp = `${filePath}.tmp-${process.pid}-${randomUUID()}`;
	try {
		await fs.promises.writeFile(tmp, value, "utf8");
		await fs.promises.rename(tmp, filePath);
	} catch (err) {
		await fs.promises.unlink(tmp).catch(() => undefined);
		throw err;
	}
};

const withMutation = (operation) => {
	const run = mutationQueue.then(operation, operation);
	mutationQueue = run.catch(() => undefined);
	return run;
};

const normalizeEvent = (input = {}, sourceIp = "") => {
	if (!input || typeof input !== "object" || Array.isArray(input)) {
		throw new errs.ValidationError("App security event must be an object");
	}

	const eventType = boundedString(input.event_type ?? input.eventType, 80);
	if (!eventType || !ALLOWED_EVENT_TYPES.has(eventType)) {
		throw new errs.ValidationError("Unsupported HYROVI Sec app event type");
	}

	const app = boundedString(input.app, 80);
	if (!app) throw new errs.ValidationError("App security event requires an app name");

	const severity = boundedString(input.severity, 20) || "info";
	if (!ALLOWED_SEVERITIES.has(severity)) {
		throw new errs.ValidationError("App security event severity must be info, low, medium, high or critical");
	}

	let timestamp = new Date().toISOString();
	if (typeof input.timestamp !== "undefined" && input.timestamp !== null) {
		const parsed = new Date(input.timestamp);
		if (Number.isNaN(parsed.getTime())) throw new errs.ValidationError("Invalid app security event timestamp");
		const skewMs = parsed.getTime() - Date.now();
		if (skewMs > 5 * 60 * 1000) {
			throw new errs.ValidationError("App security event timestamp is too far in the future");
		}
		if (skewMs < -90 * 24 * 60 * 60 * 1000) {
			throw new errs.ValidationError("App security event timestamp is older than 90 days");
		}
		timestamp = parsed.toISOString();
	}

	const ip = boundedString(input.ip, 64);
	if (ip && !net.isIP(ip)) throw new errs.ValidationError("Invalid app security event IP address");

	const normalizedSourceIp = boundedString(sourceIp, 64);
	const safeSourceIp = normalizedSourceIp && net.isIP(normalizedSourceIp) ? normalizedSourceIp : null;

	return {
		id: randomUUID(),
		timestamp,
		receivedAt: new Date().toISOString(),
		eventType,
		app,
		severity,
		ip,
		sourceIp: safeSourceIp,
		requestId: boundedString(input.request_id ?? input.requestId, 160),
		host: boundedString(input.host, 255),
		accountId: boundedString(input.account_id ?? input.accountId, 160),
		sessionId: boundedString(input.session_id ?? input.sessionId, 160),
		deviceId: boundedString(input.device_id ?? input.deviceId, 160),
		reason: boundedString(input.reason, 300),
	};
};

const archiveDate = (event) => event.timestamp.slice(0, 10);

const purgeExpiredFiles = async (retentionDays) => {
	let entries;
	try {
		entries = await fs.promises.readdir(APP_EVENTS_DIR, { withFileTypes: true });
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
		await fs.promises.unlink(`${APP_EVENTS_DIR}/${entry.name}`);
		removed += 1;
	}
	return removed;
};

const appendEvent = async (event) =>
	withMutation(async () => {
		await fs.promises.mkdir(APP_EVENTS_DIR, { recursive: true });
		const retentionDays = await readRetentionDays();
		await purgeExpiredFiles(retentionDays);

		const filePath = `${APP_EVENTS_DIR}/${archiveDate(event)}.jsonl`;
		try {
			const stat = await fs.promises.stat(filePath);
			if (stat.size >= MAX_FILE_BYTES) {
				const compacted = await readTail(filePath, Math.floor(MAX_FILE_BYTES / 2));
				await writeTextAtomic(filePath, compacted);
			}
		} catch (err) {
			if (err.code !== "ENOENT") throw err;
		}

		await fs.promises.appendFile(filePath, `${JSON.stringify(event)}\n`, "utf8");
		return event;
	});

const listArchiveFiles = async (retentionDays) => {
	try {
		const entries = await fs.promises.readdir(APP_EVENTS_DIR, { withFileTypes: true });
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

const listEvents = async (limit = 250) => {
	const boundedLimit = clamp(Number.parseInt(limit, 10) || 250, 1, MAX_LIST_LIMIT);
	const retentionDays = await readRetentionDays();
	const files = await listArchiveFiles(retentionDays);
	const events = [];

	for (const file of files) {
		const text = await readTail(`${APP_EVENTS_DIR}/${file}`, MAX_SCAN_BYTES_PER_DAY);
		for (const line of text.split("\n").filter(Boolean).reverse()) {
			const event = safeJsonParse(line);
			if (!event?.id || !event?.eventType || !event?.app) continue;
			events.push(event);
			if (events.length >= boundedLimit) return events;
		}
	}
	return events;
};

const ingest = async ({ authorization, body, sourceIp }) => {
	assertAuthorized(authorization);
	const event = normalizeEvent(body, sourceIp);
	return appendEvent(event);
};

const getStatus = async () => ({
	configured: tokenConfigured(),
	minTokenLength: MIN_TOKEN_LENGTH,
	retentionDays: await readRetentionDays(),
	allowedEventTypes: [...ALLOWED_EVENT_TYPES],
	allowedSeverities: [...ALLOWED_SEVERITIES],
});

const findCorrelatedEvents = async ({ requestId, ip, from, to, limit = 100 }) => {
	const events = await listEvents(MAX_LIST_LIMIT);
	const fromMs = from ? new Date(from).getTime() : null;
	const toMs = to ? new Date(to).getTime() : null;
	return events
		.filter((event) => {
			if (requestId && event.requestId === requestId) return true;
			if (!ip || event.ip !== ip) return false;
			const time = new Date(event.timestamp).getTime();
			if (!Number.isFinite(time)) return false;
			if (Number.isFinite(fromMs) && time < fromMs) return false;
			if (Number.isFinite(toMs) && time > toMs) return false;
			return true;
		})
		.slice(0, clamp(Number.parseInt(limit, 10) || 100, 1, 500));
};

const internalSecurityAppEvents = {
	ingest,
	listEvents,
	getStatus,
	findCorrelatedEvents,
};

export default internalSecurityAppEvents;
