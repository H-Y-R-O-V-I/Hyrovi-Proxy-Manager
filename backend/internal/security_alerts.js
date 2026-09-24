import fs from "node:fs";
import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import errs from "../lib/error.js";
import { global as logger } from "../logger.js";

const SECURITY_DIR = "/data/nginx/hyrovi-security";
const ALERTS_FILE = `${SECURITY_DIR}/alerts.json`;
const MAX_ALERTS = 1000;
const MAX_LIST_LIMIT = 500;
const MIN_FEED_TOKEN_LENGTH = 32;
const DEDUPE_WINDOW_MS = 5 * 60 * 1000;
const SEVERITIES = new Set(["info", "low", "medium", "high", "critical"]);
const STATUSES = new Set(["open", "acknowledged"]);

let mutationQueue = Promise.resolve();

const clamp = (value, min, max) => Math.max(min, Math.min(max, value));

const withMutation = (operation) => {
	const run = mutationQueue.then(operation, operation);
	mutationQueue = run.catch(() => undefined);
	return run;
};

const boundedString = (value, maxLength) => {
	if (typeof value === "undefined" || value === null) return null;
	const text = String(value).trim();
	return text ? text.slice(0, maxLength) : null;
};

const writeTextAtomic = async (filePath, value) => {
	await fs.promises.mkdir(SECURITY_DIR, { recursive: true });
	const tmp = `${filePath}.tmp-${process.pid}-${randomUUID()}`;
	try {
		await fs.promises.writeFile(tmp, value, "utf8");
		await fs.promises.rename(tmp, filePath);
	} catch (err) {
		await fs.promises.unlink(tmp).catch(() => undefined);
		throw err;
	}
};

const writeJsonAtomic = (filePath, value) => writeTextAtomic(filePath, `${JSON.stringify(value, null, 2)}\n`);

const readAlertsUnsafe = async () => {
	try {
		const value = JSON.parse(await fs.promises.readFile(ALERTS_FILE, "utf8"));
		return Array.isArray(value) ? value : [];
	} catch (err) {
		if (err.code === "ENOENT") return [];
		if (err instanceof SyntaxError) throw new errs.ConfigurationError("Invalid HYROVI Sec alert state");
		throw err;
	}
};

const normalizeSeverity = (value) => {
	const severity = String(value || "medium").trim().toLowerCase();
	if (!SEVERITIES.has(severity)) throw new errs.ValidationError("Invalid HYROVI Sec alert severity");
	return severity;
};

const normalizeType = (value) => {
	const type = String(value || "").trim();
	if (!/^[a-z0-9][a-z0-9._:-]{0,79}$/.test(type)) {
		throw new errs.ValidationError("Invalid HYROVI Sec alert type");
	}
	return type;
};

const alertDedupeKey = (input) =>
	createHash("sha256")
		.update(
			[
				String(input.type || ""),
				String(input.sourceIp || ""),
				String(input.host || ""),
				String(input.app || ""),
				String(input.requestId || ""),
				String(input.entityId || ""),
			].join("|"),
		)
		.digest("hex")
		.slice(0, 32);

const createAlert = (input = {}) =>
	withMutation(async () => {
		const now = new Date();
		const severity = normalizeSeverity(input.severity);
		const type = normalizeType(input.type);
		const title = boundedString(input.title, 180);
		if (!title) throw new errs.ValidationError("HYROVI Sec alert title is required");

		const alerts = await readAlertsUnsafe();
		const dedupeKey = boundedString(input.dedupeKey, 120) || alertDedupeKey(input);
		const existingIndex = alerts.findIndex((alert) => {
			if (alert.status !== "open" || alert.dedupeKey !== dedupeKey) return false;
			const updated = Date.parse(alert.updatedAt || alert.createdAt);
			return Number.isFinite(updated) && now.getTime() - updated <= DEDUPE_WINDOW_MS;
		});

		if (existingIndex >= 0) {
			const existing = alerts[existingIndex];
			const updated = {
				...existing,
				severity,
				title,
				detail: boundedString(input.detail, 500),
				sourceIp: boundedString(input.sourceIp, 64),
				host: boundedString(input.host, 255),
				app: boundedString(input.app, 80),
				requestId: boundedString(input.requestId, 160),
				entityId: boundedString(input.entityId, 160),
				count: clamp((Number.parseInt(existing.count, 10) || 1) + 1, 1, 1_000_000),
				updatedAt: now.toISOString(),
			};
			alerts[existingIndex] = updated;
			await writeJsonAtomic(ALERTS_FILE, alerts.slice(-MAX_ALERTS));
			return updated;
		}

		const alert = {
			id: randomUUID(),
			createdAt: now.toISOString(),
			updatedAt: now.toISOString(),
			status: "open",
			acknowledgedAt: null,
			severity,
			type,
			title,
			detail: boundedString(input.detail, 500),
			sourceIp: boundedString(input.sourceIp, 64),
			host: boundedString(input.host, 255),
			app: boundedString(input.app, 80),
			requestId: boundedString(input.requestId, 160),
			entityId: boundedString(input.entityId, 160),
			dedupeKey,
			count: 1,
		};
		const next = [...alerts, alert].slice(-MAX_ALERTS);
		await writeJsonAtomic(ALERTS_FILE, next);
		return alert;
	});

const createAlertBestEffort = async (input) => {
	try {
		return await createAlert(input);
	} catch (err) {
		logger.error(`HYROVI Sec alert persistence failed; protection continues: ${err.message}`);
		return null;
	}
};

const listAlerts = async ({ limit = 100, status, since } = {}) => {
	const alerts = await readAlertsUnsafe();
	const boundedLimit = clamp(Number.parseInt(limit, 10) || 100, 1, MAX_LIST_LIMIT);
	const normalizedStatus = status && STATUSES.has(String(status)) ? String(status) : null;
	const sinceMs = since ? Date.parse(String(since)) : null;
	return alerts
		.filter((alert) => !normalizedStatus || alert.status === normalizedStatus)
		.filter((alert) => {
			if (!Number.isFinite(sinceMs)) return true;
			const updated = Date.parse(alert.updatedAt || alert.createdAt);
			return Number.isFinite(updated) && updated > sinceMs;
		})
		.sort((left, right) => Date.parse(right.updatedAt) - Date.parse(left.updatedAt))
		.slice(0, boundedLimit);
};

const acknowledge = (id) =>
	withMutation(async () => {
		const alerts = await readAlertsUnsafe();
		const index = alerts.findIndex((alert) => alert.id === id);
		if (index < 0) throw new errs.ItemNotFoundError(id);
		if (alerts[index].status === "acknowledged") return alerts[index];
		const now = new Date().toISOString();
		alerts[index] = {
			...alerts[index],
			status: "acknowledged",
			acknowledgedAt: now,
			updatedAt: now,
		};
		await writeJsonAtomic(ALERTS_FILE, alerts);
		return alerts[index];
	});

const configuredFeedToken = () => String(process.env.HYROVI_SEC_ALERT_FEED_TOKEN || "").trim();

const feedConfigured = () => configuredFeedToken().length >= MIN_FEED_TOKEN_LENGTH;

const parseBearer = (authorization) => {
	const match = /^Bearer\s+(.+)$/i.exec(String(authorization || "").trim());
	return match?.[1]?.trim() || "";
};

const authorizeFeed = (authorization) => {
	const expected = configuredFeedToken();
	if (expected.length < MIN_FEED_TOKEN_LENGTH) {
		throw new errs.ConfigurationError(
			`HYROVI Sec alert feed is disabled; set HYROVI_SEC_ALERT_FEED_TOKEN to at least ${MIN_FEED_TOKEN_LENGTH} characters`,
		);
	}
	const candidate = parseBearer(authorization);
	if (!candidate) throw new errs.TokenRevokedError("Invalid HYROVI Sec alert feed token");
	const expectedDigest = createHash("sha256").update(expected).digest();
	const candidateDigest = createHash("sha256").update(candidate).digest();
	if (!timingSafeEqual(expectedDigest, candidateDigest)) {
		throw new errs.TokenRevokedError("Invalid HYROVI Sec alert feed token");
	}
	return true;
};

const getStatus = () => ({
	feedConfigured: feedConfigured(),
	minFeedTokenLength: MIN_FEED_TOKEN_LENGTH,
	maxAlerts: MAX_ALERTS,
});

const prepare = async () =>
	withMutation(async () => {
		await fs.promises.mkdir(SECURITY_DIR, { recursive: true });
		try {
			await fs.promises.access(ALERTS_FILE);
		} catch (_) {
			await writeJsonAtomic(ALERTS_FILE, []);
		}
	});

const internalSecurityAlerts = {
	prepare,
	createAlert,
	createAlertBestEffort,
	listAlerts,
	acknowledge,
	authorizeFeed,
	getStatus,
};

export default internalSecurityAlerts;
