import fs from "node:fs";
import { randomUUID } from "node:crypto";
import errs from "../lib/error.js";
import { global as logger } from "../logger.js";

const SECURITY_DIR = "/data/nginx/hyrovi-security";
const RULES_FILE = `${SECURITY_DIR}/detection-rules.json`;
const MAX_RULES = 100;
const MAX_METHODS = 16;
const MAX_STATUSES = 32;
const RESPONSE_MODES = new Set(["observe", "soft"]);

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

const readRulesUnsafe = async () => {
	try {
		const value = JSON.parse(await fs.promises.readFile(RULES_FILE, "utf8"));
		return Array.isArray(value) ? value : [];
	} catch (err) {
		if (err.code === "ENOENT") return [];
		if (err instanceof SyntaxError) throw new errs.ConfigurationError("Invalid HYROVI Sec detection-rule state");
		throw err;
	}
};

const normalizeMethods = (value) => {
	if (typeof value === "undefined" || value === null) return [];
	if (!Array.isArray(value)) throw new errs.ValidationError("Detection-rule methods must be an array");
	if (value.length > MAX_METHODS) throw new errs.ValidationError(`Detection-rule methods are limited to ${MAX_METHODS}`);
	const methods = [...new Set(value.map((entry) => String(entry || "").trim().toUpperCase()).filter(Boolean))];
	for (const method of methods) {
		if (!/^[A-Z][A-Z0-9_-]{0,19}$/.test(method)) {
			throw new errs.ValidationError("Detection-rule HTTP method is invalid");
		}
	}
	return methods;
};

const normalizeStatuses = (value) => {
	if (typeof value === "undefined" || value === null) return [];
	if (!Array.isArray(value)) throw new errs.ValidationError("Detection-rule statuses must be an array");
	if (value.length > MAX_STATUSES) throw new errs.ValidationError(`Detection-rule statuses are limited to ${MAX_STATUSES}`);
	const statuses = value.map((entry) => Number.parseInt(entry, 10));
	if (statuses.some((entry) => !Number.isInteger(entry) || entry < 100 || entry > 599)) {
		throw new errs.ValidationError("Detection-rule statuses must contain valid HTTP status codes");
	}
	return [...new Set(statuses)];
};

const normalizeMatch = (value = {}) => {
	if (!value || typeof value !== "object" || Array.isArray(value)) {
		throw new errs.ValidationError("Detection-rule match must be an object");
	}

	const host = boundedString(value.host, 255)?.toLowerCase() || null;
	const pathPrefix = boundedString(value.pathPrefix, 200);
	const pathContains = boundedString(value.pathContains, 160);
	const userAgentContains = boundedString(value.userAgentContains, 160)?.toLowerCase() || null;
	const methods = normalizeMethods(value.methods);
	const statuses = normalizeStatuses(value.statuses);

	if (host && !/^[a-z0-9._*:-]+$/.test(host)) {
		throw new errs.ValidationError("Detection-rule host contains unsupported characters");
	}
	if (host?.includes("*") && (!host.startsWith("*.") || host.slice(2).includes("*"))) {
		throw new errs.ValidationError("Detection-rule host wildcard is only supported as a leading *.");
	}
	if (pathPrefix && !pathPrefix.startsWith("/")) {
		throw new errs.ValidationError("Detection-rule path prefix must start with /");
	}
	if ([pathPrefix, pathContains, userAgentContains].some((entry) => entry && /[\r\n]/.test(entry))) {
		throw new errs.ValidationError("Detection-rule text matchers cannot contain line breaks");
	}

	const match = { host, pathPrefix, pathContains, methods, statuses, userAgentContains };
	if (!host && !pathPrefix && !pathContains && methods.length === 0 && statuses.length === 0 && !userAgentContains) {
		throw new errs.ValidationError("Detection rule requires at least one matcher");
	}
	return match;
};

const normalizeRuleInput = (input = {}, existing = null) => {
	if (!input || typeof input !== "object" || Array.isArray(input)) {
		throw new errs.ValidationError("Detection rule must be an object");
	}
	const now = new Date().toISOString();
	const name = boundedString(input.name ?? existing?.name, 120);
	if (!name) throw new errs.ValidationError("Detection-rule name is required");
	const response = String(input.response ?? existing?.response ?? "observe").trim().toLowerCase();
	if (!RESPONSE_MODES.has(response)) {
		throw new errs.ValidationError("Detection-rule response must be observe or soft");
	}
	const rawScore = Number.parseInt(input.score ?? existing?.score, 10);
	const score = clamp(Number.isInteger(rawScore) ? rawScore : 20, 1, 60);
	const match = normalizeMatch(input.match ?? existing?.match ?? {});

	return {
		id: existing?.id || randomUUID(),
		name,
		enabled: typeof input.enabled === "boolean" ? input.enabled : existing?.enabled !== false,
		score,
		response,
		match,
		createdAt: existing?.createdAt || now,
		updatedAt: now,
	};
};

const listRules = async () =>
	(await readRulesUnsafe()).sort((left, right) => left.name.localeCompare(right.name) || left.id.localeCompare(right.id));

const listRulesForAnalysis = async () => {
	try {
		return await listRules();
	} catch (err) {
		logger.error(`HYROVI Sec custom detection rules unavailable; built-in detection continues: ${err.message}`);
		return [];
	}
};

const createRule = (input) =>
	withMutation(async () => {
		const rules = await readRulesUnsafe();
		if (rules.length >= MAX_RULES) throw new errs.ValidationError(`Detection rules are limited to ${MAX_RULES}`);
		const rule = normalizeRuleInput(input);
		await writeJsonAtomic(RULES_FILE, [...rules, rule]);
		return rule;
	});

const updateRule = (id, input) =>
	withMutation(async () => {
		const rules = await readRulesUnsafe();
		const index = rules.findIndex((rule) => rule.id === id);
		if (index < 0) throw new errs.ItemNotFoundError(id);
		const updated = normalizeRuleInput(input, rules[index]);
		rules[index] = updated;
		await writeJsonAtomic(RULES_FILE, rules);
		return updated;
	});

const deleteRule = (id) =>
	withMutation(async () => {
		const rules = await readRulesUnsafe();
		const next = rules.filter((rule) => rule.id !== id);
		if (next.length === rules.length) throw new errs.ItemNotFoundError(id);
		await writeJsonAtomic(RULES_FILE, next);
		return { success: true };
	});

const hostMatches = (pattern, host) => {
	if (!pattern) return true;
	const normalized = String(host || "").toLowerCase();
	if (pattern.startsWith("*.")) {
		const suffix = pattern.slice(1);
		return normalized.endsWith(suffix) && normalized !== suffix.slice(1);
	}
	return normalized === pattern;
};

const ruleMatches = (rule, event) => {
	if (!rule?.enabled) return false;
	const match = rule.match || {};
	if (!hostMatches(match.host, event.host)) return false;
	if (match.pathPrefix && !String(event.path || "").startsWith(match.pathPrefix)) return false;
	if (match.pathContains && !String(event.path || "").includes(match.pathContains)) return false;
	if (Array.isArray(match.methods) && match.methods.length > 0 && !match.methods.includes(event.method)) return false;
	if (Array.isArray(match.statuses) && match.statuses.length > 0 && !match.statuses.includes(event.status)) return false;
	if (
		match.userAgentContains &&
		!String(event.userAgent || "")
			.toLowerCase()
			.includes(match.userAgentContains)
	) {
		return false;
	}
	return true;
};

const matchRules = (rules, event) =>
	(Array.isArray(rules) ? rules : [])
		.filter((rule) => ruleMatches(rule, event))
		.map((rule) => ({
			id: `custom:${rule.response}:${rule.id}`,
			score: rule.score,
			label: `Custom rule: ${rule.name}`,
			ruleId: rule.id,
			response: rule.response,
		}));

const prepare = async () =>
	withMutation(async () => {
		await fs.promises.mkdir(SECURITY_DIR, { recursive: true });
		try {
			await fs.promises.access(RULES_FILE);
		} catch (_) {
			await writeJsonAtomic(RULES_FILE, []);
		}
	});

const internalSecurityDetectionRules = {
	prepare,
	listRules,
	listRulesForAnalysis,
	createRule,
	updateRule,
	deleteRule,
	matchRules,
};

export default internalSecurityDetectionRules;
