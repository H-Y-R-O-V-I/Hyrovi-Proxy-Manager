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

const portableRule = (rule) => ({
	name: rule.name,
	enabled: rule.enabled,
	score: rule.score,
	response: rule.response,
	match: rule.match,
});

const portableRuleKey = (rule) => JSON.stringify(portableRule(rule));

const exportRules = async () => ({
	version: 1,
	exportedAt: new Date().toISOString(),
	rules: (await listRules()).map(portableRule),
});

const importRules = (payload = {}) =>
	withMutation(async () => {
		if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
			throw new errs.ValidationError("Detection-rule import payload must be an object");
		}
		if (Number.parseInt(payload.version, 10) !== 1) {
			throw new errs.ValidationError("Unsupported detection-rule export version");
		}
		const mode = String(payload.mode || "merge").trim().toLowerCase();
		if (!["merge", "replace"].includes(mode)) {
			throw new errs.ValidationError("Detection-rule import mode must be merge or replace");
		}
		if (!Array.isArray(payload.rules)) {
			throw new errs.ValidationError("Detection-rule import requires a rules array");
		}
		if (payload.rules.length > MAX_RULES) {
			throw new errs.ValidationError(`Detection-rule import is limited to ${MAX_RULES} rules`);
		}

		const imported = payload.rules.map((rule) => normalizeRuleInput(rule));
		const existing = mode === "replace" ? [] : await readRulesUnsafe();
		const existingKeys = new Set(existing.map(portableRuleKey));
		const additions = [];
		let skipped = 0;

		for (const rule of imported) {
			const key = portableRuleKey(rule);
			if (existingKeys.has(key)) {
				skipped += 1;
				continue;
			}
			existingKeys.add(key);
			additions.push(rule);
		}

		const next = [...existing, ...additions];
		if (next.length > MAX_RULES) {
			throw new errs.ValidationError(`Detection rules are limited to ${MAX_RULES}; import would create ${next.length}`);
		}
		await writeJsonAtomic(RULES_FILE, next);
		return {
			mode,
			added: additions.length,
			skipped,
			total: next.length,
		};
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

const ruleMatches = (rule, event, ignoreEnabled = false) => {
	if (!rule || (!ignoreEnabled && !rule.enabled)) return false;
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

const summarizeRuleMatches = (rule, events, sampleLimit = 10) => {
	const matches = (Array.isArray(events) ? events : []).filter((event) => ruleMatches(rule, event, true));
	return {
		ruleId: rule.id || null,
		name: rule.name,
		enabled: rule.enabled !== false,
		response: rule.response,
		score: rule.score,
		hits: matches.length,
		uniqueIps: new Set(matches.map((event) => event.ip).filter(Boolean)).size,
		uniqueHosts: new Set(matches.map((event) => event.host).filter(Boolean)).size,
		firstHitAt: matches.length > 0 ? matches[matches.length - 1].timestamp || null : null,
		lastHitAt: matches.length > 0 ? matches[0].timestamp || null : null,
		maxObservedRisk: matches.reduce((max, event) => Math.max(max, Number(event.risk) || 0), 0),
		samples: matches.slice(0, clamp(Number.parseInt(sampleLimit, 10) || 10, 1, 20)).map((event) => ({
			timestamp: event.timestamp || null,
			requestId: event.requestId || null,
			host: String(event.host || ""),
			method: String(event.method || ""),
			path: String(event.path || ""),
			status: Number.parseInt(event.status, 10) || 0,
			ip: String(event.ip || ""),
			risk: Number(event.risk) || 0,
			severity: String(event.severity || "normal"),
		})),
	};
};

const analyzeRules = (rules, events) =>
	(Array.isArray(rules) ? rules : []).map((rule) => summarizeRuleMatches(rule, events, 5));

const simulateRule = (input, events) => {
	const rule = normalizeRuleInput({ ...input, enabled: true });
	return {
		rule: portableRule(rule),
		...summarizeRuleMatches(rule, events, 20),
		ruleId: null,
	};
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
	exportRules,
	importRules,
	analyzeRules,
	simulateRule,
	matchRules,
};

export default internalSecurityDetectionRules;
