import fs from "node:fs";
import { randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import errs from "../lib/error.js";

const CONTROL_PLANE_DIR = "/data/nginx/hyrovi-control-plane";
const PROVISIONING_DIR = `${CONTROL_PLANE_DIR}/provisioning`;
const JOBS_DIR = `${PROVISIONING_DIR}/jobs`;
const LOCAL_AGENT_TOKEN_FILE = `${PROVISIONING_DIR}/local-agent-token`;
const LEASE_MS = 2 * 60 * 1000;
const MAX_RESULT_MESSAGE = 2000;

let mutationQueue = Promise.resolve();

const withMutation = (operation) => {
	const run = mutationQueue.then(operation, operation);
	mutationQueue = run.catch(() => undefined);
	return run;
};

const normalizeNodeId = (value) => {
	const id = String(value || "").trim();
	if (id === "local") return id;
	if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,119}$/.test(id)) throw new errs.ValidationError("Invalid node ID");
	return id;
};

const bounded = (value, max = 240) => String(value || "").trim().slice(0, max);
const normalizeDomain = (value) => bounded(value, 253).toLowerCase().replace(/\.$/, "");

const findPendingDomainConflict = async (domains) => {
	const wanted = new Set((Array.isArray(domains) ? domains : []).map(normalizeDomain).filter(Boolean));
	if (!wanted.size) return null;
	const entries = await fs.promises.readdir(JOBS_DIR, { withFileTypes: true });
	for (const entry of entries) {
		if (!entry.isFile() || !entry.name.endsWith(".json")) continue;
		let job;
		try {
			job = JSON.parse(await fs.promises.readFile(`${JOBS_DIR}/${entry.name}`, "utf8"));
		} catch {
			continue;
		}
		if (job?.type !== "proxy_host.create" || !["queued", "running"].includes(job?.status)) continue;
		for (const domain of job?.input?.proxyHost?.domain_names || []) {
			const normalized = normalizeDomain(domain);
			if (wanted.has(normalized)) return { domain: normalized, jobId: job.id, nodeId: job.nodeId };
		}
	}
	return null;
};

const atomicWriteJson = async (path, value) => {
	const tmp = `${path}.tmp-${process.pid}-${randomUUID()}`;
	await fs.promises.writeFile(tmp, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
	await fs.promises.rename(tmp, path);
};

const prepare = async () => {
	await fs.promises.mkdir(JOBS_DIR, { recursive: true });
	try {
		const token = (await fs.promises.readFile(LOCAL_AGENT_TOKEN_FILE, "utf8")).trim();
		if (token.length < 32) throw new Error("invalid local agent token");
	} catch (err) {
		if (err.code !== "ENOENT" && err.message !== "invalid local agent token") throw err;
		const token = randomBytes(32).toString("hex");
		try {
			await fs.promises.writeFile(LOCAL_AGENT_TOKEN_FILE, `${token}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
		} catch (writeErr) {
			if (writeErr.code !== "EEXIST") throw writeErr;
		}
	}
	return { ready: true };
};

const verifyLocalToken = async (authorization) => {
	await prepare();
	const expected = (await fs.promises.readFile(LOCAL_AGENT_TOKEN_FILE, "utf8")).trim();
	const supplied = String(authorization || "").replace(/^Bearer\s+/i, "").trim();
	const a = Buffer.from(expected, "utf8");
	const b = Buffer.from(supplied, "utf8");
	if (a.length !== b.length || !timingSafeEqual(a, b)) throw new errs.AuthError("Invalid HYROVI local provisioner token");
	return true;
};

const jobPath = (id) => `${JOBS_DIR}/${id}.json`;

const readJob = async (id) => {
	try {
		return JSON.parse(await fs.promises.readFile(jobPath(id), "utf8"));
	} catch (err) {
		if (err.code === "ENOENT") throw new errs.ItemNotFoundError(id);
		if (err instanceof SyntaxError) throw new errs.ConfigurationError("Invalid provisioning job state");
		throw err;
	}
};

const enqueueProxyHost = ({ nodeId: nodeIdInput, proxyHost, cloudflareTunnel = true, securityPolicy, securityAccess, requestedBy }) =>
	withMutation(async () => {
		await prepare();
		const nodeId = normalizeNodeId(nodeIdInput);
		const pendingConflict = await findPendingDomainConflict(proxyHost?.domain_names);
		if (pendingConflict) {
			throw new errs.ValidationError(
				`${pendingConflict.domain} already has an active provisioning job for node ${pendingConflict.nodeId}`,
			);
		}
		const now = new Date().toISOString();
		const id = randomUUID();
		const job = {
			id,
			type: "proxy_host.create",
			nodeId,
			status: "queued",
			createdAt: now,
			updatedAt: now,
			startedAt: null,
			finishedAt: null,
			leaseUntil: null,
			attempts: 0,
			requestedBy: Number.parseInt(requestedBy, 10) || 0,
			input: {
				proxyHost,
				cloudflareTunnel: cloudflareTunnel !== false,
				securityPolicy: securityPolicy || null,
				securityAccess: securityAccess || null,
			},
			result: null,
			error: null,
		};
		await atomicWriteJson(jobPath(id), job);
		return job;
	});

const listJobsUnsafe = async () => {
	await prepare();
	const entries = await fs.promises.readdir(JOBS_DIR, { withFileTypes: true });
	const result = [];
	for (const entry of entries) {
		if (!entry.isFile() || !entry.name.endsWith(".json")) continue;
		try {
			result.push(JSON.parse(await fs.promises.readFile(`${JOBS_DIR}/${entry.name}`, "utf8")));
		} catch {
			// Ignore one malformed state file.
		}
	}
	return result;
};

const claimNext = (nodeIdInput) =>
	withMutation(async () => {
		const nodeId = normalizeNodeId(nodeIdInput);
		const nowMs = Date.now();
		const jobs = (await listJobsUnsafe())
			.filter((job) => {
				if (job.nodeId !== nodeId) return false;
				if (job.status === "queued") return true;
				return job.status === "running" && (!job.leaseUntil || Date.parse(job.leaseUntil) <= nowMs);
			})
			.sort((a, b) => Date.parse(a.createdAt) - Date.parse(b.createdAt));
		const job = jobs[0];
		if (!job) return null;
		const now = new Date().toISOString();
		const claimed = {
			...job,
			status: "running",
			startedAt: job.startedAt || now,
			updatedAt: now,
			leaseUntil: new Date(nowMs + LEASE_MS).toISOString(),
			attempts: (Number.parseInt(job.attempts, 10) || 0) + 1,
		};
		await atomicWriteJson(jobPath(claimed.id), claimed);
		return claimed;
	});

const complete = (nodeIdInput, jobId, input = {}) =>
	withMutation(async () => {
		const nodeId = normalizeNodeId(nodeIdInput);
		const job = await readJob(jobId);
		if (job.nodeId !== nodeId) throw new errs.ItemNotFoundError(jobId);
		if (!["running", "queued"].includes(job.status)) return job;
		const success = input.success === true;
		const now = new Date().toISOString();
		const updated = {
			...job,
			input: null,
			status: success ? "completed" : "failed",
			updatedAt: now,
			finishedAt: now,
			leaseUntil: null,
			result: success && input.result && typeof input.result === "object" ? input.result : null,
			error: success ? null : bounded(input.error || "Provisioning failed", MAX_RESULT_MESSAGE),
		};
		await atomicWriteJson(jobPath(job.id), updated);
		return updated;
	});

const getJob = async (id) => {
	const job = await readJob(id);
	return {
		id: job.id,
		type: job.type,
		nodeId: job.nodeId,
		status: job.status,
		createdAt: job.createdAt,
		updatedAt: job.updatedAt,
		startedAt: job.startedAt,
		finishedAt: job.finishedAt,
		attempts: job.attempts,
		result: job.result,
		error: job.error,
	};
};

export default {
	prepare,
	verifyLocalToken,
	enqueueProxyHost,
	claimNext,
	complete,
	getJob,
};
