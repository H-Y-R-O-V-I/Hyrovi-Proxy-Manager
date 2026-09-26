import fs from "node:fs";
import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import errs from "../lib/error.js";

const CONTROL_PLANE_DIR = "/data/nginx/hyrovi-control-plane";
const NODES_FILE = `${CONTROL_PLANE_DIR}/nodes.json`;
const MAX_NODES = 100;
const MAX_CAPABILITIES = 32;
const MAX_ADDRESSES = 16;
const HEARTBEAT_STALE_MS = 90 * 1000;
const TOKEN_PREFIX = "hyrnode_";

let mutationQueue = Promise.resolve();

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

const normalizeNodeId = (value) => {
	const id = String(value || "").trim();
	if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,119}$/.test(id)) {
		throw new errs.ValidationError("Node ID must use letters, numbers, dot, underscore, colon or dash");
	}
	return id;
};

const normalizeName = (value) => {
	const name = boundedString(value, 120);
	if (!name) throw new errs.ValidationError("Node name is required");
	return name;
};

const normalizeStringList = (value, maxEntries, maxLength) => {
	if (typeof value === "undefined" || value === null) return [];
	if (!Array.isArray(value)) throw new errs.ValidationError("Expected an array");
	return [...new Set(value.map((entry) => boundedString(entry, maxLength)).filter(Boolean))].slice(0, maxEntries);
};

const hashToken = (token) => createHash("sha256").update(String(token || ""), "utf8").digest();

const publicNode = (node) => {
	const now = Date.now();
	const lastSeenMs = Date.parse(node.lastSeenAt || "");
	const status =
		node.mode === "local"
			? "online"
			: !node.enabled
				? "disabled"
				: Number.isFinite(lastSeenMs) && now - lastSeenMs <= HEARTBEAT_STALE_MS
					? "online"
					: node.lastSeenAt
						? "stale"
						: "pending";

	return {
		id: node.id,
		name: node.name,
		mode: node.mode,
		enabled: node.enabled,
		status,
		createdAt: node.createdAt,
		updatedAt: node.updatedAt,
		lastSeenAt: node.lastSeenAt || null,
		agent: node.agent || null,
		capabilities: node.capabilities || [],
		addresses: node.addresses || [],
		desiredRevision: Number.parseInt(node.desiredRevision, 10) || 0,
		appliedRevision: Number.parseInt(node.appliedRevision, 10) || 0,
	};
};

const writeJsonAtomic = async (filePath, value) => {
	await fs.promises.mkdir(CONTROL_PLANE_DIR, { recursive: true });
	const tmp = `${filePath}.tmp-${process.pid}-${randomUUID()}`;
	try {
		await fs.promises.writeFile(tmp, `${JSON.stringify(value, null, 2)}\n`, "utf8");
		await fs.promises.rename(tmp, filePath);
	} catch (err) {
		await fs.promises.unlink(tmp).catch(() => undefined);
		throw err;
	}
};

const readNodesUnsafe = async () => {
	try {
		const value = JSON.parse(await fs.promises.readFile(NODES_FILE, "utf8"));
		return Array.isArray(value) ? value : [];
	} catch (err) {
		if (err.code === "ENOENT") return [];
		if (err instanceof SyntaxError) throw new errs.ConfigurationError("Invalid HYROVI control-plane node state");
		throw err;
	}
};

const localNode = () =>
	publicNode({
		id: "local",
		name: process.env.HYROVI_NODE_NAME || "Local controller",
		mode: "local",
		enabled: true,
		createdAt: null,
		updatedAt: null,
		lastSeenAt: new Date().toISOString(),
		agent: {
			hostname: process.env.HOSTNAME || null,
			platform: process.platform,
			version: null,
			nginxVersion: null,
			uptimeSeconds: Math.floor(process.uptime()),
		},
		capabilities: ["proxy", "security", "certificates", "logs", "analytics", "provisioning"],
		addresses: [],
		desiredRevision: 0,
		appliedRevision: 0,
	});

const issueToken = () => `${TOKEN_PREFIX}${randomBytes(32).toString("base64url")}`;

const verifyBearerToken = (authorization, tokenHash) => {
	const value = String(authorization || "").trim();
	const match = /^Bearer\s+(.+)$/i.exec(value);
	if (!match) return false;
	const supplied = hashToken(match[1]);
	const expected = Buffer.from(String(tokenHash || ""), "hex");
	return expected.length === supplied.length && timingSafeEqual(expected, supplied);
};

const prepare = async () => {
	await fs.promises.mkdir(CONTROL_PLANE_DIR, { recursive: true });
	try {
		await fs.promises.access(NODES_FILE, fs.constants.F_OK);
	} catch (err) {
		if (err.code !== "ENOENT") throw err;
		await writeJsonAtomic(NODES_FILE, []);
	}
};

const listNodes = async () => {
	const nodes = await readNodesUnsafe();
	return [localNode(), ...nodes.map(publicNode)];
};

const getNode = async (id) => {
	const nodeId = normalizeNodeId(id);
	if (nodeId === "local") return localNode();
	const nodes = await readNodesUnsafe();
	const node = nodes.find((entry) => entry.id === nodeId);
	if (!node) throw new errs.ItemNotFoundError(nodeId);
	return publicNode(node);
};

const createNode = (input = {}) =>
	withMutation(async () => {
		const nodes = await readNodesUnsafe();
		if (nodes.length >= MAX_NODES) throw new errs.ValidationError(`HYROVI control plane is limited to ${MAX_NODES} remote nodes`);
		const name = normalizeName(input.name);
		const id = input.id ? normalizeNodeId(input.id) : `node-${randomUUID()}`;
		if (id === "local" || nodes.some((entry) => entry.id === id)) {
			throw new errs.ValidationError("Node ID is already in use");
		}
		const token = issueToken();
		const now = new Date().toISOString();
		const node = {
			id,
			name,
			mode: "remote",
			enabled: input.enabled !== false,
			tokenHash: hashToken(token).toString("hex"),
			createdAt: now,
			updatedAt: now,
			lastSeenAt: null,
			agent: null,
			capabilities: [],
			addresses: [],
			desiredRevision: 0,
			appliedRevision: 0,
		};
		await writeJsonAtomic(NODES_FILE, [...nodes, node]);
		return { node: publicNode(node), bootstrapToken: token };
	});

const updateNode = (id, input = {}) =>
	withMutation(async () => {
		const nodeId = normalizeNodeId(id);
		if (nodeId === "local") throw new errs.ValidationError("The local controller node cannot be edited here");
		const nodes = await readNodesUnsafe();
		const index = nodes.findIndex((entry) => entry.id === nodeId);
		if (index < 0) throw new errs.ItemNotFoundError(nodeId);
		const next = {
			...nodes[index],
			...(typeof input.name !== "undefined" ? { name: normalizeName(input.name) } : {}),
			...(typeof input.enabled !== "undefined" ? { enabled: Boolean(input.enabled) } : {}),
			updatedAt: new Date().toISOString(),
		};
		nodes[index] = next;
		await writeJsonAtomic(NODES_FILE, nodes);
		return publicNode(next);
	});

const deleteNode = (id) =>
	withMutation(async () => {
		const nodeId = normalizeNodeId(id);
		if (nodeId === "local") throw new errs.ValidationError("The local controller node cannot be deleted");
		const nodes = await readNodesUnsafe();
		const filtered = nodes.filter((entry) => entry.id !== nodeId);
		if (filtered.length === nodes.length) throw new errs.ItemNotFoundError(nodeId);
		await writeJsonAtomic(NODES_FILE, filtered);
		return { success: true };
	});

const rotateToken = (id) =>
	withMutation(async () => {
		const nodeId = normalizeNodeId(id);
		if (nodeId === "local") throw new errs.ValidationError("The local controller node does not use an agent token");
		const nodes = await readNodesUnsafe();
		const index = nodes.findIndex((entry) => entry.id === nodeId);
		if (index < 0) throw new errs.ItemNotFoundError(nodeId);
		const token = issueToken();
		nodes[index] = {
			...nodes[index],
			tokenHash: hashToken(token).toString("hex"),
			updatedAt: new Date().toISOString(),
		};
		await writeJsonAtomic(NODES_FILE, nodes);
		return { node: publicNode(nodes[index]), bootstrapToken: token };
	});

const authenticateNode = async (id, authorization) => {
	const nodeId = normalizeNodeId(id);
	if (nodeId === "local") throw new errs.ValidationError("The local controller does not use a remote node token");
	const nodes = await readNodesUnsafe();
	const node = nodes.find((entry) => entry.id === nodeId);
	if (!node) throw new errs.ItemNotFoundError(nodeId);
	if (!node.enabled) throw new errs.ValidationError("Node is disabled");
	if (!verifyBearerToken(authorization, node.tokenHash)) throw new errs.AuthError("Invalid HYROVI node token");
	return publicNode(node);
};

const heartbeat = (id, authorization, input = {}) =>
	withMutation(async () => {
		const nodeId = normalizeNodeId(id);
		if (nodeId === "local") throw new errs.ValidationError("Local node heartbeats are not accepted");
		const nodes = await readNodesUnsafe();
		const index = nodes.findIndex((entry) => entry.id === nodeId);
		if (index < 0) throw new errs.ItemNotFoundError(nodeId);
		const node = nodes[index];
		if (!node.enabled) throw new errs.ValidationError("Node is disabled");
		if (!verifyBearerToken(authorization, node.tokenHash)) throw new errs.AuthError("Invalid HYROVI node token");

		const now = new Date().toISOString();
		const capabilities = normalizeStringList(input.capabilities, MAX_CAPABILITIES, 80);
		const addresses = normalizeStringList(input.addresses, MAX_ADDRESSES, 120);
		const appliedRevision = Math.max(0, Number.parseInt(input.appliedRevision, 10) || 0);
		const agent = {
			hostname: boundedString(input.hostname, 120),
			platform: boundedString(input.platform, 80),
			version: boundedString(input.version, 80),
			nginxVersion: boundedString(input.nginxVersion, 80),
			uptimeSeconds: Math.max(0, Number.parseInt(input.uptimeSeconds, 10) || 0),
		};
		const updated = {
			...node,
			lastSeenAt: now,
			updatedAt: now,
			agent,
			capabilities,
			addresses,
			appliedRevision,
		};
		nodes[index] = updated;
		await writeJsonAtomic(NODES_FILE, nodes);
		return {
			node: publicNode(updated),
			desiredRevision: Number.parseInt(updated.desiredRevision, 10) || 0,
			serverTime: now,
		};
	});

export default {
	prepare,
	listNodes,
	getNode,
	createNode,
	updateNode,
	deleteNode,
	rotateToken,
	authenticateNode,
	heartbeat,
};
