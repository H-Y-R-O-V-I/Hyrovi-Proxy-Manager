import fs from "node:fs";
import net from "node:net";
import { createHash, randomUUID } from "node:crypto";
import errs from "../lib/error.js";
import proxyHostModel from "../models/proxy_host.js";
import internalNginx from "./nginx.js";

const SECURITY_DIR = "/data/nginx/hyrovi-security";
const GROUPS_FILE = `${SECURITY_DIR}/host-groups.json`;
const ACL_DIR = `${SECURITY_DIR}/host-acl`;
const HTTP_GEO_FILE = `${SECURITY_DIR}/host-groups-http.conf`;
const MAX_GROUPS = 100;
const MAX_HOSTS_PER_GROUP = 500;
const MAX_SOURCES_PER_GROUP = 250;
const MAX_HOST_ACCESS_POLICIES = 1000;
const ACCESS_MODES = new Set(["open", "allowlist", "denylist"]);
const HOST_ACCESS_MODES = new Set(["inherit", "open", "allowlist", "denylist"]);
const SECURITY_MODES = new Set(["inherit", "off", "observe", "protect", "strict"]);

let mutationQueue = Promise.resolve();

const withMutation = (fn) => {
	const next = mutationQueue.then(fn, fn);
	mutationQueue = next.catch(() => {});
	return next;
};

const normalizeSource = (value) => {
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
	const max = version === 4 ? 32 : 128;
	if (prefix < 0 || prefix > max) return null;
	return `${address}/${prefix}`;
};

const normalizeSources = (value) => {
	if (!Array.isArray(value)) return [];
	return [...new Set(value.map(normalizeSource).filter(Boolean))].slice(0, MAX_SOURCES_PER_GROUP);
};

const normalizeHostIds = (value) => {
	if (!Array.isArray(value)) return [];
	return [...new Set(value.map((id) => Number.parseInt(id, 10)).filter((id) => Number.isInteger(id) && id > 0))].slice(
		0,
		MAX_HOSTS_PER_GROUP,
	);
};

const normalizeGroup = (value = {}, existing = null) => {
	const name = String(value.name ?? existing?.name ?? "").replace(/[\r\n]+/g, " ").trim().slice(0, 80);
	if (!name) throw new errs.ValidationError("Group name is required");
	const description = String(value.description ?? existing?.description ?? "").trim().slice(0, 240);
	const accessMode = ACCESS_MODES.has(value.accessMode) ? value.accessMode : existing?.accessMode || "open";
	const securityMode = SECURITY_MODES.has(value.securityMode) ? value.securityMode : existing?.securityMode || "inherit";
	const sources = normalizeSources(typeof value.sources === "undefined" ? existing?.sources || [] : value.sources);
	if (accessMode === "allowlist" && sources.length === 0) {
		throw new errs.ValidationError("Allowlist groups require at least one IP address or CIDR");
	}
	const now = new Date().toISOString();
	return {
		id: existing?.id || randomUUID(),
		name,
		description,
		hostIds: normalizeHostIds(typeof value.hostIds === "undefined" ? existing?.hostIds || [] : value.hostIds),
		accessMode,
		sources,
		securityMode,
		createdAt: existing?.createdAt || now,
		updatedAt: existing && value === existing ? existing.updatedAt || now : now,
	};
};

const normalizeHostAccess = (value = {}) => {
	const accessMode = HOST_ACCESS_MODES.has(value.accessMode) ? value.accessMode : "inherit";
	const sources = normalizeSources(value.sources);
	if (accessMode === "allowlist" && sources.length === 0) {
		throw new errs.ValidationError("Allowlist host policies require at least one IP address or CIDR");
	}
	return { accessMode, sources };
};

const normalizeHostAccessMap = (value) => {
	if (!value || typeof value !== "object" || Array.isArray(value)) return {};
	const result = {};
	for (const [hostId, policy] of Object.entries(value).slice(0, MAX_HOST_ACCESS_POLICIES)) {
		if (!/^\d+$/.test(hostId) || Number(hostId) < 1) continue;
		try {
			const normalized = normalizeHostAccess(policy);
			if (normalized.accessMode !== "inherit") result[hostId] = normalized;
		} catch (_) {
			// Ignore malformed legacy entries instead of breaking ingress.
		}
	}
	return result;
};

const emptyState = () => ({ version: 2, groups: [], hostAccess: {} });

const readState = async () => {
	try {
		const parsed = JSON.parse(await fs.promises.readFile(GROUPS_FILE, "utf8"));
		if (!parsed || !Array.isArray(parsed.groups)) return emptyState();
		const groups = [];
		for (const candidate of parsed.groups.slice(0, MAX_GROUPS)) {
			try {
				groups.push(normalizeGroup(candidate, candidate));
			} catch (_) {
				// Ignore malformed legacy entries instead of breaking ingress.
			}
		}
		return { version: 2, groups, hostAccess: normalizeHostAccessMap(parsed.hostAccess) };
	} catch (err) {
		if (err.code === "ENOENT") return emptyState();
		throw err;
	}
};

const writeState = async (state) => {
	const tmp = `${GROUPS_FILE}.tmp-${process.pid}`;
	await fs.promises.writeFile(
		tmp,
		`${JSON.stringify({ version: 2, groups: state.groups, hostAccess: state.hostAccess || {} }, null, 2)}\n`,
		"utf8",
	);
	await fs.promises.rename(tmp, GROUPS_FILE);
};

const groupVariableName = (groupId) => `hsg_${createHash("sha256").update(String(groupId)).digest("hex").slice(0, 12)}`;
const hostVariableName = (hostId) => `hsh_${createHash("sha256").update(String(hostId)).digest("hex").slice(0, 12)}`;

const buildGeoConfig = (state) => {
	const lines = ["# Generated by HYROVI Sec host access policies. Do not edit manually."];
	for (const group of state.groups) {
		if (group.accessMode === "open") continue;
		const variable = groupVariableName(group.id);
		lines.push("", `geo ${variable} {`, "\tdefault 0;");
		for (const source of group.sources) lines.push(`\t${source} 1;`);
		lines.push("}");
	}
	for (const [hostId, policy] of Object.entries(state.hostAccess || {})) {
		if (!["allowlist", "denylist"].includes(policy.accessMode)) continue;
		const variable = hostVariableName(hostId);
		lines.push("", `geo ${variable} {`, "\tdefault 0;");
		for (const source of policy.sources) lines.push(`\t${source} 1;`);
		lines.push("}");
	}
	lines.push("");
	return lines.join("\n");
};

const groupForHost = (groups, hostId) => groups.find((group) => group.hostIds.includes(Number(hostId))) || null;

const buildHostAcl = (hostId, group, hostAccess) => {
	if (hostAccess && hostAccess.accessMode !== "inherit") {
		if (hostAccess.accessMode === "open") return "# HYROVI Sec host access override: open\n";
		const variable = hostVariableName(hostId);
		if (hostAccess.accessMode === "allowlist") {
			return `# HYROVI Sec host access override: allowlist\nif (${variable} = 0) { return 403; }\n`;
		}
		return `# HYROVI Sec host access override: denylist\nif (${variable} = 1) { return 403; }\n`;
	}
	if (!group || group.accessMode === "open") return "# HYROVI Sec inherited access: open\n";
	const variable = groupVariableName(group.id);
	if (group.accessMode === "allowlist") {
		return `# HYROVI Sec group: ${group.name} (allowlist)\nif (${variable} = 0) { return 403; }\n`;
	}
	return `# HYROVI Sec group: ${group.name} (denylist)\nif (${variable} = 1) { return 403; }\n`;
};

const listHostRows = () =>
	proxyHostModel.query().select("id", "domain_names", "enabled").where("is_deleted", 0).orderBy("id", "ASC");

const writeRuntimeFiles = async (state, hosts) => {
	await fs.promises.mkdir(ACL_DIR, { recursive: true });
	await fs.promises.writeFile(HTTP_GEO_FILE, buildGeoConfig(state), "utf8");
	const activeIds = new Set();
	for (const host of hosts) {
		activeIds.add(String(host.id));
		await fs.promises.writeFile(
			`${ACL_DIR}/${host.id}.conf`,
			buildHostAcl(host.id, groupForHost(state.groups, host.id), state.hostAccess?.[String(host.id)] || null),
			"utf8",
		);
	}
	for (const entry of await fs.promises.readdir(ACL_DIR, { withFileTypes: true })) {
		if (!entry.isFile() || !entry.name.endsWith(".conf")) continue;
		const id = entry.name.slice(0, -5);
		if (!activeIds.has(id)) await fs.promises.unlink(`${ACL_DIR}/${entry.name}`).catch(() => {});
	}
};

const syncNginxForState = async (state) => {
	const hosts = await listHostRows();
	await writeRuntimeFiles(state, hosts);
	await internalNginx.test();
	await internalNginx.reload();
	return hosts;
};

const validateHostsExist = async (hostIds) => {
	if (hostIds.length === 0) return;
	const rows = await proxyHostModel.query().select("id").whereIn("id", hostIds).where("is_deleted", 0);
	const found = new Set(rows.map((row) => row.id));
	const missing = hostIds.find((id) => !found.has(id));
	if (missing) throw new errs.ValidationError(`Proxy host ${missing} does not exist`);
};

const decorateGroups = async (groups) => {
	const hosts = await listHostRows();
	const byId = new Map(hosts.map((host) => [host.id, host]));
	return groups.map((group) => ({
		...group,
		hosts: group.hostIds.map((id) => byId.get(id)).filter(Boolean).map((host) => ({
			id: host.id,
			domainNames: host.domain_names || [],
			enabled: Boolean(host.enabled),
		})),
	}));
};

const applyNextState = async (current, next) => {
	try {
		await syncNginxForState(next);
		await writeState(next);
		return next;
	} catch (err) {
		await writeRuntimeFiles(current, await listHostRows()).catch(() => {});
		await internalNginx.reload().catch(() => {});
		throw err;
	}
};

const hostAccessView = (state, hostId) => {
	const id = Number(hostId);
	const direct = state.hostAccess?.[String(id)] || null;
	const group = groupForHost(state.groups, id);
	const effective = direct || (group ? { accessMode: group.accessMode, sources: group.sources } : { accessMode: "open", sources: [] });
	return {
		hostId: id,
		accessMode: direct?.accessMode || "inherit",
		sources: direct?.sources || [],
		policySource: direct ? "host" : group ? "group" : "default",
		effectiveAccessMode: effective.accessMode,
		effectiveSources: effective.sources,
		group: group ? { id: group.id, name: group.name, accessMode: group.accessMode, sources: group.sources } : null,
	};
};

const internalSecurityHostGroups = {
	prepare: async () => {
		await fs.promises.mkdir(SECURITY_DIR, { recursive: true });
		await fs.promises.mkdir(ACL_DIR, { recursive: true });
		try {
			await fs.promises.access(GROUPS_FILE);
		} catch (_) {
			await writeState(emptyState());
		}
		const state = await readState();
		await writeRuntimeFiles(state, await listHostRows());
		return state;
	},

	listInternal: async () => (await readState()).groups,

	list: async (access) => {
		await access.can("proxy_hosts:list");
		return decorateGroups((await readState()).groups);
	},

	create: async (access, data) => {
		await access.can("users:list");
		return withMutation(async () => {
			const current = await readState();
			if (current.groups.length >= MAX_GROUPS) throw new errs.ValidationError(`Host groups are limited to ${MAX_GROUPS}`);
			const group = normalizeGroup(data);
			await validateHostsExist(group.hostIds);
			const nextGroups = current.groups.map((entry) => ({
				...entry,
				hostIds: entry.hostIds.filter((id) => !group.hostIds.includes(id)),
			}));
			nextGroups.push(group);
			const next = await applyNextState(current, { ...current, version: 2, groups: nextGroups });
			return (await decorateGroups(next.groups)).find((entry) => entry.id === group.id);
		});
	},

	update: async (access, groupId, data) => {
		await access.can("users:list");
		return withMutation(async () => {
			const current = await readState();
			const existing = current.groups.find((group) => group.id === groupId);
			if (!existing) throw new errs.ItemNotFoundError(groupId);
			const updated = normalizeGroup(data, existing);
			await validateHostsExist(updated.hostIds);
			const nextGroups = current.groups.map((entry) => {
				if (entry.id === groupId) return updated;
				return { ...entry, hostIds: entry.hostIds.filter((id) => !updated.hostIds.includes(id)) };
			});
			const next = await applyNextState(current, { ...current, version: 2, groups: nextGroups });
			return (await decorateGroups(next.groups)).find((entry) => entry.id === groupId);
		});
	},

	delete: async (access, groupId) => {
		await access.can("users:list");
		return withMutation(async () => {
			const current = await readState();
			if (!current.groups.some((group) => group.id === groupId)) return { success: true };
			await applyNextState(current, { ...current, version: 2, groups: current.groups.filter((group) => group.id !== groupId) });
			return { success: true };
		});
	},

	getHostAccess: async (access, hostId) => {
		await access.can("proxy_hosts:list");
		const id = Number.parseInt(hostId, 10);
		if (!Number.isInteger(id) || id < 1) throw new errs.ValidationError("Invalid proxy host ID");
		await validateHostsExist([id]);
		return hostAccessView(await readState(), id);
	},

	updateHostAccess: async (access, hostId, data) => {
		const id = Number.parseInt(hostId, 10);
		await access.can("proxy_hosts:update", id);
		if (!Number.isInteger(id) || id < 1) throw new errs.ValidationError("Invalid proxy host ID");
		await validateHostsExist([id]);
		return withMutation(async () => {
			const current = await readState();
			const normalized = normalizeHostAccess(data);
			const existing = current.hostAccess?.[String(id)] || { accessMode: "inherit", sources: [] };
			if (JSON.stringify(existing) === JSON.stringify(normalized)) return hostAccessView(current, id);
			const hostAccess = { ...(current.hostAccess || {}) };
			if (normalized.accessMode === "inherit") delete hostAccess[String(id)];
			else hostAccess[String(id)] = normalized;
			const next = await applyNextState(current, { ...current, version: 2, hostAccess });
			return hostAccessView(next, id);
		});
	},

	deleteHostAccess: async (access, hostId) => {
		const id = Number.parseInt(hostId, 10);
		await access.can("proxy_hosts:update", id);
		if (!Number.isInteger(id) || id < 1) throw new errs.ValidationError("Invalid proxy host ID");
		await validateHostsExist([id]);
		return withMutation(async () => {
			const current = await readState();
			if (!current.hostAccess?.[String(id)]) return hostAccessView(current, id);
			const hostAccess = { ...current.hostAccess };
			delete hostAccess[String(id)];
			const next = await applyNextState(current, { ...current, version: 2, hostAccess });
			return hostAccessView(next, id);
		});
	},

	ensureHostAclFile: async (hostId) => {
		await fs.promises.mkdir(ACL_DIR, { recursive: true });
		const state = await readState();
		await fs.promises.writeFile(
			`${ACL_DIR}/${hostId}.conf`,
			buildHostAcl(hostId, groupForHost(state.groups, hostId), state.hostAccess?.[String(hostId)] || null),
			"utf8",
		);
	},

	removeHostAclFile: async (hostId) =>
		withMutation(async () => {
			const state = await readState();
			if (state.hostAccess?.[String(hostId)]) {
				const hostAccess = { ...state.hostAccess };
				delete hostAccess[String(hostId)];
				await writeState({ ...state, version: 2, hostAccess });
			}
			await fs.promises.unlink(`${ACL_DIR}/${hostId}.conf`).catch((err) => {
				if (err.code !== "ENOENT") throw err;
			});
		}),
};

export default internalSecurityHostGroups;
