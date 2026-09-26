import * as api from "./base";
import type { ProxyHost } from "./models";
import type { SecurityHostAccessPolicy, SecurityHostPolicy } from "./security";

export type ControlPlaneNodeStatus = "online" | "stale" | "pending" | "disabled";

export interface ControlPlaneNode {
	id: string;
	name: string;
	mode: "local" | "remote";
	enabled: boolean;
	status: ControlPlaneNodeStatus;
	createdAt: string | null;
	updatedAt: string | null;
	lastSeenAt: string | null;
	agent: {
		hostname: string | null;
		platform: string | null;
		version: string | null;
		nginxVersion: string | null;
		uptimeSeconds: number;
	} | null;
	capabilities: string[];
	addresses: string[];
	desiredRevision: number;
	appliedRevision: number;
}

export interface ControlPlaneNodeBootstrap {
	node: ControlPlaneNode;
	bootstrapToken: string;
}

export type ProvisioningJobStatus = "queued" | "running" | "completed" | "failed";

export interface ProxyHostProvisioningJob {
	id: string;
	type: "proxy_host.create";
	nodeId: string;
	status: ProvisioningJobStatus;
	createdAt: string;
	updatedAt: string;
	startedAt: string | null;
	finishedAt: string | null;
	attempts: number;
	result: {
		nodeId?: string;
		proxyHost?: {
			id: number;
			domainNames: string[];
			forwardScheme: string;
			forwardHost: string;
			forwardPort: number;
			certificateId: number;
		};
		cloudflare?: {
			tunnel: string;
			config: string;
			domains: string[];
			ingressAdded: string[];
		} | null;
		health?: {
			origin: Array<{ domain: string; status: number; ok: boolean }>;
			public: Array<{ domain: string; status: number; ok: boolean }>;
		};
	} | null;
	error: string | null;
}

export async function getControlPlaneNodes(): Promise<ControlPlaneNode[]> {
	return await api.get({ url: "/control-plane/nodes" });
}

export async function createControlPlaneNode(data: {
	name: string;
	id?: string;
	enabled?: boolean;
}): Promise<ControlPlaneNodeBootstrap> {
	return await api.post({ url: "/control-plane/nodes", data });
}

export async function updateControlPlaneNode(
	id: string,
	data: { name?: string; enabled?: boolean },
): Promise<ControlPlaneNode> {
	return await api.put({ url: `/control-plane/nodes/${encodeURIComponent(id)}`, data });
}

export async function deleteControlPlaneNode(id: string): Promise<{ success: boolean }> {
	return await api.del({ url: `/control-plane/nodes/${encodeURIComponent(id)}` });
}

export async function rotateControlPlaneNodeToken(id: string): Promise<ControlPlaneNodeBootstrap> {
	return await api.post({ url: `/control-plane/nodes/${encodeURIComponent(id)}/rotate-token` });
}

export async function provisionProxyHost(data: {
	nodeId: string;
	cloudflareTunnel: boolean;
	proxyHost: Omit<ProxyHost, "id"> & { id?: number };
	securityPolicy?: SecurityHostPolicy | null;
	securityAccess?: Pick<SecurityHostAccessPolicy, "accessMode" | "sources"> | null;
}): Promise<ProxyHostProvisioningJob> {
	return await api.post({
		url: "/control-plane/provision/proxy-hosts",
		data,
	});
}

export async function getProxyHostProvisioningJob(id: string): Promise<ProxyHostProvisioningJob> {
	return await api.get({ url: `/control-plane/provision/jobs/${encodeURIComponent(id)}` });
}

const wait = (milliseconds: number) => new Promise((resolve) => window.setTimeout(resolve, milliseconds));

export async function waitForProxyHostProvisioningJob(
	id: string,
	timeoutMs = 60_000,
): Promise<ProxyHostProvisioningJob> {
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		const job = await getProxyHostProvisioningJob(id);
		if (job.status === "completed") return job;
		if (job.status === "failed") throw new Error(job.error || "Proxy Host provisioning failed");
		await wait(700);
	}
	throw new Error("Proxy Host provisioning timed out. The job is still visible in HPM and may finish shortly.");
}
