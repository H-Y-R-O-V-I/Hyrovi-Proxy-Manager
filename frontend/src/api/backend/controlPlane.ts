import * as api from "./base";

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
