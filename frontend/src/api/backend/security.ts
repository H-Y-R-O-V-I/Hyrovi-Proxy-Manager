import * as api from "./base";

export interface SecuritySignal {
	id: string;
	score: number;
	label: string;
}

export interface SecurityEvent {
	timestamp: string | null;
	requestId: string | null;
	host: string;
	method: string;
	path: string;
	status: number;
	ip: string;
	userAgent: string;
	requestLength: number;
	bytesSent: number;
	requestTime: number;
	upstreamStatus: string;
	risk: number;
	severity: "normal" | "low" | "medium" | "high" | "critical";
	signals: SecuritySignal[];
}

export interface SecurityAttackSession {
	id: string;
	ip: string;
	requests: number;
	maxRisk: number;
	signals: string[];
	firstSeen: string;
	lastSeen: string;
}

export interface SecurityPolicy {
	autoBlockEnabled: boolean;
	autoBlockThreshold: number;
	autoBlockMinutes: number;
}

export interface SecurityOverview {
	window: {
		analyzedRequests: number;
		maxBytes: number;
		sessionWindowMs: number;
	};
	requests: number;
	suspicious: number;
	critical: number;
	activeBlocks: number;
	automation: SecurityPolicy & {
		mode: "observe" | "enforce";
		monitorIntervalMs: number;
	};
	attackSessions: SecurityAttackSession[];
}

export interface SecurityBlock {
	id: string;
	ip: string;
	reason: string;
	source: string;
	createdAt: string;
	expiresAt: string;
}

export async function getSecurityOverview(): Promise<SecurityOverview> {
	return await api.get({ url: "/security/overview" });
}

export async function getSecurityEvents(limit = 250, minRisk = 0): Promise<SecurityEvent[]> {
	return await api.get({
		url: "/security/events",
		params: { limit, minRisk },
	});
}

export async function getSecurityPolicy(): Promise<SecurityPolicy> {
	return await api.get({ url: "/security/policy" });
}

export async function updateSecurityPolicy(data: Partial<SecurityPolicy>): Promise<SecurityPolicy> {
	return await api.put({ url: "/security/policy", data });
}

export async function getSecurityBlocks(): Promise<SecurityBlock[]> {
	return await api.get({ url: "/security/blocks" });
}

export async function createSecurityBlock(data: {
	ip: string;
	durationMinutes?: number;
	reason?: string;
	source?: string;
}): Promise<SecurityBlock> {
	return await api.post({
		url: "/security/blocks",
		data,
	});
}

export async function deleteSecurityBlock(id: string): Promise<{ success: boolean }> {
	return await api.del({ url: `/security/blocks/${encodeURIComponent(id)}` });
}
