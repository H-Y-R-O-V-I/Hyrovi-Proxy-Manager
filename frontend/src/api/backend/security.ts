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
	proxyHostId: number | null;
	securityMode: SecurityHostMode;
	signals: SecuritySignal[];
}

export interface SecurityAttackSession {
	id: string;
	ip: string;
	requests: number;
	maxRisk: number;
	signals: string[];
	hosts: string[];
	firstSeen: string;
	lastSeen: string;
	activeResponse: "block" | "rate_limit" | null;
}

export interface SecurityAttackSessionPattern {
	host: string;
	method: string;
	path: string;
	count: number;
	maxRisk: number;
	statuses: number[];
}

export interface SecurityResponseHistoryEntry {
	id: string;
	at: string;
	type: "block" | "rate_limit";
	action: "started" | "removed" | "expired";
	responseId: string;
	ip: string;
	source: string;
	reason: string;
	createdAt: string | null;
	expiresAt: string | null;
}

export interface SecurityAttackSessionDetail extends SecurityAttackSession {
	requestPatterns: SecurityAttackSessionPattern[];
	activeResponses: Array<
		| (SecurityBlock & { type: "block" })
		| (SecurityRateLimit & { type: "rate_limit" })
	>;
	responseHistory: SecurityResponseHistoryEntry[];
	timeline: SecurityEvent[];
}

export interface SecuritySimilarEvent extends SecurityEvent {
	similarityScore: number;
}

export interface SecurityEventDetail extends SecurityEvent {
	similarRequests: SecuritySimilarEvent[];
	attackSession: SecurityAttackSession | null;
	activeResponses: Array<
		| (SecurityBlock & { type: "block" })
		| (SecurityRateLimit & { type: "rate_limit" })
	>;
	responseHistory: SecurityResponseHistoryEntry[];
}

export type SecurityHostMode = "off" | "observe" | "protect" | "strict";

export interface SecurityHostPolicy {
	mode: SecurityHostMode;
	autoRateLimitThreshold: number;
	autoRateLimitMinutes: number;
	autoBlockThreshold: number;
	autoBlockMinutes: number;
}

export interface SecurityHostPolicyEntry {
	id: number;
	domainNames: string[];
	enabled: boolean;
	policy: SecurityHostPolicy | null;
	effective: SecurityHostPolicy;
}
export interface SecurityPolicy {
	autoBlockEnabled: boolean;
	autoRateLimitThreshold: number;
	autoRateLimitMinutes: number;
	autoBlockThreshold: number;
	autoBlockMinutes: number;
	eventRetentionDays: number;
	eventArchiveMinRisk: number;
	trustedSources: string[];
	hostPolicies: Record<string, SecurityHostPolicy>;
}

export interface SecurityOverview {
	window: {
		analyzedRequests: number;
		maxBytes: number;
		sessionWindowMs: number;
		eventRetentionDays: number;
		eventArchiveMinRisk: number;
	};
	requests: number;
	suspicious: number;
	critical: number;
	activeBlocks: number;
	activeRateLimits: number;
	automation: SecurityPolicy & {
		mode: "observe" | "enforce";
		emergencyBypass: boolean;
		monitorIntervalMs: number;
	};
	attackSessions: SecurityAttackSession[];
}

export interface SecurityRateLimit {
	id: string;
	ip: string;
	reason: string;
	source: string;
	createdAt: string;
	expiresAt: string;
}

export type SecurityAppEventSeverity = "info" | "low" | "medium" | "high" | "critical";

export interface SecurityAppEvent {
	id: string;
	timestamp: string;
	receivedAt: string;
	eventType: string;
	app: string;
	severity: SecurityAppEventSeverity;
	ip: string | null;
	sourceIp: string | null;
	requestId: string | null;
	host: string | null;
	accountId: string | null;
	sessionId: string | null;
	deviceId: string | null;
	reason: string | null;
}

export interface SecurityAppEventsResponse {
	configured: boolean;
	minTokenLength: number;
	retentionDays: number;
	allowedEventTypes: string[];
	allowedSeverities: string[];
	events: SecurityAppEvent[];
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

export async function getSecurityAppEvents(limit = 100): Promise<SecurityAppEventsResponse> {
	return await api.get({ url: "/security/app-events", params: { limit } });
}

export async function getSecurityEvents(limit = 250, minRisk = 0): Promise<SecurityEvent[]> {
	return await api.get({
		url: "/security/events",
		params: { limit, minRisk },
	});
}

export async function getSecurityEventDetail(requestId: string): Promise<SecurityEventDetail> {
	return await api.get({ url: `/security/events/${encodeURIComponent(requestId)}` });
}

export async function getSecurityAttackSession(id: string): Promise<SecurityAttackSessionDetail> {
	return await api.get({ url: `/security/attack-sessions/${encodeURIComponent(id)}` });
}

export async function getSecurityPolicy(): Promise<SecurityPolicy> {
	return await api.get({ url: "/security/policy" });
}

export async function updateSecurityPolicy(data: Partial<SecurityPolicy>): Promise<SecurityPolicy> {
	return await api.put({ url: "/security/policy", data });
}

export async function getSecurityHostPolicies(): Promise<SecurityHostPolicyEntry[]> {
	return await api.get({ url: "/security/host-policies" });
}

export async function updateSecurityHostPolicy(
	id: number,
	data: Partial<SecurityHostPolicy>,
): Promise<SecurityHostPolicy> {
	return await api.put({ url: `/security/host-policies/${encodeURIComponent(id)}`, data });
}

export async function deleteSecurityHostPolicy(id: number): Promise<{ success: boolean }> {
	return await api.del({ url: `/security/host-policies/${encodeURIComponent(id)}` });
}
export async function getSecurityRateLimits(): Promise<SecurityRateLimit[]> {
	return await api.get({ url: "/security/rate-limits" });
}

export async function createSecurityRateLimit(data: {
	ip: string;
	durationMinutes?: number;
	reason?: string;
	source?: string;
}): Promise<SecurityRateLimit> {
	return await api.post({ url: "/security/rate-limits", data });
}

export async function deleteSecurityRateLimit(id: string): Promise<{ success: boolean }> {
	return await api.del({ url: `/security/rate-limits/${encodeURIComponent(id)}` });
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
