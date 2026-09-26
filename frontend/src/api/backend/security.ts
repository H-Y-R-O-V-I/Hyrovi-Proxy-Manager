import * as api from "./base";

export interface SecuritySignal {
	id: string;
	score: number;
	label: string;
}

export interface SecurityEvent {
	nodeId: string;
	timestamp: string | null;
	requestId: string | null;
	originRequestId: string | null;
	host: string;
	method: string;
	path: string;
	status: number;
	ip: string;
	userAgent: string;
	referrer: string;
	accept: string;
	acceptLanguage: string;
	secChUa: string;
	secChUaMobile: string;
	secChUaPlatform: string;
	deviceId: string | null;
	clientFingerprint: string | null;
	requestLength: number;
	bytesSent: number;
	requestTime: number;
	upstreamStatus: string;
	risk: number;
	severity: "normal" | "low" | "medium" | "high" | "critical";
	proxyHostId: number | null;
	securityMode: SecurityHostMode;
	endpointRulePath: string | null;
	policySource: "host" | "group" | "global" | "remote";
	groupId: string | null;
	groupName: string | null;
	signals: SecuritySignal[];
}

export interface SecurityAttackSession {
	id: string;
	nodeId: string;
	ip: string;
	requests: number;
	maxRisk: number;
	signals: string[];
	hosts: string[];
	firstSeen: string;
	lastSeen: string;
	activeResponse: "block" | "challenge" | "rate_limit" | null;
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

export type SecurityIncidentTimelineKind = "proxy_request" | "app_event" | "response_action" | "challenge";

export interface SecurityIncidentTimelineItem {
	id: string;
	timestamp: string | null;
	kind: SecurityIncidentTimelineKind;
	correlation: "attack_session" | "request_id" | "source_ip";
	severity: "normal" | "info" | "low" | "medium" | "high" | "critical";
	summary: string;
	detail: string | null;
	requestId: string | null;
	host: string | null;
	app: string | null;
	accountId: string | null;
	appSessionId: string | null;
	deviceId: string | null;
	deviceTrust: "verified" | "reported" | null;
	deviceFingerprint: string | null;
	risk: number | null;
	status: number | null;
}

export interface SecurityIncidentCorrelation {
	entities: {
		hosts: string[];
		apps: string[];
		accountIds: string[];
		appSessionIds: string[];
		deviceIds: string[];
		verifiedDeviceIds: string[];
		requestIds: string[];
	};
	items: SecurityIncidentTimelineItem[];
}

export interface SecurityAttackSessionDetail extends SecurityAttackSession {
	requestPatterns: SecurityAttackSessionPattern[];
	activeResponses: Array<
		| (SecurityBlock & { type: "block" })
		| (SecurityChallenge & { type: "challenge" })
		| (SecurityRateLimit & { type: "rate_limit" })
	>;
	responseHistory: SecurityResponseHistoryEntry[];
	appEvents: SecurityAppEvent[];
	correlation: SecurityIncidentCorrelation;
	escalation: SecurityEscalationState | null;
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
		| (SecurityChallenge & { type: "challenge" })
		| (SecurityRateLimit & { type: "rate_limit" })
	>;
	responseHistory: SecurityResponseHistoryEntry[];
	appEvents: SecurityAppEvent[];
	escalation: SecurityEscalationState | null;
}

export type SecurityHostMode = "off" | "observe" | "protect" | "strict";
export type SecurityProtectionAction = "inherit" | "observe" | "deny" | "rate_limit" | "challenge" | "block";
export interface SecurityProtectionRules {
	crawler: SecurityProtectionAction;
	ddos: SecurityProtectionAction;
	criticalFiles: SecurityProtectionAction;
	exploit: SecurityProtectionAction;
	authAbuse: SecurityProtectionAction;
	recon: SecurityProtectionAction;
	unusualMethods: SecurityProtectionAction;
}

export interface SecurityEndpointRule {
	pathPrefix: string;
	mode: SecurityHostMode;
}

export interface SecurityHostPolicy {
	mode: SecurityHostMode;
	autoRateLimitThreshold: number;
	autoRateLimitMinutes: number;
	autoBlockThreshold: number;
	autoBlockMinutes: number;
	challengeMinutes: number;
	challengeDifficulty: number;
	protectionRules: SecurityProtectionRules;
	endpointRules: SecurityEndpointRule[];
}

export interface SecurityHostPolicyDefaults extends SecurityHostPolicy {
	enforcementEnabled: boolean;
}

export interface SecurityHostPolicyGroupRef {
	id: string;
	name: string;
	securityMode: "inherit" | SecurityHostMode;
	protectionRules: SecurityProtectionRules;
	accessMode: "open" | "allowlist" | "denylist";
	sources: string[];
}

export interface SecurityHostPolicyEntry {
	id: number;
	domainNames: string[];
	enabled: boolean;
	group: SecurityHostPolicyGroupRef | null;
	policySource: "host" | "group" | "global";
	policy: SecurityHostPolicy | null;
	effective: SecurityHostPolicy;
}

export type SecurityHostAccessMode = "inherit" | "open" | "allowlist" | "denylist";

export interface SecurityHostAccessGroupRef {
	id: string;
	name: string;
	accessMode: "open" | "allowlist" | "denylist";
	sources: string[];
}

export interface SecurityHostAccessPolicy {
	hostId: number;
	accessMode: SecurityHostAccessMode;
	sources: string[];
	policySource: "host" | "group" | "default";
	effectiveAccessMode: "open" | "allowlist" | "denylist";
	effectiveSources: string[];
	group: SecurityHostAccessGroupRef | null;
}

export interface SecurityHostGroupHost {
	id: number;
	domainNames: string[];
	enabled: boolean;
}

export interface SecurityHostGroup {
	id: string;
	name: string;
	description: string;
	hostIds: number[];
	hosts: SecurityHostGroupHost[];
	accessMode: "open" | "allowlist" | "denylist";
	sources: string[];
	securityMode: "inherit" | SecurityHostMode;
	protectionRules: SecurityProtectionRules;
	createdAt: string;
	updatedAt: string;
}

export interface SecurityEventFilters {
	limit?: number;
	minRisk?: number;
	maxRisk?: number;
	host?: string;
	ip?: string;
	method?: string;
	status?: number;
	groupId?: string;
	nodeId?: string;
	search?: string;
	sinceMinutes?: number;
}
export interface SecurityPolicy {
	autoBlockEnabled: boolean;
	autoRateLimitThreshold: number;
	autoRateLimitMinutes: number;
	autoBlockThreshold: number;
	autoBlockMinutes: number;
	autoEscalationHits: number;
	autoEscalationWindowMinutes: number;
	autoEscalationCooldownSeconds: number;
	eventRetentionDays: number;
	eventArchiveMinRisk: number;
	trustedSources: string[];
	protectionRules: SecurityProtectionRules;
	hostPolicies: Record<string, SecurityHostPolicy>;
}

export interface SecurityFileStat {
	exists: boolean;
	bytes: number;
	modifiedAt: string | null;
}

export interface SecurityDirectoryStat {
	exists: boolean;
	files: number;
	bytes: number;
}

export interface SecurityDiagnostics {
	generatedAt: string;
	health: {
		status: "ok" | "warning" | "critical";
		issues: string[];
	};
	storage: {
		disk: {
			status: "ok" | "warning" | "critical";
			totalBytes: number;
			usedBytes: number;
			freeBytes: number;
			usedPercent: number;
			freePercent: number;
		};
		securityLog: SecurityFileStat;
		actionLog: SecurityFileStat;
		eventArchive: SecurityDirectoryStat;
		appEventArchive: SecurityDirectoryStat;
		stateFiles: Record<string, SecurityFileStat>;
	};
	components: {
		instrumented: boolean;
		emergencyBypass: boolean;
		monitorIntervalMs: number;
		autoResponseEnabled: boolean;
	};
	counts: {
		activeBlocks: number;
		activeRateLimits: number;
		activeChallenges: number;
		activeEscalations: number;
		detectionRules: number;
		enabledDetectionRules: number;
		openAlerts: number;
		trustedDevices: number;
		revokedTrustedDevices: number;
	};
}

export interface SecurityAttackAnalytics {
	suspiciousRequests: number;
	suspiciousRatio: number;
	observedSources: number;
	observedHosts: number;
	responseBytes: number;
	uniqueSources: number;
	uniqueTargets: number;
	uniquePaths: number;
	peakRequestsPerMinute: number;
	avgRequestsPerMinute: number;
	avgResponseBytes: number;
	riskLevels: Record<"normal" | "low" | "medium" | "high" | "critical", number>;
	performance: {
		samples: number;
		avgMs: number;
		p50Ms: number;
		p95Ms: number;
		p99Ms: number;
		maxMs: number;
		slowOver1s: number;
		slowOver3s: number;
	};
	http: {
		deniedRequests: number;
		notFoundRequests: number;
		upstream5xx: number;
		statusFamilies: Array<{ family: string; requests: number }>;
		topStatuses: Array<{ status: number; requests: number }>;
	};
	timeline: Array<{
		start: string;
		requests: number;
		suspicious: number;
		critical: number;
		bytes: number;
		avgRequestTimeMs: number;
		uniqueSources: number;
	}>;
	trafficSources: Array<{
		ip: string;
		requests: number;
		suspicious: number;
		critical: number;
		maxRisk: number;
		bytesSent: number;
		denied: number;
		missing: number;
		crawlerAttack: boolean;
		hosts: string[];
		uniquePaths: number;
		peakRequestsPerMinute: number;
		firstSeen: string | null;
		lastSeen: string | null;
	}>;
	trafficHosts: Array<{
		host: string;
		requests: number;
		suspicious: number;
		critical: number;
		maxRisk: number;
		bytesSent: number;
		sources: number;
		avgRequestTimeMs: number;
	}>;
	topPaths: Array<{
		host: string;
		path: string;
		requests: number;
		suspicious: number;
		critical: number;
		maxRisk: number;
		sources: number;
		methods: string[];
		statuses: number[];
	}>;
	topUserAgents: Array<{
		userAgent: string;
		requests: number;
		suspicious: number;
		critical: number;
		maxRisk: number;
		sources: number;
	}>;
	topSources: Array<{
		ip: string;
		requests: number;
		critical: number;
		maxRisk: number;
		hosts: string[];
		firstSeen: string | null;
		lastSeen: string | null;
	}>;
	topHosts: Array<{
		host: string;
		requests: number;
		critical: number;
		maxRisk: number;
		sources: number;
	}>;
	topTargets: Array<{
		host: string;
		path: string;
		requests: number;
		critical: number;
		maxRisk: number;
		sources: number;
		methods: string[];
		statuses: number[];
	}>;
	topSignals: Array<{
		id: string;
		label: string;
		hits: number;
		maxScore: number;
		sources: number;
		hosts: number;
	}>;
	methods: Array<{ method: string; requests: number }>;
}


export interface SecurityWebAnalytics {
	pageViews: number;
	visitors: number;
	sessions: number;
	pagesPerSession: number;
	bounceRate: number;
	avgSessionDurationMs: number;
	referrers: {
		direct: number;
		internal: number;
		external: number;
		topExternal: Array<{ host: string; count: number }>;
	};
	devices: Array<{ name: string; count: number }>;
	browsers: Array<{ name: string; count: number }>;
	operatingSystems: Array<{ name: string; count: number }>;
	clientTracking: {
		events: number;
		pageViews: number;
		consentedDevices: number;
		clientFingerprints: number;
		sessions: number;
		engagementSeconds: number;
		routeChanges: number;
		scroll: Record<"25" | "50" | "75" | "100", number>;
	};
	topPages: Array<{
		host: string;
		path: string;
		pageViews: number;
		visitors: number;
		avgRequestTimeMs: number;
	}>;
	entryPages: Array<{ host: string; path: string; sessions: number }>;
	exitPages: Array<{ host: string; path: string; sessions: number }>;
	sites: Array<{
		host: string;
		requests: number;
		pageViews: number;
		suspicious: number;
		errors: number;
		bytesSent: number;
		visitors: number;
		sessions: number;
		errorRate: number;
		avgRequestTimeMs: number;
	}>;
}

export interface SecurityOverview {
	window: {
		analyzedRequests: number;
		loadedRequests: number;
		listLimit: number;
		analysisLimit: number;
		analysisLimitReached: boolean;
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
	activeEscalations: SecurityEscalationState[];
	analytics: SecurityAttackAnalytics;
	webAnalytics: SecurityWebAnalytics;
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

export interface SecurityEscalationState {
	rateLimitId: string;
	ip: string;
	strikes: number;
	windowStartedAt: string;
	lastResponseAt: string | null;
	lastStrikeAt: string | null;
	updatedAt: string;
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
	deviceTrust: "verified" | "reported" | null;
	deviceName: string | null;
	deviceFingerprint: string | null;
	deviceSequence: number | null;
	reason: string | null;
}

export interface SecurityAppEventsResponse {
	configured: boolean;
	minTokenLength: number;
	retentionDays: number;
	allowedEventTypes: string[];
	allowedSeverities: string[];
	signedDeviceAuthSupported: boolean;
	events: SecurityAppEvent[];
}

export type SecurityAlertSeverity = "info" | "low" | "medium" | "high" | "critical";
export type SecurityAlertStatus = "open" | "acknowledged";

export interface SecurityAlert {
	id: string;
	createdAt: string;
	updatedAt: string;
	status: SecurityAlertStatus;
	acknowledgedAt: string | null;
	severity: SecurityAlertSeverity;
	type: string;
	title: string;
	detail: string | null;
	sourceIp: string | null;
	host: string | null;
	app: string | null;
	requestId: string | null;
	entityId: string | null;
	count: number;
}

export interface SecurityAlertsResponse {
	feedConfigured: boolean;
	minFeedTokenLength: number;
	maxAlerts: number;
	alerts: SecurityAlert[];
}

export type SecurityDetectionRuleResponse = "observe" | "soft";
export type SecurityDetectionRuleStage = "preview" | "active" | "paused";
export type SecurityRuleHitVerdict = "confirmed_attack" | "expected" | "false_positive";

export interface SecurityDetectionRulePromotionGate {
	enabled: boolean;
	minObservedHits: number;
	minReviews: number;
	minConfirmedAttacks: number;
	maxFalsePositivePercent: number;
}

export interface SecurityDetectionRulePromotionCheck {
	id: string;
	label: string;
	actual: number;
	required: number;
	comparison?: "max";
	passed: boolean;
}

export interface SecurityDetectionRulePromotionGateEvaluation extends SecurityDetectionRulePromotionGate {
	ready: boolean;
	falsePositivePercent: number;
	checks: SecurityDetectionRulePromotionCheck[];
}

export interface SecurityDetectionRuleMatch {
	host: string | null;
	pathPrefix: string | null;
	pathContains: string | null;
	methods: string[];
	statuses: number[];
	userAgentContains: string | null;
}

export interface SecurityDetectionRule {
	id: string;
	name: string;
	stage: SecurityDetectionRuleStage;
	enabled: boolean;
	score: number;
	response: SecurityDetectionRuleResponse;
	match: SecurityDetectionRuleMatch;
	promotionGate: SecurityDetectionRulePromotionGate;
	createdAt: string;
	updatedAt: string;
}


export interface SecurityDetectionRulesExport {
	version: 1 | 2 | 3;
	exportedAt: string;
	rules: Array<Omit<SecurityDetectionRule, "id" | "createdAt" | "updatedAt">>;
}

export interface SecurityDetectionRulesImportResult {
	mode: "merge" | "replace";
	added: number;
	skipped: number;
	total: number;
}

export interface SecurityDetectionRuleHitSample {
	timestamp: string | null;
	requestId: string | null;
	host: string;
	method: string;
	path: string;
	status: number;
	ip: string;
	risk: number;
	severity: string;
	verdict?: SecurityRuleHitVerdict | null;
}

export interface SecurityDetectionRuleReviewSummary {
	total: number;
	confirmedAttack: number;
	expected: number;
	falsePositive: number;
}

export interface SecurityDetectionRuleReview {
	id: string;
	ruleId: string;
	requestId: string;
	verdict: SecurityRuleHitVerdict;
	createdAt: string;
	updatedAt: string;
}

export interface SecurityDetectionRuleAnalyticsEntry {
	ruleId: string | null;
	name: string;
	stage: SecurityDetectionRuleStage;
	enabled: boolean;
	response: SecurityDetectionRuleResponse;
	score: number;
	hits: number;
	hitsLastHour: number;
	hitsLast24Hours: number;
	uniqueIpsLast24Hours: number;
	hourlyTrendStartAt: string;
	hourlyHits: number[];
	uniqueIps: number;
	uniqueHosts: number;
	firstHitAt: string | null;
	lastHitAt: string | null;
	maxObservedRisk: number;
	reviews: SecurityDetectionRuleReviewSummary;
	promotionGate: SecurityDetectionRulePromotionGateEvaluation;
	samples: SecurityDetectionRuleHitSample[];
}

export interface SecurityDetectionRuleAnalyticsResponse {
	analyzedEvents: number;
	limit: number;
	rules: SecurityDetectionRuleAnalyticsEntry[];
}

export interface SecurityDetectionRuleSimulation extends Omit<SecurityDetectionRuleAnalyticsEntry, "reviews"> {
	ruleId: null;
	analyzedEvents: number;
	limit: number;
	rule: Omit<SecurityDetectionRule, "id" | "createdAt" | "updatedAt">;
}

export interface SecurityTrustedDevice {
	deviceId: string;
	name: string;
	fingerprint: string;
	allowedApps: string[];
	createdAt: string;
	updatedAt: string;
	revokedAt: string | null;
	lastSequence: number;
	sequenceResetAt: string | null;
	lastSeenAt: string | null;
	lastApp: string | null;
}

export interface SecurityChallenge {
	id: string;
	ip: string;
	difficulty: number;
	attempts: number;
	maxAttempts: number;
	reason: string;
	source: string;
	createdAt: string;
	expiresAt: string;
}

export interface SecurityBlock {
	id: string;
	ip: string;
	reason: string;
	source: string;
	createdAt: string;
	expiresAt: string;
}

export async function getSecurityOverview(filters: Omit<SecurityEventFilters, "limit"> = {}): Promise<SecurityOverview> {
	return await api.get({
		url: "/security/overview",
		params: {
			minRisk: filters.minRisk,
			maxRisk: filters.maxRisk,
			host: filters.host,
			ip: filters.ip,
			method: filters.method,
			status: filters.status,
			groupId: filters.groupId,
			nodeId: filters.nodeId,
			search: filters.search,
			sinceMinutes: filters.sinceMinutes,
		},
	});
}

export async function getSecurityDiagnostics(): Promise<SecurityDiagnostics> {
	return await api.get({ url: "/security/diagnostics" });
}

export async function getSecurityAppEvents(limit = 100): Promise<SecurityAppEventsResponse> {
	return await api.get({ url: "/security/app-events", params: { limit } });
}

export async function getSecurityAlerts(limit = 100, status: SecurityAlertStatus | "" = "open"): Promise<SecurityAlertsResponse> {
	return await api.get({
		url: "/security/alerts",
		params: { limit, ...(status ? { status } : {}) },
	});
}


export async function getSecurityDetectionRules(): Promise<SecurityDetectionRule[]> {
	return await api.get({ url: "/security/detection-rules" });
}

export async function createSecurityDetectionRule(
	data: Omit<SecurityDetectionRule, "id" | "createdAt" | "updatedAt">,
): Promise<SecurityDetectionRule> {
	return await api.post({ url: "/security/detection-rules", data });
}

export async function updateSecurityDetectionRule(
	id: string,
	data: Partial<Omit<SecurityDetectionRule, "id" | "createdAt" | "updatedAt">>,
): Promise<SecurityDetectionRule> {
	return await api.put({ url: `/security/detection-rules/${encodeURIComponent(id)}`, data });
}

export async function promoteSecurityDetectionRule(id: string): Promise<{
	rule: SecurityDetectionRule;
	promotionGate: SecurityDetectionRulePromotionGateEvaluation;
}> {
	return await api.post({ url: `/security/detection-rules/${encodeURIComponent(id)}/promote` });
}

export async function deleteSecurityDetectionRule(id: string): Promise<{ success: boolean }> {
	return await api.del({ url: `/security/detection-rules/${encodeURIComponent(id)}` });
}

export async function exportSecurityDetectionRules(): Promise<SecurityDetectionRulesExport> {
	return await api.get({ url: "/security/detection-rules/export" });
}

export async function importSecurityDetectionRules(
	data: SecurityDetectionRulesExport & { mode: "merge" | "replace" },
): Promise<SecurityDetectionRulesImportResult> {
	return await api.post({ url: "/security/detection-rules/import", data });
}

export async function getSecurityDetectionRuleAnalytics(limit = 1000): Promise<SecurityDetectionRuleAnalyticsResponse> {
	return await api.get({ url: "/security/detection-rules/analytics", params: { limit } });
}

export async function simulateSecurityDetectionRule(
	data: Omit<SecurityDetectionRule, "id" | "createdAt" | "updatedAt">,
	limit = 1000,
): Promise<SecurityDetectionRuleSimulation> {
	return await api.post({ url: "/security/detection-rules/simulate", params: { limit }, data });
}

export async function reviewSecurityDetectionRuleHit(
	ruleId: string,
	requestId: string,
	verdict: SecurityRuleHitVerdict,
): Promise<SecurityDetectionRuleReview> {
	return await api.put({
		url: `/security/detection-rules/${encodeURIComponent(ruleId)}/reviews/${encodeURIComponent(requestId)}`,
		data: { verdict },
	});
}

export async function clearSecurityDetectionRuleHitReview(
	ruleId: string,
	requestId: string,
): Promise<{ success: boolean }> {
	return await api.del({
		url: `/security/detection-rules/${encodeURIComponent(ruleId)}/reviews/${encodeURIComponent(requestId)}`,
	});
}

export async function acknowledgeSecurityAlert(id: string): Promise<SecurityAlert> {
	return await api.post({ url: `/security/alerts/${encodeURIComponent(id)}/acknowledge` });
}

export async function getSecurityEvents(
	limitOrFilters: number | SecurityEventFilters = 250,
	legacyMinRisk = 0,
): Promise<SecurityEvent[]> {
	const params: SecurityEventFilters =
		typeof limitOrFilters === "number"
			? { limit: limitOrFilters, minRisk: legacyMinRisk }
			: limitOrFilters;
	return await api.get({
		url: "/security/events",
		params: {
			limit: params.limit,
			minRisk: params.minRisk,
			maxRisk: params.maxRisk,
			host: params.host,
			ip: params.ip,
			method: params.method,
			status: params.status,
			groupId: params.groupId,
			nodeId: params.nodeId,
			search: params.search,
			sinceMinutes: params.sinceMinutes,
		},
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

export async function getSecurityHostPolicyDefaults(): Promise<SecurityHostPolicyDefaults> {
	return await api.get({ url: "/security/host-policy-defaults" });
}

export async function getSecurityHostPolicies(): Promise<SecurityHostPolicyEntry[]> {
	return await api.get({ url: "/security/host-policies" });
}

export async function getSecurityHostPolicy(id: number): Promise<SecurityHostPolicyEntry> {
	return await api.get({ url: `/security/host-policies/${encodeURIComponent(id)}` });
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

export async function getSecurityHostAccess(id: number): Promise<SecurityHostAccessPolicy> {
	return await api.get({ url: `/security/host-access/${encodeURIComponent(id)}` });
}

export async function updateSecurityHostAccess(
	id: number,
	data: Pick<SecurityHostAccessPolicy, "accessMode" | "sources">,
): Promise<SecurityHostAccessPolicy> {
	return await api.put({ url: `/security/host-access/${encodeURIComponent(id)}`, data });
}

export async function deleteSecurityHostAccess(id: number): Promise<SecurityHostAccessPolicy> {
	return await api.del({ url: `/security/host-access/${encodeURIComponent(id)}` });
}

export async function getSecurityHostGroups(): Promise<SecurityHostGroup[]> {
	return await api.get({ url: "/security/host-groups" });
}

export async function createSecurityHostGroup(
	data: Pick<SecurityHostGroup, "name" | "description" | "hostIds" | "accessMode" | "sources" | "securityMode" | "protectionRules">,
): Promise<SecurityHostGroup> {
	return await api.post({ url: "/security/host-groups", data });
}

export async function updateSecurityHostGroup(
	id: string,
	data: Partial<Pick<SecurityHostGroup, "name" | "description" | "hostIds" | "accessMode" | "sources" | "securityMode" | "protectionRules">>,
): Promise<SecurityHostGroup> {
	return await api.put({ url: `/security/host-groups/${encodeURIComponent(id)}`, data });
}

export async function deleteSecurityHostGroup(id: string): Promise<{ success: boolean }> {
	return await api.del({ url: `/security/host-groups/${encodeURIComponent(id)}` });
}
export async function getSecurityTrustedDevices(): Promise<SecurityTrustedDevice[]> {
	return await api.get({ url: "/security/trusted-devices" });
}

export async function createSecurityTrustedDevice(data: {
	deviceId: string;
	name?: string;
	publicKey: string;
	allowedApps?: string[];
}): Promise<SecurityTrustedDevice> {
	return await api.post({ url: "/security/trusted-devices", data });
}

export async function revokeSecurityTrustedDevice(deviceId: string): Promise<SecurityTrustedDevice> {
	return await api.del({ url: `/security/trusted-devices/${encodeURIComponent(deviceId)}` });
}

export async function resetSecurityTrustedDeviceSequence(deviceId: string): Promise<SecurityTrustedDevice> {
	return await api.post({ url: `/security/trusted-devices/${encodeURIComponent(deviceId)}/reset-sequence` });
}

export async function getSecurityChallenges(): Promise<SecurityChallenge[]> {
	return await api.get({ url: "/security/challenges" });
}

export async function deleteSecurityChallenge(id: string): Promise<{ success: boolean }> {
	return await api.del({ url: `/security/challenges/${encodeURIComponent(id)}` });
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
