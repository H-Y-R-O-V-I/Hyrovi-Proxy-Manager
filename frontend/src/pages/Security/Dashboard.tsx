import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { IconBan, IconFilterOff, IconRefresh } from "@tabler/icons-react";
import { useMemo, useState } from "react";
import {
	createSecurityBlock,
	getSecurityAppEvents,
	getSecurityAttackSession,
	getSecurityBlocks,
	getSecurityEventDetail,
	getSecurityEvents,
	getSecurityHostGroups,
	getSecurityOverview,
	type SecurityEvent,
} from "src/api/backend";
import styles from "./Security.module.css";

const riskClass = (risk: number) => risk >= 80 ? "bg-red text-white" : risk >= 60 ? "bg-orange text-white" : risk >= 40 ? "bg-yellow text-dark" : "bg-green-lt";
const formatTime = (value: string | null) => value ? new Date(value).toLocaleString() : "—";
const formatBytes = (value: number) => {
	if (!Number.isFinite(value)) return "—";
	if (value < 1024) return `${value} B`;
	if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
	return `${(value / (1024 * 1024)).toFixed(1)} MB`;
};

type Bucket = { at: number; requests: number; suspicious: number };
type SourceAssessmentLevel = "normal" | "suspicious" | "likely_attack";

type SourceAssessment = {
	level: SourceAssessmentLevel;
	label: string;
	peakRequestsPerMinute: number;
	requests: number;
	suspicious: number;
	denied: number;
	missing: number;
	maxRisk: number;
	hostCount: number;
	uniquePaths: number;
	firstSeen: string | null;
	lastSeen: string | null;
	crawlerDetected: boolean;
	crawlerAttack: boolean;
	bytes: number;
	reasons: string[];
	signals: Array<{ id: string; label: string; score: number; count: number }>;
};

const assessmentBadgeClass = (level: SourceAssessmentLevel) =>
	level === "likely_attack" ? "bg-red text-white" : level === "suspicious" ? "bg-yellow text-dark" : "bg-green-lt";
const responseBadgeClass = (response: "block" | "challenge" | "rate_limit" | null) =>
	response === "block" ? "bg-red text-white" : response === "challenge" ? "bg-orange text-white" : response === "rate_limit" ? "bg-yellow text-dark" : "bg-secondary-lt";
const humanizeSignal = (value: string) => value.replace(/^custom:(?:soft|observe):/, "").replace(/_/g, " ");

function peakRequestsPerMinute(events: SecurityEvent[]) {
	const times = events
		.map((event) => event.timestamp ? new Date(event.timestamp).getTime() : Number.NaN)
		.filter(Number.isFinite)
		.sort((a, b) => a - b);
	let start = 0;
	let peak = 0;
	for (let end = 0; end < times.length; end += 1) {
		while (start <= end && times[end] - times[start] > 60_000) start += 1;
		peak = Math.max(peak, end - start + 1);
	}
	return peak;
}

function assessSource(events: SecurityEvent[]): SourceAssessment {
	const hosts = new Set<string>();
	const paths = new Set<string>();
	const signalMap = new Map<string, { id: string; label: string; score: number; count: number }>();
	let suspicious = 0;
	let denied = 0;
	let missing = 0;
	let maxRisk = 0;
	let bytes = 0;
	let firstSeen: string | null = null;
	let lastSeen: string | null = null;

	for (const event of events) {
		hosts.add(event.host);
		paths.add(event.path);
		if (event.timestamp) {
			if (!firstSeen || new Date(event.timestamp).getTime() < new Date(firstSeen).getTime()) firstSeen = event.timestamp;
			if (!lastSeen || new Date(event.timestamp).getTime() > new Date(lastSeen).getTime()) lastSeen = event.timestamp;
		}
		if (event.risk >= 40) suspicious += 1;
		if (event.status === 401 || event.status === 403) denied += 1;
		if (event.status === 404) missing += 1;
		maxRisk = Math.max(maxRisk, event.risk);
		bytes += Math.max(0, event.bytesSent || 0);
		for (const signal of event.signals) {
			const row = signalMap.get(signal.id) ?? { id: signal.id, label: signal.label, score: signal.score, count: 0 };
			row.count += 1;
			row.score = Math.max(row.score, signal.score);
			signalMap.set(signal.id, row);
		}
	}

	const peak = peakRequestsPerMinute(events);
	const signals = [...signalMap.values()].sort((a, b) => b.score - a.score || b.count - a.count);
	const ids = new Set(signals.map((signal) => signal.id));
	const crawlerDetected =
		ids.has("declared_crawler") ||
		ids.has("automation_client") ||
		ids.has("scanner_user_agent") ||
		ids.has("crawler_path_sweep") ||
		ids.has("crawler_404_sweep");
	const crawlerAttack = ids.has("crawler_attack");
	const strongAttackSignal =
		crawlerAttack ||
		ids.has("path_traversal") ||
		ids.has("injection_probe") ||
		ids.has("reconnaissance_burst") ||
		ids.has("auth_failure_burst") ||
		ids.has("extreme_request_burst") ||
		(ids.has("sensitive_file_probe") && ids.has("scanner_user_agent"));

	const likelyAttack =
		crawlerAttack ||
		peak >= 300 ||
		(maxRisk >= 60 && strongAttackSignal) ||
		(peak >= 100 && denied >= 20) ||
		(ids.has("reconnaissance_burst") && suspicious >= 5);
	const isSuspicious = likelyAttack || peak >= 100 || maxRisk >= 40 || suspicious > 0;

	const reasons: string[] = [];
	if (crawlerAttack) reasons.push("Crawler/scanner behavior matched the malicious-crawler attack rules and is eligible for automatic blocking.");
	else if (crawlerDetected) reasons.push("Automated crawler/bot behavior was detected, but automation alone is not considered an attack.");
	if (peak >= 300) reasons.push(`Extreme traffic burst: ${peak} requests within 60 seconds.`);
	else if (peak >= 100) reasons.push(`High request rate: ${peak} requests within 60 seconds.`);
	if (denied >= 10) reasons.push(`${denied} authentication/authorization denials (401/403) in the inspected window.`);
	if (missing >= 20) reasons.push(`${missing} missing-path responses (404), which can indicate path enumeration.`);
	for (const signal of signals.slice(0, 5)) {
		if (signal.id === "request_burst" || signal.id === "extreme_request_burst") continue;
		reasons.push(`${signal.label} (${signal.count} request${signal.count === 1 ? "" : "s"}).`);
	}
	if (!reasons.length) reasons.push("No unusual request pattern detected in this window.");

	return {
		level: likelyAttack ? "likely_attack" : isSuspicious ? "suspicious" : "normal",
		label: crawlerAttack ? "Crawler attack" : likelyAttack ? "Likely attack" : crawlerDetected && isSuspicious ? "Crawler / suspicious" : crawlerDetected ? "Crawler" : isSuspicious ? "Suspicious" : "Normal",
		peakRequestsPerMinute: peak,
		requests: events.length,
		suspicious,
		denied,
		missing,
		maxRisk,
		hostCount: hosts.size,
		uniquePaths: paths.size,
		firstSeen,
		lastSeen,
		crawlerDetected,
		crawlerAttack,
		bytes,
		reasons: [...new Set(reasons)].slice(0, 8),
		signals,
	};
}

const statusFamily = (status: number) => {
	if (status >= 500) return "5xx";
	if (status >= 400) return "4xx";
	if (status >= 300) return "3xx";
	if (status >= 200) return "2xx";
	if (status >= 100) return "1xx";
	return "other";
};

function buildBuckets(events: SecurityEvent[], sinceMinutes: number, count = 30): Bucket[] {
	const end = Date.now();
	const start = end - sinceMinutes * 60_000;
	const width = Math.max(1, (end - start) / count);
	const buckets = Array.from({ length: count }, (_, index) => ({ at: start + index * width, requests: 0, suspicious: 0 }));
	for (const event of events) {
		if (!event.timestamp) continue;
		const ts = new Date(event.timestamp).getTime();
		if (ts < start || ts > end) continue;
		const index = Math.min(count - 1, Math.max(0, Math.floor((ts - start) / width)));
		buckets[index].requests += 1;
		if (event.risk >= 40) buckets[index].suspicious += 1;
	}
	return buckets;
}

function polyline(values: number[], width = 1000, height = 180) {
	const max = Math.max(1, ...values);
	return values.map((value, index) => {
		const x = values.length <= 1 ? 0 : (index / (values.length - 1)) * width;
		const y = height - (value / max) * (height - 12);
		return `${x.toFixed(1)},${y.toFixed(1)}`;
	}).join(" ");
}

export default function SecurityDashboard() {
	const queryClient = useQueryClient();
	const [search, setSearch] = useState("");
	const [ip, setIp] = useState("");
	const [host, setHost] = useState("");
	const [method, setMethod] = useState("");
	const [status, setStatus] = useState(0);
	const [minRisk, setMinRisk] = useState(0);
	const [groupId, setGroupId] = useState("");
	const [sinceMinutes, setSinceMinutes] = useState(60);
	const [selectedRequestId, setSelectedRequestId] = useState<string | null>(null);
	const [selectedSourceIp, setSelectedSourceIp] = useState<string | null>(null);
	const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);
	const [incidentFilter, setIncidentFilter] = useState<"all" | "crawler" | "blocked" | "critical" | "unanswered">("all");

	const overview = useQuery({
		queryKey: ["security-overview", search, ip, host, method, status, minRisk, groupId, sinceMinutes],
		queryFn: () => getSecurityOverview({ search, ip, host, method, status: status || undefined, minRisk, groupId, sinceMinutes }),
		refetchInterval: 5000,
	});
	const groups = useQuery({ queryKey: ["security-host-groups"], queryFn: getSecurityHostGroups, refetchInterval: 15000 });
	const events = useQuery({
		queryKey: ["security-dashboard-events", search, ip, host, method, status, minRisk, groupId, sinceMinutes],
		queryFn: () => getSecurityEvents({ limit: 2000, search, ip, host, method, status: status || undefined, minRisk, groupId, sinceMinutes }),
		refetchInterval: 5000,
	});
	const requestDetail = useQuery({
		queryKey: ["security-dashboard-event-detail", selectedRequestId],
		queryFn: () => getSecurityEventDetail(selectedRequestId as string),
		enabled: Boolean(selectedRequestId),
		refetchInterval: selectedRequestId ? 5000 : false,
	});
	const attackSessionDetail = useQuery({
		queryKey: ["security-dashboard-attack-session", selectedSessionId],
		queryFn: () => getSecurityAttackSession(selectedSessionId as string),
		enabled: Boolean(selectedSessionId),
		refetchInterval: selectedSessionId ? 5000 : false,
	});
	const sourceDetail = useQuery({
		queryKey: ["security-source-detail", selectedSourceIp],
		queryFn: () => getSecurityEvents({ limit: 2000, ip: selectedSourceIp || undefined, sinceMinutes: 60 }),
		enabled: Boolean(selectedSourceIp),
		refetchInterval: selectedSourceIp ? 5000 : false,
	});
	const sourceOverview = useQuery({
		queryKey: ["security-source-overview", selectedSourceIp],
		queryFn: () => getSecurityOverview({ ip: selectedSourceIp || undefined, sinceMinutes: 60 }),
		enabled: Boolean(selectedSourceIp),
		refetchInterval: selectedSourceIp ? 5000 : false,
	});
	const sourceAppEvents = useQuery({
		queryKey: ["security-source-app-events", selectedSourceIp],
		queryFn: () => getSecurityAppEvents(500),
		enabled: Boolean(selectedSourceIp),
		refetchInterval: selectedSourceIp ? 10_000 : false,
	});
	const sourceBlocks = useQuery({
		queryKey: ["security-source-blocks", selectedSourceIp],
		queryFn: getSecurityBlocks,
		enabled: Boolean(selectedSourceIp),
		refetchInterval: selectedSourceIp ? 5000 : false,
	});

	const sourceStats = useMemo(() => {
		const map = new Map<string, SecurityEvent[]>();
		for (const event of events.data ?? []) {
			const rows = map.get(event.ip) ?? [];
			rows.push(event);
			map.set(event.ip, rows);
		}
		return [...map.entries()]
			.map(([source, rows]) => ({ source, ...assessSource(rows) }))
			.sort((a, b) =>
				(a.level === "likely_attack" ? -1 : a.level === "suspicious" ? 0 : 1) -
					(b.level === "likely_attack" ? -1 : b.level === "suspicious" ? 0 : 1) ||
				b.requests - a.requests ||
				b.maxRisk - a.maxRisk
			);
	}, [events.data]);
	const sourceRows = sourceStats.slice(0, 12);
	const attackSessions = useMemo(() => overview.data?.attackSessions ?? [], [overview.data]);
	const filteredAttackSessions = useMemo(() => attackSessions.filter((session) => {
		if (incidentFilter === "crawler") return session.signals.includes("crawler_attack");
		if (incidentFilter === "blocked") return session.activeResponse === "block";
		if (incidentFilter === "critical") return session.maxRisk >= 80;
		if (incidentFilter === "unanswered") return session.activeResponse === null;
		return true;
	}), [attackSessions, incidentFilter]);
	const unansweredIncidents = useMemo(() => attackSessions.filter((session) => session.activeResponse === null).length, [attackSessions]);
	const crawlerAttackCount = useMemo(() => attackSessions.filter((session) => session.signals.includes("crawler_attack")).length, [attackSessions]);
	const totalBytes = overview.data?.analytics.responseBytes ?? (events.data ?? []).reduce((sum, event) => sum + Math.max(0, event.bytesSent || 0), 0);
	const destinationCount = overview.data?.analytics.observedHosts ?? new Set((events.data ?? []).map((event) => event.host).filter(Boolean)).size;
	const hostStats = useMemo(() => {
		const map = new Map<string, { requests: number; suspicious: number; maxRisk: number; sources: Set<string>; bytes: number }>();
		for (const event of events.data ?? []) {
			const row = map.get(event.host) ?? { requests: 0, suspicious: 0, maxRisk: 0, sources: new Set<string>(), bytes: 0 };
			row.requests += 1;
			row.suspicious += event.risk >= 40 ? 1 : 0;
			row.maxRisk = Math.max(row.maxRisk, event.risk);
			row.sources.add(event.ip);
			row.bytes += Math.max(0, event.bytesSent || 0);
			map.set(event.host, row);
		}
		return [...map.entries()].map(([name, row]) => ({ name, ...row, sourceCount: row.sources.size })).sort((a, b) => b.requests - a.requests).slice(0, 8);
	}, [events.data]);
	const statusStats = useMemo(() => {
		const counts = new Map<string, number>();
		for (const event of events.data ?? []) counts.set(statusFamily(event.status), (counts.get(statusFamily(event.status)) ?? 0) + 1);
		return ["2xx", "3xx", "4xx", "5xx", "1xx", "other"].map((family) => ({ family, count: counts.get(family) ?? 0 })).filter((row) => row.count > 0);
	}, [events.data]);
	const riskStats = useMemo(() => {
		const rows = [
			{ label: "Normal 0–19", min: 0, max: 19 },
			{ label: "Low 20–39", min: 20, max: 39 },
			{ label: "Suspicious 40–59", min: 40, max: 59 },
			{ label: "High 60–79", min: 60, max: 79 },
			{ label: "Critical 80+", min: 80, max: 100 },
		];
		return rows.map((row) => ({ ...row, count: (events.data ?? []).filter((event) => event.risk >= row.min && event.risk <= row.max).length }));
	}, [events.data]);

	const hostOptions = useMemo(() => [...new Set((events.data ?? []).map((event) => event.host).filter(Boolean))].sort(), [events.data]);
	const buckets = useMemo(() => buildBuckets(events.data ?? [], sinceMinutes), [events.data, sinceMinutes]);
	const requestPoints = polyline(buckets.map((bucket) => bucket.requests));
	const suspiciousPoints = polyline(buckets.map((bucket) => bucket.suspicious));

	const sourceAssessment = useMemo(() => assessSource(sourceDetail.data ?? []), [sourceDetail.data]);
	const sourceOverviewRow = useMemo(
		() => sourceOverview.data?.analytics.trafficSources.find((row) => row.ip === selectedSourceIp) ?? null,
		[sourceOverview.data, selectedSourceIp],
	);
	const sourceListIsSampled = (sourceOverview.data?.requests ?? 0) > (sourceDetail.data?.length ?? 0);
	const sourceDestinations = useMemo(() => {
		const map = new Map<string, { requests: number; suspicious: number; maxRisk: number }>();
		for (const event of sourceDetail.data ?? []) {
			const row = map.get(event.host) ?? { requests: 0, suspicious: 0, maxRisk: 0 };
			row.requests += 1;
			row.suspicious += event.risk >= 40 ? 1 : 0;
			row.maxRisk = Math.max(row.maxRisk, event.risk);
			map.set(event.host, row);
		}
		return [...map.entries()].map(([name, row]) => ({ name, ...row })).sort((a, b) => b.requests - a.requests).slice(0, 8);
	}, [sourceDetail.data]);
	const sourceIdentities = useMemo(() => {
		const source = selectedSourceIp;
		if (!source) return [];
		const rows = (sourceAppEvents.data?.events ?? []).filter((event) => event.sourceIp === source || event.ip === source);
		const seen = new Set<string>();
		const result: Array<{
			key: string;
			app: string;
			accountId: string | null;
			sessionId: string | null;
			deviceId: string | null;
			deviceTrust: "verified" | "reported" | null;
			deviceName: string | null;
			lastSeen: string;
		}> = [];
		for (const event of rows) {
			const key = [event.app, event.accountId || "", event.sessionId || "", event.deviceId || ""].join("|");
			if (seen.has(key)) continue;
			seen.add(key);
			result.push({
				key,
				app: event.app,
				accountId: event.accountId,
				sessionId: event.sessionId,
				deviceId: event.deviceId,
				deviceTrust: event.deviceTrust,
				deviceName: event.deviceName,
				lastSeen: event.timestamp,
			});
		}
		return result.slice(0, 12);
	}, [selectedSourceIp, sourceAppEvents.data]);

	const sourceActiveBlock = useMemo(
		() => (sourceBlocks.data ?? []).find((entry) => entry.ip === selectedSourceIp) ?? null,
		[sourceBlocks.data, selectedSourceIp],
	);
	const sourceBlockedAttempts = useMemo(() => {
		if (!sourceActiveBlock) return 0;
		const started = new Date(sourceActiveBlock.createdAt).getTime();
		return (sourceDetail.data ?? []).filter((event) => {
			if (!event.timestamp || event.status !== 403) return false;
			return new Date(event.timestamp).getTime() >= started;
		}).length;
	}, [sourceActiveBlock, sourceDetail.data]);
	const sourceMethods = useMemo(() => {
		const map = new Map<string, number>();
		for (const event of sourceDetail.data ?? []) map.set(event.method || "UNKNOWN", (map.get(event.method || "UNKNOWN") ?? 0) + 1);
		return [...map.entries()].map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count);
	}, [sourceDetail.data]);
	const sourceStatuses = useMemo(() => {
		const map = new Map<string, number>();
		for (const event of sourceDetail.data ?? []) {
			const family = statusFamily(event.status);
			map.set(family, (map.get(family) ?? 0) + 1);
		}
		return [...map.entries()].map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count);
	}, [sourceDetail.data]);
	const sourcePaths = useMemo(() => {
		const map = new Map<string, { count: number; maxRisk: number; statuses: Set<number> }>();
		for (const event of sourceDetail.data ?? []) {
			const row = map.get(event.path) ?? { count: 0, maxRisk: 0, statuses: new Set<number>() };
			row.count += 1;
			row.maxRisk = Math.max(row.maxRisk, event.risk);
			if (event.status) row.statuses.add(event.status);
			map.set(event.path, row);
		}
		return [...map.entries()]
			.map(([path, row]) => ({ path, count: row.count, maxRisk: row.maxRisk, statuses: [...row.statuses].sort() }))
			.sort((a, b) => b.maxRisk - a.maxRisk || b.count - a.count)
			.slice(0, 12);
	}, [sourceDetail.data]);

	const sourceUserAgents = useMemo(() => {
		const map = new Map<string, number>();
		for (const event of sourceDetail.data ?? []) {
			const name = event.userAgent || "No user agent";
			map.set(name, (map.get(name) ?? 0) + 1);
		}
		return [...map.entries()].map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count).slice(0, 5);
	}, [sourceDetail.data]);

	const openSource = (sourceIp: string) => {
		setSelectedRequestId(null);
		setSelectedSessionId(null);
		setSelectedSourceIp(sourceIp);
	};
	const openRequest = (requestId: string) => {
		setSelectedSourceIp(null);
		setSelectedSessionId(null);
		setSelectedRequestId(requestId);
	};
	const openSession = (sessionId: string) => {
		setSelectedSourceIp(null);
		setSelectedRequestId(null);
		setSelectedSessionId(sessionId);
	};

	const block = useMutation({
		mutationFn: (sourceIp: string) => createSecurityBlock({ ip: sourceIp, durationMinutes: 60, reason: "Blocked from Security dashboard", source: "dashboard" }),
		onSuccess: async () => {
			await Promise.all([
				queryClient.invalidateQueries({ queryKey: ["security-overview"] }),
				queryClient.invalidateQueries({ queryKey: ["security-source-blocks"] }),
				queryClient.invalidateQueries({ queryKey: ["security-dashboard-events"] }),
			]);
		},
	});

	const refresh = async () => {
		await Promise.all([queryClient.invalidateQueries({ queryKey: ["security-overview"] }), queryClient.invalidateQueries({ queryKey: ["security-dashboard-events"] }), queryClient.invalidateQueries({ queryKey: ["security-host-groups"] })]);
	};

	const clearFilters = () => {
		setSearch("");
		setIp("");
		setHost("");
		setMethod("");
		setStatus(0);
		setMinRisk(0);
		setGroupId("");
		setSinceMinutes(60);
	};

	return <div className={styles.shell}>
		<div className={styles.hero}>
			<div><h1>Security traffic</h1><p>Live request flow, sources, destinations and risk — behind Cloudflare with the real client IP.</p></div>
			<button type="button" className="btn btn-outline-secondary" onClick={refresh}><IconRefresh size={17} /> Refresh</button>
		</div>

		{overview.data?.window.analysisLimitReached ? <div className="alert alert-warning py-2 px-3">
			The backend analysis reached {overview.data.window.analysisLimit.toLocaleString()} loaded events. Counts for this filter may be partial; the request table is independently capped at {overview.data.window.listLimit.toLocaleString()} rows.
		</div> : null}

		<div className={styles.metrics}>
			<div className={styles.metric}><div className={styles.metricLabel}>Requests in window</div><div className={styles.metricValue}>{overview.data?.requests ?? events.data?.length ?? 0}</div><small>{overview.data && (events.data?.length ?? 0) < overview.data.requests ? `${(events.data?.length ?? 0).toLocaleString()} listed` : "full listed window"}</small></div>
			<div className={styles.metric}><div className={styles.metricLabel}>Unique source IPs</div><div className={styles.metricValue}>{overview.data?.analytics.observedSources ?? sourceStats.length}</div></div>
			<div className={styles.metric}><div className={styles.metricLabel}>Suspicious</div><div className={styles.metricValue}>{overview.data?.suspicious ?? (events.data ?? []).filter((event) => event.risk >= 40).length}</div></div>
			<div className={styles.metric}><div className={styles.metricLabel}>Attack sessions</div><div className={styles.metricValue}>{attackSessions.length}</div></div>
			<div className={styles.metric}><div className={styles.metricLabel}>Crawler attacks</div><div className={styles.metricValue}>{crawlerAttackCount}</div></div>
			<div className={styles.metric}><div className={styles.metricLabel}>Active blocks</div><div className={styles.metricValue}>{overview.data?.activeBlocks ?? 0}</div></div>
			<div className={styles.metric}><div className={styles.metricLabel}>Unanswered incidents</div><div className={styles.metricValue}>{unansweredIncidents}</div></div>
			<div className={styles.metric}><div className={styles.metricLabel}>Destinations</div><div className={styles.metricValue}>{destinationCount}</div></div>
			<div className={styles.metric}><div className={styles.metricLabel}>Response traffic</div><div className={styles.metricValue}>{formatBytes(totalBytes)}</div></div>
		</div>

		<div className={styles.filters}>
			<input className="form-control" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search path, host, request ID…" />
			<input className="form-control font-monospace" value={ip} onChange={(e) => setIp(e.target.value)} placeholder="Source IP" />
			<select className="form-select" value={host} onChange={(e) => setHost(e.target.value)}><option value="">All hosts</option>{hostOptions.map((entry) => <option key={entry} value={entry}>{entry}</option>)}</select>
			<select className="form-select" value={method} onChange={(e) => setMethod(e.target.value)}><option value="">Method</option>{["GET","POST","PUT","PATCH","DELETE","OPTIONS"].map((entry) => <option key={entry}>{entry}</option>)}</select>
			<input className="form-control" type="number" min={0} max={599} value={status || ""} onChange={(e) => setStatus(Number(e.target.value) || 0)} placeholder="Status" />
			<select className="form-select" value={minRisk} onChange={(e) => setMinRisk(Number(e.target.value))}><option value={0}>All risk</option><option value={20}>Risk 20+</option><option value={40}>Risk 40+</option><option value={60}>Risk 60+</option><option value={80}>Risk 80+</option></select>
			<select className="form-select" value={sinceMinutes} onChange={(e) => setSinceMinutes(Number(e.target.value))}><option value={15}>15 min</option><option value={60}>1 hour</option><option value={360}>6 hours</option><option value={1440}>24 hours</option><option value={10080}>7 days</option></select>
			<select className="form-select" value={groupId} onChange={(e) => setGroupId(e.target.value)}><option value="">All groups</option>{(groups.data ?? []).map((group) => <option key={group.id} value={group.id}>{group.name}</option>)}</select>
			<button type="button" className="btn btn-outline-secondary" onClick={clearFilters}><IconFilterOff size={16} /> Clear</button>
		</div>

		<div className={styles.gridTwo}>
			<div className={styles.panel}>
				<div className={styles.panelHeader}><h3>Request volume</h3><div><div className={styles.chartLegend}><span className={styles.legendItem}>All requests</span><span className={styles.legendItem}>Risk 40+</span></div>{overview.data && (events.data?.length ?? 0) < overview.data.requests ? <small className="text-secondary">Chart: latest {(events.data?.length ?? 0).toLocaleString()} of {overview.data.requests.toLocaleString()}</small> : null}</div></div>
				<svg className={styles.chart} viewBox="0 0 1000 190" preserveAspectRatio="none" role="img" aria-label="Request volume timeline">
					<line x1="0" y1="180" x2="1000" y2="180" stroke="currentColor" opacity="0.15" />
					<polyline points={requestPoints} fill="none" stroke="currentColor" strokeWidth="4" vectorEffect="non-scaling-stroke" />
					<polyline points={suspiciousPoints} fill="none" stroke="var(--tblr-danger)" strokeWidth="3" vectorEffect="non-scaling-stroke" />
				</svg>
			</div>
			<div className={styles.panel}>
				<div className={styles.panelHeader}><h3>Top source IPs</h3><span className="text-secondary small">click a client to inspect</span></div>
				<div className={styles.sourceList}>{sourceRows.map((row) => <button type="button" className={`${styles.sourceRow} btn btn-link text-start text-reset`} key={row.source} onClick={() => openSource(row.source)}><span><span className={styles.mono}>{row.source}</span><small>{row.hostCount} hosts · {formatBytes(row.bytes)} · peak {row.peakRequestsPerMinute}/min</small></span><span>{row.requests} req<small>{row.suspicious} suspicious</small></span><span><span className={`badge ${assessmentBadgeClass(row.level)}`}>{row.label}</span><small className="text-end">risk {row.maxRisk} · {row.uniquePaths} paths</small></span></button>)}{sourceRows.length === 0 ? <div className="p-3 text-secondary">No traffic in this filter.</div> : null}</div>
			</div>
		</div>

		<div className={styles.panel}>
			<div className={styles.panelHeader}>
				<h3>Attack / incident sessions</h3>
				<div className={styles.incidentHeaderTools}>
					<span className="text-secondary small">{overview.data?.automation.mode === "enforce" ? "Enforcement active" : "Observe only"} · 5 minute correlation</span>
					<div className={styles.incidentFilters}>
						{(["all", "crawler", "blocked", "critical", "unanswered"] as const).map((value) => <button type="button" key={value} className={incidentFilter === value ? styles.incidentFilterActive : ""} onClick={() => setIncidentFilter(value)}>{value}</button>)}
					</div>
				</div>
			</div>
			<div className={styles.incidentList}>
				{filteredAttackSessions.slice(0, 10).map((session) => {
					const isCrawler = session.signals.includes("crawler_attack");
					return <button type="button" key={session.id} onClick={() => openSession(session.id)}>
						<span className={styles.incidentRisk}><span className={`badge ${riskClass(session.maxRisk)}`}>{session.maxRisk}</span></span>
						<span className={styles.incidentMain}>
							<strong>{isCrawler ? "Crawler attack" : "Attack session"} · <span className={styles.mono}>{session.ip}</span></strong>
							<small>{formatTime(session.firstSeen)} → {formatTime(session.lastSeen)} · {session.hosts.length} host{session.hosts.length === 1 ? "" : "s"}</small>
							<span className={styles.incidentSignals}>{session.signals.slice(0, 5).map((signal) => <i key={signal}>{humanizeSignal(signal)}</i>)}</span>
						</span>
						<span className={styles.incidentMeta}>
							<strong>{session.requests} suspicious req</strong>
							<span className={`badge ${responseBadgeClass(session.activeResponse)}`}>{session.activeResponse ? session.activeResponse.replace("_", " ") : "detected"}</span>
						</span>
					</button>;
				})}
				{filteredAttackSessions.length === 0 ? <div className="p-3 text-secondary">No attack sessions match this incident filter.</div> : null}
			</div>
		</div>

		<div className={styles.insightGrid}>
			<div className={styles.panel}>
				<div className={styles.panelHeader}><h3>Top destinations</h3><span className="text-secondary small">where requests go</span></div>
				<div className={styles.rankList}>{hostStats.map((row) => <button type="button" key={row.name} onClick={() => setHost(row.name)}><span><strong>{row.name || "unknown"}</strong><small>{row.sourceCount} sources · {formatBytes(row.bytes)}</small></span><span><strong>{row.requests}</strong><small>{row.suspicious} suspicious</small></span></button>)}{hostStats.length === 0 ? <div className="p-3 text-secondary">No destinations in this filter.</div> : null}</div>
			</div>
			<div className={styles.panel}>
				<div className={styles.panelHeader}><h3>Risk distribution</h3><span className="text-secondary small">request classification</span></div>
				<div className={styles.barList}>{riskStats.map((row) => <div key={row.label} className={styles.barRow}><span>{row.label}</span><div><i style={{ width: `${events.data?.length ? Math.max(2, (row.count / events.data.length) * 100) : 0}%` }} /></div><strong>{row.count}</strong></div>)}</div>
			</div>
			<div className={styles.panel}>
				<div className={styles.panelHeader}><h3>HTTP status</h3><span className="text-secondary small">response families</span></div>
				<div className={styles.statusGrid}>{statusStats.map((row) => <div key={row.family}><span>{row.family}</span><strong>{row.count}</strong><small>{events.data?.length ? `${Math.round((row.count / events.data.length) * 100)}%` : "0%"}</small></div>)}{statusStats.length === 0 ? <div className="p-3 text-secondary">No responses in this filter.</div> : null}</div>
			</div>
		</div>

		<div className={styles.panel}>
			<div className={styles.panelHeader}><h3>Request timeline</h3><span className="text-secondary small">{events.isFetching ? "Updating…" : `${events.data?.length ?? 0} requests`}</span></div>
			<div className={`${styles.timeline} table-responsive`}><table className="table table-vcenter"><thead><tr><th>Time</th><th>Source</th><th>Request → destination</th><th>Group</th><th>Status</th><th>Risk</th><th>Traffic</th><th /></tr></thead><tbody>
				{(events.data ?? []).map((event, index) => <tr key={event.requestId || `${event.timestamp}-${index}`}>
					<td className="text-nowrap">{formatTime(event.timestamp)}</td>
					<td><button type="button" className="btn btn-link p-0 font-monospace" onClick={() => openSource(event.ip)}>{event.ip}</button></td>
					<td className={styles.requestCell}><button type="button" className={styles.requestLink} onClick={() => event.requestId && openRequest(event.requestId)} disabled={!event.requestId}><span><strong>{event.method}</strong> {event.host}</span><span className={styles.requestPath}>{event.path}</span></button></td>
					<td>{event.groupName ? <span className={styles.groupBadge}>{event.groupName}</span> : <span className="text-secondary">—</span>}</td>
					<td>{event.status || "—"}</td>
					<td><button type="button" className="btn btn-link p-0" onClick={() => event.requestId && openRequest(event.requestId)} disabled={!event.requestId} title="Open why this request is suspicious"><span className={`badge ${riskClass(event.risk)}`}>{event.risk}</span></button></td>
					<td className="text-nowrap"><div>{formatBytes(event.bytesSent)}</div><small className="text-secondary">{event.requestTime ? `${Math.round(event.requestTime * 1000)} ms` : "—"}</small></td>
					<td><button type="button" className="btn btn-sm btn-outline-danger" disabled={block.isPending} onClick={() => block.mutate(event.ip)} title="Block this source IP for 60 minutes"><IconBan size={15} /></button></td>
				</tr>)}
				{!events.isLoading && (events.data?.length ?? 0) === 0 ? <tr><td colSpan={8} className="text-secondary p-4">No requests match these filters.</td></tr> : null}
			</tbody></table></div>
		</div>

		{selectedSourceIp ? <div className={styles.detailBackdrop}>
			<section className={styles.detailPanel} aria-label="Client activity details">
				<div className={styles.detailHeader}>
					<div>
						<div className={styles.detailEyebrow}>Client / source analysis</div>
						<h2 className={styles.mono}>{selectedSourceIp}</h2>
					</div>
					<button type="button" className="btn btn-sm btn-outline-secondary" onClick={() => setSelectedSourceIp(null)}>Close</button>
				</div>
				{sourceDetail.isLoading ? <div className="p-4 text-secondary">Loading client activity…</div> : null}
				{sourceDetail.isError ? <div className="alert alert-danger m-3">Could not load activity for this source.</div> : null}
				{!sourceDetail.isLoading && !sourceDetail.isError ? <div className={styles.detailBody}>
					<div className={styles.clientAssessment}>
						<div>
							<span>Assessment</span>
							<strong><span className={`badge ${assessmentBadgeClass(sourceAssessment.level)}`}>{sourceAssessment.label}</span></strong>
							{sourceActiveBlock ? <small className="d-block mt-1 text-danger">Blocked until {formatTime(sourceActiveBlock.expiresAt)}</small> : null}
						</div>
						<p>
							This is an assessment of network behavior from an IP address, not proof of a specific human identity.
							Correlated account/device information is shown on individual request details when available.
						</p>
					</div>

					{sourceListIsSampled ? <div className="alert alert-info py-2 px-3 mb-0">This client has {sourceOverview.data?.requests.toLocaleString()} matching requests in the 60-minute analysis. Detailed path/rate fields below use the latest {(sourceDetail.data?.length ?? 0).toLocaleString()} listed requests.</div> : null}
					<div className={styles.detailGrid}>
						<div><span>Requests · 60m</span><strong>{sourceOverview.data?.requests ?? sourceAssessment.requests}</strong></div>
						<div><span>{sourceListIsSampled ? "Peak rate · listed" : "Peak request rate"}</span><strong>{sourceAssessment.peakRequestsPerMinute}/60s</strong></div>
						<div><span>Suspicious requests</span><strong>{sourceOverview.data?.suspicious ?? sourceAssessment.suspicious}</strong></div>
						<div><span>Max risk</span><strong>{sourceOverviewRow?.maxRisk ?? sourceAssessment.maxRisk}</strong></div>
						<div><span>{sourceListIsSampled ? "Denied 401/403 · listed" : "Denied 401/403"}</span><strong>{sourceAssessment.denied}</strong></div>
						<div><span>{sourceListIsSampled ? "404 responses · listed" : "404 responses"}</span><strong>{sourceAssessment.missing}</strong></div>
						<div><span>Destinations</span><strong>{sourceOverview.data?.analytics.observedHosts ?? sourceAssessment.hostCount}</strong></div>
						<div><span>{sourceListIsSampled ? "Unique paths · listed" : "Unique paths"}</span><strong>{sourceAssessment.uniquePaths}</strong></div>
						<div><span>First seen · 60m</span><strong>{formatTime(sourceOverviewRow?.firstSeen ?? sourceAssessment.firstSeen)}</strong></div>
						<div><span>Last seen</span><strong>{formatTime(sourceOverviewRow?.lastSeen ?? sourceAssessment.lastSeen)}</strong></div>
						<div><span>Crawler detected</span><strong>{sourceAssessment.crawlerDetected ? "Yes" : "No"}</strong></div>
						<div><span>Response traffic</span><strong>{formatBytes(sourceOverview.data?.analytics.responseBytes ?? sourceAssessment.bytes)}</strong></div>
					</div>

					{sourceActiveBlock ? <div className={styles.detailSection}>
						<h3>Active block / observed attempts</h3>
						<div className={styles.detailGridCompact}>
							<div><span>Blocked since</span><strong>{formatTime(sourceActiveBlock.createdAt)}</strong></div>
							<div><span>Expires</span><strong>{formatTime(sourceActiveBlock.expiresAt)}</strong></div>
							<div><span>Response source</span><strong>{sourceActiveBlock.source}</strong></div>
							<div><span>403s after block</span><strong>{sourceBlockedAttempts}</strong></div>
						</div>
						<div className={styles.codeLine}>{sourceActiveBlock.reason}</div>
						<div className="text-secondary small mt-2">Blocked requests remain in HYROVI Sec traffic logs, so attempts after enforcement stay visible in this profile and the request timeline.</div>
					</div> : null}

					<div className={styles.detailSection}>
						<h3>Traffic shape</h3>
						<div className={styles.trafficBreakdown}>
							<div><span>Methods</span>{sourceMethods.map((row) => <strong key={row.name}>{row.name} <small>{row.count}</small></strong>)}</div>
							<div><span>Status families</span>{sourceStatuses.map((row) => <strong key={row.name}>{row.name} <small>{row.count}</small></strong>)}</div>
						</div>
					</div>

					<div className={styles.detailSection}>
						<h3>Most relevant paths</h3>
						<div className={styles.pathList}>
							{sourcePaths.map((row) => <button type="button" key={row.path} onClick={() => { setSearch(row.path); setIp(selectedSourceIp); setSelectedSourceIp(null); }}>
								<span className={styles.mono}>{row.path}</span>
								<span><strong>{row.count}</strong><small>risk {row.maxRisk} · {row.statuses.join(", ") || "no status"}</small></span>
							</button>)}
							{sourcePaths.length === 0 ? <div className="text-secondary p-2">No paths in this window.</div> : null}
						</div>
					</div>

					<div className={styles.detailSection}>
						<h3>Why this is {sourceAssessment.label.toLowerCase()}</h3>
						<div className={styles.reasonList}>
							{sourceAssessment.reasons.map((reason, index) => <div key={`${index}-${reason}`}>{reason}</div>)}
						</div>
					</div>

					<div className={styles.detailSection}>
						<h3>Detected signals</h3>
						<div className={styles.signalList}>
							{sourceAssessment.signals.length ? sourceAssessment.signals.slice(0, 10).map((signal) => <div key={signal.id} className={styles.signalRow}><span>{signal.label}<small>{signal.count} matching request{signal.count === 1 ? "" : "s"}</small></span><strong>+{signal.score}</strong></div>) : <div className="text-secondary">No suspicious signals detected.</div>}
						</div>
					</div>

					<div className={styles.detailSection}>
						<h3>Destinations</h3>
						<div className={styles.rankList}>
							{sourceDestinations.map((row) => <button type="button" key={row.name} onClick={() => { setHost(row.name); setIp(selectedSourceIp); setSelectedSourceIp(null); }}><span><strong>{row.name}</strong><small>{row.suspicious} suspicious · max risk {row.maxRisk}</small></span><span><strong>{row.requests}</strong><small>requests</small></span></button>)}
							{sourceDestinations.length === 0 ? <div className="text-secondary p-2">No destinations in the last hour.</div> : null}
						</div>
					</div>

					<div className={styles.detailSection}>
						<h3>Correlated identities / devices</h3>
						{sourceIdentities.length ? <div className={styles.identityList}>
							{sourceIdentities.map((identity) => <div key={identity.key}>
								<span>
									<strong>{identity.app}</strong>
									<small>{identity.accountId ? `account ${identity.accountId}` : identity.sessionId ? `session ${identity.sessionId}` : "no account/session"}</small>
								</span>
								<span>
									<strong>{identity.deviceId ? `${identity.deviceTrust === "verified" ? "Verified " : ""}device ${identity.deviceId}` : "No device"}</strong>
									<small>{identity.deviceName || `last seen ${formatTime(identity.lastSeen)}`}</small>
								</span>
							</div>)}
						</div> : <div className="text-secondary">No HYROVI app/auth identity is correlated with this IP. Treat it as a network client, not a known person.</div>}
					</div>

					<div className={styles.detailSection}>
						<h3>Client signatures</h3>
						<div className={styles.signalList}>
							{sourceUserAgents.map((row) => <div key={row.name} className={styles.signalRow}><span className={styles.mono}>{row.name}</span><strong>{row.count}</strong></div>)}
							{sourceUserAgents.length === 0 ? <div className="text-secondary">No user-agent data.</div> : null}
						</div>
					</div>

					<div className={styles.detailSection}>
						<div className={styles.detailSectionHeader}>
							<h3>Recent requests</h3>
							<div className="d-flex gap-2">
								<button type="button" className="btn btn-sm btn-outline-secondary" onClick={() => { setIp(selectedSourceIp); setSelectedSourceIp(null); }}>Filter dashboard</button>
								<button type="button" className="btn btn-sm btn-outline-danger" disabled={block.isPending} onClick={() => block.mutate(selectedSourceIp)}><IconBan size={14} /> Block 60m</button>
							</div>
						</div>
						<div className={styles.similarList}>
							{(sourceDetail.data ?? []).slice(0, 20).map((event, index) => <button type="button" key={event.requestId || `${event.timestamp}-${index}`} onClick={() => event.requestId && openRequest(event.requestId)} disabled={!event.requestId}><span>{event.method} {event.host}{event.path}<small>{formatTime(event.timestamp)} · HTTP {event.status}{sourceActiveBlock && event.timestamp && event.status === 403 && new Date(event.timestamp).getTime() >= new Date(sourceActiveBlock.createdAt).getTime() ? " · blocked attempt" : ""}</small></span><strong><span className={`badge ${riskClass(event.risk)}`}>{event.risk}</span></strong></button>)}
						</div>
					</div>
				</div> : null}
			</section>
		</div> : null}

		{selectedSessionId ? <div className={styles.detailBackdrop}>
			<section className={styles.detailPanel} aria-label="Attack session details">
				<div className={styles.detailHeader}>
					<div><div className={styles.detailEyebrow}>Attack / incident session</div><h2>{attackSessionDetail.data?.signals.includes("crawler_attack") ? "Crawler attack" : "Attack session"}</h2></div>
					<button type="button" className="btn btn-sm btn-outline-secondary" onClick={() => setSelectedSessionId(null)}>Close</button>
				</div>
				{attackSessionDetail.isLoading ? <div className="p-4 text-secondary">Loading incident…</div> : null}
				{attackSessionDetail.isError ? <div className="alert alert-danger m-3">Could not load this attack session.</div> : null}
				{attackSessionDetail.data ? <div className={styles.detailBody}>
					<div className={styles.clientAssessment}>
						<div>
							<span>Source</span>
							<strong className={styles.mono}>{attackSessionDetail.data.ip}</strong>
							<small className="d-block mt-1">{attackSessionDetail.data.activeResponse ? `Response: ${attackSessionDetail.data.activeResponse.replace("_", " ")}` : "Detected · no active response"}</small>
						</div>
						<p>This session groups suspicious requests from one source that occurred within the server-side five-minute correlation window. Response actions and app/device events are correlated into the same incident.</p>
					</div>
					<div className={styles.detailGrid}>
						<div><span>Suspicious requests</span><strong>{attackSessionDetail.data.requests}</strong></div>
						<div><span>Max risk</span><strong><span className={`badge ${riskClass(attackSessionDetail.data.maxRisk)}`}>{attackSessionDetail.data.maxRisk}</span></strong></div>
						<div><span>First seen</span><strong>{formatTime(attackSessionDetail.data.firstSeen)}</strong></div>
						<div><span>Last seen</span><strong>{formatTime(attackSessionDetail.data.lastSeen)}</strong></div>
						<div><span>Target hosts</span><strong>{attackSessionDetail.data.hosts.length}</strong></div>
						<div><span>Response</span><strong><span className={`badge ${responseBadgeClass(attackSessionDetail.data.activeResponse)}`}>{attackSessionDetail.data.activeResponse ?? "none"}</span></strong></div>
					</div>
					<div className={styles.detailSection}>
						<h3>Attack signals</h3>
						<div className={styles.incidentSignalsLarge}>{attackSessionDetail.data.signals.map((signal) => <span key={signal}>{humanizeSignal(signal)}</span>)}</div>
					</div>
					<div className={styles.detailSection}>
						<h3>Target / request patterns</h3>
						<div className={styles.pathList}>
							{attackSessionDetail.data.requestPatterns.map((pattern) => <button type="button" key={`${pattern.method}-${pattern.host}-${pattern.path}`} onClick={() => { setIp(attackSessionDetail.data?.ip ?? ""); setHost(pattern.host); setSearch(pattern.path); setSelectedSessionId(null); }}>
								<span><strong>{pattern.method} {pattern.host}</strong><small className={styles.mono}>{pattern.path}</small></span>
								<span><strong>{pattern.count}</strong><small>risk {pattern.maxRisk} · {pattern.statuses.join(", ") || "—"}</small></span>
							</button>)}
						</div>
					</div>
					<div className={styles.detailSection}>
						<div className={styles.detailSectionHeader}>
							<h3>Response history</h3>
							{attackSessionDetail.data.activeResponse !== "block" ? <button type="button" className="btn btn-sm btn-outline-danger" disabled={block.isPending} onClick={() => block.mutate(attackSessionDetail.data.ip)}><IconBan size={14} /> Block IP 60m</button> : null}
						</div>
						<div className={styles.signalList}>
							{attackSessionDetail.data.responseHistory.length ? attackSessionDetail.data.responseHistory.map((entry) => <div key={entry.id} className={styles.signalRow}><span><strong>{entry.type.replace("_", " ")} · {entry.action}</strong><small>{entry.reason}</small></span><strong>{formatTime(entry.at)}</strong></div>) : <div className="text-secondary">No response history for this incident.</div>}
						</div>
					</div>
					<div className={styles.detailSection}>
						<h3>Correlated entities</h3>
						<div className={styles.detailGridCompact}>
							<div><span>Apps</span><strong>{attackSessionDetail.data.correlation.entities.apps.length}</strong></div>
							<div><span>Accounts</span><strong>{attackSessionDetail.data.correlation.entities.accountIds.length}</strong></div>
							<div><span>Devices</span><strong>{attackSessionDetail.data.correlation.entities.deviceIds.length}</strong></div>
							<div><span>Verified devices</span><strong>{attackSessionDetail.data.correlation.entities.verifiedDeviceIds.length}</strong></div>
						</div>
					</div>
					<div className={styles.detailSection}>
						<h3>Incident timeline</h3>
						<div className={styles.incidentTimeline}>
							{attackSessionDetail.data.correlation.items.slice(0, 40).map((item) => <button type="button" key={item.id} disabled={!item.requestId} onClick={() => item.requestId && openRequest(item.requestId)}>
								<span className={styles.incidentTimelineTime}>{formatTime(item.timestamp)}</span>
								<span><strong>{item.summary}</strong><small>{item.detail || [item.host, item.app].filter(Boolean).join(" · ") || item.kind.replace("_", " ")}</small></span>
								<span>{item.risk !== null ? <span className={`badge ${riskClass(item.risk)}`}>{item.risk}</span> : <span className="badge bg-secondary-lt">{item.kind.replace("_", " ")}</span>}</span>
							</button>)}
							{attackSessionDetail.data.correlation.items.length === 0 ? <div className="text-secondary">No correlated timeline items.</div> : null}
						</div>
					</div>
				</div> : null}
			</section>
		</div> : null}

		{selectedRequestId ? <div className={styles.detailBackdrop}>
			<section className={styles.detailPanel} aria-label="Request details">
				<div className={styles.detailHeader}><div><div className={styles.detailEyebrow}>Request inspection</div><h2>{requestDetail.data?.method ?? "Request"} {requestDetail.data?.host ?? ""}</h2></div><button type="button" className="btn btn-sm btn-outline-secondary" onClick={() => setSelectedRequestId(null)}>Close</button></div>
				{requestDetail.isLoading ? <div className="p-4 text-secondary">Loading request…</div> : null}
				{requestDetail.isError ? <div className="alert alert-danger m-3">Could not load this request.</div> : null}
				{requestDetail.data ? <div className={styles.detailBody}>
					<div className={styles.detailGrid}>
						<div><span>Source IP</span><strong className={styles.mono}>{requestDetail.data.ip}</strong></div>
						<div><span>Status</span><strong>{requestDetail.data.status || "—"}</strong></div>
						<div><span>Risk</span><strong><span className={`badge ${riskClass(requestDetail.data.risk)}`}>{requestDetail.data.risk}</span></strong></div>
						<div><span>Policy</span><strong>{requestDetail.data.policySource}{requestDetail.data.groupName ? ` · ${requestDetail.data.groupName}` : ""}</strong></div>
						<div><span>Request ID</span><strong className={styles.mono}>{requestDetail.data.requestId || "—"}</strong></div>
						<div><span>Time</span><strong>{formatTime(requestDetail.data.timestamp)}</strong></div>
						<div><span>Response traffic</span><strong>{formatBytes(requestDetail.data.bytesSent)}</strong></div>
						<div><span>Request time</span><strong>{requestDetail.data.requestTime ? `${Math.round(requestDetail.data.requestTime * 1000)} ms` : "—"}</strong></div>
					</div>
					<div className={styles.detailSection}><h3>Destination</h3><div className={styles.codeLine}>{requestDetail.data.method} https://{requestDetail.data.host}{requestDetail.data.path}</div></div>
					<div className={styles.detailSection}><h3>Client</h3><div className={styles.codeLine}>{requestDetail.data.userAgent || "No user agent"}</div></div>
					<div className={styles.detailSection}><h3>Identity & device correlation</h3>{requestDetail.data.appEvents.length ? <div className={styles.identityList}>{requestDetail.data.appEvents.slice(0, 12).map((appEvent) => <div key={appEvent.id}><span><strong>{appEvent.app}</strong><small>{appEvent.eventType} · {formatTime(appEvent.timestamp)}</small></span><span>{appEvent.accountId ? `account ${appEvent.accountId}` : appEvent.sessionId ? `session ${appEvent.sessionId}` : "no account"}<small>{appEvent.deviceId ? `${appEvent.deviceTrust === "verified" ? "verified " : ""}device ${appEvent.deviceId}` : "no device"}</small></span></div>)}</div> : <div className="text-secondary">No app/auth event is correlated with this request.</div>}</div>
					{requestDetail.data.attackSession ? <div className={styles.detailSection}><div className={styles.detailSectionHeader}><h3>Attack session</h3><button type="button" className="btn btn-sm btn-outline-secondary" onClick={() => openSession(requestDetail.data?.attackSession?.id ?? "")}>Open incident</button></div><div className={styles.detailGridCompact}><div><span>Requests</span><strong>{requestDetail.data.attackSession.requests}</strong></div><div><span>Max risk</span><strong>{requestDetail.data.attackSession.maxRisk}</strong></div><div><span>Hosts</span><strong>{requestDetail.data.attackSession.hosts.length}</strong></div><div><span>Response</span><strong>{requestDetail.data.attackSession.activeResponse ?? "none"}</strong></div></div></div> : null}
					<div className={styles.detailSection}><h3>Why this request is suspicious</h3><div className={styles.signalList}>{requestDetail.data.signals.length ? requestDetail.data.signals.map((signal) => <div key={signal.id} className={styles.signalRow}><span>{signal.label}</span><strong>+{signal.score}</strong></div>) : <div className="text-secondary">No suspicious signals on this request.</div>}</div></div>
					<div className={styles.detailSection}><h3>Active responses</h3><div className={styles.signalList}>{requestDetail.data.activeResponses.length ? requestDetail.data.activeResponses.map((response) => <div key={response.id} className={styles.signalRow}><span>{response.type.replace("_", " ")}</span><strong>{response.expiresAt ? formatTime(response.expiresAt) : "active"}</strong></div>) : <div className="text-secondary">No active response for this source.</div>}</div></div>
					<div className={styles.detailSection}><div className={styles.detailSectionHeader}><h3>Similar requests</h3><button type="button" className="btn btn-sm btn-outline-danger" disabled={block.isPending} onClick={() => block.mutate(requestDetail.data.ip)}><IconBan size={14} /> Block IP 60m</button></div><div className={styles.similarList}>{requestDetail.data.similarRequests.slice(0, 8).map((item) => <button type="button" key={item.requestId || `${item.timestamp}-${item.path}`} onClick={() => item.requestId && openRequest(item.requestId)}><span>{item.method} {item.host}{item.path}</span><strong>{Math.round(item.similarityScore * 100)}%</strong></button>)}{requestDetail.data.similarRequests.length === 0 ? <div className="text-secondary">No similar requests found.</div> : null}</div></div>
				</div> : null}
			</section>
		</div> : null}
	</div>;
}
