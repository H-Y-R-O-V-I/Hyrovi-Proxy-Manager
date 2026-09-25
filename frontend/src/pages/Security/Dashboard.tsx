import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { IconBan, IconRefresh } from "@tabler/icons-react";
import { useMemo, useState } from "react";
import {
	createSecurityBlock,
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

	const overview = useQuery({ queryKey: ["security-overview"], queryFn: getSecurityOverview, refetchInterval: 5000 });
	const groups = useQuery({ queryKey: ["security-host-groups"], queryFn: getSecurityHostGroups, refetchInterval: 15000 });
	const events = useQuery({
		queryKey: ["security-dashboard-events", search, ip, host, method, status, minRisk, groupId, sinceMinutes],
		queryFn: () => getSecurityEvents({ limit: 1500, search, ip, host, method, status: status || undefined, minRisk, groupId, sinceMinutes }),
		refetchInterval: 5000,
	});
	const requestDetail = useQuery({
		queryKey: ["security-dashboard-event-detail", selectedRequestId],
		queryFn: () => getSecurityEventDetail(selectedRequestId as string),
		enabled: Boolean(selectedRequestId),
		refetchInterval: selectedRequestId ? 5000 : false,
	});

	const sourceStats = useMemo(() => {
		const map = new Map<string, { requests: number; maxRisk: number; hosts: Set<string> }>();
		for (const event of events.data ?? []) {
			const row = map.get(event.ip) ?? { requests: 0, maxRisk: 0, hosts: new Set<string>() };
			row.requests += 1; row.maxRisk = Math.max(row.maxRisk, event.risk); row.hosts.add(event.host); map.set(event.ip, row);
		}
		return [...map.entries()]
			.map(([source, row]) => ({ source, ...row, hostCount: row.hosts.size }))
			.sort((a, b) => b.requests - a.requests || b.maxRisk - a.maxRisk);
	}, [events.data]);
	const sourceRows = sourceStats.slice(0, 12);

	const hostOptions = useMemo(() => [...new Set((events.data ?? []).map((event) => event.host).filter(Boolean))].sort(), [events.data]);
	const buckets = useMemo(() => buildBuckets(events.data ?? [], sinceMinutes), [events.data, sinceMinutes]);
	const requestPoints = polyline(buckets.map((bucket) => bucket.requests));
	const suspiciousPoints = polyline(buckets.map((bucket) => bucket.suspicious));

	const block = useMutation({
		mutationFn: (sourceIp: string) => createSecurityBlock({ ip: sourceIp, durationMinutes: 60, reason: "Blocked from Security dashboard", source: "dashboard" }),
		onSuccess: async () => { await queryClient.invalidateQueries({ queryKey: ["security-overview"] }); },
	});

	const refresh = async () => {
		await Promise.all([queryClient.invalidateQueries({ queryKey: ["security-overview"] }), queryClient.invalidateQueries({ queryKey: ["security-dashboard-events"] }), queryClient.invalidateQueries({ queryKey: ["security-host-groups"] })]);
	};

	return <div className={styles.shell}>
		<div className={styles.hero}>
			<div><h1>Security traffic</h1><p>Live request flow, sources, destinations and risk — behind Cloudflare with the real client IP.</p></div>
			<button type="button" className="btn btn-outline-secondary" onClick={refresh}><IconRefresh size={17} /> Refresh</button>
		</div>

		<div className={styles.metrics}>
			<div className={styles.metric}><div className={styles.metricLabel}>Requests in window</div><div className={styles.metricValue}>{events.data?.length ?? 0}</div></div>
			<div className={styles.metric}><div className={styles.metricLabel}>Unique source IPs</div><div className={styles.metricValue}>{sourceStats.length}</div></div>
			<div className={styles.metric}><div className={styles.metricLabel}>Suspicious</div><div className={styles.metricValue}>{(events.data ?? []).filter((event) => event.risk >= 40).length}</div></div>
			<div className={styles.metric}><div className={styles.metricLabel}>Active blocks</div><div className={styles.metricValue}>{overview.data?.activeBlocks ?? 0}</div></div>
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
		</div>

		<div className={styles.gridTwo}>
			<div className={styles.panel}>
				<div className={styles.panelHeader}><h3>Request volume</h3><div className={styles.chartLegend}><span className={styles.legendItem}>All requests</span><span className={styles.legendItem}>Risk 40+</span></div></div>
				<svg className={styles.chart} viewBox="0 0 1000 190" preserveAspectRatio="none" role="img" aria-label="Request volume timeline">
					<line x1="0" y1="180" x2="1000" y2="180" stroke="currentColor" opacity="0.15" />
					<polyline points={requestPoints} fill="none" stroke="currentColor" strokeWidth="4" vectorEffect="non-scaling-stroke" />
					<polyline points={suspiciousPoints} fill="none" stroke="var(--tblr-danger)" strokeWidth="3" vectorEffect="non-scaling-stroke" />
				</svg>
			</div>
			<div className={styles.panel}>
				<div className={styles.panelHeader}><h3>Top source IPs</h3><span className="text-secondary small">filtered window</span></div>
				<div className={styles.sourceList}>{sourceRows.map((row) => <button type="button" className={`${styles.sourceRow} btn btn-link text-start text-reset`} key={row.source} onClick={() => setIp(row.source)}><span className={styles.mono}>{row.source}</span><span>{row.requests} req</span><span className={styles.risk}>{row.maxRisk}</span></button>)}{sourceRows.length === 0 ? <div className="p-3 text-secondary">No traffic in this filter.</div> : null}</div>
			</div>
		</div>

		<div className={styles.panel}>
			<div className={styles.panelHeader}><h3>Request timeline</h3><span className="text-secondary small">{events.isFetching ? "Updating…" : `${events.data?.length ?? 0} requests`}</span></div>
			<div className={`${styles.timeline} table-responsive`}><table className="table table-vcenter"><thead><tr><th>Time</th><th>Source</th><th>Request → destination</th><th>Group</th><th>Status</th><th>Risk</th><th>Traffic</th><th /></tr></thead><tbody>
				{(events.data ?? []).map((event, index) => <tr key={event.requestId || `${event.timestamp}-${index}`}>
					<td className="text-nowrap">{formatTime(event.timestamp)}</td>
					<td><button type="button" className="btn btn-link p-0 font-monospace" onClick={() => setIp(event.ip)}>{event.ip}</button></td>
					<td className={styles.requestCell}><button type="button" className={styles.requestLink} onClick={() => event.requestId && setSelectedRequestId(event.requestId)} disabled={!event.requestId}><span><strong>{event.method}</strong> {event.host}</span><span className={styles.requestPath}>{event.path}</span></button></td>
					<td>{event.groupName ? <span className={styles.groupBadge}>{event.groupName}</span> : <span className="text-secondary">—</span>}</td>
					<td>{event.status || "—"}</td>
					<td><span className={`badge ${riskClass(event.risk)}`}>{event.risk}</span></td>
					<td className="text-nowrap">{formatBytes(event.bytesSent)}</td>
					<td><button type="button" className="btn btn-sm btn-outline-danger" disabled={block.isPending} onClick={() => block.mutate(event.ip)} title="Block this source IP for 60 minutes"><IconBan size={15} /></button></td>
				</tr>)}
				{!events.isLoading && (events.data?.length ?? 0) === 0 ? <tr><td colSpan={8} className="text-secondary p-4">No requests match these filters.</td></tr> : null}
			</tbody></table></div>
		</div>

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
					</div>
					<div className={styles.detailSection}><h3>Destination</h3><div className={styles.codeLine}>{requestDetail.data.method} https://{requestDetail.data.host}{requestDetail.data.path}</div></div>
					<div className={styles.detailSection}><h3>Client</h3><div className={styles.codeLine}>{requestDetail.data.userAgent || "No user agent"}</div></div>
					<div className={styles.detailSection}><h3>Risk signals</h3><div className={styles.signalList}>{requestDetail.data.signals.length ? requestDetail.data.signals.map((signal) => <div key={signal.id} className={styles.signalRow}><span>{signal.label}</span><strong>+{signal.score}</strong></div>) : <div className="text-secondary">No suspicious signals on this request.</div>}</div></div>
					<div className={styles.detailSection}><h3>Active responses</h3><div className={styles.signalList}>{requestDetail.data.activeResponses.length ? requestDetail.data.activeResponses.map((response) => <div key={response.id} className={styles.signalRow}><span>{response.type.replace("_", " ")}</span><strong>{response.expiresAt ? formatTime(response.expiresAt) : "active"}</strong></div>) : <div className="text-secondary">No active response for this source.</div>}</div></div>
					<div className={styles.detailSection}><h3>Similar requests</h3><div className={styles.similarList}>{requestDetail.data.similarRequests.slice(0, 8).map((item) => <button type="button" key={item.requestId || `${item.timestamp}-${item.path}`} onClick={() => item.requestId && setSelectedRequestId(item.requestId)}><span>{item.method} {item.host}{item.path}</span><strong>{Math.round(item.similarityScore * 100)}%</strong></button>)}{requestDetail.data.similarRequests.length === 0 ? <div className="text-secondary">No similar requests found.</div> : null}</div></div>
				</div> : null}
			</section>
		</div> : null}
	</div>;
}
