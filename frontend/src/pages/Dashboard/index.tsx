import { useQuery } from "@tanstack/react-query";
import {
	IconActivity,
	IconArrowsCross,
	IconBan,
	IconBolt,
	IconBoltOff,
	IconDisc,
	IconNetwork,
	IconPlus,
	IconRoute,
	IconShield,
	IconWorld,
} from "@tabler/icons-react";
import { useNavigate } from "react-router-dom";
import { getSecurityOverview } from "src/api/backend";
import { HasPermission } from "src/components";
import { useHostReport, useUser } from "src/hooks";
import { showDeadHostModal, showProxyHostModal, showRedirectionHostModal, showStreamModal } from "src/modals";
import {
	ADMIN,
	DEAD_HOSTS,
	MANAGE,
	PROXY_HOSTS,
	REDIRECTION_HOSTS,
	STREAMS,
	VIEW,
} from "src/modules/Permissions";
import styles from "./Dashboard.module.css";

const formatBytes = (bytes: number) => {
	if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
	const units = ["B", "KB", "MB", "GB", "TB"];
	let value = bytes;
	let unit = 0;
	while (value >= 1024 && unit < units.length - 1) {
		value /= 1024;
		unit += 1;
	}
	return `${value >= 10 || unit === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[unit]}`;
};

const Dashboard = () => {
	const { data: hostReport } = useHostReport();
	const { data: currentUser } = useUser("me");
	const isAdmin = currentUser?.roles.includes("admin") ?? false;
	const navigate = useNavigate();
	const security = useQuery({
		queryKey: ["security-overview"],
		queryFn: () => getSecurityOverview(),
		enabled: isAdmin,
		refetchInterval: 5000,
		retry: false,
	});

	const analytics = security.data?.analytics;
	const trafficSources = analytics?.trafficSources ?? [];
	const topTargets = analytics?.topTargets ?? [];

	const hostCards = [
		{ label: "Proxy hosts", count: hostReport?.proxy ?? "—", to: "/nginx/proxy", icon: IconBolt, section: PROXY_HOSTS },
		{ label: "Redirects", count: hostReport?.redirection ?? "—", to: "/nginx/redirection", icon: IconArrowsCross, section: REDIRECTION_HOSTS },
		{ label: "Streams", count: hostReport?.stream ?? "—", to: "/nginx/stream", icon: IconDisc, section: STREAMS },
		{ label: "404 hosts", count: hostReport?.dead ?? "—", to: "/nginx/404", icon: IconBoltOff, section: DEAD_HOSTS },
	] as const;

	return (
		<div className={styles.page}>
			<div className={styles.hero}>
				<div>
					<div className={styles.eyebrow}>HYROVI NETWORK EDGE</div>
					<h1>Proxy Manager</h1>
					<p>Traffic, hosts and HYROVI Sec in one control surface.</p>
				</div>
				<div className={styles.heroActions}>
					<div className={`dropdown ${styles.quickCreate}`}>
						<button type="button" className={styles.quickCreateButton} data-bs-toggle="dropdown" aria-expanded="false" aria-label="Create host">
							<IconPlus size={24} />
						</button>
						<div className={`dropdown-menu dropdown-menu-end ${styles.quickCreateMenu}`}>
							<div className={styles.quickCreateHeader}>Create</div>
							<HasPermission section={PROXY_HOSTS} permission={MANAGE} hideError>
								<button type="button" className="dropdown-item" onClick={() => showProxyHostModal("new")}><IconBolt size={17} /><span><strong>Proxy host</strong><small>Route a domain to an application</small></span></button>
							</HasPermission>
							<HasPermission section={REDIRECTION_HOSTS} permission={MANAGE} hideError>
								<button type="button" className="dropdown-item" onClick={() => showRedirectionHostModal("new")}><IconArrowsCross size={17} /><span><strong>Redirect host</strong><small>Redirect a domain or path</small></span></button>
							</HasPermission>
							<HasPermission section={DEAD_HOSTS} permission={MANAGE} hideError>
								<button type="button" className="dropdown-item" onClick={() => showDeadHostModal("new")}><IconBoltOff size={17} /><span><strong>404 host</strong><small>Return a managed dead-host response</small></span></button>
							</HasPermission>
							<HasPermission section={STREAMS} permission={MANAGE} hideError>
								<button type="button" className="dropdown-item" onClick={() => showStreamModal("new")}><IconDisc size={17} /><span><strong>Stream</strong><small>Forward TCP/UDP traffic</small></span></button>
							</HasPermission>
						</div>
					</div>
					<div className={styles.statusStrip}>
						<span className={styles.liveDot} />
						<span>Live telemetry</span>
						<span className={styles.statusDivider} />
						<span>Real client IP via Cloudflare</span>
					</div>
				</div>
			</div>

			{isAdmin ? (
				<>
					<div className={styles.metrics}>
						<div className={styles.metric}>
							<div className={styles.metricIcon}><IconActivity size={18} /></div>
							<div><span>Requests analyzed</span><strong>{security.data?.requests ?? "—"}</strong></div>
						</div>
						<div className={styles.metric}>
							<div className={styles.metricIcon}><IconNetwork size={18} /></div>
							<div><span>Client IPs</span><strong>{analytics?.observedSources ?? "—"}</strong></div>
						</div>
						<div className={styles.metric}>
							<div className={styles.metricIcon}><IconShield size={18} /></div>
							<div><span>Suspicious</span><strong>{security.data?.suspicious ?? "—"}</strong></div>
						</div>
						<div className={styles.metric}>
							<div className={styles.metricIcon}><IconBan size={18} /></div>
							<div><span>Active blocks</span><strong>{security.data?.activeBlocks ?? "—"}</strong></div>
						</div>
					</div>

					<div className={styles.analyticsGrid}>
						<section className={styles.panel}>
							<div className={styles.panelHeader}>
								<div><span className={styles.panelKicker}>TRAFFIC</span><h2>Client IP overview</h2></div>
								<button type="button" className="btn btn-sm btn-outline-secondary" onClick={() => navigate("/security")}>Open security</button>
							</div>
							<div className="table-responsive">
								<table className="table table-vcenter table-sm mb-0">
									<thead><tr><th>IP</th><th>Requests</th><th>Hosts</th><th>Traffic</th><th>Risk</th></tr></thead>
									<tbody>
										{trafficSources.slice(0, 10).map((source) => (
											<tr key={source.ip}>
												<td><span className="font-monospace fw-semibold">{source.ip}</span></td>
												<td>{source.requests}<div className="text-secondary small">{source.suspicious} suspicious</div></td>
												<td>{source.hosts.length}</td>
												<td>{formatBytes(source.bytesSent)}</td>
												<td><span className={`badge ${source.maxRisk >= 80 ? "bg-red-lt" : source.maxRisk >= 40 ? "bg-yellow-lt" : "bg-green-lt"}`}>{source.maxRisk}</span></td>
											</tr>
										))}
										{!security.isLoading && trafficSources.length === 0 ? <tr><td colSpan={5} className="text-secondary py-4">No traffic captured yet.</td></tr> : null}
									</tbody>
								</table>
							</div>
						</section>

						<section className={styles.panel}>
							<div className={styles.panelHeader}>
								<div><span className={styles.panelKicker}>HYROVI SEC</span><h2>Attack targets</h2></div>
								<IconRoute size={20} />
							</div>
							<div className={styles.targetList}>
								{topTargets.slice(0, 7).map((target) => (
									<div className={styles.targetRow} key={target.host + target.path}>
										<div className={styles.targetMain}><strong>{target.host}</strong><span>{target.path}</span></div>
										<div className={styles.targetMeta}><span>{target.requests} hits</span><span>risk {target.maxRisk}</span></div>
									</div>
								))}
								{!security.isLoading && topTargets.length === 0 ? <div className={styles.empty}>No suspicious targets in the current window.</div> : null}
							</div>
						</section>
					</div>
				</>
			) : null}

			<section className={styles.hostSection}>
				<div className={styles.sectionHeading}><div><span className={styles.panelKicker}>ROUTING</span><h2>Proxy services</h2></div><IconWorld size={20} /></div>
				<div className={styles.hostGrid}>
					{hostCards.map((card) => (
						<HasPermission key={card.to} section={card.section} permission={VIEW} hideError>
							<button type="button" className={styles.hostCard} onClick={() => navigate(card.to)}>
								<card.icon size={20} />
								<span>{card.label}</span>
								<strong>{card.count}</strong>
							</button>
						</HasPermission>
					))}
				</div>
			</section>

			<HasPermission section={ADMIN} permission={VIEW} hideError>
				<div className={styles.footerNote}>HYROVI Proxy Manager · HYROVI Sec telemetry updates every 5 seconds</div>
			</HasPermission>
		</div>
	);
};

export default Dashboard;
