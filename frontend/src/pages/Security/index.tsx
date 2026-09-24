import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { IconBan, IconRefresh, IconShield } from "@tabler/icons-react";
import { useMemo, useState } from "react";
import {
	createSecurityBlock,
	deleteSecurityBlock,
	getSecurityBlocks,
	getSecurityEvents,
	getSecurityOverview,
	getSecurityPolicy,
	updateSecurityPolicy,
	type SecurityEvent,
} from "src/api/backend";
import { Button, HasPermission } from "src/components";
import { ADMIN, VIEW } from "src/modules/Permissions";

const POLL_MS = 5000;

const severityClass = (severity: SecurityEvent["severity"]) => {
	switch (severity) {
		case "critical":
			return "bg-red text-white";
		case "high":
			return "bg-orange text-white";
		case "medium":
			return "bg-yellow text-dark";
		case "low":
			return "bg-azure-lt";
		default:
			return "bg-green-lt";
	}
};

const formatTime = (value: string | null) => {
	if (!value) return "—";
	const date = new Date(value);
	return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
};

const Security = () => {
	const queryClient = useQueryClient();
	const [minRisk, setMinRisk] = useState(20);
	const [ip, setIp] = useState("");
	const [reason, setReason] = useState("");
	const [durationMinutes, setDurationMinutes] = useState(60);

	const overview = useQuery({
		queryKey: ["security-overview"],
		queryFn: getSecurityOverview,
		refetchInterval: POLL_MS,
	});

	const events = useQuery({
		queryKey: ["security-events", minRisk],
		queryFn: () => getSecurityEvents(300, minRisk),
		refetchInterval: POLL_MS,
	});

	const blocks = useQuery({
		queryKey: ["security-blocks"],
		queryFn: getSecurityBlocks,
		refetchInterval: POLL_MS,
	});

	const policy = useQuery({
		queryKey: ["security-policy"],
		queryFn: getSecurityPolicy,
	});

	const refresh = async () => {
		await Promise.all([
			queryClient.invalidateQueries({ queryKey: ["security-overview"] }),
			queryClient.invalidateQueries({ queryKey: ["security-events"] }),
			queryClient.invalidateQueries({ queryKey: ["security-blocks"] }),
		]);
	};

	const addBlock = useMutation({
		mutationFn: createSecurityBlock,
		onSuccess: async () => {
			setIp("");
			setReason("");
			await refresh();
		},
	});

	const removeBlock = useMutation({
		mutationFn: deleteSecurityBlock,
		onSuccess: refresh,
	});

	const updatePolicy = useMutation({
		mutationFn: updateSecurityPolicy,
		onSuccess: async () => {
			await Promise.all([
				queryClient.invalidateQueries({ queryKey: ["security-policy"] }),
				queryClient.invalidateQueries({ queryKey: ["security-overview"] }),
			]);
		},
	});

	const topSessions = useMemo(() => overview.data?.attackSessions ?? [], [overview.data]);

	const blockFromEvent = (event: SecurityEvent) => {
		setIp(event.ip);
		setReason(
			event.signals.length > 0
				? `HYROVI Sec: ${event.signals.map((signal) => signal.label).join(", ")}`
				: "HYROVI Sec suspicious request",
		);
		window.scrollTo({ top: 0, behavior: "smooth" });
	};

	return (
		<HasPermission section={ADMIN} permission={VIEW} pageLoading loadingNoLogo>
			<div>
				<div className="d-flex align-items-center justify-content-between mb-3">
					<div>
						<h2 className="mb-1">HYROVI Sec</h2>
						<div className="text-secondary">
							Live threat visibility and response for requests passing through HYROVI Proxy Manager.
						</div>
					</div>
					<Button className="btn-outline-secondary" onClick={refresh}>
						<IconRefresh size={18} className="me-1" />
						Refresh
					</Button>
				</div>

				<div className="card mb-4">
					<div className="card-body">
						<div className="d-flex flex-column flex-lg-row align-items-lg-center justify-content-between gap-3">
							<div>
								<div className="d-flex align-items-center gap-2">
									<strong>Automatic response</strong>
									<span className={`badge ${policy.data?.autoBlockEnabled ? "bg-red text-white" : "bg-blue-lt"}`}>
										{policy.data?.autoBlockEnabled ? "ENFORCE" : "OBSERVE"}
									</span>
								</div>
								<div className="text-secondary small mt-1">
									Only high-confidence public source IPs at or above the configured risk threshold are auto-blocked.
								</div>
							</div>
							<div className="d-flex flex-wrap align-items-center gap-2">
								<label className="text-secondary small">Risk</label>
								<input
									className="form-control"
									style={{ width: 88 }}
									type="number"
									min={80}
									max={100}
									defaultValue={policy.data?.autoBlockThreshold ?? 95}
									onBlur={(event) =>
										updatePolicy.mutate({ autoBlockThreshold: Number(event.target.value) })
									}
								/>
								<label className="text-secondary small">Minutes</label>
								<input
									className="form-control"
									style={{ width: 100 }}
									type="number"
									min={1}
									max={43200}
									defaultValue={policy.data?.autoBlockMinutes ?? 60}
									onBlur={(event) =>
										updatePolicy.mutate({ autoBlockMinutes: Number(event.target.value) })
									}
								/>
								<Button
									className={policy.data?.autoBlockEnabled ? "btn-outline-secondary" : "btn-danger"}
									disabled={!policy.data || updatePolicy.isPending}
									onClick={() =>
										updatePolicy.mutate({ autoBlockEnabled: !policy.data?.autoBlockEnabled })
									}
								>
									{policy.data?.autoBlockEnabled ? "Switch to observe" : "Enable auto response"}
								</Button>
							</div>
						</div>
					</div>
				</div>

				<div className="row row-cards mb-4">
					<div className="col-6 col-lg-3">
						<div className="card card-sm">
							<div className="card-body">
								<div className="text-secondary">Analyzed</div>
								<div className="h2 mb-0">{overview.data?.requests ?? "—"}</div>
							</div>
						</div>
					</div>
					<div className="col-6 col-lg-3">
						<div className="card card-sm">
							<div className="card-body">
								<div className="text-secondary">Suspicious</div>
								<div className="h2 mb-0">{overview.data?.suspicious ?? "—"}</div>
							</div>
						</div>
					</div>
					<div className="col-6 col-lg-3">
						<div className="card card-sm">
							<div className="card-body">
								<div className="text-secondary">Critical</div>
								<div className="h2 mb-0 text-red">{overview.data?.critical ?? "—"}</div>
							</div>
						</div>
					</div>
					<div className="col-6 col-lg-3">
						<div className="card card-sm">
							<div className="card-body">
								<div className="text-secondary">Active blocks</div>
								<div className="h2 mb-0">{overview.data?.activeBlocks ?? "—"}</div>
							</div>
						</div>
					</div>
				</div>

				<div className="card mb-4">
					<div className="card-header">
						<div>
							<h3 className="card-title">Block an IP</h3>
							<div className="text-secondary small">
								The block is validated with nginx before it becomes active.
							</div>
						</div>
					</div>
					<div className="card-body">
						<div className="row g-2">
							<div className="col-12 col-md-3">
								<input
									className="form-control"
									placeholder="IPv4 or IPv6"
									value={ip}
									onChange={(event) => setIp(event.target.value)}
								/>
							</div>
							<div className="col-6 col-md-2">
								<input
									className="form-control"
									type="number"
									min={1}
									max={43200}
									value={durationMinutes}
									onChange={(event) => setDurationMinutes(Number(event.target.value))}
								/>
							</div>
							<div className="col-6 col-md-5">
								<input
									className="form-control"
									placeholder="Reason"
									value={reason}
									onChange={(event) => setReason(event.target.value)}
								/>
							</div>
							<div className="col-12 col-md-2 d-grid">
								<Button
									className="btn-danger"
									disabled={!ip || addBlock.isPending}
									onClick={() =>
										addBlock.mutate({
											ip,
											durationMinutes,
											reason: reason || "Manual HYROVI Sec block",
											source: "dashboard",
										})
									}
								>
									<IconBan size={18} className="me-1" />
									Block
								</Button>
							</div>
						</div>
						{addBlock.error ? <div className="text-red mt-2">{addBlock.error.message}</div> : null}
					</div>
				</div>

				<div className="card mb-4">
					<div className="card-header">
						<h3 className="card-title">Attack sessions</h3>
					</div>
					<div className="table-responsive">
						<table className="table table-vcenter card-table">
							<thead>
								<tr>
									<th>Source</th>
									<th>Requests</th>
									<th>Max risk</th>
									<th>Signals</th>
									<th>Last seen</th>
								</tr>
							</thead>
							<tbody>
								{topSessions.length === 0 ? (
									<tr>
										<td colSpan={5} className="text-secondary">
											No suspicious attack sessions in the current analysis window.
										</td>
									</tr>
								) : (
									topSessions.map((session) => (
										<tr key={session.id}>
											<td className="font-monospace">{session.ip}</td>
											<td>{session.requests}</td>
											<td>
												<span className={`badge ${session.maxRisk >= 80 ? "bg-red text-white" : "bg-yellow text-dark"}`}>
													{session.maxRisk}
												</span>
											</td>
											<td className="text-secondary">{session.signals.join(", ") || "—"}</td>
											<td>{formatTime(session.lastSeen)}</td>
										</tr>
									))
								)}
							</tbody>
						</table>
					</div>
				</div>

				<div className="card mb-4">
					<div className="card-header d-flex align-items-center justify-content-between">
						<div>
							<h3 className="card-title">Critical & suspicious requests</h3>
							<div className="text-secondary small">
								Sensitive headers, cookies, query strings and request bodies are not stored.
							</div>
						</div>
						<select
							className="form-select w-auto"
							value={minRisk}
							onChange={(event) => setMinRisk(Number(event.target.value))}
						>
							<option value={0}>All</option>
							<option value={20}>Risk 20+</option>
							<option value={40}>Risk 40+</option>
							<option value={60}>Risk 60+</option>
							<option value={80}>Critical 80+</option>
						</select>
					</div>
					<div className="table-responsive">
						<table className="table table-vcenter card-table">
							<thead>
								<tr>
									<th>Risk</th>
									<th>Time</th>
									<th>Source</th>
									<th>Request</th>
									<th>Status</th>
									<th>Why</th>
									<th />
								</tr>
							</thead>
							<tbody>
								{(events.data ?? []).map((event) => (
									<tr key={event.requestId || `${event.timestamp}-${event.ip}-${event.path}`}>
										<td>
											<span className={`badge ${severityClass(event.severity)}`}>{event.risk}</span>
										</td>
										<td className="text-nowrap">{formatTime(event.timestamp)}</td>
										<td className="font-monospace">{event.ip}</td>
										<td style={{ minWidth: 260 }}>
											<div>
												<strong>{event.method}</strong> {event.host}
											</div>
											<div className="font-monospace text-secondary text-truncate" style={{ maxWidth: 420 }}>
												{event.path}
											</div>
										</td>
										<td>{event.status || "—"}</td>
										<td style={{ minWidth: 260 }}>
											{event.signals.map((signal) => signal.label).join(", ") || "Normal request"}
										</td>
										<td>
											<button className="btn btn-sm btn-outline-danger" onClick={() => blockFromEvent(event)}>
												Block IP
											</button>
										</td>
									</tr>
								))}
								{!events.isLoading && (events.data?.length ?? 0) === 0 ? (
									<tr>
										<td colSpan={7} className="text-secondary">
											No requests match this risk filter yet.
										</td>
									</tr>
								) : null}
							</tbody>
						</table>
					</div>
				</div>

				<div className="card">
					<div className="card-header">
						<div className="d-flex align-items-center gap-2">
							<IconShield size={20} />
							<h3 className="card-title mb-0">Active IP blocks</h3>
						</div>
					</div>
					<div className="table-responsive">
						<table className="table table-vcenter card-table">
							<thead>
								<tr>
									<th>IP</th>
									<th>Reason</th>
									<th>Source</th>
									<th>Expires</th>
									<th />
								</tr>
							</thead>
							<tbody>
								{(blocks.data ?? []).map((block) => (
									<tr key={block.id}>
										<td className="font-monospace">{block.ip}</td>
										<td>{block.reason}</td>
										<td>{block.source}</td>
										<td>{formatTime(block.expiresAt)}</td>
										<td>
											<button
												className="btn btn-sm btn-outline-secondary"
												disabled={removeBlock.isPending}
												onClick={() => removeBlock.mutate(block.id)}
											>
												Unblock
											</button>
										</td>
									</tr>
								))}
								{!blocks.isLoading && (blocks.data?.length ?? 0) === 0 ? (
									<tr>
										<td colSpan={5} className="text-secondary">
											No active IP blocks.
										</td>
									</tr>
								) : null}
							</tbody>
						</table>
					</div>
				</div>
			</div>
		</HasPermission>
	);
};

export default Security;
