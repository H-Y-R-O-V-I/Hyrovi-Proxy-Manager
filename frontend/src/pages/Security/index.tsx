import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { IconBan, IconRefresh, IconShield } from "@tabler/icons-react";
import { useEffect, useMemo, useState } from "react";
import {
	createSecurityBlock,
	createSecurityRateLimit,
	deleteSecurityBlock,
	deleteSecurityHostPolicy,
	deleteSecurityRateLimit,
	getSecurityAppEvents,
	getSecurityAttackSession,
	getSecurityBlocks,
	getSecurityEventDetail,
	getSecurityEvents,
	getSecurityHostPolicies,
	getSecurityOverview,
	getSecurityPolicy,
	getSecurityRateLimits,
	updateSecurityHostPolicy,
	updateSecurityPolicy,
	type SecurityAppEventSeverity,
	type SecurityEvent,
	type SecurityHostMode,
	type SecurityHostPolicyEntry,
} from "src/api/backend";
import { Button, HasPermission } from "src/components";
import { ADMIN, VIEW } from "src/modules/Permissions";

const POLL_MS = 5000;

type HostPolicyDraft = {
	mode: "inherit" | SecurityHostMode;
	autoRateLimitThreshold: number;
	autoRateLimitMinutes: number;
	autoBlockThreshold: number;
	autoBlockMinutes: number;
};

const hostPolicyDraft = (host: SecurityHostPolicyEntry): HostPolicyDraft => {
	const source = host.policy ?? host.effective;
	return {
		mode: host.policy?.mode ?? "inherit",
		autoRateLimitThreshold: source.autoRateLimitThreshold,
		autoRateLimitMinutes: source.autoRateLimitMinutes,
		autoBlockThreshold: source.autoBlockThreshold,
		autoBlockMinutes: source.autoBlockMinutes,
	};
};

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

const appEventSeverityClass = (severity: SecurityAppEventSeverity) => {
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
			return "bg-secondary-lt";
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
	const [trustedSourcesText, setTrustedSourcesText] = useState("");
	const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);
	const [selectedRequestId, setSelectedRequestId] = useState<string | null>(null);
	const [hostPolicyDrafts, setHostPolicyDrafts] = useState<Record<number, HostPolicyDraft>>({});

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

	const appEvents = useQuery({
		queryKey: ["security-app-events"],
		queryFn: () => getSecurityAppEvents(100),
		refetchInterval: POLL_MS,
	});

	const blocks = useQuery({
		queryKey: ["security-blocks"],
		queryFn: getSecurityBlocks,
		refetchInterval: POLL_MS,
	});
	const rateLimits = useQuery({
		queryKey: ["security-rate-limits"],
		queryFn: getSecurityRateLimits,
		refetchInterval: POLL_MS,
	});

	const policy = useQuery({
		queryKey: ["security-policy"],
		queryFn: getSecurityPolicy,
	});
	const hostPolicies = useQuery({
		queryKey: ["security-host-policies"],
		queryFn: getSecurityHostPolicies,
	});
	const incident = useQuery({
		queryKey: ["security-attack-session", selectedSessionId],
		queryFn: () => getSecurityAttackSession(selectedSessionId || ""),
		enabled: Boolean(selectedSessionId),
		refetchInterval: selectedSessionId ? POLL_MS : false,
	});
	const requestDetail = useQuery({
		queryKey: ["security-event-detail", selectedRequestId],
		queryFn: () => getSecurityEventDetail(selectedRequestId || ""),
		enabled: Boolean(selectedRequestId),
		refetchInterval: selectedRequestId ? POLL_MS : false,
	});
	useEffect(() => {
		if (policy.data) setTrustedSourcesText(policy.data.trustedSources.join("\n"));
	}, [policy.data]);
	useEffect(() => {
		if (!hostPolicies.data) return;
		const next: Record<number, HostPolicyDraft> = {};
		for (const host of hostPolicies.data) next[host.id] = hostPolicyDraft(host);
		setHostPolicyDrafts(next);
	}, [hostPolicies.data]);

	const refresh = async () => {
		await Promise.all([
			queryClient.invalidateQueries({ queryKey: ["security-overview"] }),
			queryClient.invalidateQueries({ queryKey: ["security-events"] }),
			queryClient.invalidateQueries({ queryKey: ["security-event-detail"] }),
			queryClient.invalidateQueries({ queryKey: ["security-app-events"] }),
			queryClient.invalidateQueries({ queryKey: ["security-blocks"] }),
			queryClient.invalidateQueries({ queryKey: ["security-rate-limits"] }),
			queryClient.invalidateQueries({ queryKey: ["security-policy"] }),
			queryClient.invalidateQueries({ queryKey: ["security-host-policies"] }),
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
	const addRateLimit = useMutation({
		mutationFn: createSecurityRateLimit,
		onSuccess: async () => {
			setIp("");
			setReason("");
			await refresh();
		},
	});

	const removeRateLimit = useMutation({
		mutationFn: deleteSecurityRateLimit,
		onSuccess: refresh,
	});

	const updatePolicy = useMutation({
		mutationFn: updateSecurityPolicy,
		onSuccess: async () => {
			await Promise.all([
				queryClient.invalidateQueries({ queryKey: ["security-policy"] }),
				queryClient.invalidateQueries({ queryKey: ["security-host-policies"] }),
				queryClient.invalidateQueries({ queryKey: ["security-overview"] }),
				queryClient.invalidateQueries({ queryKey: ["security-events"] }),
			]);
		},
	});
	const saveHostPolicy = useMutation({
		mutationFn: async ({ hostId, draft }: { hostId: number; draft: HostPolicyDraft }) => {
			if (draft.mode === "inherit") return deleteSecurityHostPolicy(hostId);
			return updateSecurityHostPolicy(hostId, {
				mode: draft.mode,
				autoRateLimitThreshold: draft.autoRateLimitThreshold,
				autoRateLimitMinutes: draft.autoRateLimitMinutes,
				autoBlockThreshold: draft.autoBlockThreshold,
				autoBlockMinutes: draft.autoBlockMinutes,
			});
		},
		onSuccess: async () => {
			await Promise.all([
				queryClient.invalidateQueries({ queryKey: ["security-host-policies"] }),
				queryClient.invalidateQueries({ queryKey: ["security-policy"] }),
				queryClient.invalidateQueries({ queryKey: ["security-overview"] }),
				queryClient.invalidateQueries({ queryKey: ["security-events"] }),
			]);
		},
	});

	const patchHostDraft = (host: SecurityHostPolicyEntry, patch: Partial<HostPolicyDraft>) => {
		setHostPolicyDrafts((current) => ({
			...current,
			[host.id]: { ...(current[host.id] ?? hostPolicyDraft(host)), ...patch },
		}));
	};

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
	const rateLimitFromEvent = (event: SecurityEvent) => {
		addRateLimit.mutate({
			ip: event.ip,
			durationMinutes: 10,
			reason:
				event.signals.length > 0
					? `HYROVI Sec soft restriction: ${event.signals.map((signal) => signal.label).join(", ")}`
					: "HYROVI Sec suspicious request",
			source: "dashboard-event",
		});
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

				{overview.data?.automation.emergencyBypass ? (
					<div className="alert alert-warning mb-4" role="alert">
						<strong>Emergency bypass active.</strong>{" "}
						HYROVI Sec is still observing and preserving stored response state, but IP blocks, rate limits and automatic response enforcement are disabled. Remove <code>HYROVI_SEC_EMERGENCY_BYPASS=true</code> and restart the container to restore enforcement.
					</div>
				) : null}

				<div className="card mb-4">
					<div className="card-body">
						<div className="d-flex flex-column flex-lg-row align-items-lg-center justify-content-between gap-3">
							<div>
								<div className="d-flex align-items-center gap-2">
									<strong>Automatic response</strong>
									<span
										className={`badge ${
											overview.data?.automation.emergencyBypass
												? "bg-yellow text-dark"
												: policy.data?.autoBlockEnabled
													? "bg-red text-white"
													: "bg-blue-lt"
										}`}
									>
										{overview.data?.automation.emergencyBypass
											? "BYPASS"
											: policy.data?.autoBlockEnabled
												? "ENFORCE"
												: "OBSERVE"}
									</span>
								</div>
								<div className="text-secondary small mt-1">
									Automatic response soft-limits suspicious public sources first and hard-blocks only high-confidence attacks at the configured block threshold. Trusted sources are excluded.
								</div>
							</div>
							<div className="d-flex flex-wrap align-items-center gap-2">
								<label className="text-secondary small" htmlFor="hyrovi-sec-auto-rate-risk">Soft risk</label>
								<input
									id="hyrovi-sec-auto-rate-risk"
									className="form-control"
									style={{ width: 88 }}
									type="number"
									min={40}
									max={100}
									defaultValue={policy.data?.autoRateLimitThreshold ?? 50}
									onBlur={(event) =>
										updatePolicy.mutate({ autoRateLimitThreshold: Number(event.target.value) })
									}
								/>
								<label className="text-secondary small" htmlFor="hyrovi-sec-auto-rate-minutes">Soft min</label>
								<input
									id="hyrovi-sec-auto-rate-minutes"
									className="form-control"
									style={{ width: 92 }}
									type="number"
									min={1}
									max={43200}
									defaultValue={policy.data?.autoRateLimitMinutes ?? 10}
									onBlur={(event) =>
										updatePolicy.mutate({ autoRateLimitMinutes: Number(event.target.value) })
									}
								/>
								<label className="text-secondary small" htmlFor="hyrovi-sec-auto-block-risk">Block risk</label>
								<input
									id="hyrovi-sec-auto-block-risk"
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
								<label className="text-secondary small" htmlFor="hyrovi-sec-auto-block-minutes">Block min</label>
								<input
									id="hyrovi-sec-auto-block-minutes"
									className="form-control"
									style={{ width: 92 }}
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
						<hr className="my-3" />
						<div className="row g-3 align-items-end">
							<div className="col-12 col-lg-6">
								<div className="form-label mb-1">Security event archive</div>
								<div className="text-secondary small">
									Keeps security-relevant events after the live nginx log window rolls over. Daily files are bounded and automatically removed after the retention period.
								</div>
							</div>
							<div className="col-6 col-lg-3">
								<label className="form-label" htmlFor="hyrovi-sec-event-retention">Retention days</label>
								<input
									id="hyrovi-sec-event-retention"
									className="form-control"
									type="number"
									min={1}
									max={90}
									defaultValue={policy.data?.eventRetentionDays ?? 14}
									onBlur={(event) =>
										updatePolicy.mutate({ eventRetentionDays: Number(event.target.value) })
									}
								/>
							</div>
							<div className="col-6 col-lg-3">
								<label className="form-label" htmlFor="hyrovi-sec-event-archive-risk">Archive min risk</label>
								<input
									id="hyrovi-sec-event-archive-risk"
									className="form-control"
									type="number"
									min={0}
									max={100}
									defaultValue={policy.data?.eventArchiveMinRisk ?? 20}
									onBlur={(event) =>
										updatePolicy.mutate({ eventArchiveMinRisk: Number(event.target.value) })
									}
								/>
							</div>
						</div>
						<hr className="my-3" />
						<div className="row g-3 align-items-end">
							<div className="col-12 col-lg-9">
								<label className="form-label" htmlFor="hyrovi-sec-trusted-sources">
									Trusted sources
								</label>
								<textarea
									id="hyrovi-sec-trusted-sources"
									className="form-control font-monospace"
									rows={3}
									placeholder={"203.0.113.10\n192.0.2.0/24\n2001:db8::/32"}
									value={trustedSourcesText}
									onChange={(event) => setTrustedSourcesText(event.target.value)}
								/>
								<div className="text-secondary small mt-1">
									One exact IPv4/IPv6 address or CIDR per line. These requests remain visible, but automatic rate limits and blocks will skip them.
								</div>
							</div>
							<div className="col-12 col-lg-3 d-grid">
								<Button
									className="btn-outline-primary"
									disabled={!policy.data || updatePolicy.isPending}
									onClick={() =>
										updatePolicy.mutate({
											trustedSources: trustedSourcesText
												.split(/\r?\n|,/)
												.map((entry) => entry.trim())
												.filter(Boolean),
										})
									}
								>
									Save trusted sources
								</Button>
							</div>
						</div>
						{updatePolicy.error ? <div className="text-red mt-2">{updatePolicy.error.message}</div> : null}
					</div>
				</div>

				<div className="card mb-4">
					<div className="card-header">
						<div>
							<h3 className="card-title">Per-host protection</h3>
							<div className="text-secondary small">
								Overrides are stored by Proxy Host ID, so domain renames do not lose the security policy. The global auto-response switch remains the master kill switch.
							</div>
						</div>
					</div>
					<div className="table-responsive">
						<table className="table table-vcenter card-table">
							<thead>
								<tr>
									<th>Proxy host</th>
									<th>Mode</th>
									<th>Soft risk</th>
									<th>Soft min</th>
									<th>Block risk</th>
									<th>Block min</th>
									<th>State</th>
									<th />
								</tr>
							</thead>
							<tbody>
								{(hostPolicies.data ?? []).map((host) => {
									const draft = hostPolicyDrafts[host.id] ?? hostPolicyDraft(host);
									return (
										<tr key={host.id}>
											<td style={{ minWidth: 240 }}>
												<div className="fw-semibold">{host.domainNames.join(", ") || `Proxy Host #${host.id}`}</div>
												<div className="text-secondary small">#{host.id}{host.enabled ? "" : " · disabled"}</div>
											</td>
											<td style={{ minWidth: 150 }}>
												<label className="visually-hidden" htmlFor={`hyrovi-sec-host-mode-${host.id}`}>Security mode</label>
												<select
													id={`hyrovi-sec-host-mode-${host.id}`}
													className="form-select"
													value={draft.mode}
													onChange={(event) => {
														const mode = event.target.value as HostPolicyDraft["mode"];
														patchHostDraft(host, {
															mode,
															...(mode === "strict" && draft.mode !== "strict"
																? {
																		autoRateLimitThreshold: Math.min(draft.autoRateLimitThreshold, 45),
																		autoBlockThreshold: Math.min(draft.autoBlockThreshold, 90),
																	}
																: {}),
														});
													}}
												>
													<option value="inherit">Inherit global</option>
													<option value="off">Off</option>
													<option value="observe">Observe</option>
													<option value="protect">Protect</option>
													<option value="strict">Strict</option>
												</select>
											</td>
											<td>
												<label className="visually-hidden" htmlFor={`hyrovi-sec-host-rate-risk-${host.id}`}>Auto-rate-limit risk</label>
												<input
													id={`hyrovi-sec-host-rate-risk-${host.id}`}
													className="form-control"
													style={{ width: 92 }}
													type="number"
													min={40}
													max={100}
													disabled={draft.mode === "inherit"}
													value={draft.autoRateLimitThreshold}
													onChange={(event) => patchHostDraft(host, { autoRateLimitThreshold: Number(event.target.value) })}
												/>
											</td>
											<td>
												<label className="visually-hidden" htmlFor={`hyrovi-sec-host-rate-minutes-${host.id}`}>Auto-rate-limit minutes</label>
												<input
													id={`hyrovi-sec-host-rate-minutes-${host.id}`}
													className="form-control"
													style={{ width: 105 }}
													type="number"
													min={1}
													max={43200}
													disabled={draft.mode === "inherit"}
													value={draft.autoRateLimitMinutes}
													onChange={(event) => patchHostDraft(host, { autoRateLimitMinutes: Number(event.target.value) })}
												/>
											</td>
											<td>
												<label className="visually-hidden" htmlFor={`hyrovi-sec-host-risk-${host.id}`}>Auto-block risk</label>
												<input
													id={`hyrovi-sec-host-risk-${host.id}`}
													className="form-control"
													style={{ width: 92 }}
													type="number"
													min={80}
													max={100}
													disabled={draft.mode === "inherit"}
													value={draft.autoBlockThreshold}
													onChange={(event) => patchHostDraft(host, { autoBlockThreshold: Number(event.target.value) })}
												/>
											</td>
											<td>
												<label className="visually-hidden" htmlFor={`hyrovi-sec-host-minutes-${host.id}`}>Block minutes</label>
												<input
													id={`hyrovi-sec-host-minutes-${host.id}`}
													className="form-control"
													style={{ width: 105 }}
													type="number"
													min={1}
													max={43200}
													disabled={draft.mode === "inherit"}
													value={draft.autoBlockMinutes}
													onChange={(event) => patchHostDraft(host, { autoBlockMinutes: Number(event.target.value) })}
												/>
											</td>
											<td className="text-secondary">
												{draft.mode === "inherit" ? `Global → ${host.effective.mode}` : "Host override"}
											</td>
											<td>
												<Button
													className="btn-outline-primary btn-sm"
													disabled={saveHostPolicy.isPending}
													onClick={() => saveHostPolicy.mutate({ hostId: host.id, draft })}
												>
													Save
												</Button>
											</td>
										</tr>
									);
								})}
								{!hostPolicies.isLoading && (hostPolicies.data?.length ?? 0) === 0 ? (
									<tr>
										<td colSpan={8} className="text-secondary">
											No Proxy Hosts are available yet.
										</td>
									</tr>
								) : null}
							</tbody>
						</table>
					</div>
					{saveHostPolicy.error ? <div className="card-body pt-0 text-red">{saveHostPolicy.error.message}</div> : null}
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
								<div className="text-secondary small">{overview.data?.activeRateLimits ?? "—"} rate limited</div>
							</div>
						</div>
					</div>
				</div>

				<div className="card mb-4">
					<div className="card-header d-flex align-items-center justify-content-between">
						<div>
							<h3 className="card-title">App & auth security events</h3>
							<div className="text-secondary small">
								HYROVI apps can report login, permission, token, session, device and account security events without sending passwords, tokens or arbitrary request bodies.
							</div>
						</div>
						<span className={`badge ${appEvents.data?.configured ? "bg-green-lt" : "bg-yellow text-dark"}`}>
							{appEvents.data?.configured ? "INGEST READY" : "INGEST DISABLED"}
						</span>
					</div>
					{appEvents.data && !appEvents.data.configured ? (
						<div className="card-body border-bottom">
							<div className="text-secondary small">
								Set <code>HYROVI_SEC_INGEST_TOKEN</code> to a secret with at least {appEvents.data.minTokenLength} characters and restart the container. Apps then POST to <code>/api/security/app-events/ingest</code> with <code>Authorization: Bearer …</code>.
							</div>
						</div>
					) : null}
					<div className="table-responsive">
						<table className="table table-vcenter card-table">
							<thead>
								<tr>
									<th>Time</th>
									<th>Severity</th>
									<th>Event</th>
									<th>App</th>
									<th>Identity</th>
									<th>IP</th>
									<th>Reason</th>
								</tr>
							</thead>
							<tbody>
								{(appEvents.data?.events ?? []).map((event) => {
									const identity = [
										event.accountId ? `account ${event.accountId}` : null,
										event.sessionId ? `session ${event.sessionId}` : null,
										event.deviceId ? `device ${event.deviceId}` : null,
									].filter(Boolean);
									return (
										<tr key={event.id}>
											<td className="text-nowrap">{formatTime(event.timestamp)}</td>
											<td><span className={`badge ${appEventSeverityClass(event.severity)}`}>{event.severity}</span></td>
											<td className="font-monospace">{event.eventType}</td>
											<td>{event.app}</td>
											<td className="text-secondary">{identity.join(" · ") || "—"}</td>
											<td className="font-monospace">{event.ip || "—"}</td>
											<td>{event.reason || "—"}</td>
										</tr>
									);
								})}
								{!appEvents.isLoading && (appEvents.data?.events.length ?? 0) === 0 ? (
									<tr><td colSpan={7} className="text-secondary">No app security events have been received yet.</td></tr>
								) : null}
							</tbody>
						</table>
					</div>
				</div>

				<div className="card mb-4">
					<div className="card-header">
						<div>
							<h3 className="card-title">Restrict an IP</h3>
							<div className="text-secondary small">
								Use a soft rate limit first when possible. Both rate limits and hard blocks are validated with nginx before becoming active.
							</div>
						</div>
					</div>
					<div className="card-body">
						<div className="row g-2">
							<div className="col-12 col-md-3">
								<label className="visually-hidden" htmlFor="hyrovi-sec-restrict-ip">IP address</label>
								<input
									id="hyrovi-sec-restrict-ip"
									className="form-control"
									placeholder="IPv4 or IPv6"
									value={ip}
									onChange={(event) => setIp(event.target.value)}
								/>
							</div>
							<div className="col-6 col-md-2">
								<label className="visually-hidden" htmlFor="hyrovi-sec-restrict-minutes">Duration in minutes</label>
								<input
									id="hyrovi-sec-restrict-minutes"
									className="form-control"
									type="number"
									min={1}
									max={43200}
									value={durationMinutes}
									onChange={(event) => setDurationMinutes(Number(event.target.value))}
								/>
							</div>
							<div className="col-6 col-md-4">
								<label className="visually-hidden" htmlFor="hyrovi-sec-restrict-reason">Reason</label>
								<input
									id="hyrovi-sec-restrict-reason"
									className="form-control"
									placeholder="Reason"
									value={reason}
									onChange={(event) => setReason(event.target.value)}
								/>
							</div>
							<div className="col-12 col-md-3 d-flex gap-2">
								<Button
									className="btn-outline-warning flex-fill"
									disabled={!ip || addRateLimit.isPending}
									onClick={() =>
										addRateLimit.mutate({
											ip,
											durationMinutes,
											reason: reason || "Manual HYROVI Sec rate limit",
											source: "dashboard",
										})
									}
								>
									Rate limit
								</Button>
								<Button
									className="btn-danger flex-fill"
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
						{addRateLimit.error ? <div className="text-red mt-2">{addRateLimit.error.message}</div> : null}
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
									<th>Hosts</th>
									<th>Signals</th>
									<th>Response</th>
									<th>Last seen</th>
									<th />
								</tr>
							</thead>
							<tbody>
								{topSessions.length === 0 ? (
									<tr>
										<td colSpan={8} className="text-secondary">
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
											<td className="text-secondary">{session.hosts.join(", ") || "—"}</td>
											<td className="text-secondary">{session.signals.join(", ") || "—"}</td>
											<td>
												{session.activeResponse === "block" ? (
													<span className="badge bg-red text-white">Blocked</span>
												) : session.activeResponse === "rate_limit" ? (
													<span className="badge bg-yellow text-dark">Rate limited</span>
												) : (
													<span className="text-secondary">Observe</span>
												)}
											</td>
											<td>{formatTime(session.lastSeen)}</td>
											<td>
												<button
													type="button"
													className="btn btn-sm btn-outline-primary"
													onClick={() => setSelectedSessionId(session.id)}
												>
													Details
												</button>
											</td>
										</tr>
									))
								)}
							</tbody>
						</table>
					</div>
				</div>

				{selectedSessionId ? (
					<div className="card mb-4">
						<div className="card-header d-flex align-items-center justify-content-between">
							<div>
								<h3 className="card-title">Incident detail</h3>
								<div className="text-secondary small">
									{incident.data ? `${incident.data.ip} · ${incident.data.requests} suspicious requests · risk ${incident.data.maxRisk}` : "Loading attack session…"}
								</div>
							</div>
							<button type="button" className="btn btn-sm btn-outline-secondary" onClick={() => setSelectedSessionId(null)}>
								Close
							</button>
						</div>
						{incident.error ? <div className="card-body text-red">{incident.error.message}</div> : null}
						{incident.data ? (
							<>
								<div className="card-body border-bottom">
									<div className="row g-3">
										<div className="col-6 col-lg-3">
											<div className="text-secondary small">First seen</div>
											<div>{formatTime(incident.data.firstSeen)}</div>
										</div>
										<div className="col-6 col-lg-3">
											<div className="text-secondary small">Last seen</div>
											<div>{formatTime(incident.data.lastSeen)}</div>
										</div>
										<div className="col-12 col-lg-3">
											<div className="text-secondary small">Hosts</div>
											<div>{incident.data.hosts.join(", ") || "—"}</div>
										</div>
										<div className="col-12 col-lg-3">
											<div className="text-secondary small">Active response</div>
											<div>
												{incident.data.activeResponses.length > 0
													? incident.data.activeResponses
														.map((response) => `${response.type === "block" ? "Block" : "Rate limit"} until ${formatTime(response.expiresAt)}`)
														.join(" · ")
													: "Observe only"}
											</div>
										</div>
									</div>
								</div>

								<div className="border-bottom">
									<div className="card-body pb-2">
										<h4 className="mb-1">Response history</h4>
										<div className="text-secondary small">
											Recorded HYROVI Sec rate-limit and block lifecycle actions for this source.
										</div>
									</div>
									<div className="table-responsive">
										<table className="table table-vcenter card-table">
											<thead>
												<tr>
													<th>Time</th>
													<th>Action</th>
													<th>Type</th>
													<th>Source</th>
													<th>Reason</th>
													<th>Expires</th>
												</tr>
											</thead>
											<tbody>
												{incident.data.responseHistory.map((entry) => (
													<tr key={entry.id}>
														<td className="text-nowrap">{formatTime(entry.at)}</td>
														<td>
															<span className={`badge ${entry.action === "started" ? "bg-yellow text-dark" : "bg-secondary-lt"}`}>
																{entry.action}
															</span>
														</td>
														<td>{entry.type === "block" ? "Block" : "Rate limit"}</td>
														<td>{entry.source}</td>
														<td>{entry.reason || "—"}</td>
														<td>{formatTime(entry.expiresAt)}</td>
													</tr>
												))}
												{incident.data.responseHistory.length === 0 ? (
													<tr>
														<td colSpan={6} className="text-secondary">
															No recorded response actions for this source.
														</td>
													</tr>
												) : null}
											</tbody>
										</table>
									</div>
								</div>

								<div className="border-bottom">
									<div className="card-body pb-2">
										<h4 className="mb-1">Correlated app & auth events</h4>
										<div className="text-secondary small">
											Matched by proxy request ID, or by source IP inside the incident time window.
										</div>
									</div>
									<div className="table-responsive">
										<table className="table table-vcenter card-table">
											<thead>
												<tr>
													<th>Time</th>
													<th>Severity</th>
													<th>Event</th>
													<th>App</th>
													<th>Identity</th>
													<th>Reason</th>
												</tr>
											</thead>
											<tbody>
												{incident.data.appEvents.map((event) => (
													<tr key={event.id}>
														<td className="text-nowrap">{formatTime(event.timestamp)}</td>
														<td><span className={`badge ${appEventSeverityClass(event.severity)}`}>{event.severity}</span></td>
														<td className="font-monospace">{event.eventType}</td>
														<td>{event.app}</td>
														<td className="text-secondary">
															{[
																event.accountId ? `account ${event.accountId}` : null,
																event.sessionId ? `session ${event.sessionId}` : null,
																event.deviceId ? `device ${event.deviceId}` : null,
															].filter(Boolean).join(" · ") || "—"}
														</td>
														<td>{event.reason || "—"}</td>
													</tr>
												))}
												{incident.data.appEvents.length === 0 ? (
													<tr><td colSpan={6} className="text-secondary">No correlated app security events for this incident.</td></tr>
												) : null}
											</tbody>
										</table>
									</div>
								</div>

								<div className="table-responsive border-bottom">
									<table className="table table-vcenter card-table">
										<thead>
											<tr>
												<th>Top request pattern</th>
												<th>Count</th>
												<th>Max risk</th>
												<th>Status</th>
											</tr>
										</thead>
										<tbody>
											{incident.data.requestPatterns.map((pattern) => (
												<tr key={`${pattern.host}-${pattern.method}-${pattern.path}`}>
													<td>
														<div><strong>{pattern.method}</strong> {pattern.host}</div>
														<div className="font-monospace text-secondary">{pattern.path}</div>
													</td>
													<td>{pattern.count}</td>
													<td>{pattern.maxRisk}</td>
													<td>{pattern.statuses.join(", ") || "—"}</td>
												</tr>
											))}
										</tbody>
									</table>
								</div>

								<div className="table-responsive">
									<table className="table table-vcenter card-table">
										<thead>
											<tr>
												<th>Time</th>
												<th>Risk</th>
												<th>Request</th>
												<th>Status</th>
												<th>Why</th>
											</tr>
										</thead>
										<tbody>
											{incident.data.timeline.map((event) => (
												<tr key={event.requestId || `${event.timestamp}-${event.method}-${event.path}`}>
													<td className="text-nowrap">{formatTime(event.timestamp)}</td>
													<td><span className={`badge ${severityClass(event.severity)}`}>{event.risk}</span></td>
													<td>
														<div><strong>{event.method}</strong> {event.host}</div>
														<div className="font-monospace text-secondary">{event.path}</div>
														<div className="text-secondary small text-truncate" style={{ maxWidth: 520 }}>{event.userAgent || "—"}</div>
													</td>
													<td>{event.status || "—"}</td>
													<td>{event.signals.map((signal) => signal.label).join(", ") || "Normal request"}</td>
												</tr>
											))}
										</tbody>
									</table>
								</div>
							</>
						) : null}
					</div>
				) : null}

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
												<span className="badge bg-secondary-lt ms-2">{event.securityMode}</span>
												{event.endpointRulePath ? (
													<span className="badge bg-azure-lt ms-1">rule {event.endpointRulePath}</span>
												) : null}
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
											<div className="d-flex gap-1">
												<button
													type="button"
													className="btn btn-sm btn-outline-primary"
													disabled={!event.requestId}
													onClick={() => setSelectedRequestId(event.requestId)}
												>
													Details
												</button>
												<button
													type="button"
													className="btn btn-sm btn-outline-warning"
													disabled={addRateLimit.isPending}
													onClick={() => rateLimitFromEvent(event)}
												>
													Rate limit 10m
												</button>
												<button type="button" className="btn btn-sm btn-outline-danger" onClick={() => blockFromEvent(event)}>
													Block IP
												</button>
											</div>
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

				{selectedRequestId ? (
					<div className="card mb-4">
						<div className="card-header d-flex align-items-center justify-content-between">
							<div>
								<h3 className="card-title">Request detail</h3>
								<div className="text-secondary small">
									{requestDetail.data
										? `${requestDetail.data.method} ${requestDetail.data.host}${requestDetail.data.path} · risk ${requestDetail.data.risk}`
										: "Loading request…"}
								</div>
							</div>
							<button type="button" className="btn btn-sm btn-outline-secondary" onClick={() => setSelectedRequestId(null)}>
								Close
							</button>
						</div>
						{requestDetail.error ? <div className="card-body text-red">{requestDetail.error.message}</div> : null}
						{requestDetail.data ? (
							<>
								<div className="card-body border-bottom">
									<div className="row g-3">
										<div className="col-6 col-lg-2">
											<div className="text-secondary small">Time</div>
											<div>{formatTime(requestDetail.data.timestamp)}</div>
										</div>
										<div className="col-6 col-lg-2">
											<div className="text-secondary small">Source</div>
											<div className="font-monospace">{requestDetail.data.ip}</div>
										</div>
										<div className="col-6 col-lg-2">
											<div className="text-secondary small">Status</div>
											<div>{requestDetail.data.status || "—"}</div>
										</div>
										<div className="col-6 col-lg-2">
											<div className="text-secondary small">Risk</div>
											<div><span className={`badge ${severityClass(requestDetail.data.severity)}`}>{requestDetail.data.risk}</span></div>
										</div>
										<div className="col-12 col-lg-4">
											<div className="text-secondary small">Why</div>
											<div>{requestDetail.data.signals.map((signal) => `${signal.label} (+${signal.score})`).join(", ") || "Normal request"}</div>
										</div>
									</div>
									<div className="mt-3">
										<div className="text-secondary small">Request ID</div>
										<div className="font-monospace">{requestDetail.data.requestId || "—"}</div>
									</div>
									<div className="mt-3">
										<div className="text-secondary small">Effective protection</div>
										<div>
											<span className="badge bg-secondary-lt">{requestDetail.data.securityMode}</span>
											{requestDetail.data.endpointRulePath ? (
												<span className="badge bg-azure-lt ms-1">endpoint {requestDetail.data.endpointRulePath}</span>
											) : (
												<span className="text-secondary small ms-2">host/global policy</span>
											)}
										</div>
									</div>
									{requestDetail.data.attackSession ? (
										<div className="mt-3 d-flex align-items-center gap-2">
											<span className="text-secondary small">Attack session:</span>
											<button
												type="button"
												className="btn btn-sm btn-outline-primary"
												onClick={() => setSelectedSessionId(requestDetail.data?.attackSession?.id ?? null)}
											>
												Open session · {requestDetail.data.attackSession.requests} requests
											</button>
										</div>
									) : null}
								</div>

								<div className="border-bottom">
									<div className="card-body pb-2">
										<h4 className="mb-1">Correlated app & auth events</h4>
										<div className="text-secondary small">
											Exact request-ID matches are preferred; same-source events within ±5 minutes are also shown.
										</div>
									</div>
									<div className="table-responsive">
										<table className="table table-vcenter card-table">
											<thead>
												<tr>
													<th>Time</th>
													<th>Severity</th>
													<th>Event</th>
													<th>App</th>
													<th>Identity</th>
													<th>Reason</th>
												</tr>
											</thead>
											<tbody>
												{requestDetail.data.appEvents.map((event) => (
													<tr key={event.id}>
														<td className="text-nowrap">{formatTime(event.timestamp)}</td>
														<td><span className={`badge ${appEventSeverityClass(event.severity)}`}>{event.severity}</span></td>
														<td className="font-monospace">{event.eventType}</td>
														<td>{event.app}</td>
														<td className="text-secondary">
															{[
																event.accountId ? `account ${event.accountId}` : null,
																event.sessionId ? `session ${event.sessionId}` : null,
																event.deviceId ? `device ${event.deviceId}` : null,
															].filter(Boolean).join(" · ") || "—"}
														</td>
														<td>{event.reason || "—"}</td>
													</tr>
												))}
												{requestDetail.data.appEvents.length === 0 ? (
													<tr><td colSpan={6} className="text-secondary">No correlated app security events for this request.</td></tr>
												) : null}
											</tbody>
										</table>
									</div>
								</div>

								<div className="table-responsive border-bottom">
									<table className="table table-vcenter card-table">
										<thead>
											<tr>
												<th>Similar requests</th>
												<th>Similarity</th>
												<th>Risk</th>
												<th>Source</th>
												<th>Status</th>
												<th />
											</tr>
										</thead>
										<tbody>
											{requestDetail.data.similarRequests.map((event) => (
												<tr key={event.requestId || `${event.timestamp}-${event.ip}-${event.path}`}>
													<td>
														<div className="text-nowrap">{formatTime(event.timestamp)}</div>
														<div><strong>{event.method}</strong> {event.host}</div>
														<div className="font-monospace text-secondary">{event.path}</div>
													</td>
													<td>{event.similarityScore}</td>
													<td><span className={`badge ${severityClass(event.severity)}`}>{event.risk}</span></td>
													<td className="font-monospace">{event.ip}</td>
													<td>{event.status || "—"}</td>
													<td>
														<button
															type="button"
															className="btn btn-sm btn-outline-primary"
															disabled={!event.requestId}
															onClick={() => setSelectedRequestId(event.requestId)}
														>
															Open
														</button>
													</td>
												</tr>
											))}
											{requestDetail.data.similarRequests.length === 0 ? (
												<tr><td colSpan={6} className="text-secondary">No similar requests in the retained analysis window.</td></tr>
											) : null}
										</tbody>
									</table>
								</div>

								<div className="card-body">
									<div className="text-secondary small mb-1">Response state</div>
									<div>
										{requestDetail.data.activeResponses.length > 0
											? requestDetail.data.activeResponses
												.map((response) => `${response.type === "block" ? "Block" : "Rate limit"} until ${formatTime(response.expiresAt)}`)
												.join(" · ")
											: "No active response"}
									</div>
									<div className="text-secondary small mt-2">
										{requestDetail.data.responseHistory.length} recorded response lifecycle action(s) for this source.
									</div>
								</div>
							</>
						) : null}
					</div>
				) : null}

				<div className="card mb-4">
					<div className="card-header">
						<div>
							<h3 className="card-title">Active rate limits</h3>
							<div className="text-secondary small">Soft restriction: 5 requests/second with burst 20, returned as HTTP 429 when exceeded.</div>
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
								{(rateLimits.data ?? []).map((entry) => (
									<tr key={entry.id}>
										<td className="font-monospace">{entry.ip}</td>
										<td>{entry.reason}</td>
										<td>{entry.source}</td>
										<td>{formatTime(entry.expiresAt)}</td>
										<td>
											<button
												type="button"
												className="btn btn-sm btn-outline-secondary"
												disabled={removeRateLimit.isPending}
												onClick={() => removeRateLimit.mutate(entry.id)}
											>
												Remove
											</button>
										</td>
									</tr>
								))}
								{!rateLimits.isLoading && (rateLimits.data?.length ?? 0) === 0 ? (
									<tr>
										<td colSpan={5} className="text-secondary">
											No active rate limits.
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
												type="button"
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
