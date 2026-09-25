import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { IconPlus, IconSearch, IconTrash } from "@tabler/icons-react";
import { useEffect, useMemo, useState } from "react";
import {
	createSecurityHostGroup,
	deleteSecurityHostGroup,
	getSecurityEvents,
	getSecurityHostAccess,
	getSecurityHostGroups,
	getSecurityHostPolicies,
	updateSecurityHostAccess,
	updateSecurityHostGroup,
	type SecurityHostAccessMode,
	type SecurityHostGroup,
	type SecurityHostMode,
} from "src/api/backend";
import styles from "./Security.module.css";

type Draft = {
	id: string | null;
	name: string;
	description: string;
	hostIds: number[];
	accessMode: "open" | "allowlist" | "denylist";
	sourcesText: string;
	securityMode: "inherit" | SecurityHostMode;
};

const emptyDraft = (): Draft => ({
	id: null,
	name: "",
	description: "",
	hostIds: [],
	accessMode: "open",
	sourcesText: "",
	securityMode: "inherit",
});

const draftFromGroup = (group: SecurityHostGroup): Draft => ({
	id: group.id,
	name: group.name,
	description: group.description,
	hostIds: group.hostIds,
	accessMode: group.accessMode,
	sourcesText: group.sources.join("\n"),
	securityMode: group.securityMode,
});

const parseSources = (text: string) => text.split(/[\n,]+/).map((entry) => entry.trim()).filter(Boolean);

export default function SecurityGroups() {
	const queryClient = useQueryClient();
	const groups = useQuery({ queryKey: ["security-host-groups"], queryFn: getSecurityHostGroups });
	const hosts = useQuery({ queryKey: ["security-host-policies"], queryFn: getSecurityHostPolicies });
	const [draft, setDraft] = useState<Draft>(emptyDraft);
	const [error, setError] = useState("");
	const [hostSearch, setHostSearch] = useState("");
	const [accessHostId, setAccessHostId] = useState<number | null>(null);
	const [accessMode, setAccessMode] = useState<SecurityHostAccessMode>("inherit");
	const [accessSourcesText, setAccessSourcesText] = useState("");
	const [accessError, setAccessError] = useState("");
	const hostAccess = useQuery({
		queryKey: ["security-host-access", accessHostId],
		queryFn: () => getSecurityHostAccess(accessHostId as number),
		enabled: Boolean(accessHostId),
	});
	const groupTraffic = useQuery({
		queryKey: ["security-group-traffic", draft.id],
		queryFn: () => getSecurityEvents({ limit: 2000, groupId: draft.id || undefined, sinceMinutes: 60 }),
		enabled: Boolean(draft.id),
		refetchInterval: draft.id ? 10_000 : false,
	});

	useEffect(() => {
		if (!draft.id) return;
		const fresh = groups.data?.find((group) => group.id === draft.id);
		if (!fresh) setDraft(emptyDraft());
	}, [draft.id, groups.data]);

	useEffect(() => {
		if (!hostAccess.data) return;
		setAccessMode(hostAccess.data.accessMode);
		setAccessSourcesText(hostAccess.data.sources.join("\n"));
	}, [hostAccess.data]);

	const assignedElsewhere = useMemo(() => {
		const result = new Map<number, string>();
		for (const group of groups.data ?? []) {
			if (group.id === draft.id) continue;
			for (const hostId of group.hostIds) result.set(hostId, group.name);
		}
		return result;
	}, [draft.id, groups.data]);

	const visibleHosts = useMemo(() => {
		const needle = hostSearch.trim().toLowerCase();
		if (!needle) return hosts.data ?? [];
		return (hosts.data ?? []).filter(
			(host) => host.domainNames.join(" ").toLowerCase().includes(needle) || String(host.id).includes(needle),
		);
	}, [hostSearch, hosts.data]);

	const trafficSummary = useMemo(() => {
		const rows = groupTraffic.data ?? [];
		return {
			requests: rows.length,
			sources: new Set(rows.map((event) => event.ip)).size,
			suspicious: rows.filter((event) => event.risk >= 40).length,
			critical: rows.filter((event) => event.risk >= 80).length,
		};
	}, [groupTraffic.data]);

	const refresh = async () => {
		await Promise.all([
			queryClient.invalidateQueries({ queryKey: ["security-host-groups"] }),
			queryClient.invalidateQueries({ queryKey: ["security-host-policies"] }),
			queryClient.invalidateQueries({ queryKey: ["security-host-access"] }),
			queryClient.invalidateQueries({ queryKey: ["security-dashboard-events"] }),
			queryClient.invalidateQueries({ queryKey: ["security-group-traffic"] }),
		]);
	};

	const save = useMutation({
		mutationFn: async () => {
			setError("");
			const payload = {
				name: draft.name.trim(),
				description: draft.description.trim(),
				hostIds: draft.hostIds,
				accessMode: draft.accessMode,
				sources: parseSources(draft.sourcesText),
				securityMode: draft.securityMode,
			};
			if (!payload.name) throw new Error("Group name is required");
			if (payload.accessMode === "allowlist" && payload.sources.length === 0) {
				throw new Error("Allowlist requires at least one IP or CIDR");
			}
			return draft.id ? updateSecurityHostGroup(draft.id, payload) : createSecurityHostGroup(payload);
		},
		onSuccess: async (group) => {
			await refresh();
			setDraft(draftFromGroup(group));
		},
		onError: (err) => setError(err instanceof Error ? err.message : "Could not save group"),
	});

	const saveAccess = useMutation({
		mutationFn: async () => {
			setAccessError("");
			if (!accessHostId) throw new Error("Select a proxy host");
			const sources = parseSources(accessSourcesText);
			if (accessMode === "allowlist" && sources.length === 0) {
				throw new Error("Allowlist requires at least one IP or CIDR");
			}
			return updateSecurityHostAccess(accessHostId, {
				accessMode,
				sources: accessMode === "allowlist" || accessMode === "denylist" ? sources : [],
			});
		},
		onSuccess: async (result) => {
			queryClient.setQueryData(["security-host-access", result.hostId], result);
			await Promise.all([
				queryClient.invalidateQueries({ queryKey: ["security-host-groups"] }),
				queryClient.invalidateQueries({ queryKey: ["security-overview"] }),
				queryClient.invalidateQueries({ queryKey: ["security-dashboard-events"] }),
			]);
		},
		onError: (err) => setAccessError(err instanceof Error ? err.message : "Could not save host access"),
	});

	const remove = useMutation({
		mutationFn: deleteSecurityHostGroup,
		onSuccess: async () => {
			setDraft(emptyDraft());
			await refresh();
		},
		onError: (err) => setError(err instanceof Error ? err.message : "Could not delete group"),
	});

	const toggleHost = (hostId: number) => {
		setDraft((current) => ({
			...current,
			hostIds: current.hostIds.includes(hostId)
				? current.hostIds.filter((id) => id !== hostId)
				: [...current.hostIds, hostId],
		}));
	};

	const resetDraft = () => {
		const current = draft.id ? groups.data?.find((group) => group.id === draft.id) : null;
		setDraft(current ? draftFromGroup(current) : emptyDraft());
		setError("");
	};

	const selectedAccessHost = (hosts.data ?? []).find((host) => host.id === accessHostId) ?? null;
	const effectiveAccessMode =
		accessMode === "inherit" ? hostAccess.data?.effectiveAccessMode ?? "open" : accessMode;
	const resetAccessDraft = () => {
		setAccessMode(hostAccess.data?.accessMode ?? "inherit");
		setAccessSourcesText((hostAccess.data?.sources ?? []).join("\n"));
		setAccessError("");
	};

	return <div className={styles.shell}>
		<div className={styles.hero}>
			<div><h1>Access & host groups</h1><p>Control individual sites or apply one security mode and IP policy to many proxy hosts at once.</p></div>
			<button type="button" className="btn btn-primary" onClick={() => { setDraft(emptyDraft()); setError(""); }}><IconPlus size={17} /> New group</button>
		</div>

		<div className={styles.editor}>
			<div className="d-flex align-items-start justify-content-between gap-3 mb-3">
				<div>
					<h3 className="mb-1">Individual site access</h3>
					<div className="text-secondary small">
						Direct host rules override group access. Choose Inherit to follow the host group automatically.
					</div>
				</div>
				{accessHostId ? <span className="badge bg-secondary-lt">Effective: {effectiveAccessMode}</span> : null}
			</div>

			{accessError ? <div className="alert alert-danger py-2">{accessError}</div> : null}

			<div className={styles.editorGrid}>
				<div>
					<label className="form-label" htmlFor="security-host-access-host">Proxy host</label>
					<select
						id="security-host-access-host"
						className="form-select"
						value={accessHostId ?? ""}
						onChange={(event) => {
							const next = Number(event.target.value);
							setAccessHostId(Number.isInteger(next) && next > 0 ? next : null);
							setAccessMode("inherit");
							setAccessSourcesText("");
							setAccessError("");
						}}
					>
						<option value="">Select a site…</option>
						{(hosts.data ?? []).map((host) => <option key={host.id} value={host.id}>{host.domainNames.join(", ") || `Host #${host.id}`}</option>)}
					</select>
				</div>
				<div>
					<label className="form-label" htmlFor="security-host-access-mode">IP access</label>
					<select
						id="security-host-access-mode"
						className="form-select"
						value={accessMode}
						disabled={!accessHostId || hostAccess.isLoading}
						onChange={(event) => setAccessMode(event.target.value as SecurityHostAccessMode)}
					>
						<option value="inherit">Inherit group / default</option>
						<option value="open">Open to all IPs</option>
						<option value="allowlist">Only allow listed IPs</option>
						<option value="denylist">Block listed IPs</option>
					</select>
				</div>
				{accessMode === "allowlist" || accessMode === "denylist" ? <div className={styles.gridFull}>
					<label className="form-label" htmlFor="security-host-access-sources">IPs / CIDRs</label>
					<textarea
						id="security-host-access-sources"
						className="form-control font-monospace"
						rows={4}
						value={accessSourcesText}
						onChange={(event) => setAccessSourcesText(event.target.value)}
						placeholder={accessMode === "allowlist" ? "192.168.178.0/24\n203.0.113.10" : "203.0.113.0/24"}
					/>
					<div className="form-hint">IPv4 and IPv6 addresses or CIDRs, one per line or comma-separated.</div>
				</div> : null}
			</div>

			{accessHostId && hostAccess.data ? <div className={styles.policyPreview}>
				<div>
					<span>Selected site</span>
					<strong>{selectedAccessHost?.domainNames.join(", ") || `Host #${accessHostId}`}</strong>
					<small>{hostAccess.data.group ? `Group: ${hostAccess.data.group.name}` : "No security group assigned"}</small>
				</div>
				<div>
					<span>Current inherited access</span>
					<strong>{hostAccess.data.group ? hostAccess.data.group.accessMode : "open"}</strong>
					<small>{hostAccess.data.group?.sources.length ? `${hostAccess.data.group.sources.length} group IP/CIDR rules` : "No inherited IP restriction"}</small>
				</div>
			</div> : null}

			<div className={styles.actions}>
				<button type="button" className="btn btn-outline-secondary" disabled={!accessHostId} onClick={resetAccessDraft}>Reset</button>
				<button type="button" className="btn btn-primary" disabled={!accessHostId || saveAccess.isPending || hostAccess.isLoading} onClick={() => saveAccess.mutate()}>
					{saveAccess.isPending ? "Applying…" : "Save host access"}
				</button>
			</div>
		</div>

		<div className={styles.groupLayout}>
			<div className={styles.groupList}>
				{(groups.data ?? []).map((group) => <button
					type="button"
					key={group.id}
					className={`${styles.groupItem} ${draft.id === group.id ? styles.groupItemActive : ""}`}
					onClick={() => { setDraft(draftFromGroup(group)); setError(""); }}
				>
					<div className={styles.groupTitleRow}>
						<div className="fw-bold">{group.name}</div>
						<span className={`${styles.accessBadge} ${group.accessMode !== "open" ? styles.accessBadgeActive : ""}`}>{group.accessMode}</span>
					</div>
					<div className={styles.groupMeta}>{group.hostIds.length} hosts · {group.sources.length} IP/CIDR · security {group.securityMode}</div>
				</button>)}
				{!groups.isLoading && (groups.data?.length ?? 0) === 0 ? <div className="p-3 text-secondary">No groups yet. Create one to manage hosts together.</div> : null}
			</div>

			<div className={styles.editor}>
				<div className="d-flex align-items-start justify-content-between gap-3 mb-3">
					<div>
						<h3 className="mb-1">{draft.id ? "Edit group" : "New group"}</h3>
						<div className="text-secondary small">Group IP access is inherited by member hosts unless a host has an explicit access override. Per-host security mode settings can also override the group security mode.</div>
					</div>
					{draft.id ? <button type="button" className="btn btn-outline-danger btn-sm" disabled={remove.isPending} onClick={() => remove.mutate(draft.id as string)}><IconTrash size={15} /> Delete</button> : null}
				</div>

				{error ? <div className="alert alert-danger py-2">{error}</div> : null}

				{draft.id ? <div className={styles.groupMetrics}>
					<div><span>Requests · 1h</span><strong>{trafficSummary.requests}</strong></div>
					<div><span>Sources · 1h</span><strong>{trafficSummary.sources}</strong></div>
					<div><span>Suspicious</span><strong>{trafficSummary.suspicious}</strong></div>
					<div><span>Critical</span><strong>{trafficSummary.critical}</strong></div>
				</div> : null}

				<div className={styles.editorGrid}>
					<div><label className="form-label" htmlFor="security-group-name">Name</label><input id="security-group-name" className="form-control" value={draft.name} onChange={(e) => setDraft((current) => ({ ...current, name: e.target.value }))} placeholder="Private services" /></div>
					<div><label className="form-label" htmlFor="security-group-mode">Security mode</label><select id="security-group-mode" className="form-select" value={draft.securityMode} onChange={(e) => setDraft((current) => ({ ...current, securityMode: e.target.value as Draft["securityMode"] }))}><option value="inherit">Inherit global</option><option value="off">Off</option><option value="observe">Observe</option><option value="protect">Protect</option><option value="strict">Strict</option></select></div>
					<div className={styles.gridFull}><label className="form-label" htmlFor="security-group-description">Description</label><input id="security-group-description" className="form-control" value={draft.description} onChange={(e) => setDraft((current) => ({ ...current, description: e.target.value }))} placeholder="Internal dashboards and admin tools" /></div>
					<div><label className="form-label" htmlFor="security-group-access">IP access</label><select id="security-group-access" className="form-select" value={draft.accessMode} onChange={(e) => setDraft((current) => ({ ...current, accessMode: e.target.value as Draft["accessMode"] }))}><option value="open">Open</option><option value="allowlist">Only allow listed IPs</option><option value="denylist">Block listed IPs</option></select></div>
					<div><label className="form-label" htmlFor="security-group-sources">IPs / CIDRs</label><textarea id="security-group-sources" className="form-control font-monospace" rows={4} value={draft.sourcesText} disabled={draft.accessMode === "open"} onChange={(e) => setDraft((current) => ({ ...current, sourcesText: e.target.value }))} placeholder={draft.accessMode === "allowlist" ? "192.168.178.0/24\n203.0.113.10" : "203.0.113.0/24"} /><div className="form-hint">IPv4 and IPv6 addresses or CIDRs. Cloudflare traffic uses the restored real client IP.</div></div>
				</div>

				<div className="mt-4">
					<div className={styles.hostGridHeader}>
						<div>
							<div className="form-label mb-0">Proxy hosts in this group</div>
							<div className="text-secondary small">A host can be in one security group. Selecting a host from another group moves it here.</div>
						</div>
						<div className={styles.hostTools}>
							<div className={styles.hostSearch}><IconSearch size={15} /><input value={hostSearch} onChange={(event) => setHostSearch(event.target.value)} placeholder="Search hosts" /></div>
							<button type="button" className="btn btn-sm btn-outline-secondary" onClick={() => setDraft((current) => ({ ...current, hostIds: [...new Set([...current.hostIds, ...visibleHosts.map((host) => host.id)])] }))}>Select visible</button>
							<button type="button" className="btn btn-sm btn-outline-secondary" onClick={() => setDraft((current) => ({ ...current, hostIds: current.hostIds.filter((id) => !visibleHosts.some((host) => host.id === id)) }))}>Clear visible</button>
						</div>
					</div>
					<div className={styles.hostGrid}>
						{visibleHosts.map((host) => {
							const elsewhere = assignedElsewhere.get(host.id);
							return <label key={host.id} className={`${styles.hostChoice} ${draft.hostIds.includes(host.id) ? styles.hostChoiceSelected : ""}`}>
								<input type="checkbox" className="form-check-input mt-1" checked={draft.hostIds.includes(host.id)} onChange={() => toggleHost(host.id)} />
								<span>
									<span className="d-block fw-medium">{host.domainNames.join(", ") || `Host #${host.id}`}</span>
									<span className="text-secondary small">#{host.id}{elsewhere ? ` · currently ${elsewhere} (will move)` : ""}</span>
								</span>
							</label>;
						})}
						{visibleHosts.length === 0 ? <div className="p-2 text-secondary">No proxy hosts match this search.</div> : null}
					</div>
				</div>

				<div className={styles.policyPreview}>
					<div>
						<span>Effective group access</span>
						<strong>{draft.accessMode === "open" ? "Open to all source IPs" : draft.accessMode === "allowlist" ? `Only ${parseSources(draft.sourcesText).length} listed IP/CIDR entries can connect` : `${parseSources(draft.sourcesText).length} listed IP/CIDR entries are blocked`}</strong>
					</div>
					<div>
						<span>Security inheritance</span>
						<strong>{draft.securityMode === "inherit" ? "Global security mode" : `${draft.securityMode} for group hosts`}</strong>
						<small>Explicit per-host access or security policies override the matching group value; hosts without overrides inherit this group.</small>
					</div>
				</div>

				<div className={styles.actions}><button type="button" className="btn btn-outline-secondary" onClick={resetDraft}>Reset</button><button type="button" className="btn btn-primary" disabled={save.isPending} onClick={() => save.mutate()}>{save.isPending ? "Applying…" : "Save & apply"}</button></div>
			</div>
		</div>
	</div>;
}
