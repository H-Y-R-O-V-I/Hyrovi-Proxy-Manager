import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { IconBan, IconClock, IconSearch, IconShieldOff } from "@tabler/icons-react";
import { useMemo, useState } from "react";
import {
	createControlPlaneSecurityBlock,
	createSecurityBlock,
	deleteControlPlaneSecurityBlock,
	deleteSecurityBlock,
	getControlPlaneNodes,
	getSecurityBlocks,
	waitForControlPlaneProvisioningJob,
	type SecurityBlock,
} from "src/api/backend";
import styles from "./Security.module.css";

const POLL_MS = 5000;

type BlockRow = SecurityBlock & {
	nodeId: string;
	nodeName: string;
	remote: boolean;
};

const automaticSource = (source: string) =>
	/^(auto-|policy-|auto$|crawler|scanner|escalation|adaptive)/i.test(source || "");

const formatTime = (value: string | null) => {
	if (!value) return "—";
	const date = new Date(value);
	return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
};

const remaining = (value: string | null) => {
	if (!value) return "No expiry";
	const ms = new Date(value).getTime() - Date.now();
	if (!Number.isFinite(ms) || ms <= 0) return "Expiring";
	const minutes = Math.ceil(ms / 60_000);
	if (minutes < 60) return `${minutes}m`;
	const hours = Math.ceil(minutes / 60);
	if (hours < 48) return `${hours}h`;
	return `${Math.ceil(hours / 24)}d`;
};

const SecurityBlocks = () => {
	const queryClient = useQueryClient();
	const [search, setSearch] = useState("");
	const [nodeFilter, setNodeFilter] = useState("all");
	const [ip, setIp] = useState("");
	const [reason, setReason] = useState("");
	const [durationMinutes, setDurationMinutes] = useState(60);
	const [targetNode, setTargetNode] = useState("local");
	const [message, setMessage] = useState<string | null>(null);

	const localBlocks = useQuery({
		queryKey: ["security-blocks"],
		queryFn: getSecurityBlocks,
		refetchInterval: POLL_MS,
	});

	const nodes = useQuery({
		queryKey: ["control-plane-nodes"],
		queryFn: getControlPlaneNodes,
		refetchInterval: POLL_MS,
	});

	const availableNodes = useMemo(
		() =>
			(nodes.data ?? []).filter(
				(node) =>
					node.enabled &&
					node.status === "online" &&
					node.capabilities.includes("security") &&
					node.capabilities.includes("provisioning"),
			),
		[nodes.data],
	);

	const rows = useMemo<BlockRow[]>(() => {
		const now = Date.now();
		const result: BlockRow[] = (localBlocks.data ?? []).map((block) => ({
			...block,
			nodeId: "local",
			nodeName: nodes.data?.find((node) => node.id === "local")?.name || "Raspberry Pi 5",
			remote: false,
		}));
		for (const node of nodes.data ?? []) {
			if (node.mode !== "remote") continue;
			for (const block of node.securityBlocks ?? []) {
				if (block.expiresAt && Date.parse(block.expiresAt) <= now) continue;
				result.push({
					id: block.id,
					ip: block.ip,
					reason: block.reason,
					source: block.source,
					createdAt: block.createdAt || "",
					expiresAt: block.expiresAt || "",
					nodeId: node.id,
					nodeName: node.name,
					remote: true,
				});
			}
		}
		return result.sort((a, b) => Date.parse(b.createdAt || "") - Date.parse(a.createdAt || ""));
	}, [localBlocks.data, nodes.data]);

	const filtered = useMemo(() => {
		const q = search.trim().toLowerCase();
		return rows.filter((block) => {
			if (nodeFilter !== "all" && block.nodeId !== nodeFilter) return false;
			if (!q) return true;
			return [block.ip, block.reason, block.source, block.nodeName].some((value) =>
				String(value || "").toLowerCase().includes(q),
			);
		});
	}, [rows, search, nodeFilter]);

	const refresh = async () => {
		await Promise.all([
			queryClient.invalidateQueries({ queryKey: ["security-blocks"] }),
			queryClient.invalidateQueries({ queryKey: ["control-plane-nodes"] }),
			queryClient.invalidateQueries({ queryKey: ["security-overview"] }),
		]);
	};

	const createBlock = useMutation({
		mutationFn: async () => {
			const target = ip.trim();
			if (!target) throw new Error("Enter an IP address or CIDR.");
			setMessage(null);
			if (targetNode === "local") {
				return await createSecurityBlock({
					ip: target,
					durationMinutes,
					reason: reason.trim() || "Manual HYROVI Sec block",
					source: "security-blocks-ui",
				});
			}
			const job = await createControlPlaneSecurityBlock(targetNode, {
				ip: target,
				durationMinutes,
				reason: reason.trim() || "Manual HYROVI Sec block",
				source: "security-blocks-ui",
			});
			return await waitForControlPlaneProvisioningJob(job.id);
		},
		onSuccess: async () => {
			setIp("");
			setReason("");
			setMessage("Block applied.");
			await refresh();
		},
		onError: (error) => setMessage(error instanceof Error ? error.message : "Could not apply block."),
	});

	const removeBlock = useMutation({
		mutationFn: async (block: BlockRow) => {
			setMessage(null);
			if (!block.remote) return await deleteSecurityBlock(block.id);
			const job = await deleteControlPlaneSecurityBlock(block.nodeId, block.id);
			return await waitForControlPlaneProvisioningJob(job.id);
		},
		onSuccess: async () => {
			setMessage("IP unblocked.");
			await refresh();
		},
		onError: (error) => setMessage(error instanceof Error ? error.message : "Could not remove block."),
	});

	const automated = rows.filter((block) => automaticSource(block.source)).length;

	return (
		<div className={styles.shell}>
			<div className={styles.hero}>
				<div>
					<h1>Blocked IPs</h1>
					<p>See and manage active HYROVI Sec IP/CIDR blocks across Raspberry Pi 5 and HYROVI VPS.</p>
				</div>
			</div>

			<div className="alert alert-success d-flex align-items-start gap-2 mb-0" role="status">
				<IconShieldOff size={20} className="mt-1 flex-shrink-0" />
				<div>
					<strong>Management access protected</strong>
					<div className="small mt-1">HYROVI Sec IP blocks apply to protected proxy traffic, not to <code>hpm.hyrovi.com</code>. The management hostname is reserved and stays on its direct Cloudflare → HPM admin path so you can always return here to revoke a block.</div>
				</div>
			</div>

			<div className={styles.metrics}>
				<div className={styles.metric}>
					<div className={styles.metricLabel}>Active blocks</div>
					<div className={styles.metricValue}>{rows.length}</div>
					<small>across all online nodes</small>
				</div>
				<div className={styles.metric}>
					<div className={styles.metricLabel}>Automatic</div>
					<div className={styles.metricValue}>{automated}</div>
					<small>policy / adaptive response</small>
				</div>
				<div className={styles.metric}>
					<div className={styles.metricLabel}>Manual</div>
					<div className={styles.metricValue}>{Math.max(0, rows.length - automated)}</div>
					<small>operator-created blocks</small>
				</div>
				<div className={styles.metric}>
					<div className={styles.metricLabel}>Nodes reporting</div>
					<div className={styles.metricValue}>{availableNodes.length}</div>
					<small>security + provisioning online</small>
				</div>
			</div>

			<div className="card">
				<div className="card-header">
					<div>
						<h3 className="card-title mb-1">Block IP or CIDR</h3>
						<div className="text-secondary small">Applied immediately on the selected node and recorded in the HYROVI Sec response history.</div>
					</div>
				</div>
				<div className="card-body">
					<div className="row g-2 align-items-end">
						<div className="col-12 col-lg-3">
							<label className="form-label" htmlFor="security-block-node">Node</label>
							<select id="security-block-node" className="form-select" value={targetNode} onChange={(event) => setTargetNode(event.target.value)}>
								{availableNodes.map((node) => <option key={node.id} value={node.id}>{node.name}</option>)}
							</select>
						</div>
						<div className="col-12 col-lg-3">
							<label className="form-label" htmlFor="security-block-ip">IP / CIDR</label>
							<input id="security-block-ip" className="form-control font-monospace" value={ip} onChange={(event) => setIp(event.target.value)} placeholder="203.0.113.10 or 203.0.113.0/24" />
						</div>
						<div className="col-6 col-lg-2">
							<label className="form-label" htmlFor="security-block-duration">Duration</label>
							<select id="security-block-duration" className="form-select" value={durationMinutes} onChange={(event) => setDurationMinutes(Number(event.target.value))}>
								<option value={15}>15 minutes</option>
								<option value={60}>1 hour</option>
								<option value={360}>6 hours</option>
								<option value={1440}>1 day</option>
								<option value={10080}>7 days</option>
								<option value={43200}>30 days</option>
							</select>
						</div>
						<div className="col-12 col-lg-3">
							<label className="form-label" htmlFor="security-block-reason">Reason</label>
							<input id="security-block-reason" className="form-control" value={reason} onChange={(event) => setReason(event.target.value)} placeholder="Optional reason" />
						</div>
						<div className="col-6 col-lg-1 d-grid">
							<button type="button" className="btn btn-danger" disabled={createBlock.isPending || !ip.trim()} onClick={() => createBlock.mutate()}>
								<IconBan size={17} /> Block
							</button>
						</div>
					</div>
					{message ? <div className="text-secondary small mt-2">{message}</div> : null}
				</div>
			</div>

			<div className="card">
				<div className="card-header py-3">
					<div className="d-flex flex-column flex-lg-row w-100 align-items-lg-center justify-content-between gap-3">
						<div>
							<h3 className="card-title mb-1">Active blocks</h3>
							<div className="text-secondary small">{filtered.length} shown · blocks disappear automatically after expiry.</div>
						</div>
						<div className="d-flex gap-2 flex-wrap">
							<div className="input-group input-group-flat" style={{ width: 260 }}>
								<span className="input-group-text"><IconSearch size={16} /></span>
								<input className="form-control form-control-sm" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search IP, reason, source…" />
							</div>
							<select className="form-select form-select-sm w-auto" value={nodeFilter} onChange={(event) => setNodeFilter(event.target.value)}>
								<option value="all">All nodes</option>
								{(nodes.data ?? []).map((node) => <option key={node.id} value={node.id}>{node.name}</option>)}
							</select>
						</div>
					</div>
				</div>
				<div className="table-responsive">
					<table className="table table-vcenter card-table">
						<thead>
							<tr>
								<th>IP / CIDR</th>
								<th>Node</th>
								<th>Type</th>
								<th>Reason</th>
								<th>Source</th>
								<th>Blocked since</th>
								<th>Expires</th>
								<th>Remaining</th>
								<th />
							</tr>
						</thead>
						<tbody>
							{filtered.map((block) => (
								<tr key={`${block.nodeId}:${block.id}`}>
									<td className="font-monospace fw-semibold">{block.ip}</td>
									<td><span className={`badge ${block.remote ? "bg-blue-lt" : "bg-lime-lt"}`}>{block.nodeName}</span></td>
									<td><span className={`badge ${automaticSource(block.source) ? "bg-orange-lt" : "bg-secondary-lt"}`}>{automaticSource(block.source) ? "Automatic" : "Manual"}</span></td>
									<td style={{ minWidth: 220 }}>{block.reason || "—"}</td>
									<td><code>{block.source || "—"}</code></td>
									<td>{formatTime(block.createdAt)}</td>
									<td>{formatTime(block.expiresAt)}</td>
									<td><span className="d-inline-flex align-items-center gap-1"><IconClock size={14} /> {remaining(block.expiresAt)}</span></td>
									<td className="text-end">
										<button type="button" className="btn btn-sm btn-outline-danger" disabled={removeBlock.isPending} onClick={() => removeBlock.mutate(block)}>
											<IconShieldOff size={15} /> Unblock
										</button>
									</td>
								</tr>
							))}
							{!localBlocks.isLoading && !nodes.isLoading && filtered.length === 0 ? (
								<tr><td colSpan={9} className="text-secondary py-4 text-center">No active blocks match this filter.</td></tr>
							) : null}
						</tbody>
					</table>
				</div>
			</div>
		</div>
	);
};

export default SecurityBlocks;
