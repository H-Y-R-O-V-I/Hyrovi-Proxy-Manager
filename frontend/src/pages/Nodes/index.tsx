import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { IconCopy, IconRefresh, IconServer, IconTrash } from "@tabler/icons-react";
import { useState } from "react";
import {
	createControlPlaneNode,
	deleteControlPlaneNode,
	getControlPlaneNodes,
	rotateControlPlaneNodeToken,
	updateControlPlaneNode,
} from "src/api/backend";
import { Button, HasPermission } from "src/components";
import { ADMIN, VIEW } from "src/modules/Permissions";

const POLL_MS = 10_000;

const formatTime = (value: string | null) => {
	if (!value) return "—";
	const date = new Date(value);
	return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
};

const statusClass = (status: string) => {
	switch (status) {
		case "online":
			return "bg-green-lt";
		case "stale":
			return "bg-yellow-lt";
		case "disabled":
			return "bg-secondary-lt";
		default:
			return "bg-azure-lt";
	}
};

const Nodes = () => {
	const queryClient = useQueryClient();
	const [name, setName] = useState("");
	const [nodeId, setNodeId] = useState("");
	const [bootstrapToken, setBootstrapToken] = useState<string | null>(null);

	const nodes = useQuery({
		queryKey: ["control-plane-nodes"],
		queryFn: getControlPlaneNodes,
		refetchInterval: POLL_MS,
	});

	const refresh = () => queryClient.invalidateQueries({ queryKey: ["control-plane-nodes"] });

	const createNode = useMutation({
		mutationFn: createControlPlaneNode,
		onSuccess: async (result) => {
			setBootstrapToken(result.bootstrapToken);
			setName("");
			setNodeId("");
			await refresh();
		},
	});

	const removeNode = useMutation({
		mutationFn: deleteControlPlaneNode,
		onSuccess: refresh,
	});

	const toggleNode = useMutation({
		mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
			updateControlPlaneNode(id, { enabled }),
		onSuccess: refresh,
	});

	const rotateToken = useMutation({
		mutationFn: rotateControlPlaneNodeToken,
		onSuccess: async (result) => {
			setBootstrapToken(result.bootstrapToken);
			await refresh();
		},
	});

	const copyBootstrapToken = async () => {
		if (bootstrapToken) await navigator.clipboard.writeText(bootstrapToken);
	};

	return (
		<HasPermission section={ADMIN} permission={VIEW} pageLoading loadingNoLogo>
			<div>
				<div className="d-flex flex-column flex-md-row align-items-md-center justify-content-between gap-3 mb-4">
					<div>
						<h2 className="mb-1">HYROVI Nodes</h2>
						<div className="text-secondary">
							One control plane for proxy hosts, security telemetry and enforcement across the VPS, Pi and future edge nodes.
						</div>
					</div>
					<Button className="btn-outline-secondary" onClick={() => void refresh()}>
						<IconRefresh size={18} className="me-1" />
						Refresh
					</Button>
				</div>

				<div className="card mb-4">
					<div className="card-header">
						<div>
							<h3 className="card-title">Add edge node</h3>
							<div className="text-secondary small">
								The bootstrap token is shown only after creation or rotation. The controller stores only its SHA-256 hash.
							</div>
						</div>
					</div>
					<div className="card-body">
						<div className="row g-3 align-items-end">
							<div className="col-12 col-md-5">
								<label className="form-label" htmlFor="hyrovi-node-name">Name</label>
								<input
									id="hyrovi-node-name"
									className="form-control"
									value={name}
									onChange={(event) => setName(event.target.value)}
									placeholder="Raspberry Pi 5"
								/>
							</div>
							<div className="col-12 col-md-4">
								<label className="form-label" htmlFor="hyrovi-node-id">Node ID (optional)</label>
								<input
									id="hyrovi-node-id"
									className="form-control font-monospace"
									value={nodeId}
									onChange={(event) => setNodeId(event.target.value)}
									placeholder="pi5"
								/>
							</div>
							<div className="col-12 col-md-3 d-grid">
								<Button
									className="btn-primary"
									disabled={!name.trim() || createNode.isPending}
									onClick={() => createNode.mutate({ name: name.trim(), id: nodeId.trim() || undefined })}
								>
									Add node
								</Button>
							</div>
						</div>
						{createNode.error ? <div className="text-red mt-2">{createNode.error.message}</div> : null}
					</div>
				</div>

				{bootstrapToken ? (
					<div className="alert alert-warning mb-4" role="alert">
						<div className="d-flex flex-column flex-lg-row justify-content-between gap-3">
							<div>
								<strong>New bootstrap token — copy it now.</strong>
								<div className="font-monospace text-break mt-1">{bootstrapToken}</div>
								<div className="small mt-1">It will not be returned by the normal node list.</div>
							</div>
							<div className="d-flex gap-2 align-items-start">
								<Button className="btn-outline-secondary" onClick={() => void copyBootstrapToken()}>
									<IconCopy size={18} className="me-1" />
									Copy
								</Button>
								<Button className="btn-outline-secondary" onClick={() => setBootstrapToken(null)}>
									Hide
								</Button>
							</div>
						</div>
					</div>
				) : null}

				<div className="card">
					<div className="card-header d-flex align-items-center justify-content-between">
						<div>
							<h3 className="card-title">Proxy nodes</h3>
							<div className="text-secondary small">
								Remote nodes become stale after 90 seconds without a heartbeat. Local is the controller itself.
							</div>
						</div>
						<span className="badge bg-azure-lt">{nodes.data?.length ?? 0} nodes</span>
					</div>
					<div className="table-responsive">
						<table className="table table-vcenter card-table">
							<thead>
								<tr>
									<th>Node</th>
									<th>Status</th>
									<th>Agent</th>
									<th>Capabilities</th>
									<th>Config</th>
									<th>Last seen</th>
									<th />
								</tr>
							</thead>
							<tbody>
								{(nodes.data ?? []).map((node) => (
									<tr key={node.id}>
										<td style={{ minWidth: 220 }}>
											<div className="d-flex align-items-center gap-2">
												<IconServer size={18} />
												<div>
													<div className="fw-semibold">{node.name}</div>
													<div className="font-monospace text-secondary small">{node.id} · {node.mode}</div>
												</div>
											</div>
										</td>
										<td><span className={`badge ${statusClass(node.status)}`}>{node.status.toUpperCase()}</span></td>
										<td className="small">
											<div>{node.agent?.hostname || "—"}</div>
											<div className="text-secondary">{node.agent?.platform || "—"}{node.agent?.version ? ` · ${node.agent.version}` : ""}</div>
										</td>
										<td style={{ minWidth: 180 }}>
											<div className="d-flex flex-wrap gap-1">
												{node.capabilities.map((capability) => (
													<span className="badge bg-secondary-lt" key={capability}>{capability}</span>
												))}
												{node.capabilities.length === 0 ? <span className="text-secondary">—</span> : null}
											</div>
										</td>
										<td className="font-monospace">{node.appliedRevision}/{node.desiredRevision}</td>
										<td className="text-nowrap">{formatTime(node.lastSeenAt)}</td>
										<td className="text-end">
											{node.mode === "remote" ? (
												<div className="d-flex justify-content-end gap-2">
													<Button
														className="btn-outline-secondary"
														disabled={toggleNode.isPending}
														onClick={() => toggleNode.mutate({ id: node.id, enabled: !node.enabled })}
													>
														{node.enabled ? "Disable" : "Enable"}
													</Button>
													<Button
														className="btn-outline-secondary"
														disabled={rotateToken.isPending}
														onClick={() => rotateToken.mutate(node.id)}
													>
														Rotate token
													</Button>
													<Button
														className="btn-outline-danger"
														disabled={removeNode.isPending}
														onClick={() => removeNode.mutate(node.id)}
													>
														<IconTrash size={18} />
													</Button>
												</div>
											) : null}
										</td>
									</tr>
								))}
								{!nodes.isLoading && (nodes.data?.length ?? 0) === 0 ? (
									<tr><td colSpan={7} className="text-secondary">No proxy nodes available.</td></tr>
								) : null}
							</tbody>
						</table>
					</div>
				</div>
			</div>
		</HasPermission>
	);
};

export default Nodes;
