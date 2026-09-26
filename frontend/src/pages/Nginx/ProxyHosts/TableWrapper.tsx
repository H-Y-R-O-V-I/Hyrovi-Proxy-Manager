import { IconHelp, IconSearch } from "@tabler/icons-react";
import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import Alert from "react-bootstrap/Alert";
import { deleteProxyHost, toggleProxyHost } from "src/api/backend";
import { Button, HasPermission, LoadingPage } from "src/components";
import { useProxyHosts } from "src/hooks";
import { T } from "src/locale";
import { showDeleteConfirmModal, showHelpModal, showHostLogsModal, showProxyHostModal } from "src/modals";
import { MANAGE, PROXY_HOSTS } from "src/modules/Permissions";
import { showObjectSuccess } from "src/notifications";
import Table from "./Table";

export default function TableWrapper() {
	const queryClient = useQueryClient();
	const [search, setSearch] = useState("");
	const [nodeFilter, setNodeFilter] = useState<"all" | "local" | "vps">("all");
	const [statusFilter, setStatusFilter] = useState<"all" | "enabled" | "disabled">("all");
	const { isFetching, isLoading, isError, error, data } = useProxyHosts(["owner", "access_list", "certificate"]);

	if (isLoading) {
		return <LoadingPage />;
	}

	if (isError) {
		return <Alert variant="danger">{error?.message || "Unknown error"}</Alert>;
	}

	const handleDelete = async (id: number) => {
		await deleteProxyHost(id);
		showObjectSuccess("proxy-host", "deleted");
	};

	const handleDisableToggle = async (id: number, enabled: boolean) => {
		await toggleProxyHost(id, enabled);
		queryClient.invalidateQueries({ queryKey: ["proxy-hosts"] });
		queryClient.invalidateQueries({ queryKey: ["proxy-host", id] });
		showObjectSuccess("proxy-host", enabled ? "enabled" : "disabled");
	};

	const rows = data ?? [];
	const stats = {
		total: rows.length,
		enabled: rows.filter((item) => item.enabled).length,
		local: rows.filter((item) => !item.hyroviRemote).length,
		vps: rows.filter((item) => item.hyroviRemote || item.hyroviNodeId === "vps").length,
	};
	const filtered = rows.filter((item) => {
		if (nodeFilter === "local" && item.hyroviRemote) return false;
		if (nodeFilter === "vps" && !(item.hyroviRemote || item.hyroviNodeId === "vps")) return false;
		if (statusFilter === "enabled" && !item.enabled) return false;
		if (statusFilter === "disabled" && item.enabled) return false;
		if (!search) return true;
		return (
			item.domainNames.some((domain: string) => domain.toLowerCase().includes(search)) ||
			item.forwardHost.toLowerCase().includes(search) ||
			(item.hyroviNodeName || "").toLowerCase().includes(search) ||
			`${item.forwardPort}`.includes(search)
		);
	});

	return (
		<div className="card mt-4">
			<div className="card-status-top bg-lime" />
			<div className="card-table">
				<div className="card-header py-3">
					<div className="w-100">
						<div className="d-flex flex-column flex-lg-row align-items-lg-center justify-content-between gap-3">
							<div>
								<h2 className="mb-1"><T id="proxy-hosts" /></h2>
								<div className="text-secondary small">{stats.total} total · {stats.enabled} active · {stats.local} Raspberry Pi 5 · {stats.vps} HYROVI VPS</div>
							</div>
							<div className="d-flex flex-wrap align-items-center gap-2">
								<div className="input-group input-group-flat" style={{ width: 230 }}>
									<span className="input-group-text"><IconSearch size={16} /></span>
									<input id="advanced-table-search" type="text" className="form-control form-control-sm" autoComplete="off" placeholder="Search host, target or node…" onChange={(e: any) => setSearch(e.target.value.toLowerCase().trim())} />
								</div>
								<select className="form-select form-select-sm w-auto" value={nodeFilter} onChange={(e) => setNodeFilter(e.target.value as typeof nodeFilter)} aria-label="Filter by node">
									<option value="all">All nodes</option><option value="local">Raspberry Pi 5</option><option value="vps">HYROVI VPS</option>
								</select>
								<select className="form-select form-select-sm w-auto" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value as typeof statusFilter)} aria-label="Filter by status">
									<option value="all">All status</option><option value="enabled">Active</option><option value="disabled">Disabled</option>
								</select>
								<Button size="sm" onClick={() => showHelpModal("ProxyHosts", "lime")}><IconHelp size={18} /></Button>
								<HasPermission section={PROXY_HOSTS} permission={MANAGE} hideError>
									<Button size="sm" className="btn-lime" onClick={() => showProxyHostModal("new")}><T id="object.add" tData={{ object: "proxy-host" }} /></Button>
								</HasPermission>
							</div>
						</div>
					</div>
				</div>
				<Table
					data={filtered}
					isFiltered={!!search || nodeFilter !== "all" || statusFilter !== "all"}
					isFetching={isFetching}
					onEdit={(id: number) => showProxyHostModal(id)}
					onLogs={(id: number) => showHostLogsModal(id)}
					onDelete={(id: number) => {
						const host = data?.find((h) => h.id === id);
						showDeleteConfirmModal({
							title: <T id="object.delete" tData={{ object: "proxy-host" }} />,
							onConfirm: () => handleDelete(id),
							invalidations: [["proxy-hosts"], ["proxy-host", id]],
							children: (
								<>
									<T id="object.delete.content" tData={{ object: "proxy-host" }} />
									{host?.domainNames?.length ? (
										<div className="mt-2 fw-bold text-break">{host.domainNames.join(", ")}</div>
									) : null}
									{host?.forwardHost ? (
										<div className="mt-1 text-muted small">
											({host.forwardScheme}://{host.forwardHost}:{host.forwardPort})
										</div>
									) : null}
								</>
							),
						});
					}}
					onDisableToggle={handleDisableToggle}
					onNew={() => showProxyHostModal("new")}
				/>
			</div>
		</div>
	);
}
