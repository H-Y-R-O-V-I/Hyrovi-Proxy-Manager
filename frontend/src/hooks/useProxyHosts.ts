import { useQuery } from "@tanstack/react-query";
import { getControlPlaneNodes, getProxyHosts, type ProxyHost, type ProxyHostExpansion } from "src/api/backend";

const combineProxyHosts = (localHosts: ProxyHost[], nodes: Awaited<ReturnType<typeof getControlPlaneNodes>>) => {
	const localNode = nodes.find((node) => node.id === "local");
	const local = localHosts.map((host) => ({
		...host,
		hyroviNodeId: "local",
		hyroviNodeName: localNode?.name || "Raspberry Pi 5",
		hyroviRemote: false,
	}));
	const remote = nodes
		.filter((node) => node.mode === "remote")
		.flatMap((node) =>
			(node.proxyHosts ?? []).map((host): ProxyHost => ({
				id: host.id,
				createdOn: host.createdOn || node.lastSeenAt || "",
				modifiedOn: host.modifiedOn || node.lastSeenAt || "",
				ownerUserId: 0,
				domainNames: host.domainNames,
				forwardScheme: host.forwardScheme,
				forwardHost: host.forwardHost,
				forwardPort: host.forwardPort,
				accessListId: 0,
				certificateId: host.certificateId,
				sslForced: host.sslForced,
				cachingEnabled: false,
				blockExploits: false,
				advancedConfig: "",
				meta: {},
				allowWebsocketUpgrade: false,
				http2Support: host.http2Support,
				enabled: host.enabled,
				hstsEnabled: false,
				hstsSubdomains: false,
				trustForwardedProto: false,
				hyroviNodeId: node.id,
				hyroviNodeName: node.name,
				hyroviRemote: true,
				hyroviCertificateName: host.certificateName,
			})),
		);
	return [...local, ...remote];
};

const fetchProxyHosts = async (expand?: ProxyHostExpansion[]) => {
	const [localHosts, nodes] = await Promise.all([
		getProxyHosts(expand),
		getControlPlaneNodes().catch(() => []),
	]);
	return combineProxyHosts(localHosts, nodes);
};

const useProxyHosts = (expand?: ProxyHostExpansion[], options = {}) => {
	// The local list should render immediately, even if remote node discovery is slow.
	const nodesQuery = useQuery({
		queryKey: ["proxy-host-nodes"],
		queryFn: () => getControlPlaneNodes().catch(() => []),
		staleTime: 60 * 1000,
		refetchInterval: 60 * 1000,
		retry: false,
	});
	const localQuery = useQuery<ProxyHost[], Error>({
		queryKey: ["proxy-hosts", { expand }],
		queryFn: () => getProxyHosts(expand),
		staleTime: 20 * 1000,
		refetchInterval: 30 * 1000,
		...options,
	});
	return {
		...localQuery,
		data: localQuery.data ? combineProxyHosts(localQuery.data, nodesQuery.data ?? []) : undefined,
		isFetching: localQuery.isFetching || nodesQuery.isFetching,
	};
};

export { fetchProxyHosts, useProxyHosts };
