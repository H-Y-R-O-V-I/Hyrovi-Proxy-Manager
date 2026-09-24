import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
	createProxyHost,
	deleteSecurityHostPolicy,
	getProxyHost,
	type ProxyHost,
	type SecurityHostPolicy,
	updateProxyHost,
	updateSecurityHostPolicy,
} from "src/api/backend";

const fetchProxyHost = (id: number | "new") => {
	if (id === "new") {
		return Promise.resolve({
			id: 0,
			createdOn: "",
			modifiedOn: "",
			ownerUserId: 0,
			domainNames: [],
			forwardHost: "",
			forwardPort: 0,
			accessListId: 0,
			certificateId: 0,
			sslForced: false,
			cachingEnabled: false,
			blockExploits: false,
			advancedConfig: "",
			meta: {},
			allowWebsocketUpgrade: false,
			http2Support: false,
			forwardScheme: "",
			enabled: true,
			hstsEnabled: false,
			hstsSubdomains: false,
			trustForwardedProto: false,
		} as ProxyHost);
	}
	return getProxyHost(id, ["owner"]);
};

const useProxyHost = (id: number | "new", options = {}) => {
	return useQuery<ProxyHost, Error>({
		queryKey: ["proxy-host", id],
		queryFn: () => fetchProxyHost(id),
		staleTime: 60 * 1000, // 1 minute
		...options,
	});
};

type ProxyHostMutationInput = Omit<ProxyHost, "id"> & {
	id?: number;
	hyroviSecurityPolicy?: SecurityHostPolicy | null;
};

type ProxyHostRollback = () => void;

const useSetProxyHost = () => {
	const queryClient = useQueryClient();
	return useMutation({
		mutationFn: async (values: ProxyHostMutationInput) => {
			const { hyroviSecurityPolicy, ...proxyHostValues } = values;
			const savedHost = proxyHostValues.id
				? await updateProxyHost(proxyHostValues as ProxyHost)
				: await createProxyHost(proxyHostValues as ProxyHost);

			try {
				if (hyroviSecurityPolicy === null) {
					await deleteSecurityHostPolicy(savedHost.id);
				} else if (hyroviSecurityPolicy) {
					await updateSecurityHostPolicy(savedHost.id, hyroviSecurityPolicy);
				}
			} catch (err) {
				const message = err instanceof Error ? err.message : String(err);
				throw new Error(`Proxy Host saved, but HYROVI Sec policy failed: ${message}`);
			}

			return savedHost;
		},
		onMutate: (values: ProxyHostMutationInput) => {
			if (!values.id) {
				return () => undefined;
			}
			const { hyroviSecurityPolicy: _, ...proxyHostValues } = values;
			const previousObject = queryClient.getQueryData(["proxy-host", values.id]);
			queryClient.setQueryData(["proxy-host", values.id], (old: ProxyHost) => ({
				...old,
				...proxyHostValues,
			}));
			return () => queryClient.setQueryData(["proxy-host", values.id], previousObject);
		},
		onError: (_, __, rollback: ProxyHostRollback | undefined) => rollback?.(),
		onSuccess: async ({ id }: ProxyHost) => {
			queryClient.invalidateQueries({ queryKey: ["proxy-host", id] });
			queryClient.invalidateQueries({ queryKey: ["proxy-hosts"] });
			queryClient.invalidateQueries({ queryKey: ["security-host-policies"] });
			queryClient.invalidateQueries({ queryKey: ["security-overview"] });
			queryClient.invalidateQueries({ queryKey: ["audit-logs"] });
			queryClient.invalidateQueries({ queryKey: ["host-report"] });
			queryClient.invalidateQueries({ queryKey: ["certificates"] });
		},
	});
};

export { useProxyHost, useSetProxyHost };
export type { ProxyHostMutationInput };
