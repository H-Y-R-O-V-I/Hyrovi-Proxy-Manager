import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
	deleteSecurityHostAccess,
	deleteSecurityHostPolicy,
	getProxyHost,
	provisionProxyHost,
	type ProxyHost,
	type SecurityHostAccessPolicy,
	type SecurityHostPolicy,
	updateProxyHost,
	updateSecurityHostAccess,
	updateSecurityHostPolicy,
	waitForProxyHostProvisioningJob,
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
		staleTime: 60 * 1000,
		...options,
	});
};

type ProxyHostMutationInput = Omit<ProxyHost, "id"> & {
	id?: number;
	hyroviSecurityPolicy?: SecurityHostPolicy | null;
	hyroviSecurityAccess?: Pick<SecurityHostAccessPolicy, "accessMode" | "sources"> | null;
	hyroviNodeId?: string;
	hyroviCloudflareTunnel?: boolean;
};

type ProxyHostRollback = () => void;

const useSetProxyHost = () => {
	const queryClient = useQueryClient();
	return useMutation({
		mutationFn: async (values: ProxyHostMutationInput) => {
			const {
				hyroviSecurityPolicy,
				hyroviSecurityAccess,
				hyroviNodeId = "local",
				hyroviCloudflareTunnel = true,
				...proxyHostValues
			} = values;

			if (!proxyHostValues.id) {
				const queued = await provisionProxyHost({
					nodeId: hyroviNodeId,
					cloudflareTunnel: hyroviCloudflareTunnel,
					proxyHost: proxyHostValues as Omit<ProxyHost, "id">,
					securityPolicy: hyroviSecurityPolicy,
					securityAccess: hyroviSecurityAccess,
				});
				const completed = await waitForProxyHostProvisioningJob(queued.id);
				const provisioned = completed.result?.proxyHost;
				if (!provisioned?.id) throw new Error("Provisioning completed without a Proxy Host ID");
				return {
					...proxyHostValues,
					id: provisioned.id,
					domainNames: provisioned.domainNames ?? proxyHostValues.domainNames,
					forwardScheme: provisioned.forwardScheme ?? proxyHostValues.forwardScheme,
					forwardHost: provisioned.forwardHost ?? proxyHostValues.forwardHost,
					forwardPort: provisioned.forwardPort ?? proxyHostValues.forwardPort,
					certificateId: provisioned.certificateId ?? proxyHostValues.certificateId,
				} as ProxyHost;
			}

			const savedHost = await updateProxyHost(proxyHostValues as ProxyHost);
			try {
				if (hyroviSecurityPolicy === null) {
					await deleteSecurityHostPolicy(savedHost.id);
				} else if (hyroviSecurityPolicy) {
					await updateSecurityHostPolicy(savedHost.id, hyroviSecurityPolicy);
				}
				if (hyroviSecurityAccess === null) {
					await deleteSecurityHostAccess(savedHost.id);
				} else if (hyroviSecurityAccess) {
					await updateSecurityHostAccess(savedHost.id, hyroviSecurityAccess);
				}
			} catch (err) {
				const message = err instanceof Error ? err.message : String(err);
				throw new Error(`Proxy Host saved, but HYROVI Sec configuration failed: ${message}`);
			}

			return savedHost;
		},
		onMutate: (values: ProxyHostMutationInput) => {
			if (!values.id) return () => undefined;
			const {
				hyroviSecurityPolicy: _,
				hyroviSecurityAccess: __,
				hyroviNodeId: ___,
				hyroviCloudflareTunnel: ____,
				...proxyHostValues
			} = values;
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
			queryClient.invalidateQueries({ queryKey: ["security-host-access", id] });
			queryClient.invalidateQueries({ queryKey: ["security-host-groups"] });
			queryClient.invalidateQueries({ queryKey: ["security-overview"] });
			queryClient.invalidateQueries({ queryKey: ["audit-logs"] });
			queryClient.invalidateQueries({ queryKey: ["host-report"] });
			queryClient.invalidateQueries({ queryKey: ["certificates"] });
			queryClient.invalidateQueries({ queryKey: ["control-plane-nodes"] });
		},
	});
};

export { useProxyHost, useSetProxyHost };
export type { ProxyHostMutationInput };
