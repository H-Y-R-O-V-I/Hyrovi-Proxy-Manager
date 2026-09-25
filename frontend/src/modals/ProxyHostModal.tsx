import { IconSettings, IconShield } from "@tabler/icons-react";
import cn from "classnames";
import { useQuery } from "@tanstack/react-query";
import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { Field, FieldArray, Form, Formik } from "formik";
import { type ReactNode, useState } from "react";
import { Alert } from "react-bootstrap";
import Modal from "react-bootstrap/Modal";
import {
	AccessField,
	Button,
	DomainNamesField,
	HasPermission,
	Loading,
	LocationsFields,
	NginxConfigField,
	SSLCertificateField,
	SSLOptionsFields,
} from "src/components";
import {
	getSecurityHostAccess,
	getSecurityHostPolicy,
	getSecurityHostPolicyDefaults,
	type SecurityHostMode,
	type SecurityHostPolicy,
} from "src/api/backend";
import { type ProxyHostMutationInput, useProxyHost, useSetProxyHost, useUser } from "src/hooks";
import { T } from "src/locale";
import { MANAGE, PROXY_HOSTS } from "src/modules/Permissions";
import { validateNumber, validateString } from "src/modules/Validations";
import { showObjectSuccess } from "src/notifications";

const showProxyHostModal = (id: number | "new") => {
	EasyModal.show(ProxyHostModal, { id });
};

interface Props extends InnerModalProps {
	id: number | "new";
}
const ProxyHostModal = EasyModal.create(({ id, visible, remove }: Props) => {
	const { data: currentUser, isLoading: userIsLoading, error: userError } = useUser("me");
	const { data, isLoading, error } = useProxyHost(id);
	const securityDefaults = useQuery({
		queryKey: ["security-host-policy-defaults"],
		queryFn: getSecurityHostPolicyDefaults,
	});
	const securityHostPolicy = useQuery({
		queryKey: ["security-host-policy", id],
		queryFn: () => getSecurityHostPolicy(id as number),
		enabled: id !== "new",
	});
	const securityHostAccess = useQuery({
		queryKey: ["security-host-access", id],
		queryFn: () => getSecurityHostAccess(id as number),
		enabled: id !== "new",
	});
	const { mutate: setProxyHost } = useSetProxyHost();
	const [errorMsg, setErrorMsg] = useState<ReactNode | null>(null);
	const [isSubmitting, setIsSubmitting] = useState(false);

	const onSubmit = async (values: any, { setSubmitting }: any) => {
		if (isSubmitting) return;
		setIsSubmitting(true);
		setErrorMsg(null);

		const {
			hyroviAccessMode,
			hyroviAccessSources,
			hyroviSecurityMode,
			hyroviAutoRateLimitThreshold,
			hyroviAutoRateLimitMinutes,
			hyroviAutoBlockThreshold,
			hyroviAutoBlockMinutes,
			hyroviChallengeMinutes,
			hyroviChallengeDifficulty,
			hyroviEndpointRules,
			...proxyHostValues
		} = values;

		const hyroviSecurityAccess = {
			accessMode: hyroviAccessMode,
			sources:
				hyroviAccessMode === "allowlist" || hyroviAccessMode === "denylist"
					? String(hyroviAccessSources || "")
							.split(/[\n,]+/)
							.map((source) => source.trim())
							.filter(Boolean)
					: [],
		};

		const hyroviSecurityPolicy: SecurityHostPolicy | null | undefined =
			hyroviSecurityMode === "inherit"
				? id === "new"
					? undefined
					: null
				: {
						mode: hyroviSecurityMode as SecurityHostMode,
						autoRateLimitThreshold: Number(hyroviAutoRateLimitThreshold),
						autoRateLimitMinutes: Number(hyroviAutoRateLimitMinutes),
						autoBlockThreshold: Number(hyroviAutoBlockThreshold),
						autoBlockMinutes: Number(hyroviAutoBlockMinutes),
						challengeMinutes: Number(hyroviChallengeMinutes),
						challengeDifficulty: Number(hyroviChallengeDifficulty),
						endpointRules: (Array.isArray(hyroviEndpointRules) ? hyroviEndpointRules : [])
							.map((rule: any) => ({
								pathPrefix: String(rule?.pathPrefix || "").trim(),
								mode: rule?.mode as SecurityHostMode,
							}))
							.filter((rule: any) => rule.pathPrefix),
					};

		const payload: ProxyHostMutationInput = {
			id: id === "new" ? undefined : id,
			...proxyHostValues,
			hyroviSecurityPolicy,
			hyroviSecurityAccess,
		} as ProxyHostMutationInput;

		setProxyHost(payload, {
			onError: (err: any) => setErrorMsg(<T id={err.message} />),
			onSuccess: () => {
				showObjectSuccess("proxy-host", "saved");
				remove();
			},
			onSettled: () => {
				setIsSubmitting(false);
				setSubmitting(false);
			},
		});
	};

	const securityIsLoading =
		securityDefaults.isLoading || (id !== "new" && (securityHostPolicy.isLoading || securityHostAccess.isLoading));
	const securityError =
		securityDefaults.error || (id !== "new" ? securityHostPolicy.error || securityHostAccess.error : null);
	const effectiveSecurity = securityHostPolicy.data?.policy ?? securityHostPolicy.data?.effective ?? securityDefaults.data;

	return (
		<Modal show={visible} onHide={remove}>
			{!isLoading && !securityIsLoading && (error || userError || securityError) && (
				<Alert variant="danger" className="m-3">
					{error?.message || userError?.message || securityError?.message || "Unknown error"}
				</Alert>
			)}
			{(isLoading || userIsLoading || securityIsLoading) && <Loading noLogo />}
			{!isLoading && !userIsLoading && !securityIsLoading && !securityError && data && currentUser && securityDefaults.data && (
				<Formik
					initialValues={
						{
							// Details tab
							domainNames: data?.domainNames || [],
							forwardScheme: data?.forwardScheme || "http",
							forwardHost: data?.forwardHost || "",
							forwardPort: data?.forwardPort || undefined,
							accessListId: data?.accessListId || 0,
							cachingEnabled: data?.cachingEnabled || false,
							blockExploits: data?.blockExploits || false,
							allowWebsocketUpgrade: data?.allowWebsocketUpgrade || false,
							// Locations tab
							locations: data?.locations || [],
							// SSL tab
							certificateId: data?.certificateId || 0,
							sslForced: data?.sslForced || false,
							http2Support: data?.http2Support || false,
							hstsEnabled: data?.hstsEnabled || false,
							hstsSubdomains: data?.hstsSubdomains || false,
							trustForwardedProto: data?.trustForwardedProto || false,
							// HYROVI Sec tab
							hyroviAccessMode: securityHostAccess.data?.accessMode ?? "inherit",
							hyroviAccessSources: (securityHostAccess.data?.sources ?? []).join("\n"),
							hyroviSecurityMode: securityHostPolicy.data?.policy?.mode ?? "inherit",
							hyroviAutoRateLimitThreshold: effectiveSecurity?.autoRateLimitThreshold ?? 50,
							hyroviAutoRateLimitMinutes: effectiveSecurity?.autoRateLimitMinutes ?? 10,
							hyroviAutoBlockThreshold: effectiveSecurity?.autoBlockThreshold ?? 95,
							hyroviAutoBlockMinutes: effectiveSecurity?.autoBlockMinutes ?? 60,
							hyroviChallengeMinutes: effectiveSecurity?.challengeMinutes ?? 10,
							hyroviChallengeDifficulty: effectiveSecurity?.challengeDifficulty ?? 14,
							hyroviEndpointRules: securityHostPolicy.data?.policy?.endpointRules ?? [],
							// Advanced tab
							advancedConfig: data?.advancedConfig || "",
							meta: data?.meta || {},
						} as any
					}
					onSubmit={onSubmit}
				>
					{({ values }: any) => (
						<Form>
							<Modal.Header closeButton>
								<Modal.Title>
									<T id={data?.id ? "object.edit" : "object.add"} tData={{ object: "proxy-host" }} />
								</Modal.Title>
							</Modal.Header>
							<Modal.Body className="p-0">
								<Alert variant="danger" show={!!errorMsg} onClose={() => setErrorMsg(null)} dismissible>
									{errorMsg}
								</Alert>
								<div className="card m-0 border-0">
									<div className="card-header">
										<ul className="nav nav-tabs card-header-tabs" data-bs-toggle="tabs">
											<li className="nav-item" role="presentation">
												<a
													href="#tab-details"
													className="nav-link active"
													data-bs-toggle="tab"
													aria-selected="true"
													role="tab"
												>
													<T id="column.details" />
												</a>
											</li>
											<li className="nav-item" role="presentation">
												<a
													href="#tab-locations"
													className="nav-link"
													data-bs-toggle="tab"
													aria-selected="false"
													tabIndex={-1}
													role="tab"
												>
													<T id="column.custom-locations" />
												</a>
											</li>
											<li className="nav-item" role="presentation">
												<a
													href="#tab-ssl"
													className="nav-link"
													data-bs-toggle="tab"
													aria-selected="false"
													tabIndex={-1}
													role="tab"
												>
													<T id="column.ssl" />
												</a>
											</li>
											<li className="nav-item" role="presentation">
								<a
									href="#tab-hyrovi-security"
									className="nav-link"
									data-bs-toggle="tab"
									aria-selected="false"
									tabIndex={-1}
									role="tab"
								>
									<IconShield size={18} className="me-1" />
									HYROVI Sec
								</a>
							</li>
							<li className="nav-item ms-auto" role="presentation">
												<a
													href="#tab-advanced"
													className="nav-link"
													title="Settings"
													data-bs-toggle="tab"
													aria-selected="false"
													tabIndex={-1}
													role="tab"
												>
													<IconSettings size={20} />
												</a>
											</li>
										</ul>
									</div>
									<div className="card-body">
										<div className="tab-content">
											<div className="tab-pane active show" id="tab-details" role="tabpanel">
												<DomainNamesField isWildcardPermitted dnsProviderWildcardSupported />
												<div className="row">
													<div className="col-md-3">
														<Field name="forwardScheme">
															{({ field, form }: any) => (
																<div className="mb-3">
																	<label
																		className="form-label"
																		htmlFor="forwardScheme"
																	>
																		<T id="host.forward-scheme" />
																	</label>
																	<select
																		id="forwardScheme"
																		className={`form-control ${form.errors.forwardScheme && form.touched.forwardScheme ? "is-invalid" : ""}`}
																		required
																		{...field}
																	>
																		<option value="http">http</option>
																		<option value="https">https</option>
																	</select>
																	{form.errors.forwardScheme ? (
																		<div className="invalid-feedback">
																			{form.errors.forwardScheme &&
																			form.touched.forwardScheme
																				? form.errors.forwardScheme
																				: null}
																		</div>
																	) : null}
																</div>
															)}
														</Field>
													</div>
													<div className="col-md-6">
														<Field name="forwardHost" validate={validateString(1, 255)}>
															{({ field, form }: any) => (
																<div className="mb-3">
																	<label className="form-label" htmlFor="forwardHost">
																		<T id="proxy-host.forward-host" />
																	</label>
																	<input
																		id="forwardHost"
																		type="text"
																		className={`form-control ${form.errors.forwardHost && form.touched.forwardHost ? "is-invalid" : ""}`}
																		required
																		placeholder="example.com"
																		{...field}
																	/>
																	{form.errors.forwardHost ? (
																		<div className="invalid-feedback">
																			{form.errors.forwardHost &&
																			form.touched.forwardHost
																				? form.errors.forwardHost
																				: null}
																		</div>
																	) : null}
																</div>
															)}
														</Field>
													</div>
													<div className="col-md-3">
														<Field name="forwardPort" validate={validateNumber(1, 65535)}>
															{({ field, form }: any) => (
																<div className="mb-3">
																	<label className="form-label" htmlFor="forwardPort">
																		<T id="host.forward-port" />
																	</label>
																	<input
																		id="forwardPort"
																		type="number"
																		min={1}
																		max={65535}
																		className={`form-control ${form.errors.forwardPort && form.touched.forwardPort ? "is-invalid" : ""}`}
																		required
																		placeholder="eg: 8081"
																		{...field}
																	/>
																	{form.errors.forwardPort ? (
																		<div className="invalid-feedback">
																			{form.errors.forwardPort &&
																			form.touched.forwardPort
																				? form.errors.forwardPort
																				: null}
																		</div>
																	) : null}
																</div>
															)}
														</Field>
													</div>
												</div>
												<AccessField />
												<div className="my-3">
													<h4 className="py-2">
														<T id="options" />
													</h4>
													<div className="divide-y">
														<div>
															<label className="row" htmlFor="cachingEnabled">
																<span className="col">
																	<T id="host.flags.cache-assets" />
																</span>
																<span className="col-auto">
																	<Field name="cachingEnabled" type="checkbox">
																		{({ field }: any) => (
																			<label className="form-check form-check-single form-switch">
																				<input
																					{...field}
																					id="cachingEnabled"
																					className={cn("form-check-input", {
																						"bg-lime": field.checked,
																					})}
																					type="checkbox"
																				/>
																			</label>
																		)}
																	</Field>
																</span>
															</label>
														</div>
														<div>
															<label className="row" htmlFor="blockExploits">
																<span className="col">
																	<T id="host.flags.block-exploits" />
																</span>
																<span className="col-auto">
																	<Field name="blockExploits" type="checkbox">
																		{({ field }: any) => (
																			<label className="form-check form-check-single form-switch">
																				<input
																					{...field}
																					id="blockExploits"
																					className={cn("form-check-input", {
																						"bg-lime": field.checked,
																					})}
																					type="checkbox"
																				/>
																			</label>
																		)}
																	</Field>
																</span>
															</label>
														</div>
														<div>
															<label className="row" htmlFor="allowWebsocketUpgrade">
																<span className="col">
																	<T id="host.flags.websockets-upgrade" />
																</span>
																<span className="col-auto">
																	<Field name="allowWebsocketUpgrade" type="checkbox">
																		{({ field }: any) => (
																			<label className="form-check form-check-single form-switch">
																				<input
																					{...field}
																					id="allowWebsocketUpgrade"
																					className={cn("form-check-input", {
																						"bg-lime": field.checked,
																					})}
																					type="checkbox"
																				/>
																			</label>
																		)}
																	</Field>
																</span>
															</label>
														</div>
													</div>
												</div>
											</div>
											<div className="tab-pane" id="tab-locations" role="tabpanel">
												<LocationsFields initialValues={data?.locations || []} />
											</div>
											<div className="tab-pane" id="tab-ssl" role="tabpanel">
												<SSLCertificateField
													name="certificateId"
													label="ssl-certificate"
													allowNew
												/>
												<SSLOptionsFields color="bg-lime" forProxyHost={true} />
											</div>
											<div className="tab-pane" id="tab-hyrovi-security" role="tabpanel">
								<div className="border-bottom pb-3 mb-3">
									<div className="d-flex align-items-center justify-content-between gap-3 mb-2">
										<div>
											<h4 className="mb-1">IP access control</h4>
											<div className="text-secondary small">
												Restrict this site by real client IP. A host override takes priority over its group.
											</div>
										</div>
										{id !== "new" && securityHostAccess.data ? (
											<span className="badge bg-secondary-lt">
												Effective: {securityHostAccess.data.effectiveAccessMode}
											</span>
										) : null}
									</div>

									<div className="row g-3">
										<div className="col-md-5">
											<label className="form-label" htmlFor="hyroviAccessMode">
												Access policy
											</label>
											<Field as="select" id="hyroviAccessMode" name="hyroviAccessMode" className="form-select">
												<option value="inherit">Inherit group / default</option>
												<option value="open">Open to all IPs</option>
												<option value="allowlist">Allow only listed IPs</option>
												<option value="denylist">Block listed IPs</option>
											</Field>
										</div>
										{values.hyroviAccessMode === "allowlist" || values.hyroviAccessMode === "denylist" ? (
											<div className="col-md-7">
												<label className="form-label" htmlFor="hyroviAccessSources">
													IP addresses / CIDR ranges
												</label>
												<Field
													as="textarea"
													id="hyroviAccessSources"
													name="hyroviAccessSources"
													className="form-control font-monospace"
													rows={4}
													placeholder={"192.168.178.0/24\n100.64.0.0/10\n203.0.113.42"}
												/>
												<div className="form-hint">One entry per line or comma-separated. IPv4 and IPv6 CIDR are supported.</div>
											</div>
										) : null}
									</div>

									{values.hyroviAccessMode === "inherit" && id !== "new" && securityHostAccess.data ? (
										<div className="alert alert-secondary py-2 mt-3 mb-0">
											{securityHostAccess.data.group ? (
												<>
													Inherited from group <strong>{securityHostAccess.data.group.name}</strong>:{" "}
													<strong>{securityHostAccess.data.effectiveAccessMode}</strong>
													{securityHostAccess.data.effectiveSources.length
														? ` · ${securityHostAccess.data.effectiveSources.length} IP/CIDR rules`
														: ""}
												</>
											) : (
												<>No group access rule applies. Effective access is <strong>open</strong>.</>
											)}
										</div>
									) : null}

									{values.hyroviAccessMode === "open" && securityHostAccess.data?.group ? (
										<div className="alert alert-warning py-2 mt-3 mb-0">
											This host explicitly overrides the <strong>{securityHostAccess.data.group.name}</strong> group access restriction and remains open.
										</div>
									) : null}
								</div>

								<div className="mb-3">
									<label className="form-label" htmlFor="hyroviSecurityMode">
										Protection mode
									</label>
									<Field
										as="select"
										id="hyroviSecurityMode"
										name="hyroviSecurityMode"
										className="form-select"
									>
										<option value="inherit">Inherit global policy</option>
										<option value="off">Off</option>
										<option value="observe">Observe</option>
										<option value="protect">Protect</option>
										<option value="strict">Strict</option>
									</Field>
									<div className="form-hint mt-1">
										Off excludes this host from HYROVI Sec analysis. Observe records threats without automatic response.
										 Protect and Strict can automatically rate-limit or block high-confidence attacks.
									</div>
								</div>

								{!securityDefaults.data.enforcementEnabled ? (
									<Alert variant="warning">
										Global automatic response is currently in Observe mode. Protect/Strict settings are saved, but enforcement stays disabled until the global HYROVI Sec master switch is enabled.
									</Alert>
								) : null}

								<div className="row">
									<div className="col-md-6">
										<div className="mb-3">
											<label className="form-label" htmlFor="hyroviAutoRateLimitThreshold">
												Soft restriction risk
											</label>
											<Field
												id="hyroviAutoRateLimitThreshold"
												name="hyroviAutoRateLimitThreshold"
												type="number"
												min={40}
												max={100}
												className="form-control"
												disabled={values.hyroviSecurityMode === "inherit"}
											/>
										</div>
									</div>
									<div className="col-md-6">
										<div className="mb-3">
											<label className="form-label" htmlFor="hyroviAutoRateLimitMinutes">
												Soft restriction minutes
											</label>
											<Field
												id="hyroviAutoRateLimitMinutes"
												name="hyroviAutoRateLimitMinutes"
												type="number"
												min={1}
												max={43200}
												className="form-control"
												disabled={values.hyroviSecurityMode === "inherit"}
											/>
										</div>
									</div>
									<div className="col-md-6">
										<div className="mb-3">
											<label className="form-label" htmlFor="hyroviAutoBlockThreshold">
												Hard block risk
											</label>
											<Field
												id="hyroviAutoBlockThreshold"
												name="hyroviAutoBlockThreshold"
												type="number"
												min={80}
												max={100}
												className="form-control"
												disabled={values.hyroviSecurityMode === "inherit"}
											/>
										</div>
									</div>
									<div className="col-md-6">
										<div className="mb-3">
											<label className="form-label" htmlFor="hyroviAutoBlockMinutes">
												Hard block minutes
											</label>
											<Field
												id="hyroviAutoBlockMinutes"
												name="hyroviAutoBlockMinutes"
												type="number"
												min={1}
												max={43200}
												className="form-control"
												disabled={values.hyroviSecurityMode === "inherit"}
											/>
										</div>
									</div>
									<div className="col-md-6">
										<div className="mb-3">
											<label className="form-label" htmlFor="hyroviChallengeMinutes">Challenge minutes</label>
											<Field
												id="hyroviChallengeMinutes"
												name="hyroviChallengeMinutes"
												type="number"
												min={1}
												max={120}
												className="form-control"
												disabled={values.hyroviSecurityMode === "inherit"}
											/>
										</div>
									</div>
									<div className="col-md-6">
										<div className="mb-3">
											<label className="form-label" htmlFor="hyroviChallengeDifficulty">Challenge PoW bits</label>
											<Field
												id="hyroviChallengeDifficulty"
												name="hyroviChallengeDifficulty"
												type="number"
												min={10}
												max={22}
												className="form-control"
												disabled={values.hyroviSecurityMode === "inherit"}
											/>
										</div>
									</div>
								</div>

								<div className="border-top pt-3 mt-2">
									<div className="d-flex align-items-center justify-content-between mb-2">
										<div>
											<h4 className="mb-1">Endpoint rules</h4>
											<div className="text-secondary small">
												Longest matching path prefix wins. Example: <code>/api/admin</code> can be Strict while the rest of the host stays Protect.
											</div>
										</div>
									</div>
									{values.hyroviSecurityMode === "inherit" ? (
										<div className="text-secondary small mb-3">
											Choose an explicit host mode before adding endpoint rules. This keeps endpoint behavior deterministic when the global policy changes.
										</div>
									) : (
										<FieldArray name="hyroviEndpointRules">
											{({ push, remove }) => (
												<>
													{(values.hyroviEndpointRules ?? []).map((rule: any, index: number) => (
														<div className="row g-2 align-items-end mb-2" key={`${index}-${rule.pathPrefix || "new"}`}>
															<div className="col-md-7">
																<label className="form-label" htmlFor={`hyroviEndpointPath-${index}`}>Path prefix</label>
																<Field
																	id={`hyroviEndpointPath-${index}`}
																	name={`hyroviEndpointRules.${index}.pathPrefix`}
																	className="form-control font-monospace"
																	placeholder="/api/admin"
																/>
															</div>
															<div className="col-md-3">
																<label className="form-label" htmlFor={`hyroviEndpointMode-${index}`}>Mode</label>
																<Field
																	as="select"
																	id={`hyroviEndpointMode-${index}`}
																	name={`hyroviEndpointRules.${index}.mode`}
																	className="form-select"
																>
																	<option value="off">Off</option>
																	<option value="observe">Observe</option>
																	<option value="protect">Protect</option>
																	<option value="strict">Strict</option>
																</Field>
															</div>
															<div className="col-md-2 d-grid">
																<Button className="btn-outline-danger" type="button" onClick={() => remove(index)}>
																	Remove
																</Button>
															</div>
														</div>
													))}
													{(values.hyroviEndpointRules?.length ?? 0) < 50 ? (
														<Button
															className="btn-outline-primary"
															type="button"
															onClick={() => push({ pathPrefix: "", mode: "strict" })}
														>
															Add endpoint rule
														</Button>
													) : null}
												</>
											)}
										</FieldArray>
									)}
								</div>

								{values.hyroviSecurityMode === "inherit" ? (
									<div className="text-secondary small">
										Current inherited values: soft risk {effectiveSecurity?.autoRateLimitThreshold ?? 50} for{" "}
										{effectiveSecurity?.autoRateLimitMinutes ?? 10} minutes; hard risk{" "}
										{effectiveSecurity?.autoBlockThreshold ?? 95} for {effectiveSecurity?.autoBlockMinutes ?? 60} minutes; challenge{" "}
										{effectiveSecurity?.challengeMinutes ?? 10} minutes at {effectiveSecurity?.challengeDifficulty ?? 14} PoW bits.
									</div>
								) : null}
							</div>
							<div className="tab-pane" id="tab-advanced" role="tabpanel">
												<NginxConfigField />
											</div>
										</div>
									</div>
								</div>
							</Modal.Body>
							<Modal.Footer>
								<Button data-bs-dismiss="modal" onClick={remove} disabled={isSubmitting}>
									<T id="cancel" />
								</Button>
								<HasPermission section={PROXY_HOSTS} permission={MANAGE} hideError>
									<Button
										type="submit"
										actionType="primary"
										className="ms-auto bg-lime"
										data-bs-dismiss="modal"
										isLoading={isSubmitting}
										disabled={isSubmitting}
									>
										<T id="save" />
									</Button>
								</HasPermission>
							</Modal.Footer>
						</Form>
					)}
				</Formik>
			)}
		</Modal>
	);
});

export { showProxyHostModal };
