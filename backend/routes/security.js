import express from "express";
import internalSecurity from "../internal/security.js";
import internalSecurityAppEvents from "../internal/security_app_events.js";
import internalSecurityAlerts from "../internal/security_alerts.js";
import internalSecurityChallenge from "../internal/security_challenge.js";
import internalSecurityDevices from "../internal/security_devices.js";
import internalSecurityDetectionRules from "../internal/security_detection_rules.js";
import jwtdecode from "../lib/express/jwt-decode.js";
import { debug, express as logger } from "../logger.js";

const router = express.Router({
	caseSensitive: true,
	strict: true,
	mergeParams: true,
});

router.post("/app-events/ingest", async (req, res, next) => {
	try {
		const verifiedDevice = await internalSecurityDevices.verifySignedRequest({
			headers: req.headers,
			body: req.body,
		});
		if (!verifiedDevice && !(await internalSecurityAppEvents.getStatus()).configured) {
			res.status(503).send({
				error: {
					code: 503,
					message: "HYROVI Sec app-event ingest requires a configured token or trusted signed device",
				},
			});
			return;
		}
		const event = await internalSecurityAppEvents.ingest({
			authorization: req.headers.authorization,
			body: req.body,
			sourceIp: req.ip,
			verifiedDevice,
		});
		res.status(202).send({
			accepted: true,
			id: event.id,
			timestamp: event.timestamp,
			deviceTrust: event.deviceTrust,
		});
	} catch (err) {
		debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
		next(err);
	}
});

router.all("/challenge/page", async (req, res, next) => {
	try {
		const context = internalSecurityChallenge.proxyContext(req.headers);
		const challenge = await internalSecurityChallenge.getChallengeForIp(context.ip);
		if (!challenge) {
			res.status(404).send({ error: { code: 404, message: "Not Found" } });
			return;
		}

		res.set("Cache-Control", "no-store");
		const wantsHtml = context.accept.includes("text/html");
		if (!wantsHtml) {
			res.set("Retry-After", "3");
			res.status(429).send({ challenge });
			return;
		}

		res.set({
			"Content-Type": "text/html; charset=utf-8",
			"Content-Security-Policy":
				"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'",
			"Referrer-Policy": "no-referrer",
			"X-Content-Type-Options": "nosniff",
		});
		res.status(200).send(internalSecurityChallenge.renderHtml(challenge, context.originalUri));
	} catch (err) {
		debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
		next(err);
	}
});

router.post("/challenge/verify", async (req, res, next) => {
	try {
		const context = internalSecurityChallenge.proxyContext(req.headers);
		const result = await internalSecurityChallenge.verify({
			ip: context.ip,
			id: req.body?.id,
			counter: req.body?.counter,
		});
		res.set("Cache-Control", "no-store");
		res.status(result.verified ? 200 : 400).send(result);
	} catch (err) {
		debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
		next(err);
	}
});

router.get("/integration/alerts", async (req, res, next) => {
	try {
		const status = internalSecurityAlerts.getStatus();
		if (!status.feedConfigured) {
			res.status(503).send({
				error: { code: 503, message: "HYROVI Sec alert feed is disabled" },
			});
			return;
		}
		internalSecurityAlerts.authorizeFeed(req.headers.authorization);
		const alerts = await internalSecurityAlerts.listAlerts({
			limit: req.query.limit,
			status: req.query.status,
			since: req.query.since,
		});
		res.set("Cache-Control", "no-store");
		res.status(200).send({
			generatedAt: new Date().toISOString(),
			alerts,
		});
	} catch (err) {
		debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
		next(err);
	}
});

router.use(jwtdecode());

const detectionRuleInput = (body = {}) => ({
	name: body?.name,
	enabled: body?.enabled,
	score: body?.score,
	response: body?.response,
	...(body?.match
		? {
				match: {
					host: body.match.host,
					pathPrefix: body.match.path_prefix,
					pathContains: body.match.path_contains,
					methods: body.match.methods,
					statuses: body.match.statuses,
					userAgentContains: body.match.user_agent_contains,
				},
			}
		: {}),
});

router
	.route("/detection-rules")
	.get(async (req, res, next) => {
		try {
			await res.locals.access.can("logs:list");
			res.status(200).send(await internalSecurityDetectionRules.listRules());
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	})
	.post(async (req, res, next) => {
		try {
			await res.locals.access.can("users:list");
			res.status(201).send(await internalSecurityDetectionRules.createRule(detectionRuleInput(req.body)));
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

router.get("/detection-rules/export", async (req, res, next) => {
	try {
		await res.locals.access.can("logs:list");
		res.set("Cache-Control", "no-store");
		res.status(200).send(await internalSecurityDetectionRules.exportRules());
	} catch (err) {
		debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
		next(err);
	}
});

router.post("/detection-rules/import", async (req, res, next) => {
	try {
		await res.locals.access.can("users:list");
		res.status(200).send(
			await internalSecurityDetectionRules.importRules({
				version: req.body?.version,
				mode: req.body?.mode,
				rules: Array.isArray(req.body?.rules) ? req.body.rules.map(detectionRuleInput) : req.body?.rules,
			}),
		);
	} catch (err) {
		debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
		next(err);
	}
});

router.get("/detection-rules/analytics", async (req, res, next) => {
	try {
		res.set("Cache-Control", "no-store");
		res.status(200).send(
			await internalSecurity.getDetectionRuleAnalytics(res.locals.access, {
				limit: req.query.limit,
			}),
		);
	} catch (err) {
		debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
		next(err);
	}
});

router.post("/detection-rules/simulate", async (req, res, next) => {
	try {
		res.set("Cache-Control", "no-store");
		res.status(200).send(
			await internalSecurity.getDetectionRuleSimulation(
				res.locals.access,
				detectionRuleInput(req.body),
				{ limit: req.query.limit },
			),
		);
	} catch (err) {
		debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
		next(err);
	}
});

router
	.route("/detection-rules/:rule_id")
	.put(async (req, res, next) => {
		try {
			await res.locals.access.can("users:list");
			res.status(200).send(
				await internalSecurityDetectionRules.updateRule(req.params.rule_id, detectionRuleInput(req.body)),
			);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	})
	.delete(async (req, res, next) => {
		try {
			await res.locals.access.can("users:list");
			res.status(200).send(await internalSecurityDetectionRules.deleteRule(req.params.rule_id));
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

router.get("/alerts", async (req, res, next) => {
	try {
		await res.locals.access.can("logs:list");
		const [alerts, status] = await Promise.all([
			internalSecurityAlerts.listAlerts({
				limit: req.query.limit,
				status: req.query.status,
				since: req.query.since,
			}),
			Promise.resolve(internalSecurityAlerts.getStatus()),
		]);
		res.status(200).send({ ...status, alerts });
	} catch (err) {
		debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
		next(err);
	}
});

router.post("/alerts/:alert_id/acknowledge", async (req, res, next) => {
	try {
		await res.locals.access.can("users:list");
		res.status(200).send(await internalSecurityAlerts.acknowledge(req.params.alert_id));
	} catch (err) {
		debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
		next(err);
	}
});

router.get("/app-events", async (req, res, next) => {
	try {
		await res.locals.access.can("logs:list");
		const [status, events] = await Promise.all([
			internalSecurityAppEvents.getStatus(),
			internalSecurityAppEvents.listEvents(req.query.limit),
		]);
		res.status(200).send({ ...status, events });
	} catch (err) {
		debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
		next(err);
	}
});

router
	.route("/trusted-devices")
	.get(async (req, res, next) => {
		try {
			await res.locals.access.can("logs:list");
			res.status(200).send(await internalSecurityDevices.listDevices());
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	})
	.post(async (req, res, next) => {
		try {
			await res.locals.access.can("users:list");
			res.status(201).send(
				await internalSecurityDevices.registerDevice({
					deviceId: req.body?.device_id,
					name: req.body?.name,
					publicKey: req.body?.public_key,
					allowedApps: req.body?.allowed_apps,
				}),
			);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

router.delete("/trusted-devices/:device_id", async (req, res, next) => {
	try {
		await res.locals.access.can("users:list");
		res.status(200).send(await internalSecurityDevices.revokeDevice(req.params.device_id));
	} catch (err) {
		debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
		next(err);
	}
});

router.post("/trusted-devices/:device_id/reset-sequence", async (req, res, next) => {
	try {
		await res.locals.access.can("users:list");
		res.status(200).send(await internalSecurityDevices.resetSequence(req.params.device_id));
	} catch (err) {
		debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
		next(err);
	}
});

router.get("/diagnostics", async (req, res, next) => {
	try {
		res.set("Cache-Control", "no-store");
		res.status(200).send(await internalSecurity.getDiagnostics(res.locals.access));
	} catch (err) {
		debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
		next(err);
	}
});

router.get("/overview", async (req, res, next) => {
	try {
		const data = await internalSecurity.getOverview(res.locals.access);
		res.status(200).send(data);
	} catch (err) {
		debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
		next(err);
	}
});

router.get("/events", async (req, res, next) => {
	try {
		const data = await internalSecurity.getEvents(res.locals.access, {
			limit: req.query.limit,
			minRisk: req.query.min_risk,
		});
		res.status(200).send(data);
	} catch (err) {
		debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
		next(err);
	}
});

router.get("/events/:request_id", async (req, res, next) => {
	try {
		res.status(200).send(await internalSecurity.getEventDetail(res.locals.access, req.params.request_id));
	} catch (err) {
		debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
		next(err);
	}
});

router.get("/attack-sessions/:session_id", async (req, res, next) => {
	try {
		res.status(200).send(await internalSecurity.getAttackSession(res.locals.access, req.params.session_id));
	} catch (err) {
		debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
		next(err);
	}
});

router
	.route("/policy")
	.get(async (req, res, next) => {
		try {
			res.status(200).send(await internalSecurity.getPolicy(res.locals.access));
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	})
	.put(async (req, res, next) => {
		try {
			res.status(200).send(
				await internalSecurity.updatePolicy(res.locals.access, {
					autoBlockEnabled: req.body?.auto_block_enabled,
					autoRateLimitThreshold: req.body?.auto_rate_limit_threshold,
					autoRateLimitMinutes: req.body?.auto_rate_limit_minutes,
					autoBlockThreshold: req.body?.auto_block_threshold,
					autoBlockMinutes: req.body?.auto_block_minutes,
					autoEscalationHits: req.body?.auto_escalation_hits,
					autoEscalationWindowMinutes: req.body?.auto_escalation_window_minutes,
					autoEscalationCooldownSeconds: req.body?.auto_escalation_cooldown_seconds,
					eventRetentionDays: req.body?.event_retention_days,
					eventArchiveMinRisk: req.body?.event_archive_min_risk,
					trustedSources: req.body?.trusted_sources,
				}),
			);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

router.get("/host-policy-defaults", async (req, res, next) => {
	try {
		res.status(200).send(await internalSecurity.getHostPolicyDefaults(res.locals.access));
	} catch (err) {
		debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
		next(err);
	}
});

router.get("/host-policies", async (req, res, next) => {
	try {
		res.status(200).send(await internalSecurity.listHostPolicies(res.locals.access));
	} catch (err) {
		debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
		next(err);
	}
});

router
	.route("/host-policies/:host_id")
	.get(async (req, res, next) => {
		try {
			res.status(200).send(await internalSecurity.getHostPolicy(res.locals.access, req.params.host_id));
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	})
	.put(async (req, res, next) => {
		try {
			res.status(200).send(
				await internalSecurity.updateHostPolicy(res.locals.access, req.params.host_id, {
					mode: req.body?.mode,
					autoRateLimitThreshold: req.body?.auto_rate_limit_threshold,
					autoRateLimitMinutes: req.body?.auto_rate_limit_minutes,
					autoBlockThreshold: req.body?.auto_block_threshold,
					autoBlockMinutes: req.body?.auto_block_minutes,
					challengeMinutes: req.body?.challenge_minutes,
					challengeDifficulty: req.body?.challenge_difficulty,
					endpointRules: Array.isArray(req.body?.endpoint_rules)
						? req.body.endpoint_rules.map((rule) => ({
								pathPrefix: rule?.path_prefix,
								mode: rule?.mode,
							}))
						: req.body?.endpoint_rules,
				}),
			);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	})
	.delete(async (req, res, next) => {
		try {
			res.status(200).send(await internalSecurity.deleteHostPolicy(res.locals.access, req.params.host_id));
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});
router
	.route("/challenges")
	.get(async (req, res, next) => {
		try {
			res.status(200).send(await internalSecurity.listChallenges(res.locals.access));
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

router.delete("/challenges/:id", async (req, res, next) => {
	try {
		res.status(200).send(await internalSecurity.removeChallenge(res.locals.access, req.params.id));
	} catch (err) {
		debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
		next(err);
	}
});

router
	.route("/rate-limits")
	.get(async (req, res, next) => {
		try {
			res.status(200).send(await internalSecurity.listRateLimits(res.locals.access));
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	})
	.post(async (req, res, next) => {
		try {
			res.status(201).send(
				await internalSecurity.rateLimitIp(res.locals.access, {
					ip: req.body?.ip,
					durationMinutes: req.body?.duration_minutes,
					reason: req.body?.reason,
					source: "manual",
				}),
			);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

router.delete("/rate-limits/:id", async (req, res, next) => {
	try {
		res.status(200).send(await internalSecurity.unrateLimitIp(res.locals.access, req.params.id));
	} catch (err) {
		debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
		next(err);
	}
});
router
	.route("/blocks")
	.get(async (req, res, next) => {
		try {
			res.status(200).send(await internalSecurity.listBlocks(res.locals.access));
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	})
	.post(async (req, res, next) => {
		try {
			const block = await internalSecurity.blockIp(res.locals.access, {
				ip: req.body?.ip,
				durationMinutes: req.body?.duration_minutes,
				reason: req.body?.reason,
				source: req.body?.source,
			});
			res.status(201).send(block);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

router.delete("/blocks/:block_id", async (req, res, next) => {
	try {
		res.status(200).send(await internalSecurity.unblockIp(res.locals.access, req.params.block_id));
	} catch (err) {
		debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
		next(err);
	}
});

export default router;
