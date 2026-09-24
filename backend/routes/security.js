import express from "express";
import internalSecurity from "../internal/security.js";
import internalSecurityAppEvents from "../internal/security_app_events.js";
import jwtdecode from "../lib/express/jwt-decode.js";
import { debug, express as logger } from "../logger.js";

const router = express.Router({
	caseSensitive: true,
	strict: true,
	mergeParams: true,
});

router.post("/app-events/ingest", async (req, res, next) => {
	try {
		if (!(await internalSecurityAppEvents.getStatus()).configured) {
			res.status(503).send({
				error: {
					code: 503,
					message: "HYROVI Sec app-event ingest is disabled",
				},
			});
			return;
		}
		const event = await internalSecurityAppEvents.ingest({
			authorization: req.headers.authorization,
			body: req.body,
			sourceIp: req.ip,
		});
		res.status(202).send({ accepted: true, id: event.id, timestamp: event.timestamp });
	} catch (err) {
		debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
		next(err);
	}
});

router.use(jwtdecode());

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
