import express from "express";
import internalSecurity from "../internal/security.js";
import jwtdecode from "../lib/express/jwt-decode.js";
import { debug, express as logger } from "../logger.js";

const router = express.Router({
	caseSensitive: true,
	strict: true,
	mergeParams: true,
});

router.use(jwtdecode());

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
					trustedSources: req.body?.trusted_sources,
				}),
			);
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
	.put(async (req, res, next) => {
		try {
			res.status(200).send(
				await internalSecurity.updateHostPolicy(res.locals.access, req.params.host_id, {
					mode: req.body?.mode,
					autoRateLimitThreshold: req.body?.auto_rate_limit_threshold,
					autoRateLimitMinutes: req.body?.auto_rate_limit_minutes,
					autoBlockThreshold: req.body?.auto_block_threshold,
					autoBlockMinutes: req.body?.auto_block_minutes,
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
