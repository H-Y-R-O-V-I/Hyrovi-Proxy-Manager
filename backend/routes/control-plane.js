import express from "express";
import internalControlPlaneNodes from "../internal/control_plane_nodes.js";
import internalControlPlaneProvisioning from "../internal/control_plane_provisioning.js";
import internalControlPlaneTelemetry from "../internal/control_plane_telemetry.js";
import errs from "../lib/error.js";
import jwtdecode from "../lib/express/jwt-decode.js";
import apiValidator from "../lib/validator/api.js";
import { getValidationSchema } from "../schema/index.js";
import { debug, express as logger } from "../logger.js";

const router = express.Router({
	caseSensitive: true,
	strict: true,
	mergeParams: true,
});

router.post("/agent/nodes/:node_id/heartbeat", async (req, res, next) => {
	try {
		const result = await internalControlPlaneNodes.heartbeat(
			req.params.node_id,
			req.headers.authorization,
			req.body || {},
		);
		res.status(200).send(result);
	} catch (err) {
		debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
		next(err);
	}
});

router.post("/agent/nodes/:node_id/telemetry", async (req, res, next) => {
	try {
		await internalControlPlaneNodes.authenticateNode(req.params.node_id, req.headers.authorization);
		const result = await internalControlPlaneTelemetry.ingest(req.params.node_id, req.body || {});
		res.set("Cache-Control", "no-store");
		res.status(202).send(result);
	} catch (err) {
		debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
		next(err);
	}
});

router.get("/agent/local/provisioning/next", async (req, res, next) => {
	try {
		await internalControlPlaneProvisioning.verifyLocalToken(req.headers.authorization);
		const job = await internalControlPlaneProvisioning.claimNext("local");
		if (!job) return res.sendStatus(204);
		res.set("Cache-Control", "no-store");
		return res.status(200).send(job);
	} catch (err) {
		debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
		next(err);
	}
});

router.post("/agent/local/provisioning/:job_id/result", async (req, res, next) => {
	try {
		await internalControlPlaneProvisioning.verifyLocalToken(req.headers.authorization);
		res.status(200).send(await internalControlPlaneProvisioning.complete("local", req.params.job_id, req.body || {}));
	} catch (err) {
		debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
		next(err);
	}
});

router.get("/agent/nodes/:node_id/provisioning/next", async (req, res, next) => {
	try {
		await internalControlPlaneNodes.authenticateNode(req.params.node_id, req.headers.authorization);
		const job = await internalControlPlaneProvisioning.claimNext(req.params.node_id);
		if (!job) return res.sendStatus(204);
		res.set("Cache-Control", "no-store");
		return res.status(200).send(job);
	} catch (err) {
		debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
		next(err);
	}
});

router.post("/agent/nodes/:node_id/provisioning/:job_id/result", async (req, res, next) => {
	try {
		await internalControlPlaneNodes.authenticateNode(req.params.node_id, req.headers.authorization);
		res.status(200).send(await internalControlPlaneProvisioning.complete(req.params.node_id, req.params.job_id, req.body || {}));
	} catch (err) {
		debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
		next(err);
	}
});

router.use(jwtdecode());

router
	.route("/nodes")
	.get(async (_req, res, next) => {
		try {
			await res.locals.access.can("proxy_hosts:list");
			res.status(200).send(await internalControlPlaneNodes.listNodes());
		} catch (err) {
			next(err);
		}
	})
	.post(async (req, res, next) => {
		try {
			await res.locals.access.can("users:list");
			res.status(201).send(await internalControlPlaneNodes.createNode(req.body || {}));
		} catch (err) {
			next(err);
		}
	});

router
	.route("/nodes/:node_id")
	.get(async (req, res, next) => {
		try {
			await res.locals.access.can("proxy_hosts:list");
			res.status(200).send(await internalControlPlaneNodes.getNode(req.params.node_id));
		} catch (err) {
			next(err);
		}
	})
	.put(async (req, res, next) => {
		try {
			await res.locals.access.can("users:list");
			res.status(200).send(await internalControlPlaneNodes.updateNode(req.params.node_id, req.body || {}));
		} catch (err) {
			next(err);
		}
	})
	.delete(async (req, res, next) => {
		try {
			await res.locals.access.can("users:list");
			res.status(200).send(await internalControlPlaneNodes.deleteNode(req.params.node_id));
		} catch (err) {
			next(err);
		}
	});

router.post("/nodes/:node_id/rotate-token", async (req, res, next) => {
	try {
		await res.locals.access.can("users:list");
		res.status(200).send(await internalControlPlaneNodes.rotateToken(req.params.node_id));
	} catch (err) {
		next(err);
	}
});

router.post("/provision/proxy-hosts", async (req, res, next) => {
	try {
		await res.locals.access.can("proxy_hosts:create");
		const nodeId = String(req.body?.node_id || "local").trim() || "local";
		const node = await internalControlPlaneNodes.getNode(nodeId);
		if (!node.enabled || node.status === "disabled") throw new errs.ValidationError("Selected node is disabled");
		if (nodeId !== "local" && node.status !== "online") {
			throw new errs.ValidationError(`Selected node is not online: ${node.status}`);
		}
		const proxyHost = await apiValidator(getValidationSchema("/nginx/proxy-hosts", "post"), req.body?.proxy_host);
		const rawPolicy = req.body?.security_policy;
		const securityPolicy = rawPolicy?.mode && rawPolicy.mode !== "inherit" ? {
			mode: rawPolicy.mode,
			autoRateLimitThreshold: rawPolicy.auto_rate_limit_threshold,
			autoRateLimitMinutes: rawPolicy.auto_rate_limit_minutes,
			autoBlockThreshold: rawPolicy.auto_block_threshold,
			autoBlockMinutes: rawPolicy.auto_block_minutes,
			challengeMinutes: rawPolicy.challenge_minutes,
			challengeDifficulty: rawPolicy.challenge_difficulty,
			endpointRules: Array.isArray(rawPolicy.endpoint_rules) ? rawPolicy.endpoint_rules.map((rule) => ({ pathPrefix: rule?.path_prefix, mode: rule?.mode })) : [],
		} : null;
		const rawAccess = req.body?.security_access;
		const securityAccess = rawAccess?.access_mode && rawAccess.access_mode !== "inherit" ? {
			accessMode: rawAccess.access_mode,
			sources: Array.isArray(rawAccess.sources) ? rawAccess.sources : [],
		} : null;
		const job = await internalControlPlaneProvisioning.enqueueProxyHost({
			nodeId,
			proxyHost,
			cloudflareTunnel: req.body?.cloudflare_tunnel !== false,
			securityPolicy,
			securityAccess,
			requestedBy: res.locals.access.token.getUserId(1),
		});
		res.status(202).send(await internalControlPlaneProvisioning.getJob(job.id));
	} catch (err) {
		next(err);
	}
});

router.get("/provision/jobs/:job_id", async (req, res, next) => {
	try {
		await res.locals.access.can("proxy_hosts:list");
		res.set("Cache-Control", "no-store");
		res.status(200).send(await internalControlPlaneProvisioning.getJob(req.params.job_id));
	} catch (err) {
		next(err);
	}
});

export default router;
