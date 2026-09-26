import express from "express";
import internalControlPlaneNodes from "../internal/control_plane_nodes.js";
import internalControlPlaneTelemetry from "../internal/control_plane_telemetry.js";
import jwtdecode from "../lib/express/jwt-decode.js";
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

export default router;
