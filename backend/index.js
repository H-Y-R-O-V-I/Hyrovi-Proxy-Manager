#!/usr/bin/env node

import app from "./app.js";
import internalCertificate from "./internal/certificate.js";
import internalControlPlaneNodes from "./internal/control_plane_nodes.js";
import internalControlPlaneTelemetry from "./internal/control_plane_telemetry.js";
import internalIpRanges from "./internal/ip_ranges.js";
import internalSecurity from "./internal/security.js";
import { global as logger } from "./logger.js";
import { migrateUp } from "./migrate.js";
import { getCompiledSchema } from "./schema/index.js";
import setup from "./setup.js";

const IP_RANGES_FETCH_ENABLED = process.env.IP_RANGES_FETCH_ENABLED !== "false";

async function appStart() {
	return migrateUp()
		.then(setup)
		.then(getCompiledSchema)
		.then(() => {
			if (!IP_RANGES_FETCH_ENABLED) {
				logger.info("IP Ranges fetch is disabled by environment variable");
				return;
			}
			logger.info("IP Ranges fetch is enabled");
			return internalIpRanges.fetch().catch((err) => {
				logger.error("IP Ranges fetch failed, continuing anyway:", err.message);
			});
		})
		.then(() =>
			internalSecurity.prepare().catch((err) => {
				logger.error("HYROVI Sec instrumentation failed; proxy manager will continue:", err.message);
			}),
		)
		.then(() =>
			Promise.all([internalControlPlaneNodes.prepare(), internalControlPlaneTelemetry.prepare()]).catch((err) => {
				logger.error("HYROVI control-plane state failed to initialize; local proxy will continue:", err.message);
			}),
		)
		.then(() => {
			internalCertificate.initTimer();
			internalIpRanges.initTimer();
			internalSecurity.initTimer();

			const server = app.listen(3000, () => {
				logger.info(`Backend PID ${process.pid} listening on port 3000 ...`);

				process.on("SIGTERM", () => {
					logger.info(`PID ${process.pid} received SIGTERM`);
					server.close(() => {
						logger.info("Stopping.");
						process.exit(0);
					});
				});
			});
		})
		.catch((err) => {
			logger.error(`Startup Error: ${err.message}`, err);
			setTimeout(appStart, 1000);
		});
}

try {
	appStart();
} catch (err) {
	logger.fatal(err);
	process.exit(1);
}
