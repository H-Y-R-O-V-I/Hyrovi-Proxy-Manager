import https from "node:https";
import { ProxyAgent } from "proxy-agent";
import { debug, remoteVersion as logger } from "../logger.js";
import pjson from "../package.json" with { type: "json" };

const VERSION_URL = String(process.env.HYROVI_UPDATE_URL || "").trim();

const getCurrentVersion = () => {
	const version = pjson.version.split("-").shift().split(".");
	return `v${version[0]}.${version[1]}.${version[2]}`;
};

const internalRemoteVersion = {
	cache_timeout: 1000 * 60 * 15,
	last_result: null,
	last_fetch_time: null,

	/**
	 * Fetch HYROVI update information when an explicit update feed is configured.
	 * Forks must not compare themselves against upstream Nginx Proxy Manager releases.
	 *
	 * @return {Promise<{current: string, latest: string|null, update_available: boolean}>}
	 */
	get: async () => {
		const currentVersion = getCurrentVersion();
		if (!VERSION_URL) {
			return {
				current: currentVersion,
				latest: null,
				update_available: false,
			};
		}

		if (
			!internalRemoteVersion.last_result ||
			!internalRemoteVersion.last_fetch_time ||
			Date.now() - internalRemoteVersion.last_fetch_time > internalRemoteVersion.cache_timeout
		) {
			const raw = await internalRemoteVersion.fetchUrl(VERSION_URL);
			const data = JSON.parse(raw);
			internalRemoteVersion.last_result = data;
			internalRemoteVersion.last_fetch_time = Date.now();
		} else {
			debug(logger, "Using cached HYROVI remote version result");
		}

		const latestVersion = String(internalRemoteVersion.last_result?.tag_name || "").trim() || null;
		return {
			current: currentVersion,
			latest: latestVersion,
			update_available: latestVersion
				? internalRemoteVersion.compareVersions(currentVersion, latestVersion)
				: false,
		};
	},

	fetchUrl: (url) => {
		const agent = new ProxyAgent();
		const headers = {
			"User-Agent": `HYROVI-Proxy-Manager v${pjson.version}`,
			Accept: "application/json",
		};

		return new Promise((resolve, reject) => {
			logger.info(`Fetching HYROVI update metadata from ${url}`);
			return https
				.get(url, { agent, headers }, (res) => {
					res.setEncoding("utf8");
					let raw_data = "";
					res.on("data", (chunk) => {
						raw_data += chunk;
					});
					res.on("end", () => {
						if ((res.statusCode || 500) >= 400) {
							reject(new Error(`HYROVI update feed returned HTTP ${res.statusCode}`));
							return;
						}
						resolve(raw_data);
					});
				})
				.on("error", (err) => {
					reject(err);
				});
		});
	},

	compareVersions: (current, latest) => {
		const cleanCurrent = current.replace(/^v/, "");
		const cleanLatest = latest.replace(/^v/, "");

		const currentParts = cleanCurrent.split(".").map(Number);
		const latestParts = cleanLatest.split(".").map(Number);

		for (let i = 0; i < Math.max(currentParts.length, latestParts.length); i++) {
			const curr = currentParts[i] || 0;
			const lat = latestParts[i] || 0;

			if (lat > curr) return true;
			if (lat < curr) return false;
		}
		return false;
	},
};

export default internalRemoteVersion;
