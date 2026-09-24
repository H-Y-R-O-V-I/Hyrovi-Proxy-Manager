import fs from "node:fs";
import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import errs from "../lib/error.js";

const SECURITY_DIR = "/data/nginx/hyrovi-security";
const DEVICES_FILE = `${SECURITY_DIR}/trusted-devices.json`;
const DEVICE_STATE_FILE = `${SECURITY_DIR}/trusted-device-state.json`;
const MAX_DEVICES = 200;
const MAX_ALLOWED_APPS = 32;
const MAX_PUBLIC_KEY_BYTES = 8192;
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
const SIGNATURE_CONTEXT = "HYROVI-SEC-DEVICE-V1";

let mutationQueue = Promise.resolve();

const withMutation = (operation) => {
	const run = mutationQueue.then(operation, operation);
	mutationQueue = run.catch(() => undefined);
	return run;
};

const writeTextAtomic = async (filePath, value) => {
	const tmp = `${filePath}.tmp-${process.pid}-${Date.now()}`;
	try {
		await fs.promises.writeFile(tmp, value, "utf8");
		await fs.promises.rename(tmp, filePath);
	} catch (err) {
		await fs.promises.unlink(tmp).catch(() => undefined);
		throw err;
	}
};

const writeJsonAtomic = (filePath, value) => writeTextAtomic(filePath, `${JSON.stringify(value, null, 2)}\n`);

const readJson = async (filePath, fallback) => {
	try {
		return JSON.parse(await fs.promises.readFile(filePath, "utf8"));
	} catch (err) {
		if (err.code === "ENOENT") return fallback;
		if (err instanceof SyntaxError) throw new errs.ConfigurationError(`Invalid HYROVI Sec device state: ${filePath}`);
		throw err;
	}
};

const readDevicesUnsafe = async () => {
	const value = await readJson(DEVICES_FILE, []);
	return Array.isArray(value) ? value : [];
};

const readStateUnsafe = async () => {
	const value = await readJson(DEVICE_STATE_FILE, {});
	return value && typeof value === "object" && !Array.isArray(value) ? value : {};
};

const normalizeDeviceId = (value) => {
	const id = String(value || "").trim();
	if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,119}$/.test(id)) {
		throw new errs.ValidationError("Device ID must be 1-120 characters using letters, numbers, dot, underscore, colon or dash");
	}
	return id;
};

const boundedString = (value, maxLength) => {
	if (typeof value === "undefined" || value === null) return null;
	const text = String(value).trim();
	return text ? text.slice(0, maxLength) : null;
};

const normalizeAllowedApps = (value) => {
	if (!Array.isArray(value)) throw new errs.ValidationError("Allowed apps must be a non-empty array");
	if (value.length > MAX_ALLOWED_APPS) {
		throw new errs.ValidationError(`Allowed apps are limited to ${MAX_ALLOWED_APPS} entries`);
	}
	const apps = [
		...new Set(
			value
				.map((entry) => boundedString(entry, 80))
				.filter(Boolean),
		),
	];
	if (apps.length === 0) {
		throw new errs.ValidationError("At least one allowed app is required; use * only for an intentional wildcard");
	}
	for (const app of apps) {
		if (app !== "*" && !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$/.test(app)) {
			throw new errs.ValidationError("Allowed app names may use letters, numbers, dot, underscore, colon or dash");
		}
	}
	return apps;
};

const normalizePublicKey = (value) => {
	const input = String(value || "").trim();
	if (!input || Buffer.byteLength(input, "utf8") > MAX_PUBLIC_KEY_BYTES) {
		throw new errs.ValidationError("A valid Ed25519 public key is required");
	}
	let key;
	try {
		key = createPublicKey(input);
	} catch (_) {
		throw new errs.ValidationError("Device public key is not valid PEM");
	}
	if (key.asymmetricKeyType !== "ed25519") {
		throw new errs.ValidationError("Device public key must use Ed25519");
	}
	const pem = key.export({ type: "spki", format: "pem" }).toString().trim();
	const der = key.export({ type: "spki", format: "der" });
	const fingerprint = createHash("sha256").update(der).digest("hex");
	return { pem, fingerprint };
};

const stableJson = (value) => {
	if (value === null) return "null";
	if (Array.isArray(value)) return `[${value.map((entry) => stableJson(entry)).join(",")}]`;
	switch (typeof value) {
		case "string":
		case "boolean":
		case "number":
			return JSON.stringify(value);
		case "object": {
			const entries = Object.keys(value)
				.sort()
				.filter((key) => typeof value[key] !== "undefined")
				.map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`);
			return `{${entries.join(",")}}`;
		}
		default:
			return "null";
	}
};

const signingMessage = ({ deviceId, sequence, timestamp, body }) => {
	const bodyHash = createHash("sha256").update(stableJson(body ?? {})).digest("hex");
	return [SIGNATURE_CONTEXT, deviceId, String(sequence), String(timestamp), bodyHash].join("\n");
};

const headerValue = (headers, name) => {
	const value = headers?.[name];
	if (Array.isArray(value)) return value[0] || "";
	return String(value || "").trim();
};

const signedHeadersPresent = (headers) =>
	[
		"x-hyrovi-device-id",
		"x-hyrovi-device-sequence",
		"x-hyrovi-device-time",
		"x-hyrovi-device-signature",
	].some((name) => Boolean(headerValue(headers, name)));

const publicDevice = (device, state = {}) => ({
	deviceId: device.deviceId,
	name: device.name,
	fingerprint: device.fingerprint,
	allowedApps: device.allowedApps || [],
	createdAt: device.createdAt,
	updatedAt: device.updatedAt,
	revokedAt: device.revokedAt || null,
	lastSequence: Number.parseInt(state.lastSequence, 10) || 0,
	sequenceResetAt: state.sequenceResetAt || null,
	lastSeenAt: state.lastSeenAt || null,
	lastApp: state.lastApp || null,
});

const prepare = async () =>
	withMutation(async () => {
		await fs.promises.mkdir(SECURITY_DIR, { recursive: true });
		try {
			await fs.promises.access(DEVICES_FILE);
		} catch (_) {
			await writeJsonAtomic(DEVICES_FILE, []);
		}
		try {
			await fs.promises.access(DEVICE_STATE_FILE);
		} catch (_) {
			await writeJsonAtomic(DEVICE_STATE_FILE, {});
		}
	});

const listDevices = async () => {
	const [devices, state] = await Promise.all([readDevicesUnsafe(), readStateUnsafe()]);
	return devices
		.map((device) => publicDevice(device, state[device.deviceId]))
		.sort((left, right) => left.deviceId.localeCompare(right.deviceId));
};

const registerDevice = ({ deviceId, name, publicKey, allowedApps }) =>
	withMutation(async () => {
		await fs.promises.mkdir(SECURITY_DIR, { recursive: true });
		const id = normalizeDeviceId(deviceId);
		const normalizedKey = normalizePublicKey(publicKey);
		const apps = normalizeAllowedApps(allowedApps);
		const devices = await readDevicesUnsafe();
		const existingIndex = devices.findIndex((device) => device.deviceId === id);
		if (existingIndex >= 0 && !devices[existingIndex].revokedAt) {
			throw new errs.ValidationError("A trusted device with this ID already exists");
		}
		if (existingIndex >= 0 && devices[existingIndex].revokedAt && devices[existingIndex].fingerprint === normalizedKey.fingerprint) {
			throw new errs.ValidationError("A revoked device ID must be re-registered with a new Ed25519 key");
		}
		if (existingIndex < 0 && devices.length >= MAX_DEVICES) {
			throw new errs.ValidationError(`Trusted devices are limited to ${MAX_DEVICES}`);
		}

		const now = new Date().toISOString();
		const device = {
			deviceId: id,
			name: boundedString(name, 120) || id,
			publicKey: normalizedKey.pem,
			fingerprint: normalizedKey.fingerprint,
			allowedApps: apps,
			createdAt: now,
			updatedAt: now,
			revokedAt: null,
		};
		const next = [...devices];
		if (existingIndex >= 0) next[existingIndex] = device;
		else next.push(device);
		await writeJsonAtomic(DEVICES_FILE, next);

		const state = await readStateUnsafe();
		delete state[id];
		await writeJsonAtomic(DEVICE_STATE_FILE, state);
		return publicDevice(device);
	});

const revokeDevice = (deviceId) =>
	withMutation(async () => {
		const id = normalizeDeviceId(deviceId);
		const devices = await readDevicesUnsafe();
		const index = devices.findIndex((device) => device.deviceId === id);
		if (index < 0) throw new errs.ItemNotFoundError(id);
		if (!devices[index].revokedAt) {
			devices[index] = {
				...devices[index],
				revokedAt: new Date().toISOString(),
				updatedAt: new Date().toISOString(),
			};
			await writeJsonAtomic(DEVICES_FILE, devices);
		}
		const state = await readStateUnsafe();
		delete state[id];
		await writeJsonAtomic(DEVICE_STATE_FILE, state);
		return publicDevice(devices[index]);
	});

const resetSequence = (deviceId) =>
	withMutation(async () => {
		const id = normalizeDeviceId(deviceId);
		const devices = await readDevicesUnsafe();
		const device = devices.find((entry) => entry.deviceId === id);
		if (!device || device.revokedAt) throw new errs.ItemNotFoundError(id);
		const state = await readStateUnsafe();
		state[id] = {
			lastSequence: 0,
			sequenceResetAt: new Date().toISOString(),
			lastSeenAt: null,
			lastApp: null,
		};
		await writeJsonAtomic(DEVICE_STATE_FILE, state);
		return publicDevice(device, state[id]);
	});

const verifySignedRequest = ({ headers, body }) => {
	if (!signedHeadersPresent(headers)) return Promise.resolve(null);
	return withMutation(async () => {
		const deviceId = normalizeDeviceId(headerValue(headers, "x-hyrovi-device-id"));
		const sequenceRaw = headerValue(headers, "x-hyrovi-device-sequence");
		const timeRaw = headerValue(headers, "x-hyrovi-device-time");
		const signatureRaw = headerValue(headers, "x-hyrovi-device-signature");
		if (!/^\d+$/.test(sequenceRaw) || !/^\d+$/.test(timeRaw) || !signatureRaw) {
			throw new errs.ValidationError("Incomplete HYROVI Sec device signature headers");
		}
		const sequence = Number(sequenceRaw);
		const timestamp = Number(timeRaw);
		if (!Number.isSafeInteger(sequence) || sequence < 1) {
			throw new errs.ValidationError("Device sequence must be a positive safe integer");
		}
		if (!Number.isSafeInteger(timestamp) || Math.abs(Date.now() - timestamp) > MAX_CLOCK_SKEW_MS) {
			throw new errs.ValidationError("Device signature timestamp is outside the allowed 5-minute window");
		}

		const devices = await readDevicesUnsafe();
		const device = devices.find((entry) => entry.deviceId === deviceId);
		if (!device || device.revokedAt) throw new errs.TokenRevokedError("Unknown or revoked HYROVI Sec device");
		const app = boundedString(body?.app, 80);
		if (!app || (!device.allowedApps.includes("*") && !device.allowedApps.includes(app))) {
			throw new errs.PermissionError("This device is not allowed to submit events for the requested app");
		}
		const reportedDeviceId = boundedString(body?.device_id ?? body?.deviceId, 160);
		if (reportedDeviceId && reportedDeviceId !== deviceId) {
			throw new errs.ValidationError("Signed device ID does not match the event device ID");
		}

		let signature;
		try {
			signature = Buffer.from(signatureRaw, "base64");
		} catch (_) {
			throw new errs.ValidationError("Invalid device signature encoding");
		}
		if (signature.length !== 64) throw new errs.ValidationError("Invalid Ed25519 signature length");
		const message = signingMessage({ deviceId, sequence, timestamp, body });
		let verified = false;
		try {
			verified = verifySignature(null, Buffer.from(message, "utf8"), createPublicKey(device.publicKey), signature);
		} catch (_) {
			verified = false;
		}
		if (!verified) throw new errs.TokenRevokedError("Invalid HYROVI Sec device signature");

		const state = await readStateUnsafe();
		const previousSequence = Number.parseInt(state[deviceId]?.lastSequence, 10) || 0;
		const resetAt = Date.parse(state[deviceId]?.sequenceResetAt || "");
		if (Number.isFinite(resetAt) && timestamp <= resetAt) {
			throw new errs.ValidationError("Device signature predates the current replay-counter epoch");
		}
		if (sequence <= previousSequence) {
			throw new errs.ValidationError("Device event was replayed or arrived out of order");
		}
		state[deviceId] = {
			lastSequence: sequence,
			sequenceResetAt: state[deviceId]?.sequenceResetAt || null,
			lastSeenAt: new Date().toISOString(),
			lastApp: app,
		};
		await writeJsonAtomic(DEVICE_STATE_FILE, state);
		return {
			deviceId,
			name: device.name,
			fingerprint: device.fingerprint,
			sequence,
			verifiedAt: state[deviceId].lastSeenAt,
		};
	});
};

const internalSecurityDevices = {
	prepare,
	listDevices,
	registerDevice,
	revokeDevice,
	resetSequence,
	verifySignedRequest,
	stableJson,
	signingMessage,
};

export default internalSecurityDevices;
