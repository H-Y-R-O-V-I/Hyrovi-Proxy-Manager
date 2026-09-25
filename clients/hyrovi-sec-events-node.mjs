import { createHash, createPrivateKey, generateKeyPairSync, sign as signMessage } from "node:crypto";

const SIGNATURE_CONTEXT = "HYROVI-SEC-DEVICE-V1";
const DEFAULT_INGEST_PATH = "/api/security/app-events/ingest";
const DEVICE_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,119}$/;

export class HyroviSecurityEventError extends Error {
  constructor(message, code = "HYROVI_SECURITY_EVENT_ERROR", options = {}) {
    super(message, options);
    this.name = "HyroviSecurityEventError";
    this.code = code;
  }
}

export const generateHyroviDeviceKeyPair = () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const publicKeyDer = publicKey.export({ type: "spki", format: "der" });
  return {
    privateKey: privateKeyPem,
    publicKey: publicKeyPem,
    fingerprint: createHash("sha256").update(publicKeyDer).digest("hex"),
  };
};

export const stableHyroviJson = (value) => {
  if (value === null) return "null";
  if (Array.isArray(value)) return `[${value.map((entry) => stableHyroviJson(entry)).join(",")}]`;
  switch (typeof value) {
    case "string":
    case "boolean":
    case "number":
      return JSON.stringify(value);
    case "object": {
      const entries = Object.keys(value)
        .sort()
        .filter((key) => typeof value[key] !== "undefined")
        .map((key) => `${JSON.stringify(key)}:${stableHyroviJson(value[key])}`);
      return `{${entries.join(",")}}`;
    }
    default:
      return "null";
  }
};

const assertEventBody = (event) => {
  if (!event || typeof event !== "object" || Array.isArray(event)) {
    throw new HyroviSecurityEventError("HYROVI Sec event must be an object", "INVALID_EVENT");
  }
  return event;
};

const normalizeDeviceId = (deviceId) => {
  const id = String(deviceId || "").trim();
  if (!DEVICE_ID_RE.test(id)) {
    throw new HyroviSecurityEventError(
      "Device ID must be 1-120 characters using letters, numbers, dot, underscore, colon or dash",
      "INVALID_DEVICE_ID",
    );
  }
  return id;
};

const normalizeSequence = (sequence) => {
  const value = typeof sequence === "number" ? sequence : Number(sequence);
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new HyroviSecurityEventError("Device sequence must be a positive safe integer", "INVALID_SEQUENCE");
  }
  return value;
};

const normalizeTimestamp = (timestamp) => {
  const value = typeof timestamp === "number" ? timestamp : Number(timestamp);
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new HyroviSecurityEventError("Device timestamp must be a positive Unix time in milliseconds", "INVALID_TIMESTAMP");
  }
  return value;
};

const normalizePrivateKey = (privateKey) => {
  let key;
  try {
    key = createPrivateKey(privateKey);
  } catch (cause) {
    throw new HyroviSecurityEventError("Device private key is not valid", "INVALID_PRIVATE_KEY", { cause });
  }
  if (key.asymmetricKeyType !== "ed25519") {
    throw new HyroviSecurityEventError("Device private key must use Ed25519", "INVALID_PRIVATE_KEY");
  }
  return key;
};

export const createHyroviDeviceSigningMessage = ({
  deviceId,
  sequence,
  timestamp,
  event,
}) => {
  const body = assertEventBody(event);
  const id = normalizeDeviceId(deviceId);
  const normalizedSequence = normalizeSequence(sequence);
  const normalizedTimestamp = normalizeTimestamp(timestamp);
  const bodyHash = createHash("sha256").update(stableHyroviJson(body)).digest("hex");
  return [
    SIGNATURE_CONTEXT,
    id,
    String(normalizedSequence),
    String(normalizedTimestamp),
    bodyHash,
  ].join("\n");
};

export const signHyroviSecurityEvent = ({
  deviceId,
  privateKey,
  sequence,
  timestamp = Date.now(),
  event,
}) => {
  const body = assertEventBody(event);
  const id = normalizeDeviceId(deviceId);
  const normalizedSequence = normalizeSequence(sequence);
  const normalizedTimestamp = normalizeTimestamp(timestamp);
  const key = normalizePrivateKey(privateKey);
  const message = createHyroviDeviceSigningMessage({
    deviceId: id,
    sequence: normalizedSequence,
    timestamp: normalizedTimestamp,
    event: body,
  });
  const signature = signMessage(null, Buffer.from(message, "utf8"), key).toString("base64");

  return {
    deviceId: id,
    sequence: normalizedSequence,
    timestamp: normalizedTimestamp,
    message,
    headers: {
      "X-Hyrovi-Device-ID": id,
      "X-Hyrovi-Device-Sequence": String(normalizedSequence),
      "X-Hyrovi-Device-Time": String(normalizedTimestamp),
      "X-Hyrovi-Device-Signature": signature,
    },
  };
};

const resolveEndpoint = (endpoint, baseUrl) => {
  try {
    if (endpoint) return new URL(endpoint, baseUrl || undefined).toString();
    if (baseUrl) return new URL(DEFAULT_INGEST_PATH, baseUrl).toString();
    throw new Error("missing endpoint");
  } catch (cause) {
    throw new HyroviSecurityEventError(
      "A valid HYROVI Sec ingest endpoint or baseUrl is required",
      "INVALID_ENDPOINT",
      { cause },
    );
  }
};

const resolveSequence = async (device) => {
  if (typeof device?.nextSequence === "function") {
    return normalizeSequence(await device.nextSequence());
  }
  return normalizeSequence(device?.sequence);
};

const parseJsonBestEffort = async (response) => {
  try {
    return await response.json();
  } catch (_) {
    return null;
  }
};

export const sendHyroviSecurityEvent = async (
  event,
  {
    endpoint,
    baseUrl,
    token,
    device,
    fetch: fetchImpl = globalThis.fetch,
    timestamp = Date.now(),
    signal,
  } = {},
) => {
  const body = assertEventBody(event);
  const url = resolveEndpoint(endpoint, baseUrl);
  if (typeof fetchImpl !== "function") {
    throw new HyroviSecurityEventError("No fetch implementation is available", "FETCH_UNAVAILABLE");
  }
  if (token && device) {
    throw new HyroviSecurityEventError("Choose either token auth or trusted-device auth, not both", "AMBIGUOUS_AUTH");
  }

  const headers = new Headers({ "content-type": "application/json" });
  let authMode;

  if (device) {
    const sequence = await resolveSequence(device);
    const signed = signHyroviSecurityEvent({
      deviceId: device.deviceId,
      privateKey: device.privateKey,
      sequence,
      timestamp,
      event: body,
    });
    for (const [name, value] of Object.entries(signed.headers)) headers.set(name, value);
    authMode = "device";
  } else {
    const normalizedToken = String(token || "").trim();
    if (normalizedToken.length < 32) {
      throw new HyroviSecurityEventError(
        "Shared ingest token must contain at least 32 characters",
        "INVALID_TOKEN",
      );
    }
    headers.set("authorization", `Bearer ${normalizedToken}`);
    authMode = "token";
  }

  let response;
  try {
    response = await fetchImpl(url, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      signal,
    });
  } catch (cause) {
    throw new HyroviSecurityEventError(
      authMode === "device"
        ? "HYROVI Sec event delivery failed; do not reuse this device sequence until delivery state is reconciled"
        : "HYROVI Sec event delivery failed",
      "DELIVERY_FAILED",
      { cause },
    );
  }

  const payload = await parseJsonBestEffort(response);
  if (response.status !== 202 || payload?.accepted !== true) {
    const error = new HyroviSecurityEventError(
      `HYROVI Sec rejected the security event with HTTP ${response.status}`,
      "INGEST_REJECTED",
    );
    error.status = response.status;
    error.response = payload;
    throw error;
  }

  return {
    accepted: true,
    id: payload.id,
    timestamp: payload.timestamp,
    deviceTrust: payload.deviceTrust ?? null,
    authMode,
    response,
  };
};

export const createHyroviSecurityEventSender = ({
  endpoint,
  baseUrl,
  token,
  device,
  fetch,
} = {}) => ({
  send(event, options = {}) {
    return sendHyroviSecurityEvent(event, {
      endpoint,
      baseUrl,
      token,
      device,
      fetch,
      ...options,
    });
  },
});
