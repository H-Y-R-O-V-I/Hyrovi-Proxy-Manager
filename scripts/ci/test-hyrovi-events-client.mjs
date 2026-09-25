import assert from "node:assert/strict";
import {
  createPublicKey,
  verify as verifySignature,
} from "node:crypto";
import { signingMessage as serverSigningMessage, stableJson as serverStableJson } from "../../backend/internal/security_device_protocol.js";
import {
  HyroviSecurityEventError,
  generateHyroviDeviceKeyPair,
  createHyroviDeviceSigningMessage,
  createHyroviSecurityEventSender,
  sendHyroviSecurityEvent,
  signHyroviSecurityEvent,
  stableHyroviJson,
} from "../../clients/hyrovi-sec-events-node.mjs";

const generatedIdentity = generateHyroviDeviceKeyPair();
const privatePem = generatedIdentity.privateKey;
const publicPem = generatedIdentity.publicKey;
const publicKey = createPublicKey(publicPem);
assert.equal(generatedIdentity.fingerprint.length, 64);

const event = {
  severity: "medium",
  app: "hyrovi-one",
  event_type: "login_failed",
  request_id: "request-123",
  reason: "invalid_credentials",
  nested: {
    z: 3,
    a: 1,
    ignored: undefined,
  },
  array: ["x", undefined, 2],
};

assert.equal(stableHyroviJson(event), serverStableJson(event));

const deviceId = "hyrovi-one-node-1";
const sequence = 42;
const timestamp = 1_796_000_000_000;

const clientMessage = createHyroviDeviceSigningMessage({
  deviceId,
  sequence,
  timestamp,
  event,
});
const serverMessage = serverSigningMessage({
  deviceId,
  sequence,
  timestamp,
  body: event,
});
assert.equal(clientMessage, serverMessage);

const signed = signHyroviSecurityEvent({
  deviceId,
  privateKey: privatePem,
  sequence,
  timestamp,
  event,
});
assert.equal(signed.sequence, sequence);
assert.equal(signed.timestamp, timestamp);
assert.equal(signed.headers["X-Hyrovi-Device-ID"], deviceId);
assert.equal(signed.headers["X-Hyrovi-Device-Sequence"], String(sequence));
assert.equal(signed.headers["X-Hyrovi-Device-Time"], String(timestamp));

const verified = verifySignature(
  null,
  Buffer.from(serverMessage, "utf8"),
  publicKey,
  Buffer.from(signed.headers["X-Hyrovi-Device-Signature"], "base64"),
);
assert.equal(verified, true);

let tokenRequest = null;
const tokenResult = await sendHyroviSecurityEvent(
  {
    event_type: "permission_denied",
    app: "hyrovi-one",
    severity: "high",
    account_id: "account-1",
  },
  {
    baseUrl: "https://sec.example.test",
    token: "t".repeat(40),
    fetch: async (input, init) => {
      tokenRequest = input instanceof Request ? input : new Request(input, init);
      return new Response(
        JSON.stringify({
          accepted: true,
          id: "event-token-1",
          timestamp: "2026-09-24T20:30:00.000Z",
          deviceTrust: null,
        }),
        { status: 202, headers: { "content-type": "application/json" } },
      );
    },
  },
);

assert.equal(tokenResult.authMode, "token");
assert.equal(tokenResult.id, "event-token-1");
assert.equal(tokenRequest.url, "https://sec.example.test/api/security/app-events/ingest");
assert.equal(tokenRequest.method, "POST");
assert.equal(tokenRequest.headers.get("authorization"), `Bearer ${"t".repeat(40)}`);
assert.equal(tokenRequest.headers.get("x-hyrovi-device-id"), null);

let nextSequenceCalls = 0;
let deviceRequest = null;
const sender = createHyroviSecurityEventSender({
  endpoint: "https://sec.example.test/api/security/app-events/ingest",
  device: {
    deviceId,
    privateKey: privatePem,
    nextSequence: async () => {
      nextSequenceCalls += 1;
      return 100 + nextSequenceCalls;
    },
  },
  fetch: async (input, init) => {
    deviceRequest = input instanceof Request ? input : new Request(input, init);
    const body = await deviceRequest.clone().json();
    const requestSequence = Number(deviceRequest.headers.get("x-hyrovi-device-sequence"));
    const requestTimestamp = Number(deviceRequest.headers.get("x-hyrovi-device-time"));
    const signature = Buffer.from(deviceRequest.headers.get("x-hyrovi-device-signature"), "base64");
    const message = serverSigningMessage({
      deviceId,
      sequence: requestSequence,
      timestamp: requestTimestamp,
      body,
    });
    assert.equal(verifySignature(null, Buffer.from(message, "utf8"), publicKey, signature), true);
    assert.equal(deviceRequest.headers.get("authorization"), null);

    return new Response(
      JSON.stringify({
        accepted: true,
        id: "event-device-1",
        timestamp: "2026-09-24T20:31:00.000Z",
        deviceTrust: "verified",
      }),
      { status: 202, headers: { "content-type": "application/json" } },
    );
  },
});

const deviceResult = await sender.send({
  event_type: "login_success",
  app: "hyrovi-one",
  severity: "info",
  device_id: deviceId,
});
assert.equal(deviceResult.authMode, "device");
assert.equal(deviceResult.deviceTrust, "verified");
assert.equal(nextSequenceCalls, 1);
assert.equal(deviceRequest.headers.get("x-hyrovi-device-sequence"), "101");

await assert.rejects(
  () =>
    sendHyroviSecurityEvent(
      { event_type: "login_failed", app: "hyrovi-one" },
      {
        endpoint: "https://sec.example.test/api/security/app-events/ingest",
        token: "t".repeat(40),
        device: { deviceId, privateKey: privatePem, sequence: 1 },
        fetch: async () => new Response(null, { status: 202 }),
      },
    ),
  (error) => error instanceof HyroviSecurityEventError && error.code === "AMBIGUOUS_AUTH",
);

await assert.rejects(
  () =>
    sendHyroviSecurityEvent(
      { event_type: "login_failed", app: "hyrovi-one" },
      {
        endpoint: "https://sec.example.test/api/security/app-events/ingest",
        device: { deviceId, privateKey: privatePem, sequence: 102 },
        fetch: async () => {
          throw new Error("network lost after send");
        },
      },
    ),
  (error) =>
    error instanceof HyroviSecurityEventError &&
    error.code === "DELIVERY_FAILED" &&
    error.message.includes("do not reuse this device sequence"),
);

assert.throws(
  () =>
    signHyroviSecurityEvent({
      deviceId,
      privateKey: privatePem,
      sequence: 0,
      event,
    }),
  (error) => error instanceof HyroviSecurityEventError && error.code === "INVALID_SEQUENCE",
);

console.log(
  JSON.stringify({
    generatedKeyFingerprint: generatedIdentity.fingerprint.length === 64,
    canonicalJsonMatchesServer: true,
    signingMessageMatchesServer: true,
    ed25519SignatureVerified: verified,
    tokenTransport: tokenResult.authMode,
    deviceTransport: deviceResult.authMode,
    sequenceProviderCalls: nextSequenceCalls,
    ambiguousAuthRejected: true,
    uncertainDeviceDeliveryWarnsAgainstSequenceReuse: true,
  }),
);
