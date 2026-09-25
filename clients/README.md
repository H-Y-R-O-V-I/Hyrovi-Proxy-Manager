# HYROVI Sec clients

## Node.js helper

`hyrovi-sec-challenge-node.mjs` is a dependency-free Node 22+ helper for HYROVI Sec adaptive challenges.

It intentionally retries an intercepted request at most once. The original request is cloned before the first network call, so POST/PUT bodies and application headers can be replayed after the challenge is solved. Challenge discovery and verification requests are created separately and do not copy the original Authorization, Cookie or API-key headers.

Example:

```js
import { fetchWithHyroviChallenge } from "./clients/hyrovi-sec-challenge-node.mjs";

const response = await fetchWithHyroviChallenge(
  "https://api.example.com/private/action",
  {
    method: "POST",
    headers: {
      authorization: "Bearer ...",
      "content-type": "application/json",
    },
    body: JSON.stringify({ action: "example" }),
  },
  {
    onChallenge(challenge) {
      console.log("HYROVI Sec challenge", challenge.id, challenge.difficulty);
    },
  },
);

if (!response.ok) {
  throw new Error(`Request failed with HTTP ${response.status}`);
}
```

The helper:

1. sends the original request;
2. detects `HTTP 429` plus `X-Hyrovi-Sec-Challenge: required`;
3. reads the versioned challenge JSON, falling back to `/.well-known/hyrovi-sec/challenge` if necessary;
4. validates that challenge and verification paths remain on the challenged origin;
5. solves the SHA-256 leading-zero proof locally;
6. submits only the challenge ID and counter to the verify endpoint;
7. retries the cloned original request exactly once.

The helper does not automatically loop if a request is challenged again after successful verification. It throws `HyroviChallengeError` with code `RECHALLENGED` instead.

An `AbortSignal` can be passed through the helper options to stop request handling and proof search. `onProgress` can be used to expose long-running proof progress without changing the proof algorithm.


## App/auth security-event helper

`hyrovi-sec-events-node.mjs` is a dependency-free Node 22+ client for `POST /api/security/app-events/ingest`.

It supports both HYROVI Sec authentication modes:

- shared ingest token;
- Ed25519 trusted-device signatures.

Token example:

```js
import { sendHyroviSecurityEvent } from "./clients/hyrovi-sec-events-node.mjs";

await sendHyroviSecurityEvent(
  {
    event_type: "login_failed",
    app: "hyrovi-one",
    severity: "medium",
    request_id: request.headers.get("x-hyrovi-request-id"),
    account_id: "account_42",
    reason: "invalid_credentials",
  },
  {
    baseUrl: "https://proxy.example.com",
    token: process.env.HYROVI_SEC_INGEST_TOKEN,
  },
);
```

Trusted-device example:

```js
import {
  createHyroviSecurityEventSender,
  generateHyroviDeviceKeyPair,
} from "./clients/hyrovi-sec-events-node.mjs";

const identity = generateHyroviDeviceKeyPair();

// Register identity.publicKey in HYROVI Sec once.
// Persist identity.privateKey securely on the device.

let sequence = await loadPersistedDeviceSequence();

const sender = createHyroviSecurityEventSender({
  baseUrl: "https://proxy.example.com",
  device: {
    deviceId: "hyrovi-one-node-1",
    privateKey: identity.privateKey,
    async nextSequence() {
      sequence += 1;
      await persistDeviceSequence(sequence);
      return sequence;
    },
  },
});

await sender.send({
  event_type: "session_created",
  app: "hyrovi-one",
  severity: "info",
  device_id: "hyrovi-one-node-1",
});
```

For device authentication, the sequence provider must return a strictly increasing positive integer and persist it durably before the request is sent. The helper intentionally does not retry a signed event automatically after a transport failure because the server may already have accepted that sequence.

The helper exports the canonical JSON and signing-message functions as well, so other HYROVI runtimes can implement the same protocol and test byte-for-byte compatibility.
