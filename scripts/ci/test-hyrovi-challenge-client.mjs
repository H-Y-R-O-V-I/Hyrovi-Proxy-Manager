import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import {
  HyroviChallengeError,
  fetchWithHyroviChallenge,
  readHyroviChallenge,
  validateHyroviChallenge,
} from "../../clients/hyrovi-sec-challenge-node.mjs";

const challenge = {
  version: 1,
  id: "f26a1e21-f5c3-43e4-b0e2-8ca9bba79234",
  nonce: "0123456789abcdef0123456789abcdef0123456789abcdef",
  difficulty: 10,
  expiresAt: new Date(Date.now() + 60_000).toISOString(),
  algorithm: "sha256-leading-zero-bits",
  input: "<challenge-id>:<nonce>:<counter>",
  challengePath: "/.well-known/hyrovi-sec/challenge",
  verifyPath: "/.well-known/hyrovi-sec/challenge/verify",
  maxCounter: 500_000,
  attemptsRemaining: 25,
};

const leadingZeroBits = (buffer) => {
  let bits = 0;
  for (const byte of buffer) {
    if (byte === 0) {
      bits += 8;
      continue;
    }
    for (let mask = 0x80; mask > 0 && (byte & mask) === 0; mask >>= 1) bits += 1;
    break;
  }
  return bits;
};

const proofIsValid = (counter) =>
  leadingZeroBits(
    createHash("sha256")
      .update(`${challenge.id}:${challenge.nonce}:${counter}`)
      .digest(),
  ) >= challenge.difficulty;

let originalCalls = 0;
let verificationCalls = 0;
let discoveryCalls = 0;

const fetchMock = async (input, init) => {
  const request = input instanceof Request ? input : new Request(input, init);
  const url = new URL(request.url);

  if (url.pathname === challenge.verifyPath) {
    verificationCalls += 1;
    assert.equal(request.method, "POST");
    assert.equal(request.headers.get("authorization"), null);
    assert.equal(request.headers.get("x-api-key"), null);
    assert.equal(request.headers.get("cookie"), null);
    assert.equal(request.headers.get("content-type"), "application/json");

    const body = await request.json();
    assert.equal(body.id, challenge.id);
    assert.equal(Number.isSafeInteger(body.counter), true);
    assert.equal(proofIsValid(body.counter), true);

    return new Response(JSON.stringify({ verified: true, attemptsRemaining: 25 }), {
      status: 200,
      headers: {
        "content-type": "application/json",
        "x-hyrovi-sec-challenge": "solved",
      },
    });
  }

  if (url.pathname === challenge.challengePath) {
    discoveryCalls += 1;
    return new Response(JSON.stringify({ challenge }), {
      status: 200,
      headers: {
        "content-type": "application/json",
        "x-hyrovi-sec-challenge": "required",
      },
    });
  }

  assert.equal(url.pathname, "/api/private/write");
  originalCalls += 1;
  assert.equal(request.method, "POST");
  assert.equal(request.headers.get("authorization"), "Bearer original-secret");
  assert.equal(request.headers.get("x-api-key"), "original-api-key");
  assert.equal(await request.text(), JSON.stringify({ value: 42 }));

  if (originalCalls === 1) {
    return new Response(JSON.stringify({ challenge }), {
      status: 429,
      headers: {
        "content-type": "application/json",
        "retry-after": "3",
        "x-hyrovi-sec-challenge": "required",
        "x-hyrovi-sec-challenge-endpoint": challenge.challengePath,
      },
    });
  }

  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
};

const response = await fetchWithHyroviChallenge(
  "https://api.example.test/api/private/write",
  {
    method: "POST",
    headers: {
      authorization: "Bearer original-secret",
      "content-type": "application/json",
      "x-api-key": "original-api-key",
    },
    body: JSON.stringify({ value: 42 }),
  },
  { fetch: fetchMock, yieldEvery: 500 },
);

assert.equal(response.status, 200);
assert.deepEqual(await response.json(), { ok: true });
assert.equal(originalCalls, 2);
assert.equal(verificationCalls, 1);
assert.equal(discoveryCalls, 0);

let fallbackDiscoveryCalls = 0;
const fallbackResponse = new Response("challenge body unavailable", {
  status: 429,
  headers: {
    "content-type": "text/plain",
    "x-hyrovi-sec-challenge": "required",
    "x-hyrovi-sec-challenge-endpoint": challenge.challengePath,
  },
});

const fallbackChallenge = await readHyroviChallenge(fallbackResponse, {
  requestUrl: "https://api.example.test/api/private/read",
  fetch: async (input) => {
    fallbackDiscoveryCalls += 1;
    const url = new URL(input);
    assert.equal(url.origin, "https://api.example.test");
    assert.equal(url.pathname, challenge.challengePath);
    return new Response(JSON.stringify({ challenge }), {
      status: 200,
      headers: {
        "content-type": "application/json",
        "x-hyrovi-sec-challenge": "required",
      },
    });
  },
});

assert.equal(fallbackDiscoveryCalls, 1);
assert.equal(fallbackChallenge.id, challenge.id);

assert.throws(
  () =>
    validateHyroviChallenge({
      ...challenge,
      verifyPath: "//attacker.example/verify",
    }),
  (error) => error instanceof HyroviChallengeError && error.code === "INVALID_CHALLENGE",
);

const template = await readFile("backend/templates/proxy_host.conf", "utf8");
assert.equal(
  (template.match(/proxy_pass_request_headers off;/g) || []).length,
  3,
  "all three internal challenge proxy locations must strip original headers",
);
assert.match(template, /location = \/\.well-known\/hyrovi-sec\/challenge \{/);
assert.match(template, /location = \/\.well-known\/hyrovi-sec\/challenge\/verify \{/);
assert.match(template, /proxy_set_header Content-Type "application\/json";/);

console.log(
  JSON.stringify({
    originalCalls,
    verificationCalls,
    embeddedChallengeUsed: discoveryCalls === 0,
    fallbackDiscoveryCalls,
    requestBodyReplayed: true,
    originalAuthorizationPreservedForRetry: true,
    secretsExcludedFromVerification: true,
    maliciousVerificationOriginRejected: true,
    nginxInternalHeadersStripped: true,
  }),
);
