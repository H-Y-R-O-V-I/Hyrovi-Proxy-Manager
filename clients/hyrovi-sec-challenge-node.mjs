import { createHash } from "node:crypto";

const REQUIRED_HEADER = "x-hyrovi-sec-challenge";
const DEFAULT_CHALLENGE_PATH = "/.well-known/hyrovi-sec/challenge";
const EXPECTED_ALGORITHM = "sha256-leading-zero-bits";
const EXPECTED_INPUT = "<challenge-id>:<nonce>:<counter>";
const MAX_SERVER_COUNTER = 50_000_000;

export class HyroviChallengeError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = "HyroviChallengeError";
    Object.assign(this, details);
  }
}

const getFetch = (fetchImpl) => {
  const value = fetchImpl || globalThis.fetch;
  if (typeof value !== "function") {
    throw new HyroviChallengeError("A fetch implementation is required", { code: "FETCH_UNAVAILABLE" });
  }
  return value;
};

const assertSignal = (signal) => {
  if (signal?.aborted) {
    throw new HyroviChallengeError("HYROVI Sec challenge solving was aborted", { code: "ABORTED" });
  }
};

const sameOriginEndpoint = (baseUrl, path, label) => {
  if (
    typeof path !== "string" ||
    !path.startsWith("/") ||
    path.startsWith("//") ||
    path.includes("\\")
  ) {
    throw new HyroviChallengeError(`Invalid HYROVI Sec ${label} path`, { code: "INVALID_CHALLENGE" });
  }

  const base = new URL(baseUrl);
  const endpoint = new URL(path, base);
  if (endpoint.origin !== base.origin) {
    throw new HyroviChallengeError(`HYROVI Sec ${label} escaped the challenged origin`, {
      code: "INVALID_CHALLENGE",
    });
  }
  return endpoint;
};

export const validateHyroviChallenge = (value) => {
  const challenge = value && typeof value === "object" ? value : null;
  if (!challenge || challenge.version !== 1) {
    throw new HyroviChallengeError("Unsupported HYROVI Sec challenge version", {
      code: "UNSUPPORTED_VERSION",
    });
  }
  if (typeof challenge.id !== "string" || challenge.id.length < 8 || challenge.id.length > 128) {
    throw new HyroviChallengeError("Invalid HYROVI Sec challenge ID", { code: "INVALID_CHALLENGE" });
  }
  if (typeof challenge.nonce !== "string" || !/^[0-9a-f]{32,128}$/i.test(challenge.nonce)) {
    throw new HyroviChallengeError("Invalid HYROVI Sec challenge nonce", { code: "INVALID_CHALLENGE" });
  }
  if (challenge.algorithm !== EXPECTED_ALGORITHM || challenge.input !== EXPECTED_INPUT) {
    throw new HyroviChallengeError("Unsupported HYROVI Sec proof algorithm", {
      code: "UNSUPPORTED_ALGORITHM",
    });
  }
  if (!Number.isInteger(challenge.difficulty) || challenge.difficulty < 10 || challenge.difficulty > 22) {
    throw new HyroviChallengeError("Invalid HYROVI Sec challenge difficulty", {
      code: "INVALID_CHALLENGE",
    });
  }
  if (
    !Number.isInteger(challenge.maxCounter) ||
    challenge.maxCounter < 0 ||
    challenge.maxCounter > MAX_SERVER_COUNTER
  ) {
    throw new HyroviChallengeError("Invalid HYROVI Sec challenge counter range", {
      code: "INVALID_CHALLENGE",
    });
  }
  if (!Number.isInteger(challenge.attemptsRemaining) || challenge.attemptsRemaining < 0) {
    throw new HyroviChallengeError("Invalid HYROVI Sec challenge attempt budget", {
      code: "INVALID_CHALLENGE",
    });
  }
  if (challenge.attemptsRemaining === 0) {
    throw new HyroviChallengeError("HYROVI Sec challenge has no verification attempts remaining", {
      code: "ATTEMPTS_EXHAUSTED",
    });
  }
  const expiresAt = Date.parse(challenge.expiresAt);
  if (!Number.isFinite(expiresAt)) {
    throw new HyroviChallengeError("Invalid HYROVI Sec challenge expiry", { code: "INVALID_CHALLENGE" });
  }
  if (expiresAt <= Date.now()) {
    throw new HyroviChallengeError("HYROVI Sec challenge has expired", { code: "CHALLENGE_EXPIRED" });
  }

  sameOriginEndpoint("https://hyrovi.invalid/", challenge.challengePath, "discovery");
  sameOriginEndpoint("https://hyrovi.invalid/", challenge.verifyPath, "verification");
  return challenge;
};

export const isHyroviChallengeResponse = (response) =>
  Boolean(response && response.status === 429 && response.headers?.get(REQUIRED_HEADER) === "required");

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

export const solveHyroviChallenge = async (
  input,
  { signal, yieldEvery = 25_000, onProgress } = {},
) => {
  const challenge = validateHyroviChallenge(input);
  const prefix = `${challenge.id}:${challenge.nonce}:`;
  const interval = Math.max(1, Number.parseInt(yieldEvery, 10) || 25_000);

  for (let counter = 0; counter <= challenge.maxCounter; counter += 1) {
    assertSignal(signal);
    const digest = createHash("sha256").update(prefix).update(String(counter)).digest();
    if (leadingZeroBits(digest) >= challenge.difficulty) return counter;

    if (counter > 0 && counter % interval === 0) {
      if (typeof onProgress === "function") onProgress({ counter, challenge });
      await new Promise((resolve) => setImmediate(resolve));
    }
  }

  throw new HyroviChallengeError("HYROVI Sec proof search limit reached", {
    code: "PROOF_NOT_FOUND",
  });
};

const parseChallengeBody = async (response) => {
  try {
    const payload = await response.clone().json();
    return payload?.challenge ? validateHyroviChallenge(payload.challenge) : null;
  } catch (_) {
    return null;
  }
};

export const readHyroviChallenge = async (
  response,
  { requestUrl, fetch: fetchImpl, signal } = {},
) => {
  if (!isHyroviChallengeResponse(response)) {
    throw new HyroviChallengeError("Response is not a HYROVI Sec challenge", {
      code: "NOT_CHALLENGED",
      status: response?.status,
    });
  }

  const embedded = await parseChallengeBody(response);
  if (embedded) return embedded;

  const fetchFn = getFetch(fetchImpl);
  const baseUrl = requestUrl || response.url;
  if (!baseUrl) {
    throw new HyroviChallengeError("Cannot resolve the HYROVI Sec challenge endpoint", {
      code: "MISSING_REQUEST_URL",
    });
  }

  const discoveryPath =
    response.headers.get("x-hyrovi-sec-challenge-endpoint") || DEFAULT_CHALLENGE_PATH;
  const discoveryUrl = sameOriginEndpoint(baseUrl, discoveryPath, "discovery");
  const discoveryResponse = await fetchFn(discoveryUrl, {
    method: "GET",
    headers: { accept: "application/json" },
    redirect: "error",
    signal,
  });
  const challenge = await parseChallengeBody(discoveryResponse);
  if (!discoveryResponse.ok || !challenge) {
    throw new HyroviChallengeError("Could not retrieve the current HYROVI Sec challenge", {
      code: "CHALLENGE_DISCOVERY_FAILED",
      status: discoveryResponse.status,
    });
  }
  return challenge;
};

export const verifyHyroviChallenge = async (
  baseUrl,
  input,
  counter,
  { fetch: fetchImpl, signal } = {},
) => {
  const challenge = validateHyroviChallenge(input);
  if (!Number.isSafeInteger(counter) || counter < 0 || counter > challenge.maxCounter) {
    throw new HyroviChallengeError("Invalid HYROVI Sec proof counter", { code: "INVALID_COUNTER" });
  }

  const fetchFn = getFetch(fetchImpl);
  const verifyUrl = sameOriginEndpoint(baseUrl, challenge.verifyPath, "verification");
  const response = await fetchFn(verifyUrl, {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
    },
    body: JSON.stringify({ id: challenge.id, counter }),
    redirect: "error",
    signal,
  });

  let result = null;
  try {
    result = await response.json();
  } catch (_) {
    // The status and challenge header below still produce a useful error.
  }

  const attemptsHeader = Number.parseInt(
    response.headers.get("x-hyrovi-sec-challenge-attempts-remaining"),
    10,
  );
  if (
    !response.ok ||
    result?.verified !== true ||
    (response.headers.get(REQUIRED_HEADER) &&
      response.headers.get(REQUIRED_HEADER) !== "solved")
  ) {
    throw new HyroviChallengeError("HYROVI Sec proof verification failed", {
      code: "VERIFICATION_FAILED",
      status: response.status,
      attemptsRemaining:
        result?.attemptsRemaining ??
        (Number.isInteger(attemptsHeader) ? attemptsHeader : null),
    });
  }

  return result;
};

export const fetchWithHyroviChallenge = async (
  input,
  init = {},
  {
    fetch: fetchImpl,
    signal,
    yieldEvery,
    onProgress,
    onChallenge,
  } = {},
) => {
  const fetchFn = getFetch(fetchImpl);
  const request = new Request(input, signal ? { ...init, signal } : init);
  let firstAttempt;
  let retryAttempt;

  try {
    firstAttempt = request.clone();
    retryAttempt = request.clone();
  } catch (cause) {
    throw new HyroviChallengeError(
      "Request body cannot be replayed after a HYROVI Sec challenge",
      { code: "REQUEST_NOT_REPLAYABLE", cause },
    );
  }

  const activeSignal = signal || request.signal;
  const response = await fetchFn(firstAttempt);
  if (!isHyroviChallengeResponse(response)) return response;

  const challenge = await readHyroviChallenge(response, {
    requestUrl: request.url,
    fetch: fetchFn,
    signal: activeSignal,
  });
  if (typeof onChallenge === "function") onChallenge(challenge);

  const counter = await solveHyroviChallenge(challenge, {
    signal: activeSignal,
    yieldEvery,
    onProgress,
  });
  await verifyHyroviChallenge(request.url, challenge, counter, {
    fetch: fetchFn,
    signal: activeSignal,
  });

  const retried = await fetchFn(retryAttempt);
  if (isHyroviChallengeResponse(retried)) {
    throw new HyroviChallengeError(
      "Request was challenged again immediately after successful verification",
      {
        code: "RECHALLENGED",
        status: retried.status,
        response: retried,
      },
    );
  }
  return retried;
};
