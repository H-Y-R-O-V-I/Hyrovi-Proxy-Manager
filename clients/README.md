# HYROVI Sec challenge clients

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
