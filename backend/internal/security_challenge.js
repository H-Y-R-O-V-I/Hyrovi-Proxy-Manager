import fs from "node:fs";
import net from "node:net";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import errs from "../lib/error.js";
import { global as logger } from "../logger.js";
import internalNginx from "./nginx.js";

const SECURITY_DIR = "/data/nginx/hyrovi-security";
const CHALLENGES_FILE = `${SECURITY_DIR}/challenges.json`;
const CHALLENGE_GEO_FILE = `${SECURITY_DIR}/challenged-ips.geo`;
const MAX_CHALLENGES = 5000;
const DEFAULT_DURATION_MINUTES = 10;
const DEFAULT_DIFFICULTY = 14;
const MAX_VERIFY_COUNTER = 50_000_000;
const MAX_VERIFY_ATTEMPTS = 25;
const INTERNAL_HEADER_VALUE = "challenge-v1";
const CHALLENGE_PATH = "/.well-known/hyrovi-sec/challenge";
const VERIFY_PATH = "/.well-known/hyrovi-sec/challenge/verify";

let mutationQueue = Promise.resolve();

const clamp = (value, min, max) => Math.max(min, Math.min(max, value));

const emergencyBypassEnabled = () =>
	/^(1|true|yes|on)$/i.test(String(process.env.HYROVI_SEC_EMERGENCY_BYPASS || "").trim());

const withMutation = (operation) => {
	const run = mutationQueue.then(operation, operation);
	mutationQueue = run.catch(() => undefined);
	return run;
};

const ensureSecurityDir = () => fs.promises.mkdir(SECURITY_DIR, { recursive: true });

const writeTextAtomic = async (filePath, value) => {
	await ensureSecurityDir();
	const tmp = `${filePath}.tmp-${process.pid}-${randomUUID()}`;
	try {
		await fs.promises.writeFile(tmp, value, "utf8");
		await fs.promises.rename(tmp, filePath);
	} catch (err) {
		await fs.promises.unlink(tmp).catch(() => undefined);
		throw err;
	}
};

const writeJsonAtomic = (filePath, value) => writeTextAtomic(filePath, `${JSON.stringify(value, null, 2)}\n`);

const readChallengesUnsafe = async () => {
	try {
		const value = JSON.parse(await fs.promises.readFile(CHALLENGES_FILE, "utf8"));
		return Array.isArray(value) ? value : [];
	} catch (err) {
		if (err.code === "ENOENT") return [];
		if (err instanceof SyntaxError) {
			logger.error("HYROVI Sec challenge state is invalid JSON; resetting challenges");
			return [];
		}
		throw err;
	}
};

const activeChallenges = (challenges, now = Date.now()) =>
	challenges.filter((challenge) => {
		const expiresAt = Date.parse(challenge.expiresAt);
		return (
			challenge &&
			typeof challenge === "object" &&
			net.isIP(challenge.ip) &&
			typeof challenge.id === "string" &&
			Number.isFinite(expiresAt) &&
			expiresAt > now
		);
	});

const renderGeo = (challenges) => {
	const lines = [
		"# Managed by HYROVI Sec. Do not edit manually.",
		"# Exact source IPs currently required to solve a HYROVI Sec challenge.",
	];
	if (emergencyBypassEnabled()) {
		lines.push("# EMERGENCY BYPASS ACTIVE: challenge state is preserved but not enforced.");
		return `${lines.join("\n")}\n`;
	}
	for (const challenge of activeChallenges(challenges)) {
		lines.push(`${challenge.ip} 1;`);
	}
	return `${lines.join("\n")}\n`;
};

const applyGeo = async (challenges) => {
	await ensureSecurityDir();
	let previous = "";
	try {
		previous = await fs.promises.readFile(CHALLENGE_GEO_FILE, "utf8");
	} catch (err) {
		if (err.code !== "ENOENT") throw err;
	}

	const next = renderGeo(challenges);
	if (previous === next) return false;
	await writeTextAtomic(CHALLENGE_GEO_FILE, next);
	try {
		await internalNginx.reload();
	} catch (err) {
		await writeTextAtomic(CHALLENGE_GEO_FILE, previous);
		try {
			await internalNginx.reload();
		} catch (_) {
			// Preserve the original reload error.
		}
		throw err;
	}
	return true;
};

const commitState = async (previous, next) => {
	await applyGeo(next);
	try {
		await writeJsonAtomic(CHALLENGES_FILE, next);
	} catch (err) {
		try {
			await applyGeo(previous);
		} catch (rollbackErr) {
			logger.error(`HYROVI Sec could not roll back challenge Nginx state: ${rollbackErr.message}`);
		}
		throw err;
	}
};

const purgeExpiredUnsafe = async () => {
	const challenges = await readChallengesUnsafe();
	const active = activeChallenges(challenges);
	if (active.length === challenges.length) {
		await applyGeo(active);
		return active;
	}
	await commitState(challenges, active);
	return active;
};

const purgeExpired = () => withMutation(purgeExpiredUnsafe);

const normalizeReason = (value) => String(value || "HYROVI Sec adaptive challenge").trim().slice(0, 300);

const createChallengeRecord = ({ ip, durationMinutes, difficulty, reason, source }) => {
	if (!net.isIP(ip)) throw new errs.ValidationError("A valid IPv4 or IPv6 address is required");
	const minutes = clamp(Number.parseInt(durationMinutes, 10) || DEFAULT_DURATION_MINUTES, 1, 120);
	const proofDifficulty = clamp(Number.parseInt(difficulty, 10) || DEFAULT_DIFFICULTY, 10, 22);
	const now = new Date();
	return {
		id: randomUUID(),
		ip,
		nonce: randomBytes(24).toString("hex"),
		difficulty: proofDifficulty,
		attempts: 0,
		maxAttempts: MAX_VERIFY_ATTEMPTS,
		reason: normalizeReason(reason),
		source: String(source || "manual").slice(0, 80),
		createdAt: now.toISOString(),
		expiresAt: new Date(now.getTime() + minutes * 60_000).toISOString(),
	};
};

const challengeIps = (items) =>
	withMutation(async () => {
		const challenges = await purgeExpiredUnsafe();
		const next = [...challenges];
		const byIp = new Map(challenges.map((challenge) => [challenge.ip, challenge]));
		const result = [];
		let changed = false;

		for (const item of Array.isArray(items) ? items : []) {
			const ip = String(item?.ip || "").trim();
			if (!net.isIP(ip)) throw new errs.ValidationError("A valid IPv4 or IPv6 address is required");
			const existing = byIp.get(ip);
			if (existing) {
				result.push(existing);
				continue;
			}
			if (next.length >= MAX_CHALLENGES) {
				throw new errs.ValidationError(`Active challenges are limited to ${MAX_CHALLENGES}`);
			}
			const challenge = createChallengeRecord({ ...item, ip });
			next.push(challenge);
			byIp.set(ip, challenge);
			result.push(challenge);
			changed = true;
		}

		if (changed) await commitState(challenges, next);
		return result;
	});

const challengeIp = async (item) => {
	const [challenge] = await challengeIps([item]);
	return challenge;
};

const removeChallenge = ({ id, ip }) =>
	withMutation(async () => {
		const challenges = await purgeExpiredUnsafe();
		const removed = challenges.find(
			(challenge) => (id && challenge.id === id) || (ip && challenge.ip === ip),
		);
		if (!removed) return null;
		await commitState(challenges, challenges.filter((challenge) => challenge.id !== removed.id));
		return removed;
	});

const listChallenges = () => withMutation(purgeExpiredUnsafe);

const publicChallenge = (challenge) => ({
	version: 1,
	id: challenge.id,
	nonce: challenge.nonce,
	difficulty: challenge.difficulty,
	expiresAt: challenge.expiresAt,
	algorithm: "sha256-leading-zero-bits",
	input: "<challenge-id>:<nonce>:<counter>",
	challengePath: CHALLENGE_PATH,
	verifyPath: VERIFY_PATH,
	maxCounter: MAX_VERIFY_COUNTER,
	attemptsRemaining: Math.max(0, challenge.maxAttempts - challenge.attempts),
});

const challengeResponseHeaders = (challenge) => ({
	"X-Hyrovi-Sec-Challenge": "required",
	"X-Hyrovi-Sec-Challenge-Version": String(challenge.version),
	"X-Hyrovi-Sec-Challenge-ID": challenge.id,
	"X-Hyrovi-Sec-Challenge-Algorithm": challenge.algorithm,
	"X-Hyrovi-Sec-Challenge-Difficulty": String(challenge.difficulty),
	"X-Hyrovi-Sec-Challenge-Expires": challenge.expiresAt,
	"X-Hyrovi-Sec-Challenge-Input": challenge.input,
	"X-Hyrovi-Sec-Challenge-Max-Counter": String(challenge.maxCounter),
	"X-Hyrovi-Sec-Challenge-Attempts-Remaining": String(challenge.attemptsRemaining),
	"X-Hyrovi-Sec-Challenge-Endpoint": challenge.challengePath,
	"X-Hyrovi-Sec-Challenge-Verify": challenge.verifyPath,
});

const getChallengeForIp = (ip) =>
	withMutation(async () => {
		const challenges = await purgeExpiredUnsafe();
		const challenge = challenges.find((entry) => entry.ip === ip);
		return challenge ? publicChallenge(challenge) : null;
	});

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

const verify = ({ ip, id, counter }) =>
	withMutation(async () => {
		const challenges = await purgeExpiredUnsafe();
		const challenge = challenges.find((entry) => entry.ip === ip && entry.id === id);
		if (!challenge) throw new errs.ItemNotFoundError("challenge");

		let normalizedCounter;
		if (typeof counter === "number") {
			normalizedCounter = counter;
		} else if (typeof counter === "string" && /^\d{1,8}$/.test(counter)) {
			normalizedCounter = Number(counter);
		} else {
			throw new errs.ValidationError("Invalid challenge counter");
		}
		if (!Number.isSafeInteger(normalizedCounter) || normalizedCounter < 0 || normalizedCounter > MAX_VERIFY_COUNTER) {
			throw new errs.ValidationError("Invalid challenge counter");
		}
		if (challenge.attempts >= challenge.maxAttempts) {
			throw new errs.ValidationError("Challenge verification attempt limit reached");
		}

		const digest = createHash("sha256")
			.update(`${challenge.id}:${challenge.nonce}:${normalizedCounter}`)
			.digest();
		const verified = leadingZeroBits(digest) >= challenge.difficulty;
		if (!verified) {
			const next = challenges.map((entry) =>
				entry.id === challenge.id ? { ...entry, attempts: entry.attempts + 1 } : entry,
			);
			await writeJsonAtomic(CHALLENGES_FILE, next);
			return {
				verified: false,
				attemptsRemaining: Math.max(0, challenge.maxAttempts - challenge.attempts - 1),
			};
		}

		await commitState(challenges, challenges.filter((entry) => entry.id !== challenge.id));
		return { verified: true, attemptsRemaining: challenge.maxAttempts - challenge.attempts };
	});

const proxyContext = (headers = {}) => {
	if (headers["x-hyrovi-sec-internal"] !== INTERNAL_HEADER_VALUE) {
		throw new errs.ItemNotFoundError();
	}
	const ip = String(headers["x-hyrovi-sec-source-ip"] || "").trim();
	if (!net.isIP(ip)) throw new errs.ItemNotFoundError();
	const originalUriRaw = String(headers["x-hyrovi-sec-original-uri"] || "/").replace(/[\r\n]/g, "");
	const originalUri =
		originalUriRaw.startsWith("/") && !originalUriRaw.startsWith("//") && !originalUriRaw.includes("\\")
			? originalUriRaw.slice(0, 2048)
			: "/";
	return {
		ip,
		originalUri,
		accept: String(headers.accept || ""),
	};
};

const renderHtml = (challenge, originalUri) => {
	const challengeJson = JSON.stringify(challenge).replace(/</g, "\\u003c");
	const originalJson = JSON.stringify(originalUri).replace(/</g, "\\u003c");
	return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>HYROVI Sec verification</title>
<style>
body{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#101218;color:#eef1f7;margin:0;min-height:100vh;display:grid;place-items:center}
main{width:min(520px,calc(100% - 32px));border:1px solid #313746;padding:28px;background:#171b24}
h1{font-size:24px;margin:0 0 10px}p{line-height:1.5;color:#aeb7c7}.status{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:#e7c46b}
button{font:inherit;padding:10px 14px;border:1px solid #566174;background:#202633;color:#fff;cursor:pointer}
</style>
</head>
<body>
<main>
<h1>HYROVI Sec verification</h1>
<p>This source triggered adaptive protection. Your browser is solving a small local proof before the request can continue.</p>
<p class="status" id="status">Starting verification…</p>
<button id="retry" hidden>Retry</button>
</main>
<script>
const challenge=${challengeJson};
const originalUri=${originalJson};
const statusNode=document.getElementById("status");
const retry=document.getElementById("retry");
const encoder=new TextEncoder();
function hasLeadingZeroBits(bytes,bits){
  let remaining=bits;
  for(const byte of bytes){
    if(remaining<=0)return true;
    if(remaining>=8){if(byte!==0)return false;remaining-=8;continue;}
    return (byte>>(8-remaining))===0;
  }
  return remaining<=0;
}
async function solve(){
  statusNode.textContent="Solving proof…";
  for(let counter=0;counter<=50000000;counter++){
    const input=encoder.encode(challenge.id+":"+challenge.nonce+":"+counter);
    const digest=new Uint8Array(await crypto.subtle.digest("SHA-256",input));
    if(hasLeadingZeroBits(digest,challenge.difficulty)){
      statusNode.textContent="Verifying proof…";
      const response=await fetch(challenge.verifyPath,{
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify({id:challenge.id,counter})
      });
      const result=await response.json().catch(()=>({verified:false}));
      if(response.ok&&result.verified){
        statusNode.textContent="Verified. Continuing…";
        location.replace(originalUri);
        return;
      }
      throw new Error(result?.error?.message||"Verification rejected");
    }
    if(counter%250===0) await new Promise((resolve)=>requestAnimationFrame(resolve));
  }
  throw new Error("Proof search limit reached");
}
retry.addEventListener("click",()=>location.replace(originalUri));
solve().catch((err)=>{
  statusNode.textContent="Verification failed: "+err.message;
  retry.hidden=false;
});
</script>
</body>
</html>`;
};

const prepare = () =>
	withMutation(async () => {
		await ensureSecurityDir();
		return purgeExpiredUnsafe();
	});

const internalSecurityChallenge = {
	prepare,
	purgeExpired,
	listChallenges,
	challengeIp,
	challengeIps,
	removeChallenge,
	getChallengeForIp,
	verify,
	proxyContext,
	renderHtml,
	challengeResponseHeaders,
	challengePath: CHALLENGE_PATH,
	verifyPath: VERIFY_PATH,
};

export default internalSecurityChallenge;
