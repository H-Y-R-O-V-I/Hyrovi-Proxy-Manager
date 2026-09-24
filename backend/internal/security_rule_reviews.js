import fs from "node:fs";
import { randomUUID } from "node:crypto";
import errs from "../lib/error.js";

const SECURITY_DIR = "/data/nginx/hyrovi-security";
const REVIEWS_FILE = `${SECURITY_DIR}/rule-reviews.json`;
const MAX_REVIEWS = 5000;
const VERDICTS = new Set(["confirmed_attack", "expected", "false_positive"]);

let mutationQueue = Promise.resolve();

const withMutation = (operation) => {
	const run = mutationQueue.then(operation, operation);
	mutationQueue = run.catch(() => undefined);
	return run;
};

const normalizeId = (value, label) => {
	const id = String(value || "").trim();
	if (!/^[A-Za-z0-9._:-]{1,160}$/.test(id)) {
		throw new errs.ValidationError(`${label} is invalid`);
	}
	return id;
};

const normalizeVerdict = (value) => {
	const verdict = String(value || "").trim().toLowerCase();
	if (!VERDICTS.has(verdict)) {
		throw new errs.ValidationError("Rule-hit verdict must be confirmed_attack, expected or false_positive");
	}
	return verdict;
};

const writeTextAtomic = async (filePath, value) => {
	await fs.promises.mkdir(SECURITY_DIR, { recursive: true });
	const tmp = `${filePath}.tmp-${process.pid}-${randomUUID()}`;
	try {
		await fs.promises.writeFile(tmp, value, "utf8");
		await fs.promises.rename(tmp, filePath);
	} catch (err) {
		await fs.promises.unlink(tmp).catch(() => undefined);
		throw err;
	}
};

const writeJsonAtomic = (value) => writeTextAtomic(REVIEWS_FILE, `${JSON.stringify(value, null, 2)}\n`);

const readReviewsUnsafe = async () => {
	try {
		const value = JSON.parse(await fs.promises.readFile(REVIEWS_FILE, "utf8"));
		return Array.isArray(value) ? value : [];
	} catch (err) {
		if (err.code === "ENOENT") return [];
		if (err instanceof SyntaxError) throw new errs.ConfigurationError("Invalid HYROVI Sec rule-review state");
		throw err;
	}
};

const prepare = () =>
	withMutation(async () => {
		await fs.promises.mkdir(SECURITY_DIR, { recursive: true });
		try {
			await fs.promises.access(REVIEWS_FILE);
		} catch (_) {
			await writeJsonAtomic([]);
		}
	});

const listReviews = async ({ ruleId, requestId, limit = 5000 } = {}) => {
	const normalizedRuleId = ruleId ? normalizeId(ruleId, "Detection-rule ID") : null;
	const normalizedRequestId = requestId ? normalizeId(requestId, "Request ID") : null;
	const boundedLimit = Math.max(1, Math.min(MAX_REVIEWS, Number.parseInt(limit, 10) || MAX_REVIEWS));
	return (await readReviewsUnsafe())
		.filter((review) => !normalizedRuleId || review.ruleId === normalizedRuleId)
		.filter((review) => !normalizedRequestId || review.requestId === normalizedRequestId)
		.sort((left, right) => Date.parse(right.updatedAt) - Date.parse(left.updatedAt))
		.slice(0, boundedLimit);
};

const upsertReview = ({ ruleId, requestId, verdict }) =>
	withMutation(async () => {
		const normalizedRuleId = normalizeId(ruleId, "Detection-rule ID");
		const normalizedRequestId = normalizeId(requestId, "Request ID");
		const normalizedVerdict = normalizeVerdict(verdict);
		const reviews = await readReviewsUnsafe();
		const index = reviews.findIndex(
			(review) => review.ruleId === normalizedRuleId && review.requestId === normalizedRequestId,
		);
		const now = new Date().toISOString();
		const review = {
			id: index >= 0 ? reviews[index].id : randomUUID(),
			ruleId: normalizedRuleId,
			requestId: normalizedRequestId,
			verdict: normalizedVerdict,
			createdAt: index >= 0 ? reviews[index].createdAt : now,
			updatedAt: now,
		};
		if (index >= 0) {
			reviews[index] = review;
		} else {
			if (reviews.length >= MAX_REVIEWS) {
				throw new errs.ValidationError(`Rule-hit reviews are limited to ${MAX_REVIEWS}`);
			}
			reviews.push(review);
		}
		await writeJsonAtomic(reviews);
		return review;
	});

const deleteReview = ({ ruleId, requestId }) =>
	withMutation(async () => {
		const normalizedRuleId = normalizeId(ruleId, "Detection-rule ID");
		const normalizedRequestId = normalizeId(requestId, "Request ID");
		const reviews = await readReviewsUnsafe();
		const next = reviews.filter(
			(review) => !(review.ruleId === normalizedRuleId && review.requestId === normalizedRequestId),
		);
		if (next.length === reviews.length) return { success: true };
		await writeJsonAtomic(next);
		return { success: true };
	});

const deleteReviewsForRule = (ruleId) =>
	withMutation(async () => {
		const normalizedRuleId = normalizeId(ruleId, "Detection-rule ID");
		const reviews = await readReviewsUnsafe();
		const next = reviews.filter((review) => review.ruleId !== normalizedRuleId);
		if (next.length !== reviews.length) await writeJsonAtomic(next);
		return { success: true };
	});

const summarizeReviews = (reviews = []) => ({
	total: reviews.length,
	confirmedAttack: reviews.filter((review) => review.verdict === "confirmed_attack").length,
	expected: reviews.filter((review) => review.verdict === "expected").length,
	falsePositive: reviews.filter((review) => review.verdict === "false_positive").length,
});

export default {
	prepare,
	listReviews,
	upsertReview,
	deleteReview,
	deleteReviewsForRule,
	summarizeReviews,
};
