import { createHash } from "node:crypto";

export const SIGNATURE_CONTEXT = "HYROVI-SEC-DEVICE-V1";

export const stableJson = (value) => {
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

export const signingMessage = ({ deviceId, sequence, timestamp, body }) => {
	const bodyHash = createHash("sha256").update(stableJson(body ?? {})).digest("hex");
	return [SIGNATURE_CONTEXT, deviceId, String(sequence), String(timestamp), bodyHash].join("\n");
};
