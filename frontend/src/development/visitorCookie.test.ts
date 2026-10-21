import { describe, it, expect } from "vitest";
import {
	enablePersistentTestVisitor, getVisitorCookieTestStatus,
	resetPersistentTestVisitor, type CookieTestEnvironment
} from "./visitorCookie";

function makeBrowser(hostname: string, sharedCookies: Map<string, string>, opts: Partial<CookieTestEnvironment> = {}) {
	const writes: string[] = [];
	let currentSessionReset = false;
	const env: CookieTestEnvironment = {
		hostname, protocol: "https:", dnt: false, gpc: false,
		readCookies: () => [...sharedCookies].map(([name, value]) => name + "=" + value).join("; "),
		writeCookie: (value) => {
			writes.push(value);
			const [keyValue] = value.split(";");
			const equal = keyValue.indexOf("=");
			const name = keyValue.slice(0, equal);
			const item = keyValue.slice(equal + 1);
			if (value.includes("Max-Age=0")) sharedCookies.delete(name);
			else sharedCookies.set(name, item);
		},
		clearSession: () => { currentSessionReset = true; },
		newId: () => "fa2e9780-1dc7-47e5-acb1-f1497898ea15",
		...opts
	};
	return { env, writes, reset: () => currentSessionReset };
}

describe("Development: visitor cookie across sessions", () => {
	it("has no tracking side effects before a developer clicks", () => {
		const jar = new Map<string, string>();
		const browser = makeBrowser("stoneapp.hyrovi.com", jar);
		expect(getVisitorCookieTestStatus(browser.env).optedIn).toBe(false);
		expect(browser.writes).toHaveLength(0);
		expect(jar.size).toBe(0);
	});

	it("reuses the same 90-day cookie across closed sessions and HYROVI hosts", () => {
		const jar = new Map<string, string>();
		const firstSession = makeBrowser("stoneapp.hyrovi.com", jar);
		const first = enablePersistentTestVisitor(firstSession.env);
		expect(first.optedIn).toBe(true);
		expect(first.persistentIdPresent).toBe(true);
		expect(firstSession.writes).toHaveLength(2);
		expect(firstSession.writes.every((v) => v.includes("Domain=.hyrovi.com") && v.includes("Max-Age=7776000") && v.includes("Secure"))).toBe(true);
		const id = jar.get("hyrovi_visitor_id");

		const nextSession = makeBrowser("ai.hyrovi.com", jar);
		expect(getVisitorCookieTestStatus(nextSession.env).idEnding).toBe(first.idEnding);
		enablePersistentTestVisitor(nextSession.env);
		expect(jar.get("hyrovi_visitor_id")).toBe(id);
		expect(jar.has("hyrovi_sid")).toBe(false);
	});

	it("respects browser DNT and GPC controls", () => {
		for (const privacy of [{ dnt: true }, { gpc: true }]) {
			const browser = makeBrowser("ai.hyrovi.com", new Map(), privacy);
			expect(() => enablePersistentTestVisitor(browser.env)).toThrow(/Datenschutzeinstellung/);
			expect(browser.writes).toHaveLength(0);
		}
	});

	it("rejects untrusted origins and HTTP on HYROVI domain", () => {
		for (const overrides of [
			{ hostname: "example.com" },
			{ hostname: "fakehyrovi.com" },
			{ hostname: "ai.hyrovi.com", protocol: "http:" }
		]) {
			const browser = makeBrowser("ai.hyrovi.com", new Map(), overrides);
			expect(() => enablePersistentTestVisitor(browser.env)).toThrow();
			expect(browser.writes).toHaveLength(0);
		}
	});

	it("resets analytics cookies, never unrelated site login cookies", () => {
		const jar = new Map<string, string>([["site_login", "untouched"]]);
		const browser = makeBrowser("ai.hyrovi.com", jar);
		enablePersistentTestVisitor(browser.env);
		const status = resetPersistentTestVisitor(browser.env);
		expect(status.optedIn).toBe(false);
		expect(status.persistentIdPresent).toBe(false);
		expect(jar.get("site_login")).toBe("untouched");
		expect(browser.reset()).toBe(true);
	});
});
