/**
 * Development-only first-party helper for explicitly testing a persistent
 * visitor ID across fresh browser sessions. Never import from production UI.
 * It intentionally does not persist hyrovi_sid (one ID per browser session).
 */
const CONSENT = "hyrovi_analytics_consent";
const VISITOR = "hyrovi_visitor_id";
const SESSION = "hyrovi_sid";
const COOKIE_TTL = 90 * 86400;
const UUID_PATTERN = /^[a-f0-9-]{16,64}$/;

export type CookieTestEnvironment = {
	hostname: string;
	protocol: string;
	readCookies(): string;
	writeCookie(value: string): void;
	clearSession(): void;
	newId(): string;
	dnt: boolean;
	gpc: boolean;
};

export type CookieTestStatus = {
	supported: boolean;
	scope: string;
	optedIn: boolean;
	persistentIdPresent: boolean;
	idEnding: string | null;
	privacyBlocked: boolean;
};

function browserEnvironment(): CookieTestEnvironment {
	return {
		hostname: window.location.hostname,
		protocol: window.location.protocol,
		readCookies: () => document.cookie,
		writeCookie: (value) => { document.cookie = value; },
		clearSession: () => { try { sessionStorage.removeItem(SESSION); } catch { /* disabled */ } },
		newId: () => crypto.randomUUID(),
		dnt: navigator.doNotTrack === "1",
		gpc: (navigator as Navigator & { globalPrivacyControl?: boolean }).globalPrivacyControl === true,
	};
}

function cookieScope(env: CookieTestEnvironment) {
	const shared = env.hostname === "hyrovi.com" || env.hostname.endsWith(".hyrovi.com");
	const local = ["localhost", "127.0.0.1", "::1"].includes(env.hostname);
	if (!shared && !local) throw new Error("Cookie-Test nur auf HYROVI-Domains oder lokal verfügbar");
	if (shared && env.protocol !== "https:") throw new Error("Domainübergreifende Cookies erfordern HTTPS");
	return { shared, suffix: "; Path=/; SameSite=Lax" + (env.protocol === "https:" ? "; Secure" : "") + (shared ? "; Domain=.hyrovi.com" : "") };
}

function cookie(env: CookieTestEnvironment, name: string): string {
	const row = env.readCookies().split(";").map((value) => value.trim()).find((value) => value.startsWith(name + "="));
	if (!row) return "";
	try { return decodeURIComponent(row.slice(name.length + 1)); } catch { return ""; }
}

function setCookie(env: CookieTestEnvironment, name: string, value: string, maxAge: number) {
	const { suffix } = cookieScope(env);
	env.writeCookie(name + "=" + encodeURIComponent(value) + "; Max-Age=" + maxAge + suffix);
}

/** Read-only. Opening the panel never enables tracking. */
export function getVisitorCookieTestStatus(env: CookieTestEnvironment = browserEnvironment()): CookieTestStatus {
	let scope = "Nicht unterstützt";
	let supported = true;
	try { scope = cookieScope(env).shared ? ".hyrovi.com (alle Subdomains)" : env.hostname + " (nur lokal)"; }
	catch { supported = false; }
	const id = cookie(env, VISITOR);
	const privacyBlocked = env.dnt || env.gpc;
	return {
		supported, scope,
		optedIn: cookie(env, CONSENT) === "1" && !privacyBlocked,
		persistentIdPresent: UUID_PATTERN.test(id),
		idEnding: UUID_PATTERN.test(id) ? id.slice(-6) : null,
		privacyBlocked,
	};
}

/** Explicit opt-in for the developer's own browser; reuses a valid ID. */
export function enablePersistentTestVisitor(env: CookieTestEnvironment = browserEnvironment()) {
	cookieScope(env);
	if (env.dnt || env.gpc) throw new Error("Browser-Datenschutzeinstellung verhindert Besuchertracking");
	const existing = cookie(env, VISITOR);
	const id = UUID_PATTERN.test(existing) ? existing : env.newId();
	if (!UUID_PATTERN.test(id)) throw new Error("Ungültige Besucher-ID");
	setCookie(env, VISITOR, id, COOKIE_TTL);
	setCookie(env, CONSENT, "1", COOKIE_TTL);
	return getVisitorCookieTestStatus(env);
}

/** Never delete unrelated site login cookies. */
export function resetPersistentTestVisitor(env: CookieTestEnvironment = browserEnvironment()) {
	cookieScope(env);
	setCookie(env, CONSENT, "0", COOKIE_TTL);
	setCookie(env, VISITOR, "", 0);
	env.clearSession();
	return getVisitorCookieTestStatus(env);
}
