#!/usr/bin/env python3
"""Isolated, explicitly started HYROVI test-site sessions. No cookies or identity fingerprints."""
import hashlib
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("HYROVI_TEST_DB", str(ROOT / "data" / "events.sqlite3")))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
os.chmod(DB_PATH.parent, 0o700)
PORT = int(os.environ.get("HYROVI_TEST_PORT", "7346"))
HOST = os.environ.get("HYROVI_TEST_BIND", "127.0.0.1")
KINDS = {"page", "button", "scroll", "heartbeat", "section", "visible"}
DETAILS = {"home", "features", "activity", "about", "tap", "toggle", "counter", "reset",
           "scroll25", "scroll50", "scroll75", "scroll100", "focus", "hidden", "visible", "open"}
MAX_EVENTS_PER_SESSION = 1200
LOCK = threading.RLock()

def conn():
    c = sqlite3.connect(DB_PATH, timeout=3)
    c.execute("PRAGMA busy_timeout=3000")
    return c


with conn() as c:
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, alias TEXT NOT NULL, started REAL NOT NULL, last REAL NOT NULL)")
    c.execute("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, session TEXT NOT NULL, at REAL NOT NULL, kind TEXT NOT NULL, detail TEXT NOT NULL)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_test_events_session ON events(session,at)")
    columns = {row[1] for row in c.execute("PRAGMA table_info(sessions)")}
    for col in ("browser", "platform", "language", "signature", "diagnostics"):
        if col not in columns:
            c.execute("ALTER TABLE sessions ADD COLUMN " + col + " TEXT NOT NULL DEFAULT ''")
os.chmod(DB_PATH, 0o600)


def safe_alias(value):
    value = re.sub(r"[^a-zA-Z0-9äöüÄÖÜß _-]", "", str(value or "").strip())
    return value[:32] or "Test-Besucher"


def browser_diagnostics(headers):
    ua = str(headers.get("User-Agent", ""))[:512]
    lang = str(headers.get("Accept-Language", "")).split(",", 1)[0][:32]
    if "Edg/" in ua: browser = "Edge"
    elif "Firefox/" in ua or "FxiOS/" in ua: browser = "Firefox"
    elif "Chrome/" in ua or "CriOS/" in ua: browser = "Chrome"
    elif "Safari/" in ua: browser = "Safari"
    else: browser = "Unbekannt"
    if "iPad" in ua: platform = "iPadOS"
    elif "iPhone" in ua or "iPod" in ua: platform = "iOS"
    elif "Android" in ua: platform = "Android"
    elif "Mac OS X" in ua: platform = "macOS"
    elif "Windows" in ua: platform = "Windows"
    elif "Linux" in ua: platform = "Linux"
    else: platform = "Unbekannt"
    # No hardware or HTTP fingerprint is calculated. Each test session is
    # an independent, user-started unit with a random session token.
    return browser, platform, lang, ""


def sanitized_diagnostics(value):
    # Test-start only. Coarse capability properties are for diagnostics,
    # never included in fingerprint grouping or used across origins.
    if not isinstance(value, dict):
        return {}
    allowed = {
        "timezone": r"[A-Za-z0-9/_+:-]{1,70}",
        "screen": r"(?:small|medium|large|xlarge)",
        "viewport": r"(?:small|medium|large|xlarge)",
        "touch": r"(?:none|single|multi)",
        "cpu": r"(?:unknown|1-2|3-4|5-8|9+)",
        "memory": r"(?:unknown|<=2|3-4|5-8|9+)",
        "theme": r"(?:dark|light)",
        "motion": r"(?:reduced|normal)",
        "pixelRatio": r"(?:1|2|3\+)",
        "deviceType": r"(?:mobile|tablet|desktop)",
        "screenPixels": r"[0-9]{2,5}x[0-9]{2,5}",
        "viewportPixels": r"[0-9]{2,5}x[0-9]{2,5}",
        "colorDepth": r"(?:16|24|30|32|other)",
        "orientation": r"(?:landscape|portrait)",
        "connection": r"(?:slow-2g|2g|3g|4g|unknown)",
        "features": r"(?:webgl|wasm|service-worker|touch-events)(?:,(?:webgl|wasm|service-worker|touch-events)){0,3}|",
    }
    return {k: v for k, rule in allowed.items()
            if isinstance((v := value.get(k)), str) and re.fullmatch(rule, v)}


def session_hash(token):
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,64}", token):
        return None
    return hashlib.sha256(("hyrovi-test-session-v1:" + token).encode()).hexdigest()


class Handler(BaseHTTPRequestHandler):
    server_version = "HYROVI-TestStudio"
    def log_message(self, fmt, *args):
        # No IPs, identities, tokens, paths, or request payloads in service stdout.
        return

    def headers_base(self, code=200, content_type="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        self.end_headers()

    def answer(self, code, obj):
        self.headers_base(code)
        self.wfile.write(json.dumps(obj, separators=(",", ":")).encode())

    def do_GET(self):
        route = urlsplit(self.path).path
        if route == "/healthz":
            return self.answer(200, {"ok": True, "site": "tests.hyrovi.com"})
        if route in ("/", "/index.html"):
            src, ct = "index.html", "text/html; charset=utf-8"
        elif route == "/app.js":
            src, ct = "app.js", "text/javascript; charset=utf-8"
        elif route == "/styles.css":
            src, ct = "styles.css", "text/css; charset=utf-8"
        else:
            return self.answer(404, {"error": "not_found"})
        self.headers_base(200, ct)
        self.wfile.write((ROOT / src).read_bytes())

    def do_POST(self):
        route = urlsplit(self.path).path
        if route not in ("/api/start", "/api/event"):
            return self.answer(404, {"error": "not_found"})
        try:
            n = int(self.headers.get("Content-Length", "0"))
            if n < 2 or n > 1024:
                return self.answer(413, {"error": "size_limit"})
            raw = json.loads(self.rfile.read(n))
            if not isinstance(raw, dict):
                return self.answer(400, {"error": "bad_request"})
        except (ValueError, TypeError, json.JSONDecodeError):
            return self.answer(400, {"error": "bad_request"})
        now = time.time()
        if route == "/api/start":
            alias = safe_alias(raw.get("alias", ""))
            token = secrets.token_urlsafe(24)
            sid = session_hash(token)
            browser,platform,language,signature = browser_diagnostics(self.headers)
            diagnostics = json.dumps(sanitized_diagnostics(raw.get("diagnostics")), separators=(",", ":"))
            with LOCK, conn() as c:
                # Small, bounded public lab: avoid unbounded session creation.
                recent = c.execute("SELECT count(*) FROM sessions WHERE started>?", (now - 3600,)).fetchone()[0]
                if recent >= 100:
                    return self.answer(429, {"error": "test_capacity_reached"})
                c.execute("INSERT INTO sessions (id, alias, started, last, browser, platform, language, signature, diagnostics) VALUES (?,?,?,?,?,?,?,?,?)",
                          (sid, alias, now, now, browser, platform, language, signature, diagnostics))
                c.execute("DELETE FROM events WHERE at < ?", (now - 86400,))
                c.execute("DELETE FROM sessions WHERE last < ?", (now - 86400,))
            return self.answer(201, {"session": token, "alias": alias})
        sid = session_hash(self.headers.get("X-Test-Session", ""))
        if not sid:
            return self.answer(401, {"error": "session_required"})
        kind, detail = raw.get("kind"), raw.get("detail")
        if kind not in KINDS or detail not in DETAILS:
            return self.answer(400, {"error": "unsupported_event"})
        with LOCK, conn() as c:
            valid = c.execute("SELECT id,last FROM sessions WHERE id=?", (sid,)).fetchone()
            if not valid or now - valid[1] > 7200:
                return self.answer(401, {"error": "expired_session"})
            count = c.execute("SELECT count(*) FROM events WHERE session=?", (sid,)).fetchone()[0]
            recent = c.execute("SELECT count(*) FROM events WHERE session=? AND at>?", (sid, now-60)).fetchone()[0]
            if count >= MAX_EVENTS_PER_SESSION or recent >= 120:
                return self.answer(429, {"error": "event_limit"})
            c.execute("INSERT INTO events(session,at,kind,detail) VALUES(?,?,?,?)", (sid, now, kind, detail))
            c.execute("UPDATE sessions SET last=? WHERE id=?", (now, sid))
        return self.answer(202, {"ok": True})


def cleanup_expired_sessions():
    while True:
        time.sleep(1800)
        try:
            with LOCK, conn() as c:
                now = time.time()
                c.execute("DELETE FROM events WHERE at < ?", (now - 86400,))
                c.execute("DELETE FROM sessions WHERE last < ?", (now - 86400,))
        except (sqlite3.Error, OSError):
            pass


if __name__ == "__main__":
    threading.Thread(target=cleanup_expired_sessions, daemon=True).start()
    print("HYROVI Test Studio listening at 127.0.0.1:" + str(PORT), flush=True)
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
