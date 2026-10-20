#!/usr/bin/env python3
"""One-way, sanitised VPS HPM -> Raspberry Pi HPM activity aggregation.

Does not transport source IPs, user-agents, cookies, fingerprints,
unconsented session IDs, raw access-log lines or query parameters.
"""
from __future__ import annotations

import collections
import hashlib
import datetime as dt
import json
import os
import re
import subprocess
import sys
from pathlib import Path

VPS_LOGS = Path("/opt/nginx-proxy-manager/data/logs")
DEST = "/opt/hyrovi-hpm/runtime/vps-hpm-sync/vps-hpm-activity.json"
HOST_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,251}$")
HEX64 = re.compile(r"^[a-f0-9]{64}$")
ROUTE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]{0,39}$")
SENSITIVE = {"admin", "account", "login", "logout", "auth", "signin",
             "password", "oauth", "token", "secret", "vault", "payment",
             "checkout", "billing", "profile", "user", "users", "private"}
KINDS = {"page_view", "engagement", "scroll", "route_change", "action"}
NOW = dt.datetime.now(dt.timezone.utc)
CUTOFF = NOW - dt.timedelta(hours=24)


def file_tail(filename: Path, max_bytes: int):
    if not filename.is_file():
        return []
    with filename.open("rb") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        f.seek(max(0, size - max_bytes))
        if size > max_bytes:
            f.readline()
        return f.read().decode("utf-8", "replace").splitlines()


def valid_time(s: object):
    try:
        t = dt.datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        if t.tzinfo is None:
            return None
        return t.astimezone(dt.timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return None


def safe_host(val: object):
    host = str(val or "").strip().lower()[:253]
    return host if HOST_RE.fullmatch(host) and "." in host else None


def safe_section(val: object):
    value = str(val or "").split("?", 1)[0].split("#", 1)[0]
    parts = value.lstrip("/").split("/")
    if not parts or not ROUTE.fullmatch(parts[0]):
        return "/"
    return "/[restricted]" if parts[0].lower() in SENSITIVE else "/" + parts[0]


def safe_consented_path(val: object):
    val = str(val or "/").split("?", 1)[0].split("#", 1)[0]
    parts = [p for p in val.split("/") if p]
    if any(p.lower() in SENSITIVE for p in parts):
        return "/[restricted]"
    keep = []
    for p in parts[:3]:
        if ROUTE.fullmatch(p) and not any(c.isdigit() for c in p):
            keep.append(p)
        else:
            keep.append("[dynamic]")
    return "/" + "/".join(keep) if keep else "/"


def grouped_site(host: str):
    if host not in sites:
        sites[host] = dict(host=host, source="VPS", requests=0, pages=0, writes=0,
                           failures=0, latest=None, sections=collections.Counter(),
                           browserViews=0, browserActions=0, browserScroll=0,
                           browserEngagementSeconds=0, browserLastSeen=None,
                           clientSignatures=set(), automationSignals=0)
    return sites[host]


sites = {}
requests = 0
browser_events = 0
consented = []
anonymous_browser_events = []
for row in file_tail(VPS_LOGS / "hyrovi-sec.log", 2 * 1024 * 1024):
    try:
        e = json.loads(row)
    except (TypeError, ValueError):
        continue
    host = safe_host(e.get("host"))
    status = e.get("status")
    method = str(e.get("method") or "").upper()
    when = valid_time(e.get("ts") or e.get("timestamp"))
    try:
        status = int(status)
    except (ValueError, TypeError):
        continue
    if not host or not when or when < CUTOFF or not 100 <= status <= 599:
        continue
    if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
        continue
    w = grouped_site(host)
    # Per-host security signature TYPES from headers already sent to the proxy.
    # Never export a stable per-client signature or correlate across sites.
    header_tuple = [str(e.get(k) or "").strip().lower()[:320] for k in
                    ("user_agent", "accept_language", "sec_ch_ua", "sec_ch_ua_mobile", "sec_ch_ua_platform")]
    if any(header_tuple):
        w["clientSignatures"].add(hashlib.sha256("\x00".join(header_tuple).encode()).digest()[:12])
    if re.search(r"bot|crawler|spider|curl/|wget/|python-requests|scrapy", header_tuple[0]):
        w["automationSignals"] += 1
    requests += 1
    w["requests"] += 1
    if method == "GET" and (str(e.get("accept") or "").lower().find("text/html") >= 0 or e.get("path") == "/"):
        w["pages"] += 1
    if method in {"POST", "PUT", "PATCH", "DELETE"}:
        w["writes"] += 1
    if status >= 400:
        w["failures"] += 1
    rounded = when.replace(minute=(when.minute // 5) * 5, second=0, microsecond=0).isoformat()
    if not w["latest"] or rounded > w["latest"]:
        w["latest"] = rounded
    w["sections"][safe_section(e.get("path"))] += 1

for row in file_tail(VPS_LOGS / "hyrovi-analytics-events.log", 4 * 1024 * 1024):
    try:
        e = json.loads(row)
    except (ValueError, TypeError):
        continue
    host = safe_host(e.get("host"))
    timestamp = valid_time(e.get("timestamp"))
    kind = e.get("type")
    if not host or not timestamp or timestamp < CUTOFF or kind not in KINDS:
        continue
    w = grouped_site(host)
    browser_events += 1
    if kind in {"page_view", "route_change"}:
        w["browserViews"] += 1
    if kind == "action":
        w["browserActions"] += 1
    if kind == "scroll":
        w["browserScroll"] += 1
    if kind == "engagement":
        try:
            w["browserEngagementSeconds"] += max(0, min(3600, int(e.get("visibleSeconds") or 0)))
        except (TypeError, ValueError):
            pass
    # Coarse 5-minute latest browser telemetry, not an individual timestamp.
    coarse = timestamp.replace(minute=(timestamp.minute // 5) * 5, second=0, microsecond=0).isoformat()
    if not w["browserLastSeen"] or coarse > w["browserLastSeen"]:
        w["browserLastSeen"] = coarse

    # Independent browser-observed security events: NO device/session IDs,
    # and no attempt to join them into people or long-lived browser profiles.
    # Time is rounded to minutes, URL is reduced to the first safe path segment.
    if e.get("consent") is not True:
        anonymous_browser_events.append({
            "source": "VPS",
            "host": host,
            "type": kind,
            "time": timestamp.replace(second=0, microsecond=0).isoformat(),
            "section": safe_section(e.get("path")),
            "visibleSeconds": max(0, min(3600, int(e.get("visibleSeconds") or 0))),
            "scrollDepth": max(0, min(100, int(e.get("scrollDepth") or 0))),
        })

    # Individual browser records exist ONLY after explicit consent; remote
    # HMAC deviceKey is node-scoped and is NOT joined with Pi identity.
    if e.get("consent") is True and HEX64.fullmatch(str(e.get("deviceKey") or "")):
        consented.append({
            "id": str(e.get("id") or "")[:96],
            "timestamp": timestamp.isoformat(),
            "host": host,
            "type": kind,
            "path": safe_consented_path(e.get("path")),
            "deviceKey": e["deviceKey"],
            "sessionKey": str(e.get("sessionKey") or "") if HEX64.fullmatch(str(e.get("sessionKey") or "")) else None,
            "consent": True,
            "visibleSeconds": max(0, min(3600, int(e.get("visibleSeconds") or 0))),
            "scrollDepth": max(0, min(100, int(e.get("scrollDepth") or 0))),
            "language": str(e.get("language") or "")[:32],
            "timezone": str(e.get("timezone") or "")[:80],
            "viewport": str(e.get("viewport") or "")[:32],
            "browser": str(e.get("browser") or "")[:30],
            "platform": str(e.get("platform") or "")[:40],
            "action": str(e.get("action") or "")[:64] if kind == "action" else None,
        })

all_sites = []
for site in sites.values():
    site["clientSignatures"] = len(site["clientSignatures"])
    site["sections"] = [
        {"section": name, "count": count}
        for name, count in site["sections"].most_common(6)
    ]
    all_sites.append(site)
all_sites.sort(key=lambda x: (-x["requests"], -x["browserViews"], x["host"]))
payload = {
    "schema": 1,
    "generatedAt": NOW.isoformat(),
    "window": "VPS HPM recent traffic (24h; bounded log tail)",
    "requests": requests,
    "browserEvents": browser_events,
    "websites": all_sites[:100],
    "consentedEvents": consented[-1000:],
    "anonymousBrowserEvents": anonymous_browser_events[-240:],
}
data = (json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
if len(data) > 1_500_000:
    raise RuntimeError("Unexpected export size exceeds cap")

# Fixed remote command, no untrusted input.
remote_cmd = "umask 077; cat > " + DEST + ".tmp && mv " + DEST + ".tmp " + DEST
result = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=6",
                         "pi5", remote_cmd], input=data, timeout=18,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
if result.returncode != 0:
    sys.stderr.write(result.stderr.decode("utf-8", "replace")[:1200])
    raise SystemExit(result.returncode)
print(json.dumps({"requests": requests, "sites": len(all_sites),
                  "browserEvents": browser_events,
                  "stoneappBrowserViews": sites.get("stoneapp.hyrovi.com", {}).get("browserViews", 0),
                  "consentedBrowserEvents": len(consented), "payloadBytes": len(data)}))
