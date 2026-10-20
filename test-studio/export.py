#!/usr/bin/env python3
"""Bounded, private, user-started test-lab session snapshot, VPS -> Pi."""
import datetime as dt
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import time

DB = Path("/var/lib/hyrovi-test-studio/events.sqlite3")
DEST = "/opt/hyrovi-hpm/runtime/vps-hpm-sync/tests-studio.json"
SAFE_HEX = re.compile(r"^[a-f0-9]{64}$")
SAFE_KIND = {"page", "button", "scroll", "heartbeat", "section", "visible"}
SAFE_DETAIL = {"home", "features", "activity", "about", "tap", "toggle", "counter", "reset",
               "scroll25", "scroll50", "scroll75", "scroll100", "focus", "hidden", "visible", "open"}
now = time.time()
sessions = []
if DB.exists():
    con = sqlite3.connect("file:" + str(DB) + "?mode=ro", uri=True, timeout=4)
    for sid, name, started, last, browser, platform, language, signature in con.execute(
        "SELECT id,alias,started,last,browser,platform,language,signature FROM sessions WHERE last>? ORDER BY last DESC LIMIT 100", (now-86400,)
    ):
        if not SAFE_HEX.fullmatch(sid):
            continue
        raw = con.execute(
            "SELECT at,kind,detail FROM events WHERE session=? ORDER BY id DESC LIMIT 250", (sid,)
        ).fetchall()
        events = [
            {"at": dt.datetime.fromtimestamp(at, dt.timezone.utc).isoformat(), "kind":kind, "detail":detail}
            for at,kind,detail in reversed(raw) if kind in SAFE_KIND and detail in SAFE_DETAIL
        ]
        counts = dict(con.execute("SELECT kind,count(*) FROM events WHERE session=? GROUP BY kind", (sid,)).fetchall())
        button = counts.get("button", 0)
        sections = counts.get("section", 0)
        views = counts.get("page", 0)
        scrolls = counts.get("scroll", 0)
        heartbeats = counts.get("heartbeat", 0)
        # Real test actions dominate idle heartbeat time.
        activity_score = button*4 + sections*2 + views + scrolls
        sessions.append({
            "id": sid,
            "name": str(name)[:32],
            "browser":str(browser)[:32],
            "platform":str(platform)[:32],
            "language":str(language)[:32],
            "signature":str(signature)[:20],
            "started": dt.datetime.fromtimestamp(started, dt.timezone.utc).isoformat(),
            "last": dt.datetime.fromtimestamp(last, dt.timezone.utc).isoformat(),
            "active": now-last < 32,
            "buttonActions": button,
            "pageViews": views,
            "sectionChanges": sections,
            "scrollActions": scrolls,
            "heartbeats": heartbeats,
            "eventsCount": sum(counts.values()),
            "activityScore": activity_score,
            "durationSeconds": max(0, min(7200,int(last-started))),
            "events":events
        })
    con.close()
sessions.sort(key=lambda s:(-s["activityScore"],-dt.datetime.fromisoformat(s["last"]).timestamp()))
payload = {"schema":1, "generatedAt":dt.datetime.fromtimestamp(now,dt.timezone.utc).isoformat(),
           "scope":"tests.hyrovi.com", "sessions":sessions}
data = (json.dumps(payload,ensure_ascii=False,separators=(",",":"))+"\n").encode()
if len(data)>750_000:
    # Keep ranking totals exact while shortening only the optional event tail.
    for session in sessions:
        session["events"] = session["events"][-60:]
    data = (json.dumps(payload,ensure_ascii=False,separators=(",",":"))+"\n").encode()
if len(data)>750_000:
    payload["sessions"] = sessions[:50]
    data = (json.dumps(payload,ensure_ascii=False,separators=(",",":"))+"\n").encode()
if len(data)>750_000:
    raise RuntimeError("test snapshot exceeds 750KB bounded limit")
result = subprocess.run(["ssh","-o","BatchMode=yes","-o","ConnectTimeout=5","pi5",
    "umask 077; cat > "+DEST+".tmp && mv "+DEST+".tmp "+DEST],
    input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=12)
if result.returncode:
    sys.stderr.write("test session export unavailable\n")
    raise SystemExit(result.returncode)
print(json.dumps({"sessions":len(sessions),"active":sum(s["active"] for s in sessions),
                  "events":sum(s["eventsCount"] for s in sessions),"bytes":len(data)}))
