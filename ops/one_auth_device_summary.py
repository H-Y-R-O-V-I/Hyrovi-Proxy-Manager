"""Read-only HYROVI One login-device metadata for the private HPM admin report.

Never exports session tokens, CSRF secrets, trusted-cookie hashes or raw login IDs.
An unexpired session is NOT proof that a browser tab or physical device is online.
"""

from __future__ import annotations

import hashlib
import sqlite3
import time
from pathlib import Path

DEFAULT_DB = Path("/var/lib/hyrovi-one/hyrovi-one.db")


def _label(value: object, limit: int = 80) -> str:
    return "".join(c for c in str(value or "") if c.isprintable() and c not in "<>")[:limit]


def read_one_auth_devices(db_path: Path = DEFAULT_DB, now: int | None = None) -> dict:
    """Return bounded account/device/session *metadata*; never modify One's DB."""
    timestamp = int(time.time()) if now is None else int(now)
    result: dict = {"available": False, "devices": [], "meaning": "session-validity-not-presence"}
    if not db_path.is_file():
        return result
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=2)
        try:
            conn.execute("PRAGMA query_only=ON")
            rows = conn.execute(
                "SELECT t.id,t.username,t.device_label,t.created_at,t.last_used_at,"
                "t.expires_at,t.absolute_expires_at,u.enabled,"
                "COUNT(s.token_hash) AS valid_sessions "
                "FROM trusted_logins t JOIN users u ON u.username=t.username "
                "LEFT JOIN sessions s ON s.trusted_login_id=t.id "
                "AND s.username=t.username AND s.expires_at>? "
                "GROUP BY t.id ORDER BY t.last_used_at DESC LIMIT 200",
                (timestamp,),
            ).fetchall()
        finally:
            conn.close()
    except (sqlite3.Error, OSError, ValueError):
        return result
    devices = []
    for id_value, username, label, created, used, expires, absolute, enabled, count in rows:
        valid = bool(enabled and expires > timestamp and absolute > timestamp and count)
        devices.append({
            "id": hashlib.sha256(("hpm-one-device-v1:" + str(id_value)).encode()).hexdigest()[:24],
            "account": _label(username, 60),
            "label": _label(label) or "Unbenannter Browser",
            "firstLogin": int(created),
            "lastUsed": int(used),
            "trustedUntil": min(int(expires), int(absolute)),
            "validSessions": min(100, int(count)) if valid else 0,
            "accountEnabled": bool(enabled),
        })
    result.update(available=True, devices=devices)
    return result
