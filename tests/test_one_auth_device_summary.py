import sqlite3
import tempfile
import unittest
from pathlib import Path

from ops.one_auth_device_summary import read_one_auth_devices


class OneAuthSummaryTests(unittest.TestCase):
    def test_valid_and_historic_metadata_without_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "one.db"
            connection = sqlite3.connect(db)
            connection.executescript("""
                CREATE TABLE users(username TEXT, enabled INTEGER);
                CREATE TABLE trusted_logins(id TEXT,username TEXT,device_label TEXT,
                    created_at INTEGER,last_used_at INTEGER,expires_at INTEGER,absolute_expires_at INTEGER);
                CREATE TABLE sessions(token_hash TEXT,username TEXT,trusted_login_id TEXT,expires_at INTEGER);
                INSERT INTO users VALUES('example',1);
                INSERT INTO trusted_logins VALUES('secret-device-id','example','iPad Safari',20,90,200,300);
                INSERT INTO trusted_logins VALUES('old-id','example','Old Mac',10,30,40,50);
                INSERT INTO sessions VALUES('secret-token-hash','example','secret-device-id',150);
            """)
            connection.commit()
            connection.close()
            report = read_one_auth_devices(db, 100)
            self.assertTrue(report["available"])
            self.assertEqual(len(report["devices"]), 2)
            self.assertEqual(report["devices"][0]["validSessions"], 1)
            self.assertEqual(report["devices"][1]["validSessions"], 0)
            self.assertNotIn("secret-token-hash", str(report))
            self.assertNotIn("secret-device-id", str(report))
            self.assertEqual(read_one_auth_devices(db, 100)["devices"][0]["id"], report["devices"][0]["id"])
            self.assertEqual(connection_is_readonly(db), 2)

    def test_unavailable_is_explicit(self):
        self.assertEqual(read_one_auth_devices(Path("/unavailable/one.db"))["available"], False)


def connection_is_readonly(db: Path) -> int:
    connection = sqlite3.connect(db)
    count = connection.execute("SELECT COUNT(*) FROM trusted_logins").fetchone()[0]
    connection.close()
    return count


if __name__ == "__main__":
    unittest.main()
