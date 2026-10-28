"""Database migration tests: a real v0.4 schema upgrades without losing events, incidents or statuses."""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from helpers import make_app

V04_SCHEMA = """
CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT NOT NULL, host TEXT NOT NULL, source_ip TEXT NOT NULL,
    actor TEXT NOT NULL, message TEXT NOT NULL, timestamp TEXT NOT NULL, mode TEXT NOT NULL CHECK(mode IN ('demo','imported')),
    agent_id TEXT NOT NULL DEFAULT '');
CREATE INDEX events_time_idx ON events(timestamp);
CREATE TABLE incidents (id INTEGER PRIMARY KEY AUTOINCREMENT, signature TEXT NOT NULL UNIQUE, title TEXT NOT NULL,
    severity TEXT NOT NULL, summary TEXT NOT NULL, source_ip TEXT NOT NULL, host TEXT NOT NULL, rule_id TEXT NOT NULL,
    event_count INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'open', first_seen TEXT NOT NULL, last_seen TEXT NOT NULL);
CREATE TABLE devices (agent_id TEXT PRIMARY KEY, name TEXT NOT NULL, platform TEXT NOT NULL, last_seen TEXT NOT NULL, first_seen TEXT NOT NULL);
"""


def build_v04(path):
    db = sqlite3.connect(path)
    db.executescript(V04_SCHEMA)
    rows = [("auth_failure", "bastion", "192.0.2.44", "admin", f"fail {i}", f"2026-10-27T10:0{i}:00+00:00", "demo", "") for i in range(6)]
    rows += [("policy_change", "fw", "10.0.0.1", "sec", "policy edited", "2026-10-27T10:10:00+00:00", "imported", "")]
    rows += [("service_error", "pc", "", "x", "from collector", "2026-10-27T10:11:00+00:00", "imported", "home-pc")]
    db.executemany("INSERT INTO events(type,host,source_ip,actor,message,timestamp,mode,agent_id) VALUES(?,?,?,?,?,?,?,?)", rows)
    db.execute("INSERT INTO incidents(signature,title,severity,summary,source_ip,host,rule_id,event_count,status,first_seen,last_seen) "
               "VALUES('BG-AUTH-01:192.0.2.44:bastion','Repeated authentication failures','high','6 failed','192.0.2.44','bastion','BG-AUTH-01',6,"
               "'investigating','2026-10-27T10:00:00+00:00','2026-10-27T10:05:00+00:00')")
    db.execute("INSERT INTO incidents(signature,title,severity,summary,source_ip,host,rule_id,event_count,status,first_seen,last_seen) "
               "VALUES('BG-CFG-01:7','Security policy modified','medium','policy','10.0.0.1','fw','BG-CFG-01',1,'resolved',"
               "'2026-10-27T10:10:00+00:00','2026-10-27T10:10:00+00:00')")
    db.execute("INSERT INTO devices VALUES('home-pc','Home PC','Linux','2026-10-27T10:11:00+00:00','2026-10-27T09:00:00+00:00')")
    db.commit()
    db.close()


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.dir = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_v04_upgrade_preserves_everything(self):
        build_v04(self.dir / "test.sqlite3")
        app = make_app(self.dir)
        self.assertEqual(app.migration["applied"], [1, 2])
        self.assertTrue(Path(app.migration["backup"]).exists())
        self.assertEqual(app.events.count(), 8)
        events = {e["message"]: e for e in app.events.search(limit=50)["events"]}
        self.assertEqual((events["fail 0"]["mode"], events["fail 0"]["trust"]), ("demo", "demo"))
        self.assertEqual((events["policy edited"]["mode"], events["policy edited"]["trust"]), ("imported", "manual_import"))
        self.assertEqual((events["from collector"]["mode"], events["from collector"]["trust"]), ("live", "legacy_token"))
        incidents = {i["rule_id"]: i for i in app.incidents.list()}
        self.assertEqual(incidents["BG-AUTH-01"]["status"], "investigating")
        self.assertEqual(incidents["BG-CFG-01"]["status"], "resolved")
        self.assertEqual(len(app.incidents.evidence(incidents["BG-AUTH-01"]["id"])), 6)
        self.assertEqual(len(app.incidents.evidence(incidents["BG-CFG-01"]["id"])), 1)
        self.assertEqual(incidents["BG-CFG-01"]["mode"], "imported")
        agents = app.agents.list()
        self.assertEqual((agents[0]["id"], agents[0]["status"]), ("legacy-home-pc", "legacy"))
        self.assertEqual(app.db.scalar("SELECT COUNT(*) FROM legacy_heartbeat_devices"), 1)
        # Re-running detection after migration does not duplicate migrated incidents.
        self.assertEqual(app.detector.run(), {"created": [], "updated": []})
        self.assertEqual(app.db.scalar("PRAGMA integrity_check"), "ok")
        self.assertTrue(app.audit.verify()["valid"])
        app.db.close()

    def test_migrations_are_idempotent(self):
        app = make_app(self.dir)
        self.assertEqual(app.migration["applied"], [1, 2])
        self.assertIsNone(app.migration["backup"])  # fresh install has nothing to back up
        app.db.close()
        again = make_app(self.dir)
        self.assertEqual(again.migration["applied"], [])
        self.assertEqual(again.db.schema_version(), 2)
        again.db.close()

    def test_failed_migration_rolls_back(self):
        build_v04(self.dir / "test.sqlite3")
        from guard import migrations
        original = migrations.MIGRATIONS[1]

        def broken(conn):
            original[2](conn)
            raise RuntimeError("simulated failure")
        migrations.MIGRATIONS[1] = (2, "broken", broken)
        try:
            with self.assertRaises(RuntimeError):
                make_app(self.dir)
        finally:
            migrations.MIGRATIONS[1] = original
        db = sqlite3.connect(self.dir / "test.sqlite3")
        self.assertEqual(db.execute("SELECT COUNT(*) FROM events").fetchone()[0], 8)
        self.assertIn("devices", {r[0] for r in db.execute("SELECT name FROM sqlite_master")})
        self.assertEqual(db.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0], 1)
        db.close()
        recovered = make_app(self.dir)
        self.assertEqual(recovered.events.count(), 8)
        recovered.db.close()


if __name__ == "__main__":
    unittest.main()
