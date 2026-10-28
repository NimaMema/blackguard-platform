"""Versioned schema migrations. Each migration runs in one transaction.

Version 1 reproduces the v0.4 schema so fresh installs and upgraded v0.4
databases converge on the same baseline. Version 2 introduces the platform
schema (users, agents, inventory, evidence, audit) and preserves every
existing event, incident and status.
"""

import json
from datetime import datetime, timezone


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _columns(conn, table):
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


def _tables(conn):
    return {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def m001_v04_baseline(conn):
    for sql in (
        """CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT NOT NULL, host TEXT NOT NULL,
            source_ip TEXT NOT NULL, actor TEXT NOT NULL, message TEXT NOT NULL,
            timestamp TEXT NOT NULL, mode TEXT NOT NULL CHECK(mode IN ('demo','imported')))""",
        "CREATE INDEX IF NOT EXISTS events_time_idx ON events(timestamp)",
        """CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT, signature TEXT NOT NULL UNIQUE, title TEXT NOT NULL,
            severity TEXT NOT NULL, summary TEXT NOT NULL, source_ip TEXT NOT NULL, host TEXT NOT NULL,
            rule_id TEXT NOT NULL, event_count INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'open',
            first_seen TEXT NOT NULL, last_seen TEXT NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS devices (
            agent_id TEXT PRIMARY KEY, name TEXT NOT NULL, platform TEXT NOT NULL,
            last_seen TEXT NOT NULL, first_seen TEXT NOT NULL)""",
    ):
        conn.execute(sql)
    if "agent_id" not in _columns(conn, "events"):
        conn.execute("ALTER TABLE events ADD COLUMN agent_id TEXT NOT NULL DEFAULT ''")


PLATFORM_SCHEMA = [
    """CREATE TABLE organizations (
        id INTEGER PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL)""",
    """CREATE TABLE sites (
        id INTEGER PRIMARY KEY, org_id INTEGER NOT NULL REFERENCES organizations(id),
        name TEXT NOT NULL, created_at TEXT NOT NULL)""",
    """CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)""",
    """CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, org_id INTEGER NOT NULL DEFAULT 1 REFERENCES organizations(id),
        username TEXT NOT NULL UNIQUE COLLATE NOCASE, display_name TEXT NOT NULL,
        password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','analyst','viewer')),
        disabled INTEGER NOT NULL DEFAULT 0, failed_logins INTEGER NOT NULL DEFAULT 0,
        locked_until TEXT, created_at TEXT NOT NULL, last_login_at TEXT, password_changed_at TEXT NOT NULL)""",
    """CREATE TABLE sessions (
        token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        csrf_token TEXT NOT NULL, created_at TEXT NOT NULL, last_seen_at TEXT NOT NULL,
        expires_at TEXT NOT NULL, ip TEXT NOT NULL DEFAULT '', user_agent TEXT NOT NULL DEFAULT '')""",
    "CREATE INDEX sessions_user_idx ON sessions(user_id)",
    """CREATE TABLE agents (
        id TEXT PRIMARY KEY, org_id INTEGER NOT NULL DEFAULT 1, site_id INTEGER NOT NULL DEFAULT 1,
        name TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('pending','active','suspended','revoked','legacy')),
        hostname TEXT NOT NULL DEFAULT '', platform TEXT NOT NULL DEFAULT '', fingerprint TEXT NOT NULL DEFAULT '',
        reported_fingerprint TEXT NOT NULL DEFAULT '', agent_version TEXT NOT NULL DEFAULT '',
        sources TEXT NOT NULL DEFAULT '[]', credential_hash TEXT, next_credential_hash TEXT,
        credential_issued_at TEXT, rotate_requested INTEGER NOT NULL DEFAULT 0,
        enrolled_at TEXT NOT NULL, approved_at TEXT, approved_by INTEGER, revoked_at TEXT, revoked_by INTEGER,
        status_reason TEXT NOT NULL DEFAULT '', last_contact_at TEXT, last_ip TEXT NOT NULL DEFAULT '',
        health TEXT NOT NULL DEFAULT '{}', offline_after_seconds INTEGER NOT NULL DEFAULT 180,
        offline_alerted INTEGER NOT NULL DEFAULT 0, device_id INTEGER, invite_id INTEGER)""",
    "CREATE UNIQUE INDEX agents_cred_idx ON agents(credential_hash) WHERE credential_hash IS NOT NULL",
    "CREATE UNIQUE INDEX agents_next_cred_idx ON agents(next_credential_hash) WHERE next_credential_hash IS NOT NULL",
    """CREATE TABLE enrollment_invites (
        id INTEGER PRIMARY KEY AUTOINCREMENT, org_id INTEGER NOT NULL DEFAULT 1, site_id INTEGER NOT NULL DEFAULT 1,
        code_hash TEXT NOT NULL UNIQUE, name TEXT NOT NULL, created_by INTEGER, created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL, used_at TEXT, agent_id TEXT, revoked INTEGER NOT NULL DEFAULT 0)""",
    """CREATE TABLE inventory (
        id INTEGER PRIMARY KEY AUTOINCREMENT, org_id INTEGER NOT NULL DEFAULT 1, site_id INTEGER NOT NULL DEFAULT 1,
        display_name TEXT NOT NULL, hostname TEXT NOT NULL DEFAULT '', ip_address TEXT NOT NULL DEFAULT '',
        mac_address TEXT NOT NULL DEFAULT '', os TEXT NOT NULL DEFAULT '', os_confidence TEXT NOT NULL DEFAULT 'unknown',
        identity_confidence TEXT NOT NULL DEFAULT 'unknown', origin TEXT NOT NULL, agent_id TEXT,
        approved INTEGER NOT NULL DEFAULT 0, notes TEXT NOT NULL DEFAULT '', first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL, mode TEXT NOT NULL DEFAULT 'live')""",
    "CREATE INDEX inventory_mac_idx ON inventory(mac_address)",
    "CREATE INDEX inventory_host_idx ON inventory(hostname)",
    """CREATE TABLE inventory_observations (
        id INTEGER PRIMARY KEY AUTOINCREMENT, device_id INTEGER NOT NULL REFERENCES inventory(id) ON DELETE CASCADE,
        observed_at TEXT NOT NULL, source TEXT NOT NULL, field TEXT NOT NULL, value TEXT NOT NULL,
        confidence TEXT NOT NULL CHECK(confidence IN ('confirmed','reported','inferred')), reporter TEXT NOT NULL DEFAULT '')""",
    "CREATE INDEX inventory_obs_idx ON inventory_observations(device_id, observed_at)",
    """CREATE TABLE events_v2 (
        id INTEGER PRIMARY KEY AUTOINCREMENT, uid TEXT NOT NULL UNIQUE,
        org_id INTEGER NOT NULL DEFAULT 1, site_id INTEGER NOT NULL DEFAULT 1,
        agent_id TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT 'import', type TEXT NOT NULL,
        host TEXT NOT NULL, source_ip TEXT NOT NULL DEFAULT '', dest_ip TEXT NOT NULL DEFAULT '',
        dest_port INTEGER, actor TEXT NOT NULL DEFAULT 'unknown', target TEXT NOT NULL DEFAULT '',
        message TEXT NOT NULL, details TEXT NOT NULL DEFAULT '{}', raw TEXT,
        timestamp TEXT NOT NULL, received_at TEXT NOT NULL,
        mode TEXT NOT NULL CHECK(mode IN ('demo','imported','live')),
        trust TEXT NOT NULL CHECK(trust IN ('verified_agent','legacy_token','manual_import','demo','server')))""",
    """CREATE TABLE incident_events (
        incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
        event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
        PRIMARY KEY(incident_id, event_id))""",
    "CREATE INDEX incident_events_event_idx ON incident_events(event_id)",
    """CREATE TABLE incident_notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
        author_id INTEGER, author_name TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('note','ai','system')),
        body TEXT NOT NULL, meta TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL)""",
    """CREATE TABLE rule_settings (
        rule_id TEXT PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 1, severity TEXT,
        params TEXT NOT NULL DEFAULT '{}', updated_at TEXT NOT NULL, updated_by INTEGER)""",
    """CREATE TABLE response_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
        action_type TEXT NOT NULL, integration TEXT NOT NULL DEFAULT 'manual', title TEXT NOT NULL,
        impact TEXT NOT NULL, rollback_plan TEXT NOT NULL, target TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL CHECK(status IN ('proposed','approved','rejected','completed','rolled_back','cancelled')),
        proposed_by INTEGER, proposed_at TEXT NOT NULL, decided_by INTEGER, decided_at TEXT, decision_note TEXT NOT NULL DEFAULT '',
        completed_by INTEGER, completed_at TEXT, result_note TEXT NOT NULL DEFAULT '',
        rolled_back_by INTEGER, rolled_back_at TEXT, rollback_note TEXT NOT NULL DEFAULT '')""",
    """CREATE TABLE audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor_type TEXT NOT NULL,
        actor_id TEXT NOT NULL DEFAULT '', actor_name TEXT NOT NULL DEFAULT '', action TEXT NOT NULL,
        target_type TEXT NOT NULL DEFAULT '', target_id TEXT NOT NULL DEFAULT '', outcome TEXT NOT NULL,
        ip TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT '{}', prev_hash TEXT NOT NULL, hash TEXT NOT NULL)""",
    "CREATE INDEX audit_ts_idx ON audit_log(ts)",
]


def _link_legacy_evidence(conn):
    """Reconstruct evidence links for v0.4 incidents from their signatures."""
    incidents = conn.execute("SELECT id, signature, rule_id, source_ip, host, first_seen, last_seen FROM incidents").fetchall()
    for inc in incidents:
        sig = inc["signature"]
        ids = []
        if inc["rule_id"] in ("BG-IAM-01", "BG-CFG-01", "BG-NET-01", "BG-AUTH-02"):
            tail = sig.rsplit(":", 1)[-1]
            if tail.isdigit():
                ids.append(int(tail))
        if inc["rule_id"] in ("BG-AUTH-01", "BG-AUTH-02") and inc["source_ip"]:
            ids += [r[0] for r in conn.execute(
                "SELECT id FROM events WHERE type='auth_failure' AND source_ip=? AND host=? AND timestamp BETWEEN ? AND ?",
                (inc["source_ip"], inc["host"], inc["first_seen"], inc["last_seen"]))]
        for event_id in set(ids):
            if conn.execute("SELECT 1 FROM events WHERE id=?", (event_id,)).fetchone():
                conn.execute("INSERT OR IGNORE INTO incident_events(incident_id,event_id) VALUES(?,?)", (inc["id"], event_id))


def m002_platform(conn):
    now = _now()
    for sql in PLATFORM_SCHEMA:
        conn.execute(sql)
    conn.execute("INSERT INTO organizations(id,name,created_at) VALUES(1,'Home',?)", (now,))
    conn.execute("INSERT INTO sites(id,org_id,name,created_at) VALUES(1,1,'Home network',?)", (now,))

    # Events: rebuild to widen the mode CHECK constraint and add provenance.
    conn.execute("""
        INSERT INTO events_v2(id,uid,agent_id,source,type,host,source_ip,actor,message,timestamp,received_at,mode,trust)
        SELECT id, 'legacy:' || id, agent_id,
               CASE WHEN mode='demo' THEN 'demo' WHEN agent_id != '' THEN 'legacy_collector' ELSE 'import' END,
               type, host, source_ip, actor, message, timestamp, timestamp,
               CASE WHEN mode='demo' THEN 'demo' WHEN agent_id != '' THEN 'live' ELSE 'imported' END,
               CASE WHEN mode='demo' THEN 'demo' WHEN agent_id != '' THEN 'legacy_token' ELSE 'manual_import' END
        FROM events ORDER BY id
    """)
    conn.execute("DROP TABLE events")
    conn.execute("ALTER TABLE events_v2 RENAME TO events")
    for sql in (
        "CREATE INDEX events_time_idx ON events(timestamp)",
        "CREATE INDEX events_type_time_idx ON events(type, timestamp)",
        "CREATE INDEX events_ip_idx ON events(source_ip)",
        "CREATE INDEX events_host_idx ON events(host)",
        "CREATE INDEX events_agent_idx ON events(agent_id)",
        "CREATE INDEX events_mode_idx ON events(mode)",
    ):
        conn.execute(sql)

    # Incidents: additive columns only; history and statuses are preserved.
    existing = _columns(conn, "incidents")
    for name, ddl in (
        ("org_id", "INTEGER NOT NULL DEFAULT 1"),
        ("group_key", "TEXT NOT NULL DEFAULT ''"),
        ("confidence", "TEXT NOT NULL DEFAULT 'medium'"),
        ("confidence_reason", "TEXT NOT NULL DEFAULT ''"),
        ("affected_hosts", "TEXT NOT NULL DEFAULT '[]'"),
        ("mode", "TEXT NOT NULL DEFAULT 'demo'"),
        ("created_at", "TEXT NOT NULL DEFAULT ''"),
        ("updated_at", "TEXT NOT NULL DEFAULT ''"),
        ("resolved_at", "TEXT"),
        ("assigned_to", "INTEGER"),
        ("legacy", "INTEGER NOT NULL DEFAULT 0"),
    ):
        if name not in existing:
            conn.execute(f"ALTER TABLE incidents ADD COLUMN {name} {ddl}")
    conn.execute("""UPDATE incidents SET group_key=signature, legacy=1, created_at=first_seen, updated_at=last_seen,
                    affected_hosts=json_array(host),
                    confidence_reason='Migrated from v0.4; confidence was not recorded by the earlier engine.'""")
    conn.execute("CREATE INDEX IF NOT EXISTS incidents_rule_group_idx ON incidents(rule_id, group_key)")
    _link_legacy_evidence(conn)
    conn.execute("""UPDATE incidents SET mode = CASE
        WHEN EXISTS (SELECT 1 FROM incident_events ie JOIN events e ON e.id=ie.event_id
                     WHERE ie.incident_id=incidents.id AND e.mode='live') THEN 'live'
        WHEN EXISTS (SELECT 1 FROM incident_events ie JOIN events e ON e.id=ie.event_id
                     WHERE ie.incident_id=incidents.id AND e.mode='imported') THEN 'imported' ELSE 'demo' END""")
    conn.execute("UPDATE incidents SET resolved_at=updated_at WHERE status='resolved'")

    # v0.4 heartbeat "devices" were never verified: keep them, clearly labelled.
    if "devices" in _tables(conn):
        conn.execute("ALTER TABLE devices RENAME TO legacy_heartbeat_devices")
        for row in conn.execute("SELECT * FROM legacy_heartbeat_devices").fetchall():
            conn.execute(
                """INSERT INTO inventory(display_name,hostname,os,os_confidence,identity_confidence,origin,agent_id,
                   approved,notes,first_seen,last_seen,mode) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (row["name"], "", row["platform"], "reported", "unverified", "legacy_heartbeat", None, 0,
                 f"Imported from v0.4 shared-token heartbeat (agent id '{row['agent_id']}'). Identity was never verified.",
                 row["first_seen"], row["last_seen"], "live"))
            conn.execute(
                """INSERT OR IGNORE INTO agents(id,name,status,platform,enrolled_at,last_contact_at,status_reason)
                   VALUES(?,?,?,?,?,?,?)""",
                (f"legacy-{row['agent_id']}", row["name"], "legacy", row["platform"], row["first_seen"], row["last_seen"],
                 "Reported through the v0.4 shared ingest token; re-enroll with a per-agent credential."))
    conn.execute("INSERT INTO settings(key,value) VALUES('revision','1')")
    conn.execute("INSERT INTO settings(key,value) VALUES('retention', ?)",
                 (json.dumps({"events_days": 180, "audit_days": 730, "notes_days": 0, "backups_keep": 7}),))


MIGRATIONS = [
    (1, "v0.4 baseline schema", m001_v04_baseline),
    (2, "Platform schema: users, agents, inventory, evidence, audit", m002_platform),
]
