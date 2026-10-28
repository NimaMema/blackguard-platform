"""Application service: wires storage, detection, agents and background jobs together."""

import logging
import os
import shutil
import sqlite3
import ssl
import threading
import time
from datetime import timedelta

from guard import __version__, demo
from guard.agents import Agents
from guard.ai import Analyst
from guard.audit import AuditLog
from guard.auth import Auth
from guard.db import Database, iso, parse_iso, utcnow
from guard.detection import Detector
from guard.events import EventStore
from guard.incidents import Incidents
from guard.inventory import Inventory
from guard.response import Responses

log = logging.getLogger("blackguard")
RETENTION_LIMITS = {"events_days": (7, 3650), "audit_days": (30, 3650), "backups_keep": (1, 90)}


class App:
    def __init__(self, settings):
        self.settings = settings
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        if not os.access(settings.data_dir, os.W_OK):
            raise SystemExit(f"Data directory {settings.data_dir} is not writable by this user. Mount a writable volume "
                             "(Docker: -v blackguard-data:/app/data) or fix its permissions.")
        self.db = Database(settings.db_path, settings.data_dir / "backups")
        self.migration = self.db.migrate()
        self.audit = AuditLog(self.db)
        self.auth = Auth(self.db, self.audit, settings)
        self.events = EventStore(self.db, settings.store_raw)
        self.inventory = Inventory(self.db, self.audit)
        self.agents = Agents(self.db, self.audit, self.events, self.inventory)
        self.detector = Detector(self.db, self.events, self.audit)
        self.incidents = Incidents(self.db, self.audit)
        self.responses = Responses(self.db, self.audit)
        self.analyst = Analyst(settings)
        self.started_at = utcnow()
        self.jobs = {}
        self._stop = threading.Event()
        if self.migration["applied"]:
            self.audit.record("system.migrate", detail=self.migration)
        if settings.seed_demo and self.events.count() == 0 and not self.db.get_setting("demo_seeded"):
            self.seed_demo()

    # -- ingestion pipeline -------------------------------------------------
    def ingest(self, events, **kwargs):
        result = self.events.ingest(events, **kwargs)
        detection = self.detector.run(result["accepted"]) if result["accepted"] else {"created": [], "updated": []}
        result["incidents_created"] = detection["created"]
        result["incidents_updated"] = detection["updated"]
        return result

    def ingest_notices(self, notices):
        if notices:
            result = self.ingest(notices, mode="live", trust="server", source="blackguard", atomic=False)
            for rejected in result["rejected"]:
                log.error("Server notice rejected by validation (bug): %s", rejected["error"])
            return result
        return None

    def seed_demo(self):
        self.ingest(demo.initial_events(), mode="demo", trust="demo", source="demo")
        self.db.set_setting("demo_seeded", True)

    def inject_demo(self, actor, ip=""):
        result = self.ingest(demo.injected_scenario(), mode="demo", trust="demo", source="demo")
        self.audit.record("demo.inject", actor=actor, ip=ip, detail={"events": len(result["accepted"])})
        return result

    def purge_demo(self, actor, ip=""):
        with self.db.tx() as conn:
            removed = self.events.delete_demo(conn)
            conn.execute("DELETE FROM inventory WHERE mode='demo'")
            self.audit.record("demo.purge", actor=actor, ip=ip, detail={"events_removed": removed}, conn=conn)
            self.db.bump_revision(conn)
        self.db.set_setting("demo_seeded", True)
        return removed

    # -- dashboard data -----------------------------------------------------
    def revision(self):
        return int(self.db.get_setting("revision", 0) or 0)

    def overview(self):
        modes = {r["mode"]: r["n"] for r in self.db.query("SELECT mode, COUNT(*) AS n FROM events GROUP BY mode")}
        counts = self.incidents.counts()
        agents = self.agents.list()
        approved = [a for a in agents if a["status"] == "active"]
        live = modes.get("live", 0) + modes.get("imported", 0)
        label = ("DEMO DATA" if not live else "LIVE + DEMO" if modes.get("demo") else "LIVE DATA")
        if live and not modes.get("live"):
            label = "IMPORTED + DEMO" if modes.get("demo") else "IMPORTED DATA"
        active = counts["active_by_severity"]
        posture = ("ELEVATED" if active["critical"] else "WATCHFUL" if active["high"] else
                   "GUARDED" if active["medium"] else "STABLE")
        return {
            "stats": {
                "total_events": sum(modes.values()), "live_events": modes.get("live", 0),
                "imported_events": modes.get("imported", 0), "demo_events": modes.get("demo", 0),
                "dataset_label": label, "hosts": self.db.scalar("SELECT COUNT(DISTINCT host) FROM events"),
                "incidents_active": sum(active.values()), "incidents_live_active": counts["live_active"],
                "incidents_by_status": counts["by_status"], "active_by_severity": active,
                "agents_active": len(approved), "agents_online": sum(a["connection"] == "online" for a in approved),
                "agents_pending": sum(a["status"] == "pending" for a in agents),
                "agents_attention": sum(a["status"] == "suspended" or (a["status"] == "active" and a["connection"] == "offline") for a in agents),
                "devices": self.db.scalar("SELECT COUNT(*) FROM inventory"),
                "devices_unreviewed": self.db.scalar("SELECT COUNT(*) FROM inventory WHERE approved=0"),
                "responses_pending": self.db.scalar("SELECT COUNT(*) FROM response_actions WHERE status='proposed'"),
            },
            "posture": posture,
            "histogram": self.events.hourly_histogram(24),
            "incidents": self.incidents.list(status="active", limit=6),
            "events": self.events.search(limit=6)["events"],
            "agents": [a for a in agents if a["status"] in ("active", "pending", "suspended")][:8],
            "revision": self.revision(),
            "ai": self.analyst.status(),
            "warnings": self.health_warnings(),
            "setup": {"tls": self.settings.tls_enabled,
                      "backup_verified": bool((self.db.get_setting("last_backup") or {}).get("verified"))},
        }

    def system_health(self):
        db_file = self.settings.db_path
        size = db_file.stat().st_size if db_file.exists() else 0
        backups = sorted((self.settings.data_dir / "backups").glob("*.sqlite3"))
        disk = shutil.disk_usage(self.settings.data_dir)
        return {
            "status": "degraded" if any(w["level"] == "critical" for w in self.health_warnings()) else "ok",
            "warnings": self.health_warnings(),
            "setup": {"tls": self.settings.tls_enabled,
                      "backup_verified": bool((self.db.get_setting("last_backup") or {}).get("verified"))}, "last_backup": self.db.get_setting("last_backup"),
            "last_server_downtime": self.db.get_setting("last_server_downtime"),
            "disk_free_bytes": disk.free, "disk_total_bytes": disk.total,
            "version": __version__, "schema_version": self.db.schema_version(), "started_at": iso(self.started_at),
            "uptime_seconds": int((utcnow() - self.started_at).total_seconds()),
            "database_bytes": size, "tls": self.settings.tls_enabled, "bind": self.settings.host,
            "legacy_ingest_enabled": bool(self.settings.legacy_ingest_token), "store_raw": self.settings.store_raw,
            "jobs": self.jobs, "retention": self.retention(),
            "backups": [{"name": b.name, "bytes": b.stat().st_size} for b in backups[-10:]],
            "audit_chain": self.audit.verify(), "ai": self.analyst.status(),
        }

    # -- retention & backup -------------------------------------------------
    def retention(self):
        return self.db.get_setting("retention", {"events_days": 180, "audit_days": 730, "backups_keep": 7})

    def set_retention(self, actor, values, ip=""):
        current = self.retention()
        for key, (low, high) in RETENTION_LIMITS.items():
            if key in values:
                value = values[key]
                if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
                    raise ValueError(f"{key} must be a whole number from {low} to {high}")
                current[key] = value
        self.db.set_setting("retention", current)
        self.audit.record("system.retention", actor=actor, ip=ip, detail=current)
        return current

    def apply_retention(self):
        """Delete events older than the retention period, but never evidence for unresolved incidents."""
        policy = self.retention()
        cutoff = iso(utcnow() - timedelta(days=policy["events_days"]))
        audit_cutoff = iso(utcnow() - timedelta(days=policy["audit_days"]))
        with self.db.tx() as conn:
            removed = conn.execute(
                "DELETE FROM events WHERE timestamp < ? AND id NOT IN (SELECT ie.event_id FROM incident_events ie "
                "JOIN incidents i ON i.id = ie.incident_id WHERE i.status != 'resolved')", (cutoff,)).rowcount
            conn.execute("DELETE FROM inventory_observations WHERE observed_at < ?", (cutoff,))
            # The audit log is a hash chain: trim only whole leading segments and remember the anchor.
            audit_removed = conn.execute("DELETE FROM audit_log WHERE ts < ?", (audit_cutoff,)).rowcount
            if audit_removed:
                first = conn.execute("SELECT id, prev_hash FROM audit_log ORDER BY id LIMIT 1").fetchone()
                conn.execute("INSERT INTO settings(key,value) VALUES('audit_anchor', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                             (f'"{first["prev_hash"]}"' if first else '""',))
            if removed:
                self.db.bump_revision(conn)
        if removed or audit_removed:
            self.audit.record("system.retention.apply", detail={"events_removed": removed, "audit_removed": audit_removed})
        return {"events_removed": removed, "audit_removed": audit_removed}

    def backup(self, actor=None, label="manual", ip=""):
        path = self.db.backup(label)
        result = verify_backup(path)
        self.db.set_setting("last_backup", {"file": path.name, "at": iso(), "bytes": path.stat().st_size, **result})
        self.db.prune_backups(label, self.retention().get("backups_keep", 7))
        self.audit.record("system.backup", "success" if result["verified"] else "failure", actor=actor, ip=ip,
                          detail={"file": path.name, "label": label, **result})
        if not result["verified"]:
            raise RuntimeError(f"Backup {path.name} failed verification: {result['detail']}")
        return path

    # -- health -------------------------------------------------------------
    def health_warnings(self):
        """Operational problems an administrator should know about, most severe first."""
        warnings = []
        last = self.db.get_setting("last_backup")
        if not last:
            if utcnow() - self.started_at > timedelta(hours=26):
                warnings.append(("warning", "No backup has been made yet."))
        elif not last.get("verified"):
            warnings.append(("critical", f"The last backup ({last.get('file')}) failed verification."))
        elif utcnow() - parse_iso(last["at"]) > timedelta(hours=36):
            warnings.append(("warning", f"The last verified backup is from {last['at']} (over 36 hours ago)."))
        disk = shutil.disk_usage(self.settings.data_dir)
        if disk.free < 1024 ** 3 or disk.free / max(disk.total, 1) < 0.05:
            warnings.append(("critical", f"Low disk space for the data directory: {disk.free // 1024 ** 2} MB free."))
        for name, job in self.jobs.items():
            if job.get("last_error"):
                warnings.append(("warning", f"Background job '{name}' failed: {job['last_error']}"))
        if self.settings.tls_enabled:
            days = certificate_days_left(self.settings.tls_cert)
            if days is not None and days < 30:
                warnings.append(("critical" if days < 7 else "warning", f"The TLS certificate expires in {days} days."))
        for agent in self.agents.list():
            if agent["status"] == "active":
                health = agent["health"]
                depth, limit = health.get("spool_depth") or 0, health.get("spool_limit") or 0
                if limit and depth > limit * 0.5:
                    warnings.append(("warning", f"Agent '{agent['name']}' has {depth} undelivered events buffered "
                                                f"({int(depth * 100 / limit)}% of its spool)."))
        order = {"critical": 0, "warning": 1}
        return [{"level": level, "message": message} for level, message in sorted(warnings, key=lambda w: order[w[0]])]

    # -- lifecycle ------------------------------------------------------------
    def startup(self):
        """Called once when the server starts serving: records any period the server itself was down."""
        last_alive = self.db.get_setting("server_alive_at")
        clean = self.db.get_setting("server_clean_stop")
        now = utcnow()
        if last_alive:
            gap = (now - parse_iso(last_alive)).total_seconds()
            if gap > 120:
                how = "after a clean shutdown" if clean else "after an unclean stop (crash, power loss or forced kill)"
                record = {"from": last_alive, "to": iso(now), "minutes": int(gap // 60), "clean": bool(clean)}
                self.db.set_setting("last_server_downtime", record)
                self.audit.record("system.downtime", detail=record)
                self.ingest([{"type": "collector_notice", "host": "BLACKGUARD server", "actor": "blackguard",
                              "message": f"The BLACKGUARD server was not running from {last_alive} to {iso(now)} "
                                         f"({int(gap // 60)} minutes) and restarted {how}. Agents buffer events during "
                                         "server outages and deliver them on reconnection.",
                              "uid": "notice:server_downtime:" + "".join(c for c in last_alive if c.isalnum()),
                              "details": {"kind": "server_downtime", "clean": bool(clean)}}],
                            mode="live", trust="server", source="blackguard", atomic=False)
        self.db.set_setting("server_clean_stop", False)
        self.mark_alive()

    def mark_alive(self):
        self.db.set_setting("server_alive_at", iso())

    # -- background jobs ----------------------------------------------------
    def _job(self, name, func, every_seconds):
        state = self.jobs.setdefault(name, {"last_run": None, "last_error": None, "runs": 0, "_next": 0})
        now = time.monotonic()
        if now < state["_next"]:
            return
        state["_next"] = now + every_seconds
        try:
            func()
            state.update(last_run=iso(), last_error=None, runs=state["runs"] + 1)
        except Exception as exc:  # keep the monitor alive; surface the error in system health
            state.update(last_error=f"{type(exc).__name__}: {exc}", last_run=iso())
            log.exception("Background job %s failed", name)

    def tick(self):
        self._job("agent_health", lambda: self.ingest_notices(self.agents.offline_sweep(self.started_at)),
                  self.settings.background_interval)
        self._job("heartbeat", self.mark_alive, 30)
        self._check_shutdown_request()

    @property
    def shutdown_request_file(self):
        return self.settings.data_dir / "shutdown.request"

    def _check_shutdown_request(self):
        """`start.py stop` asks for a clean stop by creating this file (works on Windows, which has no SIGTERM)."""
        if self.shutdown_request_file.exists() and getattr(self, "on_shutdown_request", None):
            self.shutdown_request_file.unlink(missing_ok=True)
            log.info("Shutdown requested via %s", self.shutdown_request_file.name)
            self.on_shutdown_request()
        self._job("sessions", self.auth.purge_expired_sessions, 300)
        self._job("retention", self.apply_retention, 3600)
        self._job("daily_backup", self._daily_backup, 3600)

    def _daily_backup(self):
        last = self.db.get_setting("last_auto_backup")
        if not last or utcnow() - parse_iso(last) > timedelta(hours=24):
            self.backup(label="auto")
            self.db.set_setting("last_auto_backup", iso())

    def start_background(self):
        def loop():
            while not self._stop.wait(5):
                self.tick()
        self._thread = threading.Thread(target=loop, name="blackguard-monitor", daemon=True)
        self._thread.start()
        return self._thread

    def stop(self, clean=True):
        """Stop background jobs and record a clean shutdown so the next start can tell it from a crash."""
        self._stop.set()
        thread = getattr(self, "_thread", None)
        if thread and thread is not threading.current_thread():
            thread.join(timeout=15)
        if clean:
            self.mark_alive()
            self.db.set_setting("server_clean_stop", iso())
        self.db.close()


def verify_backup(path):
    """Open a backup read-only and run SQLite's integrity check and a schema sanity check."""
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            version = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] if "schema_migrations" in tables else None
            events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] if "events" in tables else None
        finally:
            conn.close()
    except sqlite3.Error as exc:
        return {"verified": False, "detail": f"cannot open: {exc}"}
    ok = integrity == "ok" and {"events", "incidents"} <= tables
    return {"verified": ok, "detail": "integrity ok" if ok else f"integrity: {integrity}; tables: {sorted(tables)[:8]}",
            "schema_version": version, "events": events}


def certificate_days_left(cert_path):
    try:
        info = ssl._ssl._test_decode_cert(cert_path)  # stdlib helper; avoids third-party crypto dependencies
        expires = ssl.cert_time_to_seconds(info["notAfter"])
    except (OSError, ValueError, KeyError, AttributeError, ssl.SSLError):
        return None
    return int((expires - time.time()) // 86400)
