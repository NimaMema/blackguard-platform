"""SQLite access layer with explicit transactions and versioned migrations.

Migrations never drop user data. Before any migration runs against a
database that already holds data, an online backup is written to
``<data_dir>/backups/pre-migration-*.sqlite3``.
"""

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


def utcnow():
    return datetime.now(timezone.utc)


def iso(value=None):
    return (value or utcnow()).astimezone(timezone.utc).isoformat(timespec="seconds")


def parse_iso(value):
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


class Database:
    def __init__(self, path, backup_dir=None):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.backup_dir = Path(backup_dir) if backup_dir else Path(self.path).parent / "backups"
        self._local = threading.local()
        self._write_lock = threading.RLock()
        with self.connection() as conn:
            conn.execute("PRAGMA journal_mode=WAL")

    def _open(self):
        conn = sqlite3.connect(self.path, timeout=15, isolation_level=None, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=15000")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    @contextmanager
    def connection(self):
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._local.conn = self._open()
        yield conn

    @contextmanager
    def tx(self):
        """Serialized write transaction (BEGIN IMMEDIATE) with rollback on error."""
        with self._write_lock, self.connection() as conn:
            if conn.in_transaction:
                # Nested use joins the outer transaction.
                yield conn
                return
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise

    def query(self, sql, params=()):
        with self.connection() as conn:
            return [dict(row) for row in conn.execute(sql, params)]

    def one(self, sql, params=()):
        with self.connection() as conn:
            row = conn.execute(sql, params).fetchone()
            return dict(row) if row else None

    def scalar(self, sql, params=()):
        with self.connection() as conn:
            row = conn.execute(sql, params).fetchone()
            return row[0] if row else None

    def close(self):
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    # -- settings -----------------------------------------------------------
    def get_setting(self, key, default=None):
        row = self.one("SELECT value FROM settings WHERE key = ?", (key,))
        return json.loads(row["value"]) if row else default

    def set_setting(self, key, value, conn=None):
        sql = "INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"
        if conn is not None:
            conn.execute(sql, (key, json.dumps(value)))
        else:
            with self.tx() as c:
                c.execute(sql, (key, json.dumps(value)))

    def bump_revision(self, conn):
        """Monotonic change counter the dashboard polls for near-real-time updates."""
        conn.execute(
            "INSERT INTO settings(key,value) VALUES('revision','1') "
            "ON CONFLICT(key) DO UPDATE SET value=CAST(CAST(value AS INTEGER)+1 AS TEXT)"
        )

    # -- backup -------------------------------------------------------------
    def backup(self, label="manual"):
        """Consistent online backup using SQLite's backup API."""
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        stamp = utcnow().strftime("%Y%m%dT%H%M%SZ")
        target = self.backup_dir / f"{label}-{stamp}.sqlite3"
        counter = 1
        while target.exists():
            target = self.backup_dir / f"{label}-{stamp}-{counter}.sqlite3"
            counter += 1
        dest = sqlite3.connect(str(target))
        try:
            with self.connection() as conn:
                conn.backup(dest)
        finally:
            dest.close()
        try:
            target.chmod(0o600)
        except OSError:
            pass
        return target

    def prune_backups(self, label, keep):
        files = sorted(self.backup_dir.glob(f"{label}-*.sqlite3"))
        for old in files[:-keep] if keep > 0 else []:
            old.unlink(missing_ok=True)

    # -- migrations ---------------------------------------------------------
    def migrate(self):
        from guard.migrations import MIGRATIONS

        with self.connection() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, "
                "description TEXT NOT NULL, applied_at TEXT NOT NULL)"
            )
            applied = {row[0] for row in conn.execute("SELECT version FROM schema_migrations")}
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        pending = [m for m in MIGRATIONS if m[0] not in applied]
        backup = None
        if pending and (tables - {"schema_migrations"}):
            backup = self.backup(f"pre-migration-v{pending[0][0]}")
        for version, description, func in pending:
            with self._write_lock, self.connection() as conn:
                conn.execute("PRAGMA foreign_keys=OFF")
                conn.execute("BEGIN IMMEDIATE")
                try:
                    func(conn)
                    conn.execute(
                        "INSERT INTO schema_migrations(version,description,applied_at) VALUES(?,?,?)",
                        (version, description, iso()),
                    )
                    conn.execute("COMMIT")
                except BaseException:
                    conn.execute("ROLLBACK")
                    raise
                finally:
                    conn.execute("PRAGMA foreign_keys=ON")
        return {"applied": [m[0] for m in pending], "backup": str(backup) if backup else None}

    def schema_version(self):
        return self.scalar("SELECT COALESCE(MAX(version),0) FROM schema_migrations") or 0
