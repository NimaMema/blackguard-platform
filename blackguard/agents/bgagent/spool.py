"""Durable, bounded local buffer for events awaiting delivery.

Events and the source cursor that produced them are committed in the same
SQLite transaction, so after a crash or reboot the agent resumes exactly
where it stopped: nothing is read twice into the spool and nothing is
skipped. Events stay in the spool until the server acknowledges them;
re-sending after a lost acknowledgement is safe because every event carries
a stable ``uid`` and the server ignores duplicates.
"""

import json
import sqlite3
import threading
import time


class Spool:
    def __init__(self, path, max_events=100_000):
        self.path = str(path)
        self.max_events = max_events
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, timeout=30, isolation_level=None, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS queue (id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL,
                uid TEXT NOT NULL UNIQUE, payload TEXT NOT NULL, created REAL NOT NULL, attempts INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS cursors (source TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        """)

    def _tx(self):
        lock = self._lock

        class Tx:
            def __enter__(inner):
                lock.acquire()
                self._conn.execute("BEGIN IMMEDIATE")
                return self._conn

            def __exit__(inner, exc_type, exc, tb):
                try:
                    self._conn.execute("ROLLBACK" if exc_type else "COMMIT")
                finally:
                    lock.release()
        return Tx()

    def put(self, source, events, cursor=None):
        """Append events and (optionally) advance the source cursor atomically."""
        with self._tx() as conn:
            for event in events:
                conn.execute("INSERT OR IGNORE INTO queue(source,uid,payload,created) VALUES(?,?,?,?)",
                             (source, event["uid"], json.dumps(event, separators=(",", ":")), time.time()))
            if cursor is not None:
                conn.execute("INSERT INTO cursors(source,value) VALUES(?,?) ON CONFLICT(source) DO UPDATE SET value=excluded.value",
                             (source, json.dumps(cursor)))
            overflow = conn.execute("SELECT COUNT(*) FROM queue").fetchone()[0] - self.max_events
            if overflow > 0:
                conn.execute("DELETE FROM queue WHERE id IN (SELECT id FROM queue ORDER BY id LIMIT ?)", (overflow,))
                self._add_meta(conn, "dropped_total", overflow)

    def _add_meta(self, conn, key, amount):
        conn.execute("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=CAST(value AS INTEGER)+?",
                     (key, str(amount), amount))

    def cursor(self, source):
        with self._lock:
            row = self._conn.execute("SELECT value FROM cursors WHERE source = ?", (source,)).fetchone()
        return json.loads(row[0]) if row else None

    def batch(self, limit=200):
        """Oldest pending events, grouped by source (one source per batch)."""
        with self._lock:
            first = self._conn.execute("SELECT source FROM queue ORDER BY id LIMIT 1").fetchone()
            if not first:
                return None, []
            rows = self._conn.execute("SELECT id, payload FROM queue WHERE source = ? ORDER BY id LIMIT ?",
                                      (first[0], limit)).fetchall()
        return first[0], [(row[0], json.loads(row[1])) for row in rows]

    def ack(self, ids):
        with self._tx() as conn:
            conn.executemany("DELETE FROM queue WHERE id = ?", [(i,) for i in ids])

    def reject(self, ids):
        """Drop events the server permanently rejected (invalid), counting them."""
        if ids:
            with self._tx() as conn:
                conn.executemany("DELETE FROM queue WHERE id = ?", [(i,) for i in ids])
                self._add_meta(conn, "rejected_total", len(ids))

    def stats(self):
        with self._lock:
            depth = self._conn.execute("SELECT COUNT(*), MIN(created) FROM queue").fetchone()
            meta = dict(self._conn.execute("SELECT key, value FROM meta").fetchall())
        return {"spool_depth": depth[0], "oldest_pending_seconds": int(time.time() - depth[1]) if depth[1] else 0,
                "dropped_total": int(meta.get("dropped_total", 0)), "rejected_total": int(meta.get("rejected_total", 0)),
                "spool_limit": self.max_events}

    def close(self):
        with self._lock:
            self._conn.close()
