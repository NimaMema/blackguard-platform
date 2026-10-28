"""Append-only, hash-chained audit log for security-relevant actions.

Each record's hash covers its content and the previous record's hash, so
editing or deleting a historical row is detectable by ``verify``. This is
tamper-evident, not tamper-proof: someone with write access to the database
file can rewrite the whole chain. Export or back up the log off-box for
stronger guarantees.
"""

import hashlib
import json

from guard.db import iso

GENESIS = "0" * 64


def _digest(prev_hash, record):
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()


class AuditLog:
    FIELDS = ("ts", "actor_type", "actor_id", "actor_name", "action", "target_type", "target_id", "outcome", "ip", "detail")

    def __init__(self, db):
        self.db = db

    def record(self, action, outcome="success", actor=None, target_type="", target_id="", ip="", detail=None, conn=None):
        actor = actor or {}
        entry = {
            "ts": iso(),
            "actor_type": actor.get("type", "system"),
            "actor_id": str(actor.get("id", "")),
            "actor_name": str(actor.get("name", "")),
            "action": action,
            "target_type": target_type,
            "target_id": str(target_id),
            "outcome": outcome,
            "ip": ip or "",
            "detail": json.dumps(detail or {}, sort_keys=True, default=str)[:4000],
        }
        if conn is not None:
            self._insert(conn, entry)
        else:
            with self.db.tx() as c:
                self._insert(c, entry)

    def _insert(self, conn, entry):
        row = conn.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        prev = row[0] if row else GENESIS
        entry_hash = _digest(prev, entry)
        conn.execute(
            # Interpolated text is fixed column names / '?' placeholders; all values are bound parameters.
            f"INSERT INTO audit_log({','.join(self.FIELDS)},prev_hash,hash) VALUES({','.join('?' * len(self.FIELDS))},?,?)",  # nosec B608
            tuple(entry[f] for f in self.FIELDS) + (prev, entry_hash),
        )

    def list(self, limit=200, before_id=None, action=""):
        limit = max(1, min(int(limit), 500))
        sql, params = "SELECT * FROM audit_log WHERE 1=1", []
        if before_id:
            sql += " AND id < ?"
            params.append(int(before_id))
        if action:
            sql += " AND action LIKE ?"
            params.append(action.replace("%", "") + "%")
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        rows = self.db.query(sql, params)
        for row in rows:
            row["detail"] = json.loads(row["detail"] or "{}")
        return rows

    def verify(self):
        # After retention trims old rows, the chain restarts from the recorded anchor.
        prev = self.db.get_setting("audit_anchor") or GENESIS
        count = 0
        with self.db.connection() as conn:
            for row in conn.execute("SELECT * FROM audit_log ORDER BY id"):
                record = {f: row[f] for f in self.FIELDS}
                if row["prev_hash"] != prev or _digest(prev, record) != row["hash"]:
                    return {"valid": False, "checked": count, "broken_at": row["id"]}
                prev = row["hash"]
                count += 1
        return {"valid": True, "checked": count, "broken_at": None}
