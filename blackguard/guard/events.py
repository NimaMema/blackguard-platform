"""Event taxonomy, validation, redaction and idempotent (deduplicated) storage."""

import hashlib
import ipaddress
import json
import re
from datetime import timedelta, timezone

from guard.db import iso, parse_iso, utcnow
from guard.security import redact

EVENT_TYPES = {
    "auth_failure": "Authentication failure",
    "auth_success": "Authentication success",
    "account_created": "Account created",
    "account_deleted": "Account deleted",
    "account_enabled": "Account enabled",
    "account_disabled": "Account disabled",
    "account_locked": "Account locked out",
    "password_reset": "Password reset or change",
    "group_membership_change": "Group membership change",
    "privilege_change": "Privilege change",
    "privilege_use": "Privileged command / elevation",
    "policy_change": "Security policy change",
    "audit_log_cleared": "Audit log cleared",
    "service_installed": "Service installed",
    "network_block": "Firewall denial",
    "network_allow": "Firewall allow",
    "config_change": "Device configuration change",
    "dhcp_lease": "DHCP lease",
    "service_error": "Service error",
    "file_access": "File access",
    "collector_notice": "Collector notice",
}
MODES = ("demo", "imported", "live")
TRUST = ("verified_agent", "legacy_token", "manual_import", "demo", "server")
UID_RE = re.compile(r"^[A-Za-z0-9:._/@-]{1,128}$")
DETAIL_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
MAX_BATCH = 500
FUTURE_SKEW = timedelta(minutes=15)
MAX_AGE = timedelta(days=366)


def _text(value, field, low, high, default=None):
    if value is None or value == "":
        if default is not None:
            return default
        if low == 0:
            return ""
        raise ValueError(f"{field} is required")
    text = " ".join(str(value).replace("\x00", "").split())
    if not low <= len(text) <= high:
        raise ValueError(f"{field} must be {low}–{high} characters")
    return text


def _ip(value, field):
    value = str(value or "").strip()
    if not value:
        return ""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ValueError(f"Invalid {field}") from exc


def validate_event(event, now=None):
    """Validate and normalize one event. Raises ValueError with a safe message."""
    if not isinstance(event, dict):
        raise ValueError("Event must be an object")
    kind = event.get("type")
    if kind not in EVENT_TYPES:
        raise ValueError("Unknown event type")
    now = now or utcnow()
    when = event.get("timestamp")
    if when:
        try:
            parsed = parse_iso(when)
        except (TypeError, ValueError) as exc:
            raise ValueError("Invalid ISO-8601 timestamp") from exc
        if parsed.tzinfo is None:
            raise ValueError("Timestamp must include a timezone")
        if parsed - now > FUTURE_SKEW or now - parsed > MAX_AGE:
            raise ValueError("Timestamp outside supported range (past year, at most 15 minutes ahead)")
    else:
        parsed = now
    port = event.get("dest_port")
    if port not in (None, ""):
        try:
            port = int(port)
        except (TypeError, ValueError) as exc:
            raise ValueError("Invalid destination port") from exc
        if not 0 <= port <= 65535:
            raise ValueError("Invalid destination port")
    else:
        port = None
    details = event.get("details") or {}
    if not isinstance(details, dict) or len(details) > 24:
        raise ValueError("details must be an object with at most 24 fields")
    clean_details = {}
    for key, value in details.items():
        if not DETAIL_KEY_RE.match(str(key)):
            raise ValueError("Invalid details key")
        if isinstance(value, bool) or value is None or isinstance(value, (int, float)):
            clean_details[key] = value
        else:
            clean_details[key] = redact(str(value)[:300])
    uid = event.get("uid")
    if uid is not None and not UID_RE.match(str(uid)):
        raise ValueError("Invalid event uid")
    raw = event.get("raw")
    return {
        "type": kind,
        "host": _text(event.get("host"), "Host", 1, 120),
        "source_ip": _ip(event.get("source_ip"), "source IP"),
        "dest_ip": _ip(event.get("dest_ip"), "destination IP"),
        "dest_port": port,
        "actor": _text(event.get("actor"), "Actor", 1, 120, default="unknown"),
        "target": _text(event.get("target"), "Target", 0, 160),
        "message": redact(_text(event.get("message"), "Message", 1, 1000)),
        "details": clean_details,
        "raw": redact(str(raw)[:4000]) if raw else None,
        "timestamp": iso(parsed.astimezone(timezone.utc)),
        "client_uid": str(uid) if uid is not None else None,
    }


def content_uid(prefix, event, occurrence):
    canonical = json.dumps({k: event[k] for k in ("type", "host", "source_ip", "dest_ip", "dest_port", "actor",
                                                   "target", "message", "timestamp", "details")}, sort_keys=True)
    return f"{prefix}:{hashlib.sha256(canonical.encode()).hexdigest()[:40]}:{occurrence}"


class EventStore:
    def __init__(self, db, store_raw=False):
        self.db = db
        self.store_raw = store_raw

    def ingest(self, events, *, mode, trust, source, agent_id="", site_id=1, atomic=True):
        """Insert events idempotently.

        Returns ``{"accepted": [ids], "duplicates": n, "rejected": [{"index", "error"}]}``.
        With ``atomic=True`` any invalid event rejects the whole batch (manual imports).
        With ``atomic=False`` invalid events are reported individually so one
        malformed record can never block an agent's delivery queue.
        """
        if mode not in MODES or trust not in TRUST:
            raise ValueError("Invalid ingestion mode")
        if not isinstance(events, list) or not 1 <= len(events) <= MAX_BATCH:
            raise ValueError(f"Submit 1–{MAX_BATCH} events")
        now = utcnow()
        normalized, rejected = [], []
        for index, item in enumerate(events):
            try:
                normalized.append((index, validate_event(item, now)))
            except ValueError as exc:
                if atomic:
                    raise ValueError(f"Event {index + 1}: {exc}") from exc
                rejected.append({"index": index, "error": str(exc)})
        seen = {}
        accepted, duplicates = [], 0
        received = iso(now)
        with self.db.tx() as conn:
            for index, event in normalized:
                if event["client_uid"] and agent_id:
                    uid = f"agt:{agent_id}:{event['client_uid']}"
                elif event["client_uid"]:
                    uid = f"{source}:{event['client_uid']}"
                else:
                    base = content_uid(source, event, 0)
                    seen[base] = seen.get(base, -1) + 1
                    uid = content_uid(source, event, seen[base])
                cur = conn.execute(
                    """INSERT OR IGNORE INTO events(uid,site_id,agent_id,source,type,host,source_ip,dest_ip,dest_port,actor,
                       target,message,details,raw,timestamp,received_at,mode,trust)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (uid, site_id, agent_id, source, event["type"], event["host"], event["source_ip"], event["dest_ip"],
                     event["dest_port"], event["actor"], event["target"], event["message"],
                     json.dumps(event["details"], sort_keys=True), event["raw"] if self.store_raw else None,
                     event["timestamp"], received, mode, trust))
                if cur.rowcount:
                    accepted.append(cur.lastrowid)
                else:
                    duplicates += 1
            if accepted:
                self.db.bump_revision(conn)
        return {"accepted": accepted, "duplicates": duplicates, "rejected": rejected}

    def count(self, mode=None):
        if mode:
            return self.db.scalar("SELECT COUNT(*) FROM events WHERE mode = ?", (mode,))
        return self.db.scalar("SELECT COUNT(*) FROM events")

    def get_many(self, ids):
        ids = list(ids)[:5000]
        if not ids:
            return []
        rows = []
        for start in range(0, len(ids), 500):
            chunk = ids[start:start + 500]
            # Interpolated text is fixed column names / '?' placeholders; all values are bound parameters.
            rows += self.db.query(f"SELECT * FROM events WHERE id IN ({','.join('?' * len(chunk))})", chunk)  # nosec B608
        return [decode(r) for r in sorted(rows, key=lambda r: (r["timestamp"], r["id"]))]

    def search(self, q="", type_="", host="", source_ip="", mode="", agent_id="", since="", until="",
               limit=100, cursor=""):
        """Server-side search with keyset pagination over (timestamp, id) descending."""
        limit = max(1, min(int(limit), 500))
        sql, params = ["SELECT * FROM events WHERE 1=1"], []
        if type_:
            if type_ not in EVENT_TYPES:
                raise ValueError("Unknown event type")
            sql.append("AND type = ?")
            params.append(type_)
        for column, value in (("host", host), ("source_ip", source_ip), ("agent_id", agent_id)):
            if value:
                sql.append(f"AND {column} = ?")
                params.append(str(value)[:120])
        if mode:
            if mode not in MODES:
                raise ValueError("Unknown mode")
            sql.append("AND mode = ?")
            params.append(mode)
        for op, value in ((">=", since), ("<=", until)):
            if value:
                try:
                    sql.append(f"AND timestamp {op} ?")
                    params.append(iso(parse_iso(str(value).replace(" ", "+"))))  # '+' may arrive URL-decoded as a space
                except ValueError as exc:
                    raise ValueError("Invalid time filter") from exc
        if q:
            like = "%" + str(q)[:200].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            sql.append("AND (message LIKE ? ESCAPE '\\' OR actor LIKE ? ESCAPE '\\' OR host LIKE ? ESCAPE '\\' "
                       "OR source_ip LIKE ? ESCAPE '\\' OR target LIKE ? ESCAPE '\\' OR type LIKE ? ESCAPE '\\')")
            params += [like] * 6
        if cursor:
            try:
                ts, cid = cursor.rsplit("|", 1)
                sql.append("AND (timestamp < ? OR (timestamp = ? AND id < ?))")
                params += [ts, ts, int(cid)]
            except ValueError as exc:
                raise ValueError("Invalid cursor") from exc
        sql.append("ORDER BY timestamp DESC, id DESC LIMIT ?")
        params.append(limit + 1)
        rows = [decode(r) for r in self.db.query(" ".join(sql), params)]
        more = len(rows) > limit
        rows = rows[:limit]
        next_cursor = f"{rows[-1]['timestamp']}|{rows[-1]['id']}" if more and rows else None
        return {"events": rows, "next_cursor": next_cursor}

    def window(self, since, until, types=None):
        sql, params = "SELECT * FROM events WHERE timestamp >= ? AND timestamp <= ?", [since, until]
        if types:
            sql += f" AND type IN ({','.join('?' * len(types))})"
            params += list(types)
        return [decode(r) for r in self.db.query(sql + " ORDER BY timestamp, id", params)]

    def hourly_histogram(self, hours=24):
        start = utcnow().replace(minute=0, second=0, microsecond=0) - timedelta(hours=hours - 1)
        rows = self.db.query(
            "SELECT substr(timestamp,1,13) AS hour, mode, COUNT(*) AS n FROM events WHERE timestamp >= ? GROUP BY hour, mode",
            (iso(start),))
        buckets = []
        for i in range(hours):
            key = (start + timedelta(hours=i)).strftime("%Y-%m-%dT%H")
            counts = {r["mode"]: r["n"] for r in rows if r["hour"] == key}
            buckets.append({"hour": key + ":00:00+00:00", "live": counts.get("live", 0),
                            "imported": counts.get("imported", 0), "demo": counts.get("demo", 0)})
        return buckets

    def delete_demo(self, conn):
        conn.execute("DELETE FROM incidents WHERE mode = 'demo' AND id NOT IN ("
                     "SELECT ie.incident_id FROM incident_events ie JOIN events e ON e.id = ie.event_id WHERE e.mode != 'demo')")
        return conn.execute("DELETE FROM events WHERE mode = 'demo'").rowcount


def decode(row):
    row = dict(row)
    try:
        row["details"] = json.loads(row.get("details") or "{}")
    except ValueError:
        row["details"] = {}
    return row
