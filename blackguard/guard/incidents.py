"""Incident queries, investigation notes, status workflow and timelines."""

import json

from guard.db import iso
from guard.events import decode
from guard.rules import RULES_BY_ID

STATUSES = ("open", "investigating", "resolved")
SEVERITY_ORDER = "CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END"


def _decode(row):
    row = dict(row)
    row["affected_hosts"] = json.loads(row.get("affected_hosts") or "[]")
    rule = RULES_BY_ID.get(row["rule_id"])
    row["rule_name"] = rule.name if rule else row["rule_id"]
    return row


class Incidents:
    def __init__(self, db, audit):
        self.db = db
        self.audit = audit

    def list(self, status="", severity="", q="", mode="", limit=500):
        sql, params = ["SELECT * FROM incidents WHERE 1=1"], []
        if status:
            if status == "active":
                sql.append("AND status != 'resolved'")
            elif status in STATUSES:
                sql.append("AND status = ?")
                params.append(status)
            else:
                raise ValueError("Unknown status")
        if severity:
            sql.append("AND severity = ?")
            params.append(severity)
        if mode:
            sql.append("AND mode = ?")
            params.append(mode)
        if q:
            like = "%" + str(q)[:120].replace("%", "").replace("_", "") + "%"
            sql.append("AND (title LIKE ? OR summary LIKE ? OR host LIKE ? OR source_ip LIKE ? OR rule_id LIKE ? OR affected_hosts LIKE ?)")
            params += [like] * 6
        sql.append(f"ORDER BY (status = 'resolved'), {SEVERITY_ORDER} DESC, last_seen DESC LIMIT ?")
        params.append(max(1, min(int(limit), 1000)))
        return [_decode(r) for r in self.db.query(" ".join(sql), params)]

    def get(self, incident_id):
        row = self.db.one("SELECT * FROM incidents WHERE id = ?", (incident_id,))
        return _decode(row) if row else None

    def evidence(self, incident_id, limit=1000):
        rows = self.db.query(
            "SELECT e.* FROM incident_events ie JOIN events e ON e.id = ie.event_id WHERE ie.incident_id = ? "
            "ORDER BY e.timestamp, e.id LIMIT ?", (incident_id, limit))
        return [decode(r) for r in rows]

    def notes(self, incident_id):
        rows = self.db.query("SELECT * FROM incident_notes WHERE incident_id = ? ORDER BY id", (incident_id,))
        for row in rows:
            row["meta"] = json.loads(row["meta"] or "{}")
        return rows

    def detail(self, incident_id, response_actions):
        incident = self.get(incident_id)
        if not incident:
            return None
        rule = RULES_BY_ID.get(incident["rule_id"])
        evidence = self.evidence(incident_id)
        notes = self.notes(incident_id)
        timeline = [{"at": e["timestamp"], "kind": "event", "type": e["type"], "host": e["host"], "text": e["message"],
                     "event_id": e["id"], "mode": e["mode"]} for e in evidence]
        timeline += [{"at": n["created_at"], "kind": n["kind"], "text": n["body"], "author": n["author_name"]} for n in notes]
        timeline.sort(key=lambda t: t["at"])
        hosts = incident["affected_hosts"] or sorted({e["host"] for e in evidence})
        devices = []
        for host in hosts:
            device = self.db.one("SELECT id, display_name, hostname, ip_address, os, identity_confidence, agent_id FROM inventory "
                                 "WHERE hostname = ? COLLATE NOCASE OR display_name = ? COLLATE NOCASE LIMIT 1", (host, host))
            devices.append({"host": host, "inventory": device})
        incident.update(
            evidence=evidence, notes=notes, timeline=timeline, devices=devices,
            source_ips=sorted({e["source_ip"] for e in evidence if e["source_ip"]}),
            accounts=sorted({e["actor"] for e in evidence if e["actor"] != "unknown"}),
            rule=rule.describe() if rule else None,
            responses=response_actions,
        )
        return incident

    def set_status(self, incident_id, status, actor, note="", ip=""):
        if status not in STATUSES:
            raise ValueError("Invalid incident status")
        with self.db.tx() as conn:
            row = conn.execute("SELECT status FROM incidents WHERE id = ?", (incident_id,)).fetchone()
            if not row:
                return False
            if row["status"] == status:
                return True
            now = iso()
            conn.execute("UPDATE incidents SET status=?, updated_at=?, resolved_at=? WHERE id=?",
                         (status, now, now if status == "resolved" else None, incident_id))
            text = f"Status changed from {row['status']} to {status}."
            if note:
                text += f" Reason: {str(note).strip()[:1000]}"
            conn.execute("INSERT INTO incident_notes(incident_id,author_id,author_name,kind,body,created_at) VALUES(?,?,?,?,?,?)",
                         (incident_id, actor.get("id"), actor.get("name", ""), "system", text, now))
            self.audit.record("incident.status", actor=actor, target_type="incident", target_id=incident_id, ip=ip,
                              detail={"from": row["status"], "to": status}, conn=conn)
            self.db.bump_revision(conn)
        return True

    def add_note(self, incident_id, actor, body, kind="note", meta=None, ip=""):
        body = str(body or "").strip()
        if not 1 <= len(body) <= 8000:
            raise ValueError("Note must be 1–8000 characters")
        with self.db.tx() as conn:
            if not conn.execute("SELECT 1 FROM incidents WHERE id = ?", (incident_id,)).fetchone():
                raise LookupError("Incident not found")
            cur = conn.execute(
                "INSERT INTO incident_notes(incident_id,author_id,author_name,kind,body,meta,created_at) VALUES(?,?,?,?,?,?,?)",
                (incident_id, actor.get("id"), actor.get("name", ""), kind, body, json.dumps(meta or {}), iso()))
            conn.execute("UPDATE incidents SET updated_at=? WHERE id=?", (iso(), incident_id))
            self.audit.record(f"incident.{kind}", actor=actor, target_type="incident", target_id=incident_id, ip=ip,
                              detail={"note_id": cur.lastrowid, "length": len(body)}, conn=conn)
            self.db.bump_revision(conn)
            return cur.lastrowid

    def counts(self):
        rows = self.db.query("SELECT severity, status, mode, COUNT(*) AS n FROM incidents GROUP BY severity, status, mode")
        active = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        totals = {"open": 0, "investigating": 0, "resolved": 0}
        live_active = 0
        for r in rows:
            totals[r["status"]] = totals.get(r["status"], 0) + r["n"]
            if r["status"] != "resolved":
                active[r["severity"]] = active.get(r["severity"], 0) + r["n"]
                if r["mode"] != "demo":
                    live_active += r["n"]
        return {"active_by_severity": active, "by_status": totals, "live_active": live_active}
