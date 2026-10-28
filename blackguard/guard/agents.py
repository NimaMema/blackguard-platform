"""Agent enrollment, per-agent credentials, rotation, revocation and health.

Trust model
-----------
* An administrator creates a one-time enrollment code (expires, single use).
* The agent enrolls with that code and receives a unique credential, but stays
  ``pending``: it cannot submit data until an administrator approves it after
  comparing the machine fingerprint the agent prints locally.
* The server derives agent identity from the credential only. Any
  ``agent_id`` field a client sends is ignored, so one agent cannot report as
  another.
* Credentials are stored as SHA-256 hashes (they are 256-bit random values).
* Rotation is two-phase: the new credential becomes primary the first time it
  is used, so a lost response never locks an agent out.
"""

import json
import re
import secrets
from datetime import timedelta

from guard.db import iso, parse_iso, utcnow
from guard.security import new_enrollment_code, new_token, normalize_code, token_hash

FINGERPRINT_RE = re.compile(r"^[a-f0-9]{64}$")
SOURCE_RE = re.compile(r"^[a-z0-9_-]{1,32}$")
CREDENTIAL_MAX_AGE_DAYS = 90


class AgentError(Exception):
    def __init__(self, message, status=403):
        super().__init__(message)
        self.status = status


def _clean(value, field, high, required=True):
    text = " ".join(str(value or "").split())[:high]
    if required and not text:
        raise ValueError(f"{field} is required")
    return text


def public_agent(row, now=None):
    now = now or utcnow()
    agent = dict(row)
    for secret in ("credential_hash", "next_credential_hash"):
        agent.pop(secret, None)
    agent["health"] = json.loads(agent.get("health") or "{}")
    agent["sources"] = json.loads(agent.get("sources") or "[]")
    last = agent.get("last_contact_at")
    age = (now - parse_iso(last)).total_seconds() if last else None
    agent["seconds_since_contact"] = int(age) if age is not None else None
    if agent["status"] == "active":
        agent["connection"] = "online" if age is not None and age <= agent["offline_after_seconds"] else "offline"
    else:
        agent["connection"] = agent["status"]
    issued = agent.get("credential_issued_at")
    agent["credential_age_days"] = (now - parse_iso(issued)).days if issued else None
    agent["fingerprint_short"] = (agent.get("fingerprint") or agent.get("reported_fingerprint") or "")[:16]
    return agent


class Agents:
    def __init__(self, db, audit, events, inventory):
        self.db = db
        self.audit = audit
        self.events = events
        self.inventory = inventory

    # -- invites ------------------------------------------------------------
    def create_invite(self, name, actor, ttl_minutes=30, ip=""):
        name = _clean(name, "Device name", 80)
        ttl = int(ttl_minutes)
        if not 5 <= ttl <= 1440:
            raise ValueError("Invite lifetime must be 5–1440 minutes")
        code = new_enrollment_code()
        now = utcnow()
        with self.db.tx() as conn:
            cur = conn.execute(
                "INSERT INTO enrollment_invites(code_hash,name,created_by,created_at,expires_at) VALUES(?,?,?,?,?)",
                (token_hash(normalize_code(code)), name, actor.get("id"), iso(now), iso(now + timedelta(minutes=ttl))))
            self.audit.record("agent.invite.create", actor=actor, target_type="invite", target_id=cur.lastrowid, ip=ip,
                              detail={"name": name, "ttl_minutes": ttl}, conn=conn)
            self.db.bump_revision(conn)
        return {"id": cur.lastrowid, "code": code, "name": name, "expires_at": iso(now + timedelta(minutes=ttl))}

    def list_invites(self):
        rows = self.db.query("SELECT id,name,created_at,expires_at,used_at,agent_id,revoked FROM enrollment_invites ORDER BY id DESC LIMIT 100")
        now = utcnow()
        for r in rows:
            r["state"] = ("revoked" if r["revoked"] else "used" if r["used_at"] else
                          "expired" if parse_iso(r["expires_at"]) <= now else "valid")
        return rows

    def revoke_invite(self, invite_id, actor, ip=""):
        with self.db.tx() as conn:
            changed = conn.execute("UPDATE enrollment_invites SET revoked=1 WHERE id=? AND used_at IS NULL", (invite_id,)).rowcount
            if changed:
                self.audit.record("agent.invite.revoke", actor=actor, target_type="invite", target_id=invite_id, ip=ip, conn=conn)
                self.db.bump_revision(conn)
        return bool(changed)

    # -- enrollment ---------------------------------------------------------
    def enroll(self, data, ip=""):
        if not isinstance(data, dict):
            raise ValueError("Expected an object")
        code = normalize_code(data.get("code", ""))
        hostname = _clean(data.get("hostname"), "hostname", 120)
        platform = _clean(data.get("platform"), "platform", 120)
        version = _clean(data.get("agent_version"), "agent_version", 40, required=False)
        fingerprint = str(data.get("fingerprint", "")).lower()
        if not FINGERPRINT_RE.match(fingerprint):
            raise ValueError("fingerprint must be a 64-character hex SHA-256 value")
        sources = data.get("sources") or []
        if not isinstance(sources, list) or len(sources) > 10 or not all(isinstance(s, str) and SOURCE_RE.match(s) for s in sources):
            raise ValueError("sources must be a short list of source names")
        now = utcnow()
        with self.db.tx() as conn:
            invite = conn.execute("SELECT * FROM enrollment_invites WHERE code_hash = ?", (token_hash(code),)).fetchone()
            if (not invite or invite["used_at"] or invite["revoked"] or parse_iso(invite["expires_at"]) <= now):
                self.audit.record("agent.enroll", "failure", actor={"type": "anonymous"}, ip=ip,
                                  detail={"reason": "invalid, used, revoked or expired code", "hostname": hostname}, conn=conn)
                raise AgentError("Enrollment code is invalid, expired, or already used.", 403)
            agent_id = "agt_" + secrets.token_hex(8)
            credential = new_token("bga_")
            conn.execute(
                "INSERT INTO agents(id,org_id,site_id,name,status,hostname,platform,reported_fingerprint,agent_version,sources,"
                "credential_hash,credential_issued_at,enrolled_at,last_contact_at,last_ip,invite_id) "
                "VALUES(?,?,?,?,'pending',?,?,?,?,?,?,?,?,?,?,?)",
                (agent_id, invite["org_id"], invite["site_id"], invite["name"], hostname, platform, fingerprint, version,
                 json.dumps(sources), token_hash(credential), iso(now), iso(now), iso(now), ip, invite["id"]))
            conn.execute("UPDATE enrollment_invites SET used_at=?, agent_id=? WHERE id=?", (iso(now), agent_id, invite["id"]))
            self.audit.record("agent.enroll", actor={"type": "agent", "id": agent_id, "name": invite["name"]},
                              target_type="agent", target_id=agent_id, ip=ip,
                              detail={"hostname": hostname, "platform": platform, "fingerprint": fingerprint[:16]}, conn=conn)
            self.db.bump_revision(conn)
        return {"agent_id": agent_id, "credential": credential, "status": "pending", "name": invite["name"],
                "fingerprint": fingerprint,
                "message": "Enrolled. An administrator must approve this agent after comparing its fingerprint."}

    # -- authentication -----------------------------------------------------
    def authenticate(self, credential, ip=""):
        if not credential or not credential.startswith("bga_") or len(credential) > 120:
            raise AgentError("Agent credential required", 401)
        hashed = token_hash(credential)
        row = self.db.one("SELECT * FROM agents WHERE credential_hash = ? OR next_credential_hash = ?", (hashed, hashed))
        if not row:
            raise AgentError("Unknown or revoked agent credential", 401)
        if row["next_credential_hash"] == hashed:
            # First use of a rotated credential: promote it and retire the old one.
            with self.db.tx() as conn:
                conn.execute("UPDATE agents SET credential_hash=?, next_credential_hash=NULL, credential_issued_at=?, "
                             "rotate_requested=0 WHERE id=?", (hashed, iso(), row["id"]))
                self.audit.record("agent.rotate.complete", actor={"type": "agent", "id": row["id"], "name": row["name"]},
                                  target_type="agent", target_id=row["id"], ip=ip, conn=conn)
            row = self.db.one("SELECT * FROM agents WHERE id = ?", (row["id"],))
        return row

    @staticmethod
    def require_active(agent):
        if agent["status"] == "pending":
            raise AgentError("Agent is awaiting administrator approval", 403)
        if agent["status"] == "suspended":
            raise AgentError(f"Agent is suspended: {agent['status_reason']}", 403)
        if agent["status"] != "active":
            raise AgentError("Agent is not active", 403)

    # -- admin actions ------------------------------------------------------
    def get(self, agent_id):
        row = self.db.one("SELECT * FROM agents WHERE id = ?", (agent_id,))
        return public_agent(row) if row else None

    def list(self):
        now = utcnow()
        return [public_agent(r, now) for r in self.db.query(
            "SELECT * FROM agents ORDER BY CASE status WHEN 'pending' THEN 0 WHEN 'suspended' THEN 1 WHEN 'active' THEN 2 ELSE 3 END, name")]

    def approve(self, agent_id, actor, fingerprint_confirmation="", ip=""):
        with self.db.tx() as conn:
            row = conn.execute("SELECT * FROM agents WHERE id = ?", (agent_id,)).fetchone()
            if not row:
                raise LookupError("Agent not found")
            if row["status"] not in ("pending", "suspended"):
                raise ValueError("Only pending or suspended agents can be approved")
            confirmation = str(fingerprint_confirmation or "").lower().replace(" ", "")
            if len(confirmation) < 8 or not row["reported_fingerprint"].startswith(confirmation):
                raise ValueError("Type at least the first 8 characters of the fingerprint shown on the agent's machine to confirm its identity")
            conn.execute("UPDATE agents SET status='active', fingerprint=reported_fingerprint, approved_at=?, approved_by=?, "
                         "status_reason='' WHERE id=?", (iso(), actor.get("id"), agent_id))
            self.audit.record("agent.approve", actor=actor, target_type="agent", target_id=agent_id, ip=ip,
                              detail={"previous_status": row["status"], "fingerprint": row["reported_fingerprint"][:16]}, conn=conn)
            self.inventory.link_agent(conn, dict(row) | {"status": "active"})
            self.db.bump_revision(conn)
        return self.get(agent_id)

    def revoke(self, agent_id, actor, reason="", ip=""):
        with self.db.tx() as conn:
            row = conn.execute("SELECT status FROM agents WHERE id = ?", (agent_id,)).fetchone()
            if not row:
                raise LookupError("Agent not found")
            conn.execute("UPDATE agents SET status='revoked', credential_hash=NULL, next_credential_hash=NULL, revoked_at=?, "
                         "revoked_by=?, status_reason=? WHERE id=?",
                         (iso(), actor.get("id"), _clean(reason, "reason", 300, required=False) or "Revoked by administrator", agent_id))
            self.audit.record("agent.revoke", actor=actor, target_type="agent", target_id=agent_id, ip=ip,
                              detail={"previous_status": row["status"], "reason": reason[:300]}, conn=conn)
            self.db.bump_revision(conn)
        return self.get(agent_id)

    def request_rotation(self, agent_id, actor, ip=""):
        with self.db.tx() as conn:
            changed = conn.execute("UPDATE agents SET rotate_requested=1 WHERE id=? AND status='active'", (agent_id,)).rowcount
            if not changed:
                raise ValueError("Only active agents can rotate credentials")
            self.audit.record("agent.rotate.request", actor=actor, target_type="agent", target_id=agent_id, ip=ip, conn=conn)
            self.db.bump_revision(conn)
        return self.get(agent_id)

    def update_settings(self, agent_id, actor, name=None, offline_after_seconds=None, ip=""):
        changes = {}
        if name is not None:
            changes["name"] = _clean(name, "name", 80)
        if offline_after_seconds is not None:
            value = int(offline_after_seconds)
            if not 60 <= value <= 86400 * 7:
                raise ValueError("Offline threshold must be 60 seconds to 7 days")
            changes["offline_after_seconds"] = value
        if not changes:
            return self.get(agent_id)
        with self.db.tx() as conn:
            # Interpolated text is fixed column names / '?' placeholders; all values are bound parameters.
            if not conn.execute(f"UPDATE agents SET {', '.join(f'{k}=?' for k in changes)} WHERE id=?",  # nosec B608
                                (*changes.values(), agent_id)).rowcount:
                raise LookupError("Agent not found")
            self.audit.record("agent.update", actor=actor, target_type="agent", target_id=agent_id, ip=ip, detail=changes, conn=conn)
            self.db.bump_revision(conn)
        return self.get(agent_id)

    # -- agent-initiated ----------------------------------------------------
    def rotate(self, agent, ip=""):
        self.require_active(agent)
        credential = new_token("bga_")
        with self.db.tx() as conn:
            conn.execute("UPDATE agents SET next_credential_hash=? WHERE id=?", (token_hash(credential), agent["id"]))
            self.audit.record("agent.rotate.issue", actor={"type": "agent", "id": agent["id"], "name": agent["name"]},
                              target_type="agent", target_id=agent["id"], ip=ip, conn=conn)
        return {"credential": credential, "message": "Store the new credential, then use it for the next request."}

    def heartbeat(self, agent, data, ip=""):
        """Record contact and health. Returns (response, notices) where notices are server events to ingest."""
        if not isinstance(data, dict):
            raise ValueError("Expected an object")
        notices = []
        now = utcnow()
        fingerprint = str(data.get("fingerprint", "")).lower()
        health = data.get("health") if isinstance(data.get("health"), dict) else {}
        encoded = json.dumps(health, default=str)
        health = json.loads(encoded) if len(encoded) <= 8000 else {"error": "health report too large"}
        previous = json.loads(agent["health"] or "{}")
        stopping = health.get("state") == "stopping"
        if stopping:
            health["last_stop"] = {"at": iso(now), "reason": str(health.get("stop_reason", "agent-stopped"))[:40]}
        elif previous.get("last_stop") and not agent["offline_alerted"]:
            health["last_stop"] = previous["last_stop"]  # keep until the outage it explains is classified
        with self.db.tx() as conn:
            status = agent["status"]
            if status == "active" and fingerprint and agent["fingerprint"] and fingerprint != agent["fingerprint"]:
                status = "suspended"
                reason = "Machine fingerprint changed; re-approve if the machine was reinstalled, otherwise revoke."
                conn.execute("UPDATE agents SET status='suspended', status_reason=?, reported_fingerprint=? WHERE id=?",
                             (reason, fingerprint, agent["id"]))
                self.audit.record("agent.identity_mismatch", "failure", actor={"type": "agent", "id": agent["id"], "name": agent["name"]},
                                  target_type="agent", target_id=agent["id"], ip=ip,
                                  detail={"expected": agent["fingerprint"][:16], "reported": fingerprint[:16]}, conn=conn)
                notices.append(self.notice("identity_mismatch", agent,
                                           f"Agent '{agent['name']}' presented a different machine fingerprint "
                                           f"({fingerprint[:16]}… instead of {agent['fingerprint'][:16]}…) from {ip or 'unknown IP'}. "
                                           "The agent was suspended."))
            dropped, before = health.get("dropped_total"), previous.get("dropped_total", 0)
            if isinstance(dropped, int) and isinstance(before, int) and dropped > before:
                notices.append(self.notice("data_loss", agent,
                                           f"Agent '{agent['name']}' discarded {dropped - before} buffered event(s) because its "
                                           "local spool was full."))
            if agent["offline_alerted"] and not stopping and status == "active":
                notices.append(self.recovery_notice(agent, previous, health, now))
            conn.execute("UPDATE agents SET last_contact_at=?, last_ip=?, health=?, offline_alerted=0, "
                         "agent_version=COALESCE(NULLIF(?,''),agent_version) WHERE id=?",
                         (iso(now), ip, json.dumps(health), _clean(data.get("agent_version"), "v", 40, False), agent["id"]))
            if status == "active":
                self.inventory.touch_agent(conn, agent["id"], iso(now))
            self.db.bump_revision(conn)
        response = {"status": status, "rotate": bool(agent["rotate_requested"]), "server_time": iso(now),
                    "heartbeat_seconds": 30}
        return response, notices

    def recovery_notice(self, agent, previous, health, now):
        """Explain an outage once the agent is back, using evidence rather than guesses.

        Distinguishes: the device restarted (boot time changed), the agent was stopped while the
        device kept running (clean-stop report, same boot), the agent could not reach the server
        (it reports when deliveries started failing), or an unexplained interruption.
        """
        gap_min = int((now - parse_iso(agent["last_contact_at"])).total_seconds() // 60) if agent["last_contact_at"] else None
        before, after = previous.get("boot_time"), health.get("boot_time")
        stop = previous.get("last_stop")
        reasons = []
        if before and after:
            rebooted = abs((parse_iso(after) - parse_iso(before)).total_seconds()) > 120
        else:
            rebooted = None
        if rebooted:
            cause = "device_restarted"
            reasons.append(f"The device restarted: boot time changed from {before} to {after}.")
            if stop and stop.get("reason") == "system-shutdown":
                reasons.append(f"The agent reported a clean system shutdown at {stop['at']}.")
        elif stop:
            cause = "agent_stopped"
            reasons.append(f"The agent reported it was stopped ({stop.get('reason')}) at {stop.get('at')}"
                           + (" while the device kept running (boot time unchanged)." if rebooted is False else "."))
            reasons.append("Confirm that you stopped it; stopping a collector is also a way to hide activity.")
        elif health.get("server_unreachable_since"):
            cause = "server_unreachable"
            reasons.append(f"The agent kept running but could not reach the server since {health['server_unreachable_since']} "
                           f"(network path or BLACKGUARD server unavailable). {health.get('spool_depth', 0)} events were buffered "
                           "locally and are being delivered.")
        else:
            cause = "unexplained"
            reasons.append("No clean stop, reboot or connectivity failure was reported: the agent process may have crashed or "
                           "been killed, or the device lost power" + (" (boot-time data unavailable)." if rebooted is None else "."))
        message = f"Agent '{agent['name']}' reconnected after {gap_min if gap_min is not None else '?'} minutes. " + " ".join(reasons)
        item = self.notice("agent_recovered", agent, message)
        item["details"]["cause"] = cause
        return item

    @staticmethod
    def notice(kind, agent, message):
        now = utcnow()
        return {"type": "collector_notice", "host": agent["hostname"] or agent["name"], "actor": "blackguard",
                "message": message, "timestamp": iso(now),
                "uid": f"notice:{kind}:{agent['id']}:{now.strftime('%Y%m%dT%H%M%S')}",
                "details": {"kind": kind, "agent_id": agent["id"]}}

    def offline_sweep(self, server_started_at=None):
        """Mark agents that missed heartbeats; returns server notices for new offline transitions.

        Silence is measured from the later of the last contact and the server's own start, so agents
        are given a full threshold to reconnect after the server itself was down or restarted.
        """
        now = utcnow()
        notices = []
        rows = self.db.query("SELECT * FROM agents WHERE status='active' AND offline_alerted=0 AND last_contact_at IS NOT NULL")
        for row in rows:
            age = (now - parse_iso(row["last_contact_at"])).total_seconds()
            silent_since = max(parse_iso(row["last_contact_at"]), server_started_at or parse_iso(row["last_contact_at"]))
            if (now - silent_since).total_seconds() > row["offline_after_seconds"]:
                stop = json.loads(row["health"] or "{}").get("last_stop")
                with self.db.tx() as conn:
                    conn.execute("UPDATE agents SET offline_alerted=1 WHERE id=?", (row["id"],))
                    self.db.bump_revision(conn)
                detail = (f" Its last message was a clean stop ({stop.get('reason')}) at {stop.get('at')}." if stop
                          else " It did not report a clean stop.")
                notices.append(self.notice("agent_offline", row,
                                           f"Agent '{row['name']}' has not reported since {row['last_contact_at']} "
                                           f"({int(age // 60)} minutes; threshold {row['offline_after_seconds'] // 60} minutes)." + detail))
        stale = iso(now - timedelta(days=CREDENTIAL_MAX_AGE_DAYS))
        with self.db.tx() as conn:
            conn.execute("UPDATE agents SET rotate_requested=1 WHERE status='active' AND credential_issued_at < ? AND rotate_requested=0",
                         (stale,))
        return notices
