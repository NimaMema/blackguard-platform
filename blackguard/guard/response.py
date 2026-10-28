"""Guardian Response: an approval-gated, audited response workflow.

BLACKGUARD never blocks addresses, disconnects devices, changes firewall
rules or resets credentials on its own. Every action is a *proposal* that an
administrator must approve after acknowledging its impact. Approved actions
are carried out by a person (the ``manual`` integration) and recorded with
their outcome and rollback plan.

``Integration`` is the extension point for future authorised automations
(e.g. a router API that moves a device to a quarantine VLAN). A new
integration must implement ``plan``/``execute``/``rollback``, be explicitly
enabled by an administrator, and remains gated by the same approval and audit
workflow. No such automation ships in this release, and counter-attacks are
out of scope permanently.
"""

from guard.db import iso
from guard.rules import RULES_BY_ID

ACTION_CATALOG = {
    "review_sessions": {
        "title": "Review active sessions for the affected account",
        "steps": ["Open the account provider's security page or the device's session list.",
                  "Identify sessions from unrecognised devices or locations.",
                  "Sign out unrecognised sessions using the provider's own controls."],
        "impact": "Signing out sessions interrupts the legitimate user on those devices.",
        "rollback": "The legitimate user signs in again.",
        "changes_security": False,
    },
    "reset_credentials": {
        "title": "Reset the potentially compromised credential",
        "steps": ["Use the account provider's official password-reset or admin console (never a link from an alert email).",
                  "Choose a new unique passphrase and enable multi-factor authentication if available.",
                  "Update the password on devices and services that legitimately use the account."],
        "impact": "Devices and services using the old password will fail to sign in until updated.",
        "rollback": "Credentials cannot be 'un-reset'; restore service by updating the new password where needed.",
        "changes_security": True,
    },
    "investigate_device": {
        "title": "Investigate the affected device",
        "steps": ["Review the device's recent events in BLACKGUARD (Device inventory → device).",
                  "Run a full scan with the device's installed antivirus/EDR.",
                  "Check for unexpected startup programs, services, scheduled tasks and user accounts."],
        "impact": "None by itself; scans may slow the device temporarily.",
        "rollback": "Not applicable.",
        "changes_security": False,
    },
    "review_exposure": {
        "title": "Review firewall and internet exposure",
        "steps": ["List port-forwarding / UPnP mappings on your router.",
                  "Confirm each exposed service is intended and patched.",
                  "Plan any firewall change separately; note the current rule set first so it can be restored."],
        "impact": "Review only. Any later firewall change may break services that rely on the exposed port.",
        "rollback": "Restore the router configuration from the backup you took before changing it.",
        "changes_security": False,
    },
    "review_configuration": {
        "title": "Review the configuration change against your baseline",
        "steps": ["Compare the current policy/configuration to your known-good baseline or backup.",
                  "Identify who made the change and why.",
                  "Revert unapproved changes using the system's own admin tools after confirming impact."],
        "impact": "Reverting a legitimate change can break the purpose it served.",
        "rollback": "Re-apply the change from your notes or backup.",
        "changes_security": True,
    },
    "review_account": {
        "title": "Review the account and its privileges",
        "steps": ["Confirm the account and any new privileges were approved.",
                  "If not, disable the account or remove the privilege using the operating system's admin tools.",
                  "Review the account's activity since the change."],
        "impact": "Disabling an account or removing privileges stops anything that depends on it.",
        "rollback": "Re-enable the account / restore the group membership with the same admin tools.",
        "changes_security": True,
    },
    "isolate_device": {
        "title": "Isolate the device from the network",
        "steps": ["No automated isolation integration is configured. Perform isolation manually:",
                  "Disconnect the device's network cable or Wi-Fi, or move it to a guest/quarantine network in your router's admin interface.",
                  "Keep the device powered on if you may need its memory for investigation."],
        "impact": "The device loses network access; anyone using it is interrupted, and remote access to it is lost.",
        "rollback": "Reconnect the device or move it back to its normal network once it is cleared.",
        "changes_security": True,
    },
    "revoke_agent": {
        "title": "Revoke the BLACKGUARD agent credential",
        "steps": ["In Agents, choose Revoke for the affected agent.",
                  "Re-enroll the machine with a new enrollment code once it is trusted again."],
        "impact": "BLACKGUARD stops receiving events from that machine until it is re-enrolled.",
        "rollback": "Create a new enrollment code and re-enroll (revocation itself is permanent by design).",
        "changes_security": True,
    },
    "review_unknown_device": {
        "title": "Identify the unknown device",
        "steps": ["Find the device by MAC/hostname in your router's connected-clients list.",
                  "If it is yours, mark it known in Device inventory.",
                  "If not, block it in the router and change the Wi-Fi passphrase."],
        "impact": "Changing the Wi-Fi passphrase disconnects every wireless device until it is re-entered.",
        "rollback": "Unblock the device in the router.",
        "changes_security": True,
    },
}

TRANSITIONS = {
    "approve": ("proposed", "approved"),
    "reject": ("proposed", "rejected"),
    "cancel": ("proposed", "cancelled"),
    "complete": ("approved", "completed"),
    "rollback": ("completed", "rolled_back"),
}


class Integration:
    """Interface for future authorised response integrations (none enabled by default)."""
    name = "abstract"

    def plan(self, action):
        raise NotImplementedError

    def execute(self, action):
        raise NotImplementedError

    def rollback(self, action):
        raise NotImplementedError


class ManualIntegration(Integration):
    """Records that a human performed the steps outside BLACKGUARD."""
    name = "manual"

    def plan(self, action):
        return ACTION_CATALOG[action["action_type"]]["steps"]


INTEGRATIONS = {"manual": ManualIntegration()}


def guidance(rule_id):
    rule = RULES_BY_ID.get(rule_id)
    keys = rule.responses if rule else ("investigate_device",)
    return {
        "automatic_action": False,
        "actions": [ACTION_CATALOG[k]["title"] for k in keys],
        "recommended": [{"type": k, **{f: ACTION_CATALOG[k][f] for f in ("title", "steps", "impact", "rollback", "changes_security")}}
                        for k in keys],
        "investigation": list(rule.investigation) if rule else [],
        "false_positives": list(rule.false_positives) if rule else [],
    }


class Responses:
    def __init__(self, db, audit):
        self.db = db
        self.audit = audit

    def list(self, incident_id=None, status=""):
        sql, params = ("SELECT r.*, i.title AS incident_title, i.severity AS incident_severity FROM response_actions r "
                       "JOIN incidents i ON i.id = r.incident_id WHERE 1=1"), []
        if incident_id:
            sql += " AND r.incident_id = ?"
            params.append(incident_id)
        if status:
            sql += " AND r.status = ?"
            params.append(status)
        rows = self.db.query(sql + " ORDER BY r.id DESC LIMIT 500", params)
        for row in rows:
            row["steps"] = ACTION_CATALOG.get(row["action_type"], {}).get("steps", [])
        return rows

    def propose(self, incident_id, action_type, actor, target="", ip=""):
        if action_type not in ACTION_CATALOG:
            raise ValueError("Unknown response action")
        spec = ACTION_CATALOG[action_type]
        with self.db.tx() as conn:
            incident = conn.execute("SELECT id, host FROM incidents WHERE id = ?", (incident_id,)).fetchone()
            if not incident:
                raise LookupError("Incident not found")
            if conn.execute("SELECT 1 FROM response_actions WHERE incident_id=? AND action_type=? AND status IN ('proposed','approved')",
                            (incident_id, action_type)).fetchone():
                raise ValueError("This action is already proposed or approved for the incident")
            cur = conn.execute(
                "INSERT INTO response_actions(incident_id,action_type,integration,title,impact,rollback_plan,target,status,"
                "proposed_by,proposed_at) VALUES(?,?,?,?,?,?,?,'proposed',?,?)",
                (incident_id, action_type, "manual", spec["title"], spec["impact"], spec["rollback"],
                 str(target or incident["host"])[:200], actor.get("id"), iso()))
            self.audit.record("response.propose", actor=actor, target_type="response", target_id=cur.lastrowid, ip=ip,
                              detail={"incident_id": incident_id, "action": action_type}, conn=conn)
            self.db.bump_revision(conn)
            return cur.lastrowid

    def transition(self, action_id, verb, actor, note="", acknowledge_impact=False, ip=""):
        if verb not in TRANSITIONS:
            raise ValueError("Unknown transition")
        source, target = TRANSITIONS[verb]
        note = str(note or "").strip()[:2000]
        if verb == "approve" and not acknowledge_impact:
            raise ValueError("Approval requires acknowledging the stated impact")
        if verb in ("complete", "rollback", "reject") and not note:
            raise ValueError("Describe what was done (or why it was rejected) in the note")
        now = iso()
        columns = {"approve": ("decided_by", "decided_at", "decision_note"),
                   "reject": ("decided_by", "decided_at", "decision_note"),
                   "cancel": ("decided_by", "decided_at", "decision_note"),
                   "complete": ("completed_by", "completed_at", "result_note"),
                   "rollback": ("rolled_back_by", "rolled_back_at", "rollback_note")}[verb]
        with self.db.tx() as conn:
            row = conn.execute("SELECT * FROM response_actions WHERE id = ?", (action_id,)).fetchone()
            if not row:
                raise LookupError("Response action not found")
            if row["status"] != source:
                raise ValueError(f"Cannot {verb} an action that is {row['status']}")
            # Interpolated text is fixed column names / '?' placeholders; all values are bound parameters.
            conn.execute(f"UPDATE response_actions SET status=?, {columns[0]}=?, {columns[1]}=?, {columns[2]}=? WHERE id=?",  # nosec B608
                         (target, actor.get("id"), now, note, action_id))
            conn.execute("INSERT INTO incident_notes(incident_id,author_id,author_name,kind,body,created_at) VALUES(?,?,?,?,?,?)",
                         (row["incident_id"], actor.get("id"), actor.get("name", ""), "system",
                          f"Response '{row['title']}' {target.replace('_', ' ')}." + (f" Note: {note}" if note else ""), now))
            self.audit.record(f"response.{verb}", actor=actor, target_type="response", target_id=action_id, ip=ip,
                              detail={"incident_id": row["incident_id"], "action": row["action_type"],
                                      "impact_acknowledged": bool(acknowledge_impact)}, conn=conn)
            self.db.bump_revision(conn)
        return self.list(incident_id=row["incident_id"])
