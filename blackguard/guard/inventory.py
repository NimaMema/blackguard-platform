"""Device inventory with explicit provenance for every attribute.

Confidence vocabulary (shown in the dashboard):
* ``confirmed`` – reported by an approved agent running on the device, or entered by an administrator.
* ``reported``  – stated by another device's logs (router DHCP lease, ARP cache of a collector).
* ``inferred``  – BLACKGUARD's guess (e.g. a hostname seen in log lines). Never presented as fact.
"""

import ipaddress
import re
from datetime import timedelta

from guard.db import iso, parse_iso, utcnow

MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
HOST_RE = re.compile(r"^[A-Za-z0-9._ -]{1,120}$")
LEARNING_PERIOD = timedelta(hours=24)


def normalize_mac(value):
    mac = str(value or "").strip().lower().replace("-", ":")
    if not mac:
        return ""
    if not MAC_RE.match(mac):
        raise ValueError("Invalid MAC address")
    if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        raise ValueError("Placeholder MAC address")
    return mac


class Inventory:
    def __init__(self, db, audit):
        self.db = db
        self.audit = audit

    def _observe(self, conn, device_id, field, value, source, confidence, reporter, now):
        last = conn.execute("SELECT value, observed_at FROM inventory_observations WHERE device_id=? AND field=? "
                            "ORDER BY id DESC LIMIT 1", (device_id, field)).fetchone()
        # Bound growth: record a field again only when it changes or hourly.
        if last and last["value"] == value and parse_iso(now) - parse_iso(last["observed_at"]) < timedelta(hours=1):
            return
        conn.execute("INSERT INTO inventory_observations(device_id,observed_at,source,field,value,confidence,reporter) "
                     "VALUES(?,?,?,?,?,?,?)", (device_id, now, source, field, value, confidence, reporter))

    def link_agent(self, conn, agent):
        now = iso()
        row = conn.execute("SELECT id FROM inventory WHERE agent_id = ?", (agent["id"],)).fetchone()
        if not row and agent.get("hostname"):
            row = conn.execute("SELECT id FROM inventory WHERE agent_id IS NULL AND hostname = ? COLLATE NOCASE",
                               (agent["hostname"],)).fetchone()
        if row:
            device_id = row["id"]
            conn.execute("UPDATE inventory SET agent_id=?, hostname=?, os=?, os_confidence='confirmed', "
                         "identity_confidence='verified_agent', approved=1, last_seen=? WHERE id=?",
                         (agent["id"], agent["hostname"], agent["platform"], now, device_id))
        else:
            device_id = conn.execute(
                "INSERT INTO inventory(site_id,display_name,hostname,os,os_confidence,identity_confidence,origin,agent_id,approved,"
                "first_seen,last_seen) VALUES(?,?,?,?,'confirmed','verified_agent','agent',?,1,?,?)",
                (agent.get("site_id", 1), agent["name"], agent["hostname"], agent["platform"], agent["id"], now, now)).lastrowid
        conn.execute("UPDATE agents SET device_id=? WHERE id=?", (device_id, agent["id"]))
        self._observe(conn, device_id, "os", agent["platform"], "agent", "confirmed", agent["id"], now)
        self._observe(conn, device_id, "hostname", agent["hostname"], "agent", "confirmed", agent["id"], now)
        return device_id

    def touch_agent(self, conn, agent_id, now):
        conn.execute("UPDATE inventory SET last_seen=? WHERE agent_id=?", (now, agent_id))

    def report(self, agent, observations):
        """Store neighbour/lease observations from an approved agent. Returns server notices for new devices."""
        if not isinstance(observations, list) or len(observations) > 1000:
            raise ValueError("observations must be a list of at most 1000 items")
        now = iso()
        notices, created = [], 0
        with self.db.tx() as conn:
            learning_key = f"inventory_learning:{agent['id']}"
            started = conn.execute("SELECT value FROM settings WHERE key=?", (learning_key,)).fetchone()
            if not started:
                conn.execute("INSERT INTO settings(key,value) VALUES(?,?)", (learning_key, f'"{now}"'))
                learning = True
            else:
                learning = utcnow() - parse_iso(started["value"].strip('"')) < LEARNING_PERIOD
            for item in observations:
                if not isinstance(item, dict):
                    raise ValueError("Each observation must be an object")
                source = str(item.get("source", ""))
                if source not in ("arp", "dhcp", "neighbor"):
                    raise ValueError("Observation source must be arp, dhcp or neighbor")
                ip = str(item.get("ip", "")).strip()
                try:
                    ip = str(ipaddress.ip_address(ip)) if ip else ""
                except ValueError as exc:
                    raise ValueError("Invalid observation IP") from exc
                mac = normalize_mac(item.get("mac"))
                hostname = " ".join(str(item.get("hostname", "") or "").split())[:120]
                if hostname and not HOST_RE.match(hostname):
                    hostname = ""
                if not mac and not ip:
                    continue
                row = None
                if mac:
                    row = conn.execute("SELECT * FROM inventory WHERE mac_address=?", (mac,)).fetchone()
                if not row and ip and not mac:
                    row = conn.execute("SELECT * FROM inventory WHERE ip_address=? AND mac_address=''", (ip,)).fetchone()
                if row:
                    device_id = row["id"]
                    conn.execute("UPDATE inventory SET ip_address=COALESCE(NULLIF(?,''),ip_address), "
                                 "hostname=CASE WHEN hostname='' THEN ? ELSE hostname END, last_seen=? WHERE id=?",
                                 (ip, hostname, now, device_id))
                else:
                    label = hostname or ip or mac
                    device_id = conn.execute(
                        "INSERT INTO inventory(site_id,display_name,hostname,ip_address,mac_address,identity_confidence,origin,"
                        "approved,first_seen,last_seen,notes) VALUES(?,?,?,?,?,'reported',?,0,?,?,?)",
                        (agent.get("site_id", 1), label, hostname, ip, mac, source, now, now,
                         f"First reported by agent {agent['name']} ({source}). Not yet reviewed.")).lastrowid
                    created += 1
                    if not learning:
                        notices.append({
                            "type": "collector_notice", "host": agent["hostname"] or agent["name"], "actor": "blackguard",
                            "message": f"New device on the network: {label} (IP {ip or 'unknown'}, MAC {mac or 'unknown'}), "
                                       f"reported via {source} by {agent['name']}.",
                            "timestamp": now, "uid": f"notice:new_device:{device_id}",
                            "details": {"kind": "new_device", "agent_id": agent["id"], "device_id": device_id}})
                for field, value in (("ip", ip), ("mac", mac), ("hostname", hostname)):
                    if value:
                        self._observe(conn, device_id, field, value, source, "reported", agent["id"], now)
            self.db.bump_revision(conn)
        return {"created": created, "learning": learning}, notices

    def list(self):
        rows = self.db.query(
            "SELECT i.*, a.status AS agent_status, a.last_contact_at, a.offline_after_seconds FROM inventory i "
            "LEFT JOIN agents a ON a.id = i.agent_id ORDER BY i.approved, i.last_seen DESC")
        now = utcnow()
        for r in rows:
            if r["agent_id"] and r["agent_status"] == "active" and r["last_contact_at"]:
                age = (now - parse_iso(r["last_contact_at"])).total_seconds()
                r["health"] = "online" if age <= r["offline_after_seconds"] else "offline"
            elif r["agent_id"]:
                r["health"] = r["agent_status"]
            else:
                r["health"] = "unmonitored"
        return rows

    def detail(self, device_id):
        device = self.db.one("SELECT * FROM inventory WHERE id = ?", (device_id,))
        if not device:
            return None
        device["observations"] = self.db.query(
            "SELECT * FROM inventory_observations WHERE device_id=? ORDER BY id DESC LIMIT 200", (device_id,))
        names = [n for n in (device["hostname"], device["display_name"]) if n]
        if names:
            marks = ",".join("?" * len(names))
            device["activity"] = self.db.query(
                # Interpolated text is fixed column names / '?' placeholders; all values are bound parameters.
                f"SELECT substr(timestamp,1,10) AS day, type, COUNT(*) AS n FROM events WHERE host IN ({marks}) "  # nosec B608
                f"AND timestamp >= ? GROUP BY day, type ORDER BY day DESC", (*names, iso(utcnow() - timedelta(days=30))))
            device["recent_events"] = self.db.query(
                # Interpolated text is fixed column names / '?' placeholders; all values are bound parameters.
                f"SELECT id,timestamp,type,message,mode,source_ip FROM events WHERE host IN ({marks}) ORDER BY timestamp DESC LIMIT 25", names)  # nosec B608
        else:
            device["activity"], device["recent_events"] = [], []
        return device

    def update(self, device_id, actor, display_name=None, notes=None, approved=None, ip=""):
        changes = {}
        if display_name is not None:
            name = " ".join(str(display_name).split())[:80]
            if not name:
                raise ValueError("Name is required")
            changes["display_name"] = name
        if notes is not None:
            changes["notes"] = str(notes)[:2000]
        if approved is not None:
            changes["approved"] = 1 if approved else 0
        if not changes:
            return self.detail(device_id)
        with self.db.tx() as conn:
            # Interpolated text is fixed column names / '?' placeholders; all values are bound parameters.
            if not conn.execute(f"UPDATE inventory SET {', '.join(f'{k}=?' for k in changes)} WHERE id=?",  # nosec B608
                                (*changes.values(), device_id)).rowcount:
                raise LookupError("Device not found")
            self.audit.record("device.update", actor=actor, target_type="device", target_id=device_id, ip=ip, detail=changes, conn=conn)
            self.db.bump_revision(conn)
        return self.detail(device_id)

    def add_manual(self, actor, display_name, hostname="", ip_address="", mac_address="", os_name="", notes="", ip=""):
        name = " ".join(str(display_name or "").split())[:80]
        if not name:
            raise ValueError("Name is required")
        address = str(ip_address or "").strip()
        if address:
            try:
                address = str(ipaddress.ip_address(address))
            except ValueError as exc:
                raise ValueError("Invalid IP address") from exc
        hostname = " ".join(str(hostname or "").split())[:120]
        if hostname and not HOST_RE.match(hostname):
            raise ValueError("Invalid hostname")
        mac = normalize_mac(mac_address)
        now = iso()
        with self.db.tx() as conn:
            device_id = conn.execute(
                "INSERT INTO inventory(display_name,hostname,ip_address,mac_address,os,os_confidence,identity_confidence,origin,"
                "approved,notes,first_seen,last_seen) VALUES(?,?,?,?,?,?,'confirmed','manual',1,?,?,?)",
                (name, hostname, address, mac, str(os_name or "")[:80], "confirmed" if os_name else "unknown",
                 str(notes or "")[:2000], now, now)).lastrowid
            self.audit.record("device.create", actor=actor, target_type="device", target_id=device_id, ip=ip,
                              detail={"name": name}, conn=conn)
            self.db.bump_revision(conn)
        return self.detail(device_id)

    def observe_dhcp(self, events, agent):
        """Feed DHCP lease events (from router syslog) into inventory as 'reported' observations."""
        observations = []
        for e in events:
            if e["type"] == "dhcp_lease":
                details = e.get("details") or {}
                observations.append({"source": "dhcp", "ip": details.get("ip") or e.get("dest_ip") or "",
                                     "mac": details.get("mac", ""), "hostname": details.get("hostname", "")})
        valid = []
        for item in observations:
            try:
                normalize_mac(item["mac"])
                valid.append(item)
            except ValueError:
                continue
        return self.report(agent, valid) if valid else ({"created": 0}, [])
