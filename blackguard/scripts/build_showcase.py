"""Build the static, zero-install BLACKGUARD demo in ../showcase/demo/.

The demo runs the real dashboard (web/app.js, web/style.css) against a snapshot of real
API responses. The snapshot comes from the real server code processing a *fictional*
household: every event is synthetic and stored as demo data, and the detections are what
BLACKGUARD's actual rules produce from that synthetic data.

Usage:  python3 scripts/build_showcase.py
Privacy: all addresses are RFC 5737 documentation ranges or generic private ranges,
MAC addresses are locally administered (02:…), names are invented, credentials are throwaway.
"""

import hashlib
import http.cookiejar
import json
import os
import random
import re
import shutil
import sys
import tempfile
import threading
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = Path(os.environ.get("BLACKGUARD_SHOWCASE_OUT") or ROOT.parent / "showcase" / "demo")
sys.path.insert(0, str(ROOT))

from guard.config import Settings  # noqa: E402
from guard.db import iso  # noqa: E402
from guard.platform import App  # noqa: E402
from guard.server import Server  # noqa: E402

random.seed(7)  # reproducible fictional data
NOW = datetime.now(timezone.utc).replace(microsecond=0)
DEMO_PASSWORD = "showcase-demo-only-passphrase"  # throwaway; the snapshot database is deleted after the build


def at(minutes_ago):
    return (NOW - timedelta(minutes=minutes_ago)).isoformat()


def e(kind, host, message, minutes_ago, ip="", actor="unknown", **extra):
    item = {"type": kind, "host": host, "message": message, "timestamp": at(minutes_ago), "source_ip": ip, "actor": actor}
    item.update(extra)
    return item


def household_events():
    """A fictional household over 24 hours: routine activity plus three attack stories."""
    ev = []
    # Routine: Windows sign-ins, NAS key logins, backups, DHCP renewals, internet background noise.
    for hour in range(23, 0, -1):
        m = hour * 60 + random.randint(0, 40)
        ev.append(e("auth_success", "STUDY-PC", "Windows 4624: sign-in by alex (logon type 2)", m, actor="alex",
                    details={"windows_event_id": 4624, "logon_type": "2"}))
        ev.append(e("auth_success", "media-nas", "SSH publickey sign-in accepted for backup from 192.168.50.30", m - 5,
                    ip="192.168.50.30", actor="backup", details={"service": "ssh", "method": "publickey"}))
        ev.append(e("network_block", "Gateway router", "Firewall denied TCP 192.0.2.%d → 203.0.113.10:23" % random.randint(2, 250),
                    m - 7, ip="192.0.2.%d" % random.randint(2, 250), dest_ip="203.0.113.10", dest_port=23))
        if hour % 6 == 0:
            ev.append(e("service_error", "media-nas", "Scheduled photo backup finished with 2 skipped files", m - 12, actor="backup"))
    ev.append(e("auth_failure", "STUDY-PC", "Windows 4625: failed sign-in for alex", 610, actor="alex"))
    ev.append(e("privilege_use", "media-nas", "sudo: sam ran a command as root", 540, actor="sam", target="root",
                details={"service": "sudo", "command": "/usr/bin/apt upgrade"}))
    for n, (mac, name) in enumerate([("02:42:ac:11:00:05", "living-room-tv"), ("02:42:ac:11:00:09", "kids-tablet"),
                                     ("02:42:ac:11:00:0c", "sam-phone")]):
        ev.append(e("dhcp_lease", "Gateway router", f"DHCP lease 192.168.50.{40 + n} → {mac} ({name})", 300 - n * 50,
                    details={"ip": f"192.168.50.{40 + n}", "mac": mac, "hostname": name}))

    # Story 1: internet SSH brute force + password spray against the NAS.
    for i in range(34):
        user = ["root", "admin", "ubuntu", "pi", "test"][i % 5]
        ev.append(e("auth_failure", "media-nas", f"SSH password authentication failed for {user} from 203.0.113.77", 185 - i * 0.2,
                    ip="203.0.113.77", actor=user, details={"service": "ssh", "method": "password"}))
    for i, user in enumerate(["alex", "sam", "jordan", "guest", "support", "backup"]):
        ev.append(e("auth_failure", "media-nas", f"SSH password authentication failed for {user} from 198.51.100.23", 150 - i,
                    ip="198.51.100.23", actor=user, details={"service": "ssh", "invalid_user": user in ("guest", "support")}))
        ev.append(e("auth_failure", "Gateway router", f"Router web login failed for {user} from 198.51.100.23", 149.5 - i,
                    ip="198.51.100.23", actor=user, details={"service": "httpd", "match": "generic"}))

    # Story 2: an unknown device on the LAN guesses a local admin password, succeeds, creates a backdoor.
    for i in range(5):
        ev.append(e("auth_failure", "STUDY-PC", "Windows 4625: failed sign-in for admin", 95 - i, ip="192.168.50.66", actor="admin",
                    details={"windows_event_id": 4625, "logon_type": "3"}))
    ev.append(e("auth_success", "STUDY-PC", "Windows 4624: sign-in by admin (logon type 3)", 89, ip="192.168.50.66", actor="admin",
                details={"windows_event_id": 4624, "logon_type": "3"}))
    ev.append(e("account_created", "STUDY-PC", "Windows 4720: account svc-update created by admin", 86, actor="admin",
                target="svc-update", details={"windows_event_id": 4720}))
    ev.append(e("group_membership_change", "STUDY-PC", "Windows 4732: svc-update added to group Administrators by admin", 85,
                actor="admin", target="svc-update", details={"windows_event_id": 4732, "group": "Administrators"}))
    ev.append(e("policy_change", "STUDY-PC", "Windows 4719: system audit policy changed by admin", 83, actor="admin",
                details={"windows_event_id": 4719}))

    # Story 3: a port scan from the internet against the router's WAN address.
    for i, port in enumerate([21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 1433, 3306, 3389, 5900, 8080, 8443]):
        ev.append(e("network_block", "Gateway router", f"Firewall denied TCP 198.51.100.200 → 203.0.113.10:{port}", 45 - i * 0.05,
                    ip="198.51.100.200", dest_ip="203.0.113.10", dest_port=port, details={"service": "netfilter"}))
    return ev


AGENTS = [
    {"id": "agt_d3m0a1b2c3d4e5f6", "name": "Study PC", "hostname": "STUDY-PC", "platform": "Windows 11 Pro", "sources": ["windows_security"],
     "version": "0.5.0", "spool": 0, "delivered": 18342, "boot": 4100},
    {"id": "agt_d3m0b2c3d4e5f6a7", "name": "Media NAS", "hostname": "media-nas", "platform": "Linux 6.6 (Debian 12)",
     "sources": ["linux_auth", "syslog"], "version": "0.5.0", "spool": 0, "delivered": 52118, "boot": 20500},
    {"id": "agt_d3m0c3d4e5f6a7b8", "name": "Garage Raspberry Pi", "hostname": "garage-pi", "platform": "Linux 6.6 (Raspberry Pi OS)",
     "sources": ["journald"], "version": "0.5.0", "spool": 1260, "delivered": 9021, "boot": 2900},
]


def seed(app):
    actor = {"id": 1, "name": "demo-admin", "type": "user"}
    with app.db.tx() as conn:
        for n, a in enumerate(AGENTS):
            fp = hashlib.sha256(f"blackguard-demo-agent-{n}".encode()).hexdigest()  # synthetic, deterministic
            contact = at(0.5) if n < 2 else at(26)
            health = {"spool_depth": a["spool"], "spool_limit": 100000, "dropped_total": 0, "rejected_total": 0,
                      "agent_version": a["version"], "delivered_total": a["delivered"], "boot_time": at(a["boot"]),
                      "agent_started_at": at(a["boot"] - 1), "last_error": None if n < 2 else "Cannot reach server: timed out",
                      "server_unreachable_since": None if n < 2 else at(27),
                      "sources": [{"name": s, "kind": s, "events_total": a["delivered"] // len(a["sources"]),
                                   "last_event_at": contact, "last_error": None} for s in a["sources"]]}
            conn.execute("INSERT INTO agents(id,name,status,hostname,platform,fingerprint,reported_fingerprint,agent_version,sources,"
                         "credential_hash,credential_issued_at,enrolled_at,approved_at,approved_by,last_contact_at,last_ip,health) "
                         "VALUES(?,?,'active',?,?,?,?,?,?,?,?,?,?,1,?,?,?)",
                         (a["id"], a["name"], a["hostname"], a["platform"], fp, fp, a["version"], json.dumps(a["sources"]),
                          f"demo-not-a-credential-{n}", at(60 * 24 * 12), at(60 * 24 * 30), at(60 * 24 * 30), contact,
                          f"192.168.50.{10 + n}", json.dumps(health)))
            app.inventory.link_agent(conn, {"id": a["id"], "name": a["name"], "hostname": a["hostname"], "platform": a["platform"],
                                            "site_id": 1})
        # A pending enrollment, to show the approval workflow.
        conn.execute("INSERT INTO agents(id,name,status,hostname,platform,reported_fingerprint,agent_version,sources,enrolled_at,"
                     "last_contact_at,last_ip) VALUES('agt_d3m0d4e5f6a7b8c9','Living-room laptop','pending','family-laptop',"
                     "'Linux 6.8 (Ubuntu 24.04)',?,'0.5.0','[\"linux_auth\"]',?,?,'192.168.50.14')",
                     (hashlib.sha256(b"blackguard-demo-agent-pending").hexdigest(), at(8), at(8)))
    app.ingest(household_events(), mode="demo", trust="demo", source="demo")
    nas = {"id": AGENTS[1]["id"], "name": "Media NAS", "hostname": "media-nas", "site_id": 1}
    app.inventory.report(nas, [{"source": "dhcp", "ip": "192.168.50.66", "mac": "02:42:ac:11:00:42", "hostname": ""}])
    # Server-generated health evidence (also synthetic): the Raspberry Pi agent went silent; a new device appeared.
    pi = app.db.one("SELECT * FROM agents WHERE id = ?", (AGENTS[2]["id"],))
    notices = [app.agents.notice("agent_offline", pi, f"Agent 'Garage Raspberry Pi' has not reported since {pi['last_contact_at']} "
                                 "(26 minutes; threshold 3 minutes). It did not report a clean stop."),
               {"type": "collector_notice", "host": "media-nas", "actor": "blackguard", "timestamp": at(92),
                "message": "New device on the network: 192.168.50.66 (MAC 02:42:ac:11:00:42), reported via dhcp by Media NAS.",
                "uid": "notice:new_device:demo", "details": {"kind": "new_device", "agent_id": AGENTS[1]["id"]}}]
    app.ingest(notices, mode="demo", trust="server", source="blackguard", atomic=False)
    with app.db.tx() as conn:
        conn.execute("UPDATE inventory SET mode='demo'")
        conn.execute("UPDATE agents SET offline_alerted=1 WHERE id=?", (AGENTS[2]["id"],))

    # Investigation workflow on the synthetic incidents.
    incidents = {i["rule_id"]: i for i in app.incidents.list(limit=100)}
    crit = incidents.get("BG-AUTH-02")
    if crit:
        app.incidents.set_status(crit["id"], "investigating", actor)
        app.incidents.add_note(crit["id"], actor, "192.168.50.66 is not a known household device (no agent, first DHCP lease 92 min ago). "
                                                  "Treating the admin sign-in as unauthorised until proven otherwise.")
        rid = app.responses.propose(crit["id"], "isolate_device", actor, "192.168.50.66")
        app.responses.transition(rid, "approve", actor, "Impact accepted: the unknown device loses network access.", True)
        app.responses.propose(crit["id"], "reset_credentials", actor)
    scan = incidents.get("BG-NET-02")
    if scan:
        app.incidents.set_status(scan["id"], "resolved", actor, "Internet background scanning; no ports are forwarded on the router.")
    app.audit.record("auth.login", actor=actor, ip="192.168.50.10")


def capture(base, opener, csrf):
    def get(path):
        req = urllib.request.Request(base + path, headers={"X-CSRF-Token": csrf})
        with opener.open(req) as resp:
            body = resp.read()
            return json.loads(body) if "json" in resp.headers.get("Content-Type", "") else body.decode()

    snap = {"generated_at": iso(NOW), "routes": {}}
    r = snap["routes"]
    for path in ("/api/v1/setup/status", "/api/v1/auth/me", "/api/v1/overview", "/api/v1/rules", "/api/v1/agents",
                 "/api/v1/devices", "/api/v1/responses", "/api/v1/audit?limit=200", "/api/v1/system/health", "/api/v1/users",
                 "/api/v1/revision"):
        r[path.split("?")[0]] = get(path)
    r["/api/v1/incidents"] = get("/api/v1/incidents?status=")
    r["events"] = get("/api/v1/events?limit=500")["events"]
    r["incident_detail"] = {str(i["id"]): get(f"/api/v1/incidents/{i['id']}") for i in r["/api/v1/incidents"]["incidents"]}
    r["device_detail"] = {str(d["id"]): get(f"/api/v1/devices/{d['id']}") for d in r["/api/v1/devices"]["devices"]}
    r["report"] = get("/api/v1/report")
    r["incident_report"] = {i: get(f"/api/v1/incidents/{i}/report") for i in r["incident_detail"]}
    return snap


def scrub(snap):
    """Belt and braces: fail the build if anything outside the synthetic ranges slipped in."""
    text = json.dumps(snap)
    for ip in set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)):
        if not ip.startswith(("192.0.2.", "198.51.100.", "203.0.113.", "192.168.50.", "127.0.0.1")):
            raise SystemExit(f"Unexpected IP address in demo snapshot: {ip}")
    for secret in ("bga_", "bgs_", DEMO_PASSWORD):
        if secret in text:
            raise SystemExit(f"Secret-like value in demo snapshot: {secret}")
    return snap


def main():
    work = Path(tempfile.mkdtemp())
    try:
        app = App(Settings(data_dir=work, db_path=work / "demo.sqlite3", seed_demo=False, port=0))
        code = app.auth.ensure_setup_code()
        app.auth.complete_setup(code, "demo-admin", DEMO_PASSWORD, "Demo Administrator")
        seed(app)
        app.backup(label="auto")
        server = Server(app)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{server.server_address[1]}"
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        req = urllib.request.Request(base + "/api/v1/auth/login", data=json.dumps({"username": "demo-admin", "password": DEMO_PASSWORD}).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        with opener.open(req) as resp:
            csrf = json.load(resp)["csrf"]
        snap = scrub(capture(base, opener, csrf))
        server.shutdown()
        server.server_close()
        app.db.close()
    finally:
        shutil.rmtree(work, ignore_errors=True)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "demo-data.js").write_text("/* Generated by scripts/build_showcase.py: synthetic data processed by the real BLACKGUARD engine. */\n"
                                      "window.BLACKGUARD_DEMO = " + json.dumps(snap, separators=(",", ":")) + ";\n", encoding="utf-8")
    web = ROOT / "web"
    for name in ("app.js", "style.css", "shield.svg"):
        shutil.copy2(web / name, OUT / name)
    html = (web / "index.html").read_text(encoding="utf-8")
    html = html.replace('href="/style.css"', 'href="style.css"').replace('src="/shield.svg"', 'src="shield.svg"') \
               .replace('href="/shield.svg"', 'href="shield.svg"')
    html = html.replace('<script src="/app.js" defer></script>',
                        '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'; script-src \'self\'; style-src \'self\'; '
                        'img-src \'self\' data:; connect-src \'none\'; object-src \'none\'; base-uri \'none\'; form-action \'none\'">\n'
                        '  <link rel="stylesheet" href="demo.css">\n'
                        '  <script src="demo-data.js" defer></script>\n  <script src="demo-api.js" defer></script>\n'
                        '  <script src="app.js" defer></script>')
    html = html.replace('<a class="skip-link" href="#main">Skip to main content</a>',
                        '<a class="skip-link" href="#main">Skip to main content</a>\n<div class="demo-ribbon" role="note">'
                        '<strong>INTERACTIVE DEMO</strong> · Synthetic data processed by the real BLACKGUARD detection engine · '
                        'No backend: changes are not saved · <a href="../index.html">About BLACKGUARD</a></div>')
    html = html.replace("<title>BLACKGUARD — Security Operations Centre</title>", "<title>BLACKGUARD — Interactive Demo</title>")
    (OUT / "index.html").write_text(html, encoding="utf-8")
    print(f"Demo built in {OUT} ({len(snap['routes']['events'])} synthetic events, "
          f"{len(snap['routes']['/api/v1/incidents']['incidents'])} incidents)")


if __name__ == "__main__":
    main()
