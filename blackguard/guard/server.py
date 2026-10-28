"""HTTP API and static dashboard server (Python standard library only).

Security properties:
* Dashboard users authenticate with individual accounts; sessions are
  HttpOnly, SameSite=Strict cookies (``Secure`` with TLS) stored hashed server-side.
* State-changing requests need a per-session CSRF token header and a
  same-origin ``Origin`` when the browser sends one.
* Agents authenticate with their own bearer credential; identity is derived
  from the credential, never from the request body.
* Every route declares the permission it needs; unknown routes return 404.
* Request bodies, concurrency and per-client request rates are bounded.
"""

import hmac
import json
import logging
import re
import socket
import ssl
import threading
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from guard import __version__
from guard.agents import AgentError
from guard.ai import AIUnavailable
from guard.auth import AuthError, actor_of, public_user
from guard.config import ROOT
from guard.db import iso
from guard.reports import render_json, render_markdown
from guard.response import ACTION_CATALOG, guidance
from guard.security import RateLimiter

log = logging.getLogger("blackguard.http")
WEB = ROOT / "web"
STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/shield.svg": ("shield.svg", "image/svg+xml"),
}
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
SMALL_BODY = 256 * 1024
AGENT_BODY = 2 * 1024 * 1024


class HttpError(Exception):
    def __init__(self, status, message, headers=None):
        super().__init__(message)
        self.status = status
        self.headers = headers or {}


ROUTES = []


def route(method, pattern, auth="session", perm="view", body=SMALL_BODY):
    """auth: 'none' | 'session' | 'agent' | 'legacy'. perm: permission name for session routes."""
    def register(func):
        ROUTES.append((method, re.compile(f"^{pattern}$"), func, auth, perm, body))
        return func
    return register


def _int(value, name="id"):
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise HttpError(400, f"Invalid {name}") from exc


def _obj(data):
    if not isinstance(data, dict):
        raise HttpError(400, "Expected a JSON object")
    return data


# --------------------------------------------------------------------------- liveness
@route("GET", "/healthz", auth="none")
def healthz(h, m):
    """Unauthenticated liveness/readiness probe for Docker, systemd or Windows monitoring. Reveals no data."""
    try:
        h.app.db.scalar("SELECT 1")
    except Exception:  # database unavailable
        raise HttpError(503, "database unavailable")
    return {"status": "ok"}


# --------------------------------------------------------------------------- auth / session
@route("GET", "/api/v1/setup/status", auth="none")
def setup_status(h, m):
    return {"needs_setup": h.app.auth.user_count() == 0, "version": __version__}


@route("POST", "/api/v1/setup", auth="none")
def setup(h, m):
    if not h.server.login_limiter.allow(f"setup:{h.ip}"):
        raise HttpError(429, "Too many attempts; wait a minute.")
    d = _obj(h.body())
    h.app.auth.complete_setup(d.get("setup_code"), d.get("username"), d.get("password"), d.get("display_name", ""), ip=h.ip)
    return h.start_session(d.get("username"), d.get("password"), status=201)


@route("POST", "/api/v1/auth/login", auth="none")
def login(h, m):
    if not h.server.login_limiter.allow(f"login:{h.ip}"):
        raise HttpError(429, "Too many sign-in attempts from this address; wait a minute.", {"Retry-After": "60"})
    d = _obj(h.body())
    return h.start_session(d.get("username"), d.get("password"))


@route("POST", "/api/v1/auth/logout")
def logout(h, m):
    h.app.auth.logout(h.user, ip=h.ip)
    h.extra_headers.append(("Set-Cookie", h.cookie_header("", expire=True)))
    return {"ok": True}


@route("GET", "/api/v1/auth/me")
def me(h, m):
    row = h.app.db.one("SELECT * FROM users WHERE id = ?", (h.user["id"],))
    return {"user": public_user(row), "csrf": h.user["csrf"]}


@route("POST", "/api/v1/auth/password")
def change_password(h, m):
    d = _obj(h.body())
    h.app.auth.change_own_password(h.user, str(d.get("current_password", "")), d.get("new_password"), ip=h.ip)
    h.extra_headers.append(("Set-Cookie", h.cookie_header("", expire=True)))
    return {"ok": True, "message": "Password changed. Sign in again."}


# --------------------------------------------------------------------------- users
@route("GET", "/api/v1/users", perm="manage_users")
def users(h, m):
    return {"users": h.app.auth.list_users()}


@route("POST", "/api/v1/users", perm="manage_users")
def create_user(h, m):
    d = _obj(h.body())
    user_id = h.app.auth.create_user(d.get("username"), d.get("password"), d.get("role"), d.get("display_name", ""),
                                     actor=h.actor, ip=h.ip)
    return {"id": user_id, "users": h.app.auth.list_users()}, 201


@route("POST", r"/api/v1/users/(\d+)", perm="manage_users")
def update_user(h, m):
    d = _obj(h.body())
    user = h.app.auth.update_user(_int(m[1]), h.actor, role=d.get("role"), disabled=d.get("disabled"),
                                  display_name=d.get("display_name"), password=d.get("password"), ip=h.ip)
    return {"user": user, "users": h.app.auth.list_users()}


# --------------------------------------------------------------------------- dashboard
@route("GET", "/api/v1/revision")
def revision(h, m):
    return {"revision": h.app.revision()}


@route("GET", "/api/v1/overview")
def overview(h, m):
    return h.app.overview()


@route("GET", "/api/v1/events")
def events(h, m):
    q = h.query
    try:
        return h.app.events.search(q=q("q"), type_=q("type"), host=q("host"), source_ip=q("source_ip"), mode=q("mode"),
                                   agent_id=q("agent_id"), since=q("since"), until=q("until"),
                                   limit=_int(q("limit") or 100, "limit"), cursor=q("cursor"))
    except ValueError as exc:
        raise HttpError(400, str(exc)) from exc


@route("GET", r"/api/v1/events/(\d+)")
def event_detail(h, m):
    rows = h.app.events.get_many([_int(m[1])])
    if not rows:
        raise HttpError(404, "Event not found")
    linked = h.app.db.query("SELECT i.id, i.title, i.severity, i.status FROM incident_events ie JOIN incidents i ON i.id = ie.incident_id "
                            "WHERE ie.event_id = ?", (rows[0]["id"],))
    return {"event": rows[0], "incidents": linked}


@route("POST", "/api/v1/events/import", perm="import")
def import_events(h, m):
    d = _obj(h.body())
    result = h.app.ingest(d.get("events"), mode="imported", trust="manual_import", source="import", atomic=True)
    h.app.audit.record("events.import", actor=h.actor, ip=h.ip,
                       detail={"accepted": len(result["accepted"]), "duplicates": result["duplicates"]})
    return {"ingested": len(result["accepted"]), "duplicates": result["duplicates"],
            "incidents_created": len(result["incidents_created"])}, 201


@route("POST", "/api/v1/detect", perm="detect")
def detect(h, m):
    result = h.app.detector.run()
    h.app.audit.record("detection.sweep", actor=h.actor, ip=h.ip, detail={k: len(v) for k, v in result.items()})
    return {"created": len(result["created"]), "updated": len(result["updated"])}


@route("POST", "/api/v1/demo/inject", perm="detect")
def demo_inject(h, m):
    result = h.app.inject_demo(h.actor, h.ip)
    return {"ingested": len(result["accepted"]), "incidents_created": len(result["incidents_created"])}, 201


@route("POST", "/api/v1/demo/purge", perm="manage_system")
def demo_purge(h, m):
    d = _obj(h.body())
    if d.get("confirm") != "DELETE DEMO DATA":
        raise HttpError(400, "Type DELETE DEMO DATA to confirm. Only fictional demo records are removed.")
    return {"removed": h.app.purge_demo(h.actor, h.ip)}


# --------------------------------------------------------------------------- incidents
@route("GET", "/api/v1/incidents")
def incidents(h, m):
    q = h.query
    try:
        return {"incidents": h.app.incidents.list(status=q("status"), severity=q("severity"), q=q("q"), mode=q("mode"))}
    except ValueError as exc:
        raise HttpError(400, str(exc)) from exc


@route("GET", r"/api/v1/incidents/(\d+)")
def incident_detail(h, m):
    incident_id = _int(m[1])
    detail = h.app.incidents.detail(incident_id, h.app.responses.list(incident_id=incident_id))
    if not detail:
        raise HttpError(404, "Incident not found")
    detail["guidance"] = guidance(detail["rule_id"])
    return detail


@route("POST", r"/api/v1/incidents/(\d+)/status", perm="investigate")
def incident_status(h, m):
    d = _obj(h.body())
    try:
        changed = h.app.incidents.set_status(_int(m[1]), d.get("status"), h.actor, d.get("note", ""), ip=h.ip)
    except ValueError as exc:
        raise HttpError(400, str(exc)) from exc
    if not changed:
        raise HttpError(404, "Incident not found")
    return {"updated": True}


@route("POST", r"/api/v1/incidents/(\d+)/notes", perm="investigate")
def incident_note(h, m):
    d = _obj(h.body())
    return {"id": h.app.incidents.add_note(_int(m[1]), h.actor, d.get("body"), ip=h.ip)}, 201


@route("POST", r"/api/v1/incidents/(\d+)/ai-summary", perm="ai")
def incident_ai(h, m):
    incident_id = _int(m[1])
    detail = h.app.incidents.detail(incident_id, [])
    if not detail:
        raise HttpError(404, "Incident not found")
    if not h.server.ai_limiter.allow(f"ai:{h.user['id']}"):
        raise HttpError(429, "AI analyst rate limit reached; wait a minute.")
    try:
        analysis = h.app.analyst.analyse(detail)
    except AIUnavailable as exc:
        raise HttpError(503, str(exc)) from exc
    note_id = h.app.incidents.add_note(incident_id, {"id": None, "name": f"AI ({analysis['model']})"},
                                       h.app.analyst.as_note(analysis), kind="ai", meta=analysis, ip=h.ip)
    h.app.audit.record("ai.analyse", actor=h.actor, target_type="incident", target_id=incident_id, ip=h.ip,
                       detail={"model": analysis["model"], "note_id": note_id})
    return {"analysis": analysis, "note_id": note_id}


@route("GET", r"/api/v1/incidents/(\d+)/report", perm="export")
def incident_report(h, m):
    incident_id = _int(m[1])
    if not h.app.incidents.get(incident_id):
        raise HttpError(404, "Incident not found")
    h.app.audit.record("report.export", actor=h.actor, target_type="incident", target_id=incident_id, ip=h.ip,
                       detail={"format": h.query("format") or "md"})
    if h.query("format") == "json":
        return h.download(render_json(h.app, incident_id), "application/json", f"BLACKGUARD-incident-{incident_id}.json")
    text = render_markdown(h.app, [incident_id], h.query("pseudonymize") == "1")
    return h.download(text, "text/markdown; charset=utf-8", f"BLACKGUARD-incident-{incident_id}.md")


@route("GET", "/api/v1/report", perm="export")
def full_report(h, m):
    h.app.audit.record("report.export", actor=h.actor, target_type="all", ip=h.ip)
    return h.download(render_markdown(h.app, None, h.query("pseudonymize") == "1"), "text/markdown; charset=utf-8",
                      "BLACKGUARD-investigation.md")


# --------------------------------------------------------------------------- responses
@route("GET", "/api/v1/responses")
def responses(h, m):
    return {"responses": h.app.responses.list(status=h.query("status")), "catalog": ACTION_CATALOG}


@route("POST", r"/api/v1/incidents/(\d+)/responses", perm="propose_response")
def propose_response(h, m):
    d = _obj(h.body())
    action_id = h.app.responses.propose(_int(m[1]), d.get("action_type"), h.actor, d.get("target", ""), ip=h.ip)
    return {"id": action_id}, 201


@route("POST", r"/api/v1/responses/(\d+)/(approve|reject|complete|rollback|cancel)", perm="propose_response")
def response_transition(h, m):
    verb = m[2]
    if verb != "cancel" and "approve_response" not in h.user["permissions"]:
        raise HttpError(403, "Only administrators may approve, reject, complete or roll back response actions.")
    d = _obj(h.body())
    return {"responses": h.app.responses.transition(_int(m[1]), verb, h.actor, d.get("note", ""),
                                                     bool(d.get("acknowledge_impact")), ip=h.ip)}


# --------------------------------------------------------------------------- rules
@route("GET", "/api/v1/rules")
def rules(h, m):
    return {"rules": h.app.detector.describe_rules()}


@route("POST", r"/api/v1/rules/([A-Z0-9-]+)", perm="manage_rules")
def update_rule(h, m):
    d = _obj(h.body())
    rule = h.app.detector.update_rule(m[1], h.actor, enabled=d.get("enabled"), severity=d.get("severity"),
                                      params=d.get("params"), ip=h.ip)
    return {"rule": rule}


# --------------------------------------------------------------------------- agents & devices
@route("GET", "/api/v1/agents")
def agents(h, m):
    data = {"agents": h.app.agents.list()}
    if "manage_agents" in h.user["permissions"]:
        data["invites"] = h.app.agents.list_invites()
    return data


@route("POST", "/api/v1/agents/invites", perm="manage_agents")
def create_invite(h, m):
    d = _obj(h.body())
    return h.app.agents.create_invite(d.get("name"), h.actor, d.get("ttl_minutes", 30), ip=h.ip), 201


@route("POST", r"/api/v1/agents/invites/(\d+)/revoke", perm="manage_agents")
def revoke_invite(h, m):
    if not h.app.agents.revoke_invite(_int(m[1]), h.actor, ip=h.ip):
        raise HttpError(404, "Invite not found or already used")
    return {"ok": True}


@route("POST", r"/api/v1/agents/(agt_[a-f0-9]{16}|legacy-[A-Za-z0-9_-]{1,64})/(approve|revoke|rotate|update)", perm="manage_agents")
def agent_action(h, m):
    d = _obj(h.body())
    agent_id, verb = m[1], m[2]
    if verb == "approve":
        agent = h.app.agents.approve(agent_id, h.actor, d.get("fingerprint_confirmation", ""), ip=h.ip)
    elif verb == "revoke":
        agent = h.app.agents.revoke(agent_id, h.actor, str(d.get("reason", "")), ip=h.ip)
    elif verb == "rotate":
        agent = h.app.agents.request_rotation(agent_id, h.actor, ip=h.ip)
    else:
        agent = h.app.agents.update_settings(agent_id, h.actor, d.get("name"), d.get("offline_after_seconds"), ip=h.ip)
    return {"agent": agent}


@route("GET", "/api/v1/devices")
def devices(h, m):
    return {"devices": h.app.inventory.list()}


@route("GET", r"/api/v1/devices/(\d+)")
def device_detail(h, m):
    device = h.app.inventory.detail(_int(m[1]))
    if not device:
        raise HttpError(404, "Device not found")
    return device


@route("POST", "/api/v1/devices", perm="manage_agents")
def add_device(h, m):
    d = _obj(h.body())
    return h.app.inventory.add_manual(h.actor, d.get("display_name"), d.get("hostname", ""), d.get("ip_address", ""),
                                      d.get("mac_address", ""), d.get("os", ""), d.get("notes", ""), ip=h.ip), 201


@route("POST", r"/api/v1/devices/(\d+)", perm="manage_agents")
def update_device(h, m):
    d = _obj(h.body())
    return h.app.inventory.update(_int(m[1]), h.actor, d.get("display_name"), d.get("notes"), d.get("approved"), ip=h.ip)


# --------------------------------------------------------------------------- system
@route("GET", "/api/v1/system/health")
def system_health(h, m):
    health = h.app.system_health()
    if "manage_system" not in h.user["permissions"]:
        health.pop("backups", None)
    return health


@route("POST", "/api/v1/system/backup", perm="manage_system")
def system_backup(h, m):
    path = h.app.backup(h.actor, ip=h.ip)
    return {"file": path.name}, 201


@route("POST", "/api/v1/system/retention", perm="manage_system")
def system_retention(h, m):
    return {"retention": h.app.set_retention(h.actor, _obj(h.body()), ip=h.ip)}


@route("GET", "/api/v1/audit", perm="view_audit")
def audit(h, m):
    before = h.query("before")
    return {"entries": h.app.audit.list(limit=_int(h.query("limit") or 200, "limit"),
                                        before_id=_int(before, "before") if before else None, action=h.query("action")),
            "chain": h.app.audit.verify()}


# --------------------------------------------------------------------------- agent API
@route("POST", "/api/v1/agent/enroll", auth="none", body=16 * 1024)
def agent_enroll(h, m):
    if not h.server.enroll_limiter.allow(f"enroll:{h.ip}"):
        raise HttpError(429, "Too many enrollment attempts; wait a minute.")
    return h.app.agents.enroll(h.body(), ip=h.ip), 201


@route("GET", "/api/v1/agent/status", auth="agent")
def agent_status(h, m):
    a = h.agent
    return {"agent_id": a["id"], "name": a["name"], "status": a["status"], "reason": a["status_reason"],
            "rotate": bool(a["rotate_requested"])}


@route("POST", "/api/v1/agent/heartbeat", auth="agent")
def agent_heartbeat(h, m):
    if h.agent["status"] not in ("active", "pending"):
        h.app.agents.require_active(h.agent)
    response, notices = h.app.agents.heartbeat(h.agent, _obj(h.body()), ip=h.ip)
    h.app.ingest_notices(notices)
    return response


@route("POST", "/api/v1/agent/events", auth="agent", body=AGENT_BODY)
def agent_events(h, m):
    h.app.agents.require_active(h.agent)
    d = _obj(h.body())
    source = str(d.get("source", "agent"))[:32]
    if not re.match(r"^[a-z0-9_-]{1,32}$", source):
        raise HttpError(400, "Invalid source name")
    result = h.app.ingest(d.get("events"), mode="live", trust="verified_agent", source=source,
                          agent_id=h.agent["id"], site_id=h.agent["site_id"], atomic=False)
    if result["accepted"]:
        _, notices = h.app.inventory.observe_dhcp(h.app.events.get_many(result["accepted"]), h.agent)
        h.app.ingest_notices(notices)
    return {"accepted": len(result["accepted"]), "duplicates": result["duplicates"], "rejected": result["rejected"]}


@route("POST", "/api/v1/agent/inventory", auth="agent", body=AGENT_BODY)
def agent_inventory(h, m):
    h.app.agents.require_active(h.agent)
    result, notices = h.app.inventory.report(h.agent, _obj(h.body()).get("observations"))
    h.app.ingest_notices(notices)
    return result


@route("POST", "/api/v1/agent/rotate", auth="agent")
def agent_rotate(h, m):
    return h.app.agents.rotate(h.agent, ip=h.ip)


# --------------------------------------------------------------------------- legacy v0.4 collector API (opt-in)
@route("POST", "/api/ingest", auth="legacy", body=SMALL_BODY)
def legacy_ingest(h, m):
    d = _obj(h.body())
    agent_id = str(d.get("agent_id", ""))
    if agent_id and not re.match(r"^[A-Za-z0-9_-]{1,64}$", agent_id):
        raise HttpError(400, "Invalid agent ID")
    result = h.app.ingest(d.get("events"), mode="live", trust="legacy_token", source="legacy_collector",
                          agent_id=f"legacy-{agent_id}" if agent_id else "", atomic=True)
    return {"ingested": len(result["accepted"]), "duplicates": result["duplicates"]}, 201


@route("POST", "/api/agents/heartbeat", auth="legacy")
def legacy_heartbeat(h, m):
    d = _obj(h.body())
    agent_id = str(d.get("agent_id", ""))
    if not re.match(r"^[A-Za-z0-9_-]{1,64}$", agent_id):
        raise HttpError(400, "Agent ID must contain 1–64 letters, numbers, _ or -")
    name = " ".join(str(d.get("name", agent_id)).split())[:80] or agent_id
    with h.app.db.tx() as conn:
        conn.execute("INSERT INTO agents(id,name,status,platform,enrolled_at,last_contact_at,last_ip,status_reason) "
                     "VALUES(?,?,'legacy',?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET last_contact_at=excluded.last_contact_at, "
                     "last_ip=excluded.last_ip", (f"legacy-{agent_id}", name, str(d.get("platform", ""))[:80], iso(), iso(), h.ip,
                                                  "Legacy shared-token collector: identity not verified."))
        h.app.db.bump_revision(conn)
    return {"ok": True}


# =========================================================================== handler
class Handler(BaseHTTPRequestHandler):
    server_version = "BLACKGUARD"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = 30

    @property
    def app(self):
        return self.server.app

    def log_message(self, fmt, *args):
        log.debug("%s %s", self.ip, fmt % args)

    @property
    def ip(self):
        if self.server.app.settings.trusted_proxy:
            forwarded = self.headers.get("X-Forwarded-For", "")
            if forwarded:
                return forwarded.split(",")[-1].strip()[:64]
        return self.client_address[0]

    def query(self, name):
        values = self._query.get(name)
        return values[0][:500] if values else ""

    def body(self):
        if self._body is not None:
            return self._body
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise HttpError(400, "Invalid Content-Length") from exc
        if length < 1:
            raise HttpError(400, "A JSON body is required")
        if length > self._body_limit:
            self.close_connection = True
            raise HttpError(413, f"Request body exceeds {self._body_limit // 1024} KiB")
        if "application/json" not in self.headers.get("Content-Type", ""):
            raise HttpError(415, "Content-Type must be application/json")
        raw = self.rfile.read(length)
        self._body_read = True
        try:
            self._body = json.loads(raw)
        except (ValueError, UnicodeDecodeError) as exc:
            raise HttpError(400, "Malformed JSON") from exc
        return self._body

    # -- response helpers ---------------------------------------------------
    def cookie_header(self, token, expire=False):
        tls = self.app.settings.tls_enabled
        name = "__Host-bg_session" if tls else "bg_session"
        parts = [f"{name}={token}", "Path=/", "HttpOnly", "SameSite=Strict"]
        if tls:
            parts.append("Secure")
        parts.append("Max-Age=0" if expire else f"Max-Age={self.app.settings.session_absolute_hours * 3600}")
        return "; ".join(parts)

    def start_session(self, username, password, status=200):
        try:
            token, csrf, user = self.app.auth.login(username, password, self.ip, self.headers.get("User-Agent", ""))
        except AuthError as exc:
            raise HttpError(exc.status, str(exc)) from exc
        self.extra_headers.append(("Set-Cookie", self.cookie_header(token)))
        return {"user": user, "csrf": csrf}, status

    def download(self, text, content_type, filename):
        return ("__raw__", text.encode("utf-8"), content_type, filename)

    def send_common_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
        if self.app.settings.tls_enabled:
            self.send_header("Strict-Transport-Security", "max-age=31536000")
        for name, value in self.extra_headers:
            self.send_header(name, value)

    def drain_body(self):
        """Consume an unread request body so a kept-alive connection cannot be desynchronised."""
        if getattr(self, "_body_read", True):
            return
        self._body_read = True
        try:
            length = int(self.headers.get("Content-Length", "0") or 0)
        except ValueError:
            length = -1
        if 0 < length <= self._body_limit:
            self.rfile.read(length)
        elif length != 0:
            self.close_connection = True

    def send_payload(self, status, payload, content_type, extra=None):
        self.drain_body()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        for name, value in (extra or {}).items():
            self.send_header(name, value)
        self.send_common_headers()
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def send_json(self, data, status=200, extra=None):
        self.send_payload(status, json.dumps(data, default=str).encode("utf-8"), "application/json; charset=utf-8", extra)

    # -- dispatch -----------------------------------------------------------
    def do_GET(self):
        self.dispatch("GET")

    def do_HEAD(self):
        self.dispatch("GET")

    def do_POST(self):
        self.dispatch("POST")

    def do_PUT(self):
        self.dispatch("PUT")

    def do_DELETE(self):
        self.dispatch("DELETE")

    def do_PATCH(self):
        self.dispatch("PATCH")

    def dispatch(self, method):
        self.extra_headers = []
        self._body = None
        self._body_read = False
        self._body_limit = SMALL_BODY
        self.user = self.agent = None
        if self.headers.get("Transfer-Encoding"):
            self.close_connection = True  # chunked bodies are not supported; never reuse such a connection
        parsed = urlsplit(self.path)
        self._query = parse_qs(parsed.query, max_num_fields=30)
        path = parsed.path
        if not self.server.slots.acquire(blocking=False):
            self.close_connection = True
            return self.send_json({"error": "Server busy; retry shortly"}, 503, {"Retry-After": "5"})
        try:
            if method == "GET" and path in STATIC:
                return self.static(*STATIC[path])
            for verb, pattern, func, auth, perm, limit in ROUTES:
                match = pattern.match(path)
                if match and verb == method:
                    self._body_limit = limit
                    self.authorize(method, auth, perm)
                    result = func(self, match)
                    return self.respond(result)
            if any(p.match(path) for _, p, *_ in ROUTES):
                raise HttpError(405, "Method not allowed")
            raise HttpError(404, "Not found")
        except HttpError as exc:
            self.send_json({"error": str(exc)}, exc.status, exc.headers)
        except AgentError as exc:
            self.send_json({"error": str(exc)}, exc.status)
        except AuthError as exc:
            self.send_json({"error": str(exc)}, exc.status)
        except LookupError as exc:
            self.send_json({"error": str(exc).strip("'\"") or "Not found"}, 404)
        except (ValueError, TypeError) as exc:
            self.send_json({"error": str(exc) or "Invalid request"}, 400)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except Exception:  # never leak internals to the client
            log.exception("Unhandled error on %s %s", method, path)
            try:
                self.send_json({"error": "Internal server error; see the server log."}, 500)
            except OSError:
                pass
        finally:
            self.server.slots.release()
            self.app.db.close()  # per-request connection; worker threads are short-lived

    def respond(self, result):
        status = 200
        if isinstance(result, tuple) and result and result[0] == "__raw__":
            _, payload, content_type, filename = result
            return self.send_payload(200, payload, content_type, {"Content-Disposition": f'attachment; filename="{filename}"'})
        if isinstance(result, tuple):
            result, status = result
        self.send_json(result, status)

    def session_token(self):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except Exception:
            return ""
        for name in ("__Host-bg_session", "bg_session"):
            if name in cookie:
                return cookie[name].value
        return ""

    def authorize(self, method, auth, perm):
        if auth == "none":
            if method != "GET":
                self.check_origin()
            return
        if auth == "agent":
            header = self.headers.get("Authorization", "")
            credential = header[7:].strip() if header.startswith("Bearer ") else ""
            self.agent = self.app.agents.authenticate(credential, ip=self.ip)
            if not self.server.agent_limiter.allow(f"agent:{self.agent['id']}"):
                raise HttpError(429, "Agent rate limit exceeded", {"Retry-After": "10"})
            return
        if auth == "legacy":
            expected = self.app.settings.legacy_ingest_token
            header = self.headers.get("Authorization", "")
            if not expected:
                raise HttpError(410, "The v0.4 shared-token collector API is disabled. Enroll agents with bgagent.py (see README).")
            if not header.startswith("Bearer ") or not hmac.compare_digest(header[7:].strip(), expected):
                raise HttpError(403, "Invalid access token")
            return
        token = self.session_token()
        self.user = self.app.auth.session(token) if token else None
        if not self.user:
            raise HttpError(401, "Sign in required")
        self.actor = actor_of(self.user)
        if not self.server.api_limiter.allow(f"user:{self.user['id']}"):
            raise HttpError(429, "Too many requests", {"Retry-After": "10"})
        if method != "GET":
            self.check_origin()
            if not hmac.compare_digest(self.headers.get("X-CSRF-Token", ""), self.user["csrf"]):
                raise HttpError(403, "Missing or invalid CSRF token; reload the page.")
        if perm not in self.user["permissions"]:
            raise HttpError(403, "Your role does not allow this action.")

    def check_origin(self):
        origin = self.headers.get("Origin")
        if origin and origin != "null" and urlsplit(origin).netloc != self.headers.get("Host", ""):
            raise HttpError(403, "Cross-origin request refused")
        if origin == "null":
            raise HttpError(403, "Cross-origin request refused")

    def static(self, name, content_type):
        content = (WEB / name).read_bytes()
        self.drain_body()
        extra = {"Content-Security-Policy": CSP} if name == "index.html" else {}
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-cache")
        for key, value in extra.items():
            self.send_header(key, value)
        self.send_common_headers()
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(content)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(self, app):
        self.app = app
        settings = app.settings
        self.slots = threading.BoundedSemaphore(settings.max_concurrent_requests)
        self.login_limiter = RateLimiter(10, 10)
        self.enroll_limiter = RateLimiter(10, 5)
        self.api_limiter = RateLimiter(900, 120)
        self.agent_limiter = RateLimiter(600, 120)
        self.ai_limiter = RateLimiter(4, 2)
        if ":" in settings.host:
            self.address_family = socket.AF_INET6
        self.tls = None
        if settings.tls_enabled:
            self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.tls.minimum_version = ssl.TLSVersion.TLSv1_2
            self.tls.load_cert_chain(settings.tls_cert, settings.tls_key)
        super().__init__((settings.host, settings.port), Handler)

    def finish_request(self, request, client_address):
        # TLS handshakes run in the per-connection worker thread, with a timeout,
        # so a slow or malicious client cannot stall the accept loop.
        if self.tls:
            request.settimeout(Handler.timeout)
            try:
                request = self.tls.wrap_socket(request, server_side=True)
            except (ssl.SSLError, OSError):
                request.close()
                return
            try:
                super().finish_request(request, client_address)
            finally:
                try:
                    request.close()
                except OSError:
                    pass
            return
        super().finish_request(request, client_address)

    def drain(self, timeout=10.0):
        """Wait for in-flight requests to finish (idle keep-alive connections are not waited for)."""
        import time as _time
        deadline = _time.monotonic() + timeout
        held = 0
        while held < self.app.settings.max_concurrent_requests and _time.monotonic() < deadline:
            if self.slots.acquire(timeout=max(0.0, deadline - _time.monotonic())):
                held += 1
        for _ in range(held):
            self.slots.release()
        return held == self.app.settings.max_concurrent_requests

    def handle_error(self, request, client_address):
        log.debug("Connection error from %s", client_address, exc_info=True)

