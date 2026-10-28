"""Shared test fixtures: temporary apps, a threaded test server and an HTTP client with cookies."""

import http.cookiejar
import json
import os
import socket
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for path in (str(ROOT), str(ROOT / "agents")):
    if path not in sys.path:
        sys.path.insert(0, path)

from guard import security  # noqa: E402
from guard.config import Settings  # noqa: E402
from guard.platform import App  # noqa: E402

# Fast password hashing for tests only (production keeps N=2**15).
security.SCRYPT_N = 2 ** 10
PASSWORD = "correct horse battery staple"


def ts(minutes_ago=0, seconds=0):
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago, seconds=seconds)).isoformat(timespec="seconds")


def ev(kind="auth_failure", host="gate-01", ip="203.0.113.9", actor="admin", minutes=1, **extra):
    item = {"type": kind, "host": host, "source_ip": ip, "actor": actor, "message": f"Test {kind} {actor}@{host}",
            "timestamp": ts(minutes)}
    item.update(extra)
    return item


def make_app(directory, **overrides):
    settings = Settings(data_dir=Path(directory), db_path=Path(directory) / "test.sqlite3", seed_demo=False)
    for key, value in overrides.items():
        setattr(settings, key, value)
    return App(settings)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class TestServer:
    def __init__(self, **overrides):
        from guard.server import Server
        self.temp = tempfile.TemporaryDirectory()
        overrides.setdefault("port", free_port())
        self.app = make_app(self.temp.name, **overrides)
        self.setup_code = self.app.auth.ensure_setup_code()
        self.server = Server(self.app)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        scheme = "https" if self.app.settings.tls_enabled else "http"
        self.base = f"{scheme}://127.0.0.1:{self.app.settings.port}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.app.db.close()
        self.temp.cleanup()

    def client(self):
        return Client(self.base)

    def admin(self, username="owner"):
        client = self.client()
        if self.app.auth.user_count() == 0:
            client.post_setup("/api/v1/setup", {"setup_code": self.setup_code, "username": username, "password": PASSWORD}, expect=201)
        else:
            client.login(username)
        return client

    def user(self, username, role):
        if not self.app.db.one("SELECT 1 FROM users WHERE username = ?", (username,)):
            self.app.auth.create_user(username, PASSWORD, role)
        client = self.client()
        client.login(username)
        return client

    def agent(self, admin, name="Test agent", fingerprint="a" * 64, approve=True):
        invite = admin.post("/api/v1/agents/invites", {"name": name}, expect=201)
        enrolled = self.client().post("/api/v1/agent/enroll", {"code": invite["code"], "hostname": name.replace(" ", "-").lower(),
                                                                "platform": "Linux test", "fingerprint": fingerprint}, expect=201)
        agent = AgentClient(self.base, enrolled["credential"], enrolled["agent_id"])
        if approve:
            admin.post(f"/api/v1/agents/{enrolled['agent_id']}/approve", {"fingerprint_confirmation": fingerprint[:8]})
        return agent


class Client:
    def __init__(self, base):
        self.base = base
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.csrf = ""
        self.last_headers = {}

    def request(self, method, path, data=None, headers=None, expect=None, raw=False):
        hdrs = {"X-CSRF-Token": self.csrf}
        body = None
        if data is not None:
            body = data if isinstance(data, bytes) else json.dumps(data).encode()
            hdrs["Content-Type"] = "application/json"
        hdrs.update(headers or {})
        req = urllib.request.Request(self.base + path, data=body, headers=hdrs, method=method)
        try:
            with self.opener.open(req, timeout=10) as resp:
                status, payload, self.last_headers = resp.status, resp.read(), dict(resp.headers)
        except urllib.error.HTTPError as exc:
            status, payload, self.last_headers = exc.code, exc.read(), dict(exc.headers)
        if expect is not None and status != expect:
            raise AssertionError(f"{method} {path}: expected {expect}, got {status}: {payload[:300]!r}")
        if raw:
            return status, payload
        try:
            parsed = json.loads(payload or b"{}")
        except ValueError:
            parsed = {"_raw": payload}
        return parsed if expect is not None else (status, parsed)

    def get(self, path, expect=200):
        return self.request("GET", path, expect=expect)

    def post(self, path, data=None, expect=200, headers=None):
        return self.request("POST", path, {} if data is None else data, headers=headers, expect=expect)

    def login(self, username, password=PASSWORD):
        data = self.post("/api/v1/auth/login", {"username": username, "password": password})
        self.csrf = data["csrf"]
        return data

    def post_setup(self, *args, **kwargs):
        data = self.post(*args, **kwargs)
        self.csrf = data.get("csrf", self.csrf)
        return data


class AgentClient:
    def __init__(self, base, credential, agent_id):
        self.base, self.credential, self.agent_id = base, credential, agent_id

    def request(self, method, path, data=None, credential=None):
        hdrs = {"Authorization": f"Bearer {credential or self.credential}"}
        body = None
        if data is not None:
            body = json.dumps(data).encode()
            hdrs["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base + path, data=body, headers=hdrs, method=method)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    def events(self, events, source="test"):
        return self.request("POST", "/api/v1/agent/events", {"source": source, "events": events})

    def heartbeat(self, fingerprint="a" * 64, **health):
        return self.request("POST", "/api/v1/agent/heartbeat", {"fingerprint": fingerprint, "health": health})


def clean_env():
    for key in list(os.environ):
        if key.startswith("BLACKGUARD_"):
            os.environ.pop(key)
