"""HTTP API security: setup, sessions, CSRF, origin checks, RBAC, headers, limits, legacy API."""

import json
import unittest

from helpers import PASSWORD, TestServer


class HttpSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = TestServer()
        cls.admin = cls.srv.admin()

    @classmethod
    def tearDownClass(cls):
        cls.srv.close()

    def test_static_assets_and_security_headers(self):
        client = self.srv.client()
        for path in ("/", "/style.css", "/app.js", "/shield.svg"):
            status, body = client.request("GET", path, raw=True)
            self.assertEqual(status, 200, path)
            self.assertTrue(body)
        client.request("GET", "/", raw=True)
        headers = client.last_headers
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertNotIn("Python", headers.get("Server", ""))

    def test_setup_cannot_be_repeated(self):
        status, body = self.srv.client().request("POST", "/api/v1/setup", {"setup_code": self.srv.setup_code, "username": "intruder", "password": PASSWORD})
        self.assertEqual(status, 409)
        self.assertFalse(self.srv.app.db.one("SELECT 1 FROM users WHERE username='intruder'"))

    def test_unauthenticated_requests_rejected(self):
        client = self.srv.client()
        for path in ("/api/v1/overview", "/api/v1/events", "/api/v1/incidents", "/api/v1/audit", "/api/v1/report"):
            self.assertEqual(client.request("GET", path)[0], 401, path)
        self.assertEqual(client.request("POST", "/api/v1/detect", {})[0], 401)

    def test_session_cookie_flags(self):
        client = self.srv.client()
        client.login("owner")
        cookie = client.last_headers["Set-Cookie"]
        for flag in ("HttpOnly", "SameSite=Strict", "Path=/"):
            self.assertIn(flag, cookie)
        self.assertTrue(cookie.startswith("bg_session=bgs_"))

    def test_csrf_and_origin_enforced(self):
        client = self.srv.client()
        client.login("owner")
        token, client.csrf = client.csrf, ""
        self.assertEqual(client.request("POST", "/api/v1/detect", {})[0], 403)
        client.csrf = token
        status, _ = client.request("POST", "/api/v1/detect", {}, headers={"Origin": "https://evil.example"})
        self.assertEqual(status, 403)
        self.assertEqual(client.request("POST", "/api/v1/detect", {}, headers={"Origin": "null"})[0], 403)
        self.assertEqual(client.request("POST", "/api/v1/detect", {})[0], 200)

    def test_login_failures_are_generic_and_audited(self):
        client = self.srv.client()
        missing = client.request("POST", "/api/v1/auth/login", {"username": "nobody", "password": "x" * 12})
        wrong = client.request("POST", "/api/v1/auth/login", {"username": "owner", "password": "x" * 12})
        self.assertEqual(missing[0], 401)
        self.assertEqual(missing[1]["error"], wrong[1]["error"])
        self.assertTrue(any(a["action"] == "auth.login" and a["outcome"] == "failure" for a in self.srv.app.audit.list()))

    def test_role_based_access(self):
        viewer = self.srv.user("vera", "viewer")
        analyst = self.srv.user("andy", "analyst")
        self.assertEqual(viewer.request("GET", "/api/v1/overview")[0], 200)
        for path in ("/api/v1/detect", "/api/v1/events/import", "/api/v1/agents/invites", "/api/v1/users"):
            self.assertEqual(viewer.request("POST", path, {"events": [], "name": "x"})[0], 403, path)
        self.assertEqual(viewer.request("GET", "/api/v1/report")[0], 403)
        self.assertEqual(viewer.request("GET", "/api/v1/audit")[0], 403)
        self.assertEqual(analyst.request("POST", "/api/v1/detect", {})[0], 200)
        self.assertEqual(analyst.request("POST", "/api/v1/agents/invites", {"name": "x"})[0], 403)
        self.assertEqual(analyst.request("POST", "/api/v1/rules/BG-AUTH-01", {"enabled": False})[0], 403)
        self.assertEqual(analyst.request("GET", "/api/v1/users")[0], 403)
        self.assertNotIn("invites", analyst.get("/api/v1/agents"))

    def test_role_change_ends_sessions(self):
        self.srv.app.auth.create_user("temp", PASSWORD, "analyst")
        temp = self.srv.client()
        temp.login("temp")
        row = self.srv.app.db.one("SELECT id FROM users WHERE username='temp'")
        self.admin.post(f"/api/v1/users/{row['id']}", {"role": "viewer"})
        self.assertEqual(temp.request("GET", "/api/v1/overview")[0], 401)

    def test_last_admin_cannot_be_removed(self):
        me = self.admin.get("/api/v1/auth/me")["user"]
        status, body = self.admin.request("POST", f"/api/v1/users/{me['id']}", {"role": "viewer"})
        self.assertEqual(status, 400)
        self.assertIn("administrator", body["error"])

    def test_weak_passwords_rejected(self):
        for password in ("short", "aaaaaaaaaaaaaaaa", "password1234", "newuser-and-more"):
            status, _ = self.admin.request("POST", "/api/v1/users", {"username": "newuser", "password": password, "role": "viewer"})
            self.assertEqual(status, 400, password)

    def test_input_limits(self):
        status, _ = self.admin.request("POST", "/api/v1/events/import", b"{" + b" " * (300 * 1024) + b"}")
        self.assertEqual(status, 413)
        status, _ = self.admin.request("POST", "/api/v1/events/import", b"not json")
        self.assertEqual(status, 400)
        status, _ = self.admin.request("POST", "/api/v1/events/import", json.dumps({"events": []}).encode(), headers={"Content-Type": "text/plain"})
        self.assertEqual(status, 415)
        self.assertEqual(self.admin.request("GET", "/api/v1/events?limit=abc")[0], 400)
        self.assertEqual(self.admin.request("GET", "/api/v1/events?type=nope")[0], 400)
        self.assertEqual(self.admin.request("GET", "/api/v1/nope")[0], 404)
        self.assertEqual(self.admin.request("DELETE", "/api/v1/overview")[0], 405)

    def test_sql_metacharacters_are_data(self):
        payload = {"events": [{"type": "service_error", "host": "h'; DROP TABLE events;--", "message": "%_\\' OR 1=1 --"}]}
        self.admin.post("/api/v1/events/import", payload, expect=201)
        found = self.admin.get("/api/v1/events?q=%25_")["events"]
        self.assertTrue(any(e["host"].startswith("h'; DROP") for e in found))
        self.assertGreater(self.srv.app.events.count(), 0)

    def test_legacy_shared_token_api_disabled_by_default(self):
        status, body = self.srv.client().request("POST", "/api/ingest", {"events": []}, headers={"Authorization": "Bearer " + "x" * 30})
        self.assertEqual(status, 410)
        self.assertIn("disabled", body["error"])

    def test_logout_invalidates_session(self):
        client = self.srv.client()
        client.login("owner")
        client.post("/api/v1/auth/logout")
        self.assertEqual(client.request("GET", "/api/v1/overview")[0], 401)

    def test_keep_alive_unread_body_cannot_desync_connection(self):
        import http.client
        from urllib.parse import urlsplit
        url = urlsplit(self.srv.base)
        conn = http.client.HTTPConnection(url.hostname, url.port, timeout=10)
        cookie = "; ".join(f"{c.name}={c.value}" for c in self.admin.jar)
        headers = {"Cookie": cookie, "X-CSRF-Token": self.admin.csrf, "Content-Type": "application/json"}
        for _ in range(2):  # endpoints that ignore their body, then a GET on the same socket
            conn.request("POST", "/api/v1/detect", body=b'{"padding": "xxxxxxxx"}', headers=headers)
            self.assertEqual(conn.getresponse().read() and 200, 200)
            conn.request("GET", "/api/v1/revision", headers=headers)
            response = conn.getresponse()
            self.assertEqual(response.status, 200)
            self.assertIn("revision", json.loads(response.read()))
        conn.close()

    def test_demo_purge_requires_typed_confirmation(self):
        self.assertEqual(self.admin.request("POST", "/api/v1/demo/purge", {"confirm": "yes"})[0], 400)


class LoginRateLimitTests(unittest.TestCase):
    def test_login_rate_limited(self):
        srv = TestServer()
        try:
            srv.admin()
            client = srv.client()
            codes = [client.request("POST", "/api/v1/auth/login", {"username": "owner", "password": "wrong-password-x"})[0] for _ in range(12)]
            self.assertIn(429, codes)
        finally:
            srv.close()

    def test_account_lockout(self):
        srv = TestServer()
        try:
            srv.admin()
            srv.server.login_limiter.rate = 1000  # isolate account lockout from IP rate limiting
            srv.server.login_limiter.burst = 1000
            client = srv.client()
            for _ in range(8):
                client.request("POST", "/api/v1/auth/login", {"username": "owner", "password": "wrong-password-x"})
            status, body = client.request("POST", "/api/v1/auth/login", {"username": "owner", "password": PASSWORD})
            self.assertEqual(status, 429)
            self.assertIn("locked", body["error"])
        finally:
            srv.close()


class LegacyIngestTests(unittest.TestCase):
    def test_legacy_ingest_when_explicitly_enabled(self):
        token = "legacy-token-for-tests-1234567890"  # secret-scan: allow (test fixture)
        srv = TestServer(legacy_ingest_token=token)
        try:
            admin = srv.admin()
            client = srv.client()
            hb = client.request("POST", "/api/agents/heartbeat", {"agent_id": "home-pc", "name": "Home PC", "platform": "Linux"},
                                headers={"Authorization": f"Bearer {token}"})
            self.assertEqual(hb[0], 200)
            status, body = client.request("POST", "/api/ingest", {"agent_id": "home-pc", "events": [{"type": "service_error", "host": "pc", "message": "x"}]},
                                          headers={"Authorization": f"Bearer {token}"})
            self.assertEqual(status, 201)
            events = admin.get("/api/v1/events?mode=live")["events"]
            self.assertEqual(events[0]["trust"], "legacy_token")
            self.assertEqual(events[0]["agent_id"], "legacy-home-pc")
            agents = admin.get("/api/v1/agents")["agents"]
            self.assertEqual(agents[0]["status"], "legacy")
            self.assertEqual(client.request("POST", "/api/ingest", {"events": []}, headers={"Authorization": "Bearer wrong"})[0], 403)
        finally:
            srv.close()


if __name__ == "__main__":
    unittest.main()
