"""Investigation workflow: notes, statuses, Guardian Response approvals, reports, AI analyst, retention, backups."""

import json
import tempfile
import threading
import unittest
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from helpers import TestServer, ev, free_port, make_app
from guard.ai import Analyst
from guard.audit import AuditLog
from guard.config import Settings
from guard.db import iso, utcnow
from guard.security import RateLimiter, hash_password, redact, verify_password


class WorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = TestServer()
        cls.admin = cls.srv.admin()
        cls.analyst = cls.srv.user("ana", "analyst")
        cls.srv.app.ingest([ev(minutes=6 - i * 0.5) for i in range(5)] + [ev("auth_success", minutes=1)],
                           mode="live", trust="verified_agent", source="test", agent_id="agt_x", atomic=False)
        cls.incident = [i for i in cls.admin.get("/api/v1/incidents")["incidents"] if i["rule_id"] == "BG-AUTH-02"][0]

    @classmethod
    def tearDownClass(cls):
        cls.srv.close()

    def test_incident_detail_has_evidence_timeline_and_guidance(self):
        d = self.admin.get(f"/api/v1/incidents/{self.incident['id']}")
        self.assertEqual(len(d["evidence"]), 6)
        self.assertTrue(d["confidence_reason"])
        self.assertFalse(d["guidance"]["automatic_action"])
        self.assertTrue(d["guidance"]["investigation"] and d["guidance"]["false_positives"])
        self.assertEqual(d["rule"]["mitre"][0]["id"], "T1110")
        self.assertEqual([t["kind"] for t in d["timeline"]].count("event"), 6)
        event = self.admin.get(f"/api/v1/events/{d['evidence'][0]['id']}")
        self.assertIn(self.incident["id"], [i["id"] for i in event["incidents"]])

    def test_notes_and_status_changes_are_recorded(self):
        iid = self.incident["id"]
        self.analyst.post(f"/api/v1/incidents/{iid}/notes", {"body": "Called the account owner."}, expect=201)
        self.analyst.post(f"/api/v1/incidents/{iid}/status", {"status": "investigating"})
        notes = self.admin.get(f"/api/v1/incidents/{iid}")["notes"]
        self.assertTrue(any(n["body"] == "Called the account owner." and n["author_name"] == "ana" for n in notes))
        self.assertTrue(any("investigating" in n["body"] for n in notes))
        self.assertEqual(self.analyst.request("POST", f"/api/v1/incidents/{iid}/status", {"status": "deleted"})[0], 400)
        self.assertEqual(self.analyst.request("POST", f"/api/v1/incidents/{iid}/notes", {"body": ""})[0], 400)
        self.assertEqual(self.analyst.request("POST", "/api/v1/incidents/99999/notes", {"body": "x"})[0], 404)

    def test_guardian_response_requires_admin_approval_and_records_rollback(self):
        iid = self.incident["id"]
        aid = self.analyst.post(f"/api/v1/incidents/{iid}/responses", {"action_type": "isolate_device"}, expect=201)["id"]
        self.assertEqual(self.analyst.request("POST", f"/api/v1/incidents/{iid}/responses", {"action_type": "isolate_device"})[0], 400)
        self.assertEqual(self.analyst.request("POST", f"/api/v1/responses/{aid}/approve", {"acknowledge_impact": True})[0], 403)
        self.assertEqual(self.admin.request("POST", f"/api/v1/responses/{aid}/approve", {})[0], 400)  # impact not acknowledged
        self.admin.post(f"/api/v1/responses/{aid}/approve", {"acknowledge_impact": True, "note": "ok"})
        self.assertEqual(self.admin.request("POST", f"/api/v1/responses/{aid}/complete", {})[0], 400)  # note required
        self.admin.post(f"/api/v1/responses/{aid}/complete", {"note": "Unplugged the laptop from Wi-Fi"})
        responses = self.admin.post(f"/api/v1/responses/{aid}/rollback", {"note": "Reconnected after clean scan"})["responses"]
        self.assertEqual([r for r in responses if r["id"] == aid][0]["status"], "rolled_back")
        self.assertEqual(self.admin.request("POST", f"/api/v1/responses/{aid}/approve", {"acknowledge_impact": True})[0], 400)
        actions = [a["action"] for a in self.srv.app.audit.list()]
        for verb in ("propose", "approve", "complete", "rollback"):
            self.assertIn(f"response.{verb}", actions)
        self.assertEqual(self.analyst.request("POST", f"/api/v1/incidents/{iid}/responses", {"action_type": "hack_back"})[0], 400)

    def test_reports(self):
        iid = self.incident["id"]
        status, body = self.analyst.request("GET", f"/api/v1/incidents/{iid}/report", raw=True)
        text = body.decode()
        self.assertEqual(status, 200)
        self.assertIn("text/markdown", self.analyst.last_headers["Content-Type"])
        self.assertIn("Investigation steps", text)
        self.assertIn("has not executed", text)
        self.assertIn("203.0.113.9", text)
        status, body = self.analyst.request("GET", f"/api/v1/incidents/{iid}/report?pseudonymize=1", raw=True)
        self.assertNotIn("203.0.113.9", body.decode())
        self.assertIn("anon-", body.decode())
        data = json.loads(self.analyst.request("GET", f"/api/v1/incidents/{iid}/report?format=json", raw=True)[1])
        self.assertEqual(data["incident"]["id"], iid)
        status, body = self.analyst.request("GET", "/api/v1/report", raw=True)
        self.assertIn("Recent evidence", body.decode())
        self.assertTrue(any(a["action"] == "report.export" for a in self.srv.app.audit.list()))

    def test_overview_labels_data_honestly(self):
        o = self.admin.get("/api/v1/overview")
        self.assertEqual(o["stats"]["dataset_label"], "LIVE DATA")
        self.assertEqual(len(o["histogram"]), 24)
        self.assertGreaterEqual(sum(b["live"] for b in o["histogram"]), 6)
        self.admin.post("/api/v1/demo/inject", expect=201)
        self.assertEqual(self.admin.get("/api/v1/overview")["stats"]["dataset_label"], "LIVE + DEMO")
        removed = self.admin.post("/api/v1/demo/purge", {"confirm": "DELETE DEMO DATA"})["removed"]
        self.assertEqual(removed, 7)
        self.assertEqual(self.admin.get("/api/v1/overview")["stats"]["demo_events"], 0)
        self.assertTrue(self.admin.get(f"/api/v1/incidents/{self.incident['id']}")["id"])

    def test_event_search_pagination(self):
        self.srv.app.ingest([ev("service_error", host="pager", message=f"m{i}", minutes=i) for i in range(25)],
                            mode="imported", trust="manual_import", source="import")
        first = self.admin.get("/api/v1/events?host=pager&limit=10")
        second = self.admin.get(f"/api/v1/events?host=pager&limit=10&cursor={first['next_cursor']}")
        third = self.admin.get(f"/api/v1/events?host=pager&limit=10&cursor={second['next_cursor']}")
        ids = [e["id"] for e in first["events"] + second["events"] + third["events"]]
        self.assertEqual(len(ids), 25)
        self.assertEqual(len(set(ids)), 25)
        self.assertIsNone(third["next_cursor"])
        since = iso(utcnow() - timedelta(minutes=5, seconds=30))
        recent = self.admin.get(f"/api/v1/events?host=pager&since={since}")
        self.assertEqual(len(recent["events"]), 6)

    def test_system_backup_retention_and_health(self):
        self.admin.post("/api/v1/system/backup", expect=201)
        health = self.admin.get("/api/v1/system/health")
        self.assertTrue(health["backups"])
        self.assertTrue(health["audit_chain"]["valid"])
        self.assertEqual(self.admin.request("POST", "/api/v1/system/retention", {"events_days": 1})[0], 400)
        self.admin.post("/api/v1/system/retention", {"events_days": 30})
        self.assertNotIn("backups", self.analyst.get("/api/v1/system/health"))


class AiAnalystTests(unittest.TestCase):
    def setUp(self):
        replies = self.replies = []

        class FakeOllama(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                replies.append(body)
                content = json.dumps({"summary": "Likely password guessing followed by a successful sign-in.",
                                      "cited_event_ids": [body["messages"][1]["content"].count("id") and 1, 99999],
                                      "benign_explanations": ["Owner mistyped password"], "uncertainties": ["No session data"],
                                      "suggested_steps": ["Ask the owner"], "confidence": "medium"})
                payload = json.dumps({"message": {"role": "assistant", "content": content}}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self.ollama = HTTPServer(("127.0.0.1", free_port()), FakeOllama)
        threading.Thread(target=self.ollama.serve_forever, daemon=True).start()
        self.srv = TestServer(ollama_url=f"http://127.0.0.1:{self.ollama.server_port}")
        self.admin = self.srv.admin()

    def tearDown(self):
        self.srv.close()
        self.ollama.shutdown()
        self.ollama.server_close()

    def test_ai_summary_is_validated_labelled_and_stored(self):
        self.srv.app.ingest([ev(minutes=5 - i * 0.5, message=f"password=hunter2 attempt {i}") for i in range(5)],
                            mode="live", trust="verified_agent", source="t", atomic=False)
        incident = self.admin.get("/api/v1/incidents")["incidents"][0]
        result = self.admin.post(f"/api/v1/incidents/{incident['id']}/ai-summary")
        analysis = result["analysis"]
        self.assertEqual(analysis["invalid_citations"], [99999])
        self.assertIn("hallucinating", analysis["uncertainties"][0])
        prompt = self.replies[0]["messages"][1]["content"]
        self.assertNotIn("hunter2", prompt)  # secrets are redacted before leaving BLACKGUARD
        self.assertIn("Never suggest attacking", self.replies[0]["messages"][0]["content"])
        notes = self.admin.get(f"/api/v1/incidents/{incident['id']}")["notes"]
        ai = [n for n in notes if n["kind"] == "ai"][0]
        self.assertIn("unverified", ai["body"])

    def test_ai_disabled_by_default_and_unreachable_is_clear(self):
        self.assertFalse(Analyst(Settings()).enabled)
        bad = Analyst(Settings(ollama_url="http://127.0.0.1:9"))
        from guard.ai import AIUnavailable
        with self.assertRaises(AIUnavailable):
            bad.analyse({"evidence": [], "title": "t", "rule_id": "x", "severity": "low", "confidence": "low",
                         "confidence_reason": "", "summary": "", "status": "open", "mode": "live"}, timeout=2)

    def test_remote_ollama_refused_without_opt_in(self):
        with self.assertRaises(SystemExit):
            Settings(ollama_url="http://192.168.1.5:11434").validate()


class PrimitiveTests(unittest.TestCase):
    def test_password_hashing(self):
        encoded = hash_password("a long passphrase here")
        self.assertTrue(verify_password("a long passphrase here", encoded))
        self.assertFalse(verify_password("wrong", encoded))
        self.assertFalse(verify_password("x", "garbage"))

    def test_redaction(self):
        for secret in ("password=hunter2", "token: abcdef123456", "Authorization: Bearer abcdefghijklmnop", "card 4111 1111 1111 1111",
                       "cred bga_abcdefghijklmnopqrstuv"):
            self.assertNotIn(secret.split()[-1].split("=")[-1], redact(secret), secret)
        self.assertEqual(redact("order 1234 5678 9012 3456"), "order 1234 5678 9012 3456")  # fails Luhn, untouched

    def test_rate_limiter(self):
        limiter = RateLimiter(60, 3)
        self.assertEqual([limiter.allow("k") for _ in range(4)], [True, True, True, False])
        self.assertTrue(limiter.allow("other"))

    def test_audit_chain_detects_tampering(self):
        with tempfile.TemporaryDirectory() as d:
            app = make_app(d)
            for i in range(3):
                app.audit.record("test.action", detail={"i": i})
            self.assertTrue(app.audit.verify()["valid"])
            with app.db.tx() as conn:
                conn.execute("UPDATE audit_log SET detail = '{\"i\": 99}' WHERE action = 'test.action' AND id = (SELECT MIN(id) FROM audit_log WHERE action='test.action')")
            result = app.audit.verify()
            self.assertFalse(result["valid"])
            app.db.close()

    def test_retention_keeps_open_incident_evidence(self):
        with tempfile.TemporaryDirectory() as d:
            app = make_app(d)
            old = [ev(minutes=60 * 24 * 40 - i * 0.5) for i in range(5)] + [ev("service_error", minutes=60 * 24 * 40)]
            app.ingest(old, mode="live", trust="verified_agent", source="t", atomic=False)
            app.set_retention({"id": None}, {"events_days": 30})
            result = app.apply_retention()
            self.assertEqual(result["events_removed"], 1)  # the unlinked service_error
            self.assertEqual(app.events.count(), 5)  # evidence of the open brute-force incident is kept
            incident = app.incidents.list()[0]
            app.incidents.set_status(incident["id"], "resolved", {"id": None, "name": "t"})
            self.assertEqual(app.apply_retention()["events_removed"], 5)
            self.assertTrue(app.audit.verify()["valid"])
            app.db.close()

    def test_restore_cli_round_trip(self):
        import start
        with tempfile.TemporaryDirectory() as d:
            app = make_app(d)
            app.ingest([ev("service_error")], mode="live", trust="verified_agent", source="t")
            backup = app.backup(label="manual")
            app.ingest([ev("service_error", message="after backup")], mode="live", trust="verified_agent", source="t")
            app.db.close()
            settings = Settings(data_dir=Path(d), db_path=Path(d) / "test.sqlite3")

            class Args:
                file = str(backup)
                yes = True
            start.cmd_restore(settings, Args)
            restored = make_app(d)
            self.assertEqual(restored.events.count(), 1)
            self.assertTrue((Path(d) / "test.sqlite3.before-restore").exists())
            restored.db.close()


if __name__ == "__main__":
    unittest.main()
