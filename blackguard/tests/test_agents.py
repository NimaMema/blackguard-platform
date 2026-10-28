"""Agent enrollment, approval, identity binding, rotation, revocation, health and inventory."""

import unittest
from datetime import timedelta

from helpers import TestServer, ev
from guard.db import iso, utcnow


class AgentLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.srv = TestServer()
        self.admin = self.srv.admin()

    def tearDown(self):
        self.srv.close()

    def enroll(self, code, fingerprint="b" * 64):
        return self.srv.client().request("POST", "/api/v1/agent/enroll", {"code": code, "hostname": "laptop", "platform": "Linux",
                                                                         "fingerprint": fingerprint})

    def test_enrollment_requires_valid_single_use_code(self):
        self.assertEqual(self.enroll("AAAA-BBBB-CCCC-DDDD")[0], 403)
        invite = self.admin.post("/api/v1/agents/invites", {"name": "Laptop"}, expect=201)
        status, body = self.enroll(invite["code"].lower().replace("-", " "))  # normalisation is tolerant
        self.assertEqual(status, 201)
        self.assertTrue(body["credential"].startswith("bga_"))
        self.assertEqual(body["status"], "pending")
        self.assertEqual(self.enroll(invite["code"])[0], 403)  # single use
        stored = self.srv.app.db.one("SELECT credential_hash FROM agents WHERE id = ?", (body["agent_id"],))
        self.assertNotIn(body["credential"], str(stored))  # only a hash is stored

    def test_expired_and_revoked_codes(self):
        invite = self.admin.post("/api/v1/agents/invites", {"name": "Old"}, expect=201)
        with self.srv.app.db.tx() as conn:
            conn.execute("UPDATE enrollment_invites SET expires_at = ? WHERE id = ?", (iso(utcnow() - timedelta(minutes=1)), invite["id"]))
        self.assertEqual(self.enroll(invite["code"])[0], 403)
        second = self.admin.post("/api/v1/agents/invites", {"name": "Revoked"}, expect=201)
        self.admin.post(f"/api/v1/agents/invites/{second['id']}/revoke")
        self.assertEqual(self.enroll(second["code"])[0], 403)

    def test_pending_agent_cannot_submit_and_approval_needs_fingerprint(self):
        agent = self.srv.agent(self.admin, approve=False, fingerprint="c" * 64)
        status, body = agent.events([ev()])
        self.assertEqual(status, 403)
        self.assertIn("approval", body["error"])
        self.assertEqual(agent.request("GET", "/api/v1/agent/status")[1]["status"], "pending")
        bad = self.admin.request("POST", f"/api/v1/agents/{agent.agent_id}/approve", {"fingerprint_confirmation": "dddddddd"})
        self.assertEqual(bad[0], 400)
        self.admin.post(f"/api/v1/agents/{agent.agent_id}/approve", {"fingerprint_confirmation": "cccccccc"})
        status, body = agent.events([ev(uid="1")])
        self.assertEqual((status, body["accepted"]), (200, 1))
        device = self.admin.get("/api/v1/devices")["devices"][0]
        self.assertEqual((device["identity_confidence"], device["os_confidence"]), ("verified_agent", "confirmed"))

    def test_identity_comes_from_credential_not_request(self):
        alice = self.srv.agent(self.admin, "Alice PC", "1" * 64)
        bob = self.srv.agent(self.admin, "Bob PC", "2" * 64)
        status, _ = bob.request("POST", "/api/v1/agent/events", {"agent_id": alice.agent_id, "events": [{**ev(), "uid": "x1"}]})
        self.assertEqual(status, 200)
        stored = self.admin.get("/api/v1/events?mode=live")["events"][0]
        self.assertEqual(stored["agent_id"], bob.agent_id)
        self.assertEqual(stored["trust"], "verified_agent")
        self.assertEqual(alice.request("GET", "/api/v1/agent/status", credential="bga_forged")[0], 401)

    def test_agents_cannot_use_dashboard_and_users_cannot_use_agent_api(self):
        agent = self.srv.agent(self.admin)
        status, _ = self.srv.client().request("GET", "/api/v1/overview", headers={"Authorization": f"Bearer {agent.credential}"})
        self.assertEqual(status, 401)
        self.assertEqual(self.admin.request("POST", "/api/v1/agent/events", {"events": [ev()]})[0], 401)

    def test_revocation_is_immediate_and_keeps_data(self):
        agent = self.srv.agent(self.admin)
        agent.events([{**ev(), "uid": "keep"}])
        self.admin.post(f"/api/v1/agents/{agent.agent_id}/revoke", {"reason": "laptop sold"})
        self.assertEqual(agent.events([{**ev(), "uid": "after"}])[0], 401)
        self.assertEqual(len(self.admin.get(f"/api/v1/events?agent_id={agent.agent_id}")["events"]), 1)
        self.assertTrue(any(a["action"] == "agent.revoke" for a in self.srv.app.audit.list()))

    def test_two_phase_credential_rotation(self):
        agent = self.srv.agent(self.admin)
        self.admin.post(f"/api/v1/agents/{agent.agent_id}/rotate")
        status, hb = agent.heartbeat()
        self.assertTrue(hb["rotate"])
        _, rotated = agent.request("POST", "/api/v1/agent/rotate", {})
        old = agent.credential
        # Until the new credential is used, the old one keeps working (a lost response cannot lock the agent out).
        self.assertEqual(agent.request("GET", "/api/v1/agent/status")[0], 200)
        agent.credential = rotated["credential"]
        self.assertEqual(agent.request("GET", "/api/v1/agent/status")[1]["rotate"], False)
        self.assertEqual(agent.request("GET", "/api/v1/agent/status", credential=old)[0], 401)

    def test_fingerprint_change_suspends_agent_and_raises_incident(self):
        agent = self.srv.agent(self.admin, fingerprint="e" * 64)
        status, body = agent.heartbeat(fingerprint="f" * 64)
        self.assertEqual(body["status"], "suspended")
        self.assertEqual(agent.events([{**ev(), "uid": "z"}])[0], 403)
        incidents = self.admin.get("/api/v1/incidents?status=active")["incidents"]
        self.assertTrue(any(i["rule_id"] == "BG-HEALTH-02" for i in incidents))
        self.admin.post(f"/api/v1/agents/{agent.agent_id}/approve", {"fingerprint_confirmation": "ffffffff"})
        self.assertEqual(agent.events([{**ev(), "uid": "z2"}])[0], 200)

    def test_offline_detection_and_data_loss_notice(self):
        agent = self.srv.agent(self.admin)
        agent.heartbeat(dropped_total=0)
        agent.heartbeat(dropped_total=25)
        with self.srv.app.db.tx() as conn:
            conn.execute("UPDATE agents SET last_contact_at = ? WHERE id = ?", (iso(utcnow() - timedelta(minutes=10)), agent.agent_id))
        self.srv.app.ingest_notices(self.srv.app.agents.offline_sweep())
        self.assertEqual(self.srv.app.agents.offline_sweep(), [])  # alerts once per outage
        rules = {i["rule_id"] for i in self.admin.get("/api/v1/incidents?status=active")["incidents"]}
        self.assertIn("BG-HEALTH-01", rules)
        self.assertIn("BG-HEALTH-03", rules)
        self.assertEqual(self.admin.get("/api/v1/agents")["agents"][0]["connection"], "offline")
        agent.heartbeat(dropped_total=25)
        self.assertEqual(self.admin.get("/api/v1/agents")["agents"][0]["connection"], "online")

    def test_partial_rejection_and_deduplication(self):
        agent = self.srv.agent(self.admin)
        batch = [{**ev(), "uid": "a1"}, {"type": "bogus", "host": "x", "message": "y", "uid": "a2"}, {**ev(minutes=2), "uid": "a3"}]
        status, body = agent.events(batch)
        self.assertEqual((body["accepted"], body["duplicates"], [r["index"] for r in body["rejected"]]), (2, 0, [1]))
        status, body = agent.events(batch)
        self.assertEqual((body["accepted"], body["duplicates"]), (0, 2))

    def test_inventory_learning_period_and_new_device_alert(self):
        agent = self.srv.agent(self.admin)
        status, body = agent.request("POST", "/api/v1/agent/inventory", {"observations": [{"source": "arp", "ip": "192.168.1.5", "mac": "aa:bb:cc:00:00:01"}]})
        self.assertEqual((status, body["learning"]), (200, True))
        with self.srv.app.db.tx() as conn:
            conn.execute("UPDATE settings SET value = ? WHERE key = ?", (f'"{iso(utcnow() - timedelta(days=2))}"', f"inventory_learning:{agent.agent_id}"))
        agent.request("POST", "/api/v1/agent/inventory", {"observations": [{"source": "arp", "ip": "192.168.1.6", "mac": "aa:bb:cc:00:00:02"},
                                                                          {"source": "arp", "ip": "192.168.1.5", "mac": "aa:bb:cc:00:00:01"}]})
        incidents = [i for i in self.admin.get("/api/v1/incidents?status=active")["incidents"] if i["rule_id"] == "BG-DEV-01"]
        self.assertEqual(len(incidents), 1)
        devices = self.admin.get("/api/v1/devices")["devices"]
        reported = [d for d in devices if d["mac_address"]]
        self.assertEqual({d["identity_confidence"] for d in reported}, {"reported"})
        self.assertEqual(agent.request("POST", "/api/v1/agent/inventory", {"observations": [{"source": "scan", "ip": "1.1.1.1"}]})[0], 400)

    def test_dhcp_lease_events_feed_inventory(self):
        agent = self.srv.agent(self.admin)
        agent.events([{"type": "dhcp_lease", "host": "router", "message": "lease", "uid": "d1",
                       "details": {"ip": "192.168.1.45", "mac": "3c:22:fb:12:34:56", "hostname": "Kids-Tablet"}}])
        names = [d["display_name"] for d in self.admin.get("/api/v1/devices")["devices"]]
        self.assertIn("Kids-Tablet", names)


if __name__ == "__main__":
    unittest.main()
