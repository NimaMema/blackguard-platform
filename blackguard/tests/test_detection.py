"""Detection engine tests: every rule, idempotency, resolution semantics, confidence and realistic datasets."""

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from helpers import ev, make_app
from bgagent.parsers import parse_auth_line, parse_syslog

FIXTURES = Path(__file__).parent / "fixtures"


def render(template, fmt="syslog"):
    """Render OFFSET|line fixtures with timestamps relative to now (local timezone UTC for determinism)."""
    now = datetime.now(timezone.utc)
    for raw in (FIXTURES / template).read_text().splitlines():
        if not raw or raw.startswith("#"):
            continue
        offset, line = raw.split("|", 1)
        when = now - timedelta(seconds=int(offset))
        if fmt == "syslog":
            yield when, f"{when.strftime('%b')} {when.day:2d} {when.strftime('%H:%M:%S')} {line}"
        else:
            yield when, line.replace("Oct 27 10:00:00", f"{when.strftime('%b')} {when.day:2d} {when.strftime('%H:%M:%S')}") \
                            .replace("2026-10-27T10:00:00Z", when.strftime("%Y-%m-%dT%H:%M:%SZ"))


class DetectionTestCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.app = make_app(self.temp.name)

    def tearDown(self):
        self.app.db.close()
        self.temp.cleanup()

    def ingest(self, events, mode="live", trust="verified_agent", source="test"):
        return self.app.ingest(events, mode=mode, trust=trust, source=source, agent_id="agt_test", atomic=False)

    def active(self, rule=None):
        return [i for i in self.app.incidents.list(status="active") if rule is None or i["rule_id"] == rule]


class RuleTests(DetectionTestCase):
    def test_brute_force_threshold_and_window(self):
        self.ingest([ev(minutes=9 - i) for i in range(4)])
        self.assertEqual(self.active("BG-AUTH-01"), [])
        self.ingest([ev(minutes=4)])
        incidents = self.active("BG-AUTH-01")
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["event_count"], 5)

    def test_failures_spread_out_do_not_alert(self):
        self.ingest([ev(minutes=120 - i * 15) for i in range(6)])
        self.assertEqual(self.active("BG-AUTH-01"), [])

    def test_failures_without_ip_group_by_account(self):
        self.ingest([ev(ip="", actor="alex", minutes=5 - i * 0.5) for i in range(5)])
        incident = self.active("BG-AUTH-01")[0]
        self.assertIn("grouped by account", incident["confidence_reason"])

    def test_success_after_failures_is_critical(self):
        self.ingest([ev(minutes=9 - i) for i in range(3)] + [ev("auth_success", minutes=3)])
        incident = self.active("BG-AUTH-02")[0]
        self.assertEqual(incident["severity"], "critical")
        self.assertEqual(incident["event_count"], 4)

    def test_password_spray(self):
        self.ingest([ev(actor=f"user{i}", host=f"h{i % 2}", minutes=10 - i) for i in range(4)])
        self.assertEqual(len(self.active("BG-AUTH-03")), 1)

    def test_cross_device_correlation(self):
        self.ingest([ev(host="nas", minutes=5), ev(host="laptop", minutes=4), ev(host="router", minutes=3)])
        corr = self.active("BG-CORR-01")
        self.assertTrue(corr)
        self.assertEqual(sorted(corr[0]["affected_hosts"]), ["laptop", "nas", "router"])

    def test_privileged_group_only(self):
        self.ingest([ev("group_membership_change", actor="root", target="bob", details={"group": "video"})])
        self.assertEqual(self.active("BG-IAM-01"), [])
        self.ingest([ev("group_membership_change", actor="root", target="bob", details={"group": "sudo"})])
        self.assertEqual(len(self.active("BG-IAM-01")), 1)

    def test_single_event_rules(self):
        for kind, rule in (("account_created", "BG-IAM-02"), ("policy_change", "BG-CFG-01"), ("audit_log_cleared", "BG-CFG-02"),
                           ("service_installed", "BG-SVC-01"), ("account_locked", "BG-AUTH-04"), ("config_change", "BG-CFG-03")):
            self.ingest([ev(kind, host=f"host-{kind}")])
            self.assertEqual(len(self.active(rule)), 1, rule)

    def test_self_password_change_is_not_flagged(self):
        self.ingest([ev("password_reset", actor="alex", target="alex"), ev("password_reset", actor="unknown", target="alex", host="b")])
        self.assertEqual(self.active("BG-IAM-03"), [])
        self.ingest([ev("password_reset", actor="admin", target="alex", host="c")])
        self.assertEqual(len(self.active("BG-IAM-03")), 1)

    def test_firewall_burst_and_port_scan(self):
        self.ingest([ev("network_block", ip="198.51.100.9", minutes=3, dest_port=1000 + i) for i in range(12)])
        self.assertEqual(self.active("BG-NET-01"), [])  # below the 20-denial default
        scan = self.active("BG-NET-02")
        self.assertEqual(len(scan), 1)
        self.assertEqual(scan[0]["confidence"], "medium")
        self.ingest([ev("network_block", ip="192.168.1.77", minutes=2, dest_port=2000 + i) for i in range(10)])
        internal = [i for i in self.active("BG-NET-02") if i["source_ip"] == "192.168.1.77"][0]
        self.assertEqual(internal["confidence"], "high")
        self.ingest([ev("network_block", ip="198.51.100.10", minutes=2, dest_port=80) for _ in range(20)])
        self.assertEqual(len(self.active("BG-NET-01")), 1)

    def test_new_source_requires_history(self):
        base = [ev("auth_success", ip="192.168.1.20", actor="alex", minutes=60 * 24 * d) for d in range(1, 12)]
        self.ingest(base)
        self.ingest([ev("auth_success", ip="203.0.113.77", actor="alex", minutes=1)])
        self.assertEqual(len(self.active("BG-AUTH-05")), 1)
        fresh = make_app(Path(self.temp.name) / "other")
        fresh.ingest([ev("auth_success", ip="203.0.113.77", actor="alex")], mode="live", trust="verified_agent", source="t")
        self.assertEqual([i for i in fresh.incidents.list() if i["rule_id"] == "BG-AUTH-05"], [])
        fresh.db.close()


class EngineSemanticsTests(DetectionTestCase):
    def test_sweeps_are_idempotent(self):
        self.ingest([ev(minutes=5 - i * 0.5) for i in range(6)] + [ev("policy_change")])
        before = [(i["id"], i["event_count"]) for i in self.app.incidents.list()]
        for _ in range(3):
            result = self.app.detector.run()
            self.assertEqual(result, {"created": [], "updated": []})
        self.assertEqual(before, [(i["id"], i["event_count"]) for i in self.app.incidents.list()])

    def test_new_evidence_joins_open_incident(self):
        self.ingest([ev(minutes=8 - i * 0.5) for i in range(5)])
        self.ingest([ev(minutes=3), ev(minutes=2)])
        incidents = self.active("BG-AUTH-01")
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["event_count"], 7)

    def test_resolved_incident_is_not_silently_reused(self):
        self.ingest([ev(minutes=8 - i * 0.5) for i in range(5)])
        first = self.active("BG-AUTH-01")[0]
        self.app.incidents.set_status(first["id"], "resolved", {"id": None, "name": "test"}, "benign")
        self.ingest([ev(minutes=3)])
        incidents = [i for i in self.app.incidents.list() if i["rule_id"] == "BG-AUTH-01"]
        self.assertEqual(len(incidents), 2)
        self.assertEqual(self.app.incidents.get(first["id"])["status"], "resolved")
        self.assertEqual(self.app.incidents.get(first["id"])["event_count"], 5)

    def test_confidence_reflects_provenance(self):
        self.app.ingest([ev(minutes=5 - i * 0.5) for i in range(5)], mode="imported", trust="manual_import", source="import")
        incident = self.active("BG-AUTH-01")[0]
        self.assertEqual(incident["confidence"], "low")
        self.assertIn("imported manually", incident["confidence_reason"])
        self.assertEqual(incident["mode"], "imported")
        self.app.ingest([ev("policy_change", host="demo")], mode="demo", trust="demo", source="demo")
        self.assertEqual(self.active("BG-CFG-01")[0]["mode"], "demo")

    def test_rule_settings_validation_disable_and_tuning(self):
        actor = {"id": None, "name": "t"}
        with self.assertRaises(ValueError):
            self.app.detector.update_rule("BG-AUTH-01", actor, params={"threshold": 0})
        with self.assertRaises(ValueError):
            self.app.detector.update_rule("BG-AUTH-01", actor, params={"bogus": 3})
        with self.assertRaises(LookupError):
            self.app.detector.update_rule("BG-NOPE", actor, enabled=False)
        self.app.detector.update_rule("BG-AUTH-01", actor, params={"threshold": 3}, severity="medium")
        self.ingest([ev(minutes=3 - i * 0.5) for i in range(3)])
        incident = self.active("BG-AUTH-01")[0]
        self.assertEqual(incident["severity"], "medium")
        self.app.detector.update_rule("BG-CFG-01", actor, enabled=False)
        self.ingest([ev("policy_change")])
        self.assertEqual(self.active("BG-CFG-01"), [])
        self.assertTrue(any(a["action"] == "rule.update" for a in self.app.audit.list()))


class RealisticDatasetTests(DetectionTestCase):
    def parse_auth(self, template):
        events = []
        for index, (_, line) in enumerate(render(template)):
            event = parse_auth_line(line, "homeserver", local_tz=timezone.utc)
            if event:
                event["uid"] = f"{template}:{index}"
                events.append(event)
        return events

    def test_ssh_attack_dataset(self):
        events = self.parse_auth("auth_attack.log.tmpl")
        types = {e["type"] for e in events}
        self.assertTrue({"auth_failure", "auth_success", "account_created", "group_membership_change", "privilege_use"} <= types)
        # 30 brute-force + 6 spray + 4 targeted failures; pam_unix and "Invalid user" duplicates are not counted
        self.assertEqual(sum(e["type"] == "auth_failure" for e in events), 40)
        self.ingest(events)
        rules = {i["rule_id"] for i in self.active()}
        for expected in ("BG-AUTH-01", "BG-AUTH-02", "BG-AUTH-03", "BG-IAM-01", "BG-IAM-02"):
            self.assertIn(expected, rules)
        success = self.active("BG-AUTH-02")[0]
        self.assertIn("deploy", success["summary"])
        detail = self.app.incidents.detail(success["id"], [])
        self.assertIn("deploy", detail["accounts"])  # earlier brute-force failures from the same IP are evidence too
        self.assertTrue(detail["timeline"])
        # Redelivery of the same dataset (agent retry) creates nothing new.
        again = self.ingest(events)
        self.assertEqual(again["accepted"], [])
        self.assertEqual(again["duplicates"], len(events))

    def test_benign_dataset_raises_nothing_significant(self):
        self.ingest(self.parse_auth("auth_benign.log.tmpl"))
        significant = [i for i in self.active() if i["severity"] in ("medium", "high", "critical")]
        self.assertEqual(significant, [], [i["title"] for i in significant])

    def test_router_dataset(self):
        events = []
        for index, (_, line) in enumerate(render("router_syslog.tmpl", fmt="router")):
            event = parse_syslog(line.encode(), "192.168.1.1", "Home router")
            if event:
                event["uid"] = f"router:{index}"
                events.append(event)
        kinds = [e["type"] for e in events]
        self.assertEqual(kinds.count("network_block"), 17)
        self.assertEqual(kinds.count("dhcp_lease"), 2)
        self.assertNotIn(None, kinds)
        self.ingest(events)
        rules = {i["rule_id"] for i in self.active()}
        self.assertIn("BG-NET-02", rules)       # 16-port scan from 198.51.100.200
        self.assertIn("BG-AUTH-01", rules)      # dropbear failures from an internal address
        self.assertIn("BG-CFG-03", rules)       # MikroTik firewall rule changed


if __name__ == "__main__":
    unittest.main()
