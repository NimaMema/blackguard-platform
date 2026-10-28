"""The public demo must be honest: synthetic, labelled, credential-free, and produced by the real engine."""

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from helpers import ROOT, make_app


class ShowcaseDemoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.out = tempfile.TemporaryDirectory()
        env = dict(os.environ, BLACKGUARD_SHOWCASE_OUT=cls.out.name)
        subprocess.run([sys.executable, "scripts/build_showcase.py"], cwd=ROOT, env=env, check=True, capture_output=True)
        text = (Path(cls.out.name) / "demo-data.js").read_text()
        cls.raw = text
        cls.routes = json.loads(text[text.index("=") + 1:].rstrip().rstrip(";"))["routes"]

    @classmethod
    def tearDownClass(cls):
        cls.out.cleanup()

    def test_everything_is_labelled_synthetic(self):
        self.assertTrue(self.routes["events"])
        self.assertEqual({e["mode"] for e in self.routes["events"]}, {"demo"})
        self.assertEqual({i["mode"] for i in self.routes["/api/v1/incidents"]["incidents"]}, {"demo"})
        self.assertEqual(self.routes["/api/v1/overview"]["stats"]["dataset_label"], "DEMO DATA")
        html = (Path(self.out.name) / "index.html").read_text()
        self.assertIn("INTERACTIVE DEMO", html)
        self.assertIn("connect-src 'none'", html)  # the demo cannot talk to any backend

    def test_no_real_addresses_or_credentials(self):
        for ip in set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", self.raw)):
            self.assertTrue(ip.startswith(("192.0.2.", "198.51.100.", "203.0.113.", "192.168.50.", "127.0.0.1")), ip)
        for marker in ("bga_", "bgs_", "credential_hash", "password_hash", "demo-not-a-credential"):
            self.assertNotIn(marker, self.raw)

    def test_detections_come_from_the_real_rules(self):
        rules = {i["rule_id"] for i in self.routes["/api/v1/incidents"]["incidents"]}
        for expected in ("BG-AUTH-01", "BG-AUTH-02", "BG-AUTH-03", "BG-IAM-01", "BG-IAM-02", "BG-NET-02", "BG-DEV-01", "BG-HEALTH-01"):
            self.assertIn(expected, rules)
        critical = [d for d in self.routes["incident_detail"].values() if d["rule_id"] == "BG-AUTH-02"][0]
        self.assertTrue(critical["evidence"])
        self.assertIn("fictional demo data", critical["confidence_reason"])

    def test_overview_reports_setup_state_for_onboarding(self):
        with tempfile.TemporaryDirectory() as d:
            app = make_app(d)
            setup = app.overview()["setup"]
            self.assertEqual(setup, {"tls": False, "backup_verified": False})
            app.backup()
            self.assertTrue(app.overview()["setup"]["backup_verified"])
            app.db.close()


if __name__ == "__main__":
    unittest.main()
