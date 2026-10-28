"""24/7 reliability: outage classification, server downtime, graceful shutdown, backups, chaos delivery."""

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from datetime import timedelta
from pathlib import Path

from helpers import ROOT, TestServer, ev, free_port, make_app
from guard.config import Settings
from guard.platform import App
from bgagent.client import Client
from bgagent.identity import State, fingerprint
from bgagent.runner import Runner
from bgagent.sources import JsonlSource
from bgagent.spool import Spool
from guard.db import iso, utcnow
from guard.platform import verify_backup


def backdate_contact(app, agent_id, minutes):
    with app.db.tx() as conn:
        conn.execute("UPDATE agents SET last_contact_at = ? WHERE id = ?", (iso(utcnow() - timedelta(minutes=minutes)), agent_id))


class OutageClassificationTests(unittest.TestCase):
    """Agent offline vs. monitored device shut down vs. server/network unavailable."""

    def setUp(self):
        self.srv = TestServer()
        self.admin = self.srv.admin()
        self.agent = self.srv.agent(self.admin)
        self.app = self.srv.app

    def tearDown(self):
        self.srv.close()

    def go_offline(self, minutes=10):
        backdate_contact(self.app, self.agent.agent_id, minutes)
        self.app.ingest_notices(self.app.agents.offline_sweep(utcnow() - timedelta(hours=1)))

    def outage_incident(self):
        found = [i for i in self.admin.get("/api/v1/incidents?status=active")["incidents"] if i["rule_id"] == "BG-HEALTH-01"]
        self.assertEqual(len(found), 1)
        return self.admin.get(f"/api/v1/incidents/{found[0]['id']}")

    def recovery(self, detail):
        notes = [e for e in detail["evidence"] if e["details"].get("kind") == "agent_recovered"]
        self.assertEqual(len(notes), 1, "the recovery notice joins the open outage incident")
        return notes[0]

    def test_device_restart_detected_from_boot_time(self):
        self.agent.heartbeat(boot_time="2026-10-27T08:00:00+00:00")
        self.go_offline()
        self.agent.heartbeat(boot_time="2026-10-28T09:30:00+00:00")
        note = self.recovery(self.outage_incident())
        self.assertEqual(note["details"]["cause"], "device_restarted")
        self.assertIn("boot time changed", note["message"])

    def test_clean_system_shutdown_then_restart(self):
        self.agent.heartbeat(boot_time="2026-10-27T08:00:00+00:00")
        self.agent.heartbeat(boot_time="2026-10-27T08:00:00+00:00", state="stopping", stop_reason="system-shutdown")
        self.go_offline()
        detail = self.outage_incident()
        self.assertIn("clean stop (system-shutdown)", detail["evidence"][0]["message"])
        self.agent.heartbeat(boot_time="2026-10-28T09:30:00+00:00")
        note = self.recovery(self.outage_incident())
        self.assertEqual(note["details"]["cause"], "device_restarted")
        self.assertIn("clean system shutdown", note["message"])

    def test_agent_stopped_while_device_kept_running(self):
        self.agent.heartbeat(boot_time="2026-10-27T08:00:00+00:00")
        self.agent.heartbeat(boot_time="2026-10-27T08:00:00+00:00", state="stopping", stop_reason="agent-stopped")
        self.go_offline()
        self.agent.heartbeat(boot_time="2026-10-27T08:00:00+00:00")
        note = self.recovery(self.outage_incident())
        self.assertEqual(note["details"]["cause"], "agent_stopped")
        self.assertIn("device kept running", note["message"])
        self.assertIn("hide activity", note["message"])

    def test_server_or_network_unreachable(self):
        self.agent.heartbeat(boot_time="2026-10-27T08:00:00+00:00")
        self.go_offline()
        self.agent.heartbeat(boot_time="2026-10-27T08:00:00+00:00", server_unreachable_since=iso(utcnow() - timedelta(minutes=9)),
                             spool_depth=42)
        note = self.recovery(self.outage_incident())
        self.assertEqual(note["details"]["cause"], "server_unreachable")
        self.assertIn("42 events were buffered", note["message"])

    def test_unexplained_interruption_is_labelled_uncertain(self):
        self.go_offline()
        self.agent.heartbeat()
        note = self.recovery(self.outage_incident())
        self.assertEqual(note["details"]["cause"], "unexplained")
        self.assertIn("boot-time data unavailable", note["message"])

    def test_recovery_never_opens_a_new_incident(self):
        self.go_offline()
        incident = self.outage_incident()
        self.admin.post(f"/api/v1/incidents/{incident['id']}/status", {"status": "resolved", "note": "laptop was off"})
        self.agent.heartbeat()
        active = [i for i in self.admin.get("/api/v1/incidents?status=active")["incidents"] if i["rule_id"] == "BG-HEALTH-01"]
        self.assertEqual(active, [])

    def test_server_restart_grace_prevents_false_offline_alerts(self):
        backdate_contact(self.app, self.agent.agent_id, 60)  # silent because the *server* was down for an hour
        self.assertEqual(self.app.agents.offline_sweep(server_started_at=utcnow()), [])
        self.assertEqual(self.app.agents.offline_sweep(server_started_at=utcnow() - timedelta(minutes=2)), [])
        self.assertEqual(len(self.app.agents.offline_sweep(server_started_at=utcnow() - timedelta(minutes=5))), 1)


class ServerLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.dir)

    def test_downtime_recorded_once_and_classified(self):
        app = make_app(self.dir)
        app.startup()
        app.stop(clean=True)
        app = make_app(self.dir)
        app.db.set_setting("server_alive_at", iso(utcnow() - timedelta(minutes=45)))
        app.startup()
        down = app.db.get_setting("last_server_downtime")
        self.assertTrue(down["clean"])
        self.assertEqual(down["minutes"], 45)
        notice = app.events.search(q="was not running")["events"][0]
        self.assertEqual((notice["trust"], notice["details"]["kind"]), ("server", "server_downtime"))
        self.assertEqual(app.incidents.list(), [])  # a server outage is recorded, not raised as a security incident
        # Unclean: the process died without stop(); the next start says so.
        app.db.set_setting("server_alive_at", iso(utcnow() - timedelta(minutes=10)))
        app.startup()
        self.assertFalse(app.db.get_setting("last_server_downtime")["clean"])
        app.db.close()

    def test_backup_verification_and_health_warnings(self):
        app = make_app(self.dir)
        self.assertEqual(app.health_warnings(), [])
        app.started_at = utcnow() - timedelta(hours=30)
        self.assertIn("No backup", app.health_warnings()[0]["message"])
        path = app.backup()
        self.assertTrue(app.db.get_setting("last_backup")["verified"])
        self.assertTrue(verify_backup(path)["verified"])
        self.assertEqual(app.health_warnings(), [])
        bad = self.dir / "broken.sqlite3"
        bad.write_bytes(b"SQLite format 3\x00" + b"\x00" * 200)
        self.assertFalse(verify_backup(bad)["verified"])
        app.db.set_setting("last_backup", {"file": "x", "at": iso(utcnow() - timedelta(hours=40)), "verified": True})
        self.assertIn("over 36 hours", app.health_warnings()[0]["message"])
        app.db.set_setting("last_backup", {"file": "x", "at": iso(), "verified": False})
        self.assertEqual(app.health_warnings()[0]["level"], "critical")
        app.db.close()

    def test_env_file_loading(self):
        import start
        env = self.dir / ".env"
        env.write_text('# comment\nBLACKGUARD_PORT="9123"\nexport BLACKGUARD_SEED_DEMO=0\nPATH=/evil\nBLACKGUARD_HOST=10.0.0.1\n')
        saved = dict(os.environ)
        try:
            os.environ["BLACKGUARD_HOST"] = "127.0.0.1"
            os.environ.pop("BLACKGUARD_PORT", None)
            os.environ.pop("BLACKGUARD_SEED_DEMO", None)
            self.assertEqual(start.load_env_file(env), 2)
            self.assertEqual((os.environ["BLACKGUARD_PORT"], os.environ["BLACKGUARD_SEED_DEMO"]), ("9123", "0"))
            self.assertEqual(os.environ["BLACKGUARD_HOST"], "127.0.0.1")  # existing variables win
            self.assertEqual(os.environ["PATH"], saved["PATH"])          # only BLACKGUARD_* keys are read
        finally:
            os.environ.clear()
            os.environ.update(saved)

    def test_real_process_graceful_shutdown_and_unclean_restart(self):
        port = free_port()
        env = dict(os.environ, BLACKGUARD_DATA_DIR=str(self.dir), BLACKGUARD_PORT=str(port), BLACKGUARD_SEED_DEMO="0",
                   BLACKGUARD_LOG_FILE="")

        def start_server():
            proc = subprocess.Popen([sys.executable, "start.py"], cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for _ in range(100):
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1) as resp:
                        self.assertEqual(json.load(resp), {"status": "ok"})
                        return proc
                except OSError:
                    time.sleep(0.1)
            proc.kill()
            self.fail("server did not start: " + proc.communicate()[0])

        proc = start_server()
        # The Windows-friendly path: `start.py stop` (no signals involved).
        subprocess.run([sys.executable, "start.py", "stop"], cwd=ROOT, env=env, check=True, capture_output=True)
        out = proc.communicate(timeout=30)[0]
        self.assertEqual(proc.returncode, 0, out)
        self.assertIn("stopped cleanly", out)
        self.assertFalse((self.dir / "shutdown.request").exists())
        app = real_app(self.dir)
        self.assertTrue(app.db.get_setting("server_clean_stop"))
        app.db.close()

        proc = start_server()
        proc.kill()  # unclean: no shutdown hook runs
        proc.communicate(timeout=10)
        app = real_app(self.dir)
        self.assertFalse(app.db.get_setting("server_clean_stop"))
        app.db.set_setting("server_alive_at", iso(utcnow() - timedelta(minutes=5)))
        app.db.close()
        proc = start_server()
        proc.send_signal(signal.SIGTERM)  # the Linux/systemd/Docker path
        out = proc.communicate(timeout=30)[0]
        self.assertIn("stopped cleanly", out)
        app = real_app(self.dir)
        self.assertFalse(app.db.get_setting("last_server_downtime")["clean"])
        app.db.close()


def real_app(directory):
    """Open the database the real server process uses (data_dir/blackguard.sqlite3)."""
    return App(Settings(data_dir=Path(directory), db_path=Path(directory) / "blackguard.sqlite3", seed_demo=False))


class ChaosDeliveryTests(unittest.TestCase):
    """Server restarts and dropped acknowledgements during delivery: every event arrives exactly once."""

    def test_exactly_once_across_server_restarts_and_lost_acks(self):
        from guard.server import Server
        from bgagent.cli import main as agent_main
        data_dir, work = Path(tempfile.mkdtemp()), Path(tempfile.mkdtemp())
        port = free_port()
        holder = {}

        def up():
            app = make_app(data_dir, port=port)
            original = app.ingest
            calls = {"n": 0}

            def flaky_ingest(*args, **kwargs):
                result = original(*args, **kwargs)
                calls["n"] += 1
                if kwargs.get("trust") == "verified_agent" and calls["n"] % 3 == 0:
                    raise ConnectionResetError("simulated: committed but the response was lost")
                return result
            app.ingest = flaky_ingest
            server = Server(app)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            holder.update(app=app, server=server)
            return app

        def down():
            holder["server"].shutdown()
            holder["server"].server_close()
            holder["app"].db.close()

        try:
            app = up()
            code = app.auth.ensure_setup_code()
            app.auth.complete_setup(code, "owner", "correct horse battery staple")
            invite = app.agents.create_invite("Chaos", {"id": 1, "name": "owner"})
            state_dir = work / "agent"
            agent_main(["--state-dir", str(state_dir), "enroll", "--server", f"http://127.0.0.1:{port}", "--code", invite["code"]])
            fp, _ = fingerprint(state_dir)
            agent_id = State(state_dir).load()["agent_id"]
            app.agents.approve(agent_id, {"id": 1, "name": "owner"}, fp[:8])
            log = work / "events.jsonl"
            log.write_text("")
            spool = Spool(state_dir / "spool.sqlite3")
            runner = Runner(Client(f"http://127.0.0.1:{port}", State(state_dir).load()["credential"], timeout=5), State(state_dir), spool,
                            [JsonlSource(str(log), spool, from_start=True)], fp, interval=0, batch_size=25)
            total = 0
            for round_number in range(6):
                with log.open("a") as f:
                    for i in range(60):
                        f.write(json.dumps(ev("service_error", host="chaos", message=f"round {round_number} event {i}",
                                              uid=f"r{round_number}-{i}")) + "\n")
                total += 60
                runner.next_delivery = 0
                runner.run_once()
                if round_number % 2 == 0:
                    down()  # server stops between rounds; the agent keeps collecting
                    with log.open("a") as f:
                        for i in range(15):
                            f.write(json.dumps(ev("service_error", host="chaos", message=f"offline {round_number}-{i}",
                                                  uid=f"o{round_number}-{i}")) + "\n")
                    total += 15
                    runner.next_delivery = 0
                    runner.run_once()
                    self.assertIsNotNone(runner.server_unreachable_since)
                    up()
            for _ in range(30):  # drain the spool through remaining dropped acknowledgements
                runner.next_delivery = 0
                runner.run_once()
                if spool.stats()["spool_depth"] == 0:
                    break
            self.assertEqual(spool.stats()["spool_depth"], 0)
            self.assertEqual(spool.stats()["dropped_total"], 0)
            stored = holder["app"].db.scalar("SELECT COUNT(*) FROM events WHERE host='chaos'")
            distinct = holder["app"].db.scalar("SELECT COUNT(DISTINCT message) FROM events WHERE host='chaos'")
            self.assertEqual((stored, distinct), (total, total))
            spool.close()
        finally:
            down()
            shutil.rmtree(data_dir)
            shutil.rmtree(work)


if __name__ == "__main__":
    unittest.main()
