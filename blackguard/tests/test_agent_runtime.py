"""Agent reliability: durable spool, cursors, rotation, reconnect/backoff, restart recovery, TLS pinning."""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from helpers import TestServer, ev
from bgagent.cli import main as agent_main
from bgagent.client import ApiError, Client, validate_server_url
from bgagent.identity import State, fingerprint
from bgagent.runner import Runner
from bgagent.sources import FileTail, JsonlSource, LinuxAuthSource
from bgagent.spool import Spool


class SpoolAndTailTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.dir)

    def test_spool_is_atomic_with_cursor_and_bounded(self):
        spool = Spool(self.dir / "s.db", max_events=1000)
        spool.put("src", [{"uid": f"u{i}"} for i in range(5)], {"offset": 5})
        spool.put("src", [{"uid": "u1"}], {"offset": 6})  # duplicate uid is ignored
        self.assertEqual(spool.stats()["spool_depth"], 5)
        self.assertEqual(spool.cursor("src"), {"offset": 6})
        spool.put("src", [{"uid": f"x{i}"} for i in range(1200)])
        stats = spool.stats()
        self.assertEqual(stats["spool_depth"], 1000)
        self.assertEqual(stats["dropped_total"], 205)
        source, batch = spool.batch(10)
        spool.ack([i for i, _ in batch[:5]])
        spool.reject([i for i, _ in batch[5:]])
        self.assertEqual(spool.stats()["rejected_total"], 5)
        spool.close()
        reopened = Spool(self.dir / "s.db", max_events=1000)
        self.assertEqual(reopened.stats()["spool_depth"], 990)
        reopened.close()

    def test_file_tail_partial_lines_rotation_and_truncation(self):
        log = self.dir / "a.log"
        log.write_text("one\ntwo\nthr")
        tail = FileTail(str(log), None, from_start=True)
        lines, cursor = tail.read()
        self.assertEqual([l for _, l in lines], ["one", "two"])
        with log.open("a") as f:
            f.write("ee\n")
        self.assertEqual([l for _, l in tail.read()[0]], ["three"])
        resumed = FileTail(str(log), tail.cursor())
        self.assertEqual(resumed.read()[0], [])
        os.rename(log, self.dir / "a.log.1")
        log.write_text("fresh\n")
        self.assertEqual([l for _, l in resumed.read()[0]], ["fresh"])
        log.write_text("")  # truncation
        with log.open("a") as f:
            f.write("after-truncate\n")
        self.assertEqual([l for _, l in resumed.read()[0]], ["after-truncate"])

    def test_default_starts_at_end_of_file(self):
        log = self.dir / "b.log"
        log.write_text("old\n")
        tail = FileTail(str(log), None)
        self.assertEqual(tail.read()[0], [])

    def test_linux_auth_source_spools_with_cursor(self):
        log = self.dir / "auth.log"
        log.write_text("Oct 28 11:00:00 h sshd[1]: Failed password for root from 192.0.2.4 port 1 ssh2\nOct 28 11:00:01 h systemd[1]: noise\n")
        spool = Spool(self.dir / "s.db")
        source = LinuxAuthSource(str(log), spool, "h", from_start=True)
        self.assertEqual(source.poll(spool), 1)
        self.assertEqual(spool.cursor(source.name)["offset"], log.stat().st_size)
        self.assertEqual(LinuxAuthSource(str(log), spool, "h").poll(spool), 0)  # restart: nothing re-read
        spool.close()

    def test_transport_policy(self):
        self.assertEqual(validate_server_url("http://127.0.0.1:8000/"), "http://127.0.0.1:8000")
        self.assertEqual(validate_server_url("https://blackguard.lan:8443"), "https://blackguard.lan:8443")
        for bad in ("http://192.168.1.12:8000", "ftp://x", "file:///etc/passwd"):
            with self.assertRaises(ValueError):
                validate_server_url(bad)

    def test_state_file_is_private_and_fingerprint_stable(self):
        state = State(self.dir / "st")
        state.save({"credential": "bga_x"})
        if os.name != "nt":
            self.assertEqual(state.path.stat().st_mode & 0o077, 0)
        self.assertEqual(fingerprint(self.dir / "st"), fingerprint(self.dir / "st"))
        self.assertEqual(len(fingerprint(self.dir / "st")[0]), 64)


class RunnerReliabilityTests(unittest.TestCase):
    def setUp(self):
        self.srv = TestServer()
        self.admin = self.srv.admin()
        self.dir = Path(tempfile.mkdtemp())
        self.state_dir = self.dir / "agent"
        invite = self.admin.post("/api/v1/agents/invites", {"name": "Runner test"}, expect=201)
        agent_main(["--state-dir", str(self.state_dir), "enroll", "--server", self.srv.base, "--code", invite["code"]])
        self.state = State(self.state_dir)
        self.data = self.state.load()
        fp, _ = fingerprint(self.state_dir)
        self.fp = fp
        self.admin.post(f"/api/v1/agents/{self.data['agent_id']}/approve", {"fingerprint_confirmation": fp[:8]})
        self.log = self.dir / "events.jsonl"
        self.log.write_text("")

    def tearDown(self):
        self.srv.close()
        shutil.rmtree(self.dir)

    def runner(self, server=None):
        spool = Spool(self.state_dir / "spool.sqlite3")
        client = Client(server or self.srv.base, self.state.load()["credential"])
        return Runner(client, self.state, spool, [JsonlSource(str(self.log), spool, from_start=True)], self.fp, interval=0.2), spool

    def write(self, start, count):
        with self.log.open("a") as f:
            for i in range(start, start + count):
                f.write(json.dumps(ev("service_error", host="runner", message=f"event {i}", minutes=1)) + "\n")

    def live_count(self):
        return len(self.admin.get("/api/v1/events?mode=live&limit=500")["events"])

    def test_buffering_while_server_down_then_exactly_once_delivery(self):
        self.write(0, 30)
        runner, spool = self.runner(server="http://127.0.0.1:9")  # nothing listens on the discard port
        runner.run_once()
        self.assertEqual(spool.stats()["spool_depth"], 30)
        self.assertIsNotNone(runner.last_error)
        self.assertGreater(runner.next_delivery, 0)
        spool.close()
        # "Restart" the agent pointing at the real server: buffered events are delivered once.
        runner, spool = self.runner()
        self.write(30, 5)
        runner.run_once()
        self.assertEqual(spool.stats()["spool_depth"], 0)
        self.assertEqual(self.live_count(), 35)
        runner.run_once()
        self.assertEqual(self.live_count(), 35)
        spool.close()

    def test_lost_acknowledgement_does_not_duplicate(self):
        self.write(0, 10)
        runner, spool = self.runner()
        runner.collect()
        _, batch = spool.batch(200)
        # Simulate the server receiving the batch but the agent never seeing the reply.
        runner.client.request("POST", "/api/v1/agent/events", {"source": "jsonl", "events": [e for _, e in batch]})
        runner.deliver()
        self.assertEqual(self.live_count(), 10)
        self.assertEqual(spool.stats()["spool_depth"], 0)
        spool.close()

    def test_invalid_events_are_dropped_not_retried_forever(self):
        with self.log.open("a") as f:
            f.write(json.dumps({"type": "nonsense", "host": "x", "message": "bad"}) + "\n")
            f.write("{not json\n")
        self.write(0, 2)
        runner, spool = self.runner()
        runner.run_once()
        stats = spool.stats()
        self.assertEqual((stats["spool_depth"], stats["rejected_total"]), (0, 1))
        self.assertEqual(self.live_count(), 2)
        spool.close()

    def test_heartbeat_health_and_rotation(self):
        runner, spool = self.runner()
        self.admin.post(f"/api/v1/agents/{self.data['agent_id']}/rotate")
        runner.heartbeat()
        new_credential = self.state.load()["credential"]
        self.assertNotEqual(new_credential, self.data["credential"])
        runner.next_heartbeat = 0
        runner.heartbeat()
        agent = [a for a in self.admin.get("/api/v1/agents")["agents"] if a["id"] == self.data["agent_id"]][0]
        self.assertEqual(agent["rotate_requested"], 0)
        self.assertIn("spool_depth", agent["health"])
        self.assertEqual(Client(self.srv.base, self.data["credential"]).request.__self__.credential, self.data["credential"])
        with self.assertRaises(ApiError) as ctx:
            Client(self.srv.base, self.data["credential"]).request("GET", "/api/v1/agent/status")
        self.assertEqual(ctx.exception.status, 401)
        spool.close()

    def test_clean_stop_and_outage_tracking_reach_the_server(self):
        runner, spool = self.runner()
        runner.heartbeat()
        self.assertTrue(runner.boot_time)  # Linux CI and dev hosts expose /proc/stat btime
        self.assertTrue(runner.notify_stopping("agent-stopped"))
        agent = [a for a in self.admin.get("/api/v1/agents")["agents"] if a["id"] == self.data["agent_id"]][0]
        self.assertEqual(agent["health"]["last_stop"]["reason"], "agent-stopped")
        self.assertEqual(agent["health"]["boot_time"], runner.boot_time)
        down, _ = self.runner(server="http://127.0.0.1:9")
        down.next_heartbeat = 0
        down.heartbeat()
        self.assertIsNotNone(down.server_unreachable_since)
        self.assertFalse(down.notify_stopping("agent-stopped"))  # best effort: never blocks shutdown
        spool.close()
        down.spool.close()

    def test_revoked_agent_stops_with_clear_message(self):
        runner, spool = self.runner()
        self.admin.post(f"/api/v1/agents/{self.data['agent_id']}/revoke", {"reason": "test"})
        self.write(0, 1)
        runner.collect()
        with self.assertRaises(SystemExit) as ctx:
            runner.deliver()
        self.assertIn("rejected this agent", str(ctx.exception))
        self.assertEqual(spool.stats()["spool_depth"], 1)  # data is kept locally
        spool.close()


@unittest.skipUnless(shutil.which("openssl"), "openssl not available")
class TlsTests(unittest.TestCase):
    def test_tls_server_with_pinned_private_certificate(self):
        temp = Path(tempfile.mkdtemp())
        cert, key = temp / "c.crt", temp / "c.key"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "2",
                        "-subj", "/CN=test", "-addext", "subjectAltName=IP:127.0.0.1", "-keyout", str(key), "-out", str(cert)],
                       check=True, capture_output=True)
        srv = TestServer(tls_cert=str(cert), tls_key=str(key))
        try:
            self.assertTrue(srv.base.startswith("https://"))
            with self.assertRaises(ApiError) as ctx:
                Client(srv.base).request("GET", "/api/v1/setup/status", auth=False)
            self.assertIn("not trusted", str(ctx.exception))
            status = Client(srv.base, ca_file=str(cert)).request("GET", "/api/v1/setup/status", auth=False)
            self.assertIn("needs_setup", status)
            import ssl
            import urllib.request
            ctx_ssl = ssl.create_default_context(cafile=str(cert))
            with urllib.request.urlopen(srv.base + "/", context=ctx_ssl) as resp:
                self.assertIn("max-age", resp.headers["Strict-Transport-Security"])
            setup = Client(srv.base, ca_file=str(cert))
            import http.cookiejar
            jar = http.cookiejar.CookieJar()
            opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), urllib.request.HTTPSHandler(context=ctx_ssl))
            req = urllib.request.Request(srv.base + "/api/v1/setup", data=json.dumps({"setup_code": srv.setup_code, "username": "owner",
                                         "password": "correct horse battery staple"}).encode(), headers={"Content-Type": "application/json"}, method="POST")
            with opener.open(req) as resp:
                cookie = resp.headers["Set-Cookie"]
            self.assertTrue(cookie.startswith("__Host-bg_session="))
            self.assertIn("Secure", cookie)
            del setup
        finally:
            srv.close()
            shutil.rmtree(temp)


if __name__ == "__main__":
    unittest.main()
