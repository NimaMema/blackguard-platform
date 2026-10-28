"""Agent main loop: collect → spool → deliver, with heartbeats, backoff and rotation."""

import logging
from datetime import datetime, timezone
import random
import time

from bgagent import __version__
from bgagent.client import ApiError
from bgagent.identity import boot_time
from bgagent.sources import neighbour_observations

log = logging.getLogger("bgagent")


def _now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Runner:
    def __init__(self, client, state, spool, sources, fingerprint, interval=2.0, heartbeat_every=30,
                 inventory_every=0, batch_size=200):
        self.client = client
        self.state = state
        self.spool = spool
        self.sources = sources
        self.fingerprint = fingerprint
        self.interval = interval
        self.heartbeat_every = heartbeat_every
        self.inventory_every = inventory_every
        self.batch_size = batch_size
        self.started = time.time()
        self.backoff = 0.0
        self.next_delivery = 0.0
        self.next_heartbeat = 0.0
        self.next_inventory = 0.0
        self.server_status = "unknown"
        self.last_error = None
        self.delivered_total = 0
        self.started_at = _now_iso()
        self.boot_time = boot_time()
        self.server_unreachable_since = None  # set while deliveries/heartbeats fail for transport reasons

    # -- helpers ------------------------------------------------------------
    def _unreachable(self):
        if self.server_unreachable_since is None:
            self.server_unreachable_since = _now_iso()

    def _reachable(self):
        self.server_unreachable_since = None

    def _fail(self, exc):
        self._unreachable()
        self.last_error = str(exc)
        self.backoff = min(300.0, max(2.0, self.backoff * 2))
        delay = self.backoff * (0.8 + random.random() * 0.4)  # nosec B311
        self.next_delivery = time.monotonic() + delay
        log.warning("Server unavailable (%s); retrying in %.0fs. Events stay buffered locally.", exc, delay)

    def _permanent(self, exc):
        self.last_error = str(exc)
        text = str(exc).lower()
        if "revoked" in text or "unknown or revoked" in text or exc.status == 401:
            raise SystemExit(f"Server rejected this agent's credential: {exc}. Re-enroll with a new code if this is unexpected.")
        if "awaiting" in text:
            self.server_status = "pending"
            log.info("Waiting for an administrator to approve this agent (fingerprint %s…).", self.fingerprint[:16])
        elif "suspended" in text:
            self.server_status = "suspended"
            log.error("Agent suspended by the server: %s", exc)
        self.next_delivery = time.monotonic() + 60

    def health(self):
        stats = self.spool.stats()
        stats.update(agent_version=__version__, uptime_seconds=int(time.time() - self.started), last_error=self.last_error,
                     delivered_total=self.delivered_total, sources=[s.health() for s in self.sources],
                     boot_time=self.boot_time, agent_started_at=self.started_at,
                     server_unreachable_since=self.server_unreachable_since)
        return stats

    # -- steps --------------------------------------------------------------
    def collect(self):
        for source in self.sources:
            try:
                source.poll(self.spool)
            except Exception as exc:  # one broken source must not stop the others
                source.last_error = f"{type(exc).__name__}: {exc}"
                log.exception("Source %s failed", source.name)

    def deliver(self):
        if time.monotonic() < self.next_delivery:
            return
        for _ in range(20):
            source, items = self.spool.batch(self.batch_size)
            if not items:
                return
            ids = [i for i, _ in items]
            payload = [e for _, e in items]
            try:
                result = self.client.request("POST", "/api/v1/agent/events", {"source": source.split(":")[0].replace("-", "_")[:32],
                                                                              "events": payload})
            except ApiError as exc:
                if exc.permanent and exc.status != 400:
                    return self._permanent(exc)
                if exc.status == 400:
                    # Whole batch malformed (should not happen); drop it rather than block the queue forever.
                    log.error("Server refused a batch of %d events: %s", len(ids), exc)
                    self.spool.reject(ids)
                    continue
                return self._fail(exc)
            rejected = {r["index"] for r in result.get("rejected", []) if isinstance(r, dict)}
            for r in result.get("rejected", [])[:5]:
                log.warning("Server rejected an event: %s", r.get("error"))
            self.spool.reject([ids[i] for i in rejected if i < len(ids)])
            self.spool.ack([ids[i] for i in range(len(ids)) if i not in rejected])
            self.delivered_total += result.get("accepted", 0)
            self._reachable()
            self.server_status = "active"
            self.backoff = 0.0
            self.last_error = None

    def heartbeat(self):
        if time.monotonic() < self.next_heartbeat:
            return
        self.next_heartbeat = time.monotonic() + self.heartbeat_every
        try:
            reply = self.client.request("POST", "/api/v1/agent/heartbeat",
                                        {"fingerprint": self.fingerprint, "agent_version": __version__, "health": self.health()})
        except ApiError as exc:
            if exc.permanent:
                return self._permanent(exc)
            self._unreachable()
            self.last_error = str(exc)
            return
        self._reachable()
        self.server_status = reply.get("status", "unknown")
        if reply.get("rotate") and self.server_status == "active":
            self.rotate()

    def rotate(self):
        try:
            reply = self.client.request("POST", "/api/v1/agent/rotate", {})
        except ApiError as exc:
            log.warning("Credential rotation failed (will retry): %s", exc)
            return
        data = self.state.load()
        data["previous_credential_rotated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        data["credential"] = reply["credential"]
        self.state.save(data)  # persist before first use so a crash cannot lose it
        self.client.credential = reply["credential"]
        log.info("Credential rotated.")
        self.next_heartbeat = 0

    def inventory(self):
        if not self.inventory_every or time.monotonic() < self.next_inventory or self.server_status != "active":
            return
        self.next_inventory = time.monotonic() + self.inventory_every
        observations = neighbour_observations()
        if not observations:
            return
        try:
            self.client.request("POST", "/api/v1/agent/inventory", {"observations": observations[:1000]})
        except ApiError as exc:
            log.warning("Inventory report failed: %s", exc)

    def run_once(self):
        self.collect()
        self.heartbeat()
        self.deliver()
        self.inventory()

    def notify_stopping(self, reason):
        """Best-effort final heartbeat so the server can tell a deliberate stop from a crash or power loss."""
        health = self.health()
        health.update(state="stopping", stop_reason=reason)
        timeout, self.client.timeout = self.client.timeout, 5
        try:
            self.client.request("POST", "/api/v1/agent/heartbeat",
                                {"fingerprint": self.fingerprint, "agent_version": __version__, "health": health})
            return True
        except ApiError:
            return False
        finally:
            self.client.timeout = timeout

    def run_forever(self, stop=None):
        log.info("BLACKGUARD agent %s running with %d source(s).", __version__, len(self.sources))
        while not (stop and stop.is_set()):
            self.run_once()
            time.sleep(self.interval)
