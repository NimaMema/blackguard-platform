"""Command-line interface for the BLACKGUARD agent."""

import argparse
import json
import logging
import os
import signal
import sys
import threading
from pathlib import Path

from bgagent import __version__
from bgagent.client import ApiError, Client, validate_server_url
from bgagent.identity import State, fingerprint, host_info, stop_reason
from bgagent.runner import Runner
from bgagent.sources import JournaldSource, JsonlSource, LinuxAuthSource, SyslogSource
from bgagent.spool import Spool

DEFAULT_STATE = os.environ.get("BLACKGUARD_AGENT_STATE", str(Path.home() / ".blackguard-agent"))


def _fingerprint_text(fp):
    return " ".join(fp[i:i + 4] for i in range(0, 32, 4))


def cmd_enroll(args):
    state = State(args.state_dir)
    if state.exists() and not args.force:
        raise SystemExit(f"Already enrolled ({state.path}). Use --force to replace this enrollment.")
    server = validate_server_url(args.server)
    if args.ca_file:
        args.ca_file = str(Path(args.ca_file).resolve(strict=True))
    fp, fp_source = fingerprint(state.dir)
    info = host_info()
    sources = [s.split(":")[0] for s in args.source or []]
    client = Client(server, ca_file=args.ca_file)
    try:
        reply = client.request("POST", "/api/v1/agent/enroll", {
            "code": args.code, "hostname": args.hostname or info["hostname"], "platform": info["platform"],
            "fingerprint": fp, "agent_version": __version__, "sources": sources}, auth=False)
    except ApiError as exc:
        raise SystemExit(f"Enrollment failed: {exc}")
    state.save({"server": server, "ca_file": args.ca_file or "", "agent_id": reply["agent_id"],
                "credential": reply["credential"], "name": reply.get("name", ""), "fingerprint_source": fp_source})
    print(f"Enrolled as {reply['agent_id']} ({reply.get('name', '')}). Credential saved to {state.path} (mode 600).")
    print("\nThis agent is PENDING. In the BLACKGUARD dashboard (Agents), approve it only if the fingerprint matches:")
    print(f"\n    {_fingerprint_text(fp)}\n")
    if fp_source != "machine":
        print("Note: no OS machine ID was found; the fingerprint uses a random install ID stored with the agent state.")


def build_sources(args, spool, hostname):
    sources = []
    for spec in args.source or []:
        kind, _, value = spec.partition(":")
        if kind == "jsonl":
            sources.append(JsonlSource(value, spool, args.from_start))
        elif kind == "linux-auth":
            sources.append(LinuxAuthSource(value or "/var/log/auth.log", spool, hostname, args.from_start))
        elif kind == "journald":
            sources.append(JournaldSource(spool, hostname, args.from_start))
        elif kind == "syslog":
            sources.append(SyslogSource(value, spool, args.device_name or "router"))
        else:
            raise SystemExit(f"Unknown source '{kind}'. Use jsonl:, linux-auth:, journald or syslog:.")
    return sources


def cmd_run(args):
    state = State(args.state_dir)
    data = state.load()
    if not args.source and not args.inventory_arp:
        raise SystemExit("Specify at least one --source (or --inventory-arp).")
    spool = Spool(state.dir / "spool.sqlite3", max_events=args.spool_max)
    fp, _ = fingerprint(state.dir)
    hostname = host_info()["hostname"]
    sources = build_sources(args, spool, hostname)
    client = Client(data["server"], data["credential"], data.get("ca_file", ""))
    runner = Runner(client, state, spool, sources, fp, interval=args.interval,
                    inventory_every=300 if args.inventory_arp else 0)
    if args.once:
        runner.run_once()
        print(json.dumps({"server_status": runner.server_status, **runner.health()}, indent=2))
        return
    stop = threading.Event()
    received = {}

    def on_signal(signum, _frame):
        received["reason"] = stop_reason() if signum == signal.SIGTERM else "agent-stopped"
        stop.set()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, on_signal)
    try:
        runner.run_forever(stop)
    finally:
        if stop.is_set() and runner.server_status == "active":
            runner.notify_stopping(received.get("reason", "agent-stopped"))
        for source in sources:
            if hasattr(source, "close"):
                source.close()
        spool.close()
        logging.getLogger("bgagent").info("Agent stopped; undelivered events remain in the spool.")


def cmd_status(args):
    state = State(args.state_dir)
    data = state.load()
    fp, fp_source = fingerprint(state.dir)
    out = {"agent_id": data["agent_id"], "server": data["server"], "fingerprint": _fingerprint_text(fp),
           "fingerprint_source": fp_source}
    spool_path = state.dir / "spool.sqlite3"
    if spool_path.exists():
        out["spool"] = Spool(spool_path).stats()
    try:
        out["server_view"] = Client(data["server"], data["credential"], data.get("ca_file", "")).request("GET", "/api/v1/agent/status")
    except ApiError as exc:
        out["server_view"] = {"error": str(exc)}
    print(json.dumps(out, indent=2))


def main(argv=None):
    logging.basicConfig(level=os.environ.get("BLACKGUARD_AGENT_LOG", "INFO").upper(),
                        format="%(asctime)s %(levelname)s %(message)s")
    parser = argparse.ArgumentParser(prog="blackguard_agent.py", description=f"BLACKGUARD agent {__version__}")
    parser.add_argument("--state-dir", default=DEFAULT_STATE, help=f"Private state directory (default {DEFAULT_STATE})")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("enroll", help="Enroll with a one-time code from the dashboard")
    p.add_argument("--server", required=True, help="https://your-blackguard-server:8443")
    p.add_argument("--code", required=True, help="One-time enrollment code (Agents → Enroll device)")
    p.add_argument("--ca-file", help="Server certificate to trust (for a private/self-signed certificate)")
    p.add_argument("--hostname", help="Override the reported hostname")
    p.add_argument("--source", action="append", help="Sources you plan to run (informational)")
    p.add_argument("--force", action="store_true")
    p = sub.add_parser("run", help="Collect and deliver events")
    p.add_argument("--source", action="append",
                   help="jsonl:/path/file.jsonl | linux-auth:/var/log/auth.log | journald | syslog:udp://IP:PORT?allow=ROUTER_IP")
    p.add_argument("--device-name", help="Name for the syslog-sending device, e.g. 'Home router'")
    p.add_argument("--from-start", action="store_true", help="On first run, read existing file content (default: new lines only)")
    p.add_argument("--inventory-arp", action="store_true", help="Report this machine's ARP/neighbour cache every 5 minutes (passive)")
    p.add_argument("--interval", type=float, default=2.0)
    p.add_argument("--spool-max", type=int, default=100_000, help="Maximum buffered events before the oldest are dropped")
    p.add_argument("--once", action="store_true", help="Run one collection/delivery pass and exit")
    sub.add_parser("status", help="Show local spool and server-side status")
    sub.add_parser("fingerprint", help="Print this machine's agent fingerprint")
    args = parser.parse_args(argv)
    if args.command == "run" and not (0.2 <= args.interval <= 60 and 1000 <= args.spool_max <= 5_000_000):
        parser.error("--interval must be 0.2–60 and --spool-max 1000–5000000")
    if args.command == "fingerprint":
        fp, source = fingerprint(Path(args.state_dir).expanduser())
        print(f"{_fingerprint_text(fp)}  ({source})")
        return 0
    {"enroll": cmd_enroll, "run": cmd_run, "status": cmd_status}[args.command](args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
