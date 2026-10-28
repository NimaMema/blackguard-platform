# Reliability and delivery guarantees

This document states exactly what BLACKGUARD guarantees, what it detects, and where data can still be lost. Each claim names the test that checks it.

## Delivery model

| Stage | Guarantee | Evidence |
| --- | --- | --- |
| Log file → agent spool | Lines are committed to the SQLite spool **in the same transaction** as the file cursor. A crash or reboot never skips or re-reads a line. | `test_agent_runtime.SpoolAndTailTests` |
| Spool → server | **At-least-once.** Events stay in the spool until the server acknowledges them. Retries use exponential backoff with jitter (2 s → 5 min). | `RunnerReliabilityTests.test_buffering_while_server_down_*` |
| Server storage | **Idempotent.** Every event has a stable UID (agent ID + source position), and duplicates are ignored. | `test_lost_acknowledgement_does_not_duplicate` |
| End to end | At-least-once delivery plus idempotent storage means each spooled event is stored **exactly once**. Checked with 405 events across three server restarts and one dropped acknowledgement in every three batches. | `test_reliability.ChaosDeliveryTests` |

### Where events can still be lost

1. **Spool overflow.** If the server is unreachable long enough for more than `--spool-max` events (default 100,000) to accumulate, the oldest are dropped. This is never silent: the agent counts drops, the server opens a **BG-HEALTH-03 "Collector dropped events"** incident, and the dashboard shows the count.
2. **Log rotation while the agent is stopped.** If a file is rotated *more than once* while the agent is not running, lines in the intermediate file are not read. A single rotation or a copytruncate is handled.
3. **UDP syslog.** Datagrams lost on the network, or sent while the syslog agent is not running, are never seen. UDP has no acknowledgement. Once a datagram is received, it is spooled immediately.
4. **Windows event log overwrite.** If the Security log wraps around (fills up and overwrites itself) while the agent is stopped, overwritten records cannot be read. Increase the Security log's maximum size if your machine is often off.
5. **Disk failure** of the agent or server machine. Use backups (below).

## Outage classification

When an approved agent goes silent longer than its threshold (default 3 minutes), the server opens **BG-HEALTH-01**. When the agent reconnects, a *recovery notice* is added to the same incident with an evidence-based cause:

| Cause | Evidence used | Meaning |
| --- | --- | --- |
| `device_restarted` | The agent-reported **boot time changed** (with a clean system-shutdown report if one was received) | The monitored computer was shut down or rebooted |
| `agent_stopped` | The agent sent a **clean-stop heartbeat** and the boot time did not change | Someone stopped the agent while the device kept running. Confirm it was you: stopping a collector is also a way to hide activity |
| `server_unreachable` | The agent reports **`server_unreachable_since`** (deliveries were failing) and kept buffering | Network path or BLACKGUARD server unavailable; no data lost unless BG-HEALTH-03 fires |
| `unexplained` | None of the above | Crash, forced kill, or power loss. Labelled as uncertain |

A recovery notice never opens an incident on its own. It only joins an open outage incident.

**When the server itself is down**, nothing is wrong with the agents, so the offline check counts silence from the later of an agent's last contact and the server's own start. Every agent gets a full threshold to reconnect before any alert. On restart the server records a *server downtime* event (from/to, clean or unclean) in the event ledger and the audit log, and shows it under System health. It is not raised as a security incident.

Tests: `test_reliability.OutageClassificationTests`, `ServerLifecycleTests`.

## Graceful shutdown

| Platform | How to stop cleanly | What happens |
| --- | --- | --- |
| Linux / systemd / Docker | `SIGTERM` (`systemctl stop`, `docker stop`) | Stops accepting connections, waits up to 10 s for in-flight requests, stops background jobs, records a clean stop |
| Windows | `python start.py stop` (or Ctrl+C / Ctrl+Break in a console) | Writes `data/shutdown.request`; the server acts on it within ~5 s |
| Agent (Python) | `SIGTERM` / Ctrl+C | Sends a best-effort *stopping* heartbeat with reason `system-shutdown` (when systemd reports the host is going down) or `agent-stopped`; the spool is kept |

Stopping the Windows scheduled task from Task Scheduler is a hard kill and is recorded as an *unclean* stop. Use `start.py stop`.

Tests: `test_real_process_graceful_shutdown_and_unclean_restart` (real `start.py` process: `stop` command, then `SIGTERM`, then `SIGKILL`) and the CI `windows-agent` job's Windows server smoke test.

## Health monitoring

- `GET /healthz`: unauthenticated liveness and readiness (`{"status":"ok"}` or HTTP 503). It reveals no data. Used by the Docker HEALTHCHECK and the Windows CI smoke test.
- **System health warnings** (dashboard banner, Settings, `start.py diagnose`):
  - no verified backup in 36 h, or a backup that failed verification
  - less than 1 GB or 5 % disk free
  - a failing background job
  - a TLS certificate expiring within 30 days
  - an agent spool over 50 % full
- `python start.py diagnose` prints configuration, database integrity, disk, last backup, last server downtime, audit-chain status, every agent's state, spool, drops and last error, and all warnings. It exits non-zero on critical problems.

## Backups

- A daily automatic backup uses SQLite's online backup API and is **verified** immediately: the copy is opened read-only and passes `PRAGMA integrity_check` plus a schema check. The result is recorded and shown, and a failed verification is a critical warning.
- `python start.py verify-backup FILE` checks any backup before you rely on it. `python start.py restore FILE` re-checks it and keeps the current database as `*.before-restore`.
- Backups are **not encrypted**. Store off-box copies on encrypted media.

## Resource bounds

- Request bodies are limited to 256 KiB (2 MiB for agent batches) and batches to 500 events.
- Concurrent requests: 32 by default. Socket timeout: 30 s. Rate limits apply per user, per agent and per IP.
- Agent spool: 100,000 events by default.
- Log file: `data/logs/blackguard.log`, rotated at 5 MB × 5 files. Set `BLACKGUARD_LOG_FILE=` to disable it.
- Retention trims events (default 180 days) but never evidence for unresolved incidents.

## Not yet validated

- Multi-day soak test on real hardware.
- The Windows agent and the Windows server installer on a real Windows 10/11 machine; the user has validated basic Windows agent delivery manually, and CI covers parsing plus a Windows server start/health/stop smoke test.
- Sustained high event rates (thousands per second).
