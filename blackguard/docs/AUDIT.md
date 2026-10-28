# Audit of the v0.4 baseline

Performed before the v0.5 upgrade (2026-10-28) by reading every file, running the test suite (25 tests, all passing), and building and migrating a real v0.4 database.

## What genuinely worked

- A stdlib HTTP server serving the dashboard and a JSON API, with SQLite persistence for events, incidents and heartbeats.
- Five deterministic rules (brute force, success after failures, privilege change, policy change, firewall block).
- Incident status changes that persisted across restarts.
- Separate admin and ingest bearer tokens, generated on first run and stored in `data/access.json` (mode 600).
- A JSONL tail collector, a UDP syslog receiver with three message types, and a Windows Security log poller (untested on Windows).
- A Markdown report export, a strict CSP, `textContent`-only rendering, and loopback-only binding by default.

## Defects and weak assumptions found

| # | Finding | Impact | v0.5 resolution |
| --- | --- | --- | --- |
| 1 | The workflow lived at `blackguard/.github/workflows/ci.yml`. GitHub only reads `.github/` at the repository root | **CI never ran** | Workflow moved to the root with `working-directory`. Adds Python matrix, security, browser E2E, Docker and Windows-parse jobs |
| 2 | One shared ingest token; the server trusted the client-supplied `agent_id` | Any collector could impersonate any device; no per-device revocation | Per-agent credentials, identity derived from the credential, approval workflow |
| 3 | Heartbeats auto-registered devices | Devices joined without approval | Enrollment codes plus admin approval with a fingerprint check |
| 4 | Single shared admin token in `sessionStorage` | No individual accountability, roles or audit; token exposed to any XSS | User accounts, roles, HttpOnly session cookies, CSRF, audit log |
| 5 | No event IDs or deduplication; retries re-inserted events | Duplicates after a lost acknowledgement | Stable UIDs, a unique index and `INSERT OR IGNORE` |
| 6 | Collector cursors only in memory; syslog queue in memory; Windows read at most 200 events per poll | Events lost on restart, outage or burst | Durable spool committed atomically with the cursor; Windows drains in batches of 500 |
| 7 | `detect()` rescanned **all** events on every ingest using an O(n²) window | Slows as data grows | Incremental time-window evaluation with two-pointer sliding windows |
| 8 | Incident upsert overwrote `first_seen`, `last_seen` and summary, and left status untouched | New activity on a resolved incident stayed "resolved" and hidden | New evidence after resolution opens a new incident |
| 9 | Every single firewall block opened an incident | Alert fatigue on any internet-facing router | Threshold burst and port-scan rules |
| 10 | Event search loaded the newest 2,000 rows and filtered them in Python | Older evidence could not be found | Server-side SQL search with keyset pagination |
| 11 | No rate limiting, request concurrency bound or socket timeout | Easy to exhaust a home server | Token buckets, bounded worker slots, 30 s socket timeout |
| 12 | No TLS support; bearer tokens over plain HTTP if bound to the LAN | Credential exposure on the LAN | Optional TLS (handshake in worker threads); non-loopback binding refuses to start without TLS |
| 13 | Module-level side effects in `app.py` (DB init and demo seeding on import) | Hard to test; seeded demo data on any import | Application factory (`guard.platform.App`) |
| 14 | No schema versioning or migrations; `mode` CHECK constraint prevented new data classes | Upgrades risk data loss | Versioned migrations, pre-migration backup, transactional rollback |
| 15 | Demo and real data shared one "imported" label; no way to remove demo data | Confusing provenance | `mode` (demo/imported/live) and `trust` (verified_agent/legacy_token/manual_import/server/demo) on every event; demo purge |
| 16 | Syslog collector used receive time only and its username regex matched words like "for" | Wrong attribution | Header timestamps where present (with a `time_source` label) and stricter parsers |
| 17 | Windows collector mapped account creation (4720) to the generic `privilege_change` | Misleading findings | Precise event types; more IDs (lockout, group changes, log cleared, service installs) |
| 18 | Stale "v0.2" text on the sign-in screen; README overstated nothing but under-documented risks | Polish | Rewritten UI and documentation |

## Missing dependencies

None. The project is stdlib-only, which is a strength for a home deployment. Node is used only for checking and testing the frontend.
