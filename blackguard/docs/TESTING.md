# Testing and verification

Results from the v0.5 development run on 2026-10-28 (Linux, Python 3.13.17, Node 22.22, Chromium via Playwright). The CI workflow re-runs everything on Python 3.10, 3.12 and 3.13.

## Results

| Check | Command | Result |
| --- | --- | --- |
| Python unit and integration tests | `python3 -m unittest discover -s tests -v` | **98 passed**, 0 failed (~18 s) |
| Browser E2E: setup, every view, investigation, note, response approval, event drawer, enrollment code, rule tuning, user creation, audit chain, mobile layout (390 px, no horizontal overflow), sign-out/in, zero console errors or 5xx | `node tests/e2e/dashboard.e2e.js` | **Passed** |
| JavaScript syntax | `node --check web/app.js` | Passed |
| Secret scan | `python3 scripts/secret_scan.py` | Clean |
| Static analysis | `bandit -r guard agents start.py -ll` | 0 issues. 9 B608 findings reviewed and annotated: only fixed column names or `?` placeholders are interpolated |
| Docker | build, then run with `--read-only --cap-drop ALL --security-opt no-new-privileges` plus a volume | Built; runs as uid 999; `/api/v1/setup/status` responds; HEALTHCHECK reports `healthy`; a clear error when the data volume is missing |
| v0.4 migration (real database made with the v0.4 code) | `start.py check` on a copy | 25 events and 5 incidents preserved, `investigating` status kept, evidence links rebuilt, pre-migration backup written, integrity `ok` |

## Public-showcase run (2026-10-28)

| Check | Result |
| --- | --- |
| Python suite | **115 passed** (111 + 4 demo-honesty tests: synthetic labelling, no real addresses or credentials, detections from the real rules, onboarding state) |
| Real-server browser E2E (`tests/e2e/dashboard.e2e.js`) | Passed with Playwright 1.48.2 (the CI pin) and 1.63: setup, onboarding checklist, every view, investigation, global search, enrollment, rules, users, audit, mobile, sign-out/in |
| Showcase E2E (`tests/e2e/showcase.e2e.js`) | Passed on both versions: landing page, offline demo with **zero network API requests**, every view, investigation actions, keyboard search, sorting, time range, unsupported-action message, mobile overflow |
| Accessibility | axe-core (WCAG 2.0/2.1/2.2 A and AA rules) on the setup, sign-in, overview, settings, landing page and every demo view: **0 serious or critical violations**. Two issues found and fixed: nav-badge contrast and `<li>` outside a list. Automated checks do not cover everything in WCAG; no manual screen-reader audit has been done yet |
| bandit / secret scan | Clean |
| Portfolio assets | Regenerated from the static demo by `scripts/capture_showcase.js` and reviewed by eye for sensitive data (synthetic names, RFC 5737 and generic private addresses only) |

## Milestone A run (2026-10-28)

| Check | Result |
| --- | --- |
| Python suite | **111 passed** (98 existing + 13 new) |
| Browser E2E | Passed with Playwright 1.48.2 (the CI pin) and 1.63 |
| bandit / secret scan | Clean |
| Docker | Image builds; `/healthz` responds; `docker stop` → "stopped cleanly", exit 0 |
| New `test_reliability.py` | Chaos delivery: 405 events, 3 server restarts, every 3rd acknowledgement dropped → exactly 405 stored, 0 duplicates, 0 drops. Outage classification (restart / clean shutdown / agent stopped / server unreachable / unexplained). Server-restart grace (no false offline alerts). Server downtime recorded clean or unclean. Real `start.py` process: `stop` command, SIGTERM and SIGKILL. Backup verification and health warnings. `.env` loading |
| Windows | Not executed here. The CI `windows-agent` job parses both PowerShell scripts, runs PSScriptAnalyzer, and starts, health-checks and cleanly stops the server on `windows-latest`. The agent's new fields and the server installer still need validation on the owner's PC |

## What the Python suite covers

- `test_http_security.py`: setup cannot repeat; unauthenticated 401s; cookie flags; CSRF and Origin enforcement; generic login errors with auditing; RBAC for all three roles; session revocation on role change; last-admin protection; password policy; 413/415/400/404/405 handling; SQL metacharacters stored as data; HTTP keep-alive desync regression; IP rate limiting; account lockout; legacy API disabled by default and working when opted in.
- `test_agents.py`: single-use, expiring and revocable codes; hashed credentials; pending agents cannot submit; fingerprint-confirmed approval; identity bound to the credential (an impersonation attempt is ignored); agents and users cannot cross API boundaries; immediate revocation that keeps data; two-phase rotation; fingerprint-mismatch suspension plus an incident; offline and data-loss incidents (alerting once per outage); partial rejection; deduplication; inventory learning period and new-device alerts; DHCP lease ingestion.
- `test_agent_runtime.py`: spool atomicity, bounds and drop counting; tail handling of partial lines, rename rotation and copytruncate; start-at-end default; restart without re-reading; transport policy; private state file; **server down → buffered → restart → delivered exactly once**; lost acknowledgement causes no duplicate; invalid events dropped instead of blocking; rotation persisted before use; revoked agent stops but keeps its spool; **TLS** with an untrusted versus a pinned certificate, HSTS, and the `__Host-` Secure cookie.
- `test_detection.py`: every rule positive and negative; idempotent sweeps; evidence merging; resolved incidents never reused; provenance-based confidence; rule tuning, validation and disabling; **realistic datasets** (attack, benign false-positive check, router syslog).
- `test_parsers.py`: OpenSSH, sudo, su, shadow-utils, passwd, PAM duplicate suppression, ISO/RFC 3164/RFC 5424 timestamps, year rollover, future-time fallback, netfilter/UFW, pfSense filterlog, dropbear, MikroTik, dnsmasq and ISC DHCP, generic messages, hostile and oversized input.
- `test_migrations.py`: v0.4 → v2 upgrade preserves data; idempotent migrations; a failed migration rolls back fully and recovers on the next start.
- `test_workflow.py`: evidence, timeline and guidance; notes and status history; the response approval state machine (analyst cannot approve; impact acknowledgement and notes required; rollback); Markdown/JSON/pseudonymised reports; honest dataset labels; demo purge; keyset pagination and time filters; backup, retention and health endpoints; AI analyst against a fake Ollama (citation validation, secret redaction, labelling, disabled-by-default, remote URL refused); scrypt; redaction; rate limiter; audit-chain tamper detection; retention keeps evidence for open incidents; CLI restore round trip.

## Not tested in this environment

- **Windows agent (`BlackguardAgent.ps1`)**: not executed or parse-checked, because PowerShell is not installed here and downloading it was not permitted. The CI `windows-agent` job parses it and runs PSScriptAnalyzer on `windows-latest`, but the event mapping, DPAPI storage, ACLs and scheduled-task installation still need a manual test on a real Windows 10/11 machine.
- **Real home hardware:** routers sending syslog, real `/var/log/auth.log` on a long-running host, journald on a real systemd host (the journald source is exercised only through its parser), and ARP neighbour discovery on a real LAN.
- **macOS agent** fingerprinting (`ioreg`).
- **The real Ollama models.** Only a protocol-compatible fake server was used. Model quality is unknown.
- **Load and soak testing:** no multi-day 24/7 run or high event-rate benchmark has been done yet.
- **Independent penetration testing:** none.
