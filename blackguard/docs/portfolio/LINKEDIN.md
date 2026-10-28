# BLACKGUARD: LinkedIn and portfolio launch package

Creator: **Nima Memarahari** ([@NimaMema](https://github.com/NimaMema))

Every statement below is backed by code and tests in this repository. Before posting, replace the links in `[brackets]` with real ones: the GitHub URL once the public repository exists, and the demo URL once GitHub Pages is enabled. Nothing has been published.

**Assets**
- Thumbnail (1200×627): `linkedin-thumbnail.png`
- Social preview (1280×640, for GitHub Settings → Social preview): `social-preview.png`
- Screenshots: `../screenshots/`
- Walkthrough video: `../media/blackguard-demo.webm`

Regenerate all of them with `python3 scripts/build_showcase.py && node scripts/capture_showcase.js`.

---

## 1. Launch post

> 🛡️ **Introducing BLACKGUARD: The Guardian of Your Network and Information**
>
> I've been building an open-source, local-first security monitoring platform for home networks, designed to grow into something bigger. Today I'm sharing the first public, **experimental** release.
>
> **What it does**
> 🔹 **Observe:** agents I enroll and approve collect Windows, Linux and router security events, buffer them on-device during outages, and deliver each one exactly once (tested across server restarts and dropped acknowledgements).
> 🔹 **Detect:** 19 transparent rules mapped to MITRE ATT&CK (brute force, password spraying, success-after-failures, backdoor accounts, port scans, cross-device correlation). Every incident explains its confidence, evidence and false-positive considerations.
> 🔹 **Defend:** "Guardian Response" proposes actions with their impact and rollback plan. Nothing runs without an administrator's approval, and every decision is audited.
>
> **How it's built**
> Python standard library and SQLite on the server (zero runtime dependencies), a vanilla-JS dashboard under a strict Content-Security-Policy, per-agent credentials with approval and rotation, role-based access, and a hash-chained audit log. It ships with 115 automated tests, browser end-to-end tests with WCAG accessibility checks, and CI on Linux and Windows.
>
> **Honest status:** it's experimental and not independently security-reviewed or certified. I run it on my own Windows setup, and the limitations are documented in the repo.
>
> 👉 Try the interactive demo (synthetic data, runs in your browser): [demo link]
> 💻 Source: [GitHub link]
>
> BLACKGUARD is the foundation for a cybersecurity company I plan to build. I'd love feedback from security engineers and fellow builders.
>
> #cybersecurity #blueteam #opensource #python #detectionengineering #infosec #homelab #mitreattack

*(About 1,500 characters: comfortably within LinkedIn's limit.)*

## 2. Projects-section description (≈ 600 characters)

> **BLACKGUARD: open-source, local-first security monitoring (experimental).** Enrolled agents collect Windows, Linux and router events with durable, exactly-once delivery. 19 explainable MITRE ATT&CK-mapped detections create evidence-backed incidents, and an approval-gated "Guardian Response" workflow never acts without an administrator. Python stdlib and SQLite backend, vanilla-JS dashboard under a strict CSP, role-based access, per-agent credentials and a tamper-evident audit log. 115 automated tests plus browser and accessibility E2E. Not independently security-certified.

## 3. Technical summary for recruiters

- **Problem:** home networks and small offices have no affordable, private way to see failed logins, new accounts, firewall scans or devices going silent, or to act on them safely.
- **What I built:** a full-stack security platform. Agents (Python and PowerShell), an HTTP API with authentication, RBAC, CSRF and rate limiting, an ingestion pipeline with validation, redaction and deduplication, a detection engine, incident and response workflows, and a responsive dashboard.
- **Engineering highlights:**
  - **Reliability:** at-least-once delivery plus idempotent storage gives exactly-once storage, proven by a chaos test (server restarts plus dropped acknowledgements). Outages are classified from evidence: device rebooted, agent stopped, or server unreachable.
  - **Security:** per-agent credentials with administrator approval and fingerprint check, two-phase rotation, scrypt, server-side sessions, strict CSP, secret redaction, verified backups, tamper-evident audit log.
  - **Detection engineering:** sliding-window and correlation rules, confidence reasoning that accounts for provenance, idempotent re-runs, and validation on realistic attack *and* benign datasets.
  - **Quality:** 115 Python tests, Playwright E2E with axe-core WCAG 2.2 A/AA checks, CI on Python 3.10 to 3.13, Docker and Windows.
  - **Product:** a zero-install interactive demo that runs the real dashboard on synthetic data processed by the real engine.
- **Role:** creator and maintainer (Nima Memarahari, @NimaMema): product direction, architecture and security decisions, testing, and validation on a real Windows machine.

## 4. Elevator pitch (30 seconds)

> "BLACKGUARD is an open-source security monitoring platform you run yourself. Small agents on your Windows and Linux machines and your router send security events to a local server. Transparent, ATT&CK-mapped rules turn them into incidents that explain their evidence and confidence. When it's time to act, it proposes a response with its impact and rollback plan, and nothing happens until an administrator approves. It's experimental, but it already runs on my home setup, it's covered by more than a hundred automated tests, and you can try a live demo in your browser."

## 5. Technologies and skills demonstrated

**Languages and platforms:** Python (stdlib: `http.server`, `sqlite3`, `ssl`, `hashlib`), JavaScript (vanilla, no framework), PowerShell, HTML/CSS, SQL, Docker, systemd, Windows Task Scheduler, GitHub Actions.
**Security:** authentication and session design, RBAC, CSRF and CSP, TLS, secret handling and redaction, agent identity and credential rotation, audit logging, threat modelling, MITRE ATT&CK mapping, detection engineering, log parsing (Windows Security events, OpenSSH, sudo, netfilter, pfSense, MikroTik).
**Engineering:** reliable delivery (durable spools, idempotency), schema migrations, backup and restore, testing (unit, integration, chaos, E2E), accessibility (WCAG 2.2 AA with axe-core), technical writing.

## 6. Thumbnail

Use `linkedin-thumbnail.png` (1200×627). It shows the shield, name, tagline, three capability lines and the *Experimental · not independently security-certified* note.

## 7. Four-image carousel concept

| # | Image | Caption |
| --- | --- | --- |
| 1 | `linkedin-thumbnail.png` | "BLACKGUARD: open-source, local-first security monitoring." |
| 2 | `../screenshots/01-command-centre.png` | "Observe: posture, activity and active incidents at a glance (synthetic demo data)." |
| 3 | `../screenshots/02-investigation.png` | "Detect: every incident shows its evidence, timeline, ATT&CK techniques and *why* it fired." |
| 4 | `../screenshots/03-guardian-response.png` | "Defend: proposed actions with impact and rollback; nothing runs without approval." |

## 8. Demo video storyboard (45 to 60 seconds)

The recorded version is `../media/blackguard-demo.webm` (about 50 s, 1280×720). Re-record it with `node scripts/capture_showcase.js`.

| Time | Screen | Voice-over or caption |
| --- | --- | --- |
| 0–5 s | Command centre with the demo ribbon | "This is BLACKGUARD, running entirely in the browser on synthetic data." |
| 5–10 s | Scroll: activity chronicle and watchlist | "Agents on Windows, Linux and the router feed a local server…" |
| 10–20 s | Critical incident: success after failures | "…and transparent rules turn events into incidents that explain their evidence and confidence." |
| 20–27 s | Timeline, then Guardian Response | "Responses are proposed with their impact and rollback. Nothing runs without approval." |
| 27–35 s | Global search, then the event ledger and evidence drawer | "Every finding traces back to stored events." |
| 35–42 s | Agents | "Agents are enrolled with one-time codes, approved by fingerprint, and monitored for outages." |
| 42–50 s | Detection rules | "Nineteen ATT&CK-mapped rules, tunable and documented. Open source and experimental. Link below." |

## 9. Hashtags

`#cybersecurity #blueteam #detectionengineering #opensource #python #infosec #homelab #mitreattack #securityengineering #buildinpublic`

## 10. Maturity and limitations (for comments and DMs)

> "It's an experimental release. It hasn't had an independent security review or penetration test, so I don't present it as production-grade or certified. It isn't a replacement for antivirus/EDR or a commercial SIEM, and detections are leads for a human to verify. The Windows agent runs on my own machine. Router support covers common syslog formats, but no vendor-specific integrations have been validated yet. The full list of limitations is in the repo."

## Suggested GitHub settings (apply manually when the public repository is created)

- **Description:** "Open-source, local-first security monitoring: enrolled agents, explainable ATT&CK-mapped detections, evidence-backed incidents and approval-gated response. Experimental."
- **Topics:** `cybersecurity`, `security-monitoring`, `siem`, `detection-engineering`, `mitre-attack`, `blue-team`, `python`, `sqlite`, `homelab`, `incident-response`, `windows-event-log`, `syslog`
- **Social preview:** upload `social-preview.png`.
- **Website:** the GitHub Pages URL of `showcase/` (only after you approve publishing).
