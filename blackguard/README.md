# BLACKGUARD

**The Guardian of Your Network and Information.**

BLACKGUARD is a local-first security monitoring and defensive-response platform for a home network, built so it can grow into a small-business product. It collects security events from devices you own through enrolled agents, runs transparent detection rules, opens evidence-backed incidents, and gives you an investigation workspace plus an approval-gated response workflow. It runs from a dark, medieval-knight-styled command centre.

It runs on an ordinary home computer using only the Python standard library. There are no cloud accounts, no paid APIs and no third-party Python packages.

> **Experimental release — not independently security-certified.** BLACKGUARD is a capable personal security tool, **not** a certified or production-hardened SIEM/EDR. Detections are leads for a human to verify, not proof of compromise. BLACKGUARD never blocks, disconnects, resets or counter-attacks anything by itself. See [docs/SECURITY.md](docs/SECURITY.md) for its limits and remaining risks.

![Command centre (synthetic demo data)](docs/screenshots/01-command-centre.png)

**Try it without installing:** open [`../showcase/index.html`](../showcase/index.html) → *Launch the interactive demo* (synthetic data, runs in your browser). **Understand it:** [How it works](docs/HOW_IT_WORKS.md).

## What is real in v0.5

| Area | Implemented |
| --- | --- |
| **Accounts** | Individual users with roles (admin / analyst / viewer). Passwords hashed with scrypt. Server-side sessions in HttpOnly, SameSite=Strict cookies (Secure + `__Host-` prefix under TLS). CSRF tokens, idle and absolute timeouts, account lockout, per-IP login rate limiting, first-run setup code |
| **Agent enrollment** | One-time, expiring enrollment codes. Agents stay *pending* until an admin approves them after comparing the machine fingerprint. Each agent has a unique 256-bit credential, stored only as a hash. Two-phase rotation (automatic after 90 days or on demand), immediate revocation. Identity comes from the credential, so one agent cannot impersonate another. A fingerprint change suspends the agent and opens an incident |
| **Collectors** | Linux auth logs (OpenSSH, sudo, su, useradd/usermod/gpasswd, passwd), systemd journal, router/firewall UDP syslog (netfilter/iptables/UFW, pfSense/OPNsense filterlog, OpenWrt dropbear, MikroTik, dnsmasq/ISC DHCP, generic login/config messages), JSONL files, and Windows Security/System logs (PowerShell agent) |
| **Reliability** | Durable SQLite spool on each agent, with the source cursor committed in the same transaction. Survives restarts and server outages. Backoff with jitter. Idempotent delivery: stable event UIDs and server-side dedup mean no duplicates. Handles log rotation and copytruncate. Bounded spool with drop counting. Malformed events are rejected individually so they never block the queue. Agent health in every heartbeat |
| **Inventory** | Devices from approved agents (*confirmed*), router DHCP leases and the agent's passive ARP cache (*reported*), or manual entry. Every attribute keeps its provenance and history. Inference is never shown as fact. No scanning |
| **Detection** | 19 documented rules mapped to MITRE ATT&CK: brute force, success after failures, password spraying, lockout, first-seen source for an account, privileged-group changes, account creation/changes, policy changes, log clearing, service installs, router config changes, firewall bursts, port scans, cross-device correlation, collector offline, identity mismatch, data loss, and new device on the network. Thresholds are tunable. Each incident records confidence and its reasoning, evidence, affected devices, a timeline, investigation steps and false-positive notes |
| **Incidents** | Evidence-linked incidents. Re-runs are idempotent. New evidence joins the open incident; after resolution, new activity opens a *new* incident instead of being silently absorbed. Notes, status history, Markdown/JSON exports and pseudonymised exports |
| **Guardian Response** | Propose → admin approval with an acknowledged impact statement → performed by a person → recorded result → recorded rollback. Fully audited. Nothing executes automatically |
| **Audit** | Hash-chained, tamper-evident audit log of sign-ins, approvals, rule changes, exports and responses |
| **Operations** | Schema migrations with automatic pre-migration backups. Daily online backups and a restore command. Configurable retention that never deletes evidence for unresolved incidents. Background health jobs. Bounded concurrency and request sizes. Optional TLS. Docker and systemd units |
| **AI analyst (optional)** | Local Ollama only, off by default. Gets a redacted, bounded copy of the evidence, must cite event IDs, and its citations are validated. Output is labelled unverified and it has no ability to change anything |
| **Dashboard** | Near-real-time updates (revision polling), server-side search with pagination, an investigation workspace, inventory, agent management, rule tuning, response queue, audit log, users/settings. Demo, imported and live data are labelled throughout. Responsive layout, keyboard-accessible, strict CSP, no `innerHTML` |

## Quick start (local)

Requires **Python 3.10+**. Nothing to install.

```bash
cd blackguard
python3 start.py
```

1. The terminal prints a **one-time setup code**. Open <http://127.0.0.1:8000>, enter the code and create your administrator (12+ character password).
2. The first run loads clearly labelled **fictional demo data** so you can explore. Remove it later under **Settings → Demo data**.
3. Go to **Agents → Enroll a device** to start monitoring real machines (see below).

Prefer the CLI? Stop the server, then run `python3 start.py create-admin yourname`.

**Upgrading from v0.4:** just start the new version. The database migrates automatically after a backup is written to `data/backups/pre-migration-*.sqlite3`. All events, incidents and statuses are preserved, and old heartbeat "devices" are kept as *legacy / unverified*. The v0.4 shared tokens in `data/access.json` are left untouched but no longer grant dashboard access. See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md#upgrading-from-v04).

## Monitor your devices

A GitHub Codespace **cannot see your home network**. Run the BLACKGUARD server on a computer at home (a spare laptop, mini-PC or Raspberry Pi 4 is enough) and run agents on the devices you want to monitor. For anything beyond one machine, enable TLS first:

```bash
python3 start.py tls-selfsigned --ip 192.168.1.50          # your server's LAN address
BLACKGUARD_HOST=192.168.1.50 BLACKGUARD_PORT=8443 \
BLACKGUARD_TLS_CERT=data/tls/blackguard.crt BLACKGUARD_TLS_KEY=data/tls/blackguard.key python3 start.py
```

Copy `blackguard.crt` (never the `.key`) to each agent machine.

**Linux computer** (auth log or journald):

```bash
python3 agents/blackguard_agent.py enroll --server https://192.168.1.50:8443 --code ABCD-EFGH-JKLM-NPQR --ca-file blackguard.crt
python3 agents/blackguard_agent.py run --source linux-auth:/var/log/auth.log --inventory-arp
#   or: --source journald     (RHEL/Fedora: linux-auth:/var/log/secure)
```

**Router / firewall** (UDP syslog to an agent on your LAN):

```bash
python3 agents/blackguard_agent.py run --device-name "Home router" \
  --source "syslog:udp://192.168.1.50:5514?allow=192.168.1.1"
```

Then point your router's remote-syslog setting at `192.168.1.50:5514`. UDP syslog is unauthenticated, so firewall that port to the router's IP.

**Windows** (PowerShell as Administrator):

```powershell
.\agents\windows\BlackguardAgent.ps1 -Enroll -Server https://192.168.1.50:8443 -Code ABCD-EFGH-JKLM-NPQR -CertThumbprint <thumbprint>
.\agents\windows\BlackguardAgent.ps1 -Install    # startup task as SYSTEM, restarts on failure
```

Each agent prints a **fingerprint**. In **Agents**, approve the pending agent only if the fingerprint matches. Full instructions, systemd units and troubleshooting are in [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

Only monitor devices and logs you own or are explicitly authorised to monitor.

## Run in GitHub Codespaces (development only)

```bash
cd blackguard && python3 start.py
```

Codespaces forwards port 8000 privately. Keep its visibility **Private**, and do not upload private home logs to a cloud workspace. Codespaces is for development and the demo, not for monitoring your home.

## Docker

```bash
docker compose up --build        # publishes 127.0.0.1:8000 only; data in a named volume
docker compose logs blackguard   # shows the first-run setup code
```

The container runs as a non-root user with a read-only root filesystem, no Linux capabilities, `no-new-privileges`, and memory/PID limits.

## Verify

```bash
python3 -m unittest discover -s tests -v       # 115 tests: API, auth/RBAC, agents, ingestion, detection, migrations, chaos delivery, TLS, demo honesty
python3 start.py diagnose                       # operational health report (backups, disk, agents, warnings)
python3 scripts/secret_scan.py                  # tracked-file secret scan
node tests/e2e/dashboard.e2e.js                 # browser E2E + axe accessibility (npm: playwright, axe-core)
node tests/e2e/showcase.e2e.js                  # static demo E2E (rebuild first: python3 scripts/build_showcase.py)
```

See [docs/TESTING.md](docs/TESTING.md) for current results and what could not be tested.

## Documentation

- [docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md): agents, event pipeline, authentication, detection engine, incidents — with diagrams
- [docs/RELIABILITY.md](docs/RELIABILITY.md): exact delivery guarantees and outage handling
- [docs/PRODUCTION_READINESS.md](docs/PRODUCTION_READINESS.md) and [docs/LICENSING.md](docs/LICENSING.md): technical debt, commercial horizon, licence decisions

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): components, data model, trust model, path to multi-site/business use
- [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md): home deployment, TLS, agents, systemd, Docker, backups and recovery, troubleshooting
- [docs/DETECTIONS.md](docs/DETECTIONS.md): every rule, its logic, ATT&CK mapping and tuning
- [docs/SECURITY.md](docs/SECURITY.md): threat model, controls, limitations and remaining risks
- [docs/AI_ANALYST.md](docs/AI_ANALYST.md): the optional local AI analyst design
- [docs/AUDIT.md](docs/AUDIT.md): audit of the v0.4 baseline that motivated this upgrade
- [docs/TESTING.md](docs/TESTING.md) and [docs/ROADMAP.md](docs/ROADMAP.md)

## License

MIT. See `LICENSE`.
