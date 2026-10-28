# Deployment, operations and recovery

## 1. Choose where the server runs

Run it on an always-on machine **inside your home network**: an old laptop, mini-PC, NAS with Python, or Raspberry Pi 4 (2 GB RAM is plenty). A GitHub Codespace is cloud-hosted. It cannot receive your router's syslog or reach your LAN devices, and private home logs should not be uploaded there.

## 2. TLS (required for anything beyond localhost)

```bash
python3 start.py tls-selfsigned --ip 192.168.1.50 --hostname blackguard.lan
```

This creates `data/tls/blackguard.crt` and `blackguard.key` (mode 600) with your LAN address in the certificate. Start the server with:

```bash
export BLACKGUARD_HOST=192.168.1.50 BLACKGUARD_PORT=8443
export BLACKGUARD_TLS_CERT=$PWD/data/tls/blackguard.crt BLACKGUARD_TLS_KEY=$PWD/data/tls/blackguard.key
python3 start.py
```

The server **refuses** to bind a non-loopback address without TLS unless you set `BLACKGUARD_ALLOW_REMOTE_WITHOUT_TLS=1`, which you should only do behind a TLS-terminating reverse proxy you control. Give each agent the `.crt` file only, never the key.

For Windows agents, get the SHA-1 thumbprint to pin:

```bash
openssl x509 -in data/tls/blackguard.crt -noout -fingerprint -sha1 | tr -d ':' | cut -d= -f2
```

**Never** forward BLACKGUARD's port on your router or expose it to the internet. For remote access, use a private VPN such as WireGuard or Tailscale.

## 3. Run as a service (Linux, systemd)

```bash
sudo useradd --system --home /opt/blackguard blackguard
sudo cp -r blackguard /opt/blackguard
sudo mkdir -p /opt/blackguard/data && sudo chown -R blackguard: /opt/blackguard/data
sudo mkdir -p /etc/blackguard && sudo tee /etc/blackguard/server.env <<'EOF'
BLACKGUARD_HOST=192.168.1.50
BLACKGUARD_PORT=8443
BLACKGUARD_TLS_CERT=/opt/blackguard/data/tls/blackguard.crt
BLACKGUARD_TLS_KEY=/opt/blackguard/data/tls/blackguard.key
BLACKGUARD_SEED_DEMO=0
EOF
sudo cp /opt/blackguard/deploy/blackguard.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now blackguard
journalctl -u blackguard -n 30     # shows the first-run setup code
```

The unit restarts on failure and applies sandboxing (read-only system, `NoNewPrivileges`, memory limit).

## 3b. Run as a background task (Windows)

Settings live in a `.env` file next to `start.py` (copy `.env.example`); environment variables override it.

```powershell
cd C:\path\to\blackguard
copy .env.example .env                                   # optional: edit settings
.\deploy\windows\Install-BlackguardServer.ps1             # starts at your logon, no console window
python start.py diagnose                                 # health report: backups, disk, agents, warnings
python start.py stop                                     # clean stop (Task Scheduler "End" is a hard kill)
.\deploy\windows\Install-BlackguardServer.ps1 -Uninstall  # clean stop, then remove the task
```

Use `-AtStartup` (run as Administrator) to start at boot as SYSTEM, so it runs even when nobody is logged on. Logs are written to `data\logs\blackguard.log`. The installer does not open firewall ports; the server stays on `127.0.0.1` unless your `.env` says otherwise (and then TLS is required).

**Validate on your machine after updating:** start the task and open the dashboard. In **Agents**, your Windows agent should show *Device boot time* and *Server reachable: yes* once it runs the updated script. `python start.py stop` should be followed by "stopped cleanly" in the log.

## 4. Docker

```bash
docker compose up -d --build
docker compose logs blackguard | grep -A3 "FIRST-RUN"
```

Compose publishes `127.0.0.1:8000` only. To serve agents on the LAN, mount a certificate, set the TLS variables and bind `<LAN-IP>:8443:8000`.

## 5. Agents

### Linux

```bash
sudo useradd --system --home /var/lib/blackguard-agent blackguard-agent
sudo -u blackguard-agent python3 /opt/blackguard/agents/blackguard_agent.py --state-dir /var/lib/blackguard-agent \
     enroll --server https://192.168.1.50:8443 --code ABCD-EFGH-JKLM-NPQR --ca-file /opt/blackguard/blackguard.crt
# approve in the dashboard after comparing the printed fingerprint, then:
sudo cp /opt/blackguard/deploy/blackguard-agent.service /etc/systemd/system/
sudo systemctl enable --now blackguard-agent
```

The agent reads only the sources you name:

| Source | Example | Notes |
| --- | --- | --- |
| `linux-auth:` | `linux-auth:/var/log/auth.log` (Debian/Ubuntu), `/var/log/secure` (RHEL/Fedora) | The agent user needs read access, e.g. the `adm` group |
| `journald` | `journald` | Reads the auth/authpriv facilities via `journalctl` with a persistent cursor |
| `syslog:` | `syslog:udp://192.168.1.50:5514?allow=192.168.1.1` | A LAN bind requires `allow=`. Also firewall the port |
| `jsonl:` | `jsonl:/var/log/myapp/security.jsonl` | Events already in BLACKGUARD's JSON format |
| `--inventory-arp` | | Passive: reports this machine's ARP/neighbour cache every 5 minutes. Sends no packets |

By default an agent starts at the **end** of each file. Use `--from-start` once to backfill. `blackguard_agent.py status` shows the spool depth, dropped/rejected counts and the server's view of the agent.

### Windows

PowerShell 5.1+ as Administrator:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\agents\windows\BlackguardAgent.ps1 -Enroll -Server https://192.168.1.50:8443 -Code ABCD-EFGH-JKLM-NPQR -CertThumbprint 3FA1...
.\agents\windows\BlackguardAgent.ps1 -Run -Once     # test one pass
.\agents\windows\BlackguardAgent.ps1 -Install       # scheduled task at startup as SYSTEM
.\agents\windows\BlackguardAgent.ps1 -Status
```

State lives in `%ProgramData%\BLACKGUARD\agent`, which is ACL-restricted to Administrators and SYSTEM, and the credential is DPAPI-encrypted. Collected IDs: 4624/4625 sign-ins (service and machine accounts filtered), 4720/4722/4724/4725/4726 account lifecycle, 4728/4732/4756 group membership, 4740 lockout, 4719/4739 policy, 1102/104 log cleared, 4697/7045 service installs. Make sure your Windows audit policy logs these: `auditpol /get /category:*`.

### Router

In your router's admin UI, set *Remote syslog server* to the agent's LAN IP and port (5514). Formats recognised: OpenWrt (netfilter, dropbear, dnsmasq), pfSense/OPNsense filterlog, UFW/iptables, MikroTik RouterOS, ISC dhcpd, plus generic login and configuration messages. Unrecognised lines are ignored and counted in the agent's health report.

## 6. Backups and recovery

- **Automatic:** a consistent online backup is written daily to `data/backups/auto-*.sqlite3`. The number kept is set under Settings → Retention (default 7).
- **Manual:** run `python3 start.py backup`, or use Settings → Back up now.
- **Before every migration:** `data/backups/pre-migration-v*.sqlite3`.
- **Off-box copy (recommended):** copy `data/backups/` to another disk or an encrypted cloud drive. Backups contain security logs and password hashes, so treat them as sensitive.

**Restore:**

```bash
sudo systemctl stop blackguard           # or stop the process / container
python3 start.py restore data/backups/auto-20261028T000000Z.sqlite3
sudo systemctl start blackguard
```

`restore` checks the backup's integrity, saves the current database as `*.before-restore`, then replaces it. Pending migrations run on the next start.

**Lost admin password:** stop the server and run `python3 start.py reset-password <username>`.

## 7. Retention

Settings → Retention controls event age (default 180 days) and audit age (default 730 days). Retention runs hourly. **Evidence linked to an unresolved incident is never deleted.** When old audit entries are trimmed, an anchor is recorded so the hash chain stays verifiable.

## 8. Upgrading from v0.4

1. Stop v0.4 and back up the whole `data/` folder.
2. Start v0.5. Migrations run inside a transaction after writing `pre-migration-v1-*.sqlite3`. If a migration fails it rolls back and the server does not start.
3. Create your administrator with the setup code.
4. Your v0.4 events and incidents are intact. Statuses are kept and evidence links are reconstructed. Old collectors appear under Agents as **legacy**.
5. Old collectors are rejected with HTTP 410 until you re-enroll them with `blackguard_agent.py`. As a temporary bridge only, `BLACKGUARD_LEGACY_INGEST=1` makes the server accept the old shared ingest token from `data/access.json`. That data is labelled *legacy token (unverified)* and gets lower confidence.
6. `data/access.json` is not deleted or rotated. Delete it yourself once every collector has been re-enrolled.

## 9. Diagnostics

Start with `python3 start.py diagnose`, then the table below. `GET /healthz` (no sign-in) reports liveness for external monitors. See [RELIABILITY.md](RELIABILITY.md) for outage causes (device restarted, agent stopped, server unreachable) shown on BG-HEALTH-01 incidents.


| Symptom | Check |
| --- | --- |
| Agent stays *pending* | Approve it under Agents (fingerprint check) |
| Agent "TLS certificate not trusted" | Pass `--ca-file` with the server certificate, and use the IP or name that is in the certificate |
| Agent offline incident | Is the machine on? Run `blackguard_agent.py status`, or `journalctl -u blackguard-agent` |
| "No permission to read /var/log/auth.log" | `sudo usermod -aG adm blackguard-agent` |
| No router events | Confirm the router sends to the right IP/port, the `allow=` IP matches, and the host firewall allows UDP from the router. Check `ignored_unparsed` in the agent's health (Agents page) |
| Data loss incident | The agent's spool overflowed during a long outage. Raise `--spool-max` |
| Settings → System health shows a job error | The error text is shown; full traces are in the server log |
| `Data directory … not writable` | Fix ownership, or mount a Docker volume |

Server logs go to stderr (journald or `docker logs`). Set `BLACKGUARD_LOG_LEVEL=DEBUG` for per-request logs.
