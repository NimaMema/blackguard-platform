# Security model, controls and remaining risks

BLACKGUARD handles security-sensitive data: authentication logs, account names, IP addresses and device inventories. It is designed to be secure by default for a **private home network**. Passing tests is **not** evidence that it is production-secure; it has had no independent security review or penetration test.

## Threat model (in scope)

- Another device on the home LAN trying to read data, sign in, or submit forged events.
- A stolen or copied agent credential.
- Malicious content inside logs (XSS/SQL payloads, oversized lines, secrets).
- Browser-based attacks (CSRF, clickjacking) against a signed-in administrator.
- Accidental data loss: crashes, outages, failed upgrades.

Out of scope: an attacker with root or Administrator access on the BLACKGUARD server, who can read the database and rewrite the audit chain; internet exposure, which is unsupported; and nation-state adversaries.

## Controls implemented

| Area | Control |
| --- | --- |
| Authentication | Individual accounts; scrypt (N=2^15, r=8, p=1); 12+ character passwords; common and repetitive passwords rejected; generic login errors; dummy hashing for unknown users (timing); lockout after 8 failures for 15 min; 10 login attempts/min per IP |
| Sessions | 256-bit random tokens stored as SHA-256; HttpOnly, SameSite=Strict, Path=/, Secure + `__Host-` prefix under TLS; 30 min idle and 12 h absolute timeout; sessions revoked on password, role or disable changes |
| Authorisation | Per-route permissions for three roles; the last active admin cannot be removed; approvals for security-changing actions are admin-only |
| CSRF / clickjacking | Per-session CSRF header on every state change; same-origin `Origin` check; `frame-ancestors 'none'`, `X-Frame-Options: DENY` |
| XSS | Strict CSP (`script-src 'self'`, no inline script); the dashboard renders only through `textContent` |
| Injection | Parameterised SQL everywhere (bandit B608 findings reviewed: only fixed column names are interpolated); LIKE wildcards escaped |
| Input validation | Typed event schema; IP, port, timestamp (past year, ≤15 min future), length and detail-field limits; JSON only; 256 KiB / 2 MiB body limits |
| Agents | Per-agent credentials (hash stored); enrollment codes are single-use, expire and are stored hashed; explicit approval with a fingerprint check; identity from credential only; two-phase rotation; revocation; fingerprint-change suspension; 600 req/min per agent |
| Transport | Optional TLS 1.2+ (handshake in worker threads); refuses a non-loopback bind without TLS; HSTS under TLS; agents require HTTPS for non-loopback servers and support CA pinning |
| Resource limits | Bounded concurrent requests, socket timeouts, rate limits, bounded spools and retention; HTTP keep-alive bodies are always drained (request-desync regression test) |
| Privacy | Secrets redacted before storage (passwords, tokens, Bearer values, private keys, Luhn-valid card numbers); raw log storage off by default; pseudonymised exports; all data stays on your machine |
| Audit | Hash-chained audit log of sign-ins, user/agent/rule changes, imports, exports, responses and AI use; chain verification in the UI and `start.py check` |
| Response safety | No automatic blocking, disconnection, firewall changes or credential resets; approval requires acknowledging the impact; rollback recorded; counter-attacks are permanently out of scope |
| Secrets at rest | `agent.json` mode 600 in a 700 directory (Linux/macOS); Windows credential DPAPI-encrypted with an Administrators/SYSTEM-only ACL; TLS key mode 600 |
| Supply chain | No third-party runtime dependencies; CI runs a secret scan and bandit; Dependabot tracks GitHub Actions versions |
| Container | Non-root, read-only root filesystem, `cap_drop: ALL`, `no-new-privileges`, memory/PID limits, loopback-only port |
| Operations surface | `/healthz` is unauthenticated by design and returns only `{"status":"ok"}`; a clean stop can be requested only by writing `data/shutdown.request`, which requires write access to the data directory (already equivalent to full control) |

## Known limitations and remaining risks

1. **No independent review.** Controls were designed with OWASP ASVS/Cheat Sheet guidance in mind but have not been externally assessed.
2. **Server compromise = data compromise.** SQLite is not encrypted at rest. Use full-disk encryption on the server and protect `data/` and its backups.
3. **The audit log is tamper-*evident*, not tamper-*proof*.** Someone with write access to the database can rebuild the whole chain. Copy backups off the box.
4. **Fingerprints are self-reported.** They catch a copied credential used on another machine, but an attacker with root on the enrolled machine can replay its fingerprint.
5. **UDP syslog is unauthenticated and cleartext.** Router events can be spoofed by a LAN attacker. Treat router-only findings accordingly.
6. **No MFA yet**, and no WebAuthn. Passwords are the only factor (on the roadmap).
7. **Self-signed TLS** relies on you distributing the certificate correctly. The dashboard browser will warn until you trust it.
8. **The stdlib HTTP server** is not a hardened internet-grade server. Never expose BLACKGUARD to the internet; use a VPN for remote access.
9. **Rate limits are in-memory** and reset on restart.
10. **Windows agent untested on Windows** in this environment; see TESTING.md.
11. **Detection coverage is limited** to the log sources and rules documented. Silence does not mean safety.

## Reporting a vulnerability

This is a private repository. Open a private issue or contact the owner directly. Do not include live credentials or private logs.

## Hardening checklist for your installation

- [ ] Server on full-disk-encrypted storage; `data/` owned by the service user only
- [ ] TLS enabled before any agent connects over the LAN; port never forwarded on the router
- [ ] Demo data removed (`BLACKGUARD_SEED_DEMO=0` for fresh installs)
- [ ] Separate analyst/viewer accounts for other household members
- [ ] Off-box backup copy scheduled
- [ ] Legacy ingest disabled and `data/access.json` deleted after migrating collectors
- [ ] Windows audit policy enables logon, account management and policy-change auditing
