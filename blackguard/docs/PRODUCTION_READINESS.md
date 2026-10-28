# Production readiness: technical debt and the commercial horizon

BLACKGUARD today is an **experimental, single-household** platform. This document lists, honestly, what stands between it and a product a business could rely on. It is a plan, not a claim.

## Known technical debt

| Area | Debt | Why it matters | Suggested direction |
| --- | --- | --- | --- |
| HTTP server | Python `ThreadingHTTPServer`: one thread per connection, no HTTP/2, not hardened for hostile internet traffic | Fine on a LAN behind TLS; not suitable for exposure or high concurrency | Move the API behind a hardened ASGI stack (or a reverse proxy) once there is a need; keep the stdlib build for home use |
| Storage | Single SQLite file (WAL); detection loads events into memory per window | Scales to a household or small office, not to fleets | A storage adapter for PostgreSQL; time-partitioned event tables; streaming rule evaluation |
| Multi-tenancy | `org_id`/`site_id` exist in the schema but are not enforced in queries or the UI | Needed before more than one organisation shares a server | Enforce scoping in the service layer; site and organisation management UI; per-org roles |
| Authentication | Passwords only; no MFA, SSO or WebAuthn | Expected by any business buyer | TOTP, then WebAuthn/passkeys, then OIDC/SAML SSO |
| Rate limits and sessions | In-memory rate limiter; sessions in SQLite | Reset on restart; single node only | Shared store when scaling out |
| Secrets at rest | The database (password hashes, logs) is not encrypted at rest | Disk theft exposes data | Document full-disk encryption (now); optional encrypted backups (age/GPG); key management for hosted versions |
| Audit log | Hash chain is tamper-*evident*, stored with the data it protects | An admin with database access could rewrite it | Periodic off-box anchoring (signed export, append-only storage) |
| Frontend | Single ~1,060-line vanilla-JS file; no component tests | Harder for many contributors | Split into modules; component and unit tests; keep zero-build if possible |
| Windows agent | PowerShell script, CI-parsed; validated manually on one machine | Not fleet-tested; no signed installer | Signed MSI or service wrapper; test matrix across Windows 10/11/Server |
| Detection | 19 heuristic rules; no statistical baselining, no threat intelligence, no Sigma import | Coverage and tuning are limited | Detection-as-data rule packs, Sigma-subset import, baselining, a precision/recall evaluation harness |
| Responses | Manual integration only | No automated containment | Vendor integrations behind the existing approval workflow, each with security and rollback testing |
| Observability | Log file and health page; no metrics endpoint | Hard to monitor at scale | Prometheus-style metrics; structured logs |
| Testing | No soak or load tests; no fuzzing of parsers | Unknown behaviour under sustained load or hostile input | Multi-day soak, load benchmarks, parser fuzzing |
| Assurance | No independent security review, penetration test or certification | Required before any customer relies on it | External pentest; threat-model review; secure SDLC documentation; later SOC 2 / ISO 27001 if a hosted service is offered |

## Commercial roadmap (proposed order)

1. **Hardening for the public release (now):** keep CI green, act on community security reports, finish validating the Windows agent, and add MFA.
2. **Network visibility:** vendor-specific router adapters (OpenWrt, UniFi, pfSense/OPNsense, MikroTik) validated on real hardware; DNS and DHCP insights; an optional, explicitly authorised and scoped discovery mode.
3. **Detection engineering:** rule packs as versioned data, Sigma import, baselining, an evaluation harness with labelled datasets, and published precision figures.
4. **Defensive integrations:** the first approved automation (for example moving a device to a guest VLAN through a router API) with plan, execute, verify and rollback, under the existing approval and audit workflow.
5. **Scale and multi-tenancy:** a PostgreSQL adapter, site and organisation isolation, fleet health, centralised rule management, and remote collectors over mutual TLS or tunnels.
6. **Enterprise features:** SSO, granular RBAC, data-retention policies per tenant, reporting, and an API for integrations.
7. **Assurance:** an external penetration test before any paid offering; compliance work only when a hosted service exists.

Principle: **do not add enterprise complexity to the home edition before it is needed.** Each step above lands behind interfaces that already exist (storage access in `guard/db.py`, `guard/response.py:Integration`, `org_id`/`site_id` columns, and permission-checked routes).
