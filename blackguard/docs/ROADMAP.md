# Roadmap

Two horizons: **now** — a polished, honest, experimental open-source release; **later** — commercial development (see [PRODUCTION_READINESS.md](PRODUCTION_READINESS.md) for the technical-debt list and commercial sequence).

## Done for the public showcase

Interactive zero-install demo, landing page, screenshots/video, global search, onboarding, accessibility checks (axe, WCAG 2.2 A/AA), how-it-works documentation, contributor and security policies, licensing notes. Milestone A reliability work (outage classification, graceful shutdown, verified backups, diagnostics, Windows server installer).

## Done in v0.5

Individual accounts and roles, sessions, CSRF, rate limiting and audit log; per-agent enrollment, approval, rotation and revocation; durable agents for Linux auth, journald, syslog, JSONL and Windows; inventory with provenance; 19 ATT&CK-mapped rules with confidence reasoning; an evidence-linked incident workspace; the approval-gated Guardian Response; migrations, backups, restore and retention; TLS; Docker and systemd; the optional local AI analyst; CI that actually runs.

## Next (highest value first)

1. **Windows agent validation** on real Windows 10/11 machines: audit-policy checks and an installer.
2. **MFA**: TOTP first, then WebAuthn/passkeys for administrators.
3. **Notifications** beyond the open browser tab: email via the user's own SMTP, ntfy or Gotify, with severity filters.
4. **Authorised response integrations** behind the existing `Integration` interface, for example moving a device to a guest VLAN through a router API (OpenWrt ubus, UniFi, pfSense). Each will come with plan/execute/rollback, admin approval and impact text. Never automatic.
5. **More parsers**: UniFi, ASUS/Merlin, TP-Link Omada; macOS unified log; Sysmon on Windows.
6. **Detection-as-data**: export and import rule packs as versioned JSON; Sigma-subset import for simple single-event rules.
7. **Statistical baselining** for sign-in times and volumes per device, with explicit uncertainty.
8. **Site management UI**: multiple households or offices, invites scoped to a site.
9. **Organisation isolation and a PostgreSQL storage adapter** for business deployments.
10. **Mutual-TLS or tunnel-based remote collectors** for sites without inbound connectivity.
11. **Encrypted backups** (age/GPG) and scheduled off-box copies.
12. **Independent security review** before any business use.
