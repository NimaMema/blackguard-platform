# Changelog

All notable changes. BLACKGUARD is experimental; versions are development milestones, not stability guarantees.

## Unreleased — public showcase & 24/7 reliability

**Showcase and usability**
- Zero-install interactive demo (`showcase/demo/`): the real dashboard on synthetic data processed by the real engine; offline (`connect-src 'none'`), clearly ribboned, nothing saved.
- Public landing page (`showcase/index.html`), social preview / LinkedIn images, screenshots and a recorded walkthrough, all reproducible from scripts.
- Dashboard: global search (`/` shortcut, keyboard navigable), time-range presets, sortable ledger columns, first-run onboarding checklist, loading states, skip link, focus restore, reduced-motion support, contrast fixes, experimental labelling.
- Accessibility: axe-core WCAG 2.2 A/AA checks on every view in CI.
- Docs: How it works, LinkedIn package, licensing/commercial-use notes, production-readiness plan, CONTRIBUTING, Code of Conduct, SECURITY policy.

**Reliability (Milestone A)**
- Outage classification (device restarted / agent stopped / server unreachable / unexplained); no false offline alerts after server downtime; server downtime recorded.
- Graceful shutdown (SIGTERM, `start.py stop` on Windows), `/healthz`, verified backups, health warnings, `start.py diagnose` and `verify-backup`, `.env` loading, rotating log file, Windows server installer.
- Chaos test: exactly-once storage across server restarts and lost acknowledgements.

## v0.5 — secure platform foundation
Individual accounts and roles, per-agent enrollment with approval, durable agents for Windows/Linux/syslog, 19 ATT&CK-mapped rules, evidence-linked incidents, Guardian Response approvals, hash-chained audit log, migrations and backups, TLS, Docker, CI.

## v0.4 and earlier
Prototype: shared-token collectors, five rules, Markdown reports.
