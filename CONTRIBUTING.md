# Contributing to BLACKGUARD

Thanks for your interest! BLACKGUARD is an experimental, security-sensitive project, so changes favour clarity, tests and honesty over features.

## Ground rules

- **Defensive only.** No offensive tooling, scanning of networks you don't own, counter-attacks, covert monitoring or credential attacks.
- **Never weaken security controls** (CSP, CSRF, authentication, approval gates) to make something easier.
- **Don't fabricate.** Demo data must be synthetic and labelled; docs must not claim untested capabilities.
- **No secrets or personal data** in code, tests, screenshots or issues. Use RFC 5737 addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and locally administered MACs (`02:…`).

## Development setup

```bash
cd blackguard
python3 start.py                                   # dev server on 127.0.0.1:8000
python3 -m unittest discover -s tests -v           # Python tests (no dependencies)
python3 scripts/secret_scan.py                     # tracked-file secret scan
npm install --no-save playwright@1.48.2 axe-core@4.10.2 && npx playwright install chromium
node tests/e2e/dashboard.e2e.js                    # real-server browser test + accessibility
python3 scripts/build_showcase.py && node tests/e2e/showcase.e2e.js   # static demo test
```

Read [How it works](blackguard/docs/HOW_IT_WORKS.md) and [Architecture](blackguard/docs/ARCHITECTURE.md) first.

## Pull requests

1. Keep each PR focused; include tests for behaviour changes (detection rules need positive *and* negative cases).
2. Run the checks above; CI must be green.
3. If you change `web/`, rebuild the demo (`python3 scripts/build_showcase.py`); CI fails if the demo copies drift.
4. Sign off your commits (`git commit -s`) to certify the [Developer Certificate of Origin](https://developercertificate.org/).
5. Describe what you tested — and what you couldn't (e.g. Windows-only code).

## Good first contributions

Parsers for additional router/firewall log formats (with sanitized samples), rule tuning backed by datasets, accessibility improvements, documentation, and translations of operator guidance.

Report security vulnerabilities privately — see [SECURITY.md](SECURITY.md), not public issues.
