# Security policy

BLACKGUARD is **experimental** and has **not been independently security-reviewed or certified**. Please run it on networks you control, keep it off the public internet, and read the [security model and known risks](blackguard/docs/SECURITY.md).

## Reporting a vulnerability

Please report privately — **do not open a public issue**:

1. Use GitHub's **Report a vulnerability** button (Security → Advisories) on the repository, or
2. contact the maintainer (@NimaMema) through GitHub to arrange a private channel.

Include affected version/commit, reproduction steps and impact. Never include real credentials or private logs; sanitized samples are fine.

What to expect: acknowledgement within 7 days, an assessment and fix plan as soon as practical, and credit in the changelog if you wish. There is no bug bounty.

## Supported versions

Only the latest `main` receives fixes during the experimental phase.

## Scope

In scope: the server, agents, dashboard, showcase demo and deployment scripts in this repository. Out of scope: issues requiring an already-compromised server or administrator account, and denial-of-service against a server deliberately exposed to the internet against the documentation.
