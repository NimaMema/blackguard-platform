# Detection rules

Every rule is deterministic Python in `guard/rules.py`, with no opaque scoring. Thresholds and severities can be tuned under **Detection rules**; every change is audited. After tuning, run a sweep to re-evaluate stored events.

**Confidence** starts at the rule's base level. It rises one level when a threshold is exceeded three times over. It falls one level when all evidence comes from unverified sources (manual import or the legacy token). Each incident stores the reasoning in plain language.

| ID | Name | Logic (defaults) | Severity | ATT&CK |
| --- | --- | --- | --- | --- |
| BG-AUTH-01 | Repeated authentication failures | ≥5 failures, same host + source IP (or account if no IP), within 10 min | high | T1110, T1110.001 |
| BG-AUTH-02 | Sign-in succeeded after repeated failures | Success preceded by ≥3 failures from the same source within 15 min | critical | T1110, T1078 |
| BG-AUTH-03 | Password spraying | One IP failing as ≥4 distinct accounts within 30 min, any host | high | T1110.003 |
| BG-AUTH-04 | Account locked out | Lockout event | medium | T1110 |
| BG-AUTH-05 | First-seen source for an account | Success from an IP never seen for that account on that host, only after ≥10 successes spanning ≥7 days (silent on new installs) | low | T1078 |
| BG-IAM-01 | Privilege granted / privileged group changed | `privilege_change`, or membership change to admin/sudo/wheel/Domain Admins/… | high | T1098, T1078.003 |
| BG-IAM-02 | New account created | Account creation | medium | T1136.001/.002 |
| BG-IAM-03 | Account deleted, enabled or reset by someone else | Deletion/enable, or password reset where actor ≠ target | low | T1098, T1531 |
| BG-CFG-01 | Security policy modified | Audit or domain policy change | medium | T1562.002, T1484 |
| BG-CFG-02 | Audit log cleared | Security/System log cleared | high | T1070.001 |
| BG-CFG-03 | Router/firewall configuration changed | Device reports a config change | low | T1562.004 |
| BG-SVC-01 | New service installed | Windows 4697/7045 | medium | T1543.003 |
| BG-NET-01 | Burst of firewall denials | ≥20 denials from one IP within 10 min | low | T1595 |
| BG-NET-02 | Port-scan pattern | ≥10 distinct destination ports denied for one source within 5 min; confidence *high* when the source is internal | medium | T1046, T1595.001 |
| BG-CORR-01 | Related suspicious activity across devices | Same IP or account causing failures/lockouts on ≥2 devices within 60 min | high | T1110, T1021 |
| BG-HEALTH-01 | Collector stopped reporting | Approved agent silent longer than its threshold (default 3 min) | medium | — |
| BG-HEALTH-02 | Agent identity mismatch | Credential used with a different machine fingerprint; agent suspended | high | — |
| BG-HEALTH-03 | Collector dropped events | Agent reports spool overflow | medium | — |
| BG-DEV-01 | New device joined the network | Device absent from inventory appears in ARP/DHCP after a 24 h learning period | low | T1200 |

## Evidence and grouping

Threshold rules use two-pointer sliding windows. Overlapping qualifying windows merge into one cluster, and each cluster becomes a finding. Single-event rules group by host. New evidence joins an **open** incident for the same rule and group if the open incident saw activity within the last 24 hours. Otherwise a new incident is opened. A resolved incident is never silently reused.

## Validation

`tests/test_detection.py` covers each rule's positive and negative cases. It also runs three realistic datasets in `tests/fixtures/`, rendered with timestamps relative to the current time:

- `auth_attack.log.tmpl`: an SSH brute force with duplicate PAM and invalid-user lines, a spray, a successful sign-in, a backdoor account and a sudo-group grant. Expected: BG-AUTH-01/02/03 and BG-IAM-01/02.
- `auth_benign.log.tmpl`: three days of normal use (typos, sudo, own password change, a single UFW block). Expected: **no medium/high/critical** findings, which is the false-positive check.
- `router_syslog.tmpl`: an OpenWrt port scan, dropbear guessing from an internal host, DHCP leases, pfSense filterlog, MikroTik login and config changes.

These fixtures were written by hand in the real formats; they are not captures from a real attack. Before relying on a rule, tune it against your own environment's normal activity.

## Known gaps

- No process lineage, file-integrity or EDR telemetry; the Windows agent reads only the IDs listed in DEPLOYMENT.md.
- No threat-intelligence feeds by design (local-first). An IP's reputation is not considered.
- Syslog has no authentication; a LAN attacker could spoof router messages.
- BG-AUTH-05 is basic baselining, not statistical anomaly detection.
