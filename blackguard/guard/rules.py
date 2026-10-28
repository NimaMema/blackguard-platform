"""Transparent detection rules.

Each rule is deterministic, documents its logic, maps to MITRE ATT&CK where
the mapping is defensible, and ships investigation steps and false-positive
considerations. Thresholds are tunable per installation from the dashboard.
"""

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import timedelta

from guard.db import iso, parse_iso

LEVELS = ["low", "medium", "high", "critical"]
CONFIDENCE = ["low", "medium", "high"]
PRIVILEGED_GROUP_WORDS = ("admin", "sudo", "wheel", "root", "domain admins", "enterprise admins",
                          "backup operators", "remote desktop users", "schema admins", "account operators")


@dataclass
class Finding:
    rule_id: str
    group_key: str
    title: str
    summary: str
    evidence: list
    confidence: str
    reasons: list = field(default_factory=list)
    source_ip: str = ""
    actor: str = ""

    @property
    def hosts(self):
        return sorted({e["host"] for e in self.evidence})

    @property
    def first_seen(self):
        return min(e["timestamp"] for e in self.evidence)

    @property
    def last_seen(self):
        return max(e["timestamp"] for e in self.evidence)


@dataclass
class Param:
    name: str
    label: str
    default: int
    low: int
    high: int


class Rule:
    id = ""
    name = ""
    description = ""
    severity = "medium"
    confidence = "medium"
    event_types = ()
    mitre = ()
    params = ()
    investigation = ()
    false_positives = ()
    responses = ()  # keys into guard.response.ACTION_CATALOG

    def lookback(self, p):
        return timedelta(minutes=p.get("window_minutes", 60))

    def evaluate(self, events, p, ctx):
        raise NotImplementedError

    def describe(self, settings=None):
        settings = settings or {}
        values = {x.name: x.default for x in self.params}
        values.update(settings.get("params", {}))
        return {
            "id": self.id, "name": self.name, "description": self.description,
            "severity": settings.get("severity") or self.severity, "default_severity": self.severity,
            "confidence": self.confidence, "enabled": settings.get("enabled", True),
            "event_types": list(self.event_types),
            "mitre": [{"id": m[0], "name": m[1], "url": f"https://attack.mitre.org/techniques/{m[0].replace('.', '/')}/"} for m in self.mitre],
            "params": [{"name": x.name, "label": x.label, "value": values[x.name], "default": x.default, "min": x.low, "max": x.high}
                       for x in self.params],
            "investigation": list(self.investigation), "false_positives": list(self.false_positives),
            "responses": list(self.responses),
        }


def _ts(e):
    return parse_iso(e["timestamp"])


def sliding_clusters(events, window, threshold, measure=None):
    """Return clusters of events in which some ``window`` meets ``threshold``.

    ``measure`` maps an event to a value whose distinct count is compared to
    the threshold (e.g. distinct accounts); default counts events.
    Overlapping qualifying windows merge into one cluster.
    """
    events = sorted(events, key=lambda e: (e["timestamp"], e["id"]))
    hits = set()
    start = 0
    counter = Counter()
    for end, event in enumerate(events):
        counter[measure(event) if measure else event["id"]] += 1
        end_time = _ts(event)
        while end_time - _ts(events[start]) > window:
            key = measure(events[start]) if measure else events[start]["id"]
            counter[key] -= 1
            if counter[key] <= 0:
                del counter[key]
            start += 1
        if len(counter) >= threshold:
            hits.update(range(start, end + 1))
    clusters, current, last = [], [], None
    for index in sorted(hits):
        event = events[index]
        if current and (_ts(event) - last > window):
            clusters.append(current)
            current = []
        current.append(event)
        last = _ts(event)
    if current:
        clusters.append(current)
    return clusters


def _scaled_confidence(base, count, threshold, reasons):
    level = CONFIDENCE.index(base)
    if count >= threshold * 3 and level < 2:
        level += 1
        reasons.append(f"Volume ({count}) is at least three times the threshold ({threshold}).")
    return CONFIDENCE[level]


def _subject(e):
    return e["source_ip"] or (f"account {e['actor']}" if e["actor"] != "unknown" else "an unidentified source")


class BruteForce(Rule):
    id = "BG-AUTH-01"
    name = "Repeated authentication failures"
    description = ("At least N failed sign-ins against one host from one source IP (or, when the log has no IP, "
                   "for one account) within the window.")
    severity, confidence = "high", "medium"
    event_types = ("auth_failure",)
    mitre = (("T1110", "Brute Force"), ("T1110.001", "Password Guessing"))
    params = (Param("threshold", "Failures", 5, 2, 500), Param("window_minutes", "Window (minutes)", 10, 1, 1440))
    investigation = (
        "Identify the source: is the IP one of your own devices, a VPN, or an internet address?",
        "Check whether the targeted account exists and whether it is expected to sign in to this host.",
        "Look for a successful sign-in from the same source shortly after (see BG-AUTH-02).",
        "If the source is external, confirm the service should be reachable from the internet at all.",
    )
    false_positives = (
        "A user or script with a stale saved password retrying automatically.",
        "Several people behind one NAT address (shared home or office IP).",
        "Monitoring or backup jobs authenticating with expired credentials.",
    )
    responses = ("review_sessions", "review_exposure", "reset_credentials")

    def evaluate(self, events, p, ctx):
        groups = defaultdict(list)
        for e in events:
            if e["type"] == "auth_failure":
                key = e["source_ip"] or (f"user:{e['actor']}" if e["actor"] != "unknown" else "")
                if key:
                    groups[(e["host"], key)].append(e)
        window = timedelta(minutes=p["window_minutes"])
        findings = []
        for (host, key), items in groups.items():
            for cluster in sliding_clusters(items, window, p["threshold"]):
                reasons = [f"{len(cluster)} failures in {p['window_minutes']}-minute windows (threshold {p['threshold']})."]
                if not cluster[0]["source_ip"]:
                    reasons.append("The log did not record a source IP, so failures are grouped by account name instead.")
                conf = _scaled_confidence(self.confidence, len(cluster), p["threshold"], reasons)
                accounts = sorted({e["actor"] for e in cluster})
                findings.append(Finding(
                    self.id, f"{host}|{key}", self.name,
                    f"{len(cluster)} failed sign-ins from {_subject(cluster[0])} against {host} "
                    f"({', '.join(accounts[:5])}{'…' if len(accounts) > 5 else ''}).",
                    cluster, conf, reasons, cluster[0]["source_ip"], accounts[0] if len(accounts) == 1 else ""))
        return findings


class SuccessAfterFailures(Rule):
    id = "BG-AUTH-02"
    name = "Sign-in succeeded after repeated failures"
    description = "A successful sign-in preceded by at least N failures from the same source to the same host within the window."
    severity, confidence = "critical", "medium"
    event_types = ("auth_failure", "auth_success")
    mitre = (("T1110", "Brute Force"), ("T1078", "Valid Accounts"))
    params = (Param("threshold", "Prior failures", 3, 1, 200), Param("window_minutes", "Window (minutes)", 15, 1, 1440))
    investigation = (
        "Contact the account owner through a trusted channel: did they sign in at this time?",
        "Review what the session did after sign-in (processes, file access, new accounts, policy changes).",
        "Check whether the failures targeted the same account that succeeded, or several accounts.",
        "If the sign-in is not recognised, end the session and reset the credential through the provider's controls.",
    )
    false_positives = (
        "A legitimate user mistyping their password several times before succeeding.",
        "A device reconnecting after a password change once the new password is entered.",
    )
    responses = ("review_sessions", "reset_credentials", "investigate_device", "isolate_device")

    def evaluate(self, events, p, ctx):
        window = timedelta(minutes=p["window_minutes"])
        failures = defaultdict(list)
        successes = []
        for e in events:
            key = e["source_ip"] or (f"user:{e['actor']}" if e["actor"] != "unknown" else "")
            if not key:
                continue
            if e["type"] == "auth_failure":
                failures[(e["host"], key)].append(e)
            elif e["type"] == "auth_success":
                successes.append(((e["host"], key), e))
        findings = []
        for group, success in successes:
            when = _ts(success)
            prior = [f for f in failures[group] if timedelta(0) <= when - _ts(f) <= window]
            if len(prior) < p["threshold"]:
                continue
            same_account = sum(f["actor"] == success["actor"] for f in prior)
            reasons = [f"{len(prior)} failures preceded the success within {p['window_minutes']} minutes."]
            conf = self.confidence
            if same_account == len(prior):
                reasons.append("All failures targeted the same account that then succeeded.")
            else:
                reasons.append(f"Only {same_account} of the failures targeted the account that succeeded.")
            conf = _scaled_confidence(conf, len(prior), p["threshold"], reasons)
            findings.append(Finding(
                self.id, f"{group[0]}|{group[1]}", self.name,
                f"'{success['actor']}' signed in to {group[0]} from {_subject(success)} after {len(prior)} failed attempts.",
                prior + [success], conf, reasons, success["source_ip"], success["actor"]))
        return findings


class PasswordSpray(Rule):
    id = "BG-AUTH-03"
    name = "Password spraying pattern"
    description = "One source IP failing to sign in as at least N different accounts within the window, on any hosts."
    severity, confidence = "high", "medium"
    event_types = ("auth_failure",)
    mitre = (("T1110.003", "Password Spraying"),)
    params = (Param("threshold", "Distinct accounts", 4, 2, 200), Param("window_minutes", "Window (minutes)", 30, 1, 1440))
    investigation = (
        "List the targeted account names: are they real accounts, or guesses such as admin/root/test?",
        "Check every targeted account for successful sign-ins from the same source.",
        "Confirm whether the source address belongs to your network.",
    )
    false_positives = ("A misconfigured shared device (e.g., a printer or NAS) trying several stored accounts.",)
    responses = ("review_sessions", "review_exposure", "reset_credentials")

    def evaluate(self, events, p, ctx):
        groups = defaultdict(list)
        for e in events:
            if e["type"] == "auth_failure" and e["source_ip"]:
                groups[e["source_ip"]].append(e)
        findings = []
        for ip, items in groups.items():
            for cluster in sliding_clusters(items, timedelta(minutes=p["window_minutes"]), p["threshold"], lambda e: e["actor"]):
                accounts = sorted({e["actor"] for e in cluster})
                reasons = [f"{len(accounts)} distinct accounts targeted (threshold {p['threshold']})."]
                findings.append(Finding(self.id, ip, self.name,
                                        f"{ip} failed to sign in as {len(accounts)} different accounts: {', '.join(accounts[:8])}.",
                                        cluster, _scaled_confidence(self.confidence, len(accounts), p["threshold"], reasons),
                                        reasons, ip))
        return findings


class NewSourceForAccount(Rule):
    id = "BG-AUTH-05"
    name = "Sign-in from a source never seen for this account"
    description = ("A successful sign-in from a source IP never previously observed for the account, only once the "
                   "account has an established history (at least N prior successes spanning at least D days).")
    severity, confidence = "low", "low"
    event_types = ("auth_success",)
    mitre = (("T1078", "Valid Accounts"),)
    params = (Param("min_history", "Prior successes required", 10, 3, 10000),
              Param("min_days", "History span (days)", 7, 1, 365),
              Param("window_minutes", "Baseline lookback (minutes)", 43200, 1440, 525600))
    investigation = (
        "Ask the account owner whether they used a new device, network, or VPN.",
        "Check whether the new source also appears in other findings.",
    )
    false_positives = ("New phones/laptops, DHCP address changes, travel, or VPN exit changes.",
                       "This rule needs real history; it stays silent on new installations by design.")
    responses = ("review_sessions",)

    def lookback(self, p):
        return timedelta(minutes=5)

    def evaluate(self, events, p, ctx):
        findings = []
        for e in events:
            if e["type"] != "auth_success" or not e["source_ip"] or e["actor"] == "unknown" or e["mode"] == "demo":
                continue
            since = iso(_ts(e) - timedelta(minutes=p["window_minutes"]))
            history = ctx.db.one(
                "SELECT COUNT(*) AS n, MIN(timestamp) AS first, SUM(source_ip = ?) AS same FROM events "
                "WHERE type='auth_success' AND actor=? AND host=? AND timestamp >= ? AND timestamp < ? AND mode != 'demo'",
                (e["source_ip"], e["actor"], e["host"], since, e["timestamp"]))
            if not history or history["n"] < p["min_history"] or history["same"]:
                continue
            span = (_ts(e) - parse_iso(history["first"])).days
            if span < p["min_days"]:
                continue
            reasons = [f"{history['n']} earlier successful sign-ins over {span} days never used {e['source_ip']}."]
            findings.append(Finding(self.id, f"{e['host']}|{e['actor']}|{e['source_ip']}", self.name,
                                    f"'{e['actor']}' signed in to {e['host']} from {e['source_ip']} for the first time.",
                                    [e], self.confidence, reasons, e["source_ip"], e["actor"]))
        return findings


class SingleEventRule(Rule):
    """Raise on each matching event; events on the same host merge into one open incident."""
    summary_prefix = ""

    def matches(self, e, p):
        return e["type"] in self.event_types

    def evaluate(self, events, p, ctx):
        findings = []
        for e in events:
            if self.matches(e, p):
                findings.append(Finding(self.id, e["host"], self.name,
                                        f"{self.summary_prefix}{e['message']}", [e], self.confidence,
                                        [f"Matched event type '{e['type']}' reported by {e['source']}."],
                                        e["source_ip"], e["actor"]))
        return findings


class PrivilegeChange(SingleEventRule):
    id = "BG-IAM-01"
    name = "Privilege granted or privileged group changed"
    description = "A privilege change, or a membership change to an administrative group (admin, sudo, wheel, Domain Admins…)."
    severity, confidence = "high", "high"
    event_types = ("privilege_change", "group_membership_change")
    mitre = (("T1098", "Account Manipulation"), ("T1078.003", "Valid Accounts: Local Accounts"))
    investigation = (
        "Confirm who made the change (the 'actor') and whether it was planned.",
        "Review what the affected account has done since it gained privileges.",
        "If unapproved, remove the privilege through the system's normal administration tools and investigate the actor's account.",
    )
    false_positives = ("Software installers and OS updates adding service accounts to groups.", "Planned administration by you.")
    responses = ("review_account", "investigate_device")

    def matches(self, e, p):
        if e["type"] == "privilege_change":
            return True
        if e["type"] == "group_membership_change":
            group = str(e["details"].get("group", "") or e["target"]).lower()
            return any(word in group for word in PRIVILEGED_GROUP_WORDS)
        return False


class AccountCreated(SingleEventRule):
    id = "BG-IAM-02"
    name = "New account created"
    description = "A local or domain user account was created."
    severity, confidence = "medium", "high"
    event_types = ("account_created",)
    mitre = (("T1136.001", "Create Account: Local Account"), ("T1136.002", "Create Account: Domain Account"))
    investigation = ("Confirm the account was intentionally created and by whom.",
                     "Check the new account's group memberships and sign-in activity.")
    false_positives = ("Software that creates service accounts during installation.", "Planned user creation.")
    responses = ("review_account",)


class AccountStateChange(SingleEventRule):
    id = "BG-IAM-03"
    name = "Account deleted, enabled or password reset"
    description = "An account was deleted or re-enabled, or its password was reset by someone else."
    severity, confidence = "low", "high"
    event_types = ("account_deleted", "account_enabled", "password_reset")
    mitre = (("T1098", "Account Manipulation"), ("T1531", "Account Access Removal"))
    investigation = ("Confirm the change was expected.", "For a password reset, verify the person who performed it was authorised.")
    false_positives = ("Routine administration and self-service password changes.",)
    responses = ("review_account",)

    def matches(self, e, p):
        if e["type"] == "password_reset":
            return e["target"] and e["actor"] != "unknown" and e["target"].lower() != e["actor"].lower()
        return e["type"] in self.event_types


class AccountLockout(SingleEventRule):
    id = "BG-AUTH-04"
    name = "Account locked out"
    description = "An account was locked after too many failed sign-ins."
    severity, confidence = "medium", "high"
    event_types = ("account_locked",)
    mitre = (("T1110", "Brute Force"),)
    investigation = ("Find the failed sign-ins that caused the lockout and their source.",
                     "Confirm with the account owner before unlocking.")
    false_positives = ("A device with a stale saved password.",)
    responses = ("review_sessions", "reset_credentials")


class PolicyChange(SingleEventRule):
    id = "BG-CFG-01"
    name = "Security policy modified"
    description = "Audit, account or domain security policy was changed."
    severity, confidence = "medium", "high"
    event_types = ("policy_change",)
    mitre = (("T1562.002", "Impair Defenses: Disable Windows Event Logging"), ("T1484", "Domain or Tenant Policy Modification"))
    investigation = ("Compare the change with your expected security baseline.",
                     "Check whether auditing was reduced — that can hide later activity.")
    false_positives = ("Windows updates, group policy refresh, or intentional hardening.",)
    responses = ("review_configuration",)


class AuditLogCleared(SingleEventRule):
    id = "BG-CFG-02"
    name = "Audit log cleared"
    description = "A security or system audit log was cleared."
    severity, confidence = "high", "high"
    event_types = ("audit_log_cleared",)
    mitre = (("T1070.001", "Indicator Removal: Clear Windows Event Logs"),)
    investigation = ("Identify who cleared the log and whether it was planned maintenance.",
                     "Treat surrounding activity on this host as higher priority: evidence may be missing.",
                     "Use BLACKGUARD's stored copy of earlier events to reconstruct the timeline.")
    false_positives = ("Deliberate log maintenance by an administrator.",)
    responses = ("investigate_device", "isolate_device")


class ServiceInstalled(SingleEventRule):
    id = "BG-SVC-01"
    name = "New service installed"
    description = "A new system service was installed."
    severity, confidence = "medium", "medium"
    event_types = ("service_installed",)
    mitre = (("T1543.003", "Create or Modify System Process: Windows Service"),)
    investigation = ("Check the service name and executable path; is it signed software you installed?",
                     "Look up the executable hash with your antivirus tooling.")
    false_positives = ("Driver, antivirus, and software updates install services frequently.",)
    responses = ("investigate_device",)


class DeviceConfigChange(SingleEventRule):
    id = "BG-CFG-03"
    name = "Router or firewall configuration changed"
    description = "A network device reported that its configuration was changed or saved."
    severity, confidence = "low", "medium"
    event_types = ("config_change",)
    mitre = (("T1562.004", "Impair Defenses: Disable or Modify System Firewall"),)
    investigation = ("Confirm you or another administrator changed the router configuration at that time.",
                     "Review port-forwarding, remote-administration and DNS settings for unexpected changes.")
    false_positives = ("Firmware updates and your own configuration changes.",)
    responses = ("review_configuration", "review_exposure")


class FirewallBurst(Rule):
    id = "BG-NET-01"
    name = "Burst of firewall denials"
    description = "At least N denied connections from one source IP within the window."
    severity, confidence = "low", "medium"
    event_types = ("network_block",)
    mitre = (("T1595", "Active Scanning"),)
    params = (Param("threshold", "Denials", 20, 2, 100000), Param("window_minutes", "Window (minutes)", 10, 1, 1440))
    investigation = ("Is the source internal (one of your devices) or on the internet?",
                     "For an internal source, find out which program is attempting the blocked connections.",
                     "Internet background scanning is constant; prioritise only if paired with other findings.")
    false_positives = ("Internet-wide scanners hit every public IP continuously.",
                       "Misconfigured internal devices (smart TVs, IoT) retrying blocked destinations.")
    responses = ("review_exposure", "investigate_device")

    def evaluate(self, events, p, ctx):
        groups = defaultdict(list)
        for e in events:
            if e["type"] == "network_block" and e["source_ip"]:
                groups[e["source_ip"]].append(e)
        findings = []
        for ip, items in groups.items():
            for cluster in sliding_clusters(items, timedelta(minutes=p["window_minutes"]), p["threshold"]):
                reasons = [f"{len(cluster)} denials (threshold {p['threshold']})."]
                findings.append(Finding(self.id, ip, self.name,
                                        f"{len(cluster)} connections from {ip} were denied by {', '.join(sorted({e['host'] for e in cluster}))}.",
                                        cluster, _scaled_confidence(self.confidence, len(cluster), p["threshold"], reasons),
                                        reasons, ip))
        return findings


class PortScan(Rule):
    id = "BG-NET-02"
    name = "Port-scan pattern"
    description = "Denied connections from one source to at least N distinct destination ports within the window."
    severity, confidence = "medium", "medium"
    event_types = ("network_block",)
    mitre = (("T1046", "Network Service Discovery"), ("T1595.001", "Active Scanning: Scanning IP Blocks"))
    params = (Param("threshold", "Distinct ports", 10, 3, 65535), Param("window_minutes", "Window (minutes)", 5, 1, 1440))
    investigation = ("If the source is internal, a device on your network may be compromised or running discovery software.",
                     "If external, verify that no unexpected ports are forwarded on your router.")
    false_positives = ("Network inventory tools and some games/peer-to-peer apps.",)
    responses = ("review_exposure", "investigate_device", "isolate_device")

    def evaluate(self, events, p, ctx):
        groups = defaultdict(list)
        for e in events:
            if e["type"] == "network_block" and e["source_ip"] and e["dest_port"] is not None:
                groups[e["source_ip"]].append(e)
        findings = []
        for ip, items in groups.items():
            measure = lambda e: (e["dest_ip"], e["dest_port"])
            for cluster in sliding_clusters(items, timedelta(minutes=p["window_minutes"]), p["threshold"], measure):
                ports = sorted({e["dest_port"] for e in cluster})
                reasons = [f"{len(ports)} distinct destination ports probed (threshold {p['threshold']})."]
                internal = ctx.is_private(ip)
                if internal:
                    reasons.append("The source is a private (internal) address, which is more unusual than internet scanning.")
                findings.append(Finding(self.id, ip, self.name,
                                        f"{ip} was denied on {len(ports)} ports ({', '.join(map(str, ports[:12]))}{'…' if len(ports) > 12 else ''}).",
                                        cluster, "high" if internal else self.confidence, reasons, ip))
        return findings


class CrossDevice(Rule):
    id = "BG-CORR-01"
    name = "Related suspicious activity across devices"
    description = ("The same source IP or account produced failed sign-ins or lockouts on at least N different "
                   "devices within the window.")
    severity, confidence = "high", "medium"
    event_types = ("auth_failure", "account_locked")
    mitre = (("T1110", "Brute Force"), ("T1021", "Remote Services"))
    params = (Param("threshold", "Distinct devices", 2, 2, 100), Param("window_minutes", "Window (minutes)", 60, 5, 1440))
    investigation = ("Build a timeline across the affected devices: which was targeted first?",
                     "If the source is one of your own devices, investigate that device first — it may be compromised.",
                     "Check each affected device for successful sign-ins from the same source.")
    false_positives = ("A password manager or sync tool with a stale password on several devices.",)
    responses = ("investigate_device", "review_sessions", "reset_credentials", "isolate_device")

    def evaluate(self, events, p, ctx):
        groups = defaultdict(list)
        for e in events:
            if e["type"] in self.event_types:
                if e["source_ip"]:
                    groups[f"ip:{e['source_ip']}"].append(e)
                if e["actor"] not in ("unknown", "", "-"):
                    groups[f"user:{e['actor'].lower()}"].append(e)
        findings = []
        for key, items in groups.items():
            for cluster in sliding_clusters(items, timedelta(minutes=p["window_minutes"]), p["threshold"], lambda e: e["host"]):
                hosts = sorted({e["host"] for e in cluster})
                kind, value = key.split(":", 1)
                reasons = [f"{len(hosts)} devices affected by the same {'source IP' if kind == 'ip' else 'account'}."]
                findings.append(Finding(self.id, key, self.name,
                                        f"{'Source' if kind == 'ip' else 'Account'} {value} caused failures on {len(hosts)} devices: {', '.join(hosts)}.",
                                        cluster, _scaled_confidence(self.confidence, len(hosts), p["threshold"], reasons), reasons,
                                        value if kind == "ip" else "", value if kind == "user" else ""))
        return findings


class CollectorHealth(Rule):
    """Raised from server-generated collector notices (offline, identity mismatch, data loss)."""
    kind = ""

    @property
    def kinds(self):
        return (self.kind,)

    def evaluate(self, events, p, ctx):
        findings = []
        for e in events:
            if e["type"] == "collector_notice" and e["details"].get("kind") in self.kinds and e["trust"] == "server":
                if e["details"].get("kind") == "agent_recovered" and not ctx.db.scalar(
                        "SELECT 1 FROM incidents WHERE rule_id=? AND group_key=? AND status != 'resolved'",
                        (self.id, e["details"].get("agent_id", ""))):
                    continue  # recovery is evidence for an open outage, never a new incident on its own
                findings.append(Finding(self.id, e["details"].get("agent_id", e["host"]), self.name, e["message"], [e],
                                        self.confidence, ["Generated by the BLACKGUARD server from its own agent records."]))
        return findings


class CollectorOffline(CollectorHealth):
    id, kind = "BG-HEALTH-01", "agent_offline"
    kinds = ("agent_offline", "agent_recovered")  # the recovery notice joins the open outage incident as evidence
    name = "Collector stopped reporting"
    description = "An approved agent missed its heartbeats for longer than its offline threshold."
    severity, confidence = "medium", "high"
    event_types = ("collector_notice",)
    investigation = ("Check that the device is powered on and connected.",
                     "Check the agent's local log and spool status (`bgagent.py status`).",
                     "An attacker may stop a collector to avoid detection; review the device's last events.")
    false_positives = ("The device was shut down, asleep, or rebooting.",)
    responses = ("investigate_device",)


class IdentityMismatch(CollectorHealth):
    id, kind = "BG-HEALTH-02", "identity_mismatch"
    name = "Agent identity mismatch"
    description = "An agent credential was used from a machine whose fingerprint differs from the approved one."
    severity, confidence = "high", "medium"
    event_types = ("collector_notice",)
    investigation = ("Was the agent reinstalled or the machine re-imaged? If so, re-approve its identity.",
                     "Otherwise assume the credential was copied: revoke the agent and re-enroll.")
    false_positives = ("OS reinstall or hardware change on the agent's machine.",)
    responses = ("revoke_agent", "investigate_device")


class CollectorDataLoss(CollectorHealth):
    id, kind = "BG-HEALTH-03", "data_loss"
    name = "Collector dropped events"
    description = "An agent reported that its local buffer overflowed and events were discarded."
    severity, confidence = "medium", "high"
    event_types = ("collector_notice",)
    investigation = ("Check why the agent could not reach the server for an extended period.",
                     "Consider raising the agent's spool limit.")
    false_positives = ("Long planned server downtime.",)
    responses = ("investigate_device",)


class NewDevice(CollectorHealth):
    id, kind = "BG-DEV-01", "new_device"
    name = "New device joined the network"
    description = ("A device never seen before appeared in a collector's ARP/neighbour cache or a router DHCP lease, "
                   "after the collector's 24-hour learning period.")
    severity, confidence = "low", "high"
    event_types = ("collector_notice",)
    mitre = (("T1200", "Hardware Additions"),)
    investigation = ("Identify the device from its hostname, MAC address and when it joined.",
                     "If you recognise it, mark it as known in Device inventory.",
                     "If you do not, change your Wi-Fi password through your router's admin interface and review connected clients.")
    false_positives = ("Guests, new purchases, and phones using randomised (private) MAC addresses.",)
    responses = ("review_unknown_device",)


RULES = [BruteForce(), SuccessAfterFailures(), PasswordSpray(), AccountLockout(), NewSourceForAccount(),
         PrivilegeChange(), AccountCreated(), AccountStateChange(), PolicyChange(), AuditLogCleared(),
         DeviceConfigChange(), ServiceInstalled(), FirewallBurst(), PortScan(), CrossDevice(),
         CollectorOffline(), IdentityMismatch(), CollectorDataLoss(), NewDevice()]
RULES_BY_ID = {r.id: r for r in RULES}
