"""Bounded Markdown/JSON investigation exports with optional pseudonymisation."""

import json
import secrets

from guard.db import iso
from guard.response import guidance
from guard.security import pseudonymize

CAVEAT = ("Heuristic findings are leads, not confirmed compromises. BLACKGUARD has not executed firewall changes, "
          "blocks, account resets or any other defensive action.")


def clean(value, limit=500):
    return " ".join(str(value if value is not None else "").replace("\x00", "").replace("|", "/").split())[:limit]


class Anonymizer:
    def __init__(self, enabled):
        self.enabled = enabled
        self.salt = secrets.token_hex(16)

    def __call__(self, value):
        return pseudonymize(value, self.salt) if self.enabled and value and value != "unknown" else value


def incident_markdown(detail, anon, lines):
    lines += [
        f"### Incident {detail['id']}: {clean(detail['title'])}", "",
        f"- Rule: {clean(detail['rule_id'])} — {clean(detail['rule_name'])}",
        f"- Severity: {clean(detail['severity'])} · Confidence: {clean(detail['confidence'])} · Status: {clean(detail['status'])}",
        f"- Dataset: {clean(detail['mode'])}",
        f"- First / last evidence: {clean(detail['first_seen'])} → {clean(detail['last_seen'])}",
        f"- Affected devices: {', '.join(clean(anon(h)) for h in detail['affected_hosts']) or 'N/A'}",
        f"- Source IPs: {', '.join(clean(anon(ip)) for ip in detail.get('source_ips', [])) or 'N/A'}",
        f"- Accounts: {', '.join(clean(anon(a)) for a in detail.get('accounts', [])) or 'N/A'}",
        f"- Summary: {clean(detail['summary'])}" if not anon.enabled else "- Summary: (omitted in pseudonymised export)",
        f"- Confidence reasoning: {clean(detail['confidence_reason'], 1500)}",
    ]
    if detail.get("rule") and detail["rule"]["mitre"]:
        lines.append("- MITRE ATT&CK: " + ", ".join(f"{m['id']} {m['name']}" for m in detail["rule"]["mitre"]))
    advice = guidance(detail["rule_id"])
    lines += ["", "**Investigation steps**", ""] + [f"1. {clean(s)}" for s in advice["investigation"]]
    lines += ["", "**False-positive considerations**", ""] + [f"- {clean(s)}" for s in advice["false_positives"]]
    lines += ["", "**Recommended (human-performed) responses**", ""] + [f"- {clean(a)}" for a in advice["actions"]]
    if detail.get("responses"):
        lines += ["", "**Response actions recorded**", ""]
        lines += [f"- #{r['id']} {clean(r['title'])}: {clean(r['status'])}" for r in detail["responses"]]
    lines += ["", "**Timeline**", "", "| Time (UTC) | Kind | Host | Detail |", "| --- | --- | --- | --- |"]
    for item in detail["timeline"][:500]:
        text = item["text"] if not anon.enabled or item["kind"] != "event" else item.get("type", "event")
        lines.append(f"| {clean(item['at'])} | {clean(item['kind'])} | {clean(anon(item.get('host', '')))} | {clean(text, 300)} |")
    lines.append("")


def render_markdown(app, incident_ids=None, pseudonymize_identifiers=False, event_limit=500):
    anon = Anonymizer(pseudonymize_identifiers)
    incidents = app.incidents.list(limit=1000) if incident_ids is None else [app.incidents.get(i) for i in incident_ids]
    incidents = [i for i in incidents if i]
    stats = app.overview()["stats"]
    lines = [
        "# BLACKGUARD — Investigation report", "",
        f"Generated: {iso()}",
        f"Dataset: {clean(stats['dataset_label'])}",
        f"Pseudonymised identifiers: {'yes' if anon.enabled else 'no'}",
        "", f"**Important:** {CAVEAT} This document may contain account names, IP addresses and log text; store it securely.",
        "", "## Overview", "",
        f"- Events stored: {stats['total_events']} (live {stats['live_events']}, imported {stats['imported_events']}, demo {stats['demo_events']})",
        f"- Active incidents: {stats['incidents_active']}",
        f"- Agents: {stats['agents_online']} online of {stats['agents_active']} approved",
        "", "## Findings", "",
    ]
    if not incidents:
        lines += ["No findings recorded.", ""]
    for incident in incidents:
        incident_markdown(app.incidents.detail(incident["id"], app.responses.list(incident_id=incident["id"])), anon, lines)
    if incident_ids is None and event_limit:
        lines += [f"## Recent evidence (maximum {event_limit} records)", "",
                  "| Time (UTC) | Type | Host | Source IP | Origin | Message |", "| --- | --- | --- | --- | --- | --- |"]
        for e in app.events.search(limit=event_limit)["events"]:
            message = e["type"] if anon.enabled else e["message"]
            lines.append(f"| {clean(e['timestamp'])} | {clean(e['type'])} | {clean(anon(e['host']))} | "
                         f"{clean(anon(e['source_ip']))} | {clean(e['mode'])}/{clean(e['trust'])} | {clean(message, 300)} |")
    lines += ["", "## Scope and caveats", "", CAVEAT,
              "Reports do not establish attribution. Verify findings against the original systems before acting.", ""]
    return "\n".join(lines)


def render_json(app, incident_id):
    detail = app.incidents.detail(incident_id, app.responses.list(incident_id=incident_id))
    if not detail:
        return None
    detail["guidance"] = guidance(detail["rule_id"])
    return json.dumps({"generated": iso(), "caveat": CAVEAT, "incident": detail}, indent=2, default=str)
