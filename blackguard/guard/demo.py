"""Clearly fictional security events for a safe offline demonstration.

Addresses come from documentation ranges (RFC 5737 / private), hosts are
invented, and every record is stored with mode='demo' and trust='demo'.
"""

import secrets
from datetime import datetime, timedelta, timezone


def event(kind, host, ip, actor, message, minutes_ago, **extra):
    item = {
        "type": kind, "host": host, "source_ip": ip, "actor": actor, "message": message,
        "timestamp": (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat(timespec="seconds"),
    }
    item.update(extra)
    return item


def initial_events():
    items = []
    for minutes in range(75, 4, -6):
        items.append(event("auth_success", "demo-nas", "192.168.50.15", "media", "Demo: SMB sign-in by media account", minutes))
    for minutes in (46, 45, 44, 43, 42, 41):
        items.append(event("auth_failure", "demo-bastion", "192.0.2.44", "admin", "Demo: SSH password rejected", minutes))
    items += [
        event("auth_success", "demo-bastion", "192.0.2.44", "admin", "Demo: SSH session authenticated after prior failures", 40),
        event("group_membership_change", "demo-desktop", "", "demo-user", "Demo: 'helper' added to Administrators",
              34, target="helper", details={"group": "Administrators"}),
        event("policy_change", "demo-desktop", "", "demo-user", "Demo: audit policy for logon events disabled", 24),
        event("service_error", "demo-nas", "", "system", "Demo: backup job timed out", 12),
    ]
    for n, port in enumerate((22, 23, 80, 443, 445, 3389, 5900, 8080, 8443, 1433, 3306, 5432)):
        items.append(event("network_block", "demo-router", "198.51.100.19", "firewall",
                           f"Demo: inbound TCP to port {port} denied", 18 - n * 0.2, dest_ip="203.0.113.10", dest_port=port))
    for n, account in enumerate(("admin", "root", "guest", "support", "test")):
        items.append(event("auth_failure", "demo-router", "198.51.100.77", account, f"Demo: router web login failed for {account}", 9 - n))
        items.append(event("auth_failure", "demo-nas", "198.51.100.77", account, f"Demo: NAS login failed for {account}", 8.5 - n))
    return items


def injected_scenario():
    """One new fictional credential-attack sequence."""
    ip = f"198.51.100.{secrets.randbelow(150) + 100}"
    return [event("auth_failure", "demo-vpn", ip, "root", "Demo: VPN login rejected", 5 - n * 0.5) for n in range(6)] + \
           [event("auth_success", "demo-vpn", ip, "root", "Demo: VPN login accepted following repeated failures", 1)]
