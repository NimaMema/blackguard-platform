"""Conservative log parsers. Unknown lines return None: the agent never guesses.

Covered formats (see tests/test_parsers.py for samples):
* Linux auth logs: OpenSSH, sudo, su, useradd/userdel/usermod/gpasswd, passwd/chpasswd
* Syslog headers: RFC 3164, RFC 5424, ISO-8601 (rsyslog high precision)
* Routers/firewalls: netfilter/iptables/UFW, pfSense/OPNsense filterlog, OpenWrt dropbear,
  MikroTik RouterOS, dnsmasq and ISC dhcpd leases, generic login/config messages
"""

import hashlib
import ipaddress
import re
from datetime import datetime, timedelta, timezone

MONTHS = {m: i for i, m in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}
RFC5424 = re.compile(r"^<(\d{1,3})>\d{1,2} (\S+) (\S+) (\S+) (\S+) (\S+) (?:-|(?:\[(?:[^\]\\]|\\.)*\])+) ?(.*)$", re.S)
RFC3164 = re.compile(r"^(?:<(\d{1,3})>)?([A-Z][a-z]{2}) +(\d{1,2}) (\d\d):(\d\d):(\d\d) (?:(\S+) )?(.*)$", re.S)
ISO_LINE = re.compile(r"^(?:<(\d{1,3})>)?(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)) (\S+) (.*)$", re.S)
PROGRAM = re.compile(r"^([A-Za-z0-9_./-]{1,48})(?:\[(\d+)\])?: ?(.*)$", re.S)

USER = r"(?P<user>[^\s'\"]{1,64})"
IP = r"(?P<ip>[0-9a-fA-F:.]{3,45})"
SSH_FAIL = re.compile(rf"^Failed (?P<method>password|publickey|keyboard-interactive/pam|none) for (?:invalid user )?{USER} from {IP} port \d+")
SSH_OK = re.compile(rf"^Accepted (?P<method>password|publickey|keyboard-interactive/pam|gssapi-with-mic|hostbased) for {USER} from {IP} port \d+")
SUDO_CMD = re.compile(r"^\s*(?P<user>\S{1,64}) : .*?USER=(?P<target>\S+) ; COMMAND=(?P<cmd>.{1,300})$")
SUDO_BADPW = re.compile(r"^\s*(?P<user>\S{1,64}) : (?:(?P<n>\d+) )?incorrect password attempts?")
SUDO_DENIED = re.compile(r"^\s*(?P<user>\S{1,64}) : (?:user )?NOT in sudoers")
SU_FAIL = re.compile(r"^(?:FAILED SU \(to (?P<target>\S+)\) (?P<user>\S+)|pam_unix\(su(?:-l)?:auth\): authentication failure;.*?ruser=(?P<ruser>\S*).*?user=(?P<tuser>\S+))")
SU_OK = re.compile(r"^(?:\(to (?P<target>\S+)\) (?P<user>\S+) on|pam_unix\(su(?:-l)?:session\): session opened for user (?P<t2>\S+?)(?:\(uid=\d+\))? by (?P<u2>\S+?)(?:\(uid=\d+\))?$)")
USERADD = re.compile(r"^new user: name=(?P<target>[^,\s]+)")
USERDEL = re.compile(r"^delete user '(?P<target>[^']+)'")
GROUP_ADD = re.compile(r"^(?:add '(?P<target>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'|user (?P<t2>\S+) added by (?P<actor>\S+) to group (?P<g2>\S+))")
PASSWD = re.compile(r"^pam_unix\((?:passwd|chpasswd):chauthtok\): password changed for (?P<target>\S+)")
DROPBEAR_FAIL = re.compile(rf"^Bad password attempt for '{USER}' from {IP}:\d+")
DROPBEAR_NOUSER = re.compile(rf"^Login attempt for nonexistent user (?:'{USER}' )?from {IP}:\d+")
DROPBEAR_OK = re.compile(rf"^(?:Password|Pubkey) auth succeeded for '{USER}'.*? from {IP}:\d+")
MIKROTIK_FAIL = re.compile(rf"login failure for user {USER} from {IP} via (?P<via>\S+)")
MIKROTIK_OK = re.compile(rf"user {USER} logged in from {IP} via (?P<via>\S+)")
MIKROTIK_CHANGE = re.compile(r"(?P<what>.{1,120}?) (?:changed|added|removed) by (?P<user>\S+)")
NETFILTER_KV = re.compile(r"\b(SRC|DST|PROTO|SPT|DPT|IN|OUT)=(\S*)")
DNSMASQ_LEASE = re.compile(r"^DHCPACK\([^)]*\) (?P<ip>\S+) (?P<mac>[0-9a-fA-F:]{17})(?: (?P<host>\S+))?")
DHCPD_LEASE = re.compile(r"^DHCPACK on (?P<ip>\S+) to (?P<mac>[0-9a-fA-F:]{17})(?: \((?P<host>[^)]+)\))?")
GENERIC_FAIL = re.compile(r"(?i)\b(?:login failed|failed login|authentication fail(?:ure|ed)|invalid password|wrong password|bad password|login incorrect)\b")
GENERIC_OK = re.compile(r"(?i)\b(?:login successful|login succeeded|logged in successfully|authentication succeeded|successful login)\b")
GENERIC_CONFIG = re.compile(r"(?i)\b(?:configuration|config|settings?) (?:was |has been )?(?:changed|saved|updated|modified|restored)\b")
ANY_IP = re.compile(r"(?<![\w.:])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
FROM_IP = re.compile(r"(?i)\b(?:from|src|source|rhost|client|ip)[=: ]+\[?((?:\d{1,3}\.){3}\d{1,3})")
ANY_USER = re.compile(r"(?i)\b(?:user(?:name)?|account|login)\s*[=:]\s*['\"]?([A-Za-z0-9_.@-]{1,64})|\b(?:for|by) user ['\"]?([A-Za-z0-9_.@-]{1,64})")
BLOCK_WORDS = re.compile(r"(?i)\b(?:block(?:ed)?|den(?:y|ied)|drop(?:ped)?|reject(?:ed)?)\b")


def _ip(value):
    try:
        return str(ipaddress.ip_address(str(value).strip("[]")))
    except ValueError:
        return ""


def _user(msg):
    m = ANY_USER.search(msg)
    if m:
        return m.group(1) or m.group(2)
    by = re.search(r"\bby ([A-Za-z0-9_.@-]{1,64})\b", msg)
    return by.group(1) if by else "unknown"


def _now():
    return datetime.now(timezone.utc)


def parse_header(line, now=None, local_tz=None):
    """Split a syslog/auth.log line into (timestamp|None, hostname, program, message)."""
    now = now or _now()
    m = RFC5424.match(line)
    if m:
        stamp = None if m.group(2) == "-" else _parse_iso(m.group(2))
        app = "" if m.group(4) == "-" else m.group(4)
        return stamp, ("" if m.group(3) == "-" else m.group(3)), app, m.group(7).lstrip("\ufeff")
    m = ISO_LINE.match(line)
    if m:
        program, message = _program(m.group(4))
        return _parse_iso(m.group(2)), m.group(3), program, message
    m = RFC3164.match(line)
    if m:
        _, mon, day, hh, mm, ss, host, rest = m.groups()
        tz = local_tz or datetime.now().astimezone().tzinfo
        local_now = now.astimezone(tz)
        stamp = None
        if mon in MONTHS:
            try:
                stamp = datetime(local_now.year, MONTHS[mon], int(day), int(hh), int(mm), int(ss), tzinfo=tz)
                if stamp - local_now > timedelta(days=1):  # December log read in January
                    stamp = stamp.replace(year=stamp.year - 1)
            except ValueError:
                stamp = None
        if host and PROGRAM.match(host + " ") and host.endswith(":"):
            # "Oct 27 08:00:00 sshd[1]: msg" with no hostname
            program, message = _program(host + " " + rest)
            return stamp, "", program, message
        program, message = _program(rest)
        return stamp, host or "", program, message
    program, message = _program(line)
    return None, "", program, message


def _program(text):
    m = PROGRAM.match(text)
    if m:
        return m.group(1).rsplit("/", 1)[-1], m.group(3)
    return "", text


def _parse_iso(value):
    try:
        value = value.replace("Z", "+00:00")
        if re.search(r"[+-]\d{4}$", value):
            value = value[:-2] + ":" + value[-2:]
        parsed = datetime.fromisoformat(value)
        return parsed if parsed.tzinfo else None
    except ValueError:
        return None


def _event(kind, message, actor="unknown", source_ip="", target="", **details):
    clean = {k: v for k, v in details.items() if v not in (None, "")}
    return {"type": kind, "actor": (actor or "unknown")[:120], "source_ip": _ip(source_ip) if source_ip else "",
            "target": (target or "")[:160], "message": message[:1000], "details": clean}


def parse_auth_message(program, message):
    """Linux authentication messages (OpenSSH, sudo, su, shadow-utils, PAM)."""
    program = (program or "").lower()
    msg = message.strip()
    if program in ("sshd", "sshd-session", "ssh"):
        m = SSH_FAIL.match(msg)
        if m:
            return _event("auth_failure", f"SSH {m['method']} authentication failed for {m['user']} from {m['ip']}",
                          m["user"], m["ip"], service="ssh", method=m["method"], invalid_user="invalid user" in msg)
        m = SSH_OK.match(msg)
        if m:
            return _event("auth_success", f"SSH {m['method']} sign-in accepted for {m['user']} from {m['ip']}",
                          m["user"], m["ip"], service="ssh", method=m["method"])
        return None
    if program == "sudo":
        m = SUDO_BADPW.match(msg)
        if m:
            return _event("auth_failure", f"sudo: incorrect password for {m['user']}", m["user"], service="sudo",
                          attempts=int(m["n"]) if m["n"] else 1)
        m = SUDO_DENIED.match(msg)
        if m:
            return _event("auth_failure", f"sudo: {m['user']} is not in sudoers", m["user"], service="sudo", reason="not_in_sudoers")
        m = SUDO_CMD.match(msg)
        if m:
            return _event("privilege_use", f"sudo: {m['user']} ran a command as {m['target']}", m["user"], target=m["target"],
                          service="sudo", command=m["cmd"][:200])
        return None
    if program in ("su", "su-l"):
        m = SU_FAIL.match(msg)
        if m:
            user = m["user"] or m["ruser"] or "unknown"
            return _event("auth_failure", f"su: authentication failure switching to {m['target'] or m['tuser']}",
                          user, target=m["target"] or m["tuser"], service="su")
        m = SU_OK.match(msg)
        if m:
            return _event("privilege_use", f"su: {m['user'] or m['u2']} switched to {m['target'] or m['t2']}",
                          m["user"] or m["u2"], target=m["target"] or m["t2"], service="su")
        return None
    if program == "useradd":
        m = USERADD.match(msg)
        return _event("account_created", f"Account created: {m['target']}", target=m["target"], service="useradd") if m else None
    if program == "userdel":
        m = USERDEL.match(msg)
        return _event("account_deleted", f"Account deleted: {m['target']}", target=m["target"], service="userdel") if m else None
    if program in ("usermod", "gpasswd"):
        m = GROUP_ADD.match(msg)
        if m:
            target, group = m["target"] or m["t2"], m["group"] or m["g2"]
            return _event("group_membership_change", f"{target} added to group {group}", m["actor"] or "unknown",
                          target=target, group=group, service=program)
        return None
    if program in ("passwd", "chpasswd"):
        m = PASSWD.match(msg)
        return _event("password_reset", f"Password changed for {m['target']}", target=m["target"], service=program) if m else None
    return None


def parse_network_message(program, message):
    """Router and firewall messages."""
    program = (program or "").lower()
    msg = message.strip()
    if program == "dropbear":
        for pattern, kind in ((DROPBEAR_FAIL, "auth_failure"), (DROPBEAR_NOUSER, "auth_failure"), (DROPBEAR_OK, "auth_success")):
            m = pattern.match(msg)
            if m:
                user = m.groupdict().get("user") or "unknown"
                verb = "accepted" if kind == "auth_success" else "failed"
                return _event(kind, f"Router SSH (dropbear) sign-in {verb} for {user} from {m['ip']}", user, m["ip"], service="dropbear")
        return None
    if program == "filterlog":
        return _filterlog(msg)
    if program.startswith("dnsmasq") or program == "dhcpd":
        m = DNSMASQ_LEASE.match(msg) or DHCPD_LEASE.match(msg)
        if m and _ip(m["ip"]):
            host = (m["host"] or "").strip()
            if host == "*":
                host = ""
            return _event("dhcp_lease", f"DHCP lease {m['ip']} → {m['mac'].lower()}{' (' + host + ')' if host else ''}",
                          ip=_ip(m["ip"]), mac=m["mac"].lower(), hostname=host[:120], service=program)
        return None
    m = MIKROTIK_FAIL.search(msg)
    if m:
        return _event("auth_failure", f"Router login failed for {m['user']} from {m['ip']} via {m['via']}", m["user"], m["ip"], service=m["via"])
    m = MIKROTIK_OK.search(msg)
    if m:
        return _event("auth_success", f"Router login by {m['user']} from {m['ip']} via {m['via']}", m["user"], m["ip"], service=m["via"])
    kv = dict(NETFILTER_KV.findall(msg))
    if "SRC" in kv and "DST" in kv:
        if BLOCK_WORDS.search(msg) or "[UFW BLOCK]" in msg or "[UFW AUDIT INVALID]" in msg:
            port = kv.get("DPT")
            return _event("network_block", f"Firewall denied {kv.get('PROTO', 'IP')} {kv['SRC']} → {kv['DST']}"
                                           f"{':' + port if port else ''}", source_ip=kv["SRC"],
                          dest_ip=_ip(kv["DST"]), dest_port=int(port) if port and port.isdigit() else None,
                          protocol=kv.get("PROTO", ""), interface=kv.get("IN", ""), service="netfilter")
        return None
    if GENERIC_FAIL.search(msg) or GENERIC_OK.search(msg):
        kind = "auth_failure" if GENERIC_FAIL.search(msg) else "auth_success"
        ip_match = FROM_IP.search(msg) or ANY_IP.search(msg)
        ip = ip_match.group(1) if ip_match and ip_match.groups() else (ip_match.group(0) if ip_match else "")
        return _event(kind, f"Device reported: {msg[:300]}", _user(msg), _ip(ip),
                      service=program or "syslog", match="generic")
    m = MIKROTIK_CHANGE.search(msg)
    if m and program in ("", "system", "system,info", "routeros"):
        return _event("config_change", f"Router configuration: {msg[:300]}", m["user"], service=program or "routeros")
    if GENERIC_CONFIG.search(msg):
        return _event("config_change", f"Device reported configuration change: {msg[:300]}", _user(msg),
                      service=program or "syslog", match="generic")
    return None


def _filterlog(msg):
    fields = msg.split(",")
    if len(fields) < 12 or fields[6] not in ("block", "reject", "pass"):
        return None
    if fields[6] == "pass":
        return None
    try:
        if fields[8] == "4" and len(fields) >= 20:
            proto, src, dst = fields[16], fields[18], fields[19]
            ports = fields[20:22] if proto in ("tcp", "udp") and len(fields) >= 22 else []
        elif fields[8] == "6" and len(fields) >= 17:
            proto, src, dst = fields[12], fields[15], fields[16]
            ports = fields[17:19] if proto in ("tcp", "udp") and len(fields) >= 19 else []
        else:
            return None
    except IndexError:
        return None
    if not _ip(src):
        return None
    dport = int(ports[1]) if len(ports) == 2 and ports[1].isdigit() else None
    return _event("network_block", f"Firewall {fields[6]}ed {proto.upper()} {src} → {dst}{':' + str(dport) if dport is not None else ''} "
                                   f"on {fields[4]} ({fields[7]})", source_ip=src, dest_ip=_ip(dst), dest_port=dport,
                  protocol=proto, interface=fields[4], direction=fields[7], service="filterlog")


def _finish(event, stamp, received, host, fallback_host):
    event["host"] = (host or fallback_host or "unknown")[:120]
    details = event["details"]
    if "dest_ip" in details:
        event["dest_ip"] = details.pop("dest_ip") or ""
    if "dest_port" in details:
        port = details.pop("dest_port")
        if port is not None:
            event["dest_port"] = port
    if stamp and abs((stamp - received).total_seconds()) < 366 * 86400 and stamp - received < timedelta(minutes=10):
        event["timestamp"] = stamp.astimezone(timezone.utc).isoformat(timespec="seconds")
        details["time_source"] = "log"
    else:
        event["timestamp"] = received.astimezone(timezone.utc).isoformat(timespec="seconds")
        details["time_source"] = "received"
    return event


def parse_auth_line(line, hostname, now=None, local_tz=None):
    """Parse one line of /var/log/auth.log or /var/log/secure."""
    now = now or _now()
    line = line.replace("\x00", " ").strip()
    if not line:
        return None
    stamp, host, program, message = parse_header(line[:4000], now, local_tz)
    event = parse_auth_message(program, message)
    if not event:
        return None
    return _finish(event, stamp, now, hostname, hostname)


def parse_syslog(raw, sender, device_name="", now=None):
    """Parse one syslog datagram from a router/firewall/Linux host."""
    now = now or _now()
    line = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
    line = line.replace("\x00", " ").strip()[:4000]
    if not line:
        return None
    stamp, host, program, message = parse_header(line, now, timezone.utc)
    event = parse_network_message(program, message) or parse_auth_message(program, message)
    if not event:
        return None
    event["details"]["reported_hostname"] = host[:60] if host else ""
    event["details"]["sender"] = sender
    # The configured device name (or sender IP) is more trustworthy than a hostname inside a UDP datagram.
    return _finish(event, stamp, now, device_name or f"syslog-{sender}", host)


def stable_uid(*parts):
    return hashlib.sha256("\x1f".join(str(p) for p in parts).encode("utf-8", "replace")).hexdigest()[:48]
