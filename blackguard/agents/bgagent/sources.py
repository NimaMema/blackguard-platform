"""Event sources. Each reads only what the operator explicitly configured.

* ``jsonl``      – BLACKGUARD-format JSON lines from one file
* ``linux-auth`` – /var/log/auth.log or /var/log/secure (one file you name)
* ``journald``   – the systemd journal's auth/authpriv facilities, via journalctl
* ``syslog``     – UDP syslog receiver for a router/firewall you own
* ``arp``        – passive inventory from this machine's own ARP/neighbour cache (no packets sent)
"""

import hashlib
import ipaddress
import json
import logging
import os
import platform
import re
import shutil
import socket
import subprocess
import threading
import time
from datetime import datetime, timezone

from bgagent.parsers import parse_auth_line, parse_syslog, stable_uid

log = logging.getLogger("bgagent")


class FileTail:
    """Tail one file with a persistent (inode, offset) cursor and rotation handling."""

    def __init__(self, path, cursor, from_start=False, max_lines=500):
        self.path = os.path.abspath(os.path.expanduser(path))
        if not os.path.isfile(self.path):
            raise SystemExit(f"Source file not found or not a regular file: {self.path}")
        if not os.access(self.path, os.R_OK):
            raise SystemExit(f"No permission to read {self.path}. Add the agent user to the 'adm' group (Debian/Ubuntu) "
                             "or grant read access; do not run the agent as root unless necessary.")
        self.max_lines = max_lines
        st = os.stat(self.path)
        if (cursor and cursor.get("inode") == st.st_ino and cursor.get("offset", 0) <= st.st_size
                and cursor.get("head", "") == self._head(cursor.get("offset", 0))):
            self.inode, self.offset = st.st_ino, cursor["offset"]
        elif cursor:
            log.warning("%s was rotated or truncated since the last run; reading the current file from the start", self.path)
            self.inode, self.offset = st.st_ino, 0
        else:
            self.inode, self.offset = st.st_ino, 0 if from_start else st.st_size
        self.head = self._head(self.offset)

    def _head(self, offset):
        """Signature of the file's first bytes: detects in-place truncation (copytruncate) followed by regrowth."""
        size = min(int(offset), 256)
        if size <= 0:
            return ""
        try:
            with open(self.path, "rb") as handle:
                return hashlib.sha256(handle.read(size)).hexdigest()[:32]
        except OSError:
            return ""

    def read(self):
        """Return ([(uid_base, line)], cursor). Only complete lines are consumed."""
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return [], self.cursor()
        if st.st_ino != self.inode or st.st_size < self.offset or (self.head and self._head(self.offset) != self.head):
            log.info("%s rotated or truncated; continuing from the start of the current file", self.path)
            self.inode, self.offset, self.head = st.st_ino, 0, ""
        if st.st_size == self.offset:
            return [], self.cursor()
        lines = []
        with open(self.path, "rb") as handle:
            handle.seek(self.offset)
            for _ in range(self.max_lines):
                start = handle.tell()
                raw = handle.readline(65536)
                if not raw:
                    break
                if not raw.endswith(b"\n"):
                    if len(raw) < 65536:
                        handle.seek(start)  # partial line still being written
                        break
                lines.append((f"{self.inode}:{start}", raw.decode("utf-8", "replace").rstrip("\r\n")))
            self.offset = handle.tell()
        if self.offset <= 256 or not self.head:
            self.head = self._head(self.offset)
        return lines, self.cursor()

    def cursor(self):
        return {"inode": self.inode, "offset": self.offset, "head": self.head}


class Source:
    kind = ""
    name = ""

    def __init__(self):
        self.last_event_at = None
        self.last_error = None
        self.events_total = 0

    def health(self):
        return {"name": self.name, "kind": self.kind, "events_total": self.events_total,
                "last_event_at": self.last_event_at, "last_error": self.last_error}

    def _mark(self, count):
        if count:
            self.events_total += count
            self.last_event_at = datetime.now(timezone.utc).isoformat(timespec="seconds")


class JsonlSource(Source):
    kind = "jsonl"

    def __init__(self, path, spool, from_start=False):
        super().__init__()
        self.name = f"jsonl:{path}"
        self.tail = FileTail(path, spool.cursor(self.name), from_start)

    def poll(self, spool):
        lines, cursor = self.tail.read()
        events = []
        for uid, line in lines:
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except ValueError:
                self.last_error = "Skipped a malformed JSON line"
                continue
            if isinstance(item, dict):
                item["uid"] = item.get("uid") or f"jsonl:{uid}"
                events.append(item)
        spool.put(self.name, events, cursor)
        self._mark(len(events))
        return len(events)


class LinuxAuthSource(Source):
    kind = "linux_auth"

    def __init__(self, path, spool, hostname, from_start=False):
        super().__init__()
        self.name = f"linux-auth:{path}"
        self.hostname = hostname
        self.tail = FileTail(path, spool.cursor(self.name), from_start)

    def poll(self, spool):
        lines, cursor = self.tail.read()
        events = []
        for uid, line in lines:
            event = parse_auth_line(line, self.hostname)
            if event:
                event["uid"] = f"auth:{uid}"
                events.append(event)
        spool.put(self.name, events, cursor)
        self._mark(len(events))
        return len(events)


class JournaldSource(Source):
    kind = "journald"
    name = "journald:auth"

    def __init__(self, spool, hostname, from_start=False):
        super().__init__()
        self.binary = shutil.which("journalctl")
        if not self.binary:
            raise SystemExit("journalctl not found; use --source linux-auth:/var/log/auth.log instead.")
        self.hostname = hostname
        self.cursor = (spool.cursor(self.name) or {}).get("cursor")
        if not self.cursor and not from_start:
            out = self._run(["-n", "1"])
            self.cursor = out[-1].get("__CURSOR") if out else None
            spool.put(self.name, [], {"cursor": self.cursor})

    def _run(self, extra):
        args = [self.binary, "-o", "json", "--no-pager", "SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10"] + extra
        try:
            proc = subprocess.run(args, capture_output=True, text=True, timeout=60)  # nosec B603
        except (OSError, subprocess.SubprocessError) as exc:
            self.last_error = f"journalctl failed: {exc}"
            return []
        if proc.returncode not in (0, 1):
            self.last_error = proc.stderr.strip()[:300] or "journalctl failed"
            return []
        entries = []
        for line in proc.stdout.splitlines():
            try:
                entries.append(json.loads(line))
            except ValueError:
                continue
        return entries

    def poll(self, spool):
        entries = self._run((["--after-cursor", self.cursor] if self.cursor else []) + ["-n", "1000"])
        if not entries:
            return 0
        events = []
        for entry in entries:
            message = entry.get("MESSAGE")
            if isinstance(message, list):  # binary messages are byte arrays
                message = bytes(x for x in message if isinstance(x, int) and 0 <= x < 256).decode("utf-8", "replace")
            ident = entry.get("SYSLOG_IDENTIFIER") or entry.get("_COMM") or ""
            stamp = datetime.fromtimestamp(int(entry.get("__REALTIME_TIMESTAMP", "0")) / 1e6, timezone.utc)
            line = f"{stamp.isoformat()} {self.hostname} {ident}: {message}"
            event = parse_auth_line(line, self.hostname)
            if event:
                event["uid"] = "journal:" + stable_uid(entry.get("__CURSOR", line))
                events.append(event)
        self.cursor = entries[-1].get("__CURSOR", self.cursor)
        spool.put(self.name, events, {"cursor": self.cursor})
        self._mark(len(events))
        return len(events)


class SyslogSource(Source):
    """UDP receiver. Datagrams are parsed and spooled from the listener thread immediately."""
    kind = "syslog"

    def __init__(self, spec, spool, device_name):
        super().__init__()
        m = re.match(r"^(?:udp://)?\[?([0-9a-fA-F.:]+)\]?:(\d{1,5})(?:\?allow=([0-9a-fA-F.:,]+))?$", spec)
        if not m:
            raise SystemExit("syslog source format: syslog:udp://BIND_IP:PORT?allow=ROUTER_IP[,IP2]")
        self.bind, self.port = m.group(1), int(m.group(2))
        self.allow = set(filter(None, (m.group(3) or "").split(",")))
        for value in [self.bind, *self.allow]:
            ipaddress.ip_address(value)
        if not ipaddress.ip_address(self.bind).is_loopback and not self.allow:
            raise SystemExit("A LAN syslog listener requires ?allow=<router IP>. UDP syslog is unauthenticated; "
                             "also firewall the port so only your router can reach it.")
        self.name = f"syslog:{self.bind}:{self.port}"
        self.device_name = device_name
        self.spool = spool
        self.ignored = 0
        self.unauthorised = 0
        family = socket.AF_INET6 if ":" in self.bind else socket.AF_INET
        self.sock = socket.socket(family, socket.SOCK_DGRAM)
        self.sock.bind((self.bind, self.port))
        self.sock.settimeout(1.0)
        self.thread = threading.Thread(target=self._listen, name="syslog", daemon=True)
        self.running = True
        self.thread.start()
        log.warning("UDP syslog on %s:%s is unencrypted and unauthenticated; source addresses can be spoofed.", self.bind, self.port)

    def _listen(self):
        while self.running:
            try:
                raw, addr = self.sock.recvfrom(8192)
            except socket.timeout:
                continue
            except OSError as exc:
                self.last_error = str(exc)
                time.sleep(1)
                continue
            sender = addr[0]
            if self.allow and sender not in self.allow:
                self.unauthorised += 1
                continue
            event = parse_syslog(raw, sender, self.device_name)
            if not event:
                self.ignored += 1
                continue
            event["uid"] = "syslog:" + stable_uid(sender, raw, time.time_ns())
            try:
                self.spool.put(self.name, [event])
                self._mark(1)
            except Exception as exc:  # keep receiving
                self.last_error = f"spool write failed: {exc}"

    def poll(self, spool):
        return 0

    def health(self):
        data = super().health()
        data.update(ignored_unparsed=self.ignored, rejected_senders=self.unauthorised, listen=f"{self.bind}:{self.port}")
        return data

    def close(self):
        self.running = False
        self.sock.close()


def read_neighbours():
    """Passive read of this machine's ARP/neighbour cache. Sends no packets."""
    entries = []
    if os.path.exists("/proc/net/arp"):
        with open("/proc/net/arp", encoding="utf-8") as handle:
            for line in handle.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[2] != "0x0":
                    entries.append({"ip": parts[0], "mac": parts[3]})
        return entries
    tool = shutil.which("arp")
    if not tool:
        return entries
    try:
        out = subprocess.run([tool, "-a"] if platform.system() == "Windows" else [tool, "-an"],
                             capture_output=True, text=True, timeout=20).stdout  # nosec B603
    except (OSError, subprocess.SubprocessError):
        return entries
    for line in out.splitlines():
        ip = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
        mac = re.search(r"([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})", line)
        if ip and mac:
            parts = re.split(r"[:-]", mac.group(1))
            entries.append({"ip": ip.group(1), "mac": ":".join(p.zfill(2) for p in parts).lower()})
    return entries


def neighbour_observations():
    seen, out = set(), []
    for item in read_neighbours():
        mac = item["mac"].lower()
        if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") or mac.startswith("01:00:5e") or (item["ip"], mac) in seen:
            continue
        seen.add((item["ip"], mac))
        out.append({"source": "arp", "ip": item["ip"], "mac": mac})
    return out
