"""Machine fingerprint and private credential storage for the agent."""

import hashlib
import json
import os
import platform
import secrets
import socket
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def _read(path):
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def machine_id(state_dir):
    """A stable per-machine identifier.

    Linux: /etc/machine-id. macOS: IOPlatformUUID. Windows: MachineGuid.
    Fallback: a random ID stored in the state directory (weaker: copying the
    state directory to another machine copies the identity too).
    """
    value = _read("/etc/machine-id") or _read("/var/lib/dbus/machine-id")
    if not value and platform.system() == "Darwin":
        try:
            out = subprocess.run(["/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice"], capture_output=True,
                                 text=True, timeout=10).stdout
            for line in out.splitlines():
                if "IOPlatformUUID" in line:
                    value = line.split('"')[-2]
        except (OSError, subprocess.SubprocessError):
            value = ""
    if not value and platform.system() == "Windows":
        try:
            import winreg  # type: ignore
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
                value = winreg.QueryValueEx(key, "MachineGuid")[0]
        except OSError:
            value = ""
    source = "machine"
    if not value:
        fallback = Path(state_dir) / "install-id"
        value = _read(fallback)
        if not value:
            value = secrets.token_hex(32)
            write_private(fallback, value)
        source = "install-id"
    return value, source


def fingerprint(state_dir):
    value, source = machine_id(state_dir)
    return hashlib.sha256(f"blackguard-agent-v1:{value}".encode()).hexdigest(), source


def boot_time():
    """Best-effort UTC boot time (ISO-8601), used by the server to tell a reboot from an agent restart."""
    try:
        if os.path.exists("/proc/stat"):
            with open("/proc/stat", encoding="ascii") as handle:
                for line in handle:
                    if line.startswith("btime "):
                        return datetime.fromtimestamp(int(line.split()[1]), timezone.utc).isoformat(timespec="seconds")
        if platform.system() == "Darwin":
            out = subprocess.run(["/usr/sbin/sysctl", "-n", "kern.boottime"], capture_output=True, text=True, timeout=5).stdout
            sec = int(out.split("sec =")[1].split(",")[0])
            return datetime.fromtimestamp(sec, timezone.utc).isoformat(timespec="seconds")
        if platform.system() == "Windows":
            import ctypes
            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            kernel32.GetTickCount64.restype = ctypes.c_uint64
            uptime_ms = kernel32.GetTickCount64()
            booted = datetime.now(timezone.utc).timestamp() - uptime_ms / 1000
            return datetime.fromtimestamp(round(booted / 60) * 60, timezone.utc).isoformat(timespec="seconds")
    except (OSError, ValueError, IndexError, subprocess.SubprocessError, AttributeError):
        return None
    return None


def stop_reason():
    """Why the agent is stopping: 'system-shutdown' when systemd reports the host is going down."""
    try:
        state = subprocess.run(["systemctl", "is-system-running"], capture_output=True, text=True, timeout=3).stdout.strip()
        if state == "stopping":
            return "system-shutdown"
    except (OSError, subprocess.SubprocessError):
        pass
    return "agent-stopped"


def host_info():
    return {"hostname": socket.gethostname()[:120] or "unknown",
            "platform": f"{platform.system()} {platform.release()}".strip()[:120] or "unknown"}


def write_private(path, text):
    """Atomically write a file readable only by the current user."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-")
    try:
        os.chmod(tmp, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class State:
    """agent.json: server URL, agent id, credential (secret), CA pin."""

    def __init__(self, state_dir):
        self.dir = Path(state_dir).expanduser()
        self.path = self.dir / "agent.json"

    def exists(self):
        return self.path.exists()

    def load(self):
        if not self.path.exists():
            raise SystemExit(f"Agent is not enrolled (missing {self.path}). Run: blackguard_agent.py enroll ...")
        if os.name != "nt" and self.path.stat().st_mode & 0o077:
            raise SystemExit(f"{self.path} is readable by other users; run: chmod 600 {self.path}")
        return json.loads(self.path.read_text(encoding="utf-8"))

    def save(self, data):
        write_private(self.path, json.dumps(data, indent=2))
