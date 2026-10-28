"""Runtime configuration, read once from environment variables.

Every value has a secure default: loopback binding, no legacy shared
tokens, AI disabled, raw log storage disabled.
"""

import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent


def _bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _int(name, default, low, high):
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise SystemExit(f"{name} must be an integer") from exc
    if not low <= value <= high:
        raise SystemExit(f"{name} must be between {low} and {high}")
    return value


def is_loopback_host(host):
    if host in ("localhost",):
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


@dataclass
class Settings:
    data_dir: Path = field(default_factory=lambda: ROOT / "data")
    db_path: Path = None
    host: str = "127.0.0.1"
    port: int = 8000
    tls_cert: str = ""
    tls_key: str = ""
    allow_remote_without_tls: bool = False
    seed_demo: bool = True
    store_raw: bool = False
    legacy_ingest_token: str = ""
    max_concurrent_requests: int = 32
    session_idle_minutes: int = 30
    session_absolute_hours: int = 12
    ollama_url: str = ""
    ollama_model: str = "llama3.1:8b"
    allow_remote_ollama: bool = False
    background_interval: int = 30
    trusted_proxy: bool = False

    @property
    def tls_enabled(self):
        return bool(self.tls_cert and self.tls_key)

    def validate(self):
        if not self.tls_enabled and not is_loopback_host(self.host) and not self.allow_remote_without_tls:
            raise SystemExit(
                "Refusing to listen on a non-loopback address without TLS. Configure "
                "BLACKGUARD_TLS_CERT and BLACKGUARD_TLS_KEY (see docs/DEPLOYMENT.md), or set "
                "BLACKGUARD_ALLOW_REMOTE_WITHOUT_TLS=1 only behind a TLS-terminating private proxy "
                "or inside an isolated container network."
            )
        if bool(self.tls_cert) != bool(self.tls_key):
            raise SystemExit("Set both BLACKGUARD_TLS_CERT and BLACKGUARD_TLS_KEY, or neither.")
        if self.legacy_ingest_token and len(self.legacy_ingest_token) < 24:
            raise SystemExit("Legacy ingest token must be at least 24 characters.")
        if self.ollama_url:
            parsed = urlsplit(self.ollama_url)
            if parsed.scheme not in ("http", "https") or not parsed.hostname:
                raise SystemExit("BLACKGUARD_OLLAMA_URL must be an http(s) URL")
            if not is_loopback_host(parsed.hostname) and not self.allow_remote_ollama:
                raise SystemExit("Ollama must run on this machine (loopback) unless BLACKGUARD_ALLOW_REMOTE_OLLAMA=1.")
        return self


def load_settings():
    data_dir = Path(os.environ.get("BLACKGUARD_DATA_DIR", str(ROOT / "data")))
    db = os.environ.get("BLACKGUARD_DB")
    settings = Settings(
        data_dir=data_dir,
        db_path=Path(db) if db else data_dir / "blackguard.sqlite3",
        host=os.environ.get("BLACKGUARD_HOST", "127.0.0.1"),
        port=_int("BLACKGUARD_PORT", 8000, 1, 65535),
        tls_cert=os.environ.get("BLACKGUARD_TLS_CERT", ""),
        tls_key=os.environ.get("BLACKGUARD_TLS_KEY", ""),
        allow_remote_without_tls=_bool("BLACKGUARD_ALLOW_REMOTE_WITHOUT_TLS"),
        seed_demo=_bool("BLACKGUARD_SEED_DEMO", True),
        store_raw=_bool("BLACKGUARD_STORE_RAW"),
        legacy_ingest_token=os.environ.get("BLACKGUARD_LEGACY_INGEST_TOKEN", ""),
        max_concurrent_requests=_int("BLACKGUARD_MAX_CONCURRENT", 32, 4, 512),
        session_idle_minutes=_int("BLACKGUARD_SESSION_IDLE_MINUTES", 30, 5, 1440),
        session_absolute_hours=_int("BLACKGUARD_SESSION_ABSOLUTE_HOURS", 12, 1, 168),
        ollama_url=os.environ.get("BLACKGUARD_OLLAMA_URL", ""),
        ollama_model=os.environ.get("BLACKGUARD_OLLAMA_MODEL", "llama3.1:8b"),
        allow_remote_ollama=_bool("BLACKGUARD_ALLOW_REMOTE_OLLAMA"),
        background_interval=_int("BLACKGUARD_BACKGROUND_INTERVAL", 30, 5, 3600),
        trusted_proxy=_bool("BLACKGUARD_TRUSTED_PROXY"),
    )
    return settings
