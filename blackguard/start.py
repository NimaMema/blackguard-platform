"""BLACKGUARD launcher and administration CLI.

    python3 start.py                      run the server (default)
    python3 start.py check                validate configuration and database
    python3 start.py create-admin USER    create an administrator (prompts for password)
    python3 start.py reset-password USER  set a new password for a user (prompts)
    python3 start.py backup               write a consistent database backup
    python3 start.py restore FILE         restore a backup (server must be stopped)
    python3 start.py tls-selfsigned ...   create a private self-signed TLS certificate
    python3 start.py diagnose             operational health report (backups, disk, agents, warnings)
    python3 start.py verify-backup FILE   check a backup file before relying on it
    python3 start.py stop                 ask the running server to stop cleanly

Settings come from environment variables or a .env file next to this script (see .env.example).
"""

import argparse
import getpass
import json
import logging
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import threading
from logging.handlers import RotatingFileHandler
from contextlib import closing
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from guard import __version__  # noqa: E402
from guard.config import load_settings  # noqa: E402

LEGACY_ACCESS = "access.json"


def legacy_tokens(settings):
    """Read v0.4 shared tokens, if present. They are never deleted or rotated automatically."""
    path = settings.data_dir / LEGACY_ACCESS
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def build_app(settings):
    from guard.platform import App
    return App(settings)


def prompt_password(username):
    from guard.security import password_problem
    while True:
        first = getpass.getpass(f"New password for {username}: ")
        problem = password_problem(first, username)
        if problem:
            print(problem)
            continue
        if getpass.getpass("Repeat password: ") != first:
            print("Passwords do not match.")
            continue
        return first


def cmd_serve(settings, args):
    legacy = legacy_tokens(settings)
    if os.environ.get("BLACKGUARD_LEGACY_INGEST") == "1" and not settings.legacy_ingest_token:
        if legacy and legacy.get("ingest"):
            settings.legacy_ingest_token = legacy["ingest"]
        else:
            raise SystemExit("BLACKGUARD_LEGACY_INGEST=1 but no v0.4 ingest token was found in data/access.json.")
    settings.validate()
    app = build_app(settings)
    if app.migration["applied"]:
        print(f"Database migrated to schema v{app.db.schema_version()}.", flush=True)
        if app.migration["backup"]:
            print(f"Pre-migration backup: {app.migration['backup']}", flush=True)
    code = app.auth.ensure_setup_code()
    from guard.server import Server
    server = Server(app)
    scheme = "https" if settings.tls_enabled else "http"
    print(f"\nBLACKGUARD {__version__} listening on {scheme}://{settings.host}:{settings.port}", flush=True)
    if code:
        print("\nFIRST-RUN SETUP — no administrator account exists yet.", flush=True)
        print("Open the dashboard and enter this one-time setup code to create your administrator:", flush=True)
        print(f"\n    {code}\n", flush=True)
        print("(Or stop the server and run: python3 start.py create-admin <username>)", flush=True)
    if legacy:
        print("Note: v0.4 shared tokens in data/access.json are no longer used for sign-in. "
              "Legacy collector ingestion is " + ("ENABLED (unverified data)." if settings.legacy_ingest_token else "disabled."), flush=True)
    if not settings.tls_enabled and settings.host not in ("127.0.0.1", "localhost", "::1"):
        print("WARNING: serving without TLS on a non-loopback address. Only do this behind a private TLS proxy.", flush=True)
    app.startup()
    app.shutdown_request_file.unlink(missing_ok=True)  # ignore a stale request from before this start
    app.on_shutdown_request = lambda: threading.Thread(target=server.shutdown, daemon=True).start()
    app.start_background()

    def request_shutdown(signum, _frame):
        # serve_forever must be stopped from another thread; it then drains in-flight requests below.
        logging.getLogger("blackguard").info("Signal %s received; shutting down gracefully.", signum)
        threading.Thread(target=server.shutdown, daemon=True).start()
    for name in ("SIGTERM", "SIGBREAK", "SIGHUP"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), request_shutdown)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        drained = server.drain(timeout=10)
        server.server_close()
        app.stop(clean=True)
        print("BLACKGUARD stopped cleanly." if drained else "BLACKGUARD stopped (some requests were still running).", flush=True)


def cmd_diagnose(settings, args):
    """Human-readable operational report: configuration, storage, backups, agents, background jobs, warnings."""
    settings.validate()
    app = build_app(settings)
    health = app.system_health()
    print(f"BLACKGUARD {__version__} diagnostics")
    print(f"  Data directory : {settings.data_dir}")
    print(f"  Listen         : {'https' if settings.tls_enabled else 'http'}://{settings.host}:{settings.port}")
    print(f"  Database       : {settings.db_path} ({health['database_bytes'] // 1024} KiB, schema v{health['schema_version']}, "
          f"integrity {app.db.scalar('PRAGMA quick_check')})")
    print(f"  Disk free      : {health['disk_free_bytes'] // 1024 ** 2} MB of {health['disk_total_bytes'] // 1024 ** 2} MB")
    last = health["last_backup"]
    print(f"  Last backup    : {last['file'] + ' at ' + last['at'] + (' (verified)' if last.get('verified') else ' (NOT VERIFIED)') if last else 'none yet'}")
    down = health["last_server_downtime"]
    print(f"  Last downtime  : {down['from'] + ' -> ' + down['to'] + (' (clean)' if down['clean'] else ' (unclean)') if down else 'none recorded'}")
    print(f"  Audit chain    : {'intact' if health['audit_chain']['valid'] else 'BROKEN at #' + str(health['audit_chain']['broken_at'])} "
          f"({health['audit_chain']['checked']} entries)")
    print(f"  Events / users : {app.events.count()} events, {app.auth.user_count()} users")
    print("  Agents:")
    agents = app.agents.list()
    for a in agents:
        h = a["health"]
        print(f"    - {a['name']} [{a['id']}] {a['status']}/{a['connection']}; last contact {a['last_contact_at'] or 'never'}; "
              f"spool {h.get('spool_depth', '?')}; dropped {h.get('dropped_total', 0)}; last error: {h.get('last_error') or 'none'}")
    if not agents:
        print("    (none enrolled)")
    print("  Warnings:")
    for w in health["warnings"] or [{"level": "ok", "message": "none"}]:
        print(f"    [{w['level']}] {w['message']}")
    app.db.close()
    return 1 if health["status"] != "ok" else 0


def cmd_stop(settings, args):
    """Ask a running server (same data directory) to shut down cleanly within ~5 seconds."""
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    (settings.data_dir / "shutdown.request").write_text("stop\n", encoding="utf-8")
    print("Shutdown requested; the server stops cleanly within a few seconds.")


def cmd_verify_backup(settings, args):
    from guard.platform import verify_backup
    result = verify_backup(Path(args.file).resolve(strict=True))
    print(json.dumps(result, indent=2))
    return 0 if result["verified"] else 1


def cmd_check(settings, args):
    settings.validate()
    app = build_app(settings)
    integrity = app.db.scalar("PRAGMA integrity_check")
    health = app.system_health()
    print(json.dumps({"version": __version__, "schema_version": health["schema_version"], "integrity": integrity,
                      "users": app.auth.user_count(), "events": app.events.count(), "tls": settings.tls_enabled,
                      "bind": f"{settings.host}:{settings.port}", "audit_chain": health["audit_chain"]}, indent=2))
    return 0 if integrity == "ok" and health["audit_chain"]["valid"] else 1


def cmd_create_admin(settings, args):
    app = build_app(settings)
    password = prompt_password(args.username)
    app.auth.create_user(args.username, password, args.role, args.username, actor={"type": "cli", "name": getpass.getuser()})
    print(f"Created {args.role} '{args.username}'.")


def cmd_reset_password(settings, args):
    app = build_app(settings)
    row = app.db.one("SELECT id FROM users WHERE username = ?", (args.username,))
    if not row:
        raise SystemExit("No such user.")
    password = prompt_password(args.username)
    app.auth.update_user(row["id"], {"type": "cli", "name": getpass.getuser()}, password=password, disabled=False)
    print("Password updated; existing sessions for this user were signed out.")


def cmd_backup(settings, args):
    app = build_app(settings)
    print(app.backup({"type": "cli", "name": getpass.getuser()}))


def cmd_restore(settings, args):
    source = Path(args.file).resolve(strict=True)
    with closing(sqlite3.connect(f"file:{source}?mode=ro", uri=True)) as check:
        result = check.execute("PRAGMA integrity_check").fetchone()[0]
        tables = {r[0] for r in check.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if result != "ok" or "events" not in tables:
        raise SystemExit(f"{source} is not a healthy BLACKGUARD database (integrity: {result}).")
    target = settings.db_path
    if not args.yes:
        answer = input(f"Replace {target} with {source}? The current database is backed up first. Type RESTORE: ")
        if answer.strip() != "RESTORE":
            raise SystemExit("Cancelled.")
    if target.exists():
        safety = target.with_name(target.name + ".before-restore")
        with closing(sqlite3.connect(str(target))) as live, closing(sqlite3.connect(str(safety))) as dest:
            live.backup(dest)
        print(f"Current database saved to {safety}")
    for suffix in ("-wal", "-shm"):
        Path(str(target) + suffix).unlink(missing_ok=True)
    shutil.copy2(source, target)
    os.chmod(target, 0o600)
    print(f"Restored {source} -> {target}. Start the server; pending migrations run automatically.")


def cmd_tls(settings, args):
    openssl = shutil.which("openssl")
    if not openssl:
        raise SystemExit("openssl is required to generate a certificate. Install it, or supply your own certificate.")
    out = settings.data_dir / "tls"
    out.mkdir(parents=True, exist_ok=True)
    cert, key = out / "blackguard.crt", out / "blackguard.key"
    if (cert.exists() or key.exists()) and not args.force:
        raise SystemExit(f"{cert} already exists. Use --force to replace it (agents pinned to it must be updated).")
    names = [f"DNS:{h}" for h in args.hostname] + [f"IP:{i}" for i in args.ip] + ["DNS:localhost", "IP:127.0.0.1"]
    subprocess.run([openssl, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-days", str(args.days), "-subj", "/CN=BLACKGUARD private server", "-addext",
                    "subjectAltName=" + ",".join(names), "-keyout", str(key), "-out", str(cert)],
                   check=True, capture_output=True)
    os.chmod(key, 0o600)
    print(f"Certificate: {cert}\nPrivate key: {key}\n")
    print(f"Start with:\n  BLACKGUARD_TLS_CERT={cert} BLACKGUARD_TLS_KEY={key} python3 start.py")
    thumb = subprocess.run([openssl, "x509", "-in", str(cert), "-noout", "-fingerprint", "-sha1"], capture_output=True, text=True).stdout
    print(f"Copy {cert.name} (NOT the key) to each agent and pass --ca-file to pin it.")
    print(f"Windows agents: -CertThumbprint {thumb.strip().split('=')[-1].replace(':', '')}")


def load_env_file(path=None):
    """Load BLACKGUARD_* settings from a .env file without overriding variables already set.

    Default: ``.env`` next to start.py, or the file named by BLACKGUARD_ENV_FILE.
    """
    path = Path(path or os.environ.get("BLACKGUARD_ENV_FILE") or ROOT / ".env")
    if not path.is_file():
        return 0
    loaded = 0
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        if key.startswith("export "):
            key = key[7:].strip()
        if not key.startswith("BLACKGUARD_") or key in os.environ:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        os.environ[key] = value
        loaded += 1
    return loaded


def configure_logging(settings):
    level = os.environ.get("BLACKGUARD_LOG_LEVEL", "INFO").upper()
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    root = logging.getLogger()
    root.setLevel(level)
    if not root.handlers:
        console = logging.StreamHandler()
        console.setFormatter(fmt)
        root.addHandler(console)
    target = os.environ.get("BLACKGUARD_LOG_FILE", str(settings.data_dir / "logs" / "blackguard.log"))
    if target:
        try:
            Path(target).parent.mkdir(parents=True, exist_ok=True)
            handler = RotatingFileHandler(target, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8")
            handler.setFormatter(fmt)
            root.addHandler(handler)
        except OSError as exc:
            root.warning("File logging disabled (%s)", exc)


def main(argv=None):
    # Windows consoles and redirected output may use a legacy code page; never crash on a character.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="backslashreplace")
    load_env_file()
    parser = argparse.ArgumentParser(description=f"BLACKGUARD {__version__}")
    parser.add_argument("--agent-token", action="store_true", help=argparse.SUPPRESS)
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("serve")
    sub.add_parser("check")
    p = sub.add_parser("create-admin")
    p.add_argument("username")
    p.add_argument("--role", default="admin", choices=("admin", "analyst", "viewer"))
    p = sub.add_parser("reset-password")
    p.add_argument("username")
    sub.add_parser("backup")
    p = sub.add_parser("restore")
    p.add_argument("file")
    p.add_argument("--yes", action="store_true")
    p = sub.add_parser("tls-selfsigned")
    p.add_argument("--hostname", action="append", default=[], help="DNS name agents will use (repeatable)")
    p.add_argument("--ip", action="append", default=[], help="IP address agents will use (repeatable)")
    p.add_argument("--days", type=int, default=825)
    p.add_argument("--force", action="store_true")
    sub.add_parser("diagnose", help="Print an operational health report")
    sub.add_parser("stop", help="Ask the running server to shut down cleanly (Windows-friendly)")
    p = sub.add_parser("verify-backup", help="Check that a backup file is a healthy BLACKGUARD database")
    p.add_argument("file")
    args = parser.parse_args(argv)
    settings = load_settings()
    configure_logging(settings)
    if args.agent_token:
        raise SystemExit("v0.5 replaced the shared ingest token with per-agent enrollment. "
                         "Create an enrollment code in the dashboard (Agents → Enroll), then run agents/bgagent.py enroll.")
    commands = {None: cmd_serve, "serve": cmd_serve, "check": cmd_check, "create-admin": cmd_create_admin,
                "reset-password": cmd_reset_password, "backup": cmd_backup, "restore": cmd_restore, "tls-selfsigned": cmd_tls,
                "diagnose": cmd_diagnose, "verify-backup": cmd_verify_backup, "stop": cmd_stop}
    return commands[args.command](settings, args)


if __name__ == "__main__":
    sys.exit(main() or 0)
