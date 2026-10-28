"""Individual administrator accounts, server-side sessions and role permissions."""

import hmac
import re
from datetime import timedelta

from guard.db import iso, parse_iso, utcnow
from guard.security import (dummy_verify, hash_password, new_token, password_problem,
                            token_hash, verify_password)

ROLES = ("admin", "analyst", "viewer")

PERMISSIONS = {
    "viewer": {"view"},
    "analyst": {"view", "investigate", "import", "detect", "export", "propose_response", "ai"},
    "admin": {"view", "investigate", "import", "detect", "export", "propose_response", "ai",
              "manage_users", "manage_agents", "manage_rules", "approve_response", "manage_system", "view_audit"},
}

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,40}$")
MAX_FAILED = 8
LOCK_MINUTES = 15


class AuthError(Exception):
    def __init__(self, message, status=401):
        super().__init__(message)
        self.status = status


def public_user(row):
    return {
        "id": row["id"], "username": row["username"], "display_name": row["display_name"], "role": row["role"],
        "disabled": bool(row["disabled"]), "created_at": row["created_at"], "last_login_at": row["last_login_at"],
        "permissions": sorted(PERMISSIONS[row["role"]]),
    }


class Auth:
    def __init__(self, db, audit, settings):
        self.db = db
        self.audit = audit
        self.settings = settings

    # -- users --------------------------------------------------------------
    def user_count(self):
        return self.db.scalar("SELECT COUNT(*) FROM users")

    def create_user(self, username, password, role, display_name="", actor=None, ip=""):
        username = str(username or "").strip()
        if not USERNAME_RE.match(username):
            raise ValueError("Username must be 3–40 letters, digits, '.', '_' or '-'.")
        if role not in ROLES:
            raise ValueError("Unknown role.")
        problem = password_problem(password, username)
        if problem:
            raise ValueError(problem)
        display_name = str(display_name or username).strip()[:80] or username
        now = iso()
        with self.db.tx() as conn:
            if conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
                raise ValueError("That username already exists.")
            cur = conn.execute(
                "INSERT INTO users(username,display_name,password_hash,role,created_at,password_changed_at) VALUES(?,?,?,?,?,?)",
                (username, display_name, hash_password(password), role, now, now))
            self.audit.record("user.create", actor=actor, target_type="user", target_id=cur.lastrowid, ip=ip,
                              detail={"username": username, "role": role}, conn=conn)
            return cur.lastrowid

    def list_users(self):
        return [public_user(r) for r in self.db.query("SELECT * FROM users ORDER BY id")]

    def update_user(self, user_id, actor, role=None, disabled=None, display_name=None, password=None, ip=""):
        user = self.db.one("SELECT * FROM users WHERE id = ?", (user_id,))
        if not user:
            raise ValueError("User not found.")
        changes = {}
        with self.db.tx() as conn:
            if role is not None:
                if role not in ROLES:
                    raise ValueError("Unknown role.")
                changes["role"] = role
            if disabled is not None:
                changes["disabled"] = 1 if disabled else 0
            if display_name is not None:
                changes["display_name"] = str(display_name).strip()[:80] or user["username"]
            if password is not None:
                problem = password_problem(password, user["username"])
                if problem:
                    raise ValueError(problem)
                changes["password_hash"] = hash_password(password)
                changes["password_changed_at"] = iso()
                changes["failed_logins"] = 0
                changes["locked_until"] = None
            if not changes:
                return public_user(user)
            # Never allow the last active admin to be demoted or disabled.
            if (changes.get("role", user["role"]) != "admin" or changes.get("disabled", user["disabled"])) and user["role"] == "admin":
                remaining = conn.execute(
                    "SELECT COUNT(*) FROM users WHERE role='admin' AND disabled=0 AND id != ?", (user_id,)).fetchone()[0]
                if remaining == 0:
                    raise ValueError("At least one active administrator must remain.")
            # Interpolated text is fixed column names / '?' placeholders; all values are bound parameters.
            conn.execute(f"UPDATE users SET {', '.join(f'{k}=?' for k in changes)} WHERE id=?",  # nosec B608
                         (*changes.values(), user_id))
            if "password_hash" in changes or changes.get("disabled") or "role" in changes:
                conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            safe = {k: v for k, v in changes.items() if k != "password_hash"}
            if "password_hash" in changes:
                safe["password"] = "changed"
            self.audit.record("user.update", actor=actor, target_type="user", target_id=user_id, ip=ip, detail=safe, conn=conn)
        return public_user(self.db.one("SELECT * FROM users WHERE id = ?", (user_id,)))

    def change_own_password(self, user, current, new, ip=""):
        row = self.db.one("SELECT * FROM users WHERE id = ?", (user["id"],))
        if not row or not verify_password(current, row["password_hash"]):
            self.audit.record("user.password_change", "failure", actor=actor_of(user), target_type="user", target_id=user["id"], ip=ip)
            raise AuthError("Current password is incorrect.", 403)
        return self.update_user(user["id"], actor_of(user), password=new, ip=ip)

    # -- first-run setup ----------------------------------------------------
    def ensure_setup_code(self):
        """While no account exists, issue a one-time setup code (printed to the console)."""
        if self.user_count():
            return None
        code = new_token(nbytes=18)
        self.db.set_setting("setup_code_hash", token_hash(code))
        return code

    def complete_setup(self, code, username, password, display_name="", ip=""):
        expected = self.db.get_setting("setup_code_hash")
        if self.user_count() or not expected:
            raise AuthError("Setup has already been completed.", 409)
        if not hmac.compare_digest(token_hash(str(code or "").strip()), expected):
            self.audit.record("setup.complete", "failure", ip=ip, detail={"reason": "bad setup code"})
            raise AuthError("Setup code is incorrect. It is printed in the server console.", 403)
        user_id = self.create_user(username, password, "admin", display_name, actor={"type": "setup", "name": "first-run"}, ip=ip)
        self.db.set_setting("setup_code_hash", "")
        return user_id

    # -- sessions -----------------------------------------------------------
    def login(self, username, password, ip="", user_agent=""):
        username = str(username or "").strip()[:40]
        password = str(password or "")[:512]
        row = self.db.one("SELECT * FROM users WHERE username = ?", (username,))
        now = utcnow()
        if not row:
            dummy_verify(password)
            self.audit.record("auth.login", "failure", actor={"type": "anonymous", "name": username}, ip=ip, detail={"reason": "unknown user"})
            raise AuthError("Incorrect username or password.")
        if row["locked_until"] and parse_iso(row["locked_until"]) > now:
            dummy_verify(password)
            self.audit.record("auth.login", "failure", actor={"type": "user", "id": row["id"], "name": username}, ip=ip, detail={"reason": "locked"})
            raise AuthError("Account temporarily locked after repeated failures. Try again later.", 429)
        if not verify_password(password, row["password_hash"]) or row["disabled"]:
            with self.db.tx() as conn:
                failed = row["failed_logins"] + 1
                locked = iso(now + timedelta(minutes=LOCK_MINUTES)) if failed >= MAX_FAILED else None
                conn.execute("UPDATE users SET failed_logins=?, locked_until=? WHERE id=?",
                             (0 if locked else failed, locked, row["id"]))
                self.audit.record("auth.login", "failure", actor={"type": "user", "id": row["id"], "name": username}, ip=ip,
                                  detail={"reason": "disabled" if row["disabled"] else "bad password", "locked": bool(locked)}, conn=conn)
            raise AuthError("Incorrect username or password.")
        token = new_token("bgs_")
        csrf = new_token(nbytes=24)
        expires = now + timedelta(hours=self.settings.session_absolute_hours)
        with self.db.tx() as conn:
            conn.execute("UPDATE users SET failed_logins=0, locked_until=NULL, last_login_at=? WHERE id=?", (iso(now), row["id"]))
            conn.execute(
                "INSERT INTO sessions(token_hash,user_id,csrf_token,created_at,last_seen_at,expires_at,ip,user_agent) VALUES(?,?,?,?,?,?,?,?)",
                (token_hash(token), row["id"], csrf, iso(now), iso(now), iso(expires), ip, str(user_agent)[:200]))
            self.audit.record("auth.login", actor={"type": "user", "id": row["id"], "name": username}, ip=ip, conn=conn)
        return token, csrf, public_user(row)

    def session(self, token):
        """Resolve a session cookie, enforcing idle and absolute timeouts."""
        if not token or not token.startswith("bgs_") or len(token) > 100:
            return None
        hashed = token_hash(token)
        row = self.db.one(
            "SELECT s.*, u.username, u.display_name, u.role, u.disabled, u.created_at AS user_created, u.last_login_at "
            "FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?", (hashed,))
        if not row:
            return None
        now = utcnow()
        idle = timedelta(minutes=self.settings.session_idle_minutes)
        if row["disabled"] or parse_iso(row["expires_at"]) <= now or now - parse_iso(row["last_seen_at"]) > idle:
            with self.db.tx() as conn:
                conn.execute("DELETE FROM sessions WHERE token_hash = ?", (hashed,))
            return None
        if (now - parse_iso(row["last_seen_at"])).total_seconds() > 30:
            with self.db.tx() as conn:
                conn.execute("UPDATE sessions SET last_seen_at=? WHERE token_hash=?", (iso(now), hashed))
        return {
            "id": row["user_id"], "username": row["username"], "display_name": row["display_name"], "role": row["role"],
            "csrf": row["csrf_token"], "token_hash": hashed, "permissions": PERMISSIONS[row["role"]],
        }

    def logout(self, session, ip=""):
        with self.db.tx() as conn:
            conn.execute("DELETE FROM sessions WHERE token_hash = ?", (session["token_hash"],))
            self.audit.record("auth.logout", actor=actor_of(session), ip=ip, conn=conn)

    def purge_expired_sessions(self):
        cutoff = iso(utcnow() - timedelta(minutes=self.settings.session_idle_minutes))
        with self.db.tx() as conn:
            conn.execute("DELETE FROM sessions WHERE expires_at <= ? OR last_seen_at <= ?", (iso(), cutoff))


def actor_of(user):
    if not user:
        return {"type": "system"}
    return {"type": "user", "id": user["id"], "name": user["username"]}
