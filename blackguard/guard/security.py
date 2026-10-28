"""Security primitives: password hashing, secret tokens, rate limiting, redaction."""

import base64
import hashlib
import hmac
import re
import secrets
import threading
import time
from collections import OrderedDict

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1
SCRYPT_MAXMEM = 64 * 1024 * 1024
PASSWORD_MIN = 12
PASSWORD_MAX = 256


def _b64(data):
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
                            maxmem=SCRYPT_MAXMEM, dklen=32)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${_b64(salt)}${_b64(digest)}"


def verify_password(password, encoded):
    try:
        scheme, n, r, p, salt, digest = encoded.split("$")
        if scheme != "scrypt":
            return False
        candidate = hashlib.scrypt(password.encode("utf-8"), salt=_unb64(salt), n=int(n), r=int(r), p=int(p),
                                   maxmem=SCRYPT_MAXMEM, dklen=32)
        return hmac.compare_digest(candidate, _unb64(digest))
    except (ValueError, TypeError):
        return False


# Computed once so that unknown usernames cost the same as wrong passwords.
_DUMMY_HASH = None


def dummy_verify(password):
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password("blackguard-timing-equaliser")
    verify_password(password, _DUMMY_HASH)


COMMON_PASSWORDS = {
    "password1234", "123456789012", "qwertyuiopas", "blackguard123", "administrator", "letmein12345",
    "passwordpassword", "changeme1234", "welcome12345", "iloveyou1234",
}


def password_problem(password, username=""):
    """Return a human-readable reason a password is unacceptable, or None."""
    if not isinstance(password, str):
        return "Password is required."
    if len(password) < PASSWORD_MIN:
        return f"Password must be at least {PASSWORD_MIN} characters. A passphrase of several words works well."
    if len(password) > PASSWORD_MAX:
        return f"Password must be at most {PASSWORD_MAX} characters."
    lowered = password.lower()
    if lowered in COMMON_PASSWORDS or len(set(password)) < 5:
        return "Password is too common or repetitive."
    if username and username.lower() in lowered:
        return "Password must not contain the username."
    return None


def new_token(prefix="", nbytes=32):
    return prefix + secrets.token_urlsafe(nbytes)


def token_hash(token):
    """Secrets here have >=256 bits of entropy, so a fast keyed-free hash is appropriate."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_enrollment_code():
    # 16 base32 characters (80 bits) grouped for readability: ABCD-EFGH-IJKL-MNOP
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    raw = "".join(secrets.choice(alphabet) for _ in range(16))
    return "-".join(raw[i:i + 4] for i in range(0, 16, 4))


def normalize_code(code):
    return re.sub(r"[^A-Z0-9]", "", str(code).upper())


class RateLimiter:
    """Thread-safe token bucket keyed by arbitrary strings, with bounded memory."""

    def __init__(self, rate_per_minute, burst, max_keys=10000):
        self.rate = rate_per_minute / 60.0
        self.burst = float(burst)
        self.max_keys = max_keys
        self._buckets = OrderedDict()
        self._lock = threading.Lock()

    def allow(self, key, cost=1.0):
        now = time.monotonic()
        with self._lock:
            tokens, last = self._buckets.pop(key, (self.burst, now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            allowed = tokens >= cost
            if allowed:
                tokens -= cost
            self._buckets[key] = (tokens, now)
            while len(self._buckets) > self.max_keys:
                self._buckets.popitem(last=False)
            return allowed

    def retry_after(self, key):
        with self._lock:
            tokens, _ = self._buckets.get(key, (self.burst, 0))
        return max(1, int((1 - tokens) / self.rate) + 1) if self.rate else 60


# -- sensitive-field redaction ---------------------------------------------
REDACTIONS = [
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"), lambda m: "Bearer [REDACTED]"),
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|apikey|auth|authorization|credential|session[_-]?id|cookie)(\s*[=:]\s*)(?!Bearer \[REDACTED\])(\"[^\"]*\"|'[^']*'|\S+)"),
     lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]"),
    (re.compile(r"\bbga_[A-Za-z0-9_-]{10,}\b"), lambda m: "[REDACTED-AGENT-CREDENTIAL]"),
    (re.compile(r"\b-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)", re.S), lambda m: "[REDACTED-PRIVATE-KEY]"),
    # 13-19 digit sequences that pass a Luhn check look like payment cards.
    (re.compile(r"\b(?:\d[ -]?){12,18}\d\b"), None),
]


def _luhn(digits):
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def redact(text):
    if not text:
        return text
    out = str(text)
    for pattern, repl in REDACTIONS:
        if repl is None:
            def card(m):
                digits = re.sub(r"\D", "", m.group(0))
                return "[REDACTED-CARD]" if 13 <= len(digits) <= 19 and _luhn(digits) else m.group(0)
            out = pattern.sub(card, out)
        else:
            out = pattern.sub(repl, out)
    return out


def pseudonymize(value, salt):
    """Stable, non-reversible label for exports shared outside the household."""
    if not value:
        return value
    digest = hmac.new(salt.encode(), str(value).encode(), hashlib.sha256).hexdigest()[:10]
    return f"anon-{digest}"
