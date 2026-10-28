"""HTTPS client for the BLACKGUARD agent API (standard library only)."""

import ipaddress
import json
import ssl
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status

    @property
    def permanent(self):
        """Errors retrying cannot fix (bad credential, revoked, invalid request)."""
        return self.status in (400, 401, 403, 404, 405, 410, 413, 415)


def validate_server_url(value, allow_insecure_lan=False):
    parsed = urlsplit(value)
    host = parsed.hostname or ""
    if parsed.scheme == "https" and host:
        return value.rstrip("/")
    loopback = host == "localhost"
    try:
        loopback = loopback or ipaddress.ip_address(host).is_loopback
    except ValueError:
        pass
    if parsed.scheme == "http" and loopback:
        return value.rstrip("/")
    if parsed.scheme == "http" and allow_insecure_lan:
        return value.rstrip("/")
    raise ValueError("Use https:// for a remote server (http:// is allowed only for localhost).")


class Client:
    def __init__(self, server, credential="", ca_file="", timeout=20):
        self.server = server.rstrip("/")
        self.credential = credential
        self.timeout = timeout
        self.context = None
        if self.server.startswith("https://"):
            self.context = ssl.create_default_context(cafile=ca_file or None)
            self.context.minimum_version = ssl.TLSVersion.TLSv1_2

    def request(self, method, path, data=None, auth=True):
        headers = {"Accept": "application/json", "User-Agent": "blackguard-agent"}
        body = None
        if data is not None:
            body = json.dumps(data, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if auth and self.credential:
            headers["Authorization"] = f"Bearer {self.credential}"
        request = Request(self.server + path, data=body, headers=headers, method=method)
        try:
            with urlopen(request, timeout=self.timeout, context=self.context) as response:  # nosec B310
                return json.loads(response.read(4_000_000) or b"{}")
        except HTTPError as exc:
            try:
                message = json.loads(exc.read(65536)).get("error", exc.reason)
            except (ValueError, AttributeError):
                message = str(exc.reason)
            raise ApiError(exc.code, message) from exc
        except (URLError, TimeoutError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            if isinstance(reason, ssl.SSLCertVerificationError) or isinstance(exc, ssl.SSLCertVerificationError):
                raise ApiError(0, f"TLS certificate not trusted ({getattr(reason, 'verify_message', reason)}). "
                                  "Pass --ca-file with the server's certificate.") from exc
            raise ApiError(0, f"Cannot reach server: {reason}") from exc
