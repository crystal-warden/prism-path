# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The console's session: one random token per launch, and the guard that checks it on every request.

Loopback is not access control. A web page open in the same browser can POST a form to the console
without a preflight, and a page under a hostname that rebinds to 127.0.0.1 is served unless the server
checks `Host`. So nothing reaches a route unless all three hold:

    the `Host` header names the bound port on a loopback spelling (`127.0.0.1`, `localhost`, `[::1]`)
    an `Origin` header, when the browser sends one, is that same origin
    a request under /api/v1 carries `X-PrismPath-Session` equal to this launch's token

The token reaches the page in a `<meta>` tag the page route writes into `index.html` as it serves it,
and reaches a script on the same machine in a file only the console's user can read. A refusal is the
console's error envelope with status 403 and nothing else runs. Every response also carries the
content security policy and the headers that keep the page from being framed, sniffed or cached.

The guard is pure ASGI, so it sees the event stream's request before the stream starts and adds its
headers to every response, the stream's included, without buffering a body.
"""
import hashlib
import hmac
import json
import os
import secrets
import tempfile

TOKEN_HEADER = "X-PrismPath-Session"
META_NAME = "prismpath-session"
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "[::1]")

# The plan's policy, then the three directives `default-src` does not cover: no framing (a page that
# frames the console could click its controls), no <base> rewrite, and forms post only to the console.
CONTENT_SECURITY_POLICY = ("default-src 'self'; img-src 'self' data:; connect-src 'self'; "
                           "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
SECURITY_HEADERS = (
    (b"content-security-policy", CONTENT_SECURITY_POLICY.encode()),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"x-frame-options", b"DENY"),
)


class Session:
    """This launch's token. Minted in memory; written to disk only by `write_token_file`."""

    def __init__(self, token: str):
        self.token = token

    @classmethod
    def mint(cls) -> "Session":
        return cls(secrets.token_urlsafe(32))

    @property
    def fingerprint(self) -> str:
        """A short name for the session that audit events and logs can carry without the secret."""
        return hashlib.sha256(self.token.encode("ascii")).hexdigest()[:16]

    def matches(self, candidate) -> bool:
        """Constant time comparison; a missing or empty header never matches."""
        if not candidate or not isinstance(candidate, str):
            return False
        return hmac.compare_digest(candidate.encode("utf-8", "replace"), self.token.encode("ascii"))

    def write_token_file(self, state_dir: str, port: int) -> str:
        """Write the token to `<state_dir>/mission_control-<port>.session`, readable by its owner only.

        The directory is created owner only. The file is written to a temporary name created 0600 and
        renamed over any earlier launch's file, so the token is never readable under a wider mode, not
        even for the moment between create and chmod."""
        os.makedirs(state_dir, mode=0o700, exist_ok=True)
        path = token_file_path(state_dir, port)
        handle_fd, tmp_path = tempfile.mkstemp(dir=state_dir, prefix=".mission_control-", suffix=".tmp")
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(handle_fd, 0o600)
            with os.fdopen(handle_fd, "w", encoding="ascii") as handle:
                handle.write(self.token + "\n")
            os.replace(tmp_path, path)
        except BaseException:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise
        return path


def token_file_path(state_dir: str, port: int) -> str:
    return os.path.join(state_dir, f"mission_control-{port}.session")


def read_token_file(state_dir: str, port: int) -> str:
    """The token a running console wrote, for a script on the same machine that drives its API."""
    with open(token_file_path(state_dir, port), encoding="ascii") as handle:
        return handle.read().strip()


# What a header sent twice reads as: matches no host, no origin and no token, so it is refused.
_REPEATED = "\x00repeated"


def allowed_hosts(port: int) -> frozenset:
    return frozenset(f"{host}:{port}" for host in LOOPBACK_HOSTS)


def _refusal(status: int, message: str) -> tuple:
    body = json.dumps({"error": {"code": status, "message": message}}).encode()
    headers = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
               (b"cache-control", b"no-store"), *SECURITY_HEADERS]
    return status, headers, body


class SessionGuard:
    """ASGI middleware. Refuses a request whose Host, Origin or session header is wrong before any
    other processing, refuses a write route in the read only posture, and stamps the security headers
    on every response it lets through."""

    def __init__(self, app, session: Session, port, api_prefix: str, write_routes=frozenset(),
                 read_only: bool = False):
        self.app = app
        self.session = session
        self.port = port                      # an int, or a callable read per request (tests move it)
        self.api_prefix = api_prefix
        self.write_routes = frozenset(write_routes)
        self.read_only = read_only

    def _port(self) -> int:
        return self.port() if callable(self.port) else self.port

    def check(self, method: str, path: str, headers: dict):
        """None when the request may proceed, else (status, message)."""
        hosts = allowed_hosts(self._port())
        host = headers.get("host")
        if host not in hosts:
            return 403, "refused: the Host header is not this console's loopback origin"
        origin = headers.get("origin")
        if origin is not None and origin != f"http://{host}":
            return 403, "refused: the request comes from another origin"
        api = path == self.api_prefix or path.startswith(self.api_prefix + "/")
        if api and not self.session.matches(headers.get(TOKEN_HEADER.lower())):
            return 403, f"refused: missing or wrong {TOKEN_HEADER} header"
        if self.read_only and (method, path) in self.write_routes:
            return 403, "refused: the console runs read-only and mounts no write routes"
        return None

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {}
        for raw_name, raw_value in scope.get("headers", []):
            name = raw_name.decode("latin-1").lower()
            if name in headers:                               # a repeated Host, Origin or token is refused
                headers[name] = _REPEATED
            else:
                headers[name] = raw_value.decode("latin-1")
        refused = self.check(scope.get("method", "GET"), scope.get("path", ""), headers)
        if refused is not None:
            status, response_headers, body = _refusal(*refused)
            await send({"type": "http.response.start", "status": status, "headers": response_headers})
            await send({"type": "http.response.body", "body": body})
            return
        path = scope.get("path", "")
        no_store = path == "/" or path == "/index.html" or path.startswith(self.api_prefix + "/")

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                names = {bytes(name).lower() for name, _ in message.get("headers", [])}
                added = [header for header in SECURITY_HEADERS if header[0] not in names]
                kept = list(message.get("headers", []))
                if no_store:
                    kept = [header for header in kept if bytes(header[0]).lower() != b"cache-control"]
                    added.append((b"cache-control", b"no-store"))
                message = dict(message, headers=kept + added)
            await send(message)

        await self.app(scope, receive, send_with_headers)
