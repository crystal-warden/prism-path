# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""An HTTP CONNECT proxy on a unix socket, the one door out of the agent sandbox.

    EgressProxy(socket_path, log_path, gate=policy_gate).start()

Standard library only. The proxy accepts a CONNECT on the socket, reads the destination as written, and
decides it in this order, answering 403 with a short reason at the first refusal:

  1. the method is CONNECT and the request line is well formed (otherwise 405 or 400);
  2. the head fits the size cap and arrives within the header timeout (otherwise 431 or 408);
  3. the authority parses to a lower case ASCII host name and a port, with no userinfo, no IP literal in any
     form (dotted, decimal, hex, octal, short, bracketed IPv6), no empty label and at most one trailing dot,
     which is dropped so `a.com.` and `a.com` are one destination;
  4. the port is one of `allowed_ports` (443 unless the caller lists more);
  5. the caller's decision allows it: the gate (asked first, with the target as written) or else the decider
     function (host, port) the caller passed in;
  6. the proxy resolves the name itself and every address must be globally routable. Loopback, link local,
     private, carrier grade NAT, unspecified, multicast and reserved addresses are refused, and so are the
     IPv4 mapped, NAT64 and 6to4 IPv6 forms of them. The connection goes to the address that was checked, so
     a second lookup cannot change the answer.

An allowed tunnel is a byte relay (the proxy never reads the TLS inside) that closes after `idle_timeout`
seconds with no bytes either way. At most `max_connections` run at once; the next gets 503. Every attempt,
allowed or refused, appends one JSON line (time, host, port, decision, reason) to the log file the caller
names. The proxy writes to that file and to its socket path and nowhere else (a gate it is given may write more:
the policy gate appends receipts to a run).

The caller passes the decision in. There is no allowlist in this file: with no `gate` and no `decider` every
destination is refused. `gate(authority)` is asked first, with the CONNECT target exactly as written (case, trailing
dot, userinfo and all), once the request line and method are well formed, and answers (allowed, reason). The launcher
passes the policy decider (prismpath/agent/egress_policy.py): it reads the target into a connect reading with the
classifier, decides it with the active attested image and writes a receipt, so an odd spelling is refused with the
classifier's own reading. `decider(host, port)` is asked after the target is normalised, for a caller with no policy."""
import ipaddress
import json
import os
import re
import select
import socket
import stat
import threading
import time

MAX_HEADER_BYTES = 8192
MAX_CONNECTIONS = 32
HEADER_TIMEOUT = 10.0
IDLE_TIMEOUT = 60.0
CONNECT_TIMEOUT = 10.0
_LABEL = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")
_PORT = re.compile(r"^[0-9]{1,5}$")


def refuse_all(host, port):
    """The decider when none is given: nothing is allowed."""
    return False, "no-decider"


class Refusal(Exception):
    """A request that is not served. `status` is the HTTP code, `reason` the short token that is logged and sent."""

    def __init__(self, reason, status=403):
        super().__init__(reason)
        self.reason = reason
        self.status = status
        self.target = None


def parse_authority(authority, allowed_ports=(443,)):
    """Split a CONNECT target into (host, port) or raise Refusal. The host comes back lower case, without a trailing dot."""
    if not authority or len(authority) > 300 or any(ord(c) < 0x21 or ord(c) > 0x7e for c in authority):
        raise Refusal("bad-authority", 400)
    if "@" in authority:
        raise Refusal("userinfo", 400)
    if authority.startswith("["):
        raise Refusal("ip-literal")
    if authority.count(":") != 1:
        raise Refusal("bad-authority", 400)
    host, port_text = authority.split(":")
    if not _PORT.match(port_text):
        raise Refusal("bad-port", 400)
    port = int(port_text)
    if port < 1 or port > 65535:
        raise Refusal("bad-port", 400)
    host = host.lower()
    if host.endswith("."):
        host = host[:-1]
    if not host or len(host) > 253:
        raise Refusal("bad-host", 400)
    labels = host.split(".")
    if any(not _LABEL.match(label) for label in labels):
        raise Refusal("bad-host", 400)
    last = labels[-1]
    # 127.1, 2130706433, 0x7f000001 and 0177.0.0.1 are all addresses to a resolver, whatever the label rules say.
    if last.isdigit() or last.startswith("0x") or _is_ip(host):
        raise Refusal("ip-literal")
    if port not in allowed_ports:
        raise Refusal("port-not-allowed")
    return host, port


def _is_ip(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def address_refusal(text):
    """None when the address may be dialled, else the short reason it may not."""
    try:
        address = ipaddress.ip_address(text.split("%")[0])
    except ValueError:
        return "bad-address"
    if address.version == 6:
        embedded = address.ipv4_mapped
        if embedded is None and address in ipaddress.ip_network("64:ff9b::/96"):
            embedded = ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
        if embedded is None and address.sixtofour is not None:
            embedded = address.sixtofour
        if embedded is not None:
            return address_refusal(str(embedded))
        if address.teredo is not None:
            return "teredo-address"
    if address.is_loopback:
        return "loopback-address"
    if address.is_link_local:
        return "link-local-address"
    if address.is_private:
        return "private-address"
    if address.is_unspecified or address.is_multicast or address.is_reserved:
        return "reserved-address"
    if not address.is_global:
        return "non-global-address"
    return None


def system_resolver(host):
    return sorted({info[4][0] for info in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)})


def system_connect(address, port, timeout):
    return socket.create_connection((address, port), timeout=timeout)


class EgressProxy:
    def __init__(self, socket_path, log_path, decider=refuse_all, gate=None, resolver=system_resolver, connect=system_connect,
                 allowed_ports=(443,), max_header=MAX_HEADER_BYTES, max_connections=MAX_CONNECTIONS,
                 header_timeout=HEADER_TIMEOUT, idle_timeout=IDLE_TIMEOUT, connect_timeout=CONNECT_TIMEOUT):
        self.socket_path = str(socket_path)
        self.log_path = str(log_path)
        self.decider, self.gate, self.resolver, self.connect = decider, gate, resolver, connect
        self.allowed_ports = tuple(allowed_ports)
        self.max_header, self.max_connections = max_header, max_connections
        self.header_timeout, self.idle_timeout, self.connect_timeout = header_timeout, idle_timeout, connect_timeout
        self._slots = threading.BoundedSemaphore(max_connections)
        self._log_lock = threading.Lock()
        self._listener = None
        self._thread = None
        self._closing = threading.Event()

    # lifecycle

    def start(self):
        if os.path.lexists(self.socket_path):
            if not stat.S_ISSOCK(os.lstat(self.socket_path).st_mode):
                raise FileExistsError(f"{self.socket_path} exists and is not a socket")
            os.unlink(self.socket_path)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old = os.umask(0o177)
        try:
            listener.bind(self.socket_path)
        finally:
            os.umask(old)
        listener.listen(64)
        listener.settimeout(0.2)
        self._listener = listener
        self._thread = threading.Thread(target=self.serve_forever, name="egress-accept", daemon=True)
        self._thread.start()
        return self

    def close(self):
        self._closing.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
        if self._listener is not None:
            self._listener.close()
            self._listener = None
        try:
            os.unlink(self.socket_path)
        except FileNotFoundError:
            pass

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.close()

    def serve_forever(self):
        while not self._closing.is_set():
            try:
                client, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            if not self._slots.acquire(blocking=False):
                self._reply(client, 503, "too-many-connections")
                self._log("-", 0, "refuse", "too-many-connections")
                client.close()
                continue
            threading.Thread(target=self._serve, args=(client,), daemon=True).start()

    # one connection

    def _serve(self, client):
        host, port = "-", 0
        upstream = None
        try:
            head, rest = self._read_head(client)
            host, port, target, gated = self._parse_request(head)
            allowed, reason = gated if gated is not None else self._decide(host, port)
            if not allowed:
                raise Refusal(reason)
            addresses = self._resolve(host)
            try:
                upstream = self._dial(addresses, port)
            except OSError:
                raise Refusal("connect-failed", 502)
            self._log(host, port, "allow", reason)
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            if rest:
                upstream.sendall(rest)
            self._relay(client, upstream)
        except Refusal as refusal:
            if refusal.target is not None:
                host = refusal.target.encode("ascii", "backslashreplace").decode()
            self._log(host, port, "error" if refusal.status == 502 else "refuse", refusal.reason)
            self._reply(client, refusal.status, refusal.reason)
        except OSError:
            pass
        finally:
            for sock in (upstream, client):
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass
            self._slots.release()

    def _read_head(self, client):
        deadline = time.monotonic() + self.header_timeout
        data = b""
        while b"\r\n\r\n" not in data:
            left = deadline - time.monotonic()
            if left <= 0:
                raise Refusal("header-timeout", 408)
            client.settimeout(left)
            try:
                chunk = client.recv(4096)
            except socket.timeout:
                raise Refusal("header-timeout", 408)
            if not chunk:
                raise Refusal("incomplete-request", 400)
            data += chunk
            if len(data) > self.max_header and b"\r\n\r\n" not in data[:self.max_header]:
                raise Refusal("header-too-large", 431)
        head, _, rest = data.partition(b"\r\n\r\n")
        if len(head) > self.max_header:
            raise Refusal("header-too-large", 431)
        client.settimeout(None)
        return head, rest

    def _parse_request(self, head):
        if b"\x00" in head or b"\n" in head.replace(b"\r\n", b""):
            raise Refusal("malformed-request", 400)
        try:
            lines = head.decode("ascii").split("\r\n")
        except UnicodeDecodeError:
            raise Refusal("malformed-request", 400)
        parts = lines[0].split(" ")
        if len(parts) != 3 or not parts[0] or parts[2] not in ("HTTP/1.1", "HTTP/1.0"):
            raise Refusal("malformed-request", 400)
        if parts[0] != "CONNECT":
            raise Refusal("method-not-allowed", 405)
        for line in lines[1:]:
            if ":" not in line or line[0] in " \t":
                raise Refusal("malformed-request", 400)
        gated = None
        try:
            if self.gate is not None:
                gated = self._gated(parts[1])
                if not gated[0]:
                    raise Refusal(gated[1])
            host, port = parse_authority(parts[1], self.allowed_ports)
        except Refusal as refusal:
            refusal.target = parts[1]
            raise
        return host, port, parts[1], gated

    def _gated(self, authority):
        try:
            allowed, reason = self.gate(authority)
        except Exception:
            return False, "decider-error"
        return bool(allowed), str(reason)

    def _decide(self, host, port):
        try:
            allowed, reason = self.decider(host, port)
        except Exception:
            return False, "decider-error"
        return bool(allowed), str(reason)

    def _resolve(self, host):
        try:
            addresses = list(self.resolver(host))
        except OSError:
            raise Refusal("resolve-failed", 502)
        if not addresses:
            raise Refusal("resolve-failed", 502)
        for address in addresses:
            why = address_refusal(address)
            if why:
                raise Refusal(why)
        return addresses

    def _dial(self, addresses, port):
        error = OSError("no address")
        for address in addresses:
            try:
                return self.connect(address, port, self.connect_timeout)
            except OSError as exc:
                error = exc
        raise error

    def _relay(self, client, upstream):
        client.settimeout(None)
        upstream.settimeout(None)
        pair = {client: upstream, upstream: client}
        while True:
            ready, _, _ = select.select(list(pair), [], [], self.idle_timeout)
            if not ready:
                return
            for sock in ready:
                data = sock.recv(65536)
                if not data:
                    return
                pair[sock].sendall(data)

    def _reply(self, client, status, reason):
        text = {400: "Bad Request", 403: "Forbidden", 405: "Method Not Allowed", 408: "Request Timeout",
                431: "Request Header Fields Too Large", 502: "Bad Gateway", 503: "Service Unavailable"}.get(status, "Error")
        body = reason.encode() + b"\n"
        try:
            client.settimeout(2)
            client.sendall(f"HTTP/1.1 {status} {text}\r\nContent-Type: text/plain\r\nContent-Length: {len(body)}\r\n"
                           f"Connection: close\r\n\r\n".encode() + body)
        except OSError:
            pass

    def _log(self, host, port, decision, reason):
        line = json.dumps({"time": round(time.time(), 3), "host": host[:253], "port": port, "decision": decision,
                           "reason": reason}, ensure_ascii=True)
        with self._log_lock:
            with open(self.log_path, "a", encoding="ascii") as handle:
                handle.write(line + "\n")
