# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The instance key held in a separate process, so a confined worker can never reach it.

A root statement is only as good as the instance key that signed it. When the key is a file the deployment's own
process reads, anything that runs as that process can read it too, and a worker that gets the key can sign any
story it likes. The signer daemon holds the key in its own process and answers on a Unix socket. It signs only
what a deployment legitimately signs, and only for callers it accepts.

Who may ask. The daemon reads the caller's credentials from the kernel (`SO_PEERCRED`, captured when the caller
connected, so a caller cannot claim another identity). A caller must run as a user in `allowed_uids`, the daemon's
own user by default. A caller that is confined the way PrismPath confines a worker is refused: a process with
`NoNewPrivs` set or a seccomp filter in place (`/proc/<pid>/status`). A worker under the Landlock backend has both,
and it cannot open a socket at all, so it is refused twice. The socket is created mode 0600.

What it signs. Only bytes that start with an allowed domain prefix and then parse as that format's body under the
daemon's own key: a `prismpath-root-statement/3` statement or a `prismpath.core-run-root/2` run root. Never raw bytes
and never another format, so a caller cannot use the daemon to sign a pack manifest, an envelope or an image
attestation. For a chained statement the daemon keeps the head of each log (its last `seq`, leaves, root and
statement hash) in a canon/2 state file it writes atomically before it answers. It refuses a statement that is not
the next `seq`, that does not name the last statement as `prev`, that covers fewer leaves (the log was truncated),
or that covers the same leaves under another root (a fork). So a caller that deletes the tail of a log and its
statements cannot get the shorter story signed.

Resuming. A daemon that restarts reads its state file and continues the chain. A daemon whose state file is
missing refuses to start unless told it is a new deployment (`fresh=True`), because a daemon that forgot its heads
would sign a second chain from seq 0. When a caller crashed after the daemon signed but before the statement
reached the file, the daemon still holds that statement, and `RootSigner` appends it when it next opens the file
(`head`), so the chain resumes without a gap.

What it does not do. It cannot check that the root covers the receipts the log really holds, because it never sees
the log. A caller it accepts can still sign a root over leaves it invented. An outside witness with consistency
proofs (`prismpath.ledgers.witness`) covers that. The peer check reads `/proc` after the connection is made, so it
trusts the pid the kernel reported at connect time. Linux only.

The bytes of every statement are those an `InstanceKey` holding the same key would make: Ed25519 is deterministic,
and the daemon signs the very bytes `root_statement.signed_bytes` gives.

Run it with `python -m prismpath.ledgers.signer_daemon --key K --socket S --state F [--fresh]`, and point the
deployment at it with `PRISMPATH_INSTANCE_KEY=unix:S`.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import struct
import sys
import threading
from typing import Any, Dict, Iterable, Optional, Tuple

from prismpath import canon
from prismpath.ledgers import root_statement as rs
from prismpath.onion import keys

STATE_FORMAT = "prismpath-signer-state/1"
CORE_RUN_ROOT_FORMAT = "prismpath.core-run-root/2"          # core_evidence.ROOT_FORMAT, named here to avoid a cycle
CORE_RUN_ROOT_DOMAIN = b"prismpath.core-run-root/2\x00"
CORE_RUN_ROOT_MEMBERS = ("format", "log", "root", "leaves", "time_us", "trigger", "key_id", "public_key", "policy")
MAX_FRAME = 1 << 20
SCHEME = "unix:"


class SignerRefused(RuntimeError):
    """The daemon refused to sign. `reason` is one short word."""

    def __init__(self, reason: str, message: str = ""):
        super().__init__(f"the signer refused: {reason}" + (f" ({message})" if message else ""))
        self.reason = reason
        self.detail = message


# ------------------------------------------------------------------ framing
def _send(sock: socket.socket, doc: Dict[str, Any]) -> None:
    data = json.dumps(doc, sort_keys=True).encode("utf-8")
    sock.sendall(struct.pack(">I", len(data)) + data)


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    out = bytearray()
    while len(out) < size:
        chunk = sock.recv(size - len(out))
        if not chunk:
            raise ConnectionError("the connection closed mid frame")
        out += chunk
    return bytes(out)


def _recv(sock: socket.socket) -> Dict[str, Any]:
    (size,) = struct.unpack(">I", _recv_exact(sock, 4))
    if size > MAX_FRAME:
        raise ValueError("frame too large")
    doc = json.loads(_recv_exact(sock, size).decode("utf-8"))
    if not isinstance(doc, dict):
        raise ValueError("a frame is a JSON object")
    return doc


# ------------------------------------------------------------------ the caller
def peer_credentials(conn: socket.socket) -> Tuple[int, int, int]:
    """(pid, uid, gid) of the process at the other end, as the kernel recorded them at connect."""
    raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", raw)


def confinement(pid: int, proc: str = "/proc") -> Dict[str, Any]:
    """What `/proc/<pid>/status` says about the caller's confinement: NoNewPrivs and the seccomp mode. A status that
    cannot be read counts as confined, since the daemon cannot tell."""
    try:
        with open(os.path.join(proc, str(pid), "status"), encoding="utf-8") as handle:
            fields = dict(line.split(":", 1) for line in handle.read().splitlines() if ":" in line)
    except OSError:
        return {"readable": False, "no_new_privs": True, "seccomp": -1}
    def num(name: str) -> int:
        try:
            return int(fields.get(name, "0").strip())
        except ValueError:
            return -1
    return {"readable": True, "no_new_privs": num("NoNewPrivs") != 0, "seccomp": num("Seccomp")}


# ------------------------------------------------------------------ the daemon
class SignerDaemon:
    """One instance key, one socket, one state file. `serve_forever` answers callers one at a time."""

    def __init__(self, key: keys.Signer, socket_path: str, state_path: str, *,
                 allowed_uids: Optional[Iterable[int]] = None, refuse_confined: bool = True, fresh: bool = False,
                 proc: str = "/proc"):
        if not sys.platform.startswith("linux"):
            raise RuntimeError("the signer daemon reads SO_PEERCRED and /proc, so it runs on Linux only")
        self.key = key
        self.socket_path = socket_path
        self.state_path = state_path
        self.allowed_uids = set(allowed_uids) if allowed_uids is not None else {os.getuid()}
        self.refuse_confined = refuse_confined
        self.proc = proc
        self.lock = threading.Lock()
        self.refusals: list = []
        if os.path.exists(state_path):
            self.heads = self._load()
        elif fresh:
            self.heads = {}
            self._save()
        else:
            raise RuntimeError(f"{state_path} does not exist: a signer that forgot its chain heads would sign a "
                               f"second chain from seq 0; start it with fresh=True only for a new deployment")
        self._sock: Optional[socket.socket] = None
        self._stop = threading.Event()

    # state
    def _load(self) -> Dict[str, dict]:
        with open(self.state_path, encoding="utf-8") as handle:
            doc = canon.loads_document(handle.read())
        if not isinstance(doc, dict) or doc.get("format") != STATE_FORMAT or doc.get("key_id") != self.key.key_id \
                or not isinstance(doc.get("heads"), dict):
            raise RuntimeError(f"{self.state_path} is not a {STATE_FORMAT} file for this key")
        return dict(doc["heads"])

    def _save(self) -> None:
        doc = {"format": STATE_FORMAT, canon.ENCODING_KEY: canon.CANON2, "key_id": self.key.key_id,
               "heads": self.heads}
        canon.atomic_write(self.state_path, canon.canon2_bytes(doc).decode("utf-8") + "\n")

    # the decision to sign
    def check_caller(self, pid: int, uid: int) -> Optional[str]:
        if uid not in self.allowed_uids:
            return "uid_not_allowed"
        if self.refuse_confined:
            seen = confinement(pid, self.proc)
            if seen["no_new_privs"] or seen["seccomp"] != 0:
                return "confined_caller"
        return None

    def _parse(self, message: bytes, domain: bytes) -> dict:
        from prismpath.kernel import canon2
        raw = message[len(domain):]
        try:
            body = canon2.loads(raw)
        except (canon2.Canon2Error, UnicodeDecodeError, ValueError):
            raise SignerRefused("bad_body", "the bytes after the domain are not a canon/2 document") from None
        if not isinstance(body, dict) or canon2.dumps(body) != raw:
            raise SignerRefused("bad_body", "the body is not in its canonical canon/2 spelling")
        if body.get("key_id") != self.key.key_id or body.get("public_key") != self.key.public_raw.hex():
            raise SignerRefused("other_key", "the body names another key than the one this daemon holds")
        return body

    def sign(self, message: bytes) -> bytes:
        """The signature over `message`, or SignerRefused. Holds the lock: one decision at a time."""
        with self.lock:
            if message.startswith(rs.SIGNING_DOMAIN):
                body = self._parse(message, rs.SIGNING_DOMAIN)
                if set(body) != set(rs._BODY_FIELDS) or body["format"] != rs.STATEMENT_FORMAT:
                    raise SignerRefused("bad_body", f"not a {rs.STATEMENT_FORMAT} body")
                head = self.heads.get(body["log"])
                want_seq = 0 if head is None else head["seq"] + 1
                want_prev = "" if head is None else head["statement_sha256"]
                if type(body["seq"]) is not int or type(body["leaves"]) is not int:
                    raise SignerRefused("bad_body", "seq and leaves are integers")
                if head is not None and body["leaves"] < head["leaves"]:
                    raise SignerRefused("truncated", f"{body['leaves']} leaves after {head['leaves']} were signed")
                if head is not None and body["leaves"] == head["leaves"] and body["root"] != head["root"]:
                    raise SignerRefused("fork", "the same leaves under another root")
                if body["seq"] != want_seq or body["prev"] != want_prev:
                    raise SignerRefused("chain_broken", f"the next statement of {body['log']} is seq {want_seq} "
                                                        f"after the last one signed")
                sig = self.key.sign(message)
                statement = {**body, "sig": sig.hex()}
                self.heads[body["log"]] = {"seq": body["seq"], "leaves": body["leaves"], "root": body["root"],
                                           "statement_sha256": rs.statement_hash(statement), "statement": statement}
                self._save()                    # before the answer: a crash after this resumes from `head`
                return sig
            if message.startswith(CORE_RUN_ROOT_DOMAIN):
                body = self._parse(message, CORE_RUN_ROOT_DOMAIN)
                if set(body) != set(CORE_RUN_ROOT_MEMBERS) or body["format"] != CORE_RUN_ROOT_FORMAT:
                    raise SignerRefused("bad_body", f"not a {CORE_RUN_ROOT_FORMAT} body")
                return self.key.sign(message)
            raise SignerRefused("domain", "this daemon signs root statements and run roots only")

    def head(self, log: str) -> Optional[dict]:
        with self.lock:
            entry = self.heads.get(log)
            return dict(entry["statement"]) if entry else None

    # the socket
    def bind(self) -> None:
        directory = os.path.dirname(os.path.abspath(self.socket_path))
        os.makedirs(directory, mode=0o700, exist_ok=True)
        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)
        old = os.umask(0o177)
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.bind(self.socket_path)
        finally:
            os.umask(old)
        os.chmod(self.socket_path, 0o600)
        sock.listen(16)
        sock.settimeout(0.2)
        self._sock = sock

    def _answer(self, conn: socket.socket) -> None:
        pid, uid, _gid = peer_credentials(conn)
        refusal = self.check_caller(pid, uid)
        try:
            request = _recv(conn)
        except (ValueError, ConnectionError, struct.error):
            return
        if refusal is not None:
            self.refusals.append({"reason": refusal, "pid": pid, "uid": uid})
            _send(conn, {"ok": False, "refused": refusal})
            return
        op = request.get("op")
        try:
            if op == "public":
                _send(conn, {"ok": True, "public_key": self.key.public_raw.hex()})
            elif op == "head" and isinstance(request.get("log"), str):
                _send(conn, {"ok": True, "statement": self.head(request["log"])})
            elif op == "sign" and isinstance(request.get("message"), str):
                message = base64.b64decode(request["message"].encode("ascii"), validate=True)
                _send(conn, {"ok": True, "sig": self.sign(message).hex()})
            else:
                _send(conn, {"ok": False, "refused": "bad_request"})
        except SignerRefused as refused:
            self.refusals.append({"reason": refused.reason, "pid": pid, "uid": uid})
            _send(conn, {"ok": False, "refused": refused.reason, "message": refused.detail})
        except (ValueError, TypeError):
            _send(conn, {"ok": False, "refused": "bad_request"})

    def serve_forever(self) -> None:
        if self._sock is None:
            self.bind()
        while not self._stop.is_set():
            try:
                conn, _addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                conn.settimeout(5)
                try:
                    self._answer(conn)
                except OSError:
                    pass

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            self._sock.close()
            self._sock = None
        try:
            os.unlink(self.socket_path)
        except OSError:
            pass


# ------------------------------------------------------------------ the client
class DaemonKey:
    """An instance key the deployment does not hold: a `ChainSigner` (`prismpath.ports.keys`), the same face as
    `InstanceKey` (`public_raw`, `key_id`, `fingerprint`, `sign`) and `head`, each signature asked of the daemon at
    `socket_path`. `keys.load_signer("unix:PATH")` makes one."""

    def __init__(self, socket_path: str, timeout: float = 5.0):
        self.socket_path = socket_path
        self.timeout = timeout
        self.path = None
        answer = self._ask({"op": "public"})
        self.public_raw = bytes.fromhex(answer["public_key"])
        self.key_id = keys.key_id_of(self.public_raw)
        self.fingerprint = keys.fingerprint(self.key_id)

    def _ask(self, request: Dict[str, Any]) -> Dict[str, Any]:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            sock.connect(self.socket_path)
            _send(sock, request)
            answer = _recv(sock)
        if not answer.get("ok"):
            raise SignerRefused(str(answer.get("refused", "unknown")), str(answer.get("message", "")))
        return answer

    def sign(self, data: bytes) -> bytes:
        return bytes.fromhex(self._ask({"op": "sign", "message": base64.b64encode(data).decode("ascii")})["sig"])

    def head(self, log: str) -> Optional[dict]:
        """The last statement the daemon signed for `log`, or None."""
        return self._ask({"op": "head", "log": log})["statement"]

    def __repr__(self) -> str:
        return f"DaemonKey(fingerprint={self.fingerprint!r}, socket={self.socket_path!r})"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m prismpath.ledgers.signer_daemon",
                                     description="Hold the instance key and sign root statements for local callers.")
    parser.add_argument("--key", required=True, help="the instance private key (PEM), readable by this process only")
    parser.add_argument("--socket", required=True, help="the Unix socket to answer on (created mode 0600)")
    parser.add_argument("--state", required=True, help="the chain heads file (canon/2, written atomically)")
    parser.add_argument("--fresh", action="store_true", help="a new deployment: start with no chain heads")
    parser.add_argument("--allow-uid", type=int, action="append", default=None, help="a user id that may ask")
    args = parser.parse_args(argv)
    daemon = SignerDaemon(rs.InstanceKey.load(args.key), args.socket, args.state, allowed_uids=args.allow_uid,
                          fresh=args.fresh)
    daemon.bind()
    print(f"signing as {daemon.key.fingerprint} on {args.socket}", flush=True)
    try:
        daemon.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        daemon.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
