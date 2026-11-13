# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The governed net protocol (PROTOCOL.md): one tool call as one fixed layout UDP datagram.

The header IS the call, in typed integers, so that an XDP program, which sees bytes and cannot parse
text, can decide it. There is no path, no shell text and no free form argument in the decided part: a
file is named by a handle the tool server issued, a program by an id from a closed list. The only bytes
after the header are a file name (CREATE only, one component of a fixed alphabet) and opaque data (the
content of a write, a commit message), whose lengths are header fields.

Reading is strict, on both sides of the wire and in the kernel alike: a datagram is refused (never
guessed at) when it is short, carries trailing bytes, has the wrong magic or version, a nonzero flag or
reserved field, an unknown command, an argument with the top bit set, a name or data length past its
bound, a name outside the alphabet, or a nonzero field its command does not use. `decode` raises
`Malformed` with one of the `REASONS`, whose number the XDP program reports for the same datagram.

Everything is big endian (network order).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict

MAGIC = 0x474E4554             # "GNET"
VERSION = 1
HEADER = struct.Struct(">IBBBBQIIIHH")
HEADER_LEN = HEADER.size       # 32
assert HEADER_LEN == 32
NAME_MAX = 64
DATA_MAX = 1024
ARG_MAX = 2 ** 31 - 1          # the policy's registers are signed 32 bit; the top bit must be clear
PORT = 47011                   # the agent protocol's UDP port; every other port is not the protocol's

# commands: a closed enum
LIST, READ, WRITE, CREATE, DELETE, RUN, GIT_STATUS, GIT_LOG, GIT_COMMIT, GIT_PUSH, GIT_FETCH = range(1, 12)
COMMANDS = {LIST: "list", READ: "read", WRITE: "write", CREATE: "create", DELETE: "delete", RUN: "run",
            GIT_STATUS: "git_status", GIT_LOG: "git_log", GIT_COMMIT: "git_commit", GIT_PUSH: "git_push",
            GIT_FETCH: "git_fetch"}
CMD_MAX = max(COMMANDS)

# handle classes, fixed by the tool server when it issues a handle; the policy decides on the class
H_NONE, H_WS_FILE, H_WS_DIR, H_TC_FILE, H_TC_DIR = 0, 1, 2, 3, 4
HCLASSES = {H_NONE: "none", H_WS_FILE: "workspace_file", H_WS_DIR: "workspace_dir", H_TC_FILE: "toolchain_file",
            H_TC_DIR: "toolchain_dir"}
ROOT_HANDLE = 1                # the workspace root, class H_WS_DIR, in every session

# RUN programs: a closed list, each a fixed argv with the file as its one operand
PROGRAMS = {1: ("wc_lines", ["wc", "-l"]), 2: ("sha256", ["sha256sum"]), 3: ("grep_todo", ["grep", "-n", "TODO"])}

# which fields each command uses; every other field must be zero
USES_HANDLE = {LIST, READ, WRITE, CREATE, DELETE, RUN}
USES_ARG0 = {READ, RUN, GIT_LOG, GIT_PUSH, GIT_FETCH}
USES_ARG1 = {READ}
USES_NAME = {CREATE}
USES_DATA = {WRITE, CREATE, GIT_COMMIT}

# why a datagram is malformed; the numbers are the XDP program's (gn_xdp.h, GN_BAD_*)
REASONS = {1: "short", 2: "magic", 3: "version", 4: "command", 5: "reserved", 6: "length", 7: "name-length",
           8: "data-length", 9: "arg-range", 10: "name-char", 11: "unused-field", 12: "request-id"}
REASON_CODE = {name: code for code, name in REASONS.items()}

NAME_FIRST = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_")
NAME_REST = NAME_FIRST | frozenset(b".-")

# the policy's fields, in the register order the XDP program fills (gn_xdp.h, gn_fill)
SCHEMA = ("version", "cmd", "hclass", "arg0", "arg1", "name_len", "data_len")


class Malformed(ValueError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason
        self.code = REASON_CODE[reason]


@dataclass(frozen=True)
class Request:
    cmd: int
    request_id: int
    hclass: int = 0
    handle: int = 0
    arg0: int = 0
    arg1: int = 0
    name: bytes = b""
    data: bytes = b""
    version: int = VERSION
    magic: int = MAGIC
    flags: int = 0
    reserved: int = 0

    def reading(self, hclass: int = None) -> Dict[str, int]:
        """The policy's reading of this request: the decided fields, all integers. `hclass` overrides the
        class the request claims (the tool server re-derives it from its own handle table)."""
        return {"version": self.version, "cmd": self.cmd, "hclass": self.hclass if hclass is None else hclass,
                "arg0": self.arg0, "arg1": self.arg1, "name_len": len(self.name), "data_len": len(self.data)}


def encode(req: Request) -> bytes:
    """The datagram of a request, exactly as written; no check, so tests and probes can build malformed ones."""
    return HEADER.pack(req.magic, req.version, req.cmd, req.hclass, len(req.name), req.request_id, req.handle,
                       req.arg0, req.arg1, len(req.data), (req.flags << 8) | req.reserved) + req.name + req.data


def decode(raw: bytes) -> Request:
    """The request a datagram carries, read strictly, or `Malformed`. The order of the checks is the XDP
    program's, so both name the same reason for the same bytes."""
    if len(raw) < HEADER_LEN:
        raise Malformed("short")
    magic, version, cmd, hclass, name_len, request_id, handle, arg0, arg1, data_len, tail = HEADER.unpack_from(raw)
    if magic != MAGIC:
        raise Malformed("magic")
    if version != VERSION:
        raise Malformed("version")
    if not 1 <= cmd <= CMD_MAX:
        raise Malformed("command")
    if tail != 0:
        raise Malformed("reserved")
    if name_len > NAME_MAX:
        raise Malformed("name-length")
    if data_len > DATA_MAX:
        raise Malformed("data-length")
    if len(raw) != HEADER_LEN + name_len + data_len:
        raise Malformed("length")
    if arg0 > ARG_MAX or arg1 > ARG_MAX:
        raise Malformed("arg-range")
    if request_id == 0:
        raise Malformed("request-id")
    if ((cmd not in USES_HANDLE and (hclass or handle)) or (cmd not in USES_ARG0 and arg0)
            or (cmd not in USES_ARG1 and arg1) or (cmd not in USES_NAME and name_len)
            or (cmd not in USES_DATA and data_len)):
        raise Malformed("unused-field")
    name = raw[HEADER_LEN:HEADER_LEN + name_len]
    for index, byte in enumerate(name):
        if byte not in (NAME_FIRST if index == 0 else NAME_REST):
            raise Malformed("name-char")
    data = raw[HEADER_LEN + name_len:]
    return Request(cmd=cmd, request_id=request_id, hclass=hclass, handle=handle, arg0=arg0, arg1=arg1,
                   name=bytes(name), data=bytes(data), version=version)


# ----------------------------------------------------------------- replies (server to client)
REPLY = struct.Struct(">IBBHQII")      # magic, version, status, cause code, request id, receipt index, body length
REPLY_LEN = REPLY.size                  # 24
REPLY_MAGIC = 0x474E5452                # "GNTR"
OK, TOOL_ERROR, REFUSED, ESCALATED, FINDING, BAD_REQUEST, STATUS_UNKNOWN = range(7)
STATUSES = {OK: "ok", TOOL_ERROR: "tool_error", REFUSED: "refused", ESCALATED: "escalated", FINDING: "finding",
            BAD_REQUEST: "bad_request", STATUS_UNKNOWN: "unknown"}
BODY_MAX = 8192


@dataclass(frozen=True)
class Reply:
    status: int
    request_id: int
    cause_code: int = 0
    receipt: int = 0
    body: bytes = b""


def encode_reply(rep: Reply) -> bytes:
    body = rep.body[:BODY_MAX]
    return REPLY.pack(REPLY_MAGIC, VERSION, rep.status, rep.cause_code, rep.request_id, rep.receipt, len(body)) + body


def decode_reply(raw: bytes) -> Reply:
    if len(raw) < REPLY_LEN:
        raise Malformed("short")
    magic, version, status, cause, request_id, receipt, body_len = REPLY.unpack_from(raw)
    if magic != REPLY_MAGIC:
        raise Malformed("magic")
    if version != VERSION:
        raise Malformed("version")
    if status not in STATUSES:
        raise Malformed("command")
    if body_len > BODY_MAX or len(raw) != REPLY_LEN + body_len:
        raise Malformed("length")
    return Reply(status, request_id, cause, receipt, bytes(raw[REPLY_LEN:]))


# ----------------------------------------------------------------- LIST bodies: the handles the server issues
ENTRY = struct.Struct(">BIB")          # class, handle, name length; then the name


def encode_listing(entries) -> bytes:
    out = bytearray()
    for hclass, handle, name in entries:
        raw = name.encode("utf-8")[:255]
        out += ENTRY.pack(hclass, handle, len(raw)) + raw
    return bytes(out)


def decode_listing(body: bytes):
    entries, pos = [], 0
    while pos < len(body):
        if pos + ENTRY.size > len(body):
            raise Malformed("length")
        hclass, handle, length = ENTRY.unpack_from(body, pos)
        pos += ENTRY.size
        if pos + length > len(body):
            raise Malformed("length")
        entries.append((hclass, handle, body[pos:pos + length].decode("utf-8", "replace")))
        pos += length
    return entries
