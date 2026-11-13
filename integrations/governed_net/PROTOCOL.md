# The governed net protocol, version 1

One tool call is one UDP datagram to port **47011**. The datagram's header *is* the call, written as typed
integers at fixed offsets, so a program that sees only bytes (an XDP program in the kernel, which can't
parse text or check a signature) can decide it. Everything is big endian. The reference reader is
[`protocol.py`](protocol.py), and the kernel's reader is
[`prismpath-ebpf/gnet/gn_xdp.h`](../../prismpath-ebpf/gnet/gn_xdp.h), which runs the same checks in the
same order.

## 1. Design principles

1. **XDP sees packets, not intentions.** The decided part of a request holds no free form text: no shell
   command, no path, no URL. A file or directory is named by an integer **handle** that the tool server
   issued, and the handle's **class** (workspace file, workspace directory, toolchain file, toolchain
   directory) is a header field. A program is named by an id from a closed list. The policy decides
   directly on these integers, so the local harness's classifier (trusted Python outside the verified
   core, reading shell strings and paths) has no counterpart here. Section 4 lists which attack classes
   vanish this way and which remain policy decisions.
2. **A lying client can set any header it wants.** XDP decides what the header says. The tool server
   therefore re-derives the decided fields from its own state (the class from its own handle table, the
   lengths from the bytes carried) and decides again with the Python kernel on the same signed image.
   Any disagreement between the two decisions is recorded as a finding and never executed. An allowed
   call runs confined, under bubblewrap, with only the workspace writable and no network.
3. **XDP cannot sign.** It reports each decision (request id, image index, matched rule, cause and the
   decided fields) through a ring buffer to a userspace logger, which writes the canon/2 core receipt and
   the signed root the way `governed_harness/evidence.py` does. `formal/diff/core_evidence.py` verifies
   the result.

## 2. Request

| Offset | Size | Field | Rule |
|-------:|-----:|-------|------|
| 0 | 4 | magic | `0x474E4554` ("GNET") |
| 4 | 1 | version | 1 |
| 5 | 1 | cmd | 1 to 11 (table below) |
| 6 | 1 | hclass | 0 none, 1 workspace file, 2 workspace dir, 3 toolchain file, 4 toolchain dir; any other value reads, and the policy refuses it |
| 7 | 1 | name_len | 0 to 64 |
| 8 | 8 | request_id | nonzero |
| 16 | 4 | handle | a handle the server issued (1 is the workspace root) |
| 20 | 4 | arg0 | below 2^31 |
| 24 | 4 | arg1 | below 2^31 |
| 28 | 2 | data_len | 0 to 1024 |
| 30 | 2 | flags, reserved | 0 |
| 32 | name_len | name | CREATE only: one file name, `[A-Za-z0-9_][A-Za-z0-9_.-]*` |
| 32 + name_len | data_len | data | WRITE and CREATE: the content; GIT_COMMIT: the message |

The datagram's length must be exactly `32 + name_len + data_len`.

| cmd | Name | Uses | Meaning |
|----:|------|------|---------|
| 1 | LIST | handle (dir) | the directory's entries, each with a handle and its class |
| 2 | READ | handle (file), arg0 offset, arg1 length | a part of a file |
| 3 | WRITE | handle (file), data | overwrite a file |
| 4 | CREATE | handle (dir), name, data | create a new file; the reply carries its handle |
| 5 | DELETE | handle (file) | delete one file |
| 6 | RUN | handle (file), arg0 program | 1 `wc -l`, 2 `sha256sum`, 3 `grep -n TODO`, with the file as the one operand |
| 7 | GIT_STATUS | nothing | |
| 8 | GIT_LOG | arg0 count | |
| 9 | GIT_COMMIT | data (message) | stage everything, commit |
| 10 | GIT_PUSH | arg0 remote id | |
| 11 | GIT_FETCH | arg0 remote id | |

**Strict reading.** A datagram is refused, and never guessed at, when any of the following holds. The
checks run in this order, and the reason numbers are shared by both readers:

| # | Reason | When |
|--:|--------|------|
| 1 | short | fewer than 32 bytes |
| 2 | magic | wrong magic |
| 3 | version | version other than 1 |
| 4 | command | cmd 0 or above 11 |
| 5 | reserved | the flags or the reserved byte is nonzero |
| 7 | name-length | name_len above 64 |
| 8 | data-length | data_len above 1024 |
| 6 | length | the datagram is not exactly 32 + name_len + data_len bytes (short or trailing bytes) |
| 9 | arg-range | arg0 or arg1 has its top bit set |
| 12 | request-id | the request id is 0 |
| 11 | unused-field | a field the command does not use is nonzero (handle and hclass, arg0, arg1, name, data) |
| 10 | name-char | a name byte outside the alphabet, or a first byte that is `.` or `-` |

The enforcement point adds frame reasons of its own: 20 (a first IP fragment to the port), 21 (the UDP
length disagrees with the IP length or the frame), 22 (the IP header length is inconsistent).

**What the policy reads.** It reads seven integers: `version`, `cmd`, `hclass`, `arg0`, `arg1`, `name_len`
and `data_len`, in that register order. The handle number, the request id, the name's bytes and the data's
bytes are not decided. The handle is resolved by the server, and the name's alphabet is a reading rule
that both readers enforce.

## 3. Reply, listing, status

A reply is `magic "GNTR" (4) | version (1) | status (1) | cause code (2) | request id (8) | receipt index
(4) | body length (4) | body`. The statuses are 0 ok, 1 tool error, 2 refused, 3 escalated, 4 finding (the
server would not run what arrived), 5 bad request, and 6 unknown. A LIST body, and a CREATE body for the
new file, is a sequence of entries `class (1) | handle (4) | name length (1) | name`.

A dropped request gets no reply on the wire. The client asks the receipt logger on its own status port
(47012 by default, which is not the protocol's port, so XDP passes it) with `"GNSQ" (4) | request id (8)`,
and the answer is a reply carrying the decision's status, cause and receipt index. That answer is
information for the client. It isn't authority, and the receipts are the record.

## 4. What the protocol removes, and what stays a policy decision

**Gone by construction.** These requests can't be written, so nothing has to decide them:

| Local harness rule | Why it can't be expressed here |
|---|---|
| outside the workspace (111) | no path crosses the wire, and a handle exists only for an entry the server listed inside the workspace |
| path traversal (109) | no path. The one name field can't contain `/` and can't start with `.`, so neither `..` nor `.` can be sent |
| glob path (108) | no path. `*`, `?`, `[`, `]`, `{`, `}` and `~` are outside the name alphabet |
| symbolic link (110) | the server never issues a handle for a link (links are not listed), so a request can't name one |
| kill by pattern (105) | there is no signal command, and RUN takes a program id from a list of three readers |
| shell mutation (112) | there is no shell and no argv. The programs are fixed |
| unclassifiable call (104, for malformed calls) | a malformed request is refused by the strict reader before any policy, at the enforcement point and again at the server |

The classifier trust boundary of the local harness is gone with them. Nothing reads intent out of a
string, because the request carries no string that is decided.

**Still policy decisions.** These are rules in the signed image, decided on the header's integers:

| Rule | Decision |
|---|---|
| hclass above 4 | refuse, `agent:unclassifiable` (104) |
| WRITE, CREATE or DELETE on a toolchain class | refuse, `agent:toolchain-write` (107) |
| GIT_FETCH | refuse, `agent:network` (106) |
| GIT_PUSH | escalate, `agent:push-escalated` (113) |
| LIST of a directory class; READ of a file class with a length from 1 to 4096; WRITE or DELETE of a workspace file; CREATE in a workspace directory with a name; RUN of a listed program on a file class; GIT_STATUS; GIT_LOG with a count from 1 to 50; GIT_COMMIT with a message | allow |
| anything else (a READ of a directory, a LIST of a file, a count of 0) | refuse, `route:no-matching-edge` (32), the core's own fail closed |

**Moved, not gone.** The trust these rules need has moved to the server's handle table. A class in a
header is a claim. The server's table says what the handle is, and a claim that disagrees with the table
is a finding, so it never runs. What a handle *names* (that `.toolchain/VERSION` is a toolchain file) is
the server's classification of its own directory tree, done when it issues the handle. That
classification is trusted code outside the verified core, as the classifier was. It is much smaller (one
prefix test and an `lstat`), and it reads the server's own disk rather than an untrusted string.
