# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The Landlock backend of the per call sandbox: the same profile, applied by the
kernel to one process instead of by a mount namespace.

Why it exists. bubblewrap needs a user namespace, and on Ubuntu 24.04 an AppArmor setting forbids a bwrap inside a bwrap,
so under `prismpath agent run` the nested per call sandbox cannot start and every shell command is refused with cause
129. Landlock needs no namespace and no privilege (Linux 5.13 and later). The runner, already inside the outer agent
sandbox, applies the bash role profile to the child that will run the command, and then execs it.

What the child gets, for a profile with no network (the only kind the per call layer runs):

  * files: read and execute under the profile's read only mounts, everything under the workspace, one private scratch
    directory (`TMPDIR` and `HOME`), the five harmless character devices and a few global facts of `/proc`
    (`cpuinfo`, `meminfo`, `loadavg`, `uptime`, `version`). Not `/proc/self` or any other process's entry: a rule is
    bound to one pid, and the outer sandbox's `/proc` lists the agent, whose environment is not the command's to read. Nothing else, so the model credential, the agent's home,
    the staged sockets and every other process's `/proc` entry are out of reach. What the outer sandbox mounted
    read only over the workspace (the control paths, `.toolchain`) stays read only, because a mount flag is below
    Landlock. Without that mount a `.toolchain` directory would be writable here, so the backend refuses to run then.
  * network: from ABI 4 Landlock handles TCP bind and connect and the child is given no port, so every TCP connect
    and bind fails. Before ABI 4 there is no such control, and the child could still reach the outer sandbox's relay
    on 127.0.0.1:3128 (which forwards to the egress proxy). The choice made here is the seccomp filter below, which
    refuses `socket()` outright, on every ABI. A process with no socket has nothing to connect. It also closes what no
    Landlock ABI before 9 does, a connect to a unix socket by path (the proxy's and the decider's, both in /tmp
    of the outer sandbox), and UDP, and it refuses `io_uring`, which could open a socket behind the filter. The
    environment carries no proxy variable either. `socketpair()` stays, because a pipe between a command's own
    processes is no route out.
  * a small seccomp filter, justified by the line above and by the processes the outer sandbox does share with the
    child (no PID namespace here): `ptrace`, `process_vm_readv` and `process_vm_writev` are refused, and so are the
    System V shared memory, semaphore and message queue calls (the outer sandbox's IPC namespace is shared).
  * processes: `RLIMIT_NPROC`. Unlike inside bwrap's namespace the count is of every task of this user in the outer
    sandbox, so the limit is the tasks there now plus the profile's `max_processes`.
  * signals: from ABI 6 the child's Landlock domain cannot signal a process outside it. Before ABI 6 it can signal
    another process of the same user in the outer sandbox (the agent itself). That is a gap bubblewrap does not have,
    reported by `describe()` and left open: there is no seccomp rule that tells the agent's pid from the child's own.

Everything stricter than the bubblewrap view and never wider: a path bwrap would show that Landlock does not (`/tmp`,
`/dev/tty`) is simply absent. The runner (sandbox_exec.py) refuses a profile this backend cannot honor, that is one
with a network or a proxy, and the caller then falls back to nothing: a refusal.

Standard library only (ctypes). x86_64 and aarch64; any other machine reports the backend as unavailable.
"""
from __future__ import annotations

import ctypes
import errno
import os
import platform
import struct
import sys
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Tuple

# ---- syscall numbers (the same on x86_64 and aarch64 for the three Landlock calls)
_SYS_CREATE, _SYS_ADD_RULE, _SYS_RESTRICT = 444, 445, 446
CREATE_RULESET_VERSION = 1 << 0
RULE_PATH_BENEATH, RULE_NET_PORT = 1, 2

# ---- filesystem access rights
FS_EXECUTE, FS_WRITE_FILE, FS_READ_FILE, FS_READ_DIR = 1 << 0, 1 << 1, 1 << 2, 1 << 3
FS_REMOVE_DIR, FS_REMOVE_FILE = 1 << 4, 1 << 5
FS_MAKE_CHAR, FS_MAKE_DIR, FS_MAKE_REG, FS_MAKE_SOCK, FS_MAKE_FIFO, FS_MAKE_BLOCK, FS_MAKE_SYM = (
    1 << 6, 1 << 7, 1 << 8, 1 << 9, 1 << 10, 1 << 11, 1 << 12)
FS_REFER, FS_TRUNCATE, FS_IOCTL_DEV, FS_RESOLVE_UNIX = 1 << 13, 1 << 14, 1 << 15, 1 << 16
NET_BIND_TCP, NET_CONNECT_TCP = 1 << 0, 1 << 1
SCOPE_ABSTRACT_UNIX_SOCKET, SCOPE_SIGNAL = 1 << 0, 1 << 1

_FS_V1 = (1 << 13) - 1
# (first ABI that has it, right)
_FS_BY_ABI = ((2, FS_REFER), (3, FS_TRUNCATE), (5, FS_IOCTL_DEV), (9, FS_RESOLVE_UNIX))

RO = FS_EXECUTE | FS_READ_FILE | FS_READ_DIR
READ_ONLY_DATA = FS_READ_FILE | FS_READ_DIR
FILE_RIGHTS = FS_EXECUTE | FS_WRITE_FILE | FS_READ_FILE | FS_TRUNCATE | FS_IOCTL_DEV      # what a rule on a non directory may carry

DEVICES = ("/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom")
PROC_FILES = ("/proc/cpuinfo", "/proc/meminfo", "/proc/loadavg", "/proc/uptime", "/proc/version")

# ---- seccomp
_AUDIT_ARCH = {"x86_64": 0xC000003E, "aarch64": 0xC00000B7}
_SECCOMP_RET_ALLOW, _SECCOMP_RET_KILL_PROCESS = 0x7FFF0000, 0x80000000
_SECCOMP_RET_ERRNO = 0x00050000
_PR_SET_NO_NEW_PRIVS, _PR_SET_SECCOMP, _SECCOMP_MODE_FILTER = 38, 22, 2
_PR_SET_CHILD_SUBREAPER = 36
# name -> (x86_64, aarch64)
_DENIED = {
    "socket": (41, 198),
    "ptrace": (101, 117), "process_vm_readv": (310, 270), "process_vm_writev": (311, 271),
    "io_uring_setup": (425, 425), "io_uring_enter": (426, 426), "io_uring_register": (427, 427),
    "shmget": (29, 194), "shmat": (30, 196), "shmctl": (31, 195), "shmdt": (67, 197),
    "semget": (64, 190), "semop": (65, 193), "semctl": (66, 191), "semtimedop": (220, 192),
    "msgget": (68, 186), "msgsnd": (69, 189), "msgrcv": (70, 188), "msgctl": (71, 187),
}

_libc: Optional[ctypes.CDLL] = None


class LandlockUnavailable(RuntimeError):
    """The Landlock backend cannot confine this call here, so nothing was run."""


def _c() -> ctypes.CDLL:
    global _libc
    if _libc is None:
        _libc = ctypes.CDLL(None, use_errno=True)
    return _libc


def _machine() -> str:
    return platform.machine().lower().replace("arm64", "aarch64").replace("amd64", "x86_64")


def abi_version() -> int:
    """The kernel's Landlock ABI, or 0 when Landlock is not usable here (a kernel before 5.13, a build or a boot
    setting without it, a platform that is not Linux, or a machine this module has no syscall table for)."""
    if not sys.platform.startswith("linux") or _machine() not in _AUDIT_ARCH:
        return 0
    try:
        got = _c().syscall(_SYS_CREATE, None, ctypes.c_size_t(0), ctypes.c_uint32(CREATE_RULESET_VERSION))
    except (OSError, AttributeError):
        return 0
    return int(got) if got > 0 else 0


def available() -> bool:
    return abi_version() >= 1


def handled_fs(abi: int) -> int:
    mask = _FS_V1
    for first, right in _FS_BY_ABI:
        if abi >= first:
            mask |= right
    return mask


def handled_net(abi: int) -> int:
    return (NET_BIND_TCP | NET_CONNECT_TCP) if abi >= 4 else 0


def handled_scope(abi: int) -> int:
    return (SCOPE_ABSTRACT_UNIX_SOCKET | SCOPE_SIGNAL) if abi >= 6 else 0


def describe(abi: Optional[int] = None) -> dict:
    """What the backend enforces at this ABI, for status output and the tests."""
    abi = abi_version() if abi is None else abi
    return {"backend": "landlock", "abi": abi, "files": abi >= 1, "tcp": abi >= 4, "signals_scoped": abi >= 6,
            "abstract_unix_scoped": abi >= 6, "unix_path_by_landlock": abi >= 9, "seccomp_socket_deny": True}


# ------------------------------------------------------------------------------------------------- seccomp
def seccomp_program(machine: Optional[str] = None) -> bytes:
    """The BPF program: any syscall made through another architecture's table, or the x32 one, kills the process; the
    denied calls return EPERM; every other call is allowed (this filter removes reach, it is not the file policy)."""
    machine = machine or _machine()
    if machine not in _AUDIT_ARCH:
        raise LandlockUnavailable(f"no syscall table for {machine}")
    column = 0 if machine == "x86_64" else 1
    code: List[Tuple[int, int, int, int]] = []

    def ins(op: int, jt: int, jf: int, k: int) -> None:
        code.append((op, jt, jf, k))
    ins(0x20, 0, 0, 4)                                       # ld arch
    ins(0x15, 1, 0, _AUDIT_ARCH[machine])                    # arch matches: skip the kill
    ins(0x06, 0, 0, _SECCOMP_RET_KILL_PROCESS)
    ins(0x20, 0, 0, 0)                                       # ld nr
    if machine == "x86_64":
        ins(0x35, 0, 1, 0x40000000)                          # the x32 range
        ins(0x06, 0, 0, _SECCOMP_RET_KILL_PROCESS)
    for number in sorted({pair[column] for pair in _DENIED.values()}):
        ins(0x15, 0, 1, number)
        ins(0x06, 0, 0, _SECCOMP_RET_ERRNO | errno.EPERM)
    ins(0x06, 0, 0, _SECCOMP_RET_ALLOW)
    return b"".join(struct.pack("=HBBI", *i) for i in code)


def _install_seccomp() -> None:
    program = seccomp_program()
    buf = ctypes.create_string_buffer(program, len(program))
    fprog = struct.pack("@H6xP", len(program) // 8, ctypes.addressof(buf))
    holder = ctypes.create_string_buffer(fprog, len(fprog))
    if _c().prctl(_PR_SET_SECCOMP, _SECCOMP_MODE_FILTER, ctypes.c_ulong(ctypes.addressof(holder)), 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "seccomp filter")


# ------------------------------------------------------------------------------------------------ ruleset
@dataclass(frozen=True)
class Rule:
    path: str
    access: int


def workspace_rules(workspace: str, holes: Iterable[str]) -> List[Rule]:
    """The rules that make the workspace writable except for `holes`, which stay read only (the control paths,
    controls.py, and a `.toolchain` that no mount protects). Landlock rules only add access to a whole tree, so a
    read only hole inside a writable tree cannot be said. Instead every directory that has a hole at or below it is not
    granted as a whole: its entries are, one by one, a whole tree for a directory with no hole beneath it, read and
    write on the file for a file, read only for a hole, and a directory with a hole below is entered the same way.
    No hole means one rule for the whole workspace. What that costs is the creation, rename and removal of entries
    directly in a directory that holds a hole (the workspace root always does: `.claude`, `CLAUDE.md`; and `.git`, which holds
    `config` and `hooks`): a new file cannot be made there, an existing one can be rewritten but not deleted or
    renamed. Everything below a directory with no hole is unrestricted. Links are skipped, so a link is never a way to
    a path that has no rule. A control file that does not exist yet can never be created, because its directory
    cannot take new entries."""
    holes = {os.path.normpath(h) for h in holes}
    if not holes:
        return [Rule(workspace, ~0)]
    rules: List[Rule] = []

    def below(path: str) -> bool:
        prefix = path.rstrip("/") + "/"
        return any(h.startswith(prefix) for h in holes)

    def plan(directory: str) -> None:
        rules.append(Rule(directory, FS_READ_DIR))
        try:
            with os.scandir(directory) as it:
                entries = list(it)
        except OSError:
            return
        for entry in entries:
            path, is_dir = entry.path, entry.is_dir(follow_symlinks=False)
            if entry.is_symlink():
                continue
            if path in holes:
                rules.append(Rule(path, RO if is_dir else FS_READ_FILE))
            elif is_dir:
                plan(path) if below(path) else rules.append(Rule(path, ~0))
            else:
                rules.append(Rule(path, FS_READ_FILE | FS_WRITE_FILE | FS_TRUNCATE | FS_EXECUTE))
    plan(workspace)
    return rules


def rules_for(ro_mounts: Sequence[str], host_write: bool, workspace: str, scratch: Optional[str], proc: bool = True,
              holes: Iterable[str] = ()) -> List[Rule]:
    """The path rules of a no network profile. The caller supplies the paths as they are in the outer sandbox, so the
    workspace is at its own path."""
    out: List[Rule] = []
    for path in ro_mounts:
        out.append(Rule(path, ~0 if (path == "/" and host_write) else RO))
    out.extend(workspace_rules(workspace, holes))
    if scratch:
        out.append(Rule(scratch, ~0))
    for device in DEVICES:
        out.append(Rule(device, FS_READ_FILE | FS_WRITE_FILE | FS_TRUNCATE | FS_IOCTL_DEV))
    if proc:
        for path in PROC_FILES:
            out.append(Rule(path, FS_READ_FILE))
    return out


def _create(abi: int, net: bool, scope: bool) -> int:
    fs = handled_fs(abi)
    net_mask = handled_net(abi) if net else 0
    scope_mask = handled_scope(abi) if scope else 0
    if abi >= 6:
        attr = struct.pack("=QQQ", fs, net_mask, scope_mask)
    elif abi >= 4:
        attr = struct.pack("=QQ", fs, net_mask)
    else:
        attr = struct.pack("=Q", fs)
    buf = ctypes.create_string_buffer(attr, len(attr))
    fd = _c().syscall(_SYS_CREATE, buf, ctypes.c_size_t(len(attr)), ctypes.c_uint32(0))
    if fd < 0:
        raise OSError(ctypes.get_errno(), "landlock_create_ruleset")
    return int(fd)


def _add(ruleset: int, handled: int, rule: Rule) -> bool:
    """Add one path rule. A path that does not exist is skipped (there is nothing to allow)."""
    try:
        fd = os.open(rule.path, os.O_PATH | os.O_CLOEXEC)
    except OSError:
        return False
    try:
        access = rule.access & handled
        if not os.path.isdir(rule.path):
            access &= FILE_RIGHTS
        if access == 0:
            return False
        attr = struct.pack("=Qi", access, fd)
        buf = ctypes.create_string_buffer(attr, len(attr))
        if _c().syscall(_SYS_ADD_RULE, ctypes.c_int(ruleset), ctypes.c_int(RULE_PATH_BENEATH), buf, ctypes.c_uint32(0)) != 0:
            raise OSError(ctypes.get_errno(), f"landlock_add_rule {rule.path}")
        return True
    finally:
        os.close(fd)


def enforce(rules: Iterable[Rule], abi: Optional[int] = None, net_rules: bool = True, seccomp: bool = True,
            scope_rules: bool = True, nproc: Optional[int] = None) -> None:
    """Confine the calling process, for good: no new privileges, the process limit, the seccomp filter, then the
    Landlock domain with `rules` (and, from ABI 4, no TCP port). It is called in the child between fork and exec.
    Raises OSError when any part cannot be applied, and the caller must then not exec."""
    abi = abi_version() if abi is None else abi
    if abi < 1:
        raise OSError(errno.ENOSYS, "Landlock is not available")
    if _c().prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "no_new_privs")
    if nproc is not None:
        import resource
        resource.setrlimit(resource.RLIMIT_NPROC, (nproc, nproc))
    ruleset = _create(abi, net_rules, scope_rules)
    try:
        handled = handled_fs(abi)
        for rule in rules:
            _add(ruleset, handled, rule)
        if seccomp:
            _install_seccomp()
        if _c().syscall(_SYS_RESTRICT, ctypes.c_int(ruleset), ctypes.c_uint32(0)) != 0:
            raise OSError(ctypes.get_errno(), "landlock_restrict_self")
    finally:
        os.close(ruleset)


def set_subreaper() -> None:
    """Make this process the parent of every orphan below it, so that the runner can end whatever a command left behind."""
    _c().prctl(_PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
