# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The `agent` target of policy distribution (spec-policy-distribution.md, section 3): one agent home. The hook,
the decider, the sandbox profile, the egress proxy and the MCP proxy all read it through
`prismpath.agent.commands.load_checked`, so they hold one release together.

In a distributed home the PEP's store is `<home>/dist/` and the committed release is read from it on every load
by `committed(home)`, which checks each envelope again: its signature under the trust store, its expiry, the
revocation list and the raised floor. A home that follows a stream holds no authority key. The adapter itself
keeps nothing of its own: activating a release is the PEP's active record, which every reader then finds, and
deactivating it is the lapse that record shows.

Its own check at commit (V11, C2) holds a staged `sandbox.profile` to the profile compiled from the staged
`policy.core` (`dist:derived-mismatch`). A staged `agent.zones` is read by the artifact's own V11 check at staging
(`kinds.read_zones`), and the adapter adds nothing to it.

A decider that runs long, the egress proxy's gate and the MCP proxy, follows the committed state through
`commands.Committed`, so a revocation, an expiry or a commit reaches it at its next decision.

A commit and a rollback have no runtime step here (C6): the durable active record is the switch, and a session
already running keeps its sandbox profile while the hook decides each of its calls under the new release. A lapse
and a revocation do have one. The launcher registers every sandboxed session it starts in a distributed home under
`<home>/dist/sessions/`, and the withdrawal ends each of them, a terminate first and a kill at a later try. Each
entry holds the session's identity with its pid, the boot id and the leader's start time (`/proc/<pid>/stat`
field 22), and a withdrawal signals only a process whose identity it read again and found the same, through a
pidfd where the kernel has one, and its process group, which the launcher starts as a new session. A pid that
now names another process, or an entry from before a reboot, is a session that ended: its entry is removed and
nothing is signalled. A platform without `/proc` (macOS) cannot read the identity, so it signals nothing and the
withdrawal reports the sessions it could not verify as running. A session that has not ended makes the
withdrawal fail, so the PEP stays `reconciling` with the release that fell as
the running release, and sends `lapsed` only once every session has ended (C6, H14).
"""
from __future__ import annotations

import os
import signal
import time as _time
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Tuple

from prismpath import canon
from prismpath.distribution import kinds
from prismpath.distribution.adapters import Adapter
from prismpath.distribution.kinds import Refused

DERIVED_MISMATCH = "dist:derived-mismatch"
clock = _time.time                                 # the home's clock, Unix seconds


class AgentHomeAdapter(Adapter):
    """The adapter of one agent home at `home`. `home` is also the directory K2 looks in for an authority key."""
    kind = "agent"

    def __init__(self, home, *, end_session=None):
        self.home = str(home)
        self.running = None
        self.end_session = end_session or end_process
        self.tries: Dict[int, int] = {}                # withdrawals each session has been asked to end in

    def check(self, artifact: str, body: bytes, staged: Mapping[str, Tuple[Any, bytes]]) -> Optional[str]:
        if artifact == "sandbox.profile" and "policy.core" in staged:
            from prismpath.agent.profile import ProfileError, compile_profile
            try:
                compiled = compile_profile(staged["policy.core"][1], "bash").canonical()
            except ProfileError:
                return DERIVED_MISMATCH
            return None if compiled == bytes(body) else DERIVED_MISMATCH
        return None

    def readings(self) -> list:
        """The readings the home's deciders noted since the last call, oldest first, taken off the spool (H5)."""
        return take_readings(self.home)

    def activate(self, release) -> None:
        self.running = release.policy_sha256       # no runtime step: every reader finds the active record (C6)

    def deactivate(self, cause: str) -> None:
        """The runtime step of a lapse or a revocation: end every sandboxed session still running. Raises
        `SessionsRunning` when one has not ended, so the PEP tries again at its next tick (C9, C10)."""
        self.running = None
        left = []
        for pid in sessions(self.home):
            tries = self.tries.get(pid, 0)
            if self.end_session(pid, session_identity(self.home, pid), tries):
                self.tries.pop(pid, None)
                forget_session(self.home, pid)
            else:
                self.tries[pid] = tries + 1
                left.append(pid)
        if left:
            raise SessionsRunning(f"{len(left)} sandboxed session(s) have not ended: {left}")


    def withdraw_to(self, fallback, cause: str) -> None:
        """FB1: every sandboxed session of the release that fell ends, as at a lapse, and every reader of the home then
        finds the fallback set (`pep.read_committed_release`)."""
        self.deactivate(cause)
        self.running = fallback.policy_sha256


class SessionsRunning(RuntimeError):
    """A sandboxed session of a release that fell is still running, so the withdrawal has not worked (C10)."""


SESSIONS = "sessions"


def register_session(home, pid: int, policy_sha256: str) -> None:
    """The launcher's note of a sandboxed session it started in a distributed home, so a lapse can end it (C6)."""
    if not is_distributed(home):
        return
    from prismpath.kernel import canon2
    directory = Path(home) / "dist" / SESSIONS
    directory.mkdir(exist_ok=True)
    entry = {"pid": int(pid), "policy_sha256": policy_sha256}
    identity = process_identity(pid)
    if identity is not None:
        entry["boot_id"], entry["start_time"] = identity
    canon.atomic_write_bytes(str(directory / f"{int(pid)}.json"), canon2.dumps(entry))


def session_identity(home, pid: int) -> Optional[Tuple[str, int]]:
    """The (boot id, start time) the launcher recorded for the session `pid`, None when the entry holds none."""
    from prismpath.kernel import canon2
    try:
        entry = canon2.loads((Path(home) / "dist" / SESSIONS / f"{int(pid)}.json").read_bytes())
        boot, start = entry["boot_id"], entry["start_time"]
    except Exception:  # noqa: BLE001 - an entry that cannot be read names no process the withdrawal may signal
        return None
    if not isinstance(boot, str) or not isinstance(start, int) or isinstance(start, bool):
        return None
    return boot, start


PROC = "/proc"


def can_identify() -> bool:
    """The platform shows a process's start time and the boot id, so a pid can be told from its reuse."""
    return os.path.isfile(os.path.join(PROC, "sys", "kernel", "random", "boot_id"))


def boot_id() -> Optional[str]:
    try:
        with open(os.path.join(PROC, "sys", "kernel", "random", "boot_id")) as handle:
            return handle.read().strip() or None
    except OSError:
        return None


def process_identity(pid: int) -> Optional[Tuple[str, int]]:
    """(boot id, start time in clock ticks since boot) of the running process `pid`, None when there is none or
    the platform has no `/proc`. The start time is field 22 of `/proc/<pid>/stat`, counted after the command name,
    which may hold spaces and parentheses."""
    boot = boot_id()
    if boot is None:
        return None
    try:
        with open(os.path.join(PROC, str(int(pid)), "stat"), "rb") as handle:
            stat = handle.read()
        return boot, int(stat[stat.rindex(b")") + 2:].split()[19])
    except (OSError, ValueError, IndexError):
        return None


def forget_session(home, pid: int) -> None:
    """A session that ended, by the launcher when its program exits or by a withdrawal that ended it."""
    try:
        os.remove(Path(home) / "dist" / SESSIONS / f"{int(pid)}.json")
    except OSError:
        return


def sessions(home) -> list:
    """The process ids of the sandboxed sessions registered in the home, in order."""
    try:
        names = os.listdir(Path(home) / "dist" / SESSIONS)
    except OSError:
        return []
    return sorted(int(name[:-5]) for name in names if name.endswith(".json") and name[:-5].isdigit())


def end_process(pid: int, identity: Optional[Tuple[str, int]], tries: int) -> bool:
    """End the session whose process group leader is `pid` and whose identity the launcher recorded as `identity`:
    a terminate at the first try, a kill after. True once it has ended. A launcher starts each session in a new
    session, so its process group is its pid. The identity is read again before any signal: a pid that names
    another process, an entry from before a reboot or an entry with no identity is a session that ended, and it is
    never signalled. A platform without `/proc` cannot tell, so it signals nothing and the session counts as
    running."""
    if not can_identify():
        return False
    if identity is None or process_identity(pid) != identity:
        return True
    sig = signal.SIGTERM if tries == 0 else signal.SIGKILL
    if not _signal_leader(pid, identity, sig):
        return True
    try:
        if process_identity(pid) == identity:  # the leader's pid is held while it or its group lives
            os.killpg(pid, sig)
    except ProcessLookupError:
        pass
    except PermissionError:
        return False
    for _ in range(20):
        if process_identity(pid) != identity or _reaped(pid):
            return True
        _time.sleep(0.01)
    return False


def _signal_leader(pid: int, identity: Tuple[str, int], sig: int) -> bool:
    """Send `sig` to the leader `pid` only while it is still the process of `identity`. With a pidfd the identity is
    checked after the pidfd is open, so the signal reaches that process and no later one. False when it is gone."""
    opener, sender = getattr(os, "pidfd_open", None), getattr(signal, "pidfd_send_signal", None)
    fd = None
    if opener is not None and sender is not None:
        try:
            fd = opener(pid)
        except ProcessLookupError:
            return False
        except OSError:
            fd = None                              # a kernel before 5.3: the check and the signal stay apart
    try:
        if process_identity(pid) != identity:
            return False
        try:
            if fd is not None:
                sender(fd, sig)
            else:
                os.kill(pid, sig)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True                            # still running; the group signal reports it
        return True
    finally:
        if fd is not None:
            os.close(fd)


def _reaped(pid: int) -> bool:
    """A child of this process that ended is reaped, so it no longer reads as running."""
    try:
        done, _status = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        return False
    return done == pid


SPOOL = "recent.jsonl"
SPOOL_KEEP = 64                                    # H5: a record carries at most the last 64 decisions


def note(home, reading: Mapping[str, Any]) -> None:
    """A decider of a distributed home (the egress proxy, the MCP proxy) hands the reading it decided to the PEP's
    ring for the next state record (H5). The spool keeps the last 64, and a reading that cannot be written is
    dropped: the decision stands and only the heartbeat misses it."""
    if not is_distributed(home):
        return
    from prismpath.kernel import canon2
    path = Path(home) / "dist" / SPOOL
    try:
        with open(path, "ab") as handle:
            handle.write(canon2.dumps(dict(reading)) + b"\n")
        if path.stat().st_size > 64 * 1024:
            lines = path.read_bytes().splitlines()[-SPOOL_KEEP:]
            canon.atomic_write_bytes(str(path), b"".join(line + b"\n" for line in lines))
    except (OSError, ValueError, TypeError):
        return


def take_readings(home) -> list:
    """The spooled readings, the last 64, and the spool emptied. The spool is moved aside before it is read, so a
    reading noted meanwhile starts a new spool rather than being removed unread."""
    from prismpath.kernel import canon2
    path = Path(home) / "dist" / SPOOL
    taking = path.with_name(SPOOL + ".taking")
    try:
        os.replace(path, taking)
        lines = taking.read_bytes().splitlines()
        taking.unlink()
    except OSError:
        return []
    out = []
    for line in lines[-SPOOL_KEEP:]:
        try:
            out.append(canon2.loads(line))
        except Exception:  # noqa: BLE001 - a torn line is a reading lost to the heartbeat, not to the decision
            continue
    return out


def is_distributed(home) -> bool:
    """A home that follows a stream: its PEP store holds a trust store."""
    return (Path(home) / "dist" / "trust.json").is_file()


def committed_until(home, now: Optional[int] = None, kind: str = "agent") -> Tuple[Dict[str, bytes], int]:
    """`committed`, and the earliest `expires` of the release's envelopes, 0 when none expires. `kind` is the
    target the home is, `agent` or `gateway`, whose homes have one layout."""
    from prismpath.distribution.pep import read_committed_release
    release = read_committed_release(str(home), kind, int(clock() if now is None else now))
    expiries = [envelope.expires for envelope in release.envelopes.values() if envelope.expires]
    return dict(release.bodies), min(expiries, default=0)


def committed(home, now: Optional[int] = None) -> Dict[str, bytes]:
    """The bodies of the release the home's PEP has active, {artifact: body}, held on every load to what the PEP
    machine holds it to (`pep.read_committed`): a locked PEP, an expired or revoked release, a floor a revocation
    raised and a signer the store no longer holds each refuse. No authority key is read."""
    from prismpath.distribution.pep import read_committed
    return read_committed(str(home), "agent", int(clock() if now is None else now))


def hosts(bodies: Mapping[str, bytes]) -> Tuple[str, ...]:
    """The committed `egress.hosts`, the only hosts a distributed home's egress proxy may reach."""
    return tuple(kinds.read_hosts(bodies["egress.hosts"]))

