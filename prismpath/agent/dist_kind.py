# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The `agent` target kind of policy distribution (spec-policy-distribution.md, section 3) and the adapter of one
agent home. Importing this module registers the kind (`kinds.register`): its row, the reader and comparator of
`egress.hosts`, the comparator of `agent.zones`, the agent's reading domain (`profile.AGENT_DOMAIN`), the policy it
decides with (`prismpath.agent.policy.Policy`), the domain it is built with (CL4, P4) and the checks of `prismpath
policy compile --target agent` (`prismpath.agent.target`). The hook, the decider, the sandbox profile, the egress
proxy and the MCP proxy all read the home through `prismpath.agent.commands.load_checked` and the home functions
of `prismpath.onion.home`, so they hold one release together.

In a distributed home the PEP's store is `<home>/dist/` and the committed release is read from it on every load
by `committed(home)`, which checks each envelope again: its signature under the trust store, its expiry, the
revocation list and the raised floor. A home that follows a stream holds no authority key. The adapter itself
keeps nothing of its own: activating a release is the PEP's active record, which every reader then finds, and
deactivating it is the lapse that record shows.

Its own check at commit (V11, C2) holds a staged `sandbox.profile` to the profile compiled from the staged
`policy.core` (`dist:derived-mismatch`). A staged `agent.zones` is read by the artifact's own V11 check at staging
(`kinds.read_zones`), and the adapter adds nothing to it.

A decider that runs long, the egress proxy's gate and the MCP proxy, follows the committed state through
`home.Committed`, so a revocation, an expiry or a commit reaches it at its next decision.

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
from typing import Any, Callable, Dict, Mapping, Optional, Sequence, Tuple

from prismpath import canon
from prismpath.distribution import kinds
from prismpath.distribution.kinds import Refused
from prismpath.onion import home as onion_home
from prismpath.onion.home import (SPOOL, SPOOL_KEEP, committed_until, is_distributed, note,  # noqa: F401
                                  take_readings)
from prismpath.ports.target import CANNOT_DECIDE, LARGER, NOT_LARGER, Adapter, TargetKind

DERIVED_MISMATCH = "dist:derived-mismatch"


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


    def floor_counts(self) -> Tuple[int, int]:
        """AF7, H10: the floor answers and overrides the home's deciders made since the last call, taken off their
        spool, for the counts of the next state record."""
        return take_floor_counts(self.home)

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


# ------------------------------------------------------------------ AF1: the action floor, asked first

FLOOR_SPOOL = "floor-answers.jsonl"               # under dist/install/: one line per floor answer, for H10's counts
FLOOR_LOCK = "floor.lock"
FLOOR_RECEIPTS = "floor-receipts.jsonl"           # the receipt of every floor answer, basis `floor` and `would`


def _install_dir(home) -> str:
    return os.path.join(str(home), "dist", "install")


def held_floor(home, kind: str = "agent"):
    """(the action floor the home's PEP holds, the install part) read as a start reads them (IS10), or (None, part)
    when it holds none or its install record is lost."""
    from prismpath.distribution import install
    installed = install.Installed(os.path.join(str(home), "dist"), reads_meta=kinds.TARGETS[kind].reads_meta)
    installed.load()
    if installed.record is None or installed.record_lost:
        return None, installed
    return installed.held(install.FLOOR), installed


def floor_image(home) -> Optional[bytes]:
    """The `policy.core` of the action floor the home's PEP holds, or None."""
    if not is_distributed(home):
        return None
    held, _installed = held_floor(home)
    return None if held is None else held.bodies.get("policy.core")


def ask_floor(home, request: Mapping[str, Any], *, kind: str = "agent", now: Optional[int] = None) -> Optional[dict]:
    """AF1, AF2, AF7, AF8: what the action floor of a distributed home answers `request`, asked by the hook, the egress
    proxy and the MCP proxy before the release, in every state, through the PEP's committed state as the PEP machine
    asks it (`Pep._floor_answer`). None when the home holds no floor or the floor is silent, and then the caller
    decides as it would with no floor. When it answers, the release in force, or the fallback set when that decides,
    is asked too and its answer is `would`; an override, a floor answer whose `would` is not an allow, past the signed
    `rate` of its rule is escalated with `dist:floor-rate`, or leaves the floor silent on a rule that may only allow.
    The count is durable before the caller acts, under the home's floor lock, and the answer is spooled for the PEP's
    counts of H10. An escalation opens one an operator may answer (OP3). Returns the decision, its cause, the basis
    `floor`, the floor's policy hash, `would`, the zone it overrode, whether it is an override, and the receipt."""
    if not is_distributed(home):
        return None
    from prismpath.distribution import floor as floors
    from prismpath.distribution.pep import read_committed_release
    held, installed = held_floor(home, kind)
    if held is None:
        return None
    ceiling = installed.ceiling
    names = tuple(kinds.read_zones(ceiling.bodies["agent.zones"])["protected"]) \
        if ceiling is not None and "agent.zones" in ceiling.bodies else ()
    answer = floors.ask(kind, held.bodies, request, floor=True, ceiling_names=names)
    if answer.outcome not in (floors.ALLOW, floors.ESCALATE):
        return None
    now = int(onion_home.clock() if now is None else now)
    try:
        release = read_committed_release(str(home), kind, now)
        would, would_policy = floors.ask(kind, release.bodies, request), release.policy_sha256
    except Refused:
        would, would_policy = floors.SILENT, None
    override = would.outcome != floors.ALLOW
    meta = next(iter(held.envelopes.values())).meta if held.envelopes else {}
    import fcntl
    os.makedirs(_install_dir(home), exist_ok=True)
    with open(os.path.join(_install_dir(home), FLOOR_LOCK), "a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        book = floors.Book.load((os.path.join(installed.dir, "rates.json"), os.path.join(installed.copy, "rates.json")))
        outcome, cause, counted = answer.outcome, answer.cause, None
        if outcome == floors.ALLOW and override and meta.get("rate") is not None:
            counted = book.spend(answer.rule, meta["rate"], now)
            if counted is None:
                if answer.allow_only or kind not in floors.ESCALATING:
                    return None                                       # AF8: past the rate the release decides
                outcome, cause = floors.ESCALATE, floors.RATE
        if outcome == floors.ALLOW:
            cause = floors.ALLOWED                                     # RC3
        from prismpath.kernel import canon2
        with open(os.path.join(_install_dir(home), FLOOR_SPOOL), "ab") as handle:
            handle.write(canon2.dumps({"override": override}) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        doc = {"basis": "floor", "cause": cause, "outcome": outcome, "policy_sha256": held.policy_sha256,
               "would": would.document(would_policy), "zone": answer.zone, "time": now}
        if counted is not None:
            doc.update(rule=answer.rule, window=counted[0], count=counted[1])
        data, digest = floors.receipt(doc)
        with open(os.path.join(_install_dir(home), FLOOR_RECEIPTS), "ab") as handle:
            handle.write(data + b"\n")                                 # RC1: every floor answer's receipt, durably
            handle.flush()
            os.fsync(handle.fileno())
        if outcome == floors.ESCALATE:
            book.escalated(digest, held.policy_sha256, now)            # OP3
    return {"decision": outcome, "cause": cause, "basis": "floor", "policy_sha256": held.policy_sha256,
            "would": would.document(would_policy), "zone": answer.zone, "override": override, "receipt": data,
            "receipt_sha256": digest, **({"rule": answer.rule, "window": counted[0], "count": counted[1]}
                                         if counted is not None else {})}


def take_floor_counts(home) -> Tuple[int, int]:
    """(answers, overrides) spooled by the home's deciders, and the spool emptied, as `take_readings` takes its."""
    from prismpath.kernel import canon2
    path = os.path.join(_install_dir(home), FLOOR_SPOOL)
    taking = path + ".taking"
    try:
        os.replace(path, taking)
        lines = Path(taking).read_bytes().splitlines()
        os.unlink(taking)
    except OSError:
        return 0, 0
    answers = overrides = 0
    for line in lines:
        try:
            answers += 1
            overrides += 1 if canon2.loads(line).get("override") else 0
        except Exception:  # noqa: BLE001 - a torn line still counts as an answer, and as an override, the safer side
            overrides += 1
    return answers, overrides


def floor_hosts(home) -> Tuple[str, ...]:
    """AF1: the hosts of the action floor's `egress.hosts`, which the egress proxy asks before the release's."""
    if not is_distributed(home):
        return ()
    held, _installed = held_floor(home)
    if held is None or "egress.hosts" not in held.bodies:
        return ()
    return tuple(read_hosts(held.bodies["egress.hosts"]))


def running_profile(home, role: str = "agent"):
    """AF1: the sandbox profile of a distributed home, compiled from the policy in force and the action floor's
    together, so the sandbox never blocks what the floor allows (`profile.join`). A floor whose policy cannot be
    projected onto a profile adds nothing, and the profile is the release's alone."""
    from prismpath.agent import profile as profiles
    from prismpath.distribution.pep import read_committed_release
    release = read_committed_release(str(home), "agent", int(onion_home.clock()))
    compiled = profiles.compile_profile(release.bodies["policy.core"], role)
    image = floor_image(home)
    if image is None:
        return compiled
    try:
        return profiles.join(compiled, profiles.compile_profile(image, role))
    except profiles.ProfileError:
        return compiled


def committed(home, now: Optional[int] = None) -> Dict[str, bytes]:
    """The bodies of the release the home's PEP has active, {artifact: body}, held on every load to what the PEP
    machine holds it to (`pep.read_committed`): a locked PEP, an expired or revoked release, a floor a revocation
    raised and a signer the store no longer holds each refuse. No authority key is read."""
    from prismpath.distribution.pep import read_committed
    return read_committed(str(home), "agent", int(onion_home.clock() if now is None else now))


def hosts(bodies: Mapping[str, bytes]) -> Tuple[str, ...]:
    """The committed `egress.hosts`, the only hosts a distributed home's egress proxy may reach."""
    return tuple(read_hosts(bodies["egress.hosts"]))


# ------------------------------------------------------------------ the agent's artifacts

def read_hosts(body: bytes) -> list:
    """`egress.hosts`: a canon/2 array of lower case host names, sorted, without repeats, each one the egress proxy
    reads as itself. `Refused` with `dist:bad-format` otherwise."""
    from prismpath.agent.egress import Refusal, parse_authority
    doc = kinds.load_canonical(body, "egress.hosts")
    if not isinstance(doc, list) or not all(isinstance(name, str) for name in doc) or doc != sorted(set(doc)):
        raise Refused(kinds.BAD_FORMAT, "egress.hosts is not a sorted list of names without repeats")
    for name in doc:
        try:
            if parse_authority(f"{name}:443") != (name, 443):
                raise Refused(kinds.BAD_FORMAT, f"{name!r} is not a lower case host name")
        except Refusal:
            raise Refused(kinds.BAD_FORMAT, f"{name!r} is not a host name the egress proxy reads") from None
    return doc


def _names(body: bytes, read: Callable[[object], Sequence[str]]) -> Optional[frozenset]:
    try:
        return frozenset(read(kinds.load_canonical(body, "a compared artifact")))
    except (Refused, TypeError, KeyError, ValueError):
        return None


def _host_list(doc) -> Sequence[str]:
    if not isinstance(doc, list) or not all(isinstance(name, str) for name in doc):
        raise ValueError("not a list of host names")
    return doc


def _protected(doc) -> Sequence[str]:
    if not isinstance(doc, dict) or not isinstance(doc.get("protected"), list):
        raise ValueError("not a zone file")
    return doc["protected"]


def compare_hosts(active: bytes, staged: bytes) -> str:
    """W1 for `egress.hosts`: larger when a staged host is not in the active list."""
    old, new = _names(active, _host_list), _names(staged, _host_list)
    if old is None or new is None:
        return CANNOT_DECIDE
    return NOT_LARGER if new <= old else LARGER


def compare_zones(active: Optional[bytes], staged: Optional[bytes]) -> str:
    """W1 for `agent.zones`: larger when a name the active file protects is gone. No file protects nothing."""
    old = frozenset() if active is None else _names(active, _protected)
    new = frozenset() if staged is None else _names(staged, _protected)
    if old is None or new is None:
        return CANNOT_DECIDE
    return NOT_LARGER if old <= new else LARGER


# ------------------------------------------------------------------ the kind

ROW = kinds.Target(needs=frozenset({"policy.core", "egress.hosts"}), decides=True,
                   when_declared=frozenset({"agent.zones", "sandbox.profile"}))


def reading_domain():
    """The agent's reading domain, the values the classifier produces (`profile.AGENT_DOMAIN`)."""
    from prismpath.agent import profile
    return profile.AGENT_DOMAIN


def policy(image: bytes):
    """The policy an agent home decides with: the kernel's, bound to the agent's domain (`agent.policy.Policy`)."""
    from prismpath.agent.policy import Policy
    return Policy(image)


def domain_document() -> dict:
    """CL4, P4: the domain an agent PEP is built with, the values the classifier produces for each category."""
    from prismpath.agent import profile
    return {"kind": "agent", "categories": {name: list(values) for name, values in profile.KNOWN_CATEGORIES.items()}}


def compile_checks(image: bytes, values, points=()) -> list:
    """`prismpath policy compile --target agent`: the listed values of the source, then the image's own checks, with
    the information points named by `--point`."""
    from prismpath.agent import target
    return target.check_listed(values) + target.check(image, points)


# ------------------------------------------------------------------ sealed from a policy manifest

# The side files of a manifest an agent release is made from, and the artifact each one's bytes are (SPEC.md section 10).
MANIFEST_INPUTS = {"egress_hosts": "egress.hosts", "zones": "agent.zones"}
# The value keys an agent release carries: none yet. No artifact of a release holds `policy.max_processes`,
# `policy.timeout_s`, `policy.shell_many`, `policy.toolchain_dirs`, `policy.ro_mounts` or `policy.allowed_remotes`, and
# the launcher runs values of its own (512 processes, calls of 120 to 600 seconds), so a signed value would read as
# enforced and not be. The sealing tool refuses each until A4c wires it into what a PEP holds.
MANIFEST_VALUES: Dict[str, Any] = {}
NO_HOSTS = canon.canon2_bytes([])                  # `egress.hosts` when the manifest names none: no host is reached


def derive(release) -> Dict[str, bytes]:
    """The bodies of an agent release from a verified manifest (`policy_manifest.Release`): its `policy.core`, the
    compiled image; its `egress.hosts`, the `policy.egress_hosts` file, or the empty list when the manifest names none,
    so an absent key reaches no host; and its `agent.zones`, the `policy.zones` file, only when the manifest names one,
    so an absent key declares no zone and the release id signs that absence (section 3). Each side file is the
    artifact's body byte for byte and is read as its artifact reads it, `Refused` with its cause when it does not."""
    bodies = {"policy.core": bytes(release.image),
              "egress.hosts": bytes(release.files.get("egress_hosts", NO_HOSTS))}
    read_hosts(bodies["egress.hosts"])
    if "zones" in release.files:
        bodies["agent.zones"] = bytes(release.files["zones"])
        kinds.read_zones(bodies["agent.zones"])
    return bodies


KIND = TargetKind(name="agent", row=ROW, readers={"egress.hosts": read_hosts},
                  comparators={"egress.hosts": compare_hosts, "agent.zones": compare_zones},
                  domain=reading_domain, policy=policy, domain_document=domain_document,
                  compile_checks=compile_checks, derive=derive, manifest_inputs=MANIFEST_INPUTS,
                  manifest_values=MANIFEST_VALUES)
kinds.register(KIND)
