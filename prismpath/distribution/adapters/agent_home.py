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
`policy.core` (`dist:derived-mismatch`), and reads a staged `agent.zones` as the zone point reads it.
"""
from __future__ import annotations

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

    def __init__(self, home):
        self.home = str(home)
        self.running = None

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
        self.running = release.policy_sha256

    def deactivate(self, cause: str) -> None:
        self.running = None


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
    """The spooled readings, the last 64, and the spool emptied."""
    from prismpath.kernel import canon2
    path = Path(home) / "dist" / SPOOL
    try:
        lines = path.read_bytes().splitlines()
        path.unlink()
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


def committed(home, now: Optional[int] = None) -> Dict[str, bytes]:
    """The bodies of the release the home's PEP has active, {artifact: body}, held on every load to what the PEP
    machine holds it to (`pep.read_committed`): a locked PEP, an expired or revoked release, a floor a revocation
    raised and a signer the store no longer holds each refuse. No authority key is read."""
    from prismpath.distribution.pep import read_committed
    return read_committed(str(home), "agent", int(clock() if now is None else now))


def hosts(bodies: Mapping[str, bytes]) -> Tuple[str, ...]:
    """The committed `egress.hosts`, the only hosts a distributed home's egress proxy may reach."""
    return tuple(kinds.read_hosts(bodies["egress.hosts"]))

