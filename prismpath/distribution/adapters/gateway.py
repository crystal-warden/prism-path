# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The `gateway` target of policy distribution (spec-policy-distribution.md, section 3): one gateway home, the
reverse proxy of `prismpath.gateway.proxy` in front of one service. A release is its `policy.core` and its
`gateway.routes`, and any change of the route table is larger (9.4), so it needs a widening statement.

A gateway home has the layout of an agent home. In one that follows a stream the PEP's store is `<home>/dist/`, the
home holds its instance key and no authority key, and the committed release is read from the store on every load
and checked again (`commands.load_distributed` with kind `gateway`). The adapter keeps nothing of its own: activating
a release is the PEP's active record, which the gateway then finds, and deactivating it is the lapse that record
shows. The staged `gateway.routes` is read by the artifact's own V11 check (`kinds.read_routes`), and the adapter
adds nothing to it.

A release whose policy reads `workload` carries `identity.bundle` and `identity.map`, and one whose policy does not
carries neither (ID3). The adapter holds that at commit, with every trust domain the map names held by the bundle,
and refuses anything else with `dist:incomplete`, since the envelopes of the release then disagree.

A gateway that runs long follows the committed state through `Following`: at every decision it takes the committed
policy, the committed route table and a grant verifier over the PEP's trust store, loaded again only when a file of
the store changed or the release's earliest expiry came. So a revocation, an expiry or a new route table reaches it
at its next request, and a grant revoked by its envelope id in a `trust.revocation` reads invalid from then (GR3).
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from prismpath.distribution import kinds
from prismpath.distribution.adapters import Adapter, agent_home
from prismpath.distribution.kinds import Refused


class GatewayHomeAdapter(Adapter):
    """The adapter of one gateway home at `home`. `home` is also the directory K2 looks in for an authority key."""
    kind = "gateway"

    def __init__(self, home):
        self.home = str(home)
        self.running = None

    def check(self, artifact: str, body: bytes, staged) -> Optional[str]:
        """ID3 at commit, once, on the release's `policy.core`: the identity artifacts are there exactly when the
        policy reads `workload`, and the map names no trust domain the bundle does not hold."""
        if artifact != "policy.core":
            return None
        return identity_refusal(body, {name: pair[1] for name, pair in staged.items()})

    def readings(self) -> list:
        """The readings the gateway decided since the last call, oldest first, taken off the spool (H5)."""
        return agent_home.take_readings(self.home)

    def activate(self, release) -> None:
        self.running = release.policy_sha256

    def deactivate(self, cause: str) -> None:
        self.running = None


def identity_refusal(policy_body: bytes, bodies: Mapping[str, bytes]) -> Optional[str]:
    """ID3: None when the identity artifacts of `bodies` agree with the policy, else `dist:incomplete`. The bodies
    themselves were read by their own checks (V11)."""
    from prismpath.agent.policy import Policy
    from prismpath.gateway import identity
    try:
        reads = identity.FIELD in Policy(bytes(policy_body)).fields
    except ValueError:
        return None                                    # the policy's own check refuses it
    held = [name in bodies for name in ("identity.bundle", "identity.map")]
    if held != [reads, reads]:
        return "dist:incomplete"
    if reads:
        try:
            domains = set(kinds.read_identity_bundle(bodies["identity.bundle"]))
            entries = kinds.read_identity_map(bodies["identity.map"])
        except Refused as refused:
            return refused.cause
        if any(entry.domain not in domains for entry in entries):
            return "dist:incomplete"
    return None


def stream_of(home) -> str:
    """The stream the home's PEP follows, as its confirmed anchor names it."""
    from prismpath.distribution.trust import read_anchor
    return read_anchor((Path(home) / "dist" / "anchor.json").read_bytes()).stream


@dataclass(frozen=True)
class State:
    """What one decision of a following gateway is made under: the committed policy and route table, and the
    verifier of a grant over the trust store and stream of the PEP."""
    policy: Any
    routes: Any
    grants: Any
    bodies: Dict[str, bytes]
    identity: Any = None


def state_of(home, policy, bodies: Dict[str, bytes], setting=None) -> State:
    """The `State` of a committed release, its route table read as V11 reads it, its grants verified under the
    trust store the PEP holds now and, when its policy reads `workload`, its workload reader over the committed
    bundle and map with the front proxy `setting` (ID3, ID4). AgentError when the table does not read, the identity
    artifacts disagree with the policy, or the policy reads `workload` and no front proxy is set."""
    from prismpath.agent import commands
    from prismpath.distribution.trust import TrustStore
    from prismpath.gateway import grants
    try:
        routes = kinds.read_routes(bodies["gateway.routes"])
    except (KeyError, Refused) as error:
        raise commands.AgentError(f"the committed release holds no route table the gateway reads ({error})") from None
    trust = TrustStore.load(str(Path(home) / "dist" / "trust.json"))
    try:
        stream = stream_of(home)
    except (OSError, Refused) as error:
        raise commands.AgentError(f"the home's anchor cannot be read ({error})") from None
    verifier = grants.Verifier(None, commands._sha256_hex(policy.image), trust=trust, stream=stream,
                               clock=lambda: agent_home.clock())
    return State(policy, routes, verifier, dict(bodies), workload_reader(policy, bodies, setting))


def workload_reader(policy, bodies: Mapping[str, bytes], setting):
    """The `identity.Identity` a policy that reads `workload` is decided with, or None for one that does not.
    AgentError when it cannot be built (ID3, ID4)."""
    from prismpath.agent import commands
    from prismpath.gateway import identity
    if identity.FIELD not in policy.fields:
        return None
    if identity_refusal(policy.image, bodies) is not None:
        raise commands.AgentError("the committed release's identity.bundle and identity.map do not agree with its "
                                  "policy, which reads workload (ID3)")
    if setting is None:
        raise commands.AgentError("the policy reads workload, and no front proxy header is set to read the client "
                                  "certificate from (--client-cert-header and --front-proxy)")
    try:
        return identity.Identity.from_bodies(bodies["identity.bundle"], bodies["identity.map"], setting,
                                             clock=lambda: agent_home.clock())
    except identity.IdentityError as error:
        raise commands.AgentError(f"the committed identity artifacts do not read ({error})") from None


class Following:
    """The committed release of a gateway home that follows a stream, for the gateway that runs long. `current()`
    answers the `State` of the next decision or raises `commands.AgentError` with why the release no longer
    decides. It builds the state again only when `commands.Committed` loaded the release again."""

    def __init__(self, home, setting=None):
        from prismpath.agent import commands
        self.home = Path(home)
        self.setting = setting
        self.committed = commands.Committed(self.home, kind="gateway")
        self._loaded: Any = None
        self._state: Any = None

    def current(self) -> State:
        loaded = self.committed.current()
        if loaded is not self._loaded:
            policy, bodies = loaded
            self._state, self._loaded = state_of(self.home, policy, bodies, self.setting), loaded
        return self._state


def load(home):
    """(policy, run store) of a gateway home that follows a stream, for the commands that read it once."""
    from prismpath.agent import commands
    from prismpath.agent.run import RunStore
    policy, _bodies = commands.load_distributed(Path(home), kind="gateway")
    return policy, RunStore(Path(home) / commands.RUNS_DIR)
