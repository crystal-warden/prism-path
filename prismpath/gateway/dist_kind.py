# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The `gateway` target kind of policy distribution (spec-policy-distribution.md, section 3) and the adapter of one
gateway home, the reverse proxy of `prismpath.gateway.proxy` in front of one service. A release is its `policy.core`
and its `gateway.routes`, and any change of the route table is larger (9.4), so it needs a widening statement.

Importing this module registers the kind (`kinds.register`): its row, the readers and comparators of
`gateway.routes`, `identity.bundle` and `identity.map`, and the domain it is built with (CL4, P4). It registers no
reading domain of its own, so its `policy.core` is checked against the agent kind's, as it always has been (owner
answer Q4), and its policy is the kernel's under that domain (`onion.home.policy_of`).

A gateway home has the layout of an agent home. In one that follows a stream the PEP's store is `<home>/dist/`, the
home holds its instance key and no authority key, and the committed release is read from the store on every load
and checked again (`home.load_distributed` with kind `gateway`). The adapter keeps nothing of its own: activating
a release is the PEP's active record, which the gateway then finds, and deactivating it is the lapse that record
shows. The staged `gateway.routes` is read by the artifact's own V11 check (`read_routes`, through `kinds.read`),
and the adapter adds nothing to it.

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
from prismpath.distribution.kinds import BAD_FORMAT, Refused
from prismpath.onion import home as onion_home
from prismpath.ports.target import CANNOT_DECIDE, LARGER, NOT_LARGER, Adapter, TargetKind


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
        return onion_home.take_readings(self.home)

    def activate(self, release) -> None:
        self.running = release.policy_sha256

    def deactivate(self, cause: str) -> None:
        self.running = None


def identity_refusal(policy_body: bytes, bodies: Mapping[str, bytes]) -> Optional[str]:
    """ID3: None when the identity artifacts of `bodies` agree with the policy, else `dist:incomplete`. The bodies
    themselves were read by their own checks (V11)."""
    from prismpath.gateway import identity
    try:
        reads = identity.FIELD in onion_home.policy_of("gateway", bytes(policy_body)).fields
    except (ValueError, onion_home.AgentError):
        return None                                    # the policy's own check refuses it
    held = [name in bodies for name in ("identity.bundle", "identity.map")]
    if held != [reads, reads]:
        return "dist:incomplete"
    if reads:
        try:
            domains = set(read_identity_bundle(bodies["identity.bundle"]))
            entries = read_identity_map(bodies["identity.map"])
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
    from prismpath.distribution.trust import TrustStore
    from prismpath.gateway import grants
    try:
        routes = read_routes(bodies["gateway.routes"])
    except (KeyError, Refused) as error:
        raise onion_home.AgentError(f"the committed release holds no route table the gateway reads ({error})") from None
    trust = TrustStore.load(str(Path(home) / "dist" / "trust.json"))
    try:
        stream = stream_of(home)
    except (OSError, Refused) as error:
        raise onion_home.AgentError(f"the home's anchor cannot be read ({error})") from None
    verifier = grants.Verifier(None, onion_home.sha256_hex(policy.image), trust=trust, stream=stream,
                               clock=lambda: onion_home.clock())
    return State(policy, routes, verifier, dict(bodies), workload_reader(policy, bodies, setting))


def workload_reader(policy, bodies: Mapping[str, bytes], setting):
    """The `identity.Identity` a policy that reads `workload` is decided with, or None for one that does not.
    AgentError when it cannot be built (ID3, ID4)."""
    from prismpath.gateway import identity
    if identity.FIELD not in policy.fields:
        return None
    if identity_refusal(policy.image, bodies) is not None:
        raise onion_home.AgentError("the committed release's identity.bundle and identity.map do not agree with its "
                                  "policy, which reads workload (ID3)")
    if setting is None:
        raise onion_home.AgentError("the policy reads workload, and no front proxy header is set to read the client "
                                  "certificate from (--client-cert-header and --front-proxy)")
    try:
        return identity.Identity.from_bodies(bodies["identity.bundle"], bodies["identity.map"], setting,
                                             clock=lambda: onion_home.clock())
    except identity.IdentityError as error:
        raise onion_home.AgentError(f"the committed identity artifacts do not read ({error})") from None


class Following:
    """The committed release of a gateway home that follows a stream, for the gateway that runs long. `current()`
    answers the `State` of the next decision or raises `home.AgentError` with why the release no longer
    decides. It builds the state again only when `home.Committed` loaded the release again."""

    def __init__(self, home, setting=None):
        self.home = Path(home)
        self.setting = setting
        self.committed = onion_home.Committed(self.home, kind="gateway")
        self._loaded: Any = None
        self._state: Any = None

    def current(self) -> State:
        loaded = self.committed.current()
        if loaded is not self._loaded:
            policy, bodies = loaded
            self._state, self._loaded = state_of(self.home, policy, bodies, self.setting), loaded
        return self._state


# ------------------------------------------------------------------ the gateway's artifacts

def read_routes(body: bytes):
    """`gateway.routes`: a route table in canon/2 bytes, read by `Routes.from_doc` and spelled as
    `Routes.canonical` spells it, so one table is one body. `Refused` with `dist:bad-format` otherwise."""
    from prismpath.gateway.reading import RouteError, Routes
    doc = kinds.load_canonical(body, "gateway.routes")
    try:
        routes = Routes.from_doc(doc)
    except RouteError as error:
        raise Refused(BAD_FORMAT, f"gateway.routes is not a route table ({error})") from None
    if routes.canonical() != bytes(body):
        raise Refused(BAD_FORMAT, "gateway.routes is not the table's canonical spelling")
    return routes


def read_identity_bundle(body: bytes) -> dict:
    """`identity.bundle` (section 13.1, ID1): a canon/2 object with `domains`, `encoding` and `format`
    `prismpath.dist-identity-bundle/1`, each trust domain to the standard base64 DER of its X.509 CA certificates,
    sorted, without repeats, each a CA with keyCertSign. `Refused` with `dist:bad-format` otherwise."""
    from prismpath.gateway import identity
    doc = kinds.load_canonical(body, "identity.bundle")
    try:
        return identity.bundle_doc(doc)
    except identity.IdentityError as error:
        raise Refused(BAD_FORMAT, f"identity.bundle is not a trust bundle ({error})") from None


def read_identity_map(body: bytes) -> tuple:
    """`identity.map` (section 13.1, ID2): a canon/2 object with `encoding`, `entries` and `format`
    `prismpath.dist-identity-map/1`, its entries SPIFFE ID patterns to classes, in order. `Refused` with
    `dist:bad-format` otherwise."""
    from prismpath.gateway import identity
    doc = kinds.load_canonical(body, "identity.map")
    try:
        return identity.map_doc(doc)
    except identity.IdentityError as error:
        raise Refused(BAD_FORMAT, f"identity.map is not an identity map ({error})") from None


def compare_routes(active: bytes, staged: bytes) -> str:
    """W1 for `gateway.routes`: any change is larger, because a path that loses its route reads as another class."""
    return NOT_LARGER if bytes(active) == bytes(staged) else LARGER


def compare_bundles(active: bytes, staged: bytes) -> str:
    """W1 for `identity.bundle` (ID7): not larger when the staged bundle only removes CAs or trust domains, so a
    certificate it validates the active one validates too. Anything else, a CA added or moved to another trust
    domain, is larger."""
    try:
        old, new = read_identity_bundle(active), read_identity_bundle(staged)
    except Refused:
        return CANNOT_DECIDE
    return NOT_LARGER if all(domain in old and set(cas) <= set(old[domain]) for domain, cas in new.items()) else LARGER


def compare_maps(active: bytes, staged: bytes) -> str:
    """W1 for `identity.map` (ID7): not larger only when the staged entries are the active ones with some taken out,
    in the same order, and no entry taken out overlaps an entry kept after it. Each SPIFFE ID then keeps its class
    or reads `other`. A class changed, an entry added or moved, or one taken out whose IDs a later entry would take
    is larger, since an ID would read another class."""
    try:
        old, new = read_identity_map(active), read_identity_map(staged)
    except Refused:
        return CANNOT_DECIDE
    kept, at = [], 0
    for index, entry in enumerate(old):
        if at < len(new) and new[at] == entry:
            kept.append(index)
            at += 1
    if at != len(new):
        return LARGER                                  # an entry that is not one of the active ones, in its order
    removed = [index for index in range(len(old)) if index not in set(kept)]
    if any(old[gone].overlaps(old[later]) for gone in removed for later in kept if later > gone):
        return LARGER                                  # an ID the removed entry classed would take a later class
    return NOT_LARGER


# ------------------------------------------------------------------ the kind

ROW = kinds.Target(needs=frozenset({"policy.core", "gateway.routes"}), decides=True,
                   when_declared=frozenset({"identity.bundle", "identity.map"}))


def domain_document() -> dict:
    """CL4, P4: the domain a gateway PEP is built with, the classes its reading gives."""
    from prismpath.gateway import reading
    return {"kind": "gateway", "fields": list(reading.FIELDS),
            "categories": {"method_class": list(reading.METHOD_CLASSES), "body_class": list(reading.BODY_CLASSES),
                           "content_class": list(reading.CONTENT_CLASSES), "query": list(reading.QUERY_CLASSES),
                           "grant": list(reading.GRANT_STATES)}}


def categories() -> frozenset:
    """CL4: the category fields of the domain a gateway PEP is built with, the fields its reading gives."""
    from prismpath.gateway import reading
    return frozenset(reading.FIELDS)


KIND = TargetKind(name="gateway", row=ROW,
                  readers={"gateway.routes": read_routes, "identity.bundle": read_identity_bundle,
                           "identity.map": read_identity_map},
                  comparators={"gateway.routes": compare_routes, "identity.bundle": compare_bundles,
                               "identity.map": compare_maps},
                  domain_document=domain_document, categories=categories)
kinds.register(KIND)
