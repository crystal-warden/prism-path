# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""What the policy distribution tests share: the corpus generator's fixed keys and image, an enforcement point
over a temporary state directory for any built kind, a signer that seals releases for it, and the hold cases
(106, 107, 110 and 112), run alike on every kind whose row allows HOLD."""
from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

from prismpath import canon
from prismpath.distribution import envelope as env
from prismpath.distribution import trust as trust_module
from prismpath.distribution.adapters.host import HostAdapter
from prismpath.distribution import state_record
from prismpath.distribution.pep import Pep, PepRefused
from prismpath.hotswap.policy_host import PolicyHost
from prismpath.ledgers.root_statement import InstanceKey

REPO = Path(__file__).resolve().parent.parent


def generator():
    spec = importlib.util.spec_from_file_location("gen_distribution_corpus",
                                                  REPO / "portable" / "gen_distribution_corpus.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GEN = generator()
STREAM = GEN.STREAM
NOT_BEFORE, EXPIRES, NOW = GEN.NOT_BEFORE, GEN.EXPIRES, GEN.NOW


def instance_key(name: str = "I") -> InstanceKey:
    private = GEN.test_key(name)
    return InstanceKey(private, GEN.public_raw(private))


@dataclass
class Clock:
    now: int = NOW

    def __call__(self) -> int:
        return self.now


def seal(artifact: str, body: bytes, *, seq: int = 1, signer: str = "A", release: Optional[str] = None,
         policy_sha256: Optional[str] = None, not_before: int = NOT_BEFORE, expires: int = EXPIRES,
         meta: Optional[dict] = None, stream: str = STREAM, targets=("host",)) -> bytes:
    """A sealed envelope for `body`, by default a `policy.ppt` release of one artifact."""
    if meta is None:
        meta = GEN.image_meta(body) if artifact == "policy.ppt" else {}
    trust_kind = artifact in ("trust.revocation", "trust.rotation")
    envelope_bytes = env.build(
        artifact, body, stream=stream, seq=seq, targets=targets, not_before=not_before,
        expires=0 if artifact.startswith("trust.") else expires, meta=meta,
        policy_sha256=env.ZERO_HASH if trust_kind else (policy_sha256 or canon.sha256_hex(body)),
        release=env.ZERO_HASH if trust_kind else (release or env.release_id([(artifact, canon.sha256_hex(body))])))
    return env.seal(envelope_bytes, [GEN.test_key(signer)])


def revocation(*, envelopes=(), keys=(), policies=(), floors=None) -> bytes:
    """The canon/2 body of a revocation list (section 10)."""
    return canon.canon2_bytes({canon.ENCODING_KEY: canon.CANON2, "format": "prismpath.dist-revocation/1",
                               "envelopes": sorted(envelopes), "keys": sorted(keys), "policies": sorted(policies),
                               "floors": dict(floors or {})})


def rotation(add: str, retire: str = "") -> bytes:
    """The canon/2 body of a rotation (section 11) adding the test key `add` and retiring the test key `retire`."""
    return canon.canon2_bytes({canon.ENCODING_KEY: canon.CANON2, "format": "prismpath.dist-rotation/1",
                               "add": GEN.public_raw(GEN.test_key(add)).hex(), "retire": key_id(retire) if retire else ""})


def trust_statement(artifact: str, body: bytes, *, seq: int, signers=("A",), targets=("host",)) -> bytes:
    """A sealed trust statement on `@trust`, signed by every test key in `signers` (O2 asks for two)."""
    envelope_bytes = env.build(artifact, body, stream=env.TRUST_STREAM, seq=seq, targets=targets, not_before=NOT_BEFORE,
                               expires=0, policy_sha256=env.ZERO_HASH, release=env.ZERO_HASH)
    return env.seal(envelope_bytes, [GEN.test_key(name) for name in signers])


def key_id(name: str) -> str:
    return env.key_id(GEN.public_raw(GEN.test_key(name)))


def image(threshold: int = 5) -> bytes:
    from prismpath.kernel import ppt_compile
    return ppt_compile.compile_predicate(f"when x >= {threshold}").serialize()


@dataclass
class Point:
    """A provisioned PEP of `kind` over `state_dir`, with its adapter, its clock and its instance key. A
    release is one `artifact`."""
    state_dir: Path
    clock: Clock = field(default_factory=Clock)
    key: InstanceKey = field(default_factory=instance_key)
    authorities: List[str] = field(default_factory=lambda: ["A"])
    expiry_response: str = "refuse"
    kind: str = "host"
    artifact: str = "policy.ppt"

    def __post_init__(self):
        self.pep = self.open()

    def anchor(self) -> bytes:
        return trust_module.anchor_bytes([GEN.public_raw(GEN.test_key(name)) for name in self.authorities],
                                         target=self.kind, stream=STREAM)

    def adapter(self):
        raise NotImplementedError("a Point names its adapter")

    def open(self, provision: bool = True) -> Pep:
        """A fresh PEP over the state directory, as after a restart, provisioned on first open."""
        pep = Pep(str(self.state_dir), self.adapter(), self.key, self.clock, expiry_response=self.expiry_response)
        if provision and not pep.provisioned:
            pep.confirm(pep.provision(self.anchor()))
        return pep

    def policy_of(self, body: bytes) -> str:
        """The policy hash a release of `body` names: the body's own unless the kind says otherwise."""
        return canon.sha256_hex(body)

    def seal(self, body: bytes, seq: int = 1, **seal_args) -> bytes:
        seal_args.setdefault("policy_sha256", self.policy_of(body))
        return seal(self.artifact, body, seq=seq, targets=(self.kind,), **seal_args)

    def commit(self, body: bytes, seq: int = 1, **seal_args) -> bytes:
        self.pep.stage(self.seal(body, seq=seq, **seal_args), body)
        return self.pep.commit(STREAM, seq, seal_args.get("policy_sha256") or self.policy_of(body))

    def rotate(self, seq: int, add: str, retire: str = "", signers=None) -> bytes:
        """Stage a rotation adding `add` and retiring `retire`, signed by the old key and the new one by default."""
        body = rotation(add, retire)
        sealed = trust_statement("trust.rotation", body, seq=seq, signers=signers or (self.authorities[0], add),
                                 targets=(self.kind,))
        return self.pep.stage(sealed, body)

    def revoke(self, seq: int, signer: str = "A", **lists) -> bytes:
        """Stage the revocation list `lists` at trust sequence `seq`, which applies it (B2)."""
        body = revocation(**lists)
        return self.pep.stage(seal("trust.revocation", body, seq=seq, stream="@trust", signer=signer,
                                   targets=(self.kind,)), body)


@dataclass
class HostPep(Point):
    """A host PEP with its PolicyHost."""

    def host(self) -> PolicyHost:
        return PolicyHost(str(self.state_dir), [], dict(GEN.QUALIFICATION), instance_key=self.key)

    def adapter(self):
        return HostAdapter(self.host())


@dataclass
class MeshPep(Point):
    """A modelled mesh node."""
    kind: str = "mesh"

    def adapter(self):
        from prismpath.distribution.adapters.mesh import MeshAdapter
        return MeshAdapter()


# ------------------------------------------------------------------ the hold cases, on every kind with HOLD

def _read(point: Point, signed: bytes):
    return state_record.read(signed, point.key.public_raw)


def case_106_refuse_lapses(make: Callable[..., Point], bodies, decide: Callable) -> None:
    """X6, X1: with the setting left alone the release lapses at expiry and every decision is refused."""
    point = make(expiry_response="refuse")
    point.commit(bodies[0])
    assert point.pep.decide(lambda: decide(point.pep))["cause"] is None
    point.clock.now = EXPIRES
    record = _read(point, point.pep.tick())
    assert (record.event, record.cause, record.state, record.held) == ("lapsed", "dist:expired", "no-policy", False)
    assert point.pep.decide(lambda: decide(point.pep)) == {"decision": None, "cause": "dist:policy-lapsed", "mark": None}


def case_107_hold_keeps_deciding_and_marks_everything(make: Callable[..., Point], bodies, decide: Callable) -> None:
    """X6, X7: under HOLD the expired release keeps deciding, `held` with `dist:held` is reported, bit 5 is in
    every record and the mark on every receipt until a release that passes every rule ends the hold."""
    point = make(expiry_response="hold")
    point.commit(bodies[0])
    before = point.pep.decide(lambda: decide(point.pep))
    point.clock.now = EXPIRES
    point.pep.drain()
    held = point.pep.decide(lambda: decide(point.pep))
    assert held == {**before, "mark": "held"}
    sent = [_read(point, data) for data in point.pep.drain()]
    assert [(record.event, record.cause) for record in sent] == [("held", "dist:held")] and sent[0].state == "active"
    later = point.seal(bodies[1], seq=2, not_before=EXPIRES, expires=EXPIRES + 1000)
    for signed in (point.pep.record("beat"), point.pep.stage(later, bodies[1]), point.pep.abort(STREAM, 9, "00" * 32)):
        assert _read(point, signed).held
    point.pep = point.open()                                                        # a restart is still held
    assert point.pep.decide(lambda: decide(point.pep))["mark"] == "held"
    committed = _read(point, point.pep.commit(STREAM, 2, point.policy_of(bodies[1])))
    assert committed.event == "committed" and not committed.held
    assert point.pep.decide(lambda: decide(point.pep))["mark"] is None and not _read(point, point.pep.record("beat")).held


def case_110_a_held_pep_never_widens(make: Callable[..., Point], bodies, decide: Callable) -> None:
    """X9: a held PEP refuses a rollback with `dist:held` and changes nothing, and a release that passes every
    rule ends the hold with `committed` and bit 5 clear."""
    point = make(expiry_response="hold")
    point.commit(bodies[0], seq=1, expires=EXPIRES - 100)
    point.commit(bodies[1], seq=2)
    point.clock.now = EXPIRES
    point.pep.tick()
    record = _read(point, point.pep.rollback())
    assert (record.cause, record.held, record.active_seq) == ("dist:held", True, 2)
    fresh = point.seal(bodies[0], seq=3, not_before=EXPIRES, expires=EXPIRES + 1000)
    point.pep.stage(fresh, bodies[0])
    committed = _read(point, point.pep.commit(STREAM, 3, point.policy_of(bodies[0])))
    assert (committed.event, committed.held, committed.active_seq) == ("committed", False, 3)


def case_108_a_revocation_ends_a_hold(make: Callable[..., Point], bodies, decide: Callable) -> None:
    """X8, R5: a held PEP is sent a revocation of its active release, and one that raises the floor past it, and
    each time goes to `no-policy` with event `lapsed` and `dist:revoked`, the hold ended."""
    for lists in ({"policies": None}, {"floors": {STREAM: 2}}):
        point = make(expiry_response="hold")
        point.commit(bodies[0])
        point.clock.now = EXPIRES
        point.pep.tick()
        assert point.pep.held
        if "policies" in lists:
            lists = {"policies": [point.policy_of(bodies[0])]}
        point.pep.drain()
        ack = _read(point, point.revoke(1, **lists))
        sent = [_read(point, data) for data in point.pep.drain()]
        assert [(record.event, record.cause) for record in sent] == [("lapsed", "dist:revoked"), ("trust-applied", None)]
        assert (ack.state, ack.held, ack.trust_seq) == ("no-policy", False, 1)
        assert point.pep.decide(lambda: decide(point.pep))["cause"] == "dist:policy-lapsed"


def case_112_no_message_changes_the_setting(make: Callable[..., Point], bodies, decide: Callable) -> None:
    """X10: a held and a not held PEP each take every message, and each still answers expiry as it was built
    and provisioned. A restart with the other setting is refused."""
    for setting, expected in (("hold", "held"), ("refuse", "lapsed")):
        point = make(expiry_response=setting)
        point.commit(bodies[0])
        pep = point.pep
        pep.stage(point.seal(bodies[1], seq=2), bodies[1])
        pep.abort(STREAM, 2, point.policy_of(bodies[1]))
        pep.stage(point.seal(bodies[1], seq=3), bodies[1])
        pep.commit(STREAM, 3, point.policy_of(bodies[1]))
        pep.record("beat")
        pep.see_epoch(7)
        pep.needs(["00" * 32])
        try:
            pep.rollback()
        except PepRefused:
            pass
        point.clock.now = EXPIRES
        assert pep.expiry_response == setting and _read(point, pep.tick()).event == expected
        point.expiry_response = "refuse" if setting == "hold" else "hold"
        try:
            point.open()
        except PepRefused:
            pass
        else:
            raise AssertionError("a PEP started with another expiry setting than it was provisioned with")

