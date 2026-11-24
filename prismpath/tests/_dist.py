# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""What the policy distribution tests share: the corpus generator's fixed keys and image, an enforcement point
over a temporary state directory for any built kind, a signer that seals releases for it, and the hold cases
(106, 107, 110 and 112), run alike on every kind whose row allows HOLD."""
from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional, Sequence

from prismpath import canon
from prismpath.distribution import envelope as env
from prismpath.distribution import trust as trust_module
from prismpath.distribution.adapters import Adapter
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
         meta: Optional[dict] = None, stream: str = STREAM, targets=("host",), replaces: str = "",
         widens: bool = False) -> bytes:
    """A sealed envelope for `body`, by default a `policy.ppt` release of one artifact."""
    if meta is None:
        meta = GEN.image_meta(body) if artifact == "policy.ppt" else {}
    trust_kind = artifact in ("trust.revocation", "trust.rotation", "trust.controller")
    envelope_bytes = env.build(
        artifact, body, stream=stream, seq=seq, targets=targets, not_before=not_before,
        expires=0 if artifact.startswith("trust.") else expires, meta=meta,
        replaces=replaces, widens=widens,
        policy_sha256=env.ZERO_HASH if trust_kind else (policy_sha256 or canon.sha256_hex(body)),
        release=env.ZERO_HASH if trust_kind else (release or env.release_id([(artifact, canon.sha256_hex(body))])))
    return env.seal(envelope_bytes, [GEN.test_key(signer)])


def revocation(*, envelopes=(), keys=(), policies=(), floors=None) -> bytes:
    """The canon/2 body of a revocation list (section 10)."""
    return canon.canon2_bytes({canon.ENCODING_KEY: canon.CANON2, "format": "prismpath.dist-revocation/1",
                               "envelopes": sorted(envelopes), "keys": sorted(keys), "policies": sorted(policies),
                               "floors": dict(floors or {})})


def widening(froms=()) -> bytes:
    """The canon/2 body of a widening statement (W4) that may replace the policy hashes `froms`, any when empty."""
    return canon.canon2_bytes({canon.ENCODING_KEY: canon.CANON2, "format": "prismpath.dist-widening/1",
                               "from": sorted(froms)})


def rotation(add: str, retire: str = "") -> bytes:
    """The canon/2 body of a rotation (section 11) adding the test key `add` and retiring the test key `retire`."""
    return canon.canon2_bytes({canon.ENCODING_KEY: canon.CANON2, "format": "prismpath.dist-rotation/1",
                               "add": GEN.public_raw(GEN.test_key(add)).hex(), "retire": key_id(retire) if retire else ""})


def controller_key(key: str) -> bytes:
    """The canon/2 body of a controller key statement (K7) naming the test key `key`."""
    return canon.canon2_bytes({canon.ENCODING_KEY: canon.CANON2, "format": "prismpath.dist-controller/1",
                               "key": GEN.public_raw(GEN.test_key(key)).hex()})


def trust_statement(artifact: str, body: bytes, *, seq: int, signers=("A",), targets=("host",)) -> bytes:
    """A sealed trust statement on `@trust`, signed by every test key in `signers` (O2 asks for two)."""
    envelope_bytes = env.build(artifact, body, stream=env.TRUST_STREAM, seq=seq, targets=targets, not_before=NOT_BEFORE,
                               expires=0, policy_sha256=env.ZERO_HASH, release=env.ZERO_HASH)
    return env.seal(envelope_bytes, [GEN.test_key(name) for name in signers])


def key_id(name: str) -> str:
    return env.key_id(GEN.public_raw(GEN.test_key(name)))


def public(name: str) -> bytes:
    return GEN.public_raw(GEN.test_key(name))


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
    controller: Optional[str] = None               # the test key named as the controller key, for a /2 anchor
    fresh: int = 0                                 # H16
    has_clock: bool = True
    stream: str = STREAM
    install_keys: Sequence[str] = ()               # section 21: the test keys of the anchor's install part
    install_threshold: int = 1
    operators: Sequence[str] = ()
    install_seq: int = 0
    install_copy: Optional[Path] = None            # IS10: the second medium of the install record

    def __post_init__(self):
        self.pep = self.open()

    def anchor(self, **changes) -> bytes:
        """The anchor of the point, `/2` with an install part when it names install keys. `changes` overrides the
        install part's members (`keys`, `threshold`, `operators`, `seq`, `domain`) by test key name."""
        from prismpath.distribution import install
        controller_name = self.controller or ("C" if self.install_keys else None)
        controller = GEN.public_raw(GEN.test_key(controller_name)) if controller_name else None
        part = None
        keys = changes.pop("keys", self.install_keys)
        if keys:
            part = install.anchor_part([public(name) for name in keys],
                                       threshold=changes.pop("threshold", self.install_threshold),
                                       operators=[public(name) for name in changes.pop("operators", self.operators)],
                                       seq=changes.pop("seq", self.install_seq),
                                       domain=changes.pop("domain", None) or install.domain_sha256(self.adapter()))
        return trust_module.anchor_bytes([public(name) for name in changes.pop("authorities", self.authorities)],
                                         target=self.kind, stream=self.stream, controller=controller,
                                         fresh=self.fresh, install=part)

    def install_set(self, install_kind: str, bodies: dict, seq: int = 1, *, signers=None, metas=None,
                    **seal_args) -> list:
        """The (sealed, body) pairs of an install set of `install_kind` for this point, signed by `signers` (test key
        names, by default the first `install_threshold` install keys). A `policy.ppt` gets the image's `meta`."""
        from prismpath.distribution import install
        names = signers if signers is not None else self.install_keys[:self.install_threshold]
        metas = dict(metas or {})
        if "policy.ppt" in bodies and "policy.ppt" not in metas:
            metas["policy.ppt"] = GEN.image_meta(bodies["policy.ppt"])
        seal_args.setdefault("not_before", NOT_BEFORE)
        return install.seal_set(install_kind, bodies, stream=self.stream, seq=seq, target=self.kind,
                                signers=[GEN.test_key(name) for name in names], metas=metas, **seal_args)

    def send(self, pairs, pep: Optional[Pep] = None) -> list:
        """Stage each (sealed, body) on the PEP and answer the state records, read."""
        pep = pep or self.pep
        return [state_record.read(pep.stage(sealed, body), self.key.public_raw) for sealed, body in pairs]

    def install_trust(self, seq: int, keys, *, threshold: int, operators=(), signers=None, widens=None):
        """A sealed `install.trust` with `keys` and `operators` (test key names), signed by `signers`, by default every
        current install key and every key it adds. Returns (sealed, body)."""
        from prismpath.distribution import install
        body = install.trust_body([public(name) for name in keys], threshold=threshold,
                                  operators=[public(name) for name in operators])
        if signers is None:
            signers = list(dict.fromkeys(list(self.install_keys) + list(keys) + list(operators)))
        record = self.pep.installed.record
        if widens is None:
            widens = install.trust_widens(record, body)
        envelope_bytes = env.build("install.trust", body, stream=self.stream, seq=seq, targets=(self.kind,),
                                   not_before=NOT_BEFORE, expires=0, policy_sha256=env.ZERO_HASH,
                                   release=env.ZERO_HASH, widens=widens)
        return env.seal(envelope_bytes, [GEN.test_key(name) for name in signers]), body

    def adapter(self):
        raise NotImplementedError("a Point names its adapter")

    def open(self, provision: bool = True) -> Pep:
        """A fresh PEP over the state directory, as after a restart, provisioned on first open."""
        pep = Pep(str(self.state_dir), self.adapter(), self.key, self.clock, expiry_response=self.expiry_response,
                  has_clock=self.has_clock, install_copy=str(self.install_copy) if self.install_copy else None)
        if provision and not pep.provisioned:
            pep.confirm(pep.provision(self.anchor()))
        return pep

    def policy_of(self, body: bytes) -> str:
        """The policy hash a release of `body` names: the body's own unless the kind says otherwise."""
        return canon.sha256_hex(body)

    def seal(self, body: bytes, seq: int = 1, **seal_args) -> bytes:
        """A release of `body` that replaces the active one (W2): its `replaces` is the active policy hash."""
        seal_args.setdefault("policy_sha256", self.policy_of(body))
        active = getattr(self, "pep", None) and self.pep.active
        seal_args.setdefault("replaces", active.policy_sha256 if active else "")
        return seal(self.artifact, body, seq=seq, targets=(self.kind,), **seal_args)

    def widen(self, body: bytes, seq: int = 1, froms=(), *, pep: Optional[Pep] = None, **seal_args) -> bytes:
        """Stage the owner's widening statement (W4) for the release `seal(body, seq)` would make. It shares the
        release's stream, seq, policy hash, release id, `replaces` and `widens` (E7)."""
        pep = pep or self.pep
        policy = seal_args.get("policy_sha256") or self.policy_of(body)
        release = seal_args.get("release") or env.release_id([(self.artifact, canon.sha256_hex(body))])
        replaces = seal_args.get("replaces", pep.active.policy_sha256 if pep.active else "")
        statement = widening(froms)
        sealed = seal("trust.widening", statement, seq=seq, release=release, policy_sha256=policy,
                      targets=(self.kind,), signer=seal_args.get("signer", "A"), replaces=replaces,
                      widens=seal_args.get("widens", False), not_before=seal_args.get("not_before", NOT_BEFORE))
        return pep.stage(sealed, statement)

    def stage(self, body: bytes, seq: int = 1, *, pep: Optional[Pep] = None, **seal_args) -> bytes:
        """Stage a release of `body` that replaces the active one. A first install is larger than no policy, and
        on a kind that cannot decide another table than the active one is larger (W2), so the owner's widening
        statement covering any PEP is staged before it (W3) unless the caller says how it widens. A renewal of
        the active table goes in on its signature. Returns the release's stage-ack."""
        pep = pep or self.pep
        active = pep.active
        changed = (active is None or not pep.target.decides
                   and active.bodies.get(self.artifact, b"") != bytes(body))
        if changed and "widens" not in seal_args:
            seal_args["widens"] = True                   # it allows more than what it replaces (W1, W2, W6)
            self.widen(body, seq, pep=pep, **seal_args)
        seal_args.setdefault("replaces", pep.active.policy_sha256 if pep.active else "")
        return pep.stage(self.seal(body, seq=seq, **seal_args), body)

    def commit(self, body: bytes, seq: int = 1, **seal_args) -> bytes:
        """Stage and commit a release of `body` (`stage`)."""
        self.stage(body, seq, **seal_args)
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


def release_with_statement(point: "Point", body: bytes, seq: int, *, widen: bool, replaces: str,
                           froms=None, **seal_args) -> List[tuple]:
    """The (sealed, body) pairs a controller stores for one release of `body` on `point`'s kind. With `widen`
    the release says it widens and its widening statement, from `replaces` (any policy when it replaces
    nothing) unless `froms` is given, comes first (W3, W7). Every envelope shares `replaces` and `widens` (E7)."""
    seal_args.setdefault("widens", widen)
    release = seal_args.get("release") or env.release_id([(point.artifact, canon.sha256_hex(body))])
    policy = seal_args.get("policy_sha256") or point.policy_of(body)
    pairs = []
    if widen:
        statement = widening(([replaces] if replaces else []) if froms is None else froms)
        pairs.append((seal("trust.widening", statement, seq=seq, release=release, policy_sha256=policy,
                           targets=(point.kind,), replaces=replaces, widens=seal_args["widens"],
                           signer=seal_args.get("signer", "A")), statement))
    pairs.append((point.seal(body, seq=seq, replaces=replaces, **seal_args), body))
    return pairs


HOSTS = canon.canon2_bytes(["api.example.com"])


class ModelAgent(Adapter):
    """A model of an agent home that holds the committed release in memory, as the mesh model holds its table.
    The agent home itself is PR 9's."""
    kind = "agent"

    def __init__(self):
        self.running = None

    def activate(self, release) -> None:
        self.running = release

    def deactivate(self, cause: str) -> None:
        self.running = None


@dataclass
class AgentPep(Point):
    """A PEP of the `agent` row over `ModelAgent`. A release is its `policy.core` and its `egress.hosts`,
    `hosts` unless a call names others."""
    kind: str = "agent"
    artifact: str = "policy.core"
    hosts: bytes = HOSTS

    def adapter(self):
        return ModelAgent()

    def release_of(self, body: bytes, hosts: Optional[bytes] = None) -> str:
        return env.release_id([("egress.hosts", canon.sha256_hex(hosts or self.hosts)),
                               ("policy.core", canon.sha256_hex(body))])

    def seal(self, body: bytes, seq: int = 1, hosts: Optional[bytes] = None, **seal_args) -> bytes:
        seal_args.setdefault("release", self.release_of(body, hosts))
        return super().seal(body, seq, **seal_args)

    def seal_hosts(self, body: bytes, seq: int = 1, hosts: Optional[bytes] = None, **seal_args) -> bytes:
        """The `egress.hosts` envelope of the release of `body` at `seq`."""
        hosts = hosts or self.hosts
        seal_args.setdefault("release", self.release_of(body, hosts))
        seal_args.setdefault("policy_sha256", self.policy_of(body))
        active = self.pep.active
        seal_args.setdefault("replaces", active.policy_sha256 if active else "")
        return seal("egress.hosts", hosts, seq=seq, targets=(self.kind,), **seal_args)

    def widen(self, body: bytes, seq: int = 1, froms=(), *, pep: Optional[Pep] = None, hosts: Optional[bytes] = None,
              **seal_args) -> bytes:
        seal_args.setdefault("release", self.release_of(body, hosts))
        return super().widen(body, seq, froms, pep=pep, **seal_args)

    def stage(self, body: bytes, seq: int = 1, *, pep: Optional[Pep] = None, hosts: Optional[bytes] = None,
              **seal_args) -> bytes:
        """Stage both envelopes of the release, the statement first on a first install. Returns the first
        refusal among the acks, or the last ack."""
        pep = pep or self.pep
        seal_args.setdefault("release", self.release_of(body, hosts))
        if pep.active is None and "widens" not in seal_args:
            seal_args["widens"] = True                   # a first install allows more than no policy
            self.widen(body, seq, pep=pep, hosts=hosts, **seal_args)
        seal_args.setdefault("replaces", pep.active.policy_sha256 if pep.active else "")
        acks = [super().stage(body, seq, pep=pep, **seal_args),
                pep.stage(self.seal_hosts(body, seq, hosts, **seal_args), hosts or self.hosts)]
        refused = [ack for ack in acks if state_record.read(ack, self.key.public_raw).event == "refused"]
        return refused[0] if refused else acks[-1]


def answer(point, receipt, answer="allow", *, signer="O1", pep=None, not_before=None, lifetime=300, policy=None,
           kind=None):
    """A sealed `operator.answer` to the escalation whose receipt hash is `receipt`, and its body."""
    from prismpath.distribution import floor, kinds
    pep = pep or state_record.pep_id(point.key.public_raw).hex()
    kind = kind or point.kind
    body = floor.answer_body(answer, pep, receipt)
    start = point.clock.now - 10 if not_before is None else not_before
    held = point.pep.floor_set()
    doc = {"artifact": kinds.ANSWER, "body_sha256": canon.sha256_hex(body), "body_size": len(body),
           "encoding": "canon/2", "expires": start + lifetime, "format": env.FORMAT, "meta": {}, "not_before": start,
           "policy_sha256": policy or (held.policy_sha256 if held else "00" * 32), "release": env.ZERO_HASH,
           "replaces": "", "seq": 1, "stream": STREAM, "targets": [kind], "widens": False}
    raw = canon.canon2_bytes(doc)                     # raw, so a lifetime the writer refuses can be sent
    key = GEN.test_key(signer)
    return env.seal_entries(raw, [(key_id(signer), key.sign(env.signed_message(raw)))]), body


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
    for signed in (point.pep.record("beat"), point.stage(bodies[1], 2, not_before=EXPIRES, expires=EXPIRES + 1000),
                   point.pep.abort(STREAM, 9, "00" * 32)):
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
    point.stage(bodies[0], 3, not_before=EXPIRES, expires=EXPIRES + 1000)
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
        pep.take_statement(b"PPEP" + bytes(98))
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

