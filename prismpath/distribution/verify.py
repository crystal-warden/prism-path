# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The one verifier of policy distribution (spec-policy-distribution.md, section 9.1). An enforcement point,
the controller (F1), a gateway reading a grant (GR2) and the command line all call `verify`.

The rules run in the order V2 to V11 and the first that fails is the only cause reported (V1). The verifier
is a function of its arguments: it reads no clock, no file and no floor of its own. What the enforcement
point holds comes in as a `PepView` and its trust store, and the time floor the PEP should make durable
after V6 passed comes back in the `Verdict` (V13). The widening rule V12 joins with W1 to W7.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import FrozenSet, Optional

from prismpath import canon
from prismpath.distribution import envelope as env
from prismpath.distribution import kinds
from prismpath.distribution.kinds import Refused, Verdict
from prismpath.distribution.trust import TrustStore

SKEW = 300                                         # section 7: a PEP's clock is within 300 seconds of true time
__all__ = ["SKEW", "Floor", "Staged", "PepView", "Verdict", "verify"]


@dataclass(frozen=True)
class Floor:
    """Q1: the highest `seq` committed on the PEP's stream and the envelope ids committed at it."""
    seq: int = 0
    ids: FrozenSet[str] = frozenset()


@dataclass(frozen=True)
class Staged:
    """What a staged release shares (E7): its stream, `seq`, policy hash, release id, `replaces` and `widens`."""
    stream: str
    seq: int
    policy_sha256: str
    release: str
    replaces: str
    widens: bool


@dataclass(frozen=True)
class PepView:
    """What the verifier needs of an enforcement point. `kind` must have a row in `kinds.TARGETS`.
    `qualification` is the qualification envelope a `host` PEP admits images under, already verified,
    `body_bound` is the PEP's own bound on the body of an artifact, within its kind's, and never on a trust body (E6), and `has_clock` is False for a PEP with no real time
    clock, whose `now` is its time floor plus its monotonic count (T2) and which never applies T3.
    `instance_key_id` is the PEP's own instance key id, which a rotation may never add (O4)."""
    kind: str
    stream: str
    floor: Floor = field(default_factory=Floor)
    active: Optional[str] = None
    staged: Optional[Staged] = None
    qualification: Optional[dict] = None
    body_bound: int = env.MAX_BODY
    has_clock: bool = True
    instance_key_id: Optional[str] = None

    def __post_init__(self):
        if self.kind not in kinds.TARGETS:
            raise ValueError(f"no enforcement point of kind {self.kind!r} is built")
        if not kinds.is_stream(self.stream):
            raise ValueError(f"{self.stream!r} is not a stream name")


def _floor_check(envelope: env.Envelope, trust: TrustStore, pep: PepView) -> Optional[Verdict]:
    """V8. None to go on, or the verdict: a refusal, or an envelope at its floor that changes nothing."""
    envelope_id = envelope.envelope_id
    if envelope.artifact in kinds.ON_TRUST_STREAM:                 # R1, O1: one trust sequence, no step skipped
        if envelope.seq == trust.trust_seq + 1:
            return None
        if envelope.seq == trust.trust_seq and envelope_id == trust.trust_id:
            return Verdict(None, envelope, unchanged=True)
        return Verdict("dist:trust-replay", envelope)
    floor = max(pep.floor.seq, trust.floors.get(envelope.stream, 0))   # Q2, Q3, and R4's raised floor
    if envelope.seq > floor:
        return None
    if envelope.seq == pep.floor.seq == floor and envelope_id in pep.floor.ids:
        return Verdict(None, envelope, unchanged=True)
    return Verdict("dist:seq-replay", envelope)


def verify(sealed: bytes, body: bytes, *, trust: TrustStore, pep: PepView, now: int,
           reads_meta: Optional[bool] = None) -> Verdict:
    """V1: the sealed envelope and its body checked in the order V2 to V11 for `pep` at the PEP's clock
    reading `now` (Unix seconds). Returns the first failure's cause, or the accepted envelope. `reads_meta` True
    reads `meta` in full whatever the kind, as a controller always does (F1)."""
    return _verify(sealed, bytes(body), trust, pep, now, reads_meta, through_v8=False)


def verify_envelope(sealed: bytes, *, trust: TrustStore, pep: PepView, now: int,
                      reads_meta: Optional[bool] = None) -> Verdict:
    """V2 to V8 of a sealed envelope whose body has not been read (B9): what a PEP checks before it fetches or
    assembles the body. Returns the first failure's cause, or the envelope, whose `body_size` and `body_sha256`
    then bound and name the body to read."""
    return _verify(sealed, b"", trust, pep, now, reads_meta, through_v8=True)


def _verify(sealed: bytes, body: bytes, trust: TrustStore, pep: PepView, now: int, reads_meta: Optional[bool],
            *, through_v8: bool) -> Verdict:
    # V2: the container reads, and the envelope and body fit the bounds (B9: nothing past either is read)
    try:
        envelope_bytes, entries = env.unseal(sealed)
    except Refused as refused:
        return Verdict(refused.cause)
    target = kinds.TARGETS[pep.kind]
    artifact_bound = min(pep.body_bound, target.body_bound)
    if len(body) > max(artifact_bound, target.trust_bound):
        return Verdict("dist:too-large")
    # V3: the signatures, over the bytes as they came and before anything reads them (E9)
    counted = trust.counting(entries, env.signed_message(envelope_bytes), kinds.AUTHORITY)   # K4: every kind's role
    if not counted.ok:
        return counted
    # V4: the envelope reads
    try:
        envelope = env.read(envelope_bytes, reads_meta=target.reads_meta if reads_meta is None else reads_meta)
    except Refused as refused:
        return Verdict(refused.cause)
    # V5: for this PEP's kind, an artifact its kind uses or a trust kind its machine applies, on its stream or
    # `@trust`
    stream = env.TRUST_STREAM if envelope.artifact in kinds.ON_TRUST_STREAM else pep.stream
    if (pep.kind not in envelope.targets or envelope.stream != stream
            or not (envelope.artifact in target.uses or envelope.artifact in target.applies)):
        return Verdict("dist:target-mismatch", envelope)
    # ...then the signed size against the bound of that artifact, before any body is read (E6, B9)
    bound = target.trust_bound if envelope.artifact in kinds.TRUST_ARTIFACTS else artifact_bound
    if envelope.body_size > bound:
        return Verdict("dist:too-large", envelope)
    # V6: time, against the larger of the clock and the time floor (T1, T3, T4; X4 a trust kind never expires).
    # A PEP with no clock has no ground to call an envelope early (T3) and catches up by V13 (T2).
    time = max(now, trust.time_floor)
    if pep.has_clock and envelope.not_before - time > SKEW:
        return Verdict("dist:not-yet-valid", envelope)
    if envelope.expires and time >= envelope.expires:
        return Verdict("dist:expired", envelope)
    time_floor = max(trust.time_floor, envelope.not_before)          # V13

    def refused(cause: str) -> Verdict:
        return Verdict(cause, envelope, time_floor=time_floor)

    # V7: revocation
    if envelope.envelope_id in trust.revoked_envelopes or envelope.policy_sha256 in trust.revoked_policies:
        return refused("dist:revoked")
    # V8: the sequence
    floor = _floor_check(envelope, trust, pep)
    if floor is not None:
        return Verdict(floor.cause, envelope, unchanged=floor.unchanged, time_floor=time_floor)
    if through_v8:
        return Verdict(None, envelope, time_floor=time_floor)
    # V9: the body
    if len(body) != envelope.body_size or canon.sha256_hex(body) != envelope.body_sha256:
        return refused("dist:body-mismatch")
    # V10: the release already staged at this seq agrees (E7)
    staged = pep.staged
    if (envelope.artifact not in kinds.ON_TRUST_STREAM and staged is not None
            and staged.stream == envelope.stream and staged.seq == envelope.seq
            and (staged.policy_sha256, staged.release, staged.replaces, staged.widens)
            != (envelope.policy_sha256, envelope.release, envelope.replaces, envelope.widens)):
        return refused("dist:incomplete")
    # V11: the artifact's own check
    cause = target.check_for(envelope.artifact)(envelope, body, pep)
    if cause is None and envelope.artifact == "trust.revocation":
        cause = trust.check_revocation(body)                                     # R6
    if cause is None and envelope.artifact == "trust.rotation":
        cause = trust.check_rotation(body, entries, env.signed_message(envelope_bytes), pep.instance_key_id)  # O2-O4
    if cause is not None:
        return refused(cause)
    return Verdict(None, envelope, time_floor=time_floor)
