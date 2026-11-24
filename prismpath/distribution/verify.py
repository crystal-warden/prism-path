# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The one verifier of policy distribution (spec-policy-distribution.md, section 9.1). An enforcement point,
the controller (F1), a gateway reading a grant (GR2) and the command line all call `verify`.

The rules run in the order V2 to V11 and the first that fails is the only cause reported (V1). The verifier
is a function of its arguments: it reads no clock, no file and no floor of its own. What the enforcement
point holds comes in as a `PepView` and its trust store, and the time floor the PEP should make durable
after V6 passed comes back in the `Verdict` (V13). The widening rule V12 joins with W1 to W7.

`rules` names the rule set. `RELEASE`, the default, is V2 to V11 for an envelope a PEP may stage. `GR2` is how a
gateway reads a grant (section 13): V2 to V7 and V9, with V5 admitting only a `grant` on the gateway's own stream.
A grant is not a release, so it has no floor (V8), no staged release to agree with (V10) and no widening rule, and
what it covers is the gateway's to read after the verdict.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, FrozenSet, Mapping, Optional

from prismpath import canon
from prismpath.distribution import envelope as env
from prismpath.distribution import kinds
from prismpath.distribution.kinds import Refused, Verdict
from prismpath.distribution.trust import TrustStore

SKEW = 300                                         # section 7: a PEP's clock is within 300 seconds of true time
RELEASE, GR2 = "release", "gr2"                    # the rule sets: V2 to V11, and a gateway's reading of a grant
__all__ = ["SKEW", "RELEASE", "GR2", "Floor", "Staged", "PepView", "Verdict", "verify"]


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
    install: Any = None                            # `InstallView`: the PEP's install part (section 21), or None

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
           reads_meta: Optional[bool] = None, rules: str = RELEASE) -> Verdict:
    """V1: the sealed envelope and its body checked in the order V2 to V11 for `pep` at the PEP's clock
    reading `now` (Unix seconds), or with `rules` GR2 the rules a gateway reads a grant with. Returns the first
    failure's cause, or the accepted envelope. `reads_meta` True reads `meta` in full whatever the kind, as a
    controller always does (F1)."""
    if rules not in (RELEASE, GR2):
        raise ValueError(f"{rules!r} is not a rule set")
    return _verify(sealed, bytes(body), trust, pep, now, reads_meta, through_v8=False, grant=rules == GR2)


def verify_envelope(sealed: bytes, *, trust: TrustStore, pep: PepView, now: int,
                      reads_meta: Optional[bool] = None) -> Verdict:
    """V2 to V8 of a sealed envelope whose body has not been read (B9): what a PEP checks before it fetches or
    assembles the body. Returns the first failure's cause, or the envelope, whose `body_size` and `body_sha256`
    then bound and name the body to read."""
    return _verify(sealed, b"", trust, pep, now, reads_meta, through_v8=True)


def _verify(sealed: bytes, body: bytes, trust: TrustStore, pep: PepView, now: int, reads_meta: Optional[bool],
            *, through_v8: bool, grant: bool = False) -> Verdict:
    # V2: the container reads, and the envelope and body fit the bounds (B9: nothing past either is read)
    try:
        envelope_bytes, entries = env.unseal(sealed)
    except Refused as refused:
        return Verdict(refused.cause)
    target = kinds.TARGETS[pep.kind]
    artifact_bound = min(pep.body_bound, target.body_bound)
    if len(body) > max(artifact_bound, target.trust_bound):
        return Verdict("dist:too-large")
    # V3: the signatures, over the bytes as they came and before anything reads them (E9). K4: every role under which
    # the envelope is signed is found, the authority's in the trust store and the install keys' in the install record
    # (IS2), and V3 fails only when there is none
    message = env.signed_message(envelope_bytes)
    counted = trust.counting(entries, message, kinds.AUTHORITY)
    record = pep.install.record if pep.install is not None else None
    installed = record.counting(entries, message) if record is not None else None
    if not counted.ok and not (installed is not None and installed.ok):
        if counted.cause == "dist:unknown-key" and installed is not None:
            return installed
        return counted
    # V4: the envelope reads
    try:
        envelope = env.read(envelope_bytes, reads_meta=target.reads_meta if reads_meta is None else reads_meta)
    except Refused as refused:
        return Verdict(refused.cause)
    # V5, K4: the role the artifact needs is one it is signed under. An install kind is checked on its own path
    if envelope.artifact in kinds.INSTALL_ARTIFACTS:
        return _verify_install(envelope, entries, message, body, trust, pep, now, installed, through_v8=through_v8)
    if not counted.ok:
        return Verdict(counted.cause, envelope)
    # V5: for this PEP's kind, an artifact its kind uses or a trust kind its machine applies, on its stream or
    # `@trust`. A revocation, a rotation or a controller key statement is for every PEP whatever `targets` says, since one trust sequence
    # counts the same for all of them (R1)
    on_trust = envelope.artifact in kinds.ON_TRUST_STREAM
    stream = env.TRUST_STREAM if on_trust else pep.stream
    if grant:                                                       # GR2: a grant, for this gateway, on its stream
        if envelope.artifact != "grant" or pep.kind != "gateway" or pep.kind not in envelope.targets \
                or envelope.stream != pep.stream:
            return Verdict("dist:target-mismatch", envelope)
    elif (not (on_trust or pep.kind in envelope.targets) or envelope.stream != stream
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
    if grant:                                                       # GR2: V9 and no other rule
        if len(body) != envelope.body_size or canon.sha256_hex(body) != envelope.body_sha256:
            return refused("dist:body-mismatch")
        return Verdict(None, envelope, time_floor=time_floor)
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
    others = record.ids if record is not None else frozenset()                   # K4: the install part's keys
    if cause is None and envelope.artifact == "trust.rotation":
        cause = trust.check_rotation(body, entries, env.signed_message(envelope_bytes), pep.instance_key_id,
                                     others=others)                              # O2-O4, K4
    if cause is None and envelope.artifact == "trust.controller":
        cause = trust.check_controller(body, pep.instance_key_id, others=others)  # K7, K4, K5
    if cause is None and envelope.artifact not in kinds.TRUST_ARTIFACTS and pep.install is not None:
        from prismpath.distribution import install
        if not install.inside(pep.kind, pep.install.ceiling, {envelope.artifact: body}, whole=False):
            cause = install.ABOVE_CEILING                                         # CL2
    if cause is not None:
        return refused(cause)
    return Verdict(None, envelope, time_floor=time_floor)


@dataclass(frozen=True)
class InstallView:
    """What the verifier needs of a PEP's install part (section 21): the install record, the staged install sets by
    kind, the held ceiling, and whether the statement came in a message, where an install threshold of 1 takes no
    install statement (IS4), or by provisioning."""
    record: Any = None
    staged: Mapping[str, Any] = field(default_factory=dict)
    ceiling: Any = None
    message: bool = True


def _verify_install(envelope, entries, message: bytes, body: bytes, trust: TrustStore, pep: PepView, now: int,
                    installed: Optional[Verdict], *, through_v8: bool) -> Verdict:
    """IS5: an install statement through V5 to V11 with the differences section 21 gives them. V3 counted the install
    keys against the install threshold. V5 takes an install kind on the PEP's own stream, by provisioning or, where
    the install threshold is 2 or more, in a message (IS4), and a set in the form of its kind (IS3). V6 applies T3 and
    never raises the time floor. V7 is never read against an install kind (IS7). V8 is IS6, or IS11 for an
    `install.trust`. V10 holds a set's statements to one set. V11 is the check of the artifact `as` names, then the
    ceiling (CL3). V12 is the PEP's when the set is whole (IS12)."""
    from prismpath.distribution import install
    view = pep.install
    record = view.record if view is not None else None
    if installed is None or not installed.ok:
        return Verdict(installed.cause if installed is not None else "dist:unknown-key", envelope)
    target = kinds.TARGETS[pep.kind]
    artifact = envelope.artifact
    named = envelope.meta.get("as") if artifact != install.TRUST else None
    # V5
    if view.message and record.threshold < 2:
        return Verdict("dist:target-mismatch", envelope)                      # IS4: provisioning only
    if envelope.stream != pep.stream or artifact not in install.BUILT:
        return Verdict("dist:target-mismatch", envelope)
    if artifact != install.TRUST:
        _needed, allowed = kinds.install_form(pep.kind, artifact)
        if pep.kind not in envelope.targets or not (named in allowed or named == kinds.NONE):
            return Verdict("dist:target-mismatch", envelope)
    listed = artifact == install.TRUST or named == kinds.POLICY_LIST
    bound = target.trust_bound if listed else min(pep.body_bound, target.body_bound)
    if envelope.body_size > bound or len(body) > bound:
        return Verdict("dist:too-large", envelope)
    # V6: T3 where the PEP has a clock; an install statement never raises the time floor (T1, V13)
    time = max(now, trust.time_floor if trust.readable else 0)
    if pep.has_clock and envelope.not_before - time > SKEW:
        return Verdict("dist:not-yet-valid", envelope)
    # V8: IS6, IS11
    envelope_id = envelope.envelope_id
    if artifact == install.TRUST:
        if envelope.seq == record.trust_seq and envelope_id == record.trust_id:
            return Verdict(None, envelope, unchanged=True)
        if envelope.seq != record.trust_seq + 1:
            return Verdict("dist:trust-replay", envelope)
    else:
        held, held_seq = record.sets[artifact], record.seqs[artifact]
        if envelope.seq == held_seq and held is not None and envelope_id in held.envelope_ids:
            return Verdict(None, envelope, unchanged=True)
        if envelope.seq <= held_seq:
            return Verdict("dist:seq-replay", envelope)
        staged = view.staged.get(artifact)
        if staged is not None and envelope.seq < staged.seq:
            return Verdict("dist:seq-replay", envelope)                       # IS4, G2
    if through_v8:
        return Verdict(None, envelope)
    # V9
    if len(body) != envelope.body_size or canon.sha256_hex(body) != envelope.body_sha256:
        return Verdict("dist:body-mismatch", envelope)
    # V10: the statements of one set share stream, seq, policy hash, release id, replaces, widens and rate
    if artifact != install.TRUST:
        staged = view.staged.get(artifact)
        if staged is not None and staged.seq == envelope.seq:
            first = next(iter(staged.envelopes.values()))
            if ((first.policy_sha256, first.release, first.replaces, first.widens, first.meta.get("rate"))
                    != (envelope.policy_sha256, envelope.release, envelope.replaces, envelope.widens,
                        envelope.meta.get("rate"))):
                return Verdict("dist:incomplete", envelope)
            if named in staged.statements and staged.statements[named][0] != envelope_id:
                return Verdict("dist:incomplete", envelope)
    # V11: the check of the artifact `as` names, then the ceiling
    if artifact == install.TRUST:
        check = kinds.ARTIFACTS[install.TRUST].check
        cause = check(envelope, body, pep) or install.check_trust(
            record, body, entries, message, widens=envelope.widens, instance_key_id=pep.instance_key_id, trust=trust)
    elif named == kinds.NONE:
        cause = None
    elif named == kinds.POLICY_LIST:
        try:
            kinds.read_ceiling_list(body)
            cause = None
        except Refused as refused:
            cause = refused.cause
    else:
        cause = target.check_for(named)(envelope, body, pep)
        if cause is None and artifact != install.CEILING and not install.inside(
                pep.kind, view.ceiling, {named: body}, whole=False):
            cause = install.ABOVE_CEILING                                       # CL3
    if cause is not None:
        return Verdict(cause, envelope)
    return Verdict(None, envelope)
