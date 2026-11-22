# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The kind table of policy distribution (spec-policy-distribution.md, section 3), held in one place so a
new kind is one row.

The names are closed lists of the format: an envelope naming any other artifact or target kind is
`dist:bad-format` (E8), and each artifact's `meta` members are its row's. A target kind has a row in
`TARGETS` once an enforcement point of that kind is built. This version has `host`. A PEP of a kind with no
row cannot be described to the verifier. Each artifact's own check (V11) is `check(envelope, body, pep)`,
which answers None or the cause.

The three trust kinds read their bodies here as their formats. What a trust statement does to the trust
store (R1 to R7, O1 to O4) and the widening rule (W1 to W7) are applied by the code that owns them, not
by this table.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, FrozenSet, Optional

from prismpath import canon
from prismpath.kernel import canon2, causes

BAD_FORMAT = "dist:bad-format"
MAX_SEQ = 2 ** 53 - 1                              # E1 seq, and every integer the format carries
_HEX64 = re.compile(r"[0-9a-f]{64}")
_STREAM = re.compile(r"[a-z0-9._/-]{1,64}")


class Refused(Exception):
    """A distribution check failed. `cause` is the registered cause name, the only thing reported."""

    def __init__(self, cause: str, detail: str = ""):
        super().__init__(f"{cause}: {detail}" if detail else cause)
        self.cause = cause


@dataclass(frozen=True)
class Verdict:
    """What a check decided: `cause` None when it passed, else the one registered cause. `envelope` is the
    parsed envelope once it read. `unchanged` is an envelope accepted that changes nothing (Q3, R1).
    `time_floor` is the enforcement point's time floor after V6 passed (V13), for the PEP to make durable."""
    cause: Optional[str]
    envelope: Any = None
    unchanged: bool = False
    time_floor: Optional[int] = None

    @property
    def ok(self) -> bool:
        return self.cause is None


def is_hex64(value: Any) -> bool:
    return isinstance(value, str) and _HEX64.fullmatch(value) is not None


def is_stream(value: Any) -> bool:
    return isinstance(value, str) and _STREAM.fullmatch(value) is not None


def is_int(value: Any, low: int, high: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and low <= value <= high


def load_canonical(raw: bytes, what: str) -> Any:
    """The canon/2 value of `raw` read strictly (E2): `document:not-canonical` for canon/2 in another
    spelling, `dist:bad-format` for anything that is not canon/2. Never respelled."""
    try:
        return canon2.loads(raw)
    except canon2.Canon2Error as error:
        if error.rule == "not-canonical":
            raise Refused(canon.NotCanonical.CAUSE, f"the {what} is not its canonical spelling") from None
        raise Refused(BAD_FORMAT, f"the {what} is not canon/2 ({error.rule})") from None


TARGET_KINDS = frozenset({"agent", "cfs", "gateway", "host", "mesh", "xdp"})


@dataclass(frozen=True)
class Target:
    """A target kind: the artifacts it needs before it commits (C2), those it needs only when another
    artifact of the release asks for them (`policy.spiral`, when the `policy.ppt` declares packing), and
    whether it can decide larger (W1). `uses` is what V5 admits. `expiry_hold` is whether a deployment may
    choose HOLD at expiry (X6), true only for `mesh` and `cfs`."""
    needs: FrozenSet[str]
    decides: bool
    when_declared: FrozenSet[str] = frozenset()
    expiry_hold: bool = False

    @property
    def uses(self) -> FrozenSet[str]:
        return self.needs | self.when_declared


ROLES = frozenset({"authority"})                    # K4: the key roles this version knows
AUTHORITY = "authority"


@dataclass(frozen=True)
class Artifact:
    """An artifact kind: its `meta` members and its own check (V11), None when no target in `TARGETS` uses
    it yet."""
    meta_required: FrozenSet[str] = frozenset()
    meta_optional: FrozenSet[str] = frozenset()
    check: Optional[Callable[[Any, bytes, Any], Optional[str]]] = None
    role: str = AUTHORITY                          # K4: every artifact kind needs the authority in this version


# ------------------------------------------------------------------ the artifact checks (V11)

def _first_cause(reasons) -> Optional[str]:
    return causes.reason_name(reasons[0]) if reasons else None


def check_policy_ppt(envelope, body: bytes, pep) -> Optional[str]:
    """`policy.ppt` on a deciding target that reads `meta` (V11): `validate_image`, the signed counts, the
    recomputed WCET, the packing profile, and the qualification envelope gate the PEP holds, each with its
    existing cause. `meta` means what the same members of a `ppt-pack/1` manifest mean."""
    from prismpath.hotswap import policy_pack
    meta = envelope.meta
    ok, reasons = policy_pack.validate_image(body)
    if not ok:
        return _first_cause(reasons)
    cause = _first_cause(policy_pack.check_counts(meta, body))
    if cause:
        return cause
    packing = meta.get("packing")
    if packing is not None and not (isinstance(packing, dict) and set(packing) == {"profile", "sidecar_sha256"}
                                    and packing["profile"] == "spiral" and is_hex64(packing["sidecar_sha256"])):
        return "packing:unknown-profile"              # the one profile defined is a spiral with its sidecar's hash
    if pep.qualification is None:
        return "envelope:missing"
    ok, reasons = policy_pack.check_envelope({"envelope_id": meta["qualification"], "fields": meta["fields"]},
                                             body, pep.qualification)
    return None if ok else _first_cause(reasons)


def check_policy_spiral(_envelope, _body: bytes, _pep) -> Optional[str]:
    """`policy.spiral` has no check of its own when it is verified. Its SHA-256 is held against the
    `sidecar_sha256` of the staged `policy.ppt` envelope's `meta.packing` when the release commits (C2), with
    `spiral:sidecar-missing` and `spiral:sidecar-hash-mismatch`, by the host's adapter."""
    return None


def _trust_body(body: bytes, form: str, members: FrozenSet[str]) -> dict:
    """A trust body read strictly as canon/2 with exactly `members` and `format` `form`, or `Refused`."""
    doc = load_canonical(body, f"{form} body")
    if not isinstance(doc, dict) or set(doc) != members or doc["format"] != form or doc["encoding"] != canon.CANON2:
        raise Refused(BAD_FORMAT, f"not a {form} body")
    return doc


def _sorted_hashes(value: Any) -> bool:
    return isinstance(value, list) and all(is_hex64(item) for item in value) and value == sorted(set(value))


REVOCATION_FORMAT = "prismpath.dist-revocation/1"
ROTATION_FORMAT = "prismpath.dist-rotation/1"
WIDENING_FORMAT = "prismpath.dist-widening/1"


def read_revocation(body: bytes) -> dict:
    """Section 10: a revocation list, its `envelopes`, `keys` and `policies` sorted hash lists without
    repeats and `floors` an object of stream names to a `seq`. `Refused` when it does not read."""
    doc = _trust_body(body, REVOCATION_FORMAT, frozenset({"encoding", "envelopes", "floors", "format", "keys",
                                                          "policies"}))
    if not all(_sorted_hashes(doc[name]) for name in ("envelopes", "keys", "policies")):
        raise Refused(BAD_FORMAT, "a revocation list that is not sorted hashes without repeats")
    floors = doc["floors"]
    if not isinstance(floors, dict) or not all(is_stream(stream) and is_int(seq, 1, MAX_SEQ)
                                               for stream, seq in floors.items()):
        raise Refused(BAD_FORMAT, "revocation floors")
    return doc


def read_rotation(body: bytes) -> dict:
    """Section 11: a rotation, the new public key in `add` and the key id it retires, or the empty string."""
    doc = _trust_body(body, ROTATION_FORMAT, frozenset({"add", "encoding", "format", "retire"}))
    if not is_hex64(doc["add"]) or not (doc["retire"] == "" or is_hex64(doc["retire"])):
        raise Refused(BAD_FORMAT, "rotation members")
    return doc


def read_widening(body: bytes) -> dict:
    """W4: a widening statement, the sorted policy hashes it may replace in `from`."""
    doc = _trust_body(body, WIDENING_FORMAT, frozenset({"encoding", "format", "from"}))
    if not _sorted_hashes(doc["from"]):
        raise Refused(BAD_FORMAT, "a widening statement whose from is not sorted hashes without repeats")
    return doc


def _reads(reader: Callable[[bytes], dict]) -> Callable[[Any, bytes, Any], Optional[str]]:
    def check(_envelope, body: bytes, _pep) -> Optional[str]:
        try:
            reader(body)
        except Refused as refused:
            return refused.cause
        return None
    return check


# ------------------------------------------------------------------ the table

ARTIFACTS: Dict[str, Artifact] = {
    "policy.core": Artifact(),
    "policy.ppt": Artifact(frozenset({"fields", "counts", "wcet_cycles", "qualification"}),
                           frozenset({"packing", "flow_sha256", "overlay_of"}), check_policy_ppt),
    "policy.spiral": Artifact(check=check_policy_spiral),
    "sandbox.profile": Artifact(frozenset({"compiler"})),
    "egress.hosts": Artifact(),
    "gateway.routes": Artifact(),
    "net.dests": Artifact(),
    "net.edge": Artifact(frozenset({"flow_sha256", "names_sha256", "qualification"})),
    "cfs.table": Artifact(),
    "grant": Artifact(),
    "trust.widening": Artifact(check=_reads(read_widening)),
    "trust.revocation": Artifact(check=_reads(read_revocation)),
    "trust.rotation": Artifact(check=_reads(read_rotation)),
}
TRUST_ARTIFACTS = frozenset({"trust.widening", "trust.revocation", "trust.rotation"})
ON_TRUST_STREAM = frozenset({"trust.revocation", "trust.rotation"})     # R1, O1: they travel on `@trust`

TARGETS: Dict[str, Target] = {
    "host": Target(needs=frozenset({"policy.ppt"}), decides=False, when_declared=frozenset({"policy.spiral"})),
}

assert set(TARGETS) <= TARGET_KINDS and TRUST_ARTIFACTS <= set(ARTIFACTS)
assert all(target.uses <= set(ARTIFACTS) - TRUST_ARTIFACTS for target in TARGETS.values())
assert all(ARTIFACTS[name].check is not None for target in TARGETS.values() for name in target.uses | TRUST_ARTIFACTS)
assert all(artifact.role in ROLES for artifact in ARTIFACTS.values())
