# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The kind table of policy distribution (spec-policy-distribution.md, section 3), held in one place so a
new kind is one row.

The names are closed lists of the format: an envelope naming any other artifact or target kind is
`dist:bad-format` (E8), and each artifact's `meta` members are its row's. A target kind has a row in
`TARGETS` once an enforcement point of that kind is built: `host`, `agent`, `gateway`, `mesh` and `xdp` here, and `cfs`, whose table
layout lives with the cFS app, registered by `integrations/cfs/dist_kind.py` through `register_target`. The `xdp`
row's destination table is read by the edge's own reader (`prismpath-ebpf/net_dist.py`), which lives beside the
loader it feeds and is found from here, so a tree without it refuses the artifact rather than guessing at it. A
PEP of a kind with no row cannot be described to the verifier. Each artifact's own check (V11) is
`check(envelope, body, pep)`, which answers None or the cause. A target row may hold its own check of an
artifact in `checks`, as a mesh node reads a `policy.ppt` with its own table parser and ignores `meta`.

A target row also says which trust kinds its machine applies (`applies`). V5 refuses any other trust kind
with `dist:target-mismatch`, so a statement is never verified and then left unapplied.
"""
from __future__ import annotations

import hashlib
import importlib
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, FrozenSet, Optional

from prismpath import canon
from prismpath.kernel import canon2, causes

BAD_FORMAT = "dist:bad-format"
# refusals a later clock or the next trust statement may remove, so the envelope is offered and tried again
RETRYABLE = frozenset({"dist:not-yet-valid", "dist:unknown-key", "dist:trust-replay"})
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
    whether it can decide larger (W1). `uses` is what V5 admits besides the trust kinds in `applies`, the ones
    its machine applies. `expiry_hold` is whether a deployment may choose HOLD at expiry (X6), true only for
    `mesh` and `cfs`. `body_bound` is the kind's bound on the body of an artifact it uses and `trust_bound` its
    bound on a trust body, 16,384 bytes for every kind, which holds the largest list R7 allows (E6), and `checks` the kind's own V11 checks
    where they differ from the artifact's. `reads_meta` is false for a kind whose own check does not read `meta`,
    so its reader only bounds `meta` and skips its members (E9). `compares` is what a kind that cannot decide
    still compares with the active release (W2): a `policy.ppt` table, any change of which is larger."""
    needs: FrozenSet[str]
    decides: bool
    when_declared: FrozenSet[str] = frozenset()
    expiry_hold: bool = False
    applies: FrozenSet[str] = frozenset({"trust.widening", "trust.revocation", "trust.rotation"})
    body_bound: int = 16777215
    trust_bound: int = 16384
    checks: Any = None
    reads_meta: bool = True
    compares: FrozenSet[str] = frozenset()

    @property
    def uses(self) -> FrozenSet[str]:
        return self.needs | self.when_declared

    def check_for(self, artifact: str) -> Optional[Callable[[Any, bytes, Any], Optional[str]]]:
        """V11 for `artifact` on this kind: the kind's own check, else the artifact's."""
        return (self.checks or {}).get(artifact) or ARTIFACTS[artifact].check


ROLES = frozenset({"authority"})                    # K4: the key roles this version knows
AUTHORITY = "authority"


# ------------------------------------------------------------------ the forms of the meta members (E11)

COUNT_MEMBERS = frozenset({"atoms", "nodes", "edges", "prog_words", "max_steps", "max_stack"})


def _string(low: int, high: int) -> Callable[[Any], bool]:
    return lambda value: isinstance(value, str) and low <= len(value) <= high


def _fields(value: Any) -> bool:
    return isinstance(value, dict) and all(isinstance(kind, str) for kind in value.values())


def _counts(value: Any) -> bool:
    return (isinstance(value, dict) and set(value) == COUNT_MEMBERS
            and all(is_int(count, 0, 65535) for count in value.values()))


def _packing(value: Any) -> bool:
    return (isinstance(value, dict) and set(value) == {"profile", "sidecar_sha256"}
            and _string(1, 32)(value["profile"]) and is_hex64(value["sidecar_sha256"]))


FORMS: Dict[str, Callable[[Any], bool]] = {
    "fields": _fields,
    "counts": _counts,
    "wcet_cycles": lambda value: is_int(value, 0, MAX_SEQ),
    "qualification": _string(1, 128),
    "packing": _packing,
    "flow_sha256": lambda value: is_hex64(value),
    "overlay_of": _string(1, 128),
    "names_sha256": lambda value: is_hex64(value),
    "compiler": lambda value: is_int(value, 1, MAX_SEQ),
}


@dataclass(frozen=True)
class Artifact:
    """An artifact kind: its `meta` members, each of the form `FORMS` gives it (E11), and its own check (V11),
    None for an artifact whose reader lives with a target not built yet. A target registered from outside the
    package names the check in its row (`Target.checks`)."""
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
    if "packing" in meta and meta["packing"]["profile"] != "spiral":     # the form is E11's, read at V4
        return "packing:unknown-profile"
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


def check_policy_core(envelope, body: bytes, _pep) -> Optional[str]:
    """`policy.core` (V11): the image loads as the core reads it, with the core's own cause when it does not,
    the harness knows every target it names, every value a rule names is inside its field's reading domain
    (`policy:out-of-domain`, 9.4), and its SHA-256 is the envelope's `policy_sha256`."""
    from prismpath.kernel import core_policy
    refusal = core_policy.load_policy(bytes(body))
    if refusal is not None:
        return refusal[0]
    from prismpath.agent.policy import OutsideDomain, Policy
    try:
        Policy(bytes(body))
    except OutsideDomain:
        return "policy:out-of-domain"
    except ValueError:
        return "policy:unreadable"
    return None if hashlib.sha256(bytes(body)).hexdigest() == envelope.policy_sha256 else "image:sha256-mismatch"


def read_hosts(body: bytes) -> list:
    """`egress.hosts`: a canon/2 array of lower case host names, sorted, without repeats, each one the egress proxy
    reads as itself. `Refused` with `dist:bad-format` otherwise."""
    from prismpath.agent.egress import Refusal, parse_authority
    doc = load_canonical(body, "egress.hosts")
    if not isinstance(doc, list) or not all(isinstance(name, str) for name in doc) or doc != sorted(set(doc)):
        raise Refused(BAD_FORMAT, "egress.hosts is not a sorted list of names without repeats")
    for name in doc:
        try:
            if parse_authority(f"{name}:443") != (name, 443):
                raise Refused(BAD_FORMAT, f"{name!r} is not a lower case host name")
        except Refusal:
            raise Refused(BAD_FORMAT, f"{name!r} is not a host name the egress proxy reads") from None
    return doc


def check_mesh_table(_envelope, body: bytes, _pep) -> Optional[str]:
    """`policy.ppt` on a mesh node (V11): the node runs its own table parser and ignores `meta`, so the check is
    the image check alone, with its existing causes."""
    from prismpath.hotswap import policy_pack
    ok, reasons = policy_pack.validate_image(body)
    return None if ok else _first_cause(reasons)


def _trust_body(body: bytes, form: str, members: FrozenSet[str]) -> dict:
    """A trust body read strictly as canon/2 with exactly `members` and `format` `form`, or `Refused`."""
    doc = load_canonical(body, f"{form} body")
    if not isinstance(doc, dict) or set(doc) != members or doc["format"] != form or doc["encoding"] != canon.CANON2:
        raise Refused(BAD_FORMAT, f"not a {form} body")
    return doc


def _sorted_hashes(value: Any) -> bool:
    return isinstance(value, list) and all(is_hex64(item) for item in value) and value == sorted(set(value))


REVOCATION_FORMAT = "prismpath.dist-revocation/1"
REVOCATION_ENTRIES, REVOCATION_FLOORS = 64, 16       # section 10, R7
ROTATION_FORMAT = "prismpath.dist-rotation/1"
WIDENING_FORMAT = "prismpath.dist-widening/1"


def read_revocation(body: bytes) -> dict:
    """Section 10: a revocation list, its `envelopes`, `keys` and `policies` sorted hash lists without
    repeats and `floors` an object of stream names to a `seq`. `Refused` when it does not read, and with
    `dist:too-large` when a list holds more than 64 entries or `floors` more than 16 streams (R7)."""
    doc = _trust_body(body, REVOCATION_FORMAT, frozenset({"encoding", "envelopes", "floors", "format", "keys",
                                                          "policies"}))
    if not all(_sorted_hashes(doc[name]) for name in ("envelopes", "keys", "policies")):
        raise Refused(BAD_FORMAT, "a revocation list that is not sorted hashes without repeats")
    floors = doc["floors"]
    if not isinstance(floors, dict) or not all(is_stream(stream) and is_int(seq, 1, MAX_SEQ)
                                               for stream, seq in floors.items()):
        raise Refused(BAD_FORMAT, "revocation floors")
    if any(len(doc[name]) > REVOCATION_ENTRIES for name in ("envelopes", "keys", "policies")) \
            or len(floors) > REVOCATION_FLOORS:
        raise Refused("dist:too-large", "a revocation list beyond 64 entries or 16 streams")       # R7
    return doc


def read_rotation(body: bytes) -> dict:
    """Section 11: a rotation, the new public key in `add` and the key id it retires, or the empty string."""
    doc = _trust_body(body, ROTATION_FORMAT, frozenset({"add", "encoding", "format", "retire"}))
    if not is_hex64(doc["add"]) or not (doc["retire"] == "" or is_hex64(doc["retire"])):
        raise Refused(BAD_FORMAT, "rotation members")
    return doc


WIDENING_FROM = 64                                 # W4: the hashes a widening statement may list


def read_widening(body: bytes) -> dict:
    """W4: a widening statement, the sorted policy hashes it may replace in `from`, at most 64 of them
    (`dist:too-large` past that)."""
    doc = _trust_body(body, WIDENING_FORMAT, frozenset({"encoding", "format", "from"}))
    if not _sorted_hashes(doc["from"]):
        raise Refused(BAD_FORMAT, "a widening statement whose from is not sorted hashes without repeats")
    if len(doc["from"]) > WIDENING_FROM:
        raise Refused("dist:too-large", f"a widening statement from {len(doc['from'])} hashes, past {WIDENING_FROM}")
    return doc


def read_profile(body: bytes) -> dict:
    """`sandbox.profile`: a sandbox profile in canon/2 bytes (`Profile.canonical`). Whether it is the one the policy
    compiles to is the agent home's check at commit (`dist:derived-mismatch`)."""
    doc = load_canonical(body, "sandbox.profile")
    if not isinstance(doc, dict) or doc.get("format") not in ("prismpath.profile/1", "prismpath.profile/2"):
        raise Refused(BAD_FORMAT, "sandbox.profile is not a sandbox profile")
    return doc


ZONES_FORMAT = "prismpath.dist-zones/1"
ZONES_MAX, ZONE_NAME_MAX = 10000, 512


def read_zones(body: bytes) -> dict:
    """`agent.zones`: a canon/2 object with `encoding`, `format` and `protected`, the owner's protected names,
    sorted, without repeats, at most 10,000 names of 1 to 512 characters, none of them a path. `Refused` with
    `dist:bad-format` otherwise. Where the names are looked up is the home's own setting (section 3)."""
    doc = _trust_body(body, ZONES_FORMAT, frozenset({"encoding", "format", "protected"}))
    names = doc["protected"]
    if (not isinstance(names, list) or len(names) > ZONES_MAX or names != sorted(set(names))
            or not all(isinstance(name, str) and 1 <= len(name) <= ZONE_NAME_MAX and "/" not in name
                       and name not in (".", "..") for name in names)):
        raise Refused(BAD_FORMAT, "agent.zones protects sorted names without repeats, none of them a path")
    return doc


def read_routes(body: bytes):
    """`gateway.routes`: a route table in canon/2 bytes, read by `Routes.from_doc` and spelled as
    `Routes.canonical` spells it, so one table is one body. `Refused` with `dist:bad-format` otherwise."""
    from prismpath.gateway.reading import RouteError, Routes
    doc = load_canonical(body, "gateway.routes")
    try:
        routes = Routes.from_doc(doc)
    except RouteError as error:
        raise Refused(BAD_FORMAT, f"gateway.routes is not a route table ({error})") from None
    if routes.canonical() != bytes(body):
        raise Refused(BAD_FORMAT, "gateway.routes is not the table's canonical spelling")
    return routes


GRANT_FORMAT = "prismpath.dist-grant/1"
GRANT_METHOD_CLASSES = ("delete", "other", "read", "write")
_GRANT_CLASS = re.compile(r"[a-z][a-z0-9_]{0,31}")


def read_grant(body: bytes) -> dict:
    """Section 13: a grant body, a canon/2 object with `encoding`, `format` `prismpath.dist-grant/1` and the classes
    it covers, `method_classes` of read, write, delete and other and `path_classes` route classes other than
    `other` and `unknown`, each sorted, without repeats and holding at least one. `Refused` with `dist:bad-format`
    otherwise."""
    doc = _trust_body(body, GRANT_FORMAT, frozenset({"encoding", "format", "method_classes", "path_classes"}))
    for name, allowed in (("method_classes", GRANT_METHOD_CLASSES), ("path_classes", None)):
        values = doc[name]
        if (not isinstance(values, list) or not values or values != sorted(set(values))
                or not all(isinstance(value, str) and _GRANT_CLASS.fullmatch(value) for value in values)
                or (allowed is not None and not set(values) <= set(allowed))
                or (allowed is None and {"other", "unknown"} & set(values))):
            raise Refused(BAD_FORMAT, f"a grant's {name} are not classes it can cover")
    return doc


EDGE_DIR = Path(__file__).resolve().parents[2] / "prismpath-ebpf"


def edge_reader():
    """`net_dist`, the XDP edge's reader of `net.dests` and its loader adapter, from `prismpath-ebpf/` beside the
    package. `Refused` with `dist:bad-format` in a tree that does not carry it, so a destination table is never
    taken unread."""
    if "net_dist" in sys.modules:
        return sys.modules["net_dist"]
    if not (EDGE_DIR / "net_dist.py").is_file():
        raise Refused(BAD_FORMAT, "this tree has no reader of the XDP edge's destination table")
    if str(EDGE_DIR) not in sys.path:
        sys.path.insert(0, str(EDGE_DIR))
    return importlib.import_module("net_dist")


def read_dests(body: bytes):
    """`net.dests`: a `prismpath.net_dests/1` destination table in its canonical spelling, one the edge can use
    (`net_from_policy.Destinations`). `Refused` with `dist:bad-format` otherwise."""
    return edge_reader().read_dests(body)


def check_net_edge(_envelope, body: bytes, _pep) -> Optional[str]:
    """`net.edge` when it is staged (V11): the image check, with its existing causes. That it is byte for byte the
    table compiled from the staged `policy.core` and `net.dests` is the edge adapter's check at commit (C2), with
    `dist:derived-mismatch`, as the agent home holds a `sandbox.profile`."""
    from prismpath.hotswap import policy_pack
    ok, reasons = policy_pack.validate_image(body)
    return None if ok else _first_cause(reasons)


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
    "policy.core": Artifact(check=check_policy_core),
    "policy.ppt": Artifact(frozenset({"fields", "counts", "wcet_cycles", "qualification"}),
                           frozenset({"packing", "flow_sha256", "overlay_of"}), check_policy_ppt),
    "policy.spiral": Artifact(check=check_policy_spiral),
    "sandbox.profile": Artifact(frozenset({"compiler"}), check=_reads(lambda body: read_profile(body))),
    "egress.hosts": Artifact(check=_reads(read_hosts)),
    "agent.zones": Artifact(check=_reads(read_zones)),
    "gateway.routes": Artifact(check=_reads(read_routes)),
    "net.dests": Artifact(check=_reads(read_dests)),
    "net.edge": Artifact(frozenset({"flow_sha256", "names_sha256", "qualification"}), check=check_net_edge),
    "cfs.table": Artifact(),
    "grant": Artifact(check=_reads(read_grant)),
    "trust.widening": Artifact(check=_reads(read_widening)),
    "trust.revocation": Artifact(check=_reads(read_revocation)),
    "trust.rotation": Artifact(check=_reads(read_rotation)),
}
TRUST_ARTIFACTS = frozenset({"trust.widening", "trust.revocation", "trust.rotation"})
ON_TRUST_STREAM = frozenset({"trust.revocation", "trust.rotation"})     # R1, O1: they travel on `@trust`

TRUST_BOUND = 16384                                # E6: every kind takes the largest revocation list R7 allows
MESH_TABLE_MAX = 640                               # E6: TBL_MAX in prismpath-hw/mesh/main/ppt_mesh.c

TARGETS: Dict[str, Target] = {
    "host": Target(needs=frozenset({"policy.ppt"}), decides=False, when_declared=frozenset({"policy.spiral"}),
                   compares=frozenset({"policy.ppt"})),
    "agent": Target(needs=frozenset({"policy.core", "egress.hosts"}), decides=True,
                    when_declared=frozenset({"agent.zones", "sandbox.profile"})),
    "gateway": Target(needs=frozenset({"policy.core", "gateway.routes"}), decides=True),
    "xdp": Target(needs=frozenset({"policy.core", "net.dests", "net.edge"}), decides=True),
    "mesh": Target(needs=frozenset({"policy.ppt"}), decides=False, expiry_hold=True, body_bound=MESH_TABLE_MAX,
                   checks={"policy.ppt": check_mesh_table}, reads_meta=False, compares=frozenset({"policy.ppt"})),
}


def _check_row(name: str, target: Target) -> None:
    """The invariants every row holds: a kind of the closed list, artifacts it uses that are not trust kinds,
    trust kinds it applies that are, and a check for every artifact it may verify."""
    if name not in TARGET_KINDS:
        raise ValueError(f"{name!r} is not a target kind of this format")
    if target.trust_bound != TRUST_BOUND:
        raise ValueError(f"the {name} row's trust bound is {TRUST_BOUND} bytes, as every kind's (E6)")
    if not target.uses <= set(ARTIFACTS) - TRUST_ARTIFACTS or not target.applies <= TRUST_ARTIFACTS:
        raise ValueError(f"the {name} row names an artifact or a trust kind that is not one")
    if any(target.check_for(artifact) is None for artifact in target.uses | target.applies):
        raise ValueError(f"the {name} row uses an artifact with no check")


def register_target(name: str, target: Target) -> None:
    """Add the row of a target kind whose checks live outside this package, as the cFS app's table layout does.
    The name must be on the closed list, and a kind is registered once with one row."""
    _check_row(name, target)
    existing = TARGETS.get(name)
    if existing is not None and existing != target:
        raise ValueError(f"the {name} kind is registered with another row")
    TARGETS[name] = target


for _name, _target in TARGETS.items():
    _check_row(_name, _target)
assert TRUST_ARTIFACTS <= set(ARTIFACTS) and ON_TRUST_STREAM <= TRUST_ARTIFACTS
assert all(member in FORMS for artifact in ARTIFACTS.values()
           for member in artifact.meta_required | artifact.meta_optional)
assert all(artifact.role in ROLES for artifact in ARTIFACTS.values())
