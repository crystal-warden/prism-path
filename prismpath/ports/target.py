# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The target kind port and the target runtime port of policy distribution.

`TargetKind` is what one kind of enforcement point registers with the kind registry
(`prismpath.distribution.kinds.register`): its row of the kind table, the readers of the artifacts only it uses,
their widening comparators, the reading domain its `policy.core` is checked against, the policy object it decides
with, the domain document and the categories it was built with (CL4, P4), and the checks `prismpath policy compile
--target` runs for it. A kind registers when its module is imported, and a surface imports every built in kind
once (`prismpath.kinds_builtin`). A kind that was never registered has no row, so no enforcement point of it can
be built and its artifacts do not read: the registry fails closed.

A kind that can be sealed from a signed policy manifest (`dist seal --manifest`, SPEC.md section 10) also registers
`derive`, which makes the bodies of its release from what the manifest check verified, `manifest_inputs`, the side
files of the manifest it reads and the artifact each one is, and `manifest_values`, the value keys it carries and the
one value it carries each at. A kind with no `derive` is not sealed from a manifest, and a manifest that names it
does not hold.

`Adapter` is the target runtime port, the interface between the one enforcement point machine
(`prismpath.distribution.pep`) and the runtime a target kind protects.

`kind` names the target. `check(artifact, body, staged)` is the target's own part of V11, run at commit over
the whole staged release, since one artifact may name another (C2). Whether a staged release allows more
(W1) is not an adapter's: a kind that can decide compares with the comparators of
`prismpath.distribution.widening`, one per artifact, which answer `LARGER`, `NOT_LARGER` or `CANNOT_DECIDE`.
`activate(release)` makes the runtime use a committed release, `deactivate()` makes
it refuse, and `withdraw_to(fallback, cause)` makes it run the fallback set in place of a release (FB1). An
adapter never verifies a signature, reads a clock or touches a floor. Those are the machine's.

Beside the calls an adapter tells the machine what it needs to build its view: `home`, the directory the
runtime keeps its files in (K2), `qualification`, the qualification envelope a `policy.ppt` is admitted
under, `body_bound`, its bound on a body (E6), and `floor_layout`, the layout document (AF10) a table kind was built
with, without which it takes no action floor.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, FrozenSet, List, Mapping, Optional, Sequence, Tuple

from prismpath.kernel.domain import ReadingDomain

LARGER, NOT_LARGER, CANNOT_DECIDE = "larger", "not-larger", "cannot-decide"

Comparator = Callable[[Any, Any], str]            # (active body, staged body) -> LARGER, NOT_LARGER, CANNOT_DECIDE
Reader = Callable[[bytes], Any]                    # a body to its reading, or `Refused` with the cause
CompileChecks = Callable[[bytes, Mapping[str, Sequence[str]]], List[Tuple[Any, str]]]
Derive = Callable[[Any], Mapping[str, bytes]]      # a verified `policy_manifest.Release` -> {artifact: body}


@dataclass(frozen=True)
class TargetKind:
    """One target kind as it registers itself. `name` is on the closed list of the format (E8) and `row` is its
    `kinds.Target`. `readers` and `comparators` are the kind's own, by artifact. `domain` answers the reading domain
    its `policy.core` is checked against, and None is the agent kind's, which every kind is checked against until each
    has its own (owner answer Q4). `policy` builds the policy object the kind decides with from an image, and None is
    the kernel's policy bound to `domain`. `domain_document` answers the domain the kind was built with as a document
    (P4) and `categories` its category fields (CL4), None for the defaults the install part gives. `compile_checks`
    answers the findings of `prismpath policy compile --target` for an image and its listed values. `derive` answers the
    bodies of the kind's release from a verified `policy_manifest.Release`, by artifact, or raises `kinds.Refused`;
    `manifest_inputs` maps each side file key of the manifest it reads to the artifact the file's bytes are, and
    `manifest_values` each value key it carries to the value it carries it at (a key at another value is not carried,
    and the sealing tool refuses it rather than seal a release that drops it)."""
    name: str
    row: Any
    readers: Mapping[str, Reader] = field(default_factory=dict)
    comparators: Mapping[str, Comparator] = field(default_factory=dict)
    domain: Optional[Callable[[], ReadingDomain]] = None
    policy: Optional[Callable[[bytes], Any]] = None
    domain_document: Optional[Callable[[], Any]] = None
    categories: Optional[Callable[[], FrozenSet[str]]] = None
    compile_checks: Optional[CompileChecks] = None
    derive: Optional[Derive] = None
    manifest_inputs: Mapping[str, str] = field(default_factory=dict)
    manifest_values: Mapping[str, Any] = field(default_factory=dict)


class Adapter:
    """The base every adapter extends. A subclass sets `kind` and overrides `activate` and `deactivate`."""
    kind: str = ""
    home: Optional[str] = None
    qualification: Optional[dict] = None
    body_bound: int = 16777215
    floor_layout: Optional[bytes] = None

    def check(self, artifact: str, body: bytes, staged: Mapping[str, Tuple[Any, bytes]]) -> Optional[str]:
        """The target's own check of one staged artifact against the rest of the staged release, which maps
        each artifact to its (envelope, body). None when it holds, else the cause."""
        return None

    def activate(self, release: Any) -> None:
        raise NotImplementedError

    def deactivate(self, cause: str) -> None:
        raise NotImplementedError

    def withdraw_to(self, fallback: Any, cause: str) -> None:
        """C10, FB1: withdraw the release and run the PEP's fallback set, given in the shape of a release, in its
        place. A runtime that runs what `activate` gives it runs the fallback set the same way."""
        self.activate(fallback)


TargetRuntime = Adapter                            # the port's name in the plan of the layers
