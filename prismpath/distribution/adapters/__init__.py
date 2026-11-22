# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The adapter interface between the one enforcement point machine (`prismpath.distribution.pep`) and the
runtime a target kind protects.

An adapter has four calls. `kind` names the target. `check(artifact, body, staged)` is the target's own
part of V11, run at commit over the whole staged release, since one artifact may name another (C2).
`compare(active, staged)` answers whether the staged release allows more (W1), `LARGER`, `NOT_LARGER` or
`CANNOT_DECIDE`. `activate(release)` makes the runtime use a committed release and `deactivate()` makes
it refuse. An adapter never verifies a signature, reads a clock or touches a floor. Those are the
machine's.

Beside the calls an adapter tells the machine what it needs to build its view: `home`, the directory the
runtime keeps its files in (K2), `qualification`, the qualification envelope a `policy.ppt` is admitted
under, and `body_bound`, its bound on a body (E6).
"""
from __future__ import annotations

from typing import Any, Mapping, Optional, Tuple

LARGER, NOT_LARGER, CANNOT_DECIDE = "larger", "not-larger", "cannot-decide"


class Adapter:
    """The base every adapter extends. A subclass sets `kind` and overrides `activate` and `deactivate`."""
    kind: str = ""
    home: Optional[str] = None
    qualification: Optional[dict] = None
    body_bound: int = 16777215

    def check(self, artifact: str, body: bytes, staged: Mapping[str, Tuple[Any, bytes]]) -> Optional[str]:
        """The target's own check of one staged artifact against the rest of the staged release, which maps
        each artifact to its (envelope, body). None when it holds, else the cause."""
        return None

    def compare(self, active: Any, staged: Any) -> str:
        """W1: whether `staged` allows more than `active`. A target that cannot decide answers so (W2)."""
        return CANNOT_DECIDE

    def activate(self, release: Any) -> None:
        raise NotImplementedError

    def deactivate(self, cause: str) -> None:
        raise NotImplementedError
