# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Dev builds and escape hatches (spec-policy-distribution.md, section 16).

Whether this is a dev build is a fact of the installed package (D2): the module `prismpath._dev_build` is in
the repository and is left out of the wheel and of the product export (D4), so an installed product is a
production build whatever its environment or configuration says. `hatch` is the one gate every escape
hatch passes. In a production build it refuses with `dist:hatch-refused`, and the caller then runs the
check the hatch would have skipped (D1). In a dev build it lets the hatch through, and every audit event it
writes carries `dev_build` true (D3).
"""
from __future__ import annotations

import importlib.util
from typing import Any, Optional

from prismpath.distribution.kinds import Refused

DEV_BUILD_MODULE = "prismpath._dev_build"
HATCH_REFUSED = "dist:hatch-refused"


class HatchRefused(Refused):
    """An escape hatch asked for in a production build. Its cause is `dist:hatch-refused`."""

    def __init__(self, name: str):
        super().__init__(HATCH_REFUSED, f"the escape hatch {name} works only in a dev build")
        self.hatch = name


def is_dev_build() -> bool:
    """True only when the built package carries `prismpath._dev_build` (D2)."""
    return importlib.util.find_spec(DEV_BUILD_MODULE) is not None


def hatch(name: str, audit: Optional[Any] = None) -> None:
    """Pass the escape hatch `name`, or raise `HatchRefused` in a production build. Either way `audit`
    (an `AuditLog`, when given) records one `hatch` event with the hatch, the result and `dev_build`."""
    dev_build = is_dev_build()
    if audit is not None:
        event = {"hatch": name, "dev_build": dev_build, "result": "allowed" if dev_build else "refused"}
        if not dev_build:
            event["cause"] = HATCH_REFUSED
        audit.append("distribution", "hatch", event)
    if not dev_build:
        raise HatchRefused(name)
