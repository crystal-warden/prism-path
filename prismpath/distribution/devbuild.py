# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Dev builds and escape hatches (spec-policy-distribution.md, section 16).

Whether this is a dev build is a fact of where the code runs from (D2). A dev build is a source checkout
whose root, the parent of the `prismpath` package directory, holds both `pyproject.toml` and the marker
file `.prismpath-dev-build`. The marker is outside the package, so no wheel and no sdist can carry it. It is
not tracked, `.gitignore` lists it, and only `python tools/dev_build.py on` writes it. An installed package
has no `pyproject.toml` beside it and is never a dev build.

`hatch` is the one gate every escape hatch passes. In a production build it refuses with
`dist:hatch-refused`, and the caller then runs the check the hatch would have skipped (D1). In a dev build
it lets the hatch through, and every audit event it writes carries `dev_build` true (D3).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from prismpath.distribution.kinds import Refused

MARKER = ".prismpath-dev-build"
HATCH_REFUSED = "dist:hatch-refused"
PACKAGE_DIR = Path(__file__).resolve().parent.parent


class HatchRefused(Refused):
    """An escape hatch asked for in a production build. Its cause is `dist:hatch-refused`."""

    def __init__(self, name: str):
        super().__init__(HATCH_REFUSED, f"the escape hatch {name} works only in a dev build")
        self.hatch = name


def is_dev_build(package_dir: Optional[Path] = None) -> bool:
    """True only when the parent of the `prismpath` package directory (this one unless `package_dir` is
    given) holds both `pyproject.toml` and the marker (D2)."""
    root = Path(package_dir or PACKAGE_DIR).parent
    return (root / MARKER).is_file() and (root / "pyproject.toml").is_file()


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
