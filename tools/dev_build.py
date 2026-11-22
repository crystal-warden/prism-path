#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Turn this research checkout into a dev build, or back (docs/design/spec-policy-distribution.md, D2).

    python tools/dev_build.py on       write .prismpath-dev-build beside pyproject.toml
    python tools/dev_build.py off      remove it
    python tools/dev_build.py status   say which build this checkout is

A dev build is the only build in which an escape hatch works (`prismpath.distribution.devbuild`). The
marker is outside the package, ignored by git and written only here, so no package built from the
checkout carries it.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from prismpath.distribution import devbuild  # noqa: E402

MARKER_PATH = ROOT / devbuild.MARKER


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("action", choices=("on", "off", "status"))
    args = parser.parse_args(argv)
    if args.action == "on":
        MARKER_PATH.write_text("this checkout is a dev build: escape hatches work here and nowhere else\n",
                               encoding="utf-8")
    elif args.action == "off":
        MARKER_PATH.unlink(missing_ok=True)
    print("dev build" if devbuild.is_dev_build() else "production build")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
