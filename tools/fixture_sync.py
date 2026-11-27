# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Each crate's tests/fixtures corpora are byte identical copies of the product corpora.

The product corpora under prismpath/portable/conformance and prismpath/telemetry/conformance are the
authority. A crate carries copies so a packaged crate tests itself with no Python tree beside it, and
this check is what keeps a copy from drifting. It never writes; a mismatch is fixed by copying the
product file by hand in a reviewed change.

    python -m tools.fixture_sync          # exit 1 on any mismatch or missing copy
    python -m tools.fixture_sync --list   # print the mapping
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from tools import tree

REPO_ROOT = tree.REPO_ROOT
KERNEL_CORPUS = "prismpath/portable/conformance"
WIRE_CORPUS = "prismpath/telemetry/conformance"
COPIES = {
    "prismpath-rs/tests/fixtures": (KERNEL_CORPUS, ["canon2", "capability", "causes", "connector", "context", "contract", "crypto_agility",
                                                    "crypto_migration", "durable", "field_definitions", "flows", "level_m", "locked_flows", "merkle_consistency", "merkle_stream", "parse_limits",
                                                    "predicates", "reach", "rules_source"]),
    "prismpath-hotswap-rs/tests/fixtures": (KERNEL_CORPUS, ["distribution", "host_trace", "hotswap", "install_larger", "receipts"]),
    "prismpath-telemetry-rs/tests/fixtures": (WIRE_CORPUS, ["boundary", "concentrator", "decisions", "defined_wire", "inputs",
                                                            "policy_forms", "receipt_stream", "receipts", "refresh", "replay", "spiral"]),
}
# A copy a crate reads from the other corpus: the wire crate's defined fields tests replay the kernel's
# field definitions corpus, the same file the kernel crate copies.
CROSS_COPIES = [("prismpath-telemetry-rs/tests/fixtures/field_definitions.json", f"{KERNEL_CORPUS}/field_definitions.json")]


def pairs() -> list[tuple[str, str]]:
    """(crate copy, product authority) for every copy."""
    out = []
    for crate_dir, (corpus, names) in COPIES.items():
        for name in names:
            out.append((f"{crate_dir}/{name}.json", f"{corpus}/{name}.json"))
    return out + CROSS_COPIES


def check(repo_root: Path = REPO_ROOT) -> list[str]:
    problems = []
    for copy, authority in pairs():
        copy_path, authority_path = repo_root / copy, repo_root / authority
        if not authority_path.exists():
            problems.append(f"{authority}: the product corpus is missing")
        elif not copy_path.exists():
            problems.append(f"{copy}: the crate copy is missing")
        elif copy_path.read_bytes() != authority_path.read_bytes():
            problems.append(f"{copy}: differs from {authority}")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--repo", default=str(REPO_ROOT))
    args = parser.parse_args(argv)
    if args.list:
        for copy, authority in pairs():
            print(f"{copy}  <=  {authority}")
        return 0
    problems = check(Path(args.repo).resolve())
    for problem in problems:
        print(f"fixture sync: {problem}")
    if problems:
        return 1
    print(f"fixture sync ok: {len(pairs())} crate copies byte identical to the product corpora")
    return 0


if __name__ == "__main__":
    sys.exit(main())
