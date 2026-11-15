# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""PROVENANCE.md and SHA256SUMS: what this tree was made from, and whether it still is that.

The product repository is generated from the research repository by `tools/export_clean.py`, which
writes both records. PROVENANCE.md names the research commit and tree the export was made from.
SHA256SUMS lists the sha256 of every other file in the tree, in the format `sha256sum -c` reads.

    python -m tools.provenance check                       # every file is listed and hashes to its line
    python -m tools.provenance check --research PATH       # and the tree is the export of the research
                                                           # checkout at PATH, which must be at the commit
                                                           # PROVENANCE.md names

The second form is the one that says the tree is what research makes at that commit: it runs the
checkout's own exporter into a temporary directory and compares every file, byte for byte and by
executable bit, in both directions. The hashes alone say only that the tree was not edited since the
export. Neither is a signature and neither proves who produced the tree.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from tools import tree

REPO_ROOT = tree.REPO_ROOT
SUMS = "SHA256SUMS"
COMMIT_LINE = re.compile(r"^Research commit: `([0-9a-f]{40})`$", re.MULTILINE)


def sha256_lines(files: dict[str, bytes]) -> str:
    """The SHA256SUMS text for {path: bytes}, sorted by path."""
    return "".join(f"{hashlib.sha256(data).hexdigest()}  {path}\n" for path, data in sorted(files.items()))


def parse_sums(text: str) -> dict[str, str]:
    sums = {}
    for number, line in enumerate(text.splitlines(), 1):
        digest, separator, path = line.partition("  ")
        if not separator or not re.fullmatch(r"[0-9a-f]{64}", digest) or not path:
            raise ValueError(f"{SUMS} line {number} is not `<sha256>  <path>`")
        if path in sums:
            raise ValueError(f"{SUMS} lists {path} twice")
        sums[path] = digest
    return sums


def recorded_commit(repo_root: Path) -> str | None:
    path = repo_root / "PROVENANCE.md"
    found = COMMIT_LINE.search(path.read_text(encoding="utf-8")) if path.exists() else None
    return found.group(1) if found else None


def check_hashes(repo_root: Path) -> list[str]:
    if not (repo_root / SUMS).exists():
        return [f"{SUMS} is missing"]
    try:
        sums = parse_sums((repo_root / SUMS).read_text(encoding="utf-8"))
    except ValueError as error:
        return [str(error)]
    paths = set(tree.tracked_paths(repo_root)) - {SUMS}
    problems = [f"{path}: in the tree but not in {SUMS}" for path in sorted(paths - set(sums))]
    problems += [f"{path}: in {SUMS} but not in the tree" for path in sorted(set(sums) - paths)]
    for path in sorted(paths & set(sums)):
        if hashlib.sha256((repo_root / path).read_bytes()).hexdigest() != sums[path]:
            problems.append(f"{path}: differs from {SUMS}")
    if recorded_commit(repo_root) is None:
        problems.append("PROVENANCE.md names no research commit")
    return problems


def executable_paths(root: Path) -> set[str]:
    return {path for path in tree.tracked_paths(root) if (root / path).stat().st_mode & 0o111}


def check_against_research(repo_root: Path, research: Path) -> list[str]:
    commit = recorded_commit(repo_root)
    head = subprocess.run(["git", "-C", str(research), "rev-parse", "HEAD"], capture_output=True, text=True)
    if head.returncode != 0:
        return [f"{research} is not a git checkout"]
    if head.stdout.strip() != commit:
        return [f"{research} is at {head.stdout.strip()[:12]}, and PROVENANCE.md names {str(commit)[:12]}: check out that commit"]
    with tempfile.TemporaryDirectory(prefix="prismpath-export-") as scratch:
        exported = subprocess.run([sys.executable, str(research / "tools" / "export_clean.py"), "--out", scratch],
                                  capture_output=True, text=True)
        if exported.returncode != 0:
            return [f"the research exporter failed: {(exported.stderr or exported.stdout).strip()[-400:]}"]
        scratch_root = Path(scratch)
        mine, theirs = set(tree.tracked_paths(repo_root)), set(tree.tracked_paths(scratch_root))
        problems = [f"{path}: in this tree, not in the export of research at {commit[:12]}" for path in sorted(mine - theirs)]
        problems += [f"{path}: in the export of research at {commit[:12]}, not in this tree" for path in sorted(theirs - mine)]
        for path in sorted(mine & theirs):
            if (repo_root / path).read_bytes() != (scratch_root / path).read_bytes():
                problems.append(f"{path}: differs from the export of research at {commit[:12]}")
        problems += [f"{path}: executable bit differs from the export" for path in
                     sorted(executable_paths(repo_root) ^ executable_paths(scratch_root))]
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["check"])
    parser.add_argument("--repo", default=str(REPO_ROOT), help="the tree to check (default: this one)")
    parser.add_argument("--research", type=Path, help="a research checkout at the commit PROVENANCE.md names")
    args = parser.parse_args(argv)
    repo_root = Path(args.repo).resolve()
    problems = check_hashes(repo_root)
    if args.research and not problems:
        problems += check_against_research(repo_root, args.research.resolve())
    for problem in problems:
        print(f"provenance: {problem}")
    if problems:
        return 1
    files = len(tree.tracked_paths(repo_root))
    print(f"provenance ok: {files} files, research commit {recorded_commit(repo_root)}"
          + (", identical to its export" if args.research else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
