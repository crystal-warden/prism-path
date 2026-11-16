# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The boundary check: nothing here points at something absent, and a built package carries only the tree.

Repository mode (the default) checks the tree:

1. Every relative markdown link resolves to a file in this tree.
2. Every link into the research repository that names a file pins a commit: a `blob/<40 hex>/` or
   `tree/<40 hex>/` path, never `main`, so a claim and the file it cites stay matched. A link to the
   repository home carries no path and is fine.
3. The files a shipped feature needs are tracked: the corpora, the compiler references, the reference
   hashes, the Mission Control static assets, the compiler and the canary verifier.

What the tree may contain is decided where it is made, by the manifest in the research repository's
tools/export_clean.py, and `python -m tools.provenance check --research PATH` proves the tree is exactly
what that manifest makes at the commit PROVENANCE.md names. Nothing here re-decides it.

Package mode checks a built artifact: `--wheel FILE` or `--sdist FILE`. Every member must be a file of
this tree or something the build generates (metadata, the data directory, the egg info), so a held file
cannot ride in on a package data glob, and the members a shipped feature needs must be present.

    python -m tools.check_boundary
    python -m tools.check_boundary --wheel dist/prismpath-0.1.0-py3-none-any.whl
    python -m tools.check_boundary --sdist dist/prismpath-0.1.0.tar.gz
"""
from __future__ import annotations

import argparse
import posixpath
import re
import sys
import tarfile
import zipfile
from pathlib import Path

from tools import tree

REPO_ROOT = tree.REPO_ROOT
RESEARCH_LINK = re.compile(r"https://github\.com/crystal-warden/prism-path/(blob|tree|raw)/([^/\s)]+)/")
MARKDOWN_LINK = re.compile(r"\]\(([^)]+)\)")
REQUIRED_IN_WHEEL = [
    "prismpath/kernel/ppt_compile.py",
    "prismpath/telemetry/canary_verify.py",
    "prismpath/portable/conformance/flows.json",
    "prismpath/portable/conformance/predicates.json",
    "prismpath/telemetry/conformance/decisions.json",
    "prismpath/telemetry/conformance/inputs.json",
    "prismpath/tests/fixtures/compiler/SHA256SUMS",
    "prismpath/tests/fixtures/compiler/anchored/incident_severity.ppt",
    "prismpath/tests/fixtures/reference_hashes.json",
    "prismpath/tests/fixtures/kappa_dataset.jsonl",
    "prismpath/tests/fixtures/alert_router.md",
    "prismpath/mission_control/static/index.html",
    "prismpath/mission_control/static/js/main.mjs",
    "prismpath/mission_control/static/js/markup.mjs",
    "prismpath/mission_control/static/style.css",
    "prismpath/mission_control/static/vendor/cytoscape.min.js",
    "prismpath/mission_control/static/vendor/cytoscape.LICENSE",
    "prismpath/gallery/pr_review/pr_review.md",
    "prismpath/policies/p1_lockfile.json",
]
REQUIRED_IN_SDIST = REQUIRED_IN_WHEEL + [
    "SPEC.md", "PROTOCOL.md", "COMPATIBILITY.md", "DIVERGENCES.md", "PROVENANCE.md", "SHA256SUMS",
    "prismpath/tests/test_causes.py", "prismpath/telemetry/tests/test_canary_verify.py",
]


def check_links(repo_root: Path, paths: list[str]) -> list[str]:
    problems = []
    for repo_path in paths:
        if not repo_path.endswith(".md"):
            continue
        text = (repo_root / repo_path).read_text(encoding="utf-8", errors="replace")
        base = posixpath.dirname(repo_path)
        for match in MARKDOWN_LINK.finditer(text):
            target = match.group(1).strip()
            if target.startswith(("http://", "https://", "mailto:", "#", "//")):
                research = RESEARCH_LINK.match(target)
                if research and not re.fullmatch(r"[0-9a-f]{40}", research.group(2)):
                    problems.append(f"{repo_path}: research link not pinned to a commit: {target}")
                continue
            core = target.split("#", 1)[0].split("?", 1)[0]
            if not core:
                continue
            resolved = posixpath.normpath(posixpath.join(base, core))
            if not (repo_root / resolved).exists():
                problems.append(f"{repo_path}: dangling link {target}")
    return problems


def check_repository(repo_root: Path) -> list[str]:
    paths = tree.tracked_paths(repo_root)
    present = set(paths)
    problems = check_links(repo_root, paths)
    problems += [f"required file missing: {path}" for path in REQUIRED_IN_SDIST if path not in present]
    return problems


def archive_members(artifact: Path) -> list[str]:
    if artifact.suffix == ".whl":
        with zipfile.ZipFile(artifact) as archive:
            return [name for name in archive.namelist() if not name.endswith("/")]
    with tarfile.open(artifact) as archive:
        members = [member.name for member in archive.getmembers() if member.isfile()]
    # an sdist nests everything under <name>-<version>/
    return [name.split("/", 1)[1] for name in members if "/" in name]


GENERATED_MEMBERS = re.compile(r"(^|/)([^/]+\.dist-info|[^/]+\.data|[^/]+\.egg-info)/|^(PKG-INFO|setup\.cfg)$")


def check_package(repo_root: Path, artifact: Path, required: list[str]) -> list[str]:
    members = archive_members(artifact)
    present = set(members)
    in_tree = set(tree.tracked_paths(repo_root))
    problems = []
    for member in members:
        if member not in in_tree and not GENERATED_MEMBERS.search(member):
            problems.append(f"{artifact.name}: carries {member}, which is not a file of this tree")
    for path in required:
        if path not in present:
            problems.append(f"{artifact.name}: required member missing: {path}")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", default=str(REPO_ROOT))
    parser.add_argument("--wheel", type=Path)
    parser.add_argument("--sdist", type=Path)
    args = parser.parse_args(argv)
    repo_root = Path(args.repo).resolve()
    if args.wheel or args.sdist:
        problems = []
        if args.wheel:
            problems += check_package(repo_root, args.wheel, REQUIRED_IN_WHEEL)
        if args.sdist:
            problems += check_package(repo_root, args.sdist, REQUIRED_IN_SDIST)
        label = "package boundary"
    else:
        problems = check_repository(repo_root)
        label = "repository boundary"
    for problem in problems:
        print(f"{label}: {problem}")
    if problems:
        print(f"{label}: {len(problems)} problem(s)")
        return 1
    print(f"{label} ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
