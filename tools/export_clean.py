#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Generate the lean product mirror of this monorepo.

This repo (crystal-warden/prism-path) is the single source of truth: the full
research, the evidence ledger, the hardware sprints, the OpenTimestamps anchors.
The public product mirror (crystal-warden/prismpath) is a GENERATED subset of it
-- the runnable control plane and its tooling, with the research demoted to a
link. You never hand-edit the mirror; you run this and it is rebuilt, so the two
can never drift and the provenance chain never fragments.

    python tools/export_clean.py --out ../prismpath-clean

By default this only writes the tree and prints a summary. It never inits a git
repo, never commits, never pushes -- creating and publishing the public repo is
a human step. `--commit` will make a local commit in the target if it is already
a git repo; there is deliberately no --push.

What the mirror contains, and what it points elsewhere for, is the MANIFEST
below -- it is meant to be read and adjusted. The one judgement call worth your
eye is HARDWARE / EBPF: by default the down-to-silicon proofs live in the
research repo (the mirror is "install and run"), and the README's portability
pillar links to them there. Flip them into INCLUDE_PREFIXES if you want the
mirror to carry the substrates too.
"""
import argparse
import posixpath
import re
import shutil
import subprocess
import sys
from pathlib import Path

# ------------------------------------------------------------------ manifest
# A tracked file lands in the mirror if it matches an INCLUDE rule and no
# EXCLUDE rule. Order: excludes win.
INCLUDE_PREFIXES = [
    "prismpath/",              # the Python kernel + CLI + portable JS + examples + tests
    "prismpath-rs/",           # the four published crates
    "prismpath-telemetry-rs/",
    "prismpath-hotswap-rs/",
    "prismpath-preflight/",
    "prismpath-go/",           # the Go conformance port
    "adapters/",               # telemetry + fusion adapters (the Vector-facing tools)
    "integrations/",           # the Vector integration
    "tools/",                  # lint / gate tooling
    "docs/guides/",            # product docs (the tour, code nodes)
    "docs/design/",            # design specs (incl. the secure-hotswap prior-art note)
    ".github/ISSUE_TEMPLATE/",
]
INCLUDE_FILES = [
    "LICENSE", "NOTICE", "CHANGELOG.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md",
    "SECURITY.md", "CITATION.cff", "GETTING_STARTED.md", "ROADMAP.md",
    "SPEC.md", "PROTOCOL.md", "action.yml", "MANIFEST.in", "pyproject.toml",
    "Cargo.toml", "Cargo.lock", ".gitignore", ".pre-commit-hooks.yaml",
    "docs/README.md", "docs/decoder-ring.md", "docs/objections.md",
    ".github/PULL_REQUEST_TEMPLATE.md", ".github/ISSUE_TEMPLATE/config.yml",
    # README.md is generated below (banner + link rewrite), not copied verbatim.
]
# Excludes win over includes. These are the research/evidence/hardware/scratch.
EXCLUDE_PREFIXES = [
    "docs/research/",          # papers, evidence ledger, OTS anchors
    "research/",               # embedder scouts, route-eval experiments
    "prismpath-hw/",           # hardware sprints  (flip to INCLUDE to ship substrates)
    "prismpath-ebpf/",         # kernel decode plane  (flip to INCLUDE to ship substrates)
    ".github/workflows/",      # CI is regenerated clean below
]
EXCLUDE_SUFFIXES = [".deferrals"]           # empty top-level scratch files
EXCLUDE_EXACT = {"docs_health_report.md", "tools/arch_scorecard.json"}  # generated reports

RESEARCH_REPO = "https://github.com/crystal-warden/prism-path/blob/main/"
MIRROR_BANNER = (
    "> **This is the lean product mirror of "
    "[crystal-warden/prism-path](https://github.com/crystal-warden/prism-path).** "
    "It is generated: the runnable control plane and its tooling, nothing more. "
    "The research, the FQ paper, the evidence ledger timestamped to Bitcoin, and "
    "the hardware and kernel substrates all live in that repo.\n\n"
)


ROOT = Path(__file__).resolve().parent.parent    # the source repo, wherever this is run from


def tracked_files():
    out = subprocess.check_output(["git", "ls-files"], text=True, cwd=ROOT)
    return [l for l in out.splitlines() if l]


def is_included(path):
    if path in EXCLUDE_EXACT:
        return False
    if any(path.startswith(p) for p in EXCLUDE_PREFIXES):
        return False
    if any(path.endswith(s) for s in EXCLUDE_SUFFIXES):
        return False
    if path in INCLUDE_FILES:
        return True
    return any(path.startswith(p) for p in INCLUDE_PREFIXES)


# ------------------------------------------------------------ link rewriting
LINK = re.compile(r"(\]\()([^)]+)(\))")


def classify_target(raw, md_path, included, tracked):
    """keep | rewrite | leave for a markdown link target relative to md_path."""
    t = raw.strip()
    if t.startswith(("http://", "https://", "mailto:", "#", "//", "www.")):
        return "leave", None
    core = t.split("#", 1)[0].split("?", 1)[0]
    anchor = t[len(core):]
    if not core:
        return "leave", None
    base = posixpath.dirname(md_path)
    rp = posixpath.normpath(posixpath.join(base, core))
    if rp.startswith(".."):
        return "leave", None
    if rp in included:
        return "keep", None
    if rp in tracked:                                   # excluded-but-real -> research repo
        return "rewrite", RESEARCH_REPO + rp + anchor
    # directory link: does it name a real subtree?
    inc_dir = any(f == rp or f.startswith(rp + "/") for f in included)
    trk_dir = any(f == rp or f.startswith(rp + "/") for f in tracked)
    if inc_dir:
        return "keep", None
    if trk_dir:
        return "rewrite", RESEARCH_REPO + rp + anchor
    return "leave", None                                # not tracked anywhere: don't invent a URL


def rewrite_markdown(text, md_path, included, tracked, stats):
    def repl(m):
        kind, new = classify_target(m.group(2), md_path, included, tracked)
        if kind == "rewrite":
            stats.append((md_path, m.group(2), new))
            return m.group(1) + new + m.group(3)
        return m.group(0)
    return LINK.sub(repl, text)


# --------------------------------------------------------------- clean CI
CLEAN_CI = """\
name: ci

on:
  push:
    branches: [main]
  pull_request:
  workflow_dispatch:

# Generated by tools/export_clean.py in crystal-warden/prism-path. Do not hand-edit
# here; edit the generator in the source repo and re-export.

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        python-version: ["3.10", "3.11", "3.12"]
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-python@v7
        with:
          python-version: ${{ matrix.python-version }}
      - name: Install
        run: pip install numpy pytest cryptography
      - name: Unit tests
        run: python -m pytest prismpath/tests -q
      - name: Fuzz the predicate sandbox
        run: python -m prismpath.fuzz_predicates -n 20000

  conformance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-python@v7
        with:
          python-version: "3.12"
      - uses: actions/setup-node@v7
        with:
          node-version: "22"
      - name: Install
        run: pip install numpy pytest
      - name: Port unit tests
        run: node --test prismpath/portable/prismpath.test.mjs
      - name: Editor grammar tests
        run: node --test prismpath/editor/vscode/test/grammar.test.mjs
      - name: Frozen conformance vectors (port side)
        run: node prismpath/portable/run_vectors.mjs prismpath/portable/conformance
      - name: Crypto-agility proofs (JS twin)
        run: node prismpath/portable/run_crypto_agility.mjs
      - name: Frozen conformance vectors (reference-drift side)
        run: python -m pytest prismpath/tests/test_conformance_vectors.py -q

  crates:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: dtolnay/rust-toolchain@stable
      - name: Build + test the workspace
        run: cargo test --workspace

  go:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-go@v5
        with:
          go-version: "1.22"
      - name: Go conformance
        run: cd prismpath-go && go test ./...
"""


def strip_research_datafiles(text):
    """Drop the pyproject data-files line that ships docs/research (absent in the mirror)."""
    return "\n".join(l for l in text.splitlines()
                     if "docs/research" not in l) + ("\n" if text.endswith("\n") else "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="../prismpath-clean",
                    help="target directory for the mirror (default ../prismpath-clean)")
    ap.add_argument("--commit", action="store_true",
                    help="make a local commit if --out is already a git repo (never pushes)")
    args = ap.parse_args()

    root = ROOT
    out = Path(args.out).resolve()
    if out == root:
        sys.exit("refusing to export onto the source repo")

    tracked = set(tracked_files())
    included = sorted(f for f in tracked if is_included(f))
    # README.md is generated (not copied from INCLUDE_FILES) but DOES exist in the
    # mirror, so links to it must classify as "keep", not redirect to the research repo.
    included_set = set(included) | {"README.md"}

    # wipe only the tracked-content areas of the target, preserve its .git
    if out.exists():
        for child in out.iterdir():
            if child.name == ".git":
                continue
            shutil.rmtree(child) if child.is_dir() else child.unlink()
    out.mkdir(parents=True, exist_ok=True)

    rewrites = []
    for rel in included:
        src = root / rel
        dst = out / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if rel.endswith(".md"):
            text = src.read_text()
            dst.write_text(rewrite_markdown(text, rel, included_set, tracked, rewrites))
        elif rel == "pyproject.toml":
            dst.write_text(strip_research_datafiles(src.read_text()))
        else:
            shutil.copy2(src, dst)

    # generated README: mirror banner + link rewrite of the source README
    readme = rewrite_markdown((root / "README.md").read_text(),
                              "README.md", included_set, tracked, rewrites)
    lines = readme.split("\n")
    i = 1 if lines and lines[0].startswith("# ") else 0            # banner after the H1
    (out / "README.md").write_text("\n".join(lines[:i] + ["", MIRROR_BANNER.rstrip()] + lines[i:]))

    # generated clean CI
    (out / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
    (out / ".github" / "workflows" / "ci.yml").write_text(CLEAN_CI)

    n_files = len(included) + 2   # + README + ci.yml
    total_kb = sum((out / f).stat().st_size for f in included) // 1024
    print(f"mirror written to {out}")
    print(f"  files:        {n_files}  (~{total_kb} KB of tracked content)")
    print(f"  excluded:     {len(tracked) - len(included)} tracked files held back")
    print(f"  link rewrites {len(rewrites)} -> research repo:")
    for md, old, new in rewrites:
        print(f"    {md}: {old}  ->  {new}")

    if args.commit and (out / ".git").exists():
        subprocess.run(["git", "-C", str(out), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(out), "commit", "-q", "-m",
                        "export: regenerate product mirror from prism-path"], check=True)
        print("  committed locally (not pushed)")


if __name__ == "__main__":
    main()
