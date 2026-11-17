#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Generate the product repository's tree from this repository.

This repo (crystal-warden/prism-path) is the only place work lands. The product repository
(crystal-warden/prismpath) is a GENERATED subset of it: the Python engine and command line, the four
Rust crates, the frozen conformance corpora and the tools that check them, with the research, the
evidence ledger, the hardware and kernel substrates and the other language ports left here. The one
rule is

    all work lands in research main; the product repo's main changes only by export.

Nothing in the product repository is edited by hand, so the two cannot drift and there is no second
line to promote into or merge from. Run this on a clean checkout of research main, write the result
over the product repository's working tree, and commit it there:

    python tools/export_clean.py --out ../prismpath-clean

By default this only writes the tree and prints a summary. It never inits a git repo, never commits and
never pushes; creating and publishing the commit in the product repository is a human step. `--commit`
makes a local commit in the target if it is already a git repo; there is deliberately no --push. The
export refuses a working tree with uncommitted changes to tracked files, so a product tree always
names a research commit that exists (`--allow-dirty` is for working on this script).

What the product carries is the MANIFEST below, meant to be read and adjusted. A tracked file lands in
the tree if an include rule matches it and no exclude rule does. These are not copied as they are:

  * `tools/mirror/` is an overlay: each file in it is written into the tree at its path under that
    directory, replacing the research file of the same path. It holds what the product's packaging and
    CI say about a tree that carries less than research does (pyproject.toml, MANIFEST.in, the CI
    workflow, the Dictionary subset, and the product's wording of the docs that
    describe what the product carries: README-like pages, GETTING_STARTED, CONTRIBUTING, the guides).
  * `tools/mirror_readme.md` is the product's README.md, and the page PyPI shows.
  * PROVENANCE.md and SHA256SUMS are generated: the research commit and tree the export was made from,
    and the sha256 of every other file in it.

  * `tools/mirror_publish.yml` is written as `.github/workflows/publish.yml` (PyPI Trusted Publishing).
  * The overlay pyproject.toml takes its `version` from research's pyproject.toml, so the two cannot
    diverge. That one line is the only rewrite.

Otherwise nothing is rewritten on the way: a file in the tree is a research file byte for byte, or an
overlay file byte for byte, or one of the two generated records.
"""
import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

# ------------------------------------------------------------------ manifest
# Order: excludes win over includes.
INCLUDE_PREFIXES = [
    "prismpath/",              # the Python engine, command line, Mission Control, telemetry, the corpora and tests
    "prismpath-rs/",           # the four crates
    "prismpath-telemetry-rs/",
    "prismpath-hotswap-rs/",
    "prismpath-preflight/",
    "tools/",                  # the maintenance, boundary and acceptance tools and their tests
    "docs/guides/",            # product guides
    "docs/design/",            # design specs
    "docs/standards/",         # the cause and regulatory crosswalks and their pinned taxonomies
    ".github/ISSUE_TEMPLATE/",
]
INCLUDE_FILES = [
    "LICENSE", "NOTICE", "CHANGELOG.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "SECURITY.md",
    "CITATION.cff", "GETTING_STARTED.md", "SPEC.md", "PROTOCOL.md", "DIVERGENCES.md", "COMPATIBILITY.md",
    "action.yml", "Cargo.toml", "Cargo.lock", ".gitignore", ".pre-commit-hooks.yaml",
    "docs/README.md", ".github/PULL_REQUEST_TEMPLATE.md",
    # pyproject.toml, MANIFEST.in, docs/DICTIONARY.md and .github/workflows/ci.yml come from tools/mirror/,
    # README.md from tools/mirror_readme.md, PROVENANCE.md and SHA256SUMS are generated.
]
# Research only: held back, and what each holds back is named so the next reader need not guess.
EXCLUDE_PREFIXES = [
    # research areas and the other language ports
    "docs/research/",          # papers, the evidence ledger, protocols
    "research/",               # experiments
    "formal/",                 # the Lean development
    "prismpath-hw/",           # the C target, the fabric, the firmware
    "prismpath-ebpf/",         # the kernel target
    "prismpath-go/",           # the Go kernel
    "prismpath-reflect-bindings/",
    "adapters/",               # the compliance and fusion adapters
    "integrations/",           # Vector and the other integrations, the governed examples
    "prismpath/comparisons/",  # the comparison harness and its results
    "prismpath/benchmark/",
    "prismpath/measurements/",
    "prismpath/evidence/",     # OpenTimestamps anchors over research documents
    "prismpath/telemetry/bench/",
    "prismpath/telemetry/evidence/",
    "prismpath/editor/",       # editor tooling
    "prismpath/deploy/",       # timestamp service wrappers
    "prismpath/portable/prismpath",     # the standalone JavaScript kernel and its test
    "prismpath/portable/run_",          # the JavaScript runners
    "prismpath/portable/bundle_engine.mjs",
    "prismpath/portable/crypto_migration_policy.mjs",
    "prismpath/portable/playground.html",
    "prismpath/portable/README.md",     # describes the JavaScript kernel
    "prismpath/bundle_compile.py",      # the bundle compiler for the JavaScript engine; the command is withdrawn without it
    "prismpath/safety/bypass_", "prismpath/safety/measure_p1.py", "prismpath/safety/gen_p1_lockfile.py",
    "prismpath/safety/benign_corpus.py",
    "prismpath/evals/eval_",
    "prismpath/bypass_", "prismpath/eval_", "prismpath/measure_p1.py", "prismpath/gen_p1_lockfile.py",
    "prismpath/benign_corpus.py",       # alias shims for the held modules
    "prismpath/examples/code_nodes_gemma/", "prismpath/examples/mdflow_interop/",
    "prismpath/examples/cli_worker/log_alert", "prismpath/examples/cli_worker/release_gate",
    "prismpath-rs/examples/core_diff.rs", "prismpath-rs/examples/canon2_diff.rs",
    "prismpath-hotswap-rs/examples/core_evidence.rs",   # legs of the Lean differential harness
    "docs/SYSTEM_MAP.md", "docs/POSITION.md", "docs/decoder-ring.md", "docs/objections.md",
    "docs/CONVENTIONS.md", "docs/media/", "docs/vocabulary.json", "docs/design/arch-scorecard.md",
    "docs/DICTIONARY.md",      # the full Dictionary; the product carries its subset from tools/mirror/
    "ROADMAP.md", "METHODOLOGY.md", "README.md", "pyproject.toml", "MANIFEST.in",
    ".github/workflows/",      # CI is the overlay's
    # tests whose subject is held above
    "prismpath/tests/test_research_only.py", "prismpath/tests/conftest.py",   # the conftest only skips what research can't run as the product does
    "prismpath/tests/test_capability_audit.py",     # reads the JavaScript kernel
    "prismpath/tests/test_benchmark.py", "prismpath/tests/test_comparison.py",
    "prismpath/tests/test_comparisons_", "prismpath/tests/test_glue_opa_", "prismpath/tests/test_gate_zero_kappa.py",
    "prismpath/tests/test_benign_corpus.py", "prismpath/tests/test_bypass_", "prismpath/tests/test_gen_p1_lockfile.py",
    "prismpath/tests/test_compile.py", "prismpath/tests/test_portable_", "prismpath/tests/test_docs_health.py",
    "prismpath/tests/test_evidence_check_manifest.py", "prismpath/tests/test_mdflow_interop.py",
    "prismpath/tests/test_net_swap.py", "prismpath/telemetry/tests/test_bench_codecs.py",
    "prismpath/tests/test_core_diff.py", "prismpath/tests/test_core_evidence.py",
    "prismpath/tests/test_ebpf_", "prismpath/tests/test_arch_guard.py",
    "prismpath/tests/test_field_definitions_tables.py", "prismpath/tests/test_mission_control_guide.py",
    # research tooling beside the product's
    "tools/mirror/", "tools/mirror_readme.md", "tools/tests/test_export.py", "tools/mirror_publish.yml", "tools/export_clean.py",
    "tools/arch_guard.", "tools/arch_scorecard.json", "tools/arith_lint.py", "tools/docs_health.py",
    "tools/evidence_check.py", "tools/ledger_lint.py", "tools/run_corpora.py", "tools/fq_redundancy.py", "tools/gen_mission_control_guide.py",
    "tools/reproduce.sh", "docs/guides/reproduce.md",
]
EXCLUDE_SUFFIXES = [".deferrals"]           # empty top-level scratch files
EXCLUDE_EXACT = {"docs_health_report.md", "interactions.jsonl"}

OVERLAY_DIR = "tools/mirror"
README_SOURCE = "tools/mirror_readme.md"
PUBLISH_SOURCE = "tools/mirror_publish.yml"
PUBLISH_PATH = ".github/workflows/publish.yml"
VERSION_LINE = re.compile(r'^version = "[^"]*"', re.MULTILINE)
GENERATED = ("PROVENANCE.md", "SHA256SUMS")

ROOT = Path(__file__).resolve().parent.parent    # the source repo, wherever this is run from
sys.path.insert(0, str(ROOT))
from tools import provenance  # noqa: E402   the one definition of SHA256SUMS
from tools.tree import is_bytecode  # noqa: E402   the one definition of what is not part of a tree


def git(*args):
    return subprocess.check_output(["git", *args], text=True, cwd=ROOT).strip()


def tracked_files():
    return [path for path in git("ls-files").splitlines() if path]


def is_included(path):
    if path in EXCLUDE_EXACT or any(path.endswith(suffix) for suffix in EXCLUDE_SUFFIXES):
        return False
    if any(path.startswith(prefix) for prefix in EXCLUDE_PREFIXES):
        return False
    return path in INCLUDE_FILES or any(path.startswith(prefix) for prefix in INCLUDE_PREFIXES)


def overlay_files():
    """Every file under tools/mirror/, as (path in the tree, source path in this repo), apart from any
    bytecode Python wrote there."""
    base = ROOT / OVERLAY_DIR
    return sorted((p.relative_to(base).as_posix(), p) for p in base.rglob("*")
                  if p.is_file() and not is_bytecode(p.relative_to(base).as_posix()))


def export_plan(tracked):
    """The whole tree as {path in the tree: source file}, before the generated records."""
    plan = {path: ROOT / path for path in tracked if is_included(path)}
    for path, source in overlay_files():
        plan[path] = source
    plan["README.md"] = ROOT / README_SOURCE
    plan[PUBLISH_PATH] = ROOT / PUBLISH_SOURCE
    for name in GENERATED:
        plan.pop(name, None)
    return plan


def research_version():
    found = VERSION_LINE.search((ROOT / "pyproject.toml").read_text())
    if not found:
        sys.exit("pyproject.toml has no version line")
    return found.group(0)


def render(rel, source):
    """The bytes written for one path: the source's, except the overlay pyproject's version line."""
    data = source.read_bytes()
    if rel == "pyproject.toml":
        data = VERSION_LINE.sub(research_version(), data.decode(), count=1).encode()
    return data


def provenance_text(commit, tree):
    return (
        "# Provenance\n\n"
        "This tree is generated. It is the research repository crystal-warden/prism-path at one commit,\n"
        "exported by `tools/export_clean.py`, and it is never edited by hand: a change to it is a change\n"
        "to the research repository, made there and exported again.\n\n"
        f"Research commit: `{commit}`\n"
        f"Research tree: `{tree}`\n\n"
        "`SHA256SUMS` holds the sha256 of every other file in this tree. Every file is the research file\n"
        "of the same path byte for byte, except those that `tools/mirror/` and `tools/mirror_readme.md`\n"
        "supply in research for this repository (the README, the packaging, the CI workflow, the\n"
        "Dictionary subset and the product's wording of some docs), which are copied as written there. `python -m tools.provenance check`\n"
        "verifies the hashes, and `python -m tools.provenance check --research PATH` also checks the tree\n"
        "against a research checkout at the commit named above.\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="../prismpath-clean",
                    help="target directory for the tree (default ../prismpath-clean)")
    ap.add_argument("--commit", action="store_true",
                    help="make a local commit if --out is already a git repo (never pushes)")
    ap.add_argument("--allow-dirty", action="store_true",
                    help="export with uncommitted changes to tracked files (the commit named is then not the tree)")
    args = ap.parse_args()

    out = Path(args.out).resolve()
    if out == ROOT:
        sys.exit("refusing to export onto the source repo")
    if not args.allow_dirty and git("status", "--porcelain", "--untracked-files=no"):
        sys.exit("refusing to export a working tree with uncommitted changes: the tree would name a commit it is not")

    tracked = tracked_files()
    plan = export_plan(tracked)
    commit = git("rev-parse", "HEAD")
    tree = git("rev-parse", "HEAD^{tree}")

    # wipe only the content of the target, preserving its .git
    if out.exists():
        for child in out.iterdir():
            if child.name != ".git":
                shutil.rmtree(child) if child.is_dir() else child.unlink()
    out.mkdir(parents=True, exist_ok=True)

    contents = {}
    for rel, source in sorted(plan.items()):
        dst = out / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, dst)
        dst.write_bytes(render(rel, source))
        contents[rel] = dst.read_bytes()

    (out / "PROVENANCE.md").write_text(provenance_text(commit, tree))
    contents["PROVENANCE.md"] = (out / "PROVENANCE.md").read_bytes()
    (out / "SHA256SUMS").write_text(provenance.sha256_lines(contents))

    print(f"product tree written to {out}")
    print(f"  research commit: {commit}")
    print(f"  files:           {len(contents) + 1}")
    print(f"  held back:       {len(tracked) - len([p for p in plan if p in set(tracked)])} tracked files")

    if args.commit and (out / ".git").exists():
        subprocess.run(["git", "-C", str(out), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(out), "commit", "-q", "-m",
                        f"Export of crystal-warden/prism-path at {commit[:12]}"], check=True)
        print("  committed locally (not pushed)")


if __name__ == "__main__":
    main()
