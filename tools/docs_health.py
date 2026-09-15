#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Docs-health lint (Phase 6) + new-work capture audit (Phase 5). Runnable in CI.

Scoped to THIS public repo (not the private sibling dirs, not vendored, not _retired, not gitignored
caches). Every check is a function over one collected list of markdown files, so each can be imported
and unit tested against a fixture tree (prismpath/tests/test_docs_health.py); `main` composes them:

  dead_doc_links            markdown [..](x.md) whose target doesn't resolve
  brand_residue             a NEW 'mdflow' self-reference leaking into the docs (post-rename
                            hygiene). The legitimate third-party + interop mentions are allowlisted,
                            so only new leaks flag.
  lingering_dupes           normalized-content duplicates still present in the scanned tree
  backticked_missing_paths  ADVISORY, reported but never gated: backticked tokens in prose that look
                            repo-local and don't resolve
  coverage_gaps             each key session task # and result artifact referenced in
                            SUPPORTING_EVIDENCE/CLAIMS

Emits docs_health_report.md; exits 1 on dead links or brand residue (real defects). A missing evidence
ledger raises DocsHealthError, which is left uncaught so the traceback names the bad path: the audit
cannot tell "nothing is captured" from "I read the wrong file", so it must not guess.
"""
import os
import re
import json
import hashlib
from collections import defaultdict

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # scope: THIS public repo only
EXC = re.compile(r"(node_modules|/\.git/|\.venv|/venv|site-packages|dist-info|__pycache__|\.pytest_cache|docs_health_report|/ET-BERT/|/_src/|/extern/|_retired_docs)")
EVIDENCE_REL = "docs/research/supporting-evidence.md"
CLAIMS_REL = "docs/research/CLAIMS_detection_metrics.md"  # optional; lives in the private lab repo, absent here
REPORT_REL = "docs_health_report.md"


class DocsHealthError(RuntimeError):
    """An input the lint depends on is missing, so its verdict would be meaningless."""


def read_text(path):
    return open(path, encoding="utf-8", errors="ignore").read()


def collect_markdown(base):
    """Every .md under `base` that the exclusion pattern does not filter out, in walk order."""
    md_paths = []
    for dirpath, _, filenames in os.walk(base):
        if EXC.search(dirpath + "/"):
            continue
        for filename in filenames:
            if filename.endswith(".md") and not EXC.search(os.path.join(dirpath, filename)):
                md_paths.append(os.path.join(dirpath, filename))
    return md_paths


LINK_RX = re.compile(r"\[[^\]]+\]\(([^)]+\.md)(?:#[^)]*)?\)")


def dead_doc_links(base, md_paths):
    """Markdown links to a .md target that resolves from none of the three roots writers use."""
    dead = []
    for md_path in md_paths:
        doc_dir = os.path.dirname(md_path)
        for matched in LINK_RX.finditer(read_text(md_path)):
            target = matched.group(1)
            if target.startswith("http"):
                continue
            candidates = [os.path.join(doc_dir, target), os.path.join(base, target),
                          os.path.join(os.path.dirname(doc_dir), target)]
            if not any(os.path.exists(candidate) for candidate in candidates):
                dead.append((os.path.relpath(md_path, base), target))
    return dead


BRAND_RX = re.compile(r"\bmdflow\b", re.I)
# `mdflow` is BOTH the name this project carried before it was renamed to PrismPath AND a real
# third-party tool (Lindquist's) that PrismPath interops with and cites. Those legitimate mentions live
# in a known set of paths; flag `mdflow` ONLY outside them (i.e. a NEW leak into core docs).
MDFLOW_OK = ("examples/mdflow_interop/", "examples/code_nodes/README.md", "docs/guides/code-nodes.md",
             "docs/guides/tour.md",   # the interop-example citation moved here from the root README
             "docs/research/paper-routing-spectrum.md", "CHANGELOG.md", "ROADMAP.md")


def brand_residue(base, md_paths):
    """Pre-rename self-references leaking into the docs, one finding per line."""
    residue = []
    for md_path in md_paths:
        rel = os.path.relpath(md_path, base)
        if rel == "README.md" or any(ok in rel for ok in MDFLOW_OK):   # root README cites the mdflow interop example
            continue
        for line_number, line in enumerate(read_text(md_path).split("\n"), 1):
            if BRAND_RX.search(line):
                residue.append((rel, line_number, line.strip()[:80]))
    return residue


DUP_OK = ("/gallery/", "/adapters/")   # gallery showcases the core flows; adapters ship self-contained copies


def _normalized_hash(text):
    """Content identity with whitespace, case and the project's own two names factored out."""
    squeezed = re.sub(r"\s+", "", text.lower().replace("prismpath", "\x00").replace("mdflow", "\x00"))
    return hashlib.sha256(squeezed.encode()).hexdigest()


def lingering_dupes(base, md_paths):
    """Groups of scanned docs whose normalized content is identical."""
    by_hash = defaultdict(list)
    for md_path in md_paths:
        rel = os.path.relpath(md_path, base)
        if any(ok in "/" + rel for ok in DUP_OK):
            continue
        by_hash[_normalized_hash(read_text(md_path))].append(rel)
    return [paths for paths in by_hash.values() if len(paths) > 1]


LOCAL_PREFIXES = ("prismpath/", "prismpath-rs/", "prismpath-telemetry-rs/", "prismpath-hotswap-rs/",
                  "prismpath-preflight/", "prismpath-go/", "prismpath-hw/", "prismpath-ebpf/",
                  "adapters/", "integrations/", "tools/", "docs/", "research/")
# Declared archived or separate first-party lab locations (see the ledger provenance taxonomy). These
# are legitimately absent from this repo; the ledger names them as such, so they are not drift.
# adapters/compliance/ left this list in September 2026 when the adapter was rebuilt and shipped again.
ARCHIVED_EXTERNAL = ("etbert-lab/", "triage-corpus/", "triage-7b-lab/",
                     "knowledge-lib/", "governor-lab/", "benign_corpus/",
                     "adapters/fusion/live_capture.py")
BTICK_RX = re.compile(r"`([A-Za-z0-9_][A-Za-z0-9_./\-]*)`")


def backticked_missing_paths(base, md_paths):
    """ADVISORY, non-failing. A `path/like/this.py` in prose is not a markdown link, so
    dead_doc_links never sees it; that is exactly how rows #65-71 kept citing an
    `adapters/compliance/` provenance the taxonomy calls "reproducible from THIS repo" after the
    adapter left the tree. This surfaces the class: backticked tokens that LOOK repo-local, don't
    exist on disk, and are NOT a declared archived/separate-lab location. Reported only (not in the
    exit-1 gate) until false-positives are tuned, so no CI regression; promote to a gate later."""
    missing_paths = []
    for md_path in md_paths:
        rel = os.path.relpath(md_path, base)
        if rel == "CHANGELOG.md":                                 # append-only history legitimately names removed paths
            continue
        for matched in BTICK_RX.finditer(read_text(md_path)):
            token = matched.group(1)
            if "*" in token or "/" not in token:                  # need a real path; no globs, no bare names
                continue
            if ".venv" in token or "__pycache__" in token:        # env/cache dirs are not claims
                continue
            if not token.startswith(LOCAL_PREFIXES):              # only things claiming to be repo-local
                continue
            if token.startswith(ARCHIVED_EXTERNAL):               # declared archived/lab: expected-absent
                continue
            if "." not in token.split("/")[-1] and not token.endswith("/"):
                continue                                          # file-like (has ext) or explicit dir only
            if not os.path.exists(os.path.join(base, token.rstrip("/"))):
                missing_paths.append((rel, token))
    return missing_paths


TASKS = ["#30", "#35", "#53", "#54", "#55", "#56", "#58"]
ARTIFACTS = ["validation_v0.json", "lm_deepdive.json", "enrich_lift_v0.json", "sequence_lift_v0.json",
             "decomposed_v0.json", "embed_routed_v0.json", "agentic_pull_demo.json", "rag_nodes_v1.json",
             "step4_recert_livepool.json", "step6_perfamily_recall.json",
             "ledger_airgap.py", "validate_triage_decomposed.py", "build_knowledge_index.py"]


def evidence_text(base):
    """The ledger plus the optional private-lab claims file, as one blob to search.

    The ledger is mandatory: reading "" when the path goes stale makes the coverage audit report
    EVERY task and artifact as a gap, which is indistinguishable from a real capture failure.
    """
    evidence_path = os.path.join(base, EVIDENCE_REL)
    if not os.path.exists(evidence_path):
        raise DocsHealthError(f"evidence ledger missing at {evidence_path}; fix this path, do not ignore")
    claims_path = os.path.join(base, CLAIMS_REL)
    claims = read_text(claims_path) if os.path.exists(claims_path) else ""
    return read_text(evidence_path) + claims


def coverage_gaps(base):
    """Key session tasks and result artifacts with no mention in the durable evidence docs."""
    captured = evidence_text(base)
    task_gaps = [task for task in TASKS if task not in captured]
    artifact_gaps = [artifact for artifact in ARTIFACTS if artifact not in captured]
    return task_gaps, artifact_gaps


def build_report(md_paths, dead, residue, dupes, task_gaps, artifact_gaps, missing_paths):
    """The JSON payload; residue is truncated for the payload but counted in full."""
    return {"canonical_md_files": len(md_paths), "dead_doc_links": dead,
            "brand_residue_in_prismpath": residue[:40], "brand_residue_count": len(residue),
            "lingering_dupes": dupes, "task_coverage_gaps": task_gaps, "artifact_coverage_gaps": artifact_gaps,
            "backticked_missing_paths_advisory": missing_paths}


def render_markdown(report):
    """docs_health_report.md, rendered from the same payload the JSON carries."""
    dead = report["dead_doc_links"]
    residue = report["brand_residue_in_prismpath"]
    dupes = report["lingering_dupes"]
    missing_paths = report["backticked_missing_paths_advisory"]
    task_gaps = report["task_coverage_gaps"]
    artifact_gaps = report["artifact_coverage_gaps"]
    lines = ["# Docs Health Report", "",
             f"- canonical .md files scanned: **{report['canonical_md_files']}**",
             f"- dead doc-links: **{len(dead)}**", f"- brand residue (mdflow in prismpath): **{report['brand_residue_count']}**",
             f"- lingering content dupes: **{len(dupes)}**",
             f"- task-coverage gaps: **{task_gaps or 'none'}**", f"- artifact-coverage gaps: **{artifact_gaps or 'none'}**", ""]
    if dead:
        lines += ["## Dead doc-links", *[f"- `{md_path}` → `{target}`" for md_path, target in dead], ""]
    if report["brand_residue_count"]:
        lines += ["## Brand residue (prismpath docs mentioning mdflow)", *[f"- `{md_path}`:{line_number} — {text}" for md_path, line_number, text in residue], ""]
    if dupes:
        lines += ["## Lingering dupes", *[f"- {' == '.join(group)}" for group in dupes], ""]
    lines += [f"- backticked repo-local paths that don't resolve (advisory): **{len(missing_paths)}**", ""]
    if missing_paths:
        lines += ["## Backticked missing paths (ADVISORY — not gated)",
                  "Paths in prose that look repo-local, don't exist on disk, and aren't a declared "
                  "archived/separate-lab location. Either fix the reference or mark it archived.",
                  *[f"- `{md_path}` → `{target}`" for md_path, target in missing_paths], ""]
    return lines


def run_checks(base):
    """Every check over one markdown collection, as the JSON payload."""
    md_paths = collect_markdown(base)
    dead = dead_doc_links(base, md_paths)
    residue = brand_residue(base, md_paths)
    dupes = lingering_dupes(base, md_paths)
    missing_paths = backticked_missing_paths(base, md_paths)
    task_gaps, artifact_gaps = coverage_gaps(base)
    return build_report(md_paths, dead, residue, dupes, task_gaps, artifact_gaps, missing_paths)


def main(base=BASE):
    """Write the report, print the JSON, and return the process exit code."""
    report = run_checks(base)
    with open(os.path.join(base, REPORT_REL), "w", encoding="utf-8") as report_file:
        report_file.write("\n".join(render_markdown(report)) + "\n")
    print(json.dumps(report, indent=2))
    # honor the docstring: fail on real defects only, never on the coverage or advisory checks
    return 1 if (report["dead_doc_links"] or report["brand_residue_count"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
