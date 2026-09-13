#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Docs-health lint (Phase 6) + new-work capture audit (Phase 5). Runnable in CI.

Scoped to THIS public repo (not the private sibling dirs, not vendored, not _retired, not gitignored caches):
  1. dead doc-links   — markdown [..](x.md) whose target doesn't resolve
  2. brand residue    — a NEW 'mdflow' self-reference leaking into the docs (post-rename hygiene). The
                        legitimate third-party + interop mentions are allowlisted, so only new leaks flag.
  3. lingering dupes  — normalized-content duplicates still present across canonical repos
  4. task coverage    — each key session task # referenced in SUPPORTING_EVIDENCE/CLAIMS
  5. artifact coverage— each session result artifact referenced in a durable doc
Emits docs_health_report.md; exits 1 on dead links or brand residue (real defects).
"""
import os, re, json, hashlib
from collections import defaultdict

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # scope: THIS public repo only
CANON = ["."]
EXC = re.compile(r"(node_modules|/\.git/|\.venv|/venv|site-packages|dist-info|__pycache__|\.pytest_cache|docs_health_report|/ET-BERT/|/_src/|/extern/|_retired_docs)")
EV = os.path.join(BASE, "docs/research/supporting-evidence.md")
# NB: `if os.path.exists(EV)` below degrades silently to "" — if this path ever goes stale
# again, checks 4-5 report EVERY task/artifact as a gap instead of erroring. Assert loudly:
assert os.path.exists(EV), f"evidence ledger missing at {EV} — fix this path, do not ignore"
CLAIMS = os.path.join(BASE, "docs/research/CLAIMS_detection_metrics.md")  # optional; lives in the private lab repo, absent here

mds = []
for canon_root in CANON:
    for dp, _, fn in os.walk(os.path.join(BASE, canon_root)):
        if EXC.search(dp + "/"):
            continue
        for filename in fn:
            if filename.endswith(".md") and not EXC.search(os.path.join(dp, filename)):
                mds.append(os.path.join(dp, filename))


def read(path):
    return open(path, encoding="utf-8", errors="ignore").read()


# 1. dead doc-links (targets ending .md)
dead = []
linkrx = re.compile(r"\[[^\]]+\]\(([^)]+\.md)(?:#[^)]*)?\)")
for md_path in mds:
    doc_dir = os.path.dirname(md_path)
    for matched in linkrx.finditer(read(md_path)):
        tgt = matched.group(1)
        if tgt.startswith("http"):
            continue
        cands = [os.path.join(doc_dir, tgt), os.path.join(BASE, tgt),
                 os.path.join(os.path.dirname(doc_dir), tgt)]
        if not any(os.path.exists(candidate) for candidate in cands):
            dead.append((os.path.relpath(md_path, BASE), tgt))

# 2. brand residue — pre-rename self-references leaking into the docs.
# `mdflow` is BOTH the name this project carried before it was renamed to PrismPath AND a real
# third-party tool (Lindquist's) that PrismPath interops with and cites. Those legitimate mentions live
# in a known set of paths; flag `mdflow` ONLY outside them (i.e. a NEW leak into core docs).
residue = []
brx = re.compile(r"\bmdflow\b", re.I)
MDFLOW_OK = ("examples/mdflow_interop/", "examples/code_nodes/README.md", "docs/guides/code-nodes.md",
             "docs/guides/tour.md",   # the interop-example citation moved here from the root README
             "docs/research/paper-routing-spectrum.md", "CHANGELOG.md", "ROADMAP.md")
for md_path in mds:
    rel = os.path.relpath(md_path, BASE)
    if rel == "README.md" or any(ok in rel for ok in MDFLOW_OK):   # root README cites the mdflow interop example
        continue
    for line_number, line in enumerate(read(md_path).split("\n"), 1):
        if brx.search(line):
            residue.append((os.path.relpath(md_path, BASE), line_number, line.strip()[:80]))

# 3. lingering dupes across canonical repos
def nh(text):
    return hashlib.sha256(re.sub(r"\s+", "", text.lower().replace("prismpath", "\x00").replace("mdflow", "\x00")).encode()).hexdigest()
DUP_OK = ("/gallery/", "/adapters/")   # gallery showcases the core flows; adapters ship self-contained copies
byh = defaultdict(list)
for md_path in mds:
    rel = os.path.relpath(md_path, BASE)
    if any(ok in "/" + rel for ok in DUP_OK):
        continue
    byh[nh(read(md_path))].append(rel)
dupes = [paths for paths in byh.values() if len(paths) > 1]

# 6. backticked repo-relative paths (ADVISORY, non-failing). A `path/like/this.py` in prose is not a
#    markdown link, so check 1 never sees it; that is exactly how rows #65-71 kept citing an
#    `adapters/compliance/` provenance the taxonomy calls "reproducible from THIS repo" after the
#    adapter left the tree. This surfaces the class: backticked tokens that LOOK repo-local, don't
#    exist on disk, and are NOT a declared archived/separate-lab location. Reported only (not in the
#    exit-1 gate) until false-positives are tuned, so no CI regression; promote to a gate later.
LOCAL_PREFIXES = ("prismpath/", "prismpath-rs/", "prismpath-telemetry-rs/", "prismpath-hotswap-rs/",
                  "prismpath-preflight/", "prismpath-go/", "prismpath-hw/", "prismpath-ebpf/",
                  "adapters/", "integrations/", "tools/", "docs/", "research/")
# Declared archived or separate first-party lab locations (see the ledger provenance taxonomy). These
# are legitimately absent from this repo; the ledger names them as such, so they are not drift.
# adapters/compliance/ left this list in September 2026 when the adapter was rebuilt and shipped again.
ARCHIVED_EXTERNAL = ("etbert-lab/", "triage-corpus/", "triage-7b-lab/",
                     "knowledge-lib/", "governor-lab/", "benign_corpus/",
                     "adapters/fusion/live_capture.py")
btickrx = re.compile(r"`([A-Za-z0-9_][A-Za-z0-9_./\-]*)`")
missing_paths = []
for md_path in mds:
    rel = os.path.relpath(md_path, BASE)
    if rel == "CHANGELOG.md":                                 # append-only history legitimately names removed paths
        continue
    for matched in btickrx.finditer(read(md_path)):
        tok = matched.group(1)
        if "*" in tok or "/" not in tok:                      # need a real path; no globs, no bare names
            continue
        if ".venv" in tok or "__pycache__" in tok:            # env/cache dirs are not claims
            continue
        if not tok.startswith(LOCAL_PREFIXES):                # only things claiming to be repo-local
            continue
        if tok.startswith(ARCHIVED_EXTERNAL):                 # declared archived/lab: expected-absent
            continue
        if "." not in tok.split("/")[-1] and not tok.endswith("/"):
            continue                                          # file-like (has ext) or explicit dir only
        if not os.path.exists(os.path.join(BASE, tok.rstrip("/"))):
            missing_paths.append((rel, tok))

# 4 + 5. coverage audit
evtext = (read(EV) if os.path.exists(EV) else "") + (read(CLAIMS) if os.path.exists(CLAIMS) else "")
TASKS = ["#30", "#35", "#53", "#54", "#55", "#56", "#58"]
ARTIFACTS = ["validation_v0.json", "lm_deepdive.json", "enrich_lift_v0.json", "sequence_lift_v0.json",
             "decomposed_v0.json", "embed_routed_v0.json", "agentic_pull_demo.json", "rag_nodes_v1.json",
             "step4_recert_livepool.json", "step6_perfamily_recall.json",
             "ledger_airgap.py", "validate_triage_decomposed.py", "build_knowledge_index.py"]
task_gaps = [task for task in TASKS if task not in evtext]
artifact_gaps = [artifact for artifact in ARTIFACTS if artifact not in evtext]

report = {"canonical_md_files": len(mds), "dead_doc_links": dead,
          "brand_residue_in_prismpath": residue[:40], "brand_residue_count": len(residue),
          "lingering_dupes": dupes, "task_coverage_gaps": task_gaps, "artifact_coverage_gaps": artifact_gaps,
          "backticked_missing_paths_advisory": missing_paths}

md = ["# Docs Health Report", "",
      f"- canonical .md files scanned: **{len(mds)}**",
      f"- dead doc-links: **{len(dead)}**", f"- brand residue (mdflow in prismpath): **{len(residue)}**",
      f"- lingering content dupes: **{len(dupes)}**",
      f"- task-coverage gaps: **{task_gaps or 'none'}**", f"- artifact-coverage gaps: **{artifact_gaps or 'none'}**", ""]
if dead:
    md += ["## Dead doc-links", *[f"- `{md_path}` → `{target}`" for md_path, target in dead], ""]
if residue:
    md += ["## Brand residue (prismpath docs mentioning mdflow)", *[f"- `{md_path}`:{line_number} — {tx}" for md_path, line_number, tx in residue[:40]], ""]
if dupes:
    md += ["## Lingering dupes", *[f"- {' == '.join(group)}" for group in dupes], ""]
md += [f"- backticked repo-local paths that don't resolve (advisory): **{len(missing_paths)}**", ""]
if missing_paths:
    md += ["## Backticked missing paths (ADVISORY — not gated)",
           "Paths in prose that look repo-local, don't exist on disk, and aren't a declared "
           "archived/separate-lab location. Either fix the reference or mark it archived.",
           *[f"- `{md_path}` → `{target}`" for md_path, target in missing_paths], ""]
open(os.path.join(BASE, "docs_health_report.md"), "w").write("\n".join(md) + "\n")
print(json.dumps(report, indent=2))
raise SystemExit(1 if (dead or residue) else 0)   # honor the docstring: fail on real defects
