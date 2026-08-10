#!/usr/bin/env python3
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
for r in CANON:
    for dp, _, fn in os.walk(os.path.join(BASE, r)):
        if EXC.search(dp + "/"):
            continue
        for f in fn:
            if f.endswith(".md") and not EXC.search(os.path.join(dp, f)):
                mds.append(os.path.join(dp, f))


def read(p):
    return open(p, encoding="utf-8", errors="ignore").read()


# 1. dead doc-links (targets ending .md)
dead = []
linkrx = re.compile(r"\[[^\]]+\]\(([^)]+\.md)(?:#[^)]*)?\)")
for p in mds:
    d = os.path.dirname(p)
    for m in linkrx.finditer(read(p)):
        tgt = m.group(1)
        if tgt.startswith("http"):
            continue
        cands = [os.path.join(d, tgt), os.path.join(BASE, tgt),
                 os.path.join(os.path.dirname(d), tgt)]
        if not any(os.path.exists(c) for c in cands):
            dead.append((os.path.relpath(p, BASE), tgt))

# 2. brand residue — pre-rename self-references leaking into the docs.
# `mdflow` is BOTH the name this project carried before it was renamed to PrismPath AND a real
# third-party tool (Lindquist's) that PrismPath interops with and cites. Those legitimate mentions live
# in a known set of paths; flag `mdflow` ONLY outside them (i.e. a NEW leak into core docs).
residue = []
brx = re.compile(r"\bmdflow\b", re.I)
MDFLOW_OK = ("examples/mdflow_interop/", "examples/code_nodes/README.md", "docs/guides/code-nodes.md",
             "docs/research/paper-routing-spectrum.md", "CHANGELOG.md", "ROADMAP.md")
for p in mds:
    rel = os.path.relpath(p, BASE)
    if rel == "README.md" or any(ok in rel for ok in MDFLOW_OK):   # root README cites the mdflow interop example
        continue
    for i, line in enumerate(read(p).split("\n"), 1):
        if brx.search(line):
            residue.append((os.path.relpath(p, BASE), i, line.strip()[:80]))

# 3. lingering dupes across canonical repos
def nh(t):
    return hashlib.sha256(re.sub(r"\s+", "", t.lower().replace("prismpath", "\x00").replace("mdflow", "\x00")).encode()).hexdigest()
DUP_OK = ("/gallery/", "/adapters/")   # gallery showcases the core flows; adapters ship self-contained copies
byh = defaultdict(list)
for p in mds:
    rel = os.path.relpath(p, BASE)
    if any(ok in "/" + rel for ok in DUP_OK):
        continue
    byh[nh(read(p))].append(rel)
dupes = [v for v in byh.values() if len(v) > 1]

# 4 + 5. coverage audit
evtext = (read(EV) if os.path.exists(EV) else "") + (read(CLAIMS) if os.path.exists(CLAIMS) else "")
TASKS = ["#30", "#35", "#53", "#54", "#55", "#56", "#58"]
ARTIFACTS = ["validation_v0.json", "lm_deepdive.json", "enrich_lift_v0.json", "sequence_lift_v0.json",
             "decomposed_v0.json", "embed_routed_v0.json", "agentic_pull_demo.json", "rag_nodes_v1.json",
             "step4_recert_livepool.json", "step6_perfamily_recall.json",
             "ledger_airgap.py", "validate_triage_decomposed.py", "build_knowledge_index.py"]
task_gaps = [t for t in TASKS if t not in evtext]
artifact_gaps = [a for a in ARTIFACTS if a not in evtext]

report = {"canonical_md_files": len(mds), "dead_doc_links": dead,
          "brand_residue_in_prismpath": residue[:40], "brand_residue_count": len(residue),
          "lingering_dupes": dupes, "task_coverage_gaps": task_gaps, "artifact_coverage_gaps": artifact_gaps}

md = ["# Docs Health Report", "",
      f"- canonical .md files scanned: **{len(mds)}**",
      f"- dead doc-links: **{len(dead)}**", f"- brand residue (mdflow in prismpath): **{len(residue)}**",
      f"- lingering content dupes: **{len(dupes)}**",
      f"- task-coverage gaps: **{task_gaps or 'none'}**", f"- artifact-coverage gaps: **{artifact_gaps or 'none'}**", ""]
if dead:
    md += ["## Dead doc-links", *[f"- `{p}` → `{t}`" for p, t in dead], ""]
if residue:
    md += ["## Brand residue (prismpath docs mentioning mdflow)", *[f"- `{p}`:{i} — {tx}" for p, i, tx in residue[:40]], ""]
if dupes:
    md += ["## Lingering dupes", *[f"- {' == '.join(g)}" for g in dupes], ""]
open(os.path.join(BASE, "docs_health_report.md"), "w").write("\n".join(md) + "\n")
print(json.dumps(report, indent=2))
raise SystemExit(1 if (dead or residue) else 0)   # honor the docstring: fail on real defects
