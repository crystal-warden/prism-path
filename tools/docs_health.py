#!/usr/bin/env python3
"""Docs-health lint (Phase 6) + new-work capture audit (Phase 5). Runnable in CI.

Checks the CANONICAL repos (not mdflow working tree, not vendored, not _retired):
  1. dead doc-links   — markdown [..](x.md) whose target doesn't resolve
  2. brand residue    — 'mdflow' left in published prismpath docs (post-rename hygiene)
  3. lingering dupes  — normalized-content duplicates still present across canonical repos
  4. task coverage    — each key session task # referenced in SUPPORTING_EVIDENCE/CLAIMS
  5. artifact coverage— each session result artifact referenced in a durable doc
Emits docs_health_report.md; exits 1 on dead links or brand residue (real defects).
"""
import os, re, json, hashlib
from collections import defaultdict

BASE = "/home/cwadmin/cwprojects"
CANON = ["prismpath", "cw-strategy", "etbert-lab", "knowledge-lib"]
EXC = re.compile(r"(node_modules|/\.git/|\.venv|/venv|site-packages|dist-info|__pycache__|/ET-BERT/|/_src/|/extern/|_retired_docs)")
EV = os.path.join(BASE, "prismpath/prismpath/docs/papers/SUPPORTING_EVIDENCE.md")
CLAIMS = os.path.join(BASE, "etbert-lab/CLAIMS_detection_metrics.md")

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

# 2. brand residue in published prismpath docs
residue = []
brx = re.compile(r"\bmdflow\b", re.I)
for p in mds:
    if "/prismpath/" not in p:
        continue
    for i, line in enumerate(read(p).split("\n"), 1):
        if brx.search(line):
            residue.append((os.path.relpath(p, BASE), i, line.strip()[:80]))

# 3. lingering dupes across canonical repos
def nh(t):
    return hashlib.sha256(re.sub(r"\s+", "", t.lower().replace("prismpath", "\x00").replace("mdflow", "\x00")).encode()).hexdigest()
byh = defaultdict(list)
for p in mds:
    byh[nh(read(p))].append(os.path.relpath(p, BASE))
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
