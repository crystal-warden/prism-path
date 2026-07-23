#!/usr/bin/env python3
"""PrismPath architecture guard + per-adapter scorecard.

Instruments the three highest-signal "is-it-really-general" failure modes (see ARCH persona memo):
  Signal 1 — domain vocabulary or an adapter-import inside CORE  ->  HARD FAIL (the bright line).
  Signal 3 — core churn (LOC changed) since a baseline ref       ->  TREND (reported, must DECAY per adapter).
  Signal 7 — marginal adapter cost + %-of-logic-in-markdown       ->  TREND (adapter #N should cost < #1; logic in .md).

Co-evolution edits the core early; only Signal 1 is gated. Run: python tools/arch_guard.py [--baseline REF]
Dependency-free (stdlib + git). Emits docs/ARCH_SCORECARD.md + prints a summary; exit 1 iff Signal 1 fails.
"""
import os, re, json, sys, subprocess, argparse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)  # repo root (tools/ lives under it)


def loc(path):
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            return sum(1 for _ in f)
    except OSError:
        return 0


def scan_domain_nouns(path, noun_map):
    """Return [(lineno, domain, noun, text)] for any domain noun found (word-boundary, case-insensitive)."""
    hits = []
    try:
        lines = open(path, encoding="utf-8", errors="ignore").read().splitlines()
    except OSError:
        return hits
    compiled = []
    for domain, nouns in noun_map.items():
        for n in nouns:
            pat = n if n.startswith("\\b") or "\\b" in n else r"\b" + re.escape(n) + r"\b"
            compiled.append((domain, n, re.compile(pat, re.I)))
    for i, line in enumerate(lines, 1):
        low = line
        for domain, n, rx in compiled:
            if rx.search(low):
                hits.append((i, domain, n, line.strip()[:80]))
    return hits


def scan_adapter_imports(path, adapter_code_modules):
    """Return [(lineno, module)] where CORE imports an adapter code module."""
    hits = []
    stems = [os.path.splitext(os.path.basename(m))[0] for m in adapter_code_modules]
    if not stems:
        return hits
    rx = re.compile(r"^\s*(?:from\s+[\w.]*?\b(" + "|".join(map(re.escape, stems)) +
                    r")\b|import\s+[\w.]*?\b(" + "|".join(map(re.escape, stems)) + r")\b)")
    try:
        for i, line in enumerate(open(path, encoding="utf-8", errors="ignore"), 1):
            if rx.search(line):
                hits.append((i, next(s for s in stems if s in line)))
    except OSError:
        pass
    return hits


def git_core_churn(pkg_dir, core_modules, baseline):
    if not baseline:
        return None
    paths = [os.path.join(pkg_dir, m) for m in core_modules]
    try:
        out = subprocess.run(["git", "-C", ROOT, "diff", "--numstat", baseline, "--", *paths],
                             capture_output=True, text=True, timeout=30)
        if out.returncode != 0:
            return {"error": out.stderr.strip()[:120]}
        added = removed = files = 0
        for ln in out.stdout.splitlines():
            p = ln.split("\t")
            if len(p) >= 3 and p[0].isdigit():
                added += int(p[0]); removed += int(p[1]) if p[1].isdigit() else 0; files += 1
        return {"baseline": baseline, "core_files_changed": files, "lines_added": added, "lines_removed": removed}
    except Exception as e:
        return {"error": str(e)[:120]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=os.path.join(HERE, "arch_guard.config.json"))
    ap.add_argument("--baseline", default=None, help="git ref to measure core churn since (Signal 3)")
    args = ap.parse_args()
    cfg = json.load(open(args.config))
    pkg = os.path.join(ROOT, cfg["package_dir"])
    core = cfg["core_modules"]
    adapters = cfg["adapters"]
    all_adapter_code = [m for a in adapters.values() for m in a.get("code", [])]

    # ---- Signal 1: core purity (HARD) ----
    violations = []
    for m in core:
        p = os.path.join(pkg, m)
        if not os.path.exists(p):
            continue
        for (ln, dom, noun, text) in scan_domain_nouns(p, cfg["domain_nouns"]):
            violations.append({"file": m, "line": ln, "kind": "domain-noun", "domain": dom, "noun": noun, "text": text})
        for (ln, mod) in scan_adapter_imports(p, all_adapter_code):
            violations.append({"file": m, "line": ln, "kind": "adapter-import", "module": mod})

    # ---- Signal 3: core churn (TREND) ----
    core_loc = sum(loc(os.path.join(pkg, m)) for m in core if os.path.exists(os.path.join(pkg, m)))
    churn = git_core_churn(pkg, core, args.baseline)

    # ---- Signal 7: marginal cost + %-logic-in-md (TREND) ----
    scores = []
    for name, a in adapters.items():
        code_loc = sum(loc(os.path.join(pkg, m)) for m in a.get("code", []))
        md_loc = sum(loc(os.path.join(pkg, m)) for m in a.get("flows", []))
        total = code_loc + md_loc
        scores.append({"adapter": name, "code_loc": code_loc, "flow_md_loc": md_loc,
                       "pct_logic_in_md": round(md_loc / total, 3) if total else None})

    result = {
        "signal_1_core_purity": {"PASS": not violations, "violations": violations},
        "signal_3_core_churn": {"core_total_loc": core_loc, "churn_since_baseline": churn,
                                "note": "track per-adapter; must DECAY. flat/rising = rebuilding, not generalizing."},
        "signal_7_marginal_cost": {"adapters": scores,
                                   "note": "adapter #N should cost < #1; higher %_logic_in_md = logic stays in plain-English (good)."},
        "unclassified_needs_triage": cfg.get("unclassified_needs_triage", []),
    }

    # ---- scorecard.md ----
    md = ["# PrismPath Architecture Scorecard", "",
          "_Generated by `tools/arch_guard.py`. Signal 1 is gated; 3 & 7 are trends to watch across adapters._", "",
          f"## Signal 1 — Core purity (HARD GATE): {'✅ PASS' if not violations else '❌ FAIL (' + str(len(violations)) + ')'}"]
    if violations:
        md.append("| file | line | kind | detail |")
        md.append("|---|---|---|---|")
        for v in violations[:60]:
            detail = f"{v.get('domain','')}:{v.get('noun','')}" if v["kind"] == "domain-noun" else f"imports {v.get('module','')}"
            md.append(f"| `{v['file']}` | {v['line']} | {v['kind']} | {detail} |")
    md += ["", f"## Signal 3 — Core churn (trend)", f"- core total LOC: **{core_loc}** across {len(core)} declared-core modules",
           f"- churn since baseline: `{json.dumps(churn)}`", "- watch: core LOC changed per adapter milestone must DECAY.",
           "", "## Signal 7 — Marginal adapter cost + %-logic-in-md (trend)",
           "| adapter | code LOC | flow .md LOC | % logic in .md |", "|---|---|---|---|"]
    for s in scores:
        md.append(f"| {s['adapter']} | {s['code_loc']} | {s['flow_md_loc']} | {s['pct_logic_in_md']} |")
    md += ["", "## Unclassified modules (triage core vs adapter during refactor)",
           ", ".join(f"`{m}`" for m in cfg.get("unclassified_needs_triage", []))]
    os.makedirs(os.path.join(pkg, "docs"), exist_ok=True)
    open(os.path.join(pkg, "docs", "ARCH_SCORECARD.md"), "w").write("\n".join(md) + "\n")
    json.dump(result, open(os.path.join(HERE, "arch_scorecard.json"), "w"), indent=2)

    print(json.dumps({"signal_1_PASS": not violations, "n_violations": len(violations),
                      "core_total_loc": core_loc, "signal_7": scores,
                      "sample_violations": violations[:12]}, indent=2))
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
