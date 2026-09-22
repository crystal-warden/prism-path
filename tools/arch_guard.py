#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The architecture guard: the Dictionary's enforceable contract, checked, plus the adapter scorecard.

Four things fail the build, each with the file, the line and what to do:
  * a domain noun or an adapter import inside a CORE module (the hexagonal bright line, Signal 1);
  * a declared path that does not exist: a core module, an adapter's code or flow, an orchestration
    module, the console. A checker that skips a missing module is a checker that can be silenced by
    deleting the module, so absence is an error, never a skip;
  * a deprecated identifier used outside the paths that keep it alive on purpose (a shim that warns,
    the test that pins the warning) and outside certified paths, which never move;
  * vocabulary drift: a term named in docs/vocabulary.json with no entry in docs/DICTIONARY.md, or a
    domain the dictionary does not name, so the two files cannot part ways silently.

The domain nouns, the deprecated identifiers and the certified paths come from docs/vocabulary.json,
the structured half of the Dictionary; the prose explains, this file enforces. Two trend signals are
reported and not gated: core churn since a baseline (Signal 3) and the marginal cost of each adapter
with its share of logic in Markdown (Signal 7).

Run: python tools/arch_guard.py [--baseline REF]. Dependency free (stdlib and git). Writes
docs/design/arch-scorecard.md (git ignored) and tools/arch_scorecard.json; exit 1 on any hard failure.
"""
import argparse
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def loc(path):
    try:
        with open(path, encoding="utf-8", errors="ignore") as handle:
            return sum(1 for _ in handle)
    except OSError:
        return 0


def read_lines(path):
    try:
        with open(path, encoding="utf-8", errors="ignore") as handle:
            return handle.read().splitlines()
    except OSError:
        return []


def noun_pattern(noun):
    """A noun written with its own \\b markers is a regex; a plain word gets word boundaries."""
    if "\\b" in noun:
        return re.compile(noun, re.I)
    return re.compile(r"\b" + re.escape(noun) + r"\b", re.I)


def scan_domain_nouns(path, domains):
    """[(line, domain, noun, text)] for every domain noun in the file, case insensitive."""
    compiled = [(domain, noun, noun_pattern(noun)) for domain, entry in domains.items() for noun in entry["nouns"]]
    hits = []
    for line_number, line in enumerate(read_lines(path), 1):
        for domain, noun, pattern in compiled:
            if pattern.search(line):
                hits.append((line_number, domain, noun, line.strip()[:80]))
    return hits


def scan_adapter_imports(path, adapter_code_modules):
    """[(line, module)] where the file imports an adapter code module."""
    stems = [os.path.splitext(os.path.basename(module_path))[0] for module_path in adapter_code_modules]
    if not stems:
        return []
    alternatives = "|".join(map(re.escape, stems))
    pattern = re.compile(r"^\s*(?:from\s+[\w.]*?\b(" + alternatives + r")\b|import\s+[\w.]*?\b(" + alternatives + r")\b)")
    hits = []
    for line_number, line in enumerate(read_lines(path), 1):
        if pattern.search(line):
            hits.append((line_number, next(stem for stem in stems if stem in line)))
    return hits


def python_files(root, scan_roots):
    for scan_root in scan_roots:
        base = os.path.join(root, scan_root)
        for directory, subdirectories, files in os.walk(base):
            subdirectories[:] = [name for name in subdirectories if name not in ("__pycache__", ".venv", "node_modules", "target")]
            for name in files:
                if name.endswith(".py"):
                    yield os.path.relpath(os.path.join(directory, name), root).replace(os.sep, "/")


def path_is_under(relative_path, prefixes):
    return any(relative_path == prefix or relative_path.startswith(prefix.rstrip("/") + "/") or
               (prefix.endswith("/") and relative_path.startswith(prefix)) for prefix in prefixes)


def scan_deprecated(root, scan_roots, vocabulary):
    """[(file, line, identifier, canonical, text)] for a deprecated identifier outside its allowed
    paths and outside the certified paths."""
    certified = vocabulary.get("certified", {}).get("paths", [])
    findings = []
    entries = [(entry, re.compile(entry["identifier"] if "\\b" in entry["identifier"] else r"\b" + re.escape(entry["identifier"]) + r"\b"))
               for entry in vocabulary.get("deprecated", [])]
    for relative_path in python_files(root, scan_roots):
        if path_is_under(relative_path, certified):
            continue
        lines = None
        for entry, pattern in entries:
            if path_is_under(relative_path, entry.get("allowed_paths", [])):
                continue
            if lines is None:
                lines = read_lines(os.path.join(root, relative_path))
            for line_number, line in enumerate(lines, 1):
                if pattern.search(line):
                    findings.append((relative_path, line_number, entry["identifier"], entry["canonical"], line.strip()[:80]))
    return findings


def dictionary_terms(dictionary_path):
    """The set of entry names in the dictionary, the bold term before the colon."""
    return {match.group(1) for match in re.finditer(r"^\*\*([^*]+)\*\*:", "\n".join(read_lines(dictionary_path)), re.M)}


def vocabulary_drift(vocabulary, dictionary_path):
    """Every term the vocabulary names must be a dictionary entry, and every domain must be named in
    the dictionary's domain paragraph, so an enforced word is always an explained word."""
    text = "\n".join(read_lines(dictionary_path))
    terms = dictionary_terms(dictionary_path)
    problems = []
    for entry in vocabulary.get("deprecated", []) + vocabulary.get("certified", {}).get("identifiers", []):
        if entry.get("term") not in terms:
            problems.append(f"vocabulary names the term {entry.get('term')!r} for {entry['identifier']!r}, and the dictionary has no such entry")
    for domain in vocabulary.get("domains", {}):
        if not re.search(r"\b" + re.escape(domain) + r"\b", text):
            problems.append(f"vocabulary declares the domain {domain!r} and the dictionary never names it")
    if "docs/vocabulary.json" not in text:
        problems.append("the dictionary does not name docs/vocabulary.json as its enforceable half")
    return problems


def missing_declared_paths(root, package_directory, config):
    """Every declared path, relative to the package directory, that does not exist."""
    declared = list(config.get("core_modules", []))
    for adapter in config.get("adapters", {}).values():
        declared += adapter.get("code", []) + adapter.get("flows", [])
    declared += config.get("orchestration_fallback", []) + config.get("console", [])
    return [path for path in declared if not os.path.exists(os.path.join(package_directory, path))]


def git_core_churn(root, package_directory, core_modules, baseline):
    if not baseline:
        return None
    paths = [os.path.join(package_directory, module) for module in core_modules]
    try:
        out = subprocess.run(["git", "-C", root, "diff", "--numstat", baseline, "--", *paths],
                             capture_output=True, text=True, timeout=30)
        if out.returncode != 0:
            return {"error": out.stderr.strip()[:120]}
        added = removed = files = 0
        for line in out.stdout.splitlines():
            columns = line.split("\t")
            if len(columns) >= 3 and columns[0].isdigit():
                added += int(columns[0])
                removed += int(columns[1]) if columns[1].isdigit() else 0
                files += 1
        return {"baseline": baseline, "core_files_changed": files, "lines_added": added, "lines_removed": removed}
    except Exception as error:
        return {"error": str(error)[:120]}


def run(root, config_path, baseline=None):
    """Every check over one tree. Returns (result, hard_failures); the caller decides about writing."""
    config = json.load(open(config_path, encoding="utf-8"))
    vocabulary = json.load(open(os.path.join(root, config["vocabulary"]), encoding="utf-8"))
    dictionary_path = os.path.join(root, config["dictionary"])
    package_directory = os.path.join(root, config["package_dir"])
    core = config["core_modules"]
    adapters = config["adapters"]
    all_adapter_code = [module for adapter in adapters.values() for module in adapter.get("code", [])]

    missing = missing_declared_paths(root, package_directory, config)
    violations = []
    for module in core:
        module_path = os.path.join(package_directory, module)
        if not os.path.exists(module_path):
            continue                                  # reported once, under missing declared paths
        for (line_number, domain, noun, text) in scan_domain_nouns(module_path, vocabulary["domains"]):
            violations.append({"file": module, "line": line_number, "kind": "domain-noun", "domain": domain, "noun": noun, "text": text,
                               "fix": f"the word belongs to the {domain} adapter; move the logic behind a port or rename the concept in core"})
        for (line_number, module_name) in scan_adapter_imports(module_path, all_adapter_code):
            violations.append({"file": module, "line": line_number, "kind": "adapter-import", "module": module_name,
                               "fix": "core must not import an adapter; invert the dependency through a port"})
    deprecated = [{"file": path, "line": line_number, "identifier": identifier, "canonical": canonical, "text": text,
                   "fix": f"use {canonical}; if this file must keep the old name alive, add it to allowed_paths in docs/vocabulary.json with the reason"}
                  for (path, line_number, identifier, canonical, text) in scan_deprecated(root, config.get("scan_roots", [config["package_dir"]]), vocabulary)]
    drift = vocabulary_drift(vocabulary, dictionary_path)

    core_loc = sum(loc(os.path.join(package_directory, module)) for module in core if os.path.exists(os.path.join(package_directory, module)))
    churn = git_core_churn(root, package_directory, core, baseline)
    scores = []
    for name, adapter in adapters.items():
        code_loc = sum(loc(os.path.join(package_directory, module)) for module in adapter.get("code", []))
        markdown_loc = sum(loc(os.path.join(package_directory, module)) for module in adapter.get("flows", []))
        total = code_loc + markdown_loc
        scores.append({"adapter": name, "code_loc": code_loc, "flow_md_loc": markdown_loc,
                       "pct_logic_in_md": round(markdown_loc / total, 3) if total else None})

    hard_failures = len(violations) + len(missing) + len(deprecated) + len(drift)
    result = {
        "signal_1_core_purity": {"PASS": not violations, "violations": violations},
        "declared_paths": {"PASS": not missing, "missing": missing,
                           "fix": "a declared module that no longer exists is removed from tools/arch_guard.config.json in the same change that removes the file"},
        "deprecated_identifiers": {"PASS": not deprecated, "findings": deprecated},
        "vocabulary_drift": {"PASS": not drift, "problems": drift},
        "signal_3_core_churn": {"core_total_loc": core_loc, "churn_since_baseline": churn,
                                "note": "track per adapter; must decay. flat or rising means rebuilding, not generalizing."},
        "signal_7_marginal_cost": {"adapters": scores,
                                   "note": "adapter N should cost less than adapter 1; a higher share of logic in Markdown is the point."},
        "unclassified_needs_triage": config.get("unclassified_needs_triage", []),
    }
    return result, hard_failures


def render_scorecard(result, core_count):
    violations = result["signal_1_core_purity"]["violations"]
    md = ["# PrismPath Architecture Scorecard", "",
          "_Generated by `tools/arch_guard.py`, do not hand edit. Signal 1, declared paths, deprecated identifiers and vocabulary drift are gated; 3 and 7 are trends._", "",
          f"## Signal 1: core purity: {'PASS' if not violations else 'FAIL (' + str(len(violations)) + ')'}"]
    if violations:
        md += ["| file | line | kind | detail |", "|---|---|---|---|"]
        for violation in violations[:60]:
            detail = f"{violation.get('domain', '')}:{violation.get('noun', '')}" if violation["kind"] == "domain-noun" else f"imports {violation.get('module', '')}"
            md.append(f"| `{violation['file']}` | {violation['line']} | {violation['kind']} | {detail} |")
    md += ["", f"## Declared paths: {'PASS' if result['declared_paths']['PASS'] else 'FAIL'}"]
    md += [f"- missing: `{path}`" for path in result["declared_paths"]["missing"]]
    md += ["", f"## Deprecated identifiers: {'PASS' if result['deprecated_identifiers']['PASS'] else 'FAIL'}"]
    md += [f"- `{finding['file']}:{finding['line']}` uses `{finding['identifier']}`; {finding['fix']}" for finding in result["deprecated_identifiers"]["findings"][:60]]
    md += ["", f"## Vocabulary drift: {'PASS' if result['vocabulary_drift']['PASS'] else 'FAIL'}"]
    md += [f"- {problem}" for problem in result["vocabulary_drift"]["problems"]]
    churn = result["signal_3_core_churn"]
    md += ["", "## Signal 3: core churn (trend)", f"- core total LOC: **{churn['core_total_loc']}** across {core_count} declared core modules",
           f"- churn since baseline: `{json.dumps(churn['churn_since_baseline'])}`", "",
           "## Signal 7: marginal adapter cost and share of logic in Markdown (trend)",
           "| adapter | code LOC | flow .md LOC | share of logic in .md |", "|---|---|---|---|"]
    for score in result["signal_7_marginal_cost"]["adapters"]:
        md.append(f"| {score['adapter']} | {score['code_loc']} | {score['flow_md_loc']} | {score['pct_logic_in_md']} |")
    md += ["", "## Unclassified modules (triage core vs adapter during a refactor)",
           ", ".join(f"`{module}`" for module in result["unclassified_needs_triage"]) or "none"]
    return "\n".join(md) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", default=os.path.join(HERE, "arch_guard.config.json"))
    parser.add_argument("--baseline", default=None, help="git ref to measure core churn since (Signal 3)")
    parser.add_argument("--root", default=ROOT, help="the repository root (default: this checkout)")
    args = parser.parse_args()
    result, hard_failures = run(args.root, args.config, args.baseline)
    config = json.load(open(args.config, encoding="utf-8"))
    scorecard_dir = os.path.join(args.root, "docs", "design")
    os.makedirs(scorecard_dir, exist_ok=True)
    with open(os.path.join(scorecard_dir, "arch-scorecard.md"), "w", encoding="utf-8") as scorecard_file:
        scorecard_file.write(render_scorecard(result, len(config["core_modules"])))
    with open(os.path.join(HERE, "arch_scorecard.json"), "w", encoding="utf-8") as json_file:
        json.dump(result, json_file, indent=2)
        json_file.write("\n")
    summary = {"PASS": hard_failures == 0, "hard_failures": hard_failures,
               "signal_1_violations": len(result["signal_1_core_purity"]["violations"]),
               "missing_declared_paths": result["declared_paths"]["missing"],
               "deprecated_identifier_findings": [f"{finding['file']}:{finding['line']} {finding['identifier']}" for finding in result["deprecated_identifiers"]["findings"][:12]],
               "vocabulary_drift": result["vocabulary_drift"]["problems"],
               "core_total_loc": result["signal_3_core_churn"]["core_total_loc"],
               "signal_7": result["signal_7_marginal_cost"]["adapters"]}
    print(json.dumps(summary, indent=2))
    return 1 if hard_failures else 0


if __name__ == "__main__":
    sys.exit(main())
