#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The architecture guard: the Dictionary's enforceable contract, checked, plus the adapter scorecard.

Seven things fail the build, each with the file, the line and what to do. The first four are the original contract.
  * a domain noun or an adapter import inside a CORE module (the hexagonal bright line, Signal 1);
  * a declared path that does not exist: a core module, an adapter's code or flow, an orchestration
    module, the console. A checker that skips a missing module is a checker that can be silenced by
    deleting the module, so absence is an error, never a skip;
  * a deprecated identifier used outside the paths that keep it alive on purpose (a shim that warns,
    the test that pins the warning) and outside certified paths, which never move;
  * vocabulary drift: a term named in docs/vocabulary.json with no entry in docs/DICTIONARY.md, or a
    domain the dictionary does not name, so the two files cannot part ways silently;
  * a production file that is in no layer, or in two, or a declared one that is gone (S1);
  * a wrong way import between layers, function level imports included, an adapter importing another adapter
    package, another module's private name used, or a file outside the onion that both decides and appends a
    receipt (S2, S3, S5, S7). Each is one line of tools/arch_baseline.json. A line that is not there fails, and
    so does a line there that is gone, so the file only shrinks (--shrink-baseline deletes, nothing adds);
  * on a branch named refactor-*, a path of tools/frozen_paths.txt that is modified, deleted or renamed against
    the merge base with main (G8).

The domain nouns, the deprecated identifiers and the certified paths come from docs/vocabulary.json,
the structured half of the Dictionary; the prose explains, this file enforces. Two trend signals are
reported and not gated: core churn since a baseline (Signal 3) and the marginal cost of each adapter
with its share of logic in Markdown (Signal 7).

Run: python tools/arch_guard.py [--baseline REF] [--shrink-baseline]. Dependency free (stdlib and git). Writes
docs/design/arch-scorecard.md (git ignored) and tools/arch_scorecard.json; exit 1 on any hard failure.
"""
import argparse
import ast
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


# ---- layers, import direction, private use, the governor rule, the baseline and the frozen paths (R0) ----

LAYER_RANK = {"kernel": 0, "ports": 1, "onion": 2, "adapter": 3, "surface": 4, "tooling": 5}
# importer layer -> the layers it may import. An adapter may import another adapter only inside its own package.
ALLOWED = {
    "kernel": {"kernel"},
    "ports": {"kernel", "ports"},
    "onion": {"kernel", "ports", "onion"},
    "adapter": {"kernel", "ports", "onion", "adapter"},
    "surface": {"kernel", "ports", "onion", "adapter", "surface"},
    "tooling": set(LAYER_RANK),
}
BASELINE_SECTIONS = ("import_direction", "private_use", "decides_outside_onion")


def production_files(package_directory, exempt_directories):
    """Every .py file under the package, relative to it, outside the exempt directory names."""
    found = []
    for directory, subdirectories, files in os.walk(package_directory):
        subdirectories[:] = sorted(name for name in subdirectories if name != "__pycache__" and name not in exempt_directories)
        for name in sorted(files):
            if name.endswith(".py"):
                found.append(os.path.relpath(os.path.join(directory, name), package_directory).replace(os.sep, "/"))
    return sorted(found)


def declared_layers(config):
    """({file: layer}, [problems]). A file declared twice is a problem."""
    table, problems = {}, []
    for layer, files in config.get("layers", {}).items():
        if layer not in LAYER_RANK:
            problems.append(f"the layer {layer!r} is not one of {', '.join(LAYER_RANK)}")
        for path in files:
            if path in table:
                problems.append(f"{path} is declared in two layers, {table[path]} and {layer}")
            table[path] = layer
    return table, problems


def layer_problems(package_directory, config):
    """(layer table, [problems]): a production file in no layer, and a declared file that is gone."""
    table, problems = declared_layers(config)
    present = production_files(package_directory, set(config.get("layer_exempt_dirs", ["tests"])))
    problems += [f"{path} is in no layer; declare it in tools/arch_guard.config.json" for path in present if path not in table]
    problems += [f"{path} is declared in a layer and does not exist; remove it from the config in the change that removes the file"
                 for path in sorted(table) if path not in set(present)]
    return table, problems


class Resolver:
    """Dotted module name to file, and the alias modules that only re export a moved module."""

    def __init__(self, package_directory, files):
        self.package_directory = package_directory
        self.files = set(files)
        self.aliases = {}

    def file_of(self, dotted):
        """The file of a dotted module name under prismpath, or None."""
        if dotted != "prismpath" and not dotted.startswith("prismpath."):
            return None
        relative = dotted[len("prismpath"):].lstrip(".").replace(".", "/")
        for candidate in ((relative + ".py") if relative else None, (relative + "/__init__.py") if relative else "__init__.py"):
            if candidate and candidate in self.files:
                return self.follow(candidate)
        return None

    def follow(self, path):
        """The file an alias module stands for, so an import of the old name is judged as the new one."""
        if path not in self.aliases:
            self.aliases[path] = None
            target = self.alias_target(path)
            self.aliases[path] = target
        return self.aliases[path] or path

    def alias_target(self, path):
        if "/" in path:
            return None
        try:
            with open(os.path.join(self.package_directory, path), encoding="utf-8") as handle:
                source = handle.read()
        except OSError:
            return None
        if "_sys.modules[__name__] = _m" not in source:
            return None
        match = re.search(r"^from (prismpath(?:\.\w+)*) import (\w+) as _m$", source, re.M)
        if not match:
            return None
        return self.file_of(match.group(1) + "." + match.group(2))

    def is_alias(self, path):
        self.follow(path)
        return self.aliases.get(path) is not None


def _is_type_checking(test):
    return (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or \
           (isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING")


def _is_main_guard(test):
    return (isinstance(test, ast.Compare) and isinstance(test.left, ast.Name) and test.left.id == "__name__"
            and len(test.comparators) == 1 and isinstance(test.comparators[0], ast.Constant)
            and test.comparators[0].value == "__main__")


def live_nodes(tree):
    """Every node of the tree except the body of `if TYPE_CHECKING:` and of `if __name__ == "__main__":` (S8).
    Function level imports are live."""
    stack = [tree]
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, ast.If) and (_is_type_checking(node.test) or _is_main_guard(node.test)):
            stack.append(node.test)
            stack.extend(node.orelse)
            continue
        stack.extend(ast.iter_child_nodes(node))


def _package_of(path):
    """The dotted package a file's relative imports start from."""
    parts = ["prismpath"] + path.split("/")[:-1]
    return parts


def import_targets(resolver, path, node):
    """[(file, bound name or None, module file or None)] for one Import or ImportFrom node. The third item is the
    module a bound name stands for, for the private use check."""
    out = []
    if isinstance(node, ast.Import):
        for item in node.names:
            target = resolver.file_of(item.name)
            if target is not None:
                bound = item.asname or item.name.split(".")[0]
                out.append((target, bound if item.asname else item.name, target))
        return out
    if node.level:
        base = _package_of(path)[:len(_package_of(path)) - (node.level - 1)]
        module = ".".join(base + ([node.module] if node.module else []))
    else:
        module = node.module or ""
    if not (module == "prismpath" or module.startswith("prismpath.")):
        return out
    base_file = resolver.file_of(module)
    for item in node.names:
        sub = resolver.file_of(module + "." + item.name) if item.name != "*" else None
        if sub is not None and sub != base_file:
            out.append((sub, item.asname or item.name, sub))
        elif base_file is not None:
            out.append((base_file, None, None))
    return out


def file_imports(resolver, path, tree):
    """(set of imported files, module aliases {name: file}) over the live nodes of one file."""
    imported, bound = set(), {}
    for node in live_nodes(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for target, name, module in import_targets(resolver, path, node):
                imported.add(target)
                if name is not None and module is not None:
                    bound[name] = module
    return imported, bound


def _is_private(name):
    return name.startswith("_") and not (name.startswith("__") and name.endswith("__"))


def dotted_name(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def private_uses(resolver, path, tree, bound):
    """[(target file, private name)] for every use of another module's private name in one file."""
    uses = []
    for node in live_nodes(tree):
        if isinstance(node, ast.ImportFrom):
            if node.level:
                base = _package_of(path)[:len(_package_of(path)) - (node.level - 1)]
                module_name = ".".join(base + ([node.module] if node.module else []))
            else:
                module_name = node.module or ""
            base_file = resolver.file_of(module_name)
            for item in node.names:
                if not _is_private(item.name):
                    continue
                target = resolver.file_of(module_name + "." + item.name) or base_file
                if target is not None and target != path:
                    uses.append((target, item.name))
        elif isinstance(node, ast.Attribute) and _is_private(node.attr):
            dotted = dotted_name(node.value)
            if dotted is None:
                continue
            target = bound.get(dotted) or resolver.file_of(dotted if dotted.startswith("prismpath") else "")
            if target is not None and target != path:
                uses.append((target, node.attr))
    return uses


def decides_outside_onion(tree):
    """True when one file both asks a policy to decide and appends to a run, which is the governor's sequence."""
    decides = appends = False
    for node in live_nodes(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "decide":
                decides = True
            elif node.func.attr == "append" and len(node.args) + len(node.keywords) >= 2:
                appends = True
    return decides and appends


def layer_findings(root, config):
    """({section: sorted lines}, [layer problems]) for the tree. Each line is one offending pair or site."""
    package_directory = os.path.join(root, config["package_dir"])
    table, problems = layer_problems(package_directory, config)
    resolver = Resolver(package_directory, table)
    allowed_pairs = {tuple(pair) for pair in config.get("adapter_allowed_pairs", [])}
    imports, private, deciders = set(), [], set()
    for path in sorted(table):
        if resolver.is_alias(path):
            if LAYER_RANK.get(table[path]) is not None and table.get(resolver.follow(path)) != table[path]:
                problems.append(f"{path} is an alias of {resolver.follow(path)} and must sit in its layer")
            continue
        try:
            with open(os.path.join(package_directory, path), encoding="utf-8") as handle:
                tree = ast.parse(handle.read(), filename=path)
        except (OSError, SyntaxError) as error:
            problems.append(f"{path} cannot be parsed ({type(error).__name__})")
            continue
        layer = table[path]
        files, bound = file_imports(resolver, path, tree)
        for target in files:
            if target == path or target not in table:
                continue
            other = table[target]
            if other in ALLOWED[layer]:
                if layer == "adapter" and other == "adapter" and path.split("/")[0] != target.split("/")[0] \
                        and (path.split("/")[0], target.split("/")[0]) not in allowed_pairs:
                    imports.add(f"{path} -> {target} (adapter -> adapter, another package)")
                continue
            imports.add(f"{path} -> {target} ({layer} -> {other})")
        counts = {}
        for target, name in private_uses(resolver, path, tree, bound):
            key = f"{path} -> {target} :: {name}"
            counts[key] = counts.get(key, 0) + 1
            private.append(f"{key} #{counts[key]}")
        if layer not in ("onion", "tooling") and decides_outside_onion(tree):
            deciders.add(path)
    return {"import_direction": sorted(imports), "private_use": sorted(private),
            "decides_outside_onion": sorted(deciders)}, problems


def read_baseline(path):
    if not os.path.exists(path):
        return {section: [] for section in BASELINE_SECTIONS}
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    return {section: list(data.get(section, [])) for section in BASELINE_SECTIONS}


def write_baseline(path, sections):
    """One line per entry, sorted, so two branches that delete different lines merge by line."""
    doc = ("The ratchet. One line per offending import pair, per private use and per file that decides outside the onion. "
           "A line that is not here fails tools/arch_guard.py, and so does a line here that no longer exists. "
           "The file only loses lines. Delete them with python tools/arch_guard.py --shrink-baseline.")
    lines = ["{", f'  "_doc": {json.dumps(doc)},']
    for index, section in enumerate(BASELINE_SECTIONS):
        entries = sorted(set(sections[section]))
        lines.append(f'  "{section}": [' + ("]" if not entries else ""))
        if entries:
            lines += ["    " + json.dumps(entry) + ("," if position < len(entries) - 1 else "") for position, entry in enumerate(entries)]
            lines.append("  ]")
        lines[-1] += "," if index < len(BASELINE_SECTIONS) - 1 else ""
    lines.append("}")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def compare_baseline(found, baseline):
    """({section: new lines}, {section: stale lines})."""
    new = {section: sorted(set(found[section]) - set(baseline[section])) for section in BASELINE_SECTIONS}
    stale = {section: sorted(set(baseline[section]) - set(found[section])) for section in BASELINE_SECTIONS}
    return new, stale


FROZEN_BRANCH = re.compile(r"^refactor-")


def current_branch(root):
    for variable in ("GITHUB_HEAD_REF", "GITHUB_REF_NAME"):
        if os.environ.get(variable):
            return os.environ[variable]
    out = subprocess.run(["git", "-C", root, "rev-parse", "--abbrev-ref", "HEAD"], capture_output=True, text=True)
    return out.stdout.strip() if out.returncode == 0 else ""


def frozen_findings(root, frozen_file, branch=None, base_ref=None):
    """([changed frozen paths as 'S path'], note). Only a branch named refactor-* is held to the list (G8).
    Added files are allowed; modified, deleted and renamed files fail against the merge base with origin/main."""
    branch = current_branch(root) if branch is None else branch
    if not FROZEN_BRANCH.match(branch):
        return [], f"branch {branch!r} is not a refactor branch, so the frozen paths are not held"
    try:
        with open(frozen_file, encoding="utf-8") as handle:
            specs = [line.strip() for line in handle if line.strip() and not line.startswith("#")]
    except OSError:
        return [f"? {frozen_file} is missing"], "the frozen paths file is missing"
    refs = [base_ref] if base_ref else ["origin/main", "main"]
    for ref in refs:
        base = subprocess.run(["git", "-C", root, "merge-base", ref, "HEAD"], capture_output=True, text=True)
        if base.returncode == 0 and base.stdout.strip():
            break
    else:
        return [f"? no merge base with {' or '.join(refs)}, so the frozen paths cannot be checked"], "no merge base"
    diff = subprocess.run(["git", "-C", root, "diff", "--name-status", "-M", "--diff-filter=MDR", base.stdout.strip(), "HEAD", "--", *specs],
                          capture_output=True, text=True)
    if diff.returncode != 0:
        return [f"? git diff failed ({diff.stderr.strip()[:120]})"], "git diff failed"
    changed = [" ".join(line.split("\t")) for line in diff.stdout.splitlines() if line.strip()]
    return changed, f"merge base {base.stdout.strip()[:10]}"


def run(root, config_path, baseline=None, branch=None):
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

    found, layer_issues = layer_findings(root, config)
    baseline = read_baseline(os.path.join(root, config.get("baseline", "tools/arch_baseline.json")))
    new_lines, stale_lines = compare_baseline(found, baseline)
    frozen, frozen_note = frozen_findings(root, os.path.join(root, config.get("frozen_paths", "tools/frozen_paths.txt")), branch=branch)
    ratchet_failures = sum(len(lines) for lines in new_lines.values()) + sum(len(lines) for lines in stale_lines.values())

    hard_failures = len(violations) + len(missing) + len(deprecated) + len(drift) + len(layer_issues) + ratchet_failures + len(frozen)
    result = {
        "signal_1_core_purity": {"PASS": not violations, "violations": violations},
        "declared_paths": {"PASS": not missing, "missing": missing,
                           "fix": "a declared module that no longer exists is removed from tools/arch_guard.config.json in the same change that removes the file"},
        "deprecated_identifiers": {"PASS": not deprecated, "findings": deprecated},
        "vocabulary_drift": {"PASS": not drift, "problems": drift},
        "layers": {"PASS": not layer_issues, "problems": layer_issues,
                   "fix": "every production file is in exactly one layer of tools/arch_guard.config.json (refactor plan 1.3)"},
        "ratchet": {"PASS": ratchet_failures == 0, "counts": {section: len(found[section]) for section in BASELINE_SECTIONS},
                    "baseline_counts": {section: len(baseline[section]) for section in BASELINE_SECTIONS},
                    "new": new_lines, "stale": stale_lines,
                    "fix": "a new line is a wrong way import, a private use or a decision outside the onion that this change added, so remove it. "
                           "a stale line was fixed, so delete it with python tools/arch_guard.py --shrink-baseline. The baseline file only loses lines."},
        "frozen_paths": {"PASS": not frozen, "changed": frozen, "note": frozen_note,
                         "fix": "a refactor branch may add to a frozen path and may not modify, delete or rename one (G8, tools/frozen_paths.txt)"},
        "signal_3_core_churn": {"core_total_loc": core_loc, "churn_since_baseline": churn,
                                "note": "track per adapter; must decay. flat or rising means rebuilding, not generalizing."},
        "signal_7_marginal_cost": {"adapters": scores,
                                   "note": "adapter N should cost less than adapter 1; a higher share of logic in Markdown is the point."},
        "unclassified_needs_triage": config.get("unclassified_needs_triage", []),
    }
    return result, hard_failures


def render_scorecard(result, core_count):
    violations = result["signal_1_core_purity"]["violations"]
    lines = ["# PrismPath Architecture Scorecard", "",
          "_Generated by `tools/arch_guard.py`, do not hand edit. Signal 1, declared paths, deprecated identifiers and vocabulary drift are gated; 3 and 7 are trends._", "",
          f"## Signal 1: core purity: {'PASS' if not violations else 'FAIL (' + str(len(violations)) + ')'}"]
    if violations:
        lines += ["| file | line | kind | detail |", "|---|---|---|---|"]
        for violation in violations[:60]:
            detail = f"{violation.get('domain', '')}:{violation.get('noun', '')}" if violation["kind"] == "domain-noun" else f"imports {violation.get('module', '')}"
            lines.append(f"| `{violation['file']}` | {violation['line']} | {violation['kind']} | {detail} |")
    lines += ["", f"## Declared paths: {'PASS' if result['declared_paths']['PASS'] else 'FAIL'}"]
    lines += [f"- missing: `{path}`" for path in result["declared_paths"]["missing"]]
    lines += ["", f"## Deprecated identifiers: {'PASS' if result['deprecated_identifiers']['PASS'] else 'FAIL'}"]
    lines += [f"- `{finding['file']}:{finding['line']}` uses `{finding['identifier']}`; {finding['fix']}" for finding in result["deprecated_identifiers"]["findings"][:60]]
    lines += ["", f"## Vocabulary drift: {'PASS' if result['vocabulary_drift']['PASS'] else 'FAIL'}"]
    lines += [f"- {problem}" for problem in result["vocabulary_drift"]["problems"]]
    churn = result["signal_3_core_churn"]
    lines += ["", "## Signal 3: core churn (trend)", f"- core total LOC: **{churn['core_total_loc']}** across {core_count} declared core modules",
           f"- churn since baseline: `{json.dumps(churn['churn_since_baseline'])}`", "",
           "## Signal 7: marginal adapter cost and share of logic in Markdown (trend)",
           "| adapter | code LOC | flow .md LOC | share of logic in .md |", "|---|---|---|---|"]
    for score in result["signal_7_marginal_cost"]["adapters"]:
        lines.append(f"| {score['adapter']} | {score['code_loc']} | {score['flow_md_loc']} | {score['pct_logic_in_md']} |")
    lines += ["", "## Unclassified modules (triage core vs adapter during a refactor)",
           ", ".join(f"`{module}`" for module in result["unclassified_needs_triage"]) or "none"]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", default=os.path.join(HERE, "arch_guard.config.json"))
    parser.add_argument("--baseline", default=None, help="git ref to measure core churn since (Signal 3)")
    parser.add_argument("--root", default=ROOT, help="the repository root (default: this checkout)")
    parser.add_argument("--branch", default=None, help="the branch name the frozen paths check uses (default: the checked out branch)")
    parser.add_argument("--shrink-baseline", action="store_true",
                        help="delete the baseline lines that no longer exist. It never adds a line")
    parser.add_argument("--regenerate-baseline", action="store_true",
                        help="write the baseline whole from the tree. Only the contract package and a merge of main use this")
    args = parser.parse_args()
    config = json.load(open(args.config, encoding="utf-8"))
    if args.shrink_baseline or args.regenerate_baseline:
        baseline_path = os.path.join(args.root, config.get("baseline", "tools/arch_baseline.json"))
        found, _issues = layer_findings(args.root, config)
        if args.regenerate_baseline:
            write_baseline(baseline_path, found)
            print("baseline written: " + ", ".join(f"{section} {len(found[section])}" for section in BASELINE_SECTIONS))
        else:
            old = read_baseline(baseline_path)
            kept = {section: [line for line in old[section] if line in set(found[section])] for section in BASELINE_SECTIONS}
            write_baseline(baseline_path, kept)
            print("baseline shrunk: " + ", ".join(f"{section} {len(old[section])} to {len(kept[section])}" for section in BASELINE_SECTIONS))
    result, hard_failures = run(args.root, args.config, args.baseline, args.branch)
    scorecard_dir = os.path.join(args.root, "docs", "design")
    os.makedirs(scorecard_dir, exist_ok=True)
    with open(os.path.join(scorecard_dir, "arch-scorecard.md"), "w", encoding="utf-8") as scorecard_file:
        scorecard_file.write(render_scorecard(result, len(config["core_modules"])))
    with open(os.path.join(args.root, "tools", "arch_scorecard.json"), "w", encoding="utf-8") as json_file:
        json.dump(result, json_file, indent=2)
        json_file.write("\n")
    summary = {"PASS": hard_failures == 0, "hard_failures": hard_failures,
               "signal_1_violations": len(result["signal_1_core_purity"]["violations"]),
               "missing_declared_paths": result["declared_paths"]["missing"],
               "deprecated_identifier_findings": [f"{finding['file']}:{finding['line']} {finding['identifier']}" for finding in result["deprecated_identifiers"]["findings"][:12]],
               "vocabulary_drift": result["vocabulary_drift"]["problems"],
               "layer_problems": result["layers"]["problems"][:12],
               "baseline_new": result["ratchet"]["new"], "baseline_stale": result["ratchet"]["stale"],
               "frozen_paths_changed": result["frozen_paths"]["changed"],
               "core_total_loc": result["signal_3_core_churn"]["core_total_loc"],
               "signal_7": result["signal_7_marginal_cost"]["adapters"]}
    print(json.dumps(summary, indent=2))
    return 1 if hard_failures else 0


if __name__ == "__main__":
    sys.exit(main())
