# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Flow authoring, static analysis, testing, and tooling commands."""
import argparse
import json
import os
import sys

from prismpath import flow_files
from prismpath.cli.common import parse_flow, report_findings
from prismpath.kernel import analysis

# `compile` bundles the standalone JavaScript engine, which only the research repository carries. The
# module that does it is excluded from the product repository's export, so there the command is
# registered only so an explicit call fails with a clear message.
try:
    from prismpath import bundle_compile
except ImportError:
    bundle_compile = None


def register(subparsers) -> None:
    # Flow authoring, static analysis, and testing commands.
    init_parser = subparsers.add_parser(
        'init', help='Scaffold a starter flow - zero to a running, validated flow in two commands')
    init_parser.add_argument('path', nargs='?', default=None,
                             help='where to write the flow; .md is added when missing, and the tests go '
                                  'beside it as <name>.tests.md (default: ./flow.md, or ./<template>.md)')
    init_parser.add_argument('--template', default=None, metavar='NAME',
                             help="start from a gallery flow instead of the generic starter "
                                  "(`--template list` shows what's available); copies the flow AND "
                                  "its routing tests")
    init_parser.set_defaults(func=init_cmd)

    validate_parser = subparsers.add_parser(
        'validate', help='Static analysis: does the flow compile? (fast, no model)')
    validate_parser.add_argument('flow_md', type=str, help='Path to the flow markdown file')
    validate_parser.add_argument('--json', action='store_true', help='machine-readable findings')
    validate_parser.set_defaults(func=validate_flow)

    test_parser = subparsers.add_parser(
        'test', help='Assert a flow\'s routing from a Markdown fixture (no LLM)')
    test_parser.add_argument('flow_md', type=str, help='Path to the flow markdown file')
    test_parser.add_argument('tests_md', nargs='?', default=None,
                             help='fixture file (default <flow>.tests.md)')
    test_parser.add_argument('--json', action='store_true', help='machine-readable results')
    test_parser.add_argument('--emit-labels', default=None, metavar='PATH',
                             help='append each case as a labeled routing record (JSONL)')
    test_parser.set_defaults(func=test_flow)

    graph_parser = subparsers.add_parser(
        'graph', help='Render the flow as a Mermaid diagram (solid=deterministic, dashed=semantic)')
    graph_parser.add_argument('flow_md', type=str, help='Path to the flow markdown file')
    graph_parser.add_argument('--direction', default='TD', choices=['TD', 'LR'], help='layout direction')
    graph_parser.add_argument('--fenced', action='store_true', help='wrap in a ```mermaid fence for READMEs')
    graph_parser.set_defaults(func=graph_flow)

    lint_parser = subparsers.add_parser(
        'lint', help='Static analysis + semantic-ambiguity check (needs the embedder)')
    lint_parser.add_argument('flow_md', type=str, help='Path to the flow markdown file')
    lint_parser.add_argument('--json', action='store_true', help='machine-readable findings')
    lint_parser.set_defaults(func=lint_flow)

    contract_parser = subparsers.add_parser(
        'contract', help="Derive each node's worker output schema from its `when` edges")
    contract_parser.add_argument('flow_md', type=str, help='Path to the flow markdown file')
    contract_parser.add_argument('--json', action='store_true',
                                 help='emit the per-node schemas as JSON (constrained-decoding grammar)')
    contract_parser.set_defaults(func=contract_cmd)

    if bundle_compile:
        compile_parser = subparsers.add_parser(
            'compile', help='Compile a flow and its lock into a single-file portable JS bundle')
        compile_parser.add_argument('flow_md', type=str, help='Path to the flow markdown file')
        compile_parser.add_argument('--tier', choices=['p0', 'p1'], required=True,
                                    help='portability tier to compile (p0: ML-free, p1: embedded locked vectors)')
        compile_parser.add_argument('--out', default=None, help='output path for the .mjs bundle (default: <flow>.bundle.mjs)')
        compile_parser.set_defaults(func=bundle_compile.compile_cmd)
    else:
        # `compile` built a single file JavaScript bundle around the standalone JS engine, which this
        # distribution does not carry. The name stays registered, out of the grouped help, so an explicit
        # call fails with a clear message and a nonzero exit instead of an argparse "invalid choice".
        compile_parser = subparsers.add_parser('compile', help=argparse.SUPPRESS)
        compile_parser.add_argument('flow_md', nargs='?', default=None)
        compile_parser.add_argument('--tier', default=None)
        compile_parser.add_argument('--out', default=None)
        compile_parser.set_defaults(func=compile_unavailable_cmd)

    portable_parser = subparsers.add_parser(
        'portable', help='Is this flow (and its @spawn children) in the ML-free portable subset? '
                         'Portable flows run on any conformant kernel, the Rust crate included')
    portable_parser.add_argument('flow_md', type=str, help='Path to the flow markdown file')
    portable_parser.add_argument('--json', action='store_true', help='machine-readable findings')
    portable_parser.set_defaults(func=portable_cmd)

    plugins_parser = subparsers.add_parser(
        'plugins', help='Audit the plugin ecosystem: list installed plugins, or verify a flow\'s '
                        '@worker bindings all resolve (--check)')
    plugins_parser.add_argument('--json', action='store_true', help='machine-readable listing (CI)')
    plugins_parser.add_argument('--check', metavar='FLOW', default=None,
                                help='verify every @worker binding in FLOW resolves; exit 1 otherwise')
    plugins_parser.add_argument('--new', metavar='NAME', default=None,
                                help='scaffold a pip-installable WORKER PACK: a package that '
                                     'registers itself via the prismpath.plugins entry point - '
                                     'pip install it and its workers are @worker-bindable')
    plugins_parser.set_defaults(func=plugins_cmd)

    import_parser = subparsers.add_parser(
        'import', help='Import a LangGraph StateGraph (.py) as a skeleton flow (with TODO conditions)')
    import_parser.add_argument('py_file', type=str, help='the LangGraph Python file')
    import_parser.add_argument('--name', default='imported', help='flow name')
    import_parser.add_argument('--out', default=None, help='write the .md flow here (else stdout)')
    import_parser.set_defaults(func=import_cmd)

    from prismpath.ci_report import add_parser as _add_ci_report
    _add_ci_report(subparsers)

    from prismpath.kernel.model_check import add_parser as _add_verify
    _add_verify(subparsers)

    from prismpath.lsp import add_parser as _add_lsp
    _add_lsp(subparsers)


def import_cmd(args) -> int:
    from prismpath.workers import langgraph_import
    with open(args.py_file, encoding="utf-8") as fh:
        py_content = fh.read()
    md = langgraph_import.import_langgraph(py_content, name=args.name)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(md)
        print(f"wrote {args.out} - fill in the TODO conditions, then `prismpath validate` it")
    else:
        print(md)
    return 0


def graph_flow(args) -> int:
    from prismpath.kernel import graph_export
    graph = parse_flow(args.flow_md)
    out = (graph_export.to_mermaid_fenced if args.fenced else graph_export.to_mermaid)(graph, args.direction)
    print(out)
    return 0


def test_flow(args) -> int:
    from prismpath.kernel import flow_test
    from prismpath.kernel.parser import parse_file
    tests_path = args.tests_md or flow_test.default_tests_path(args.flow_md)
    if not os.path.exists(tests_path):
        print(f"no fixture found: {tests_path}")
        return 2
    report = flow_test.run_tests(args.flow_md, tests_path)
    if args.emit_labels:
        count_written = flow_test.emit_labels(report, parse_file(args.flow_md).name, args.emit_labels)
        print(f"wrote {count_written} labeled records to {args.emit_labels}")
    if args.json:
        print(json.dumps({"passed": report.passed, "failed": report.failed,
                          "cases": [vars(res) for res in report.results]}, indent=2))
        return 0 if report.ok else 1
    for res in report.results:
        mark = "✓" if res.ok else "✗"
        line = f"  {mark} [{res.node}] --{res.how}--> {res.got}  (expect {res.expect})"
        if not res.ok and res.detail:
            line += f"  - {res.detail}"
        print(line)
    print(f"\n{report.passed}/{len(report.results)} passed"
          + ("" if report.ok else f", {report.failed} FAILED"))
    return 0 if report.ok else 1


def validate_flow(args) -> int:
    graph = parse_flow(args.flow_md)
    findings = list(analysis.analyze(graph))
    findings += flow_files.analyze_composition(graph, args.flow_md)   # cross-flow @spawn checks (item #4)
    findings += analysis.analyze_authoring(graph)                     # typos the parser keeps as meta or prose
    return report_findings(findings, args.json)


def contract_cmd(args) -> int:
    """Print each node's derived worker output contract (the fields its `when` edges read, with
    inferred types). Non-zero exit iff a field is used two incompatible ways (a real authoring bug)."""
    from prismpath.kernel import contract
    graph = parse_flow(args.flow_md)
    contract_dict = contract.derive_contract(graph)
    if args.json:
        print(json.dumps({node_name: contract.to_json_schema(field_specs) for node_name, field_specs in contract_dict.items() if field_specs}, indent=2))
    else:
        print(contract.describe(contract_dict))
    conflicts = [(node_name, field_name) for node_name, field_specs in contract_dict.items() for field_name, field_spec in field_specs.items() if field_spec.get("conflict")]
    for node_name, field_name in conflicts:
        print(f"  ✗ [{node_name}] field {field_name!r}: {contract_dict[node_name][field_name]['conflict']}")
    return 1 if conflicts else 0


def _new_worker_pack(name: str) -> int:
    """Scaffold `prismpath-<name>/` - a pip-installable worker pack. One `pip install -e` later its
    workers are visible in `prismpath plugins` (entry-point source) and bindable with
    `@worker(<name>.<worker>)`. The generated example shows both worker shapes: a pure function,
    and a CLI wrapped via `prismpath.cli_worker.CliWorker` (commented - the 'any tool is a worker'
    bridge)."""
    import re as _re
    if not _re.fullmatch(r"[a-z][a-z0-9_]*", name):
        print(f"✗ pack name {name!r} must be lowercase [a-z0-9_], starting with a letter")
        return 1
    root = f"prismpath-{name.replace('_', '-')}"
    mod = f"prismpath_{name}"
    if os.path.exists(root):
        print(f"✗ {root}/ already exists")
        return 1
    os.makedirs(os.path.join(root, mod))
    os.makedirs(os.path.join(root, "tests"))

    def write_file(rel_path: str, text_content: str) -> None:
        with open(os.path.join(root, rel_path), "w", encoding="utf-8") as fh:
            fh.write(text_content)

    write_file("pyproject.toml", f'''[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "{root}"
version = "0.1.0"
description = "A worker pack for prismpath flows - bind with @worker({name}.<worker>)"
requires-python = ">=3.10"

# THE integration point: this line is what makes `pip install` enough. The registry discovers the
# pack through the entry-point group and `prismpath plugins` lists it with source "entry-point".
[project.entry-points."prismpath.plugins"]
{name} = "{mod}"

[tool.setuptools]
packages = ["{mod}"]
''')
    write_file(os.path.join(mod, "__init__.py"), f'''"""{name} - a prismpath worker pack.

Workers are plain callables `(node, instruction, state) -> outcome` (a dict outcome routes on its
fields; a string routes semantically). Flows bind them by name in the document:

    ## mynode
    Do the thing.
    @worker({name}.hello)
    -> done: always

`prismpath plugins --check flow.md` verifies bindings resolve; dispatched outcomes carry `_worker`
provenance automatically.
"""

NAME = "{name}"
VERSION = "0.1.0"
DESCRIPTION = "example worker pack (edit me)"


def hello(node, instruction, state):
    """A pure example worker: echoes the node instruction as its outcome."""
    return {{"text": f"hello from {name}: {{instruction}}", "ok": True}}


# The 'any CLI is a worker' bridge - wrap a real tool in ~3 lines (uncomment + edit):
#   from prismpath.workers.cli_worker import CliWorker
#   jq = CliWorker(["jq", "-c", ".summary", "{{instruction}}"])   # JSON stdout -> outcome fields
WORKERS = {{"hello": hello}}
''')
    write_file(os.path.join("tests", "test_workers.py"), f'''from {mod} import WORKERS


def test_hello_outcome_shape():
    out = WORKERS["hello"]("n", "greet the world", {{}})
    assert out["ok"] is True and "greet the world" in out["text"]
''')
    write_file("README.md", f'''# {root}

A worker pack for prismpath flows. Install it and its workers are bindable in any flow document:

```bash
pip install -e .          # registers the `{name}` plugin via the prismpath.plugins entry point
prismpath plugins            # -> {name} 0.1.0 [entry-point] - workers: hello
```

```markdown
## mynode
Do the thing.
@worker({name}.hello)
-> done: always
```

Add workers to `WORKERS` in `{mod}/__init__.py` - plain `(node, instruction, state) -> outcome`
callables. To wrap an existing CLI as a worker, see the `CliWorker` example in the module.
''')
    print(f"✓ scaffolded {root}/ - a pip-installable worker pack")
    print(f"    {root}/pyproject.toml            the prismpath.plugins entry point ({name} = {mod})")
    print(f"    {root}/{mod}/__init__.py    WORKERS: hello (edit me)")
    print(f"    {root}/tests/test_workers.py    pytest")
    print(f"\nNext: cd {root} && pip install -e . && prismpath plugins   # it appears as [entry-point]")
    return 0


STARTER_FLOW = '''---
name: triage
start: classify
---

## classify
Read the incoming report and classify it.
-> handle_bug: when kind == "bug"
-> handle_question: when kind == "question"
-> escalate: the report is urgent or describes an outage
-> handle_question: the report is a routine request

## handle_bug
Reproduce the bug and file it with repro steps.
-> done: always

## handle_question
Answer the question from the docs.
-> done: always

## escalate
Page the on-call human with the report.
-> done: always

## done
Finished.
'''


STARTER_TESTS = '''# Routing tests for the starter flow - `prismpath test flow.md` (no model needed)

| node     | outcome                                   | fields          | expect          |
|----------|-------------------------------------------|-----------------|-----------------|
| classify | the dashboard crashes on load             | kind=bug        | handle_bug      |
| classify | how do I export my data?                  | kind=question   | handle_question |
'''


def _gallery_dir() -> str:
    """The gallery ships inside the package (under prismpath/ in both repo layouts)."""
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "gallery")


def gallery_templates() -> dict:
    """{name: dir} for every gallery entry that has the template pair (<name>.md + <name>.tests.md)."""
    out = {}
    root_dir = _gallery_dir()
    if os.path.isdir(root_dir):
        for name in sorted(os.listdir(root_dir)):
            template_dir = os.path.join(root_dir, name)
            if os.path.isfile(os.path.join(template_dir, f"{name}.md")) and \
               os.path.isfile(os.path.join(template_dir, f"{name}.tests.md")):
                out[name] = template_dir
    return out


def init_cmd(args) -> int:
    """Scaffold a starter flow + its routing tests, and print the model-free commands that make them
    do something. Bare: the generic triage starter (deterministic `when` + semantic edges - editing
    it teaches the format). `--template <name>`: start from a real gallery flow instead - every
    gallery entry doubles as a starter."""
    templates = gallery_templates()
    if args.template == "list":
        if not templates:
            print("no gallery templates found")
            return 1
        print("gallery templates (prismpath init --template <name>):")
        for name, template_dir in templates.items():
            first = ""
            readme = os.path.join(template_dir, "README.md")
            if os.path.isfile(readme):
                with open(readme, encoding="utf-8") as fh:
                    lines = [line.strip() for line in fh if line.strip() and not line.startswith("#")]
                first = f" - {lines[0][:90]}" if lines else ""
            print(f"  {name}{first}")
        return 0

    if args.template is not None:
        if args.template not in templates:
            print(f"✗ no gallery template {args.template!r} (have: {', '.join(templates) or 'none'}; "
                  f"see `prismpath init --template list`)")
            return 1
        src = templates[args.template]
        if args.path:
            print("(note: <path> is ignored with --template - template files keep their names, "
                  "because flows may reference each other, e.g. an @spawn child)")
        # copy EVERY .md in the entry, names preserved: the flow, its tests, and any companion
        # flows (a fan-out's child, a sub-flow) - templates are self-contained working sets.
        parts = sorted(file_item for file_item in os.listdir(src) if file_item.endswith(".md") and file_item != "README.md")
        for file_item in parts:
            if os.path.exists(file_item):
                print(f"✗ {file_item} already exists - init this template in an empty/other directory")
                return 1
        for file_item in parts:
            with open(os.path.join(src, file_item), encoding="utf-8") as f_in, \
                 open(file_item, "w", encoding="utf-8") as f_out:
                f_out.write(f_in.read())
        flow_path = f"{args.template}.md"
        others = [file_item for file_item in parts if file_item != flow_path]
        print(f"✓ wrote {flow_path} - the {args.template!r} gallery flow")
        print(f"✓ wrote {', '.join(others)}\n")
    else:
        flow_path = args.path or "flow.md"
        if not flow_path.endswith(".md"):
            flow_path += ".md"           # `init demo` writes demo.md, like every other flow
        tests_path = os.path.splitext(flow_path)[0] + ".tests.md"
        for path_item in (flow_path, tests_path):
            if os.path.exists(path_item):
                print(f"✗ {path_item} already exists - pick another path (prismpath init <path>)")
                return 1
        with open(flow_path, "w", encoding="utf-8") as fh:
            fh.write(STARTER_FLOW)
        with open(tests_path, "w", encoding="utf-8") as fh:
            fh.write(STARTER_TESTS)
        print(f"✓ wrote {flow_path} - a triage flow (deterministic `when` + semantic edges)")
        print(f"✓ wrote {tests_path} - routing scenarios as a Markdown table\n")

    print("Next (no model, no config needed):")
    print(f"  prismpath validate {flow_path}     # static analysis: does the flow compile?")
    print(f"  prismpath test {flow_path}         # assert the routing table routes as written")
    print(f"  prismpath graph {flow_path}        # render it as a Mermaid diagram")
    print("\nThen make it yours: edit the nodes, add test rows for the semantic edges")
    print("(pip install 'prismpath[embeddings]' exercises those + `prismpath run`), wire a real")
    print("agent (GETTING_STARTED.md), or bind tools with @worker (prismpath plugins).")
    return 0


def plugins_cmd(args) -> int:
    """Audit the plugin ecosystem. Bare: list every discovered plugin (bundled + entry-point) with
    what it provides. `--check FLOW`: verify every `@worker` binding in the flow resolves against
    what is installed - the CI gate that keeps a flow from reaching a host missing its tools.
    `--new NAME`: scaffold a pip-installable worker pack."""
    from prismpath.plugins import registry
    if args.new:
        return _new_worker_pack(args.new)
    if args.check:
        graph = parse_flow(args.check)
        problems = registry.check_flow(graph)
        if problems:
            print(f"✗ {len(problems)} unresolved @worker binding(s):")
            for problem in problems:
                print(f"  ✗ {problem}")
            return 1
        bound = sum(1 for node_obj in graph.nodes.values() if "worker" in node_obj.annotations)
        print(f"✓ all @worker bindings resolve ({bound} bound node(s))")
        return 0
    print(registry.audit(as_json=args.json))
    return 0


def portable_cmd(args) -> int:
    """Report the flow's portability TIER - for the whole composition tree (`@spawn` children
    included). P0 = ML-free (runs on any conformant kernel, the Rust crate included); P1 = all reachable semantic
    edges are pinned in the lockfile, so routing needs only an outcome-side embedder (ONNX-able -
    appliance/edge); P2 = semantic edges not fully locked (full stack). Exit 0 iff P0 (unchanged
    contract: "portable" means the ML-free subset)."""
    graph = parse_flow(args.flow_md)
    tree = flow_files.portability_tier_tree(graph, args.flow_md)
    if args.json:
        out = {"tier": tree["tier"],
               "flows": {path_str: {"tier": details["tier"],
                             "semantic_edges": [{"node": node_name, "target": target, "condition": condition}
                                                for node_name, target, condition in details["semantic_edges"]],
                             "unlocked": details["unlocked"], "lock": details["lock"],
                             "lock_error": details.get("lock_error")}
                         for path_str, details in tree["flows"].items()}}
        print(json.dumps(out, indent=2))
        return 0 if tree["tier"] == "P0" else 1
    blurb = {
        "P0": "P0 ✅  - every reachable edge is decidable (when/error/event); no ML runtime needed. "
              "Runs on any conformant kernel (the Rust crate in this distribution, or an edge appliance).",
        "P1": "P1 🔒  - semantic edges present, ALL pinned in the lockfile: routing needs only an "
              "outcome-side embedder at runtime (ONNX-able). Appliance/edge-deployable with the lock.",
        "P2": "P2      - semantic edges not fully covered by a lock; needs the full engine "
              "(live embedding / LLM escalation). Run `prismpath lock` to reach P1, or rewrite the "
              "edges as `when` predicates to reach P0.",
    }
    print(blurb[tree["tier"]])
    for path_str, details in tree["flows"].items():
        if details["tier"] == "P0" and len(tree["flows"]) == 1:
            continue
        extra = f" (lock: {details['lock']})" if details["lock"] else ""
        print(f"  {details['tier']}  {path_str}{extra}")
        if details.get("lock_error"):
            # a present but unreadable lock reads as P2 as well, so say why rather than let the
            # operator conclude the flow was never locked
            print(f"        ! lockfile could not be read, treated as no lock: {details['lock_error']}")
        for node_name, target, condition in details["semantic_edges"]:
            mark = "unlocked" if condition in details["unlocked"] else "locked"
            print(f"        [{node_name}] -> {target}: {condition!r}  ({mark})")
    return 0 if tree["tier"] == "P0" else 1


def compile_unavailable_cmd(args) -> int:
    """Refuse the JavaScript bundle compile: the engine it bundles is not in this distribution.

    The research repository carries the standalone JavaScript kernel and the bundle compiler. Here the
    portable subset is still checked by `prismpath portable`, and a Level M flow compiles to a table
    image with `python -m prismpath.kernel.ppt_compile`."""
    print("prismpath compile is not available in this distribution: the standalone JavaScript engine "
          "it bundles is not shipped. Use `prismpath portable` to check the portable subset, or "
          "`python -m prismpath.kernel.ppt_compile` for a Level M table image. The bundle compiler "
          "lives in the research repository, crystal-warden/prism-path.", file=sys.stderr)
    return 2


def lint_flow(args) -> int:
    graph = parse_flow(args.flow_md)
    findings = list(analysis.analyze(graph))
    findings += flow_files.analyze_composition(graph, args.flow_md)   # cross-flow @spawn checks (item #4)
    # the non-decidable checks (need the embedder): near-ties, and polarity mirrors (the 0.82 class).
    from prismpath.kernel.lint import semantic_ambiguity, polarity_mirror
    findings += semantic_ambiguity(graph)
    findings += polarity_mirror(graph)
    findings.sort(key=lambda finding: (finding.severity != "error", finding.code, finding.node or ""))
    return report_findings(findings, args.json)
