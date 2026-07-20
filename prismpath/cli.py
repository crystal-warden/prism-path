import argparse
import json
import os

from prismpath.parser import parse_file
from prismpath.engine import run
from prismpath import analysis


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='Command-line interface for prismpath')
    subparsers = parser.add_subparsers(dest='command')

    run_parser = subparsers.add_parser('run', help='Parse the flow and run it (mock agent by default; '
                                                   '--agent ollama:MODEL for a real local model)')
    run_parser.add_argument('flow_md', type=str, help='Path to the flow markdown file')
    run_parser.add_argument('--type-gate', action='store_true',
                            help='validate each worker output against the derived contract (contract.py)')
    run_parser.add_argument('--agent', default=None, metavar='SPEC',
                            help='real worker instead of the mock: `ollama:llama3.2` (local Ollama) '
                                 'or `openai:MODEL@BASE` (any OpenAI-compatible endpoint — vLLM, '
                                 'LM Studio, llama.cpp). JSON replies feed `when` predicates; '
                                 'failures ride the flow\'s `on error` edges')
    run_parser.set_defaults(func=run_flow)

    lint_parser = subparsers.add_parser(
        'lint', help='Static analysis + semantic-ambiguity check (needs the embedder)')
    lint_parser.add_argument('flow_md', type=str, help='Path to the flow markdown file')
    lint_parser.add_argument('--json', action='store_true', help='machine-readable findings')
    lint_parser.set_defaults(func=lint_flow)

    validate_parser = subparsers.add_parser(
        'validate', help='Static analysis: does the flow compile? (fast, no model)')
    validate_parser.add_argument('flow_md', type=str, help='Path to the flow markdown file')
    validate_parser.add_argument('--json', action='store_true', help='machine-readable findings')
    validate_parser.set_defaults(func=validate_flow)

    resume_parser = subparsers.add_parser(
        'resume', help='Resume a suspended/crashed run from a JSON checkpoint (mock agent)')
    resume_parser.add_argument('checkpoint', type=str, help='Path to the checkpoint JSON')
    resume_parser.add_argument('--choose', default=None,
                               help='the edge target a human picks (for a needs_human suspension)')
    resume_parser.set_defaults(func=resume_flow)

    lock_parser = subparsers.add_parser(
        'lock', help='Write a routing lockfile (committed condition embeddings) for reproducible routing')
    lock_parser.add_argument('flow_md', type=str, help='Path to the flow markdown file')
    lock_parser.add_argument('--check', action='store_true',
                             help='verify the local embedder still matches an existing lock')
    lock_parser.add_argument('--centroids', default=None, metavar='LABELED_JSONL',
                             help='pin LEARNED routing: build per-condition centroids from this '
                                  'labeled benchmark and commit the shrunk vectors in the lock')
    lock_parser.add_argument('--prior', type=float, default=4.0,
                             help='centroid shrinkage prior weight (pseudo-count toward the '
                                  'zero-shot condition vector; default 4.0)')
    lock_parser.set_defaults(func=lock_flow)

    import_parser = subparsers.add_parser(
        'import', help='Import a LangGraph StateGraph (.py) as a skeleton flow (with TODO conditions)')
    import_parser.add_argument('py_file', type=str, help='the LangGraph Python file')
    import_parser.add_argument('--name', default='imported', help='flow name')
    import_parser.add_argument('--out', default=None, help='write the .md flow here (else stdout)')
    import_parser.set_defaults(func=import_cmd)

    cal_parser = subparsers.add_parser(
        'calibrate', help='Calibrate the escalation threshold τ from labeled routing decisions')
    cal_parser.add_argument('labels', type=str, help='labeled routing-decision JSONL')
    cal_parser.add_argument('--alpha', type=float, default=0.05, help='target risk (default 0.05)')
    cal_parser.add_argument('--out', default=None, help='write calibration JSON to this path')
    cal_parser.set_defaults(func=calibrate_cmd)

    graph_parser = subparsers.add_parser(
        'graph', help='Render the flow as a Mermaid diagram (solid=deterministic, dashed=semantic)')
    graph_parser.add_argument('flow_md', type=str, help='Path to the flow markdown file')
    graph_parser.add_argument('--direction', default='TD', choices=['TD', 'LR'], help='layout direction')
    graph_parser.add_argument('--fenced', action='store_true', help='wrap in a ```mermaid fence for READMEs')
    graph_parser.set_defaults(func=graph_flow)

    label_parser = subparsers.add_parser(
        'label', help='Hand-label routing decisions in a JSONL log (calibration data)')
    label_parser.add_argument('log', type=str, help='routing-decision JSONL (from run_logged)')
    label_parser.set_defaults(func=label_cmd)

    test_parser = subparsers.add_parser(
        'test', help='Assert a flow\'s routing from a Markdown fixture (no LLM)')
    test_parser.add_argument('flow_md', type=str, help='Path to the flow markdown file')
    test_parser.add_argument('tests_md', nargs='?', default=None,
                             help='fixture file (default <flow>.tests.md)')
    test_parser.add_argument('--json', action='store_true', help='machine-readable results')
    test_parser.add_argument('--emit-labels', default=None, metavar='PATH',
                             help='append each case as a labeled routing record (JSONL)')
    test_parser.set_defaults(func=test_flow)

    contract_parser = subparsers.add_parser(
        'contract', help="Derive each node's worker output schema from its `when` edges")
    contract_parser.add_argument('flow_md', type=str, help='Path to the flow markdown file')
    contract_parser.add_argument('--json', action='store_true',
                                 help='emit the per-node schemas as JSON (constrained-decoding grammar)')
    contract_parser.set_defaults(func=contract_cmd)

    annotate_parser = subparsers.add_parser(
        'annotate', help='Blind-label a benchmark (labels hidden) for inter-annotator κ (gate zero)')
    annotate_parser.add_argument('benchmark', type=str, help='labeled benchmark JSONL (labels are hidden)')
    annotate_parser.add_argument('--out', required=True, help='per-annotator output JSONL (resumable)')
    annotate_parser.add_argument('--flows-dir', default=None, help='flows dir (default: package flows/)')
    annotate_parser.add_argument('--limit', type=int, default=None, help='max cases this session')
    annotate_parser.set_defaults(func=annotate_cmd)

    kappa_parser = subparsers.add_parser(
        'kappa', help="Cohen's κ between two annotation files (+ adjudicated gold / disagreements)")
    kappa_parser.add_argument('a', type=str, help='annotator A JSONL (benchmark-shaped)')
    kappa_parser.add_argument('b', type=str, help='annotator B JSONL (benchmark-shaped)')
    kappa_parser.add_argument('--by-stratum', action='store_true', help='also report κ per stratum')
    kappa_parser.add_argument('--gold', default=None, help='write agreed cases as a gold benchmark JSONL')
    kappa_parser.add_argument('--disagreements', default=None, help='write disagreements for a 3rd pass')
    kappa_parser.set_defaults(func=kappa_cmd)

    centroids_parser = subparsers.add_parser(
        'centroids', help='Cross-validate prototype/centroid routing vs zero-shot embedding on a benchmark')
    centroids_parser.add_argument('benchmark', type=str, help='labeled benchmark JSONL')
    centroids_parser.add_argument('--folds', type=int, default=5)
    centroids_parser.add_argument('--prior', type=float, default=4.0, help='shrinkage prior weight')
    centroids_parser.add_argument('--flows-dir', default=None)
    centroids_parser.set_defaults(func=centroids_cmd)

    compose_parser = subparsers.add_parser(
        'compose', help='Advance pending fan-out/composition runs in the queue: spawn children, '
                        'join, resume parents (the out-of-band harness tick — item #4)')
    compose_parser.add_argument('--queue', default=None,
                                help='queue dir to scan (default: the prismpath queue dir)')
    compose_parser.set_defaults(func=compose_cmd)

    portable_parser = subparsers.add_parser(
        'portable', help='Is this flow (and its @spawn children) in the ML-free portable subset? '
                         'Portable flows run on portable/prismpath.mjs — browser/edge/appliance')
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
                                     'registers itself via the prismpath.plugins entry point — '
                                     'pip install it and its workers are @worker-bindable')
    plugins_parser.set_defaults(func=plugins_cmd)

    from prismpath.ci_report import add_parser as _add_ci_report
    _add_ci_report(subparsers)

    init_parser = subparsers.add_parser(
        'init', help='Scaffold a starter flow — zero to a running, validated flow in two commands')
    init_parser.add_argument('path', nargs='?', default=None,
                             help='where to write the flow (default: ./flow.md, or ./<template>.md)')
    init_parser.add_argument('--template', default=None, metavar='NAME',
                             help="start from a gallery flow instead of the generic starter "
                                  "(`--template list` shows what's available); copies the flow AND "
                                  "its routing tests")
    init_parser.set_defaults(func=init_cmd)

    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 2
    return args.func(args)


def _mock_agent(node, instruction, state):
    return {'text': node, 'tests_pass': True, 'always': True}


def run_flow(args) -> int:
    graph = parse_file(args.flow_md)
    agent = _mock_agent
    if getattr(args, "agent", None):
        from prismpath.chat_agent import chat_agent
        try:
            agent = chat_agent(args.agent)
        except ValueError as e:
            print(f"✗ {e}")
            return 2
    result = run(graph, agent, type_gate=getattr(args, "type_gate", False))
    print(f"Path: {result.path}")
    print(f"Stopped Reason: {result.stopped}")
    if result.stopped == "contract_violation" and result.pending:
        for v in result.pending.get("violations", []):
            print(f"  ✗ [{result.pending['node']}] {v}")
    return 1 if result.stopped == "contract_violation" else 0


def resume_flow(args) -> int:
    from prismpath import checkpoint
    try:
        result = checkpoint.resume(args.checkpoint, _mock_agent, choose=args.choose)
    except checkpoint.CheckpointError as e:
        print(f"cannot resume: {e}")
        return 1
    print(f"Path: {result.path}")
    print(f"Stopped Reason: {result.stopped}")
    if result.pending:
        cands = [c.get('target') for c in result.pending.get('candidates', [])]
        print(f"Awaiting human — candidates: {cands}  (resume with --choose <edge>)")
    return 0


def import_cmd(args) -> int:
    from prismpath import langgraph_import
    md = langgraph_import.import_langgraph(open(args.py_file).read(), name=args.name)
    if args.out:
        open(args.out, "w").write(md)
        print(f"wrote {args.out} — fill in the TODO conditions, then `prismpath validate` it")
    else:
        print(md)
    return 0


def calibrate_cmd(args) -> int:
    from prismpath import calibrate, routelog
    recs = routelog.load_records(args.labels)
    cal = calibrate.calibrate(recs, alpha=args.alpha)
    print(f"n={cal['n']} labeled decisions; target risk α={cal['alpha']}")
    print(f"calibrated τ = {cal['tau']}  (escalation threshold with a ≥{1-cal['alpha']:.0%} "
          f"correctness guarantee on non-escalated decisions)")
    for p in cal["curve"]:
        mark = "  <- τ" if p["tau"] == cal["tau"] else ""
        print(f"  τ={p['tau']:.3f}  acc={p['accuracy']:.3f} (lower {p['acc_lower']:.3f})  "
              f"escalate={p['escalation_rate']:.0%}{mark}")
    if args.out:
        calibrate.save_calibration(args.out, cal)
        print(f"wrote {args.out}")
    return 0


def graph_flow(args) -> int:
    from prismpath import graph_export
    graph = parse_file(args.flow_md)
    out = (graph_export.to_mermaid_fenced if args.fenced else graph_export.to_mermaid)(graph, args.direction)
    print(out)
    return 0


def label_cmd(args) -> int:
    from prismpath import routelog
    records = routelog.load_records(args.log)
    if not records:
        print(f"no records in {args.log}")
        return 1

    def ask(rec, targets):
        print(f"\n[{rec.get('flow')}/{rec.get('node')}] outcome: {(rec.get('outcome_text') or '')[:120]}")
        for i, c in enumerate(rec.get("candidates", [])):
            sc = c.get("score")
            sc = f"  ({sc:.3f})" if isinstance(sc, (int, float)) else ""
            mark = "   <- router chose" if c.get("target") == rec.get("chosen") else ""
            print(f"  {i+1}. {c.get('target')}: {(c.get('condition') or '')[:80]}{sc}{mark}")
        raw = input("correct edge # (Enter=skip, q=quit): ").strip().lower()
        if raw == "q":
            raise KeyboardInterrupt
        return targets[int(raw) - 1] if raw.isdigit() and 1 <= int(raw) <= len(targets) else None

    try:
        routelog.label_records(records, ask)
    except (KeyboardInterrupt, EOFError):
        pass
    routelog.save_records(args.log, records)
    print(f"\n{routelog.label_stats(records)}")
    return 0


def test_flow(args) -> int:
    from prismpath import flow_test
    from prismpath.parser import parse_file
    tests_path = args.tests_md or flow_test.default_tests_path(args.flow_md)
    if not __import__("os").path.exists(tests_path):
        print(f"no fixture found: {tests_path}")
        return 2
    report = flow_test.run_tests(args.flow_md, tests_path)
    if args.emit_labels:
        n = flow_test.emit_labels(report, parse_file(args.flow_md).name, args.emit_labels)
        print(f"wrote {n} labeled records to {args.emit_labels}")
    if args.json:
        print(json.dumps({"passed": report.passed, "failed": report.failed,
                          "cases": [vars(r) for r in report.results]}, indent=2))
        return 0 if report.ok else 1
    for r in report.results:
        mark = "✓" if r.ok else "✗"
        line = f"  {mark} [{r.node}] --{r.how}--> {r.got}  (expect {r.expect})"
        if not r.ok and r.detail:
            line += f"  — {r.detail}"
        print(line)
    print(f"\n{report.passed}/{len(report.results)} passed"
          + ("" if report.ok else f", {report.failed} FAILED"))
    return 0 if report.ok else 1


def lock_flow(args) -> int:
    from prismpath import lockfile
    if args.check:
        try:
            lock = lockfile.load_lock(lockfile.lock_path(args.flow_md))
            # verify_tree degrades to the single-flow fingerprint check when there are no children.
            ok = lockfile.verify_tree(args.flow_md, policy="warn")
        except lockfile.LockError as e:
            print(f"lock check FAILED: {e}")
            return 1
        kids = len(lock.get("children") or {})
        tree = f" + {kids} pinned child lock(s)" if kids else ""
        print(f"lock OK — embedder reproduces the fingerprint{tree} (probe cosine "
              f"{lockfile.probe_cosine(lock):.6f})" if ok
              else "lock: drift detected (see warning above)")
        return 0 if ok else 1
    # Optional learned-routing pins: build per-condition centroids from a labeled benchmark and
    # commit the shrunk vectors (roadmap item #2 follow-on) — applies to the root flow only.
    centroids = counts = None
    if getattr(args, "centroids", None):
        from prismpath import centroid
        from prismpath.parser import parse_file as _pf
        recs = [json.loads(l) for l in open(args.centroids, encoding="utf-8") if l.strip()]
        graph = _pf(args.flow_md)
        centroids, counts = centroid.build_centroids(recs, {graph.name: graph})
        if not centroids:
            print(f"note: no labeled records in {args.centroids} matched this flow's semantic "
                  f"conditions — lock will pin zero-shot vectors only")
    # lock_tree pins the whole composition tree (@spawn children, recursively), saving child locks;
    # it degrades to build_lock for a childless flow. Save the top-level lock here.
    lock = lockfile.lock_tree(args.flow_md, centroids=centroids, centroid_counts=counts,
                              prior_weight=getattr(args, "prior", 4.0))
    path = lockfile.save_lock(args.flow_md, lock)
    kids = len(lock.get("children") or {})
    tree = f", pinned {kids} child lock(s)" if kids else ""
    cen = len(lock.get("centroids") or {})
    cen_s = f", {cen} learned centroid(s)" if cen else ""
    print(f"wrote {path}: {len(lock['conditions'])} semantic condition(s), "
          f"embedder {lock['embedder']['name']} (dim {lock['embedder']['dim']}), "
          f"δ={lock['delta']}{cen_s}{tree}")
    return 0


def _report(findings, as_json: bool) -> int:
    """Print findings and return an exit code (non-zero iff any error-severity finding)."""
    errors = [f for f in findings if f.severity == "error"]
    warnings = [f for f in findings if f.severity == "warning"]
    if as_json:
        print(json.dumps({
            "ok": not errors,
            "errors": len(errors), "warnings": len(warnings),
            "findings": [f.as_dict() for f in findings],
        }, indent=2))
        return 1 if errors else 0
    for f in findings:
        print(f)
    if not findings:
        print("  clean ✅  — the flow compiles")
    else:
        summary = []
        if errors:
            summary.append(f"{len(errors)} error(s)")
        if warnings:
            summary.append(f"{len(warnings)} warning(s)")
        print(f"\n{'✗ does not compile' if errors else '✅ compiles (with advisories)'}"
              f" — {', '.join(summary)}")
    return 1 if errors else 0


def validate_flow(args) -> int:
    graph = parse_file(args.flow_md)
    findings = list(analysis.analyze(graph))
    findings += analysis.analyze_composition(graph, args.flow_md)   # cross-flow @spawn checks (item #4)
    return _report(findings, args.json)


def contract_cmd(args) -> int:
    """Print each node's derived worker output contract (the fields its `when` edges read, with
    inferred types). Non-zero exit iff a field is used two incompatible ways (a real authoring bug)."""
    from prismpath import contract
    graph = parse_file(args.flow_md)
    c = contract.derive_contract(graph)
    if args.json:
        print(json.dumps({n: contract.to_json_schema(fs) for n, fs in c.items() if fs}, indent=2))
    else:
        print(contract.describe(c))
    conflicts = [(n, f) for n, fs in c.items() for f, s in fs.items() if s.get("conflict")]
    for n, f in conflicts:
        print(f"  ✗ [{n}] field {f!r}: {c[n][f]['conflict']}")
    return 1 if conflicts else 0


def annotate_cmd(args) -> int:
    from prismpath import annotate
    annotate.annotate_loop(args.benchmark, args.out, flows_dir=args.flows_dir, limit=args.limit)
    return 0


def kappa_cmd(args) -> int:
    from prismpath import kappa
    a, b = kappa.load(args.a), kappa.load(args.b)
    rep = kappa.report(a, b, by_stratum=args.by_stratum)
    print(json.dumps(rep, indent=2))
    print(f"\nCohen's κ = {rep['kappa']} ({rep['band']}) over {rep['n']} co-labeled cases")
    if args.gold or args.disagreements:
        gold, dis = kappa.adjudicate(a, b)
        if args.gold:
            kappa.dump(gold, args.gold)
            print(f"wrote {len(gold)} agreed gold cases -> {args.gold} (a reproduce.py dataset)")
        if args.disagreements:
            kappa.dump(dis, args.disagreements)
            print(f"wrote {len(dis)} disagreements -> {args.disagreements} (for a 3rd-pass adjudication)")
    return 0


def centroids_cmd(args) -> int:
    from prismpath import centroid
    recs = [json.loads(l) for l in open(args.benchmark, encoding="utf-8") if l.strip()]
    res = centroid.cross_validate(recs, flows_dir=args.flows_dir, folds=args.folds, prior_weight=args.prior)
    print(json.dumps(res, indent=2))
    return 0


def _new_worker_pack(name: str) -> int:
    """Scaffold `prismpath-<name>/` — a pip-installable worker pack. One `pip install -e` later its
    workers are visible in `prismpath plugins` (entry-point source) and bindable with
    `@worker(<name>.<worker>)`. The generated example shows both worker shapes: a pure function,
    and a CLI wrapped via `prismpath.cli_worker.CliWorker` (commented — the 'any tool is a worker'
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

    write = lambda rel, text: open(os.path.join(root, rel), "w", encoding="utf-8").write(text)
    write("pyproject.toml", f'''[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "{root}"
version = "0.1.0"
description = "A worker pack for prismpath flows — bind with @worker({name}.<worker>)"
requires-python = ">=3.10"

# THE integration point: this line is what makes `pip install` enough. The registry discovers the
# pack through the entry-point group and `prismpath plugins` lists it with source "entry-point".
[project.entry-points."prismpath.plugins"]
{name} = "{mod}"

[tool.setuptools]
packages = ["{mod}"]
''')
    write(os.path.join(mod, "__init__.py"), f'''"""{name} — an prismpath worker pack.

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


# The 'any CLI is a worker' bridge — wrap a real tool in ~3 lines (uncomment + edit):
#   from prismpath.cli_worker import CliWorker
#   jq = CliWorker(["jq", "-c", ".summary", "{{instruction}}"])   # JSON stdout -> outcome fields
WORKERS = {{"hello": hello}}
''')
    write(os.path.join("tests", "test_workers.py"), f'''from {mod} import WORKERS


def test_hello_outcome_shape():
    out = WORKERS["hello"]("n", "greet the world", {{}})
    assert out["ok"] is True and "greet the world" in out["text"]
''')
    write("README.md", f'''# {root}

A worker pack for prismpath flows. Install it and its workers are bindable in any flow document:

```bash
pip install -e .          # registers the `{name}` plugin via the prismpath.plugins entry point
prismpath plugins            # -> {name} 0.1.0 [entry-point] — workers: hello
```

```markdown
## mynode
Do the thing.
@worker({name}.hello)
-> done: always
```

Add workers to `WORKERS` in `{mod}/__init__.py` — plain `(node, instruction, state) -> outcome`
callables. To wrap an existing CLI as a worker, see the `CliWorker` example in the module.
''')
    print(f"✓ scaffolded {root}/ — a pip-installable worker pack")
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


STARTER_TESTS = '''# Routing tests for the starter flow — `prismpath test flow.md` (no model needed)

| node     | outcome                                   | fields          | expect          |
|----------|-------------------------------------------|-----------------|-----------------|
| classify | the dashboard crashes on load             | kind=bug        | handle_bug      |
| classify | how do I export my data?                  | kind=question   | handle_question |
'''


def _gallery_dir() -> str:
    """The gallery ships inside the package (sibling of this file in both repo layouts)."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "gallery")


def _gallery_templates() -> dict:
    """{name: dir} for every gallery entry that has the template pair (<name>.md + <name>.tests.md)."""
    out = {}
    root = _gallery_dir()
    if os.path.isdir(root):
        for name in sorted(os.listdir(root)):
            d = os.path.join(root, name)
            if os.path.isfile(os.path.join(d, f"{name}.md")) and \
               os.path.isfile(os.path.join(d, f"{name}.tests.md")):
                out[name] = d
    return out


def init_cmd(args) -> int:
    """Scaffold a starter flow + its routing tests, and print the model-free commands that make them
    do something. Bare: the generic triage starter (deterministic `when` + semantic edges — editing
    it teaches the format). `--template <name>`: start from a real gallery flow instead — every
    gallery entry doubles as a starter."""
    templates = _gallery_templates()
    if args.template == "list":
        if not templates:
            print("no gallery templates found")
            return 1
        print("gallery templates (prismpath init --template <name>):")
        for name, d in templates.items():
            first = ""
            readme = os.path.join(d, "README.md")
            if os.path.isfile(readme):
                lines = [l.strip() for l in open(readme, encoding="utf-8") if l.strip()
                         and not l.startswith("#")]
                first = f" — {lines[0][:90]}" if lines else ""
            print(f"  {name}{first}")
        return 0

    if args.template is not None:
        if args.template not in templates:
            print(f"✗ no gallery template {args.template!r} (have: {', '.join(templates) or 'none'}; "
                  f"see `prismpath init --template list`)")
            return 1
        src = templates[args.template]
        if args.path:
            print("(note: <path> is ignored with --template — template files keep their names, "
                  "because flows may reference each other, e.g. an @spawn child)")
        # copy EVERY .md in the entry, names preserved: the flow, its tests, and any companion
        # flows (a fan-out's child, a sub-flow) — templates are self-contained working sets.
        parts = sorted(f for f in os.listdir(src) if f.endswith(".md") and f != "README.md")
        for f in parts:
            if os.path.exists(f):
                print(f"✗ {f} already exists — init this template in an empty/other directory")
                return 1
        for f in parts:
            with open(os.path.join(src, f), encoding="utf-8") as f_in, \
                 open(f, "w", encoding="utf-8") as f_out:
                f_out.write(f_in.read())
        flow_path = f"{args.template}.md"
        others = [f for f in parts if f != flow_path]
        print(f"✓ wrote {flow_path} — the {args.template!r} gallery flow")
        print(f"✓ wrote {', '.join(others)}\n")
    else:
        flow_path = args.path or "flow.md"
        tests_path = os.path.splitext(flow_path)[0] + ".tests.md"
        for p in (flow_path, tests_path):
            if os.path.exists(p):
                print(f"✗ {p} already exists — pick another path (prismpath init <path>)")
                return 1
        with open(flow_path, "w", encoding="utf-8") as f:
            f.write(STARTER_FLOW)
        with open(tests_path, "w", encoding="utf-8") as f:
            f.write(STARTER_TESTS)
        print(f"✓ wrote {flow_path} — a triage flow (deterministic `when` + semantic edges)")
        print(f"✓ wrote {tests_path} — routing scenarios as a Markdown table\n")

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
    what is installed — the CI gate that keeps a flow from reaching a host missing its tools.
    `--new NAME`: scaffold a pip-installable worker pack."""
    from prismpath.plugins import registry
    if args.new:
        return _new_worker_pack(args.new)
    if args.check:
        graph = parse_file(args.check)
        problems = registry.check_flow(graph)
        if problems:
            print(f"✗ {len(problems)} unresolved @worker binding(s):")
            for p in problems:
                print(f"  ✗ {p}")
            return 1
        bound = sum(1 for n in graph.nodes.values() if "worker" in n.annotations)
        print(f"✓ all @worker bindings resolve ({bound} bound node(s))")
        return 0
    print(registry.audit(as_json=args.json))
    return 0


def portable_cmd(args) -> int:
    """Report the flow's portability TIER — for the whole composition tree (`@spawn` children
    included). P0 = ML-free (runs on portable/prismpath.mjs anywhere); P1 = all reachable semantic
    edges are pinned in the lockfile, so routing needs only an outcome-side embedder (ONNX-able —
    appliance/edge); P2 = semantic edges not fully locked (full stack). Exit 0 iff P0 (unchanged
    contract: "portable" means the ML-free subset)."""
    graph = parse_file(args.flow_md)
    tree = analysis.portability_tier_tree(graph, args.flow_md)
    if args.json:
        out = {"tier": tree["tier"],
               "flows": {p: {"tier": d["tier"],
                             "semantic_edges": [{"node": n, "target": t, "condition": c}
                                                for n, t, c in d["semantic_edges"]],
                             "unlocked": d["unlocked"], "lock": d["lock"]}
                         for p, d in tree["flows"].items()}}
        print(json.dumps(out, indent=2))
        return 0 if tree["tier"] == "P0" else 1
    blurb = {
        "P0": "P0 ✅  — every reachable edge is decidable (when/error/event); no ML runtime needed. "
              "Runs on portable/prismpath.mjs (browser/edge/appliance).",
        "P1": "P1 🔒  — semantic edges present, ALL pinned in the lockfile: routing needs only an "
              "outcome-side embedder at runtime (ONNX-able). Appliance/edge-deployable with the lock.",
        "P2": "P2      — semantic edges not fully covered by a lock; needs the full engine "
              "(live embedding / LLM escalation). Run `prismpath lock` to reach P1, or rewrite the "
              "edges as `when` predicates to reach P0.",
    }
    print(blurb[tree["tier"]])
    for path, d in tree["flows"].items():
        if d["tier"] == "P0" and len(tree["flows"]) == 1:
            continue
        extra = f" (lock: {d['lock']})" if d["lock"] else ""
        print(f"  {d['tier']}  {path}{extra}")
        for n, t, c in d["semantic_edges"]:
            mark = "unlocked" if c in d["unlocked"] else "locked"
            print(f"        [{n}] -> {t}: {c!r}  ({mark})")
    return 0 if tree["tier"] == "P0" else 1


def compose_cmd(args) -> int:
    """Advance every pending fan-out in the queue by one tick: spawn/poll children and, where a join is
    ready, aggregate + resume the parent. The out-of-band harness a deployment runs on a schedule
    (mirrors the timeout scanner). Uses the mock agent, like `run`/`resume`."""
    from prismpath import composer
    recs = composer.advance_fanouts(_mock_agent, qdir=args.queue)
    for r in recs:
        if r.get("error"):
            print(f"  ✗ {r['path']}: {r['error']}")
        elif r.get("joined"):
            print(f"  [{r.get('node')}] {r.get('done', 0)}/{r.get('spawned', 0)} children done "
                  f"-> joined ({r.get('event')}), parent resumed")
        else:
            print(f"  [{r.get('node')}] {r.get('done', 0)}/{r.get('spawned', 0)} children done "
                  f"-> still waiting")
    print(f"advanced {len(recs)} fan-out(s)")
    return 0


def lint_flow(args) -> int:
    graph = parse_file(args.flow_md)
    findings = list(analysis.analyze(graph))
    findings += analysis.analyze_composition(graph, args.flow_md)   # cross-flow @spawn checks (item #4)
    # the non-decidable checks (need the embedder): near-ties, and polarity mirrors (the 0.82 class).
    from prismpath.lint import semantic_ambiguity, polarity_mirror
    findings += semantic_ambiguity(graph)
    findings += polarity_mirror(graph)
    findings.sort(key=lambda f: (f.severity != "error", f.code, f.node or ""))
    return _report(findings, args.json)


if __name__ == '__main__':
    raise SystemExit(main())
