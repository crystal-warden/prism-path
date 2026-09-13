# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
import argparse
import json
import os
import sys

from prismpath.kernel.parser import parse_file
from prismpath.kernel.engine import run
from prismpath.kernel import analysis
# The four people who touch a PrismPath deployment, and the commands that are theirs. The help text
# is grouped by this table instead of one flat list; tests/test_cli_personas.py keeps every registered
# subcommand in exactly one group.
PERSONAS = (
    ("Process owner: author and test the policy of record",
     ("init", "validate", "test", "graph", "lint", "context")),
    ("Engineer: implement the interface once, calibrate for deployment, deliver",
     ("contract", "capability", "compile", "portable", "lock", "verify", "plugins", "ci-report", "lsp", "import",
      "calibrate", "label", "annotate", "kappa", "centroids")),
    ("Operator: run the system day to day, swap and attest policy (Mission Control is the console; this is the scripted path)",
     ("run", "resume", "compose", "swap", "trail")),
    ("Assessor: anchor, verify, and read the evidence",
     ("ledger", "facet")),
)


def _grouped_help(subparsers) -> str:
    """Render the subcommands grouped by persona, one line each, from the registered parsers."""
    out = ["commands, by who runs them", ""]
    for title, names in PERSONAS:
        out.append(title + ":")
        for name in names:
            sub = subparsers.choices.get(name)
            help_text = ""
            if sub is not None:
                for action in subparsers._choices_actions:
                    if action.dest == name:
                        help_text = (action.help or "").split(". ")[0].split(": ")[0]
                        if len(help_text) > 88:
                            help_text = help_text[:85].rsplit(" ", 1)[0] + "..."
                        break
            out.append(f"  {name:<12} {help_text}")
        out.append("")
    out.append("`swap` splits by action: keygen, envelope, and pack are the engineer's setup; swap and attest are the "
               "operator's; verify is the assessor's.")
    return "\n".join(out)


def _add_owner_commands(subparsers) -> None:
    # Adding process owner commands for flow authoring, static analysis, and testing.
    init_parser = subparsers.add_parser(
        'init', help='Scaffold a starter flow - zero to a running, validated flow in two commands')
    init_parser.add_argument('path', nargs='?', default=None,
                             help='where to write the flow (default: ./flow.md, or ./<template>.md)')
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


def _add_engineer_commands(subparsers) -> None:
    # Adding engineer commands for compilation, calibration, verification, and tooling integration.
    contract_parser = subparsers.add_parser(
        'contract', help="Derive each node's worker output schema from its `when` edges")
    contract_parser.add_argument('flow_md', type=str, help='Path to the flow markdown file')
    contract_parser.add_argument('--json', action='store_true',
                                 help='emit the per-node schemas as JSON (constrained-decoding grammar)')
    contract_parser.set_defaults(func=contract_cmd)

    compile_parser = subparsers.add_parser(
        'compile', help='Compile a flow and its lock into a single-file portable JS bundle')
    compile_parser.add_argument('flow_md', type=str, help='Path to the flow markdown file')
    compile_parser.add_argument('--tier', choices=['p0', 'p1'], required=True,
                                help='portability tier to compile (p0: ML-free, p1: embedded locked vectors)')
    compile_parser.add_argument('--out', default=None, help='output path for the .mjs bundle (default: <flow>.bundle.mjs)')
    compile_parser.set_defaults(func=compile_cmd)

    portable_parser = subparsers.add_parser(
        'portable', help='Is this flow (and its @spawn children) in the ML-free portable subset? '
                         'Portable flows run on portable/prismpath.mjs - browser/edge/appliance')
    portable_parser.add_argument('flow_md', type=str, help='Path to the flow markdown file')
    portable_parser.add_argument('--json', action='store_true', help='machine-readable findings')
    portable_parser.set_defaults(func=portable_cmd)

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

    cal_parser = subparsers.add_parser(
        'calibrate', help='Calibrate the escalation threshold tau from labeled routing decisions')
    cal_parser.add_argument('labels', type=str, help='labeled routing-decision JSONL')
    cal_parser.add_argument('--alpha', type=float, default=0.05, help='target risk (default 0.05)')
    cal_parser.add_argument('--out', default=None, help='write calibration JSON to this path')
    cal_parser.set_defaults(func=calibrate_cmd)

    label_parser = subparsers.add_parser(
        'label', help='Hand-label routing decisions in a JSONL log (calibration data)')
    label_parser.add_argument('log', type=str, help='routing-decision JSONL (from run_logged)')
    label_parser.set_defaults(func=label_cmd)

    annotate_parser = subparsers.add_parser(
        'annotate', help='Blind-label a benchmark (labels hidden) for inter-annotator kappa (gate zero)')
    annotate_parser.add_argument('benchmark', type=str, help='labeled benchmark JSONL (labels are hidden)')
    annotate_parser.add_argument('--out', required=True, help='per-annotator output JSONL (resumable)')
    annotate_parser.add_argument('--flows-dir', default=None, help='flows dir (default: package flows/)')
    annotate_parser.add_argument('--limit', type=int, default=None, help='max cases this session')
    annotate_parser.set_defaults(func=annotate_cmd)

    kappa_parser = subparsers.add_parser(
        'kappa', help="Cohen's kappa between two annotation files (+ adjudicated gold / disagreements)")
    kappa_parser.add_argument('a', type=str, help='annotator A JSONL (benchmark-shaped)')
    kappa_parser.add_argument('b', type=str, help='annotator B JSONL (benchmark-shaped)')
    kappa_parser.add_argument('--by-stratum', action='store_true', help='also report kappa per stratum')
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

    from prismpath.ci_report import add_parser as _add_ci_report
    _add_ci_report(subparsers)

    from prismpath.kernel.model_check import add_parser as _add_verify
    _add_verify(subparsers)

    from prismpath.lsp import add_parser as _add_lsp
    _add_lsp(subparsers)


def _add_operator_commands(subparsers) -> None:
    # Adding operator commands for system execution, state resumption, hot swaps, and execution logs.
    run_parser = subparsers.add_parser('run', help='Parse the flow and run it (mock agent by default; '
                                                   '--agent ollama:MODEL for a real local model)')
    run_parser.add_argument('flow_md', type=str, help='Path to the flow markdown file')
    run_parser.add_argument('--type-gate', action='store_true',
                            help='validate each worker output against the derived contract (contract.py)')
    run_parser.add_argument('--agent', default=None, metavar='SPEC',
                            help='real worker instead of the mock: `ollama:llama3.2` (local Ollama) '
                                 'or `openai:MODEL@BASE` (any OpenAI-compatible endpoint - vLLM, '
                                 'LM Studio, llama.cpp). JSON replies feed `when` predicates; '
                                 'failures ride the flow\'s `on error` edges')
    run_parser.set_defaults(func=run_flow)

    resume_parser = subparsers.add_parser(
        'resume', help='Resume a suspended/crashed run from a JSON checkpoint (mock agent)')
    resume_parser.add_argument('checkpoint', type=str, help='Path to the checkpoint JSON')
    resume_parser.add_argument('--choose', default=None,
                               help='the edge target a human picks (for a needs_human suspension)')
    resume_parser.set_defaults(func=resume_flow)

    compose_parser = subparsers.add_parser(
        'compose', help='Advance pending fan-out/composition runs in the queue: spawn children, '
                        'join, resume parents (the out-of-band harness tick - item #4)')
    compose_parser.add_argument('--queue', default=None,
                                help='queue dir to scan (default: the prismpath queue dir)')
    compose_parser.set_defaults(func=compose_cmd)

    swap_parser = subparsers.add_parser(
        'swap', help='Secure policy hot-swap: signed packs, envelope check, attested swap '
                     '(spec-secure-hotswap)')
    swap_parser.add_argument('action', choices=[
        'keygen', 'pack', 'verify', 'envelope', 'swap', 'attest'],
        help='keygen | pack | verify | envelope | swap | attest')
    swap_parser.add_argument('--ppt', help='the .ppt image (pack/verify/swap)')
    swap_parser.add_argument('--priv', help='authority private key (keygen writes it; pack/envelope use it)')
    swap_parser.add_argument('--pub', nargs='+', help='authority public key(s) (verify/swap/attest)')
    swap_parser.add_argument('--out', help='output dir (keygen/envelope) or state dir (swap/attest)')
    swap_parser.add_argument('--name', default='authority', help='keygen key name (default authority)')
    swap_parser.add_argument('--fields', help='comma list name:kind (pack/envelope), e.g. temp:int,rule:str')
    swap_parser.add_argument('--version', type=int, default=1, help='monotonic pack version (pack)')
    swap_parser.add_argument('--envelope-id', dest='envelope_id', default='env1',
                             help='envelope id the pack targets / the envelope defines')
    swap_parser.add_argument('--envelope', help='envelope base path without .json/.sig (swap/attest)')
    swap_parser.add_argument('--caps', help='comma list k=v envelope caps (envelope), e.g. atoms=1024,nodes=256')
    swap_parser.add_argument('--revoked', help='revocation list JSON of key_ids (verify/swap)')
    swap_parser.add_argument('--overlay-of', dest='overlay_of', default=None,
                             help='pack: name the policy of record this pack temporarily overrides; attest shows it as overlay_of')
    swap_parser.add_argument('--allow-unsigned', dest='allow_unsigned', action='store_true',
                             help='demo escape hatch: swap an unsigned image, stamped in the audit log')
    swap_parser.set_defaults(func=swap_cmd)

    from prismpath import trail as _trail
    _trail.add_parser(subparsers)


def _add_assessor_commands(subparsers) -> None:
    # Adding assessor commands for ledger timestamp anchoring and telemetry processing.
    ledger_parser = subparsers.add_parser(
        'ledger', help='Flow-Ledger attestation: OTS anchor/upgrade/verify + air-gap tier (#36/#53)')
    ledger_parser.add_argument('action', choices=[
        'anchor', 'upgrade', 'verify', 'export-request', 'relay-stamp', 'import-proofs', 'rfc3161'],
        help='ledger attestation action')
    ledger_parser.add_argument('--repo', help='ledger git repo (anchor: enumerate Output-Hash trailers)')
    ledger_parser.add_argument('--out', help='output dir (anchor/upgrade/verify) or bundle path (air-gap)')
    ledger_parser.add_argument('--label', default='v1', help='anchor label (default v1)')
    ledger_parser.add_argument('--leaf', help='leaf hash hex (verify)')
    ledger_parser.add_argument('--root', help='root file (rfc3161 / export-request)')
    ledger_parser.add_argument('--request', help='stamp-request bundle (relay-stamp)')
    ledger_parser.add_argument('--proofs', help='proof bundle (import-proofs)')
    ledger_parser.add_argument('--dir', help='roots dir (import-proofs)')
    ledger_parser.add_argument('--cafile', help='TSA CA cert (rfc3161 verify)')
    ledger_parser.add_argument('--tsr', help='RFC-3161 response file to verify')
    ledger_parser.add_argument('--policy-hash', dest='policy_hash', default=None,
                               help='C1: bind the flow-definition hash to the anchored record')
    ledger_parser.add_argument('--gate-id', dest='gate_id', default=None,
                               help='C1: bind the gate identity that produced the record')
    ledger_parser.add_argument('--ots', action='store_true',
                               help='verify: include the full OTS/Bitcoin proof chain')
    ledger_parser.set_defaults(func=ledger_cmd)

    facet_parser = subparsers.add_parser(
        'facet', help='Facet telemetry: decision-preserving quantization, wire encoding, and stream decoding')
    facet_parser.add_argument('action', choices=['quantize', 'encode', 'decode'],
                              help='facet action: quantize | encode | decode')
    facet_parser.add_argument('flow_md', type=str, help='Path to the flow markdown file')
    facet_parser.add_argument('payload', type=str, help='JSON reading or HEX string')
    facet_parser.set_defaults(func=facet_cmd)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='Command-line interface for prismpath',
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    subparsers = parser.add_subparsers(dest='command', metavar='<command>')

    _add_owner_commands(subparsers)
    _add_engineer_commands(subparsers)
    _add_operator_commands(subparsers)
    _add_assessor_commands(subparsers)

    parser.epilog = _grouped_help(subparsers)
    subparsers._choices_actions = []   # the flat list is replaced by the grouped epilog above
    return parser


def main(argv=None) -> int:
    parser = build_parser()
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
        from prismpath.workers.chat_agent import chat_agent
        try:
            agent = chat_agent(args.agent)
        except ValueError as exc:
            print(f"✗ {exc}")
            return 2
    result = run(graph, agent, type_gate=getattr(args, "type_gate", False))
    print(f"Path: {result.path}")
    print(f"Stopped Reason: {result.stopped}")
    if result.stopped == "contract_violation" and result.pending:
        for violation in result.pending.get("violations", []):
            print(f"  ✗ [{result.pending['node']}] {violation}")
    return 1 if result.stopped == "contract_violation" else 0


def resume_flow(args) -> int:
    from prismpath.ledgers import checkpoint
    try:
        result = checkpoint.resume(args.checkpoint, _mock_agent, choose=args.choose)
    except checkpoint.CheckpointError as exc:
        print(f"cannot resume: {exc}")
        return 1
    print(f"Path: {result.path}")
    print(f"Stopped Reason: {result.stopped}")
    if result.pending:
        cands = [cand.get('target') for cand in result.pending.get('candidates', [])]
        print(f"Awaiting human - candidates: {cands}  (resume with --choose <edge>)")
    return 0


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


def calibrate_cmd(args) -> int:
    from prismpath.routing import calibrate
    from prismpath.routing import routelog
    recs = routelog.load_records(args.labels)
    cal = calibrate.calibrate(recs, alpha=args.alpha)
    print(f"n={cal['n']} labeled decisions; target risk alpha={cal['alpha']}")
    print(f"calibrated tau = {cal['tau']}  (escalation threshold with a >={1-cal['alpha']:.0%} "
          f"correctness guarantee on non-escalated decisions)")
    for point in cal["curve"]:
        mark = "  <- tau" if point["tau"] == cal["tau"] else ""
        print(f"  tau={point['tau']:.3f}  acc={point['accuracy']:.3f} (lower {point['acc_lower']:.3f})  "
              f"escalate={point['escalation_rate']:.0%}{mark}")
    if args.out:
        calibrate.save_calibration(args.out, cal)
        print(f"wrote {args.out}")
    return 0


def graph_flow(args) -> int:
    from prismpath.kernel import graph_export
    graph = parse_file(args.flow_md)
    out = (graph_export.to_mermaid_fenced if args.fenced else graph_export.to_mermaid)(graph, args.direction)
    print(out)
    return 0


def label_cmd(args) -> int:
    from prismpath.routing import routelog
    records = routelog.load_records(args.log)
    if not records:
        print(f"no records in {args.log}")
        return 1

    def ask(rec, targets):
        print(f"\n[{rec.get('flow')}/{rec.get('node')}] outcome: {(rec.get('outcome_text') or '')[:120]}")
        for index, cand in enumerate(rec.get("candidates", [])):
            sc = cand.get("score")
            score_str = f"  ({sc:.3f})" if isinstance(sc, (int, float)) else ""
            mark = "   <- router chose" if cand.get("target") == rec.get("chosen") else ""
            print(f"  {index+1}. {cand.get('target')}: {(cand.get('condition') or '')[:80]}{score_str}{mark}")
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


def lock_flow(args) -> int:
    from prismpath.routing import lockfile
    if args.check:
        try:
            lock = lockfile.load_lock(lockfile.lock_path(args.flow_md))
            # verify_tree degrades to the single-flow fingerprint check when there are no children.
            ok = lockfile.verify_tree(args.flow_md, policy="warn")
        except lockfile.LockError as exc:
            print(f"lock check FAILED: {exc}")
            return 1
        kids = len(lock.get("children") or {})
        tree = f" + {kids} pinned child lock(s)" if kids else ""
        print(f"lock OK - embedder reproduces the fingerprint{tree} (probe cosine "
              f"{lockfile.probe_cosine(lock):.6f})" if ok
              else "lock: drift detected (see warning above)")
        return 0 if ok else 1
    # Optional learned-routing pins: build per-condition centroids from a labeled benchmark and
    # commit the shrunk vectors (roadmap item #2 follow-on) - applies to the root flow only.
    centroids = counts = None
    if getattr(args, "centroids", None):
        from prismpath.routing import centroid
        from prismpath.kernel.parser import parse_file as _pf
        with open(args.centroids, encoding="utf-8") as fh:
            recs = [json.loads(line) for line in fh if line.strip()]
        graph = _pf(args.flow_md)
        centroids, counts = centroid.build_centroids(recs, {graph.name: graph})
        if not centroids:
            print(f"note: no labeled records in {args.centroids} matched this flow's semantic "
                  f"conditions - lock will pin zero-shot vectors only")
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
          f"delta={lock['delta']}{cen_s}{tree}")
    return 0


def _report(findings, as_json: bool) -> int:
    """Print findings and return an exit code (non-zero iff any error-severity finding)."""
    errors = [finding for finding in findings if finding.severity == "error"]
    warnings = [finding for finding in findings if finding.severity == "warning"]
    if as_json:
        print(json.dumps({
            "ok": not errors,
            "errors": len(errors), "warnings": len(warnings),
            "findings": [finding.as_dict() for finding in findings],
        }, indent=2))
        return 1 if errors else 0
    for finding in findings:
        print(finding)
    if not findings:
        print("  clean ✅  · the flow compiles")
    else:
        summary = []
        if errors:
            summary.append(f"{len(errors)} error(s)")
        if warnings:
            summary.append(f"{len(warnings)} warning(s)")
        print(f"\n{'✗ does not compile' if errors else '✅ compiles (with advisories)'}"
              f" - {', '.join(summary)}")
    return 1 if errors else 0


def validate_flow(args) -> int:
    graph = parse_file(args.flow_md)
    findings = list(analysis.analyze(graph))
    findings += analysis.analyze_composition(graph, args.flow_md)   # cross-flow @spawn checks (item #4)
    return _report(findings, args.json)


def contract_cmd(args) -> int:
    """Print each node's derived worker output contract (the fields its `when` edges read, with
    inferred types). Non-zero exit iff a field is used two incompatible ways (a real authoring bug)."""
    from prismpath.kernel import contract
    graph = parse_file(args.flow_md)
    contract_dict = contract.derive_contract(graph)
    if args.json:
        print(json.dumps({node_name: contract.to_json_schema(field_specs) for node_name, field_specs in contract_dict.items() if field_specs}, indent=2))
    else:
        print(contract.describe(contract_dict))
    conflicts = [(node_name, field_name) for node_name, field_specs in contract_dict.items() for field_name, field_spec in field_specs.items() if field_spec.get("conflict")]
    for node_name, field_name in conflicts:
        print(f"  ✗ [{node_name}] field {field_name!r}: {contract_dict[node_name][field_name]['conflict']}")
    return 1 if conflicts else 0


def annotate_cmd(args) -> int:
    from prismpath.evals import annotate
    annotate.annotate_loop(args.benchmark, args.out, flows_dir=args.flows_dir, limit=args.limit)
    return 0


def kappa_cmd(args) -> int:
    from prismpath.evals import kappa
    annotator_a, annotator_b = kappa.load(args.a), kappa.load(args.b)
    rep = kappa.report(annotator_a, annotator_b, by_stratum=args.by_stratum)
    print(json.dumps(rep, indent=2))
    print(f"\nCohen's kappa = {rep['kappa']} ({rep['band']}) over {rep['n']} co-labeled cases")
    if args.gold or args.disagreements:
        gold, dis = kappa.adjudicate(annotator_a, annotator_b)
        if args.gold:
            kappa.dump(gold, args.gold)
            print(f"wrote {len(gold)} agreed gold cases -> {args.gold} (a reproduce.py dataset)")
        if args.disagreements:
            kappa.dump(dis, args.disagreements)
            print(f"wrote {len(dis)} disagreements -> {args.disagreements} (for a 3rd-pass adjudication)")
    return 0


def centroids_cmd(args) -> int:
    from prismpath.routing import centroid
    with open(args.benchmark, encoding="utf-8") as fh:
        recs = [json.loads(line) for line in fh if line.strip()]
    res = centroid.cross_validate(recs, flows_dir=args.flows_dir, folds=args.folds, prior_weight=args.prior)
    print(json.dumps(res, indent=2))
    return 0


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
    write_file(os.path.join(mod, "__init__.py"), f'''"""{name} - an prismpath worker pack.

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
    """The gallery ships inside the package (sibling of this file in both repo layouts)."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "gallery")


def _gallery_templates() -> dict:
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
    templates = _gallery_templates()
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
        graph = parse_file(args.check)
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
    included). P0 = ML-free (runs on portable/prismpath.mjs anywhere); P1 = all reachable semantic
    edges are pinned in the lockfile, so routing needs only an outcome-side embedder (ONNX-able -
    appliance/edge); P2 = semantic edges not fully locked (full stack). Exit 0 iff P0 (unchanged
    contract: "portable" means the ML-free subset)."""
    graph = parse_file(args.flow_md)
    tree = analysis.portability_tier_tree(graph, args.flow_md)
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
              "Runs on portable/prismpath.mjs (browser/edge/appliance).",
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


def _gather_compile_inputs(flow_md_path: str, target_tier: str):
    """Gather and validate inputs for compiling a JS bundle."""
    from prismpath.kernel.parser import parse_file
    from prismpath.kernel import analysis
    from prismpath.routing import lockfile
    import base64

    parsed_graph = parse_file(flow_md_path)
    tier_tree = analysis.portability_tier_tree(parsed_graph, flow_md_path)
    flow_tier = tier_tree["tier"]

    if target_tier == "p0" and flow_tier != "P0":
        print(f"✗ Flow is not P0 (current tier: {flow_tier}). It has semantic edges. "
              f"Please rewrite them as deterministic 'when' predicates to compile for P0, "
              f"or compile for P1.")
        return None

    if target_tier == "p1" and flow_tier == "P2":
        print(f"✗ Flow has unlocked semantic edges (current tier: P2). "
              f"Please run `prismpath lock {flow_md_path}` first to commit routing vectors, "
              f"or rewrite them to compile for P0.")
        return None

    embedded_lock_js = "null"
    lock_data = {}
    compressed_conditions = {}
    if target_tier == "p1":
        import numpy as numpy_module
        lock_file_path = lockfile.lock_path(flow_md_path)
        if not os.path.exists(lock_file_path):
            print(f"✗ Lockfile missing: {lock_file_path}. Please run `prismpath lock {flow_md_path}` first.")
            return None
        try:
            lock_data = lockfile.load_lock(lock_file_path)
        except Exception as lock_exception:
            print(f"✗ Failed to load lockfile {lock_file_path}: {lock_exception}")
            return None

        for condition_str, f32_b64 in lock_data.get("conditions", {}).items():
            f32_bytes = base64.b64decode(f32_b64)
            array_f32 = numpy_module.frombuffer(f32_bytes, dtype="<f4").astype(numpy_module.float32)
            array_f16 = array_f32.astype(numpy_module.float16)
            compressed_conditions[condition_str] = base64.b64encode(array_f16.tobytes()).decode("ascii")

        embedded_lock_js = json.dumps({
            "delta": lock_data.get("delta", 0.05),
            "conditions": compressed_conditions
        }, indent=2)

    package_directory = os.path.dirname(os.path.abspath(__file__))
    kernel_path = os.path.join(package_directory, "portable", "prismpath.mjs")
    try:
        with open(kernel_path, "r", encoding="utf-8") as file_handle:
            js_kernel = file_handle.read()
    except Exception as file_exception:
        print(f"✗ Failed to read JS kernel from {kernel_path}: {file_exception}")
        return None

    nodes_dict = {}
    for node_name, node_obj in parsed_graph.nodes.items():
        nodes_dict[node_name] = {
            "name": node_name,
            "instruction": node_obj.instruction,
            "terminal": node_obj.terminal,
            "annotations": node_obj.annotations,
            "edges": node_obj.edges
        }
    parsed_graph_js = json.dumps({
        "name": parsed_graph.name,
        "start": parsed_graph.start,
        "nodes": nodes_dict
    }, indent=2)

    lock_info = {
        "lock_data": lock_data,
        "compressed_conditions": compressed_conditions
    }
    return js_kernel, parsed_graph_js, embedded_lock_js, lock_info


BUNDLE_ENGINE_FILE = "bundle_engine.mjs"
# The engine source is a real module that imports the kernel; the bundle inlines the kernel instead,
# so the import between these markers is dropped on the way in. The markers are the whole contract
# between the compiler here and portable/bundle_engine.mjs (test_compile asserts both sides of it).
BUNDLE_STRIP_BEGIN = "// prismpath-bundle-strip-begin"
BUNDLE_STRIP_END = "// prismpath-bundle-strip-end"


def _read_bundle_engine() -> str:
    """Read portable/bundle_engine.mjs and drop the import of the kernel the bundle inlines."""
    engine_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "portable", BUNDLE_ENGINE_FILE)
    with open(engine_path, "r", encoding="utf-8") as file_handle:
        engine_source = file_handle.read()
    begin_index = engine_source.find(BUNDLE_STRIP_BEGIN)
    end_index = engine_source.find(BUNDLE_STRIP_END)
    if begin_index < 0 or end_index < begin_index:
        raise RuntimeError(f"{engine_path} is missing its bundle strip markers")
    end_of_line = engine_source.find("\n", end_index)
    return engine_source[:begin_index] + engine_source[end_of_line + 1:]


def _build_compile_bundle(target_tier: str, js_kernel: str, parsed_graph_js: str, embedded_lock_js: str) -> str:
    """Assemble the standalone JS bundle containing kernel and serialized graph."""
    bundle_parts = []
    bundle_parts.append(f"// Auto-generated by prismpath compile --tier {target_tier}")
    bundle_parts.append("// Single-file portable JS bundle ready for Node/Browser.\n")
    bundle_parts.append(js_kernel)
    bundle_parts.append(f"\nexport const GRAPH = {parsed_graph_js};\n")
    bundle_parts.append(f"export const EMBEDDED_LOCK = {embedded_lock_js};\n")

    bundle_parts.append(_read_bundle_engine())
    # The engine takes the graph and the lock as arguments, so the bundle binds its own to the
    # runFlow(agent, opts) entry point that compiled bundles have always exported.
    bundle_parts.append(
        "\nexport function runFlow(agent, opts = {}) {\n"
        "  return runCompiled(GRAPH, EMBEDDED_LOCK, agent, opts);\n"
        "}\n")
    return "\n".join(bundle_parts)


def _b64_decoded_size(vector_b64: str) -> int:
    """The number of bytes a base64 payload decodes to, exactly. Three quarters of the encoded
    length counts the padding as data, which is what turned the compile report's KB figure into an
    estimate printed as a measurement."""
    text = vector_b64.strip()
    return len(text) * 3 // 4 - text.count("=")


def _write_compile_output(out_path: str, bundle_code: str, flow_md_path: str, target_tier: str, lock_info: dict) -> int:
    """Write the compiled bundle code to disk and print status feedback."""
    with open(out_path, "w", encoding="utf-8") as file_handle:
        file_handle.write(bundle_code)

    f32_size = 0
    f16_size = 0
    if target_tier == "p1":
        lock_data = lock_info.get("lock_data", {})
        compressed_conditions = lock_info.get("compressed_conditions", {})
        f32_size = sum(_b64_decoded_size(vector_b64) for vector_b64 in lock_data.get("conditions", {}).values())
        f16_size = sum(_b64_decoded_size(vector_b64) for vector_b64 in compressed_conditions.values())

    saving_message = f" (lock vectors compressed f32 -> f16: {f32_size/1024:.1f}KB -> {f16_size/1024:.1f}KB)" if target_tier == "p1" else ""
    print(f"✓ compiled {flow_md_path} to {out_path}{saving_message}")
    return 0


def compile_cmd(args) -> int:
    """Compile the flow and its lock into a single-file portable JS bundle."""
    gathered_inputs = _gather_compile_inputs(args.flow_md, args.tier)
    if gathered_inputs is None:
        return 1
    js_kernel, parsed_graph_js, embedded_lock_js, lock_info = gathered_inputs
    bundle_code = _build_compile_bundle(args.tier, js_kernel, parsed_graph_js, embedded_lock_js)
    out_path = args.out or (os.path.splitext(args.flow_md)[0] + ".bundle.mjs")
    return _write_compile_output(out_path, bundle_code, args.flow_md, args.tier, lock_info)


def compose_cmd(args) -> int:
    """Advance every pending fan-out in the queue by one tick: spawn/poll children and, where a join is
    ready, aggregate + resume the parent. The out-of-band harness a deployment runs on a schedule
    (mirrors the timeout scanner). Uses the mock agent, like `run`/`resume`."""
    from prismpath.workers import composer
    recs = composer.advance_fanouts(_mock_agent, qdir=args.queue)
    for record in recs:
        if record.get("error"):
            print(f"  ✗ {record['path']}: {record['error']}")
        elif record.get("joined"):
            print(f"  [{record.get('node')}] {record.get('done', 0)}/{record.get('spawned', 0)} children done "
                  f"-> joined ({record.get('event')}), parent resumed")
        else:
            print(f"  [{record.get('node')}] {record.get('done', 0)}/{record.get('spawned', 0)} children done "
                  f"-> still waiting")
    print(f"advanced {len(recs)} fan-out(s)")
    return 0


def lint_flow(args) -> int:
    graph = parse_file(args.flow_md)
    findings = list(analysis.analyze(graph))
    findings += analysis.analyze_composition(graph, args.flow_md)   # cross-flow @spawn checks (item #4)
    # the non-decidable checks (need the embedder): near-ties, and polarity mirrors (the 0.82 class).
    from prismpath.kernel.lint import semantic_ambiguity, polarity_mirror
    findings += semantic_ambiguity(graph)
    findings += polarity_mirror(graph)
    findings.sort(key=lambda finding: (finding.severity != "error", finding.code, finding.node or ""))
    return _report(findings, args.json)


def _parse_fields(spec):
    return dict(part.split(":", 1) for part in spec.split(",")) if spec else {}


def swap_cmd(args):
    """Secure policy hot-swap CLI (spec-secure-hotswap). Loud absence: a missing `cryptography`
    surfaces the install message and exits non-zero, never a silent pass."""
    import json as _json
    try:
        from prismpath.hotswap import policy_pack
        from prismpath.hotswap import policy_host
    except Exception as exc:                                  # pragma: no cover
        print(str(exc), file=sys.stderr)
        return 2
    action = args.action
    try:
        if action == 'keygen':
            print(_json.dumps(policy_pack.keygen(args.out or '.', args.name), indent=1))
            return 0
        if action == 'pack':
            if not (args.ppt and args.priv and args.pub):
                print('pack needs --ppt --priv --pub', file=sys.stderr)
                return 2
            manifest = policy_pack.build_pack(args.ppt, _parse_fields(args.fields), args.version,
                                              args.envelope_id, args.priv, args.pub[0], overlay_of=args.overlay_of)
            print(_json.dumps(manifest, indent=1))
            return 0
        if action == 'verify':
            if not (args.ppt and args.pub):
                print('verify needs --ppt --pub', file=sys.stderr)
                return 2
            ok, reasons, _manifest = policy_pack.verify_pack(args.ppt, args.pub, policy_pack.load_revoked(args.revoked))
            print(_json.dumps({'ok': ok, 'reasons': reasons}, indent=1))
            return 0 if ok else 1
        if action == 'envelope':
            if not (args.priv and args.pub and args.out):
                print('envelope needs --priv --pub --out', file=sys.stderr)
                return 2
            caps = ({key: int(val) for key, val in (kv.split("=", 1) for kv in args.caps.split(","))}
                    if args.caps else None)
            env = policy_pack.build_envelope(args.envelope_id, _parse_fields(args.fields), caps,
                                             args.priv, args.pub[0], args.out)
            print(_json.dumps(env, indent=1))
            return 0
        if action in ('swap', 'attest'):
            if not (args.out and args.pub and args.envelope):
                print(f'{action} needs --out (state dir) --pub --envelope', file=sys.stderr)
                return 2
            env, reasons = policy_pack.load_envelope(args.envelope, args.pub)
            if env is None:
                print(_json.dumps({'ok': False, 'reasons': reasons}, indent=1))
                return 1
            host = policy_host.PolicyHost(args.out, args.pub, env, revoked=policy_pack.load_revoked(args.revoked))
            if action == 'attest':
                print(_json.dumps(host.attest(), indent=1))
                return 0
            if not args.ppt:
                print('swap needs --ppt', file=sys.stderr)
                return 2
            res = host.swap(args.ppt, allow_unsigned=args.allow_unsigned)
            print(_json.dumps(res, indent=1))
            return 0 if res.get('ok') else 1
    except RuntimeError as exc:                               # loud absence (no cryptography)
        print(str(exc), file=sys.stderr)
        return 2
    return 2


def ledger_cmd(args):
    """Flow-Ledger attestation CLI (#36 connected OTS + #53 air-gap tier)."""
    import json as _json
    from prismpath.ledgers import ledger_ots as ots
    from prismpath.ledgers import ledger_airgap as airgap
    action = args.action
    if action == 'anchor':
        hashes = ots.from_ledger(args.repo) if args.repo else []
        if not hashes:
            print('no Output-Hash values found in ledger (need --repo with PrismPath-Output-Hash trailers)')
            return 1
        res = ots.anchor(hashes, args.out or '.', args.label)
        print(_json.dumps(res, indent=1))
        return 0 if res.get('stamped') else 1
    if action == 'upgrade':
        res = ots.upgrade(args.out or '.', args.label)
        print(_json.dumps(res, indent=1))
        return 0 if res.get('ots_rc') == 0 else 1
    if action == 'verify':
        if not args.leaf:
            print('--leaf <hex> required for verify')
            return 2
        res = ots.verify_unit(args.leaf, args.out or '.', args.label)
        print(_json.dumps(res, indent=1))
        return 0 if res.get('merkle_ok') and res.get('ots_ok') else 1
    if action == 'export-request':
        if not (args.root and args.out):
            print('--root and --out required for export-request')
            return 2
        res = airgap.export_stamp_request([(args.root, args.label)], args.out,
                                      policy_hash=args.policy_hash, gate_id=args.gate_id)
        print(_json.dumps(res, indent=1))
        return 0
    if action == 'relay-stamp':
        if not (args.request and args.out):
            print('--request and --out required for relay-stamp')
            return 2
        print(_json.dumps(airgap.relay_stamp(args.request, args.out), indent=1))
        return 0
    if action == 'import-proofs':
        if not args.proofs:
            print('--proofs required for import-proofs')
            return 2
        print(_json.dumps(airgap.import_proofs(args.proofs, args.dir or '.'), indent=1))
        return 0
    if action == 'rfc3161':
        if not args.root:
            print('--root required for rfc3161')
            return 2
        if args.tsr and args.cafile:
            res = airgap.rfc3161_verify(args.root, args.tsr, args.cafile)
            print(_json.dumps(res, indent=1))
            return 0 if res.get('verified') else 1
        print(_json.dumps(airgap.rfc3161_query(args.root), indent=1))
        return 0
    print('unknown ledger action: ' + str(action))
    return 2


def _load_telemetry():
    """The Facet codec ships in the package (prismpath.telemetry); PROTOCOL.md is its specification."""
    from prismpath.telemetry import packed, quantizer, wire, zeckendorf
    return quantizer, zeckendorf, wire, packed


def facet_cmd(args) -> int:
    quantizer, zeckendorf, wire, packed = _load_telemetry()
    graph = parse_file(args.flow_md)
    parts = quantizer.build_partitions(graph)
    action = args.action

    if action in ('quantize', 'encode'):
        if os.path.exists(args.payload):
            with open(args.payload, "r", encoding="utf-8") as fh:
                reading = json.load(fh)
        else:
            reading = json.loads(args.payload)

        order = sorted(parts.keys())
        missing = [field_name for field_name in order if field_name not in reading]
        if missing:
            raise KeyError(f"reading missing decision fields: {missing}")

        syms = quantizer.quantize(parts, reading)

        if action == 'quantize':
            symbol_tuple = tuple(syms[field_name] for field_name in order)
            print(symbol_tuple)
            return 0
        elif action == 'encode':
            bits = wire.encode_reading(parts, reading)
            raw_bytes = packed.pack(bits, 8)
            print(raw_bytes.hex())
            return 0

    elif action == 'decode':
        raw_bytes = bytes.fromhex(args.payload)
        bits = packed.unpack(raw_bytes)
        recon_reading = wire.decode_reading(parts, bits)

        start_node = graph.start
        route = None
        cause = None

        if start_node in graph.nodes:
            from prismpath.kernel import predicates
            for target, cond in graph.nodes[start_node].edges:
                if predicates.is_deterministic(cond) and predicates.eval_condition(cond, recon_reading):
                    route = target
                    cause = cond
                    break

        print(f"Next node: {route}")
        print(f"Cause: {cause}")
        return 0

    return 2


if __name__ == '__main__':
    raise SystemExit(main())
