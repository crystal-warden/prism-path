# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Routing lockfile, calibration, labeling, and evaluation commands."""
import json
import sys

from prismpath.cli.common import CliError, require_file


def register(subparsers) -> None:
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


def calibrate_cmd(args) -> int:
    from prismpath.routing import calibrate
    from prismpath.routing import routelog
    require_file(args.labels)
    recs = routelog.load_records(args.labels)
    cal = calibrate.calibrate(recs, alpha=args.alpha)
    if cal["n"] == 0:
        raise CliError(f"{args.labels} has no labeled routing decisions with a margin, so there is nothing to "
                       "calibrate from. Semantic decisions are logged with their margin by run_logged "
                       "(then `prismpath label`), and `prismpath test --emit-labels` records the margin of "
                       "every row that routed through the embedder.")
    print(f"n={cal['n']} labeled decisions; target risk alpha={cal['alpha']}")
    print(f"calibrated tau = {cal['tau']}  (escalation threshold with a >={1-cal['alpha']:.0%} "
          f"correctness guarantee on non-escalated decisions)")
    for point in cal["curve"]:
        mark = "  <- tau" if point["tau"] == cal["tau"] else ""
        print(f"  tau={point['tau']:.3f}  acc={point['accuracy']:.3f} (lower {point['acc_lower']:.3f})  "
              f"escalate={point['escalation_rate']:.0%}{mark}")
    if cal.get("warning"):
        print(f"warning: {cal['warning']}", file=sys.stderr)
    if args.out:
        calibrate.save_calibration(args.out, cal)
        print(f"wrote {args.out}")
    return 0


def label_cmd(args) -> int:
    from prismpath.routing import routelog
    require_file(args.log)
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
    if not res:
        # an empty report used to print as `{}` and exit 0
        raise CliError(f"no row of {args.benchmark} is a semantic routing decision in the flows it names "
                       "(a row needs a flow with semantic edges at that node, and a label that is one of its targets); "
                       "--flows-dir says where the flows are")
    print(json.dumps(res, indent=2))
    return 0
