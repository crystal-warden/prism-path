"""annotate.py — blind human labeling of the routing benchmark for inter-annotator κ (gate zero).

Steps a human through each benchmark case with the AI label HIDDEN: it shows the node's instruction,
the worker's outcome, and the node's out-edges (numbered), and records which edge the annotator picks.
Output is benchmark-shaped (`{flow, node, outcome, label, stratum}`) so two annotators' files feed
`prismpath kappa` directly and the adjudicated gold is a drop-in `reproduce.py` dataset.

Resumable (skips cases already in the output file) and I/O-injectable (input_fn/print_fn) so the loop
is unit-testable without a TTY. See `prismpath.kappa` for the agreement math.
"""
from __future__ import annotations

import json
import os
from typing import Callable, Iterator, List, Optional

from prismpath.parser import parse_file

_FLOWS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "flows")


def _key(c: dict):
    return (c.get("flow", ""), c.get("node", ""), (c.get("outcome") or "").strip())


def blind_cases(benchmark_path: str, flows_dir: Optional[str] = None) -> Iterator[dict]:
    """Yield each labeled benchmark case with its LABEL STRIPPED and the node's out-edges resolved from
    the flow (target + condition), so an annotator sees only the decision, never the intended answer."""
    flows_dir = flows_dir or _FLOWS
    graphs = {}
    for line in open(benchmark_path, encoding="utf-8"):
        if not line.strip():
            continue
        c = json.loads(line)
        flow = c["flow"]
        if flow not in graphs:
            graphs[flow] = parse_file(os.path.join(flows_dir, f"{flow}.md"))
        node = graphs[flow].nodes[c["node"]]
        yield {"flow": flow, "node": c["node"], "outcome": c["outcome"], "stratum": c.get("stratum"),
               "instruction": node.instruction, "edges": list(node.edges),
               "targets": [t for t, _ in node.edges]}


def _done_keys(out_path: str) -> set:
    if not os.path.exists(out_path):
        return set()
    return {_key(json.loads(l)) for l in open(out_path, encoding="utf-8") if l.strip()}


def _resolve(raw: str, targets: List[str]) -> Optional[str]:
    """Map a raw entry (edge number 1..N, or an exact target name) to a target, or None to skip."""
    raw = raw.strip()
    if raw.isdigit() and 1 <= int(raw) <= len(targets):
        return targets[int(raw) - 1]
    return raw if raw in targets else None


def present(case: dict) -> str:
    """The blind prompt for one case (used by the loop and testable on its own)."""
    lines = [f"[{case['flow']}/{case['node']}]  ({case.get('stratum', '?')})",
             f"  instruction: {case['instruction'][:200]}",
             f"  OUTCOME: {case['outcome']}",
             "  which edge should this route to?"]
    for i, (t, c) in enumerate(case["edges"], 1):
        lines.append(f"    {i}. -> {t}: {c}")
    return "\n".join(lines)


def annotate_loop(benchmark_path: str, out_path: str, flows_dir: Optional[str] = None,
                  input_fn: Callable[[str], str] = input, print_fn: Callable[[str], None] = print,
                  limit: Optional[int] = None) -> int:
    """Interactive blind-annotation loop. Appends one benchmark-shaped record per pick; blank input
    skips a case, 'q' saves and quits. Returns the number of cases labeled this session."""
    cases = list(blind_cases(benchmark_path, flows_dir))
    done = _done_keys(out_path)
    todo = [c for c in cases if _key(c) not in done]
    if limit is not None:
        todo = todo[:limit]
    print_fn(f"{len(done)} already labeled, {len(todo)} to go ({len(cases)} total). "
             f"Enter the edge number (or name); blank = skip, q = save & quit.")
    n = 0
    with open(out_path, "a", encoding="utf-8") as f:
        for case in todo:
            print_fn("\n" + present(case))
            raw = input_fn("pick> ")
            if raw.strip().lower() in ("q", "quit"):
                break
            pick = _resolve(raw, case["targets"])
            if pick is None:
                print_fn("  (skipped)")
                continue
            f.write(json.dumps({"flow": case["flow"], "node": case["node"], "outcome": case["outcome"],
                                "label": pick, "stratum": case.get("stratum")}) + "\n")
            f.flush()
            n += 1
    print_fn(f"\nlabeled {n} case(s) this session -> {out_path}")
    return n
