"""Item #5 T3: CROSS-LANGUAGE conformance — the Python engine and portable/prismpath.mjs must route
IDENTICALLY on the portable subset.

Each fixture is a flow + a per-node script of outcomes (consumed in visit order; `__raise__`
throws, exercising the error tier). Both engines replay every fixture; paths, stop reasons, and
the pending node must match exactly. This is the evidence behind "the auditable subset runs
anywhere" — not a claim, a diff. Skips cleanly when node isn't installed.

The fixtures deliberately torture the predicate-semantics parity: bool==1, chained comparisons,
substring `in`, tuple membership, True-vs-true (constant vs field name), missing fields,
not-in-on-type-error, []-is-falsy, visits loops, else, error_count escalation, wait/needs_human
suspension, spawn passthrough, stuck, and max_steps.
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from prismpath.engine import run
from prismpath.parser import parse

NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="node not installed — portable port untested here")

REPO = Path(__file__).resolve().parent.parent


def scripted_agent(script: dict):
    used: dict = {}
    def agent(node, instruction, state):
        seq = script.get(node)
        if seq is None:
            return {"text": node}
        i = used.get(node, 0)
        used[node] = i + 1
        outcome = seq[min(i, len(seq) - 1)]
        if isinstance(outcome, dict) and "__raise__" in outcome:
            raise RuntimeError(outcome["__raise__"])
        return outcome
    return agent


# ---------------------------------------------------------------------------- fixtures
PREDICATE_FLOW = """---
name: predicates
start: route
---

## route
Route on the emitted fields. NB the guards: with every field missing, an unguarded
`x == true` would be None == None (true) and an unguarded `a not in b` is not-in-on-None
(satisfied) — both would shadow every later edge. The guards keep each fixture on its
own branch, which the meta-check below enforces.
-> chained: when 1 < n < 5
-> boolnum: when flag == 1
-> substr: when "error" in text
-> member: when action in ("contain", "watch")
-> pyconst: when x == True
-> fieldname: when x == true and x != None
-> notin: when a and a not in b
-> empty: when items
-> done: else

## chained
-> route: when visits < 2
-> done: else

## boolnum
-> done: always

## substr
-> done: always

## member
-> done: always

## pyconst
-> done: always

## fieldname
-> done: always

## notin
-> done: always

## empty
-> done: always

## done
Done.
"""

ERROR_FLOW = """---
name: errors
start: work
---

## work
-> recovered: on error when error_count >= 2
-> work: on error
-> done: when ok

## recovered
Recovered.

## done
Done.
"""

WAIT_FLOW = """---
name: waits
start: hold
---

## hold
-> go: on event ping
-> bail: on timeout

## go
Done.

## bail
Bailed.
"""

LOOP_FLOW = """---
name: loops
start: spin
---

## spin
-> spin: when visits < 100
-> out: else

## out
Done.
"""


def _fx(name, flow, script, **kw):
    return {"name": name, "flow": flow, "script": script, **kw}


FIXTURES = [
    # -- predicate torture: each case picks a different branch of PREDICATE_FLOW
    _fx("chained-comparison", PREDICATE_FLOW, {"route": [{"text": "r", "n": 3}]}),
    _fx("bool-eq-one", PREDICATE_FLOW, {"route": [{"text": "r", "flag": True}]}),
    _fx("substring-in", PREDICATE_FLOW, {"route": [{"text": "r", "text": "an error happened"}]}),
    _fx("tuple-membership", PREDICATE_FLOW, {"route": [{"text": "r", "action": "watch"}]}),
    _fx("True-is-a-constant", PREDICATE_FLOW, {"route": [{"text": "r", "x": True}]}),
    _fx("true-is-a-field-name", PREDICATE_FLOW, {"route": [{"text": "r", "x": 7, "true": 7}]}),
    _fx("not-in-on-type-error-satisfied", PREDICATE_FLOW, {"route": [{"text": "r", "a": 1, "b": 42}]}),
    _fx("empty-list-is-falsy", PREDICATE_FLOW, {"route": [{"text": "r", "items": []}]}),
    _fx("nonempty-list-is-truthy", PREDICATE_FLOW, {"route": [{"text": "r", "items": [1]}]}),
    _fx("missing-fields-fall-to-else", PREDICATE_FLOW, {"route": [{"text": "r"}]}),
    _fx("string-vs-int-ordering-unsatisfied", PREDICATE_FLOW, {"route": [{"text": "r", "n": "three"}]}),
    _fx("float-int-equality", PREDICATE_FLOW, {"route": [{"text": "r", "flag": 1.0}]}),
    # -- engine mechanics
    _fx("visits-loop", PREDICATE_FLOW,
        {"route": [{"text": "r", "n": 2}], "chained": [{"text": "c"}]}),
    _fx("error-count-escalation", ERROR_FLOW,
        {"work": [{"__raise__": "kapow"}, {"__raise__": "kapow again"}]}),
    _fx("error-then-success", ERROR_FLOW,
        {"work": [{"__raise__": "once"}, {"text": "w", "ok": True}]}),
    _fx("wait-suspension", WAIT_FLOW, {"hold": [{"text": "h", "wait": True, "timeout_s": 60}]}),
    _fx("spawn-implies-wait", WAIT_FLOW,
        {"hold": [{"text": "h", "spawn": {"items": [1, 2], "child": "x.md"}}]}),
    _fx("needs-human", WAIT_FLOW, {"hold": [{"text": "h", "needs_human": True, "reason": "?"}]}),
    _fx("resume-reentry-at-event-target", WAIT_FLOW, {"go": [{"text": "g"}]}, start="go",
        state={"transcript": [], "visits": {"hold": 1}}),
    _fx("stuck-deterministic-no-match", ERROR_FLOW, {"work": [{"text": "w", "ok": False}]}),
    _fx("max-steps", LOOP_FLOW, {"spin": [{"text": "s"}]}, maxSteps=10),
]

# ---- fixtures added from the DIFFERENTIAL FUZZER's findings (each covers a fixed divergence) ----
KEYWORD_FLOW = """---
name: kw
start: route
---

## route
`class` is a Python hard keyword: this predicate is a PredicateError on BOTH engines, so the
edge is non-matching and everything falls to else — never a route flip.
-> quarantine: when class == "phish"
-> review: else

## quarantine
Q.

## review
R.
"""

PYSTR_FLOW = """---
name: pystr
start: route
---

## route
A PLAIN (non-dict) outcome becomes `text` via Python str(): True -> "True", None -> "None".
-> got_true: when text == "True"
-> got_none: when text == "None"
-> other: else

## got_true
T.

## got_none
N.

## other
O.
"""

PAREN_FLOW = """---
name: parens
start: route
---

## route
Ten nested parens add ZERO AST depth in Python — the port must agree.
-> deep: when ((((((((((x))))))))))
-> flat: else

## deep
D.

## flat
F.
"""

FIXTURES += [
    _fx("python-keyword-field-name-is-error-both-sides", KEYWORD_FLOW,
        {"route": [{"text": "r", "class": "phish"}]}),                 # both must land on `review`
    _fx("plain-bool-outcome-pystr", PYSTR_FLOW, {"route": [True]}),    # str(True) == "True"
    _fx("plain-none-outcome-pystr", PYSTR_FLOW, {"route": [None]}),    # str(None) == "None"
    _fx("dict-with-none-text", PYSTR_FLOW, {"route": [{"text": None}]}),
    _fx("deep-parens-zero-ast-depth", PAREN_FLOW, {"route": [{"text": "r", "x": 1}]}),
    _fx("top-level-tuple-always-truthy", parse_flow_src := """---
name: tup
start: route
---

## route
A bare `when done, verified` is a TUPLE in Python — non-empty, so ALWAYS truthy (a real trap,
but parity first; both engines must take it).
-> trap: when done, verified
-> safe: else

## trap
T.

## safe
S.
""", {"route": [{"text": "r"}]}),
]


def _python_results():
    out = []
    for fx in FIXTURES:
        graph = parse(fx["flow"])
        res = run(graph, scripted_agent(fx["script"]), max_steps=fx.get("maxSteps", 25),
                  start=fx.get("start"), state=json.loads(json.dumps(fx["state"])) if "state" in fx else None)
        out.append({"name": fx["name"], "path": res.path, "stopped": res.stopped,
                    "pending_node": (res.pending or {}).get("node"),
                    "spawn": (res.pending or {}).get("spawn")})
    return out


def _js_results(tmp_path):
    fixtures_file = tmp_path / "fixtures.json"
    fixtures_file.write_text(json.dumps(FIXTURES))
    p = subprocess.run([NODE, str(REPO / "portable" / "run_conformance.mjs"), str(fixtures_file)],
                       capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, f"node runner failed: {p.stderr[:500]}"
    out = []
    for r in json.loads(p.stdout):
        assert "error" not in r, f"port errored on {r['name']}: {r.get('error')}"
        out.append({"name": r["name"], "path": r["path"], "stopped": r["stopped"],
                    "pending_node": (r.get("pending") or {}).get("node"),
                    "spawn": (r.get("pending") or {}).get("spawn")})
    return out


def test_python_and_port_route_identically(tmp_path):
    py = _python_results()
    js = _js_results(tmp_path)
    assert len(py) == len(js) == len(FIXTURES)
    for a, b in zip(py, js):
        assert a == b, (f"CONFORMANCE DIVERGENCE on {a['name']!r}:\n  python: {a}\n  port:   {b}")


def test_fixture_branches_actually_diverge():
    # meta-check: the predicate fixtures genuinely exercise DIFFERENT branches (a fixture set that
    # all routed to `done` would vacuously pass conformance).
    py = _python_results()
    branches = {r["path"][1] for r in py if r["name"].count("-") and len(r["path"]) > 1
                and r["path"][0] == "route"}
    assert len(branches) >= 7, f"fixtures collapsed to too few branches: {branches}"
