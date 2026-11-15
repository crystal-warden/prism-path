# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The engine level conformance fixtures: flows, scripted worker outcomes, and the scripted worker.

`gen_conformance.py` computes the expected results for these from the Python engine and writes
`conformance/flows.json`; every kernel implementation is judged against that file. The fixtures used
to live inside the JavaScript port's parity test, which this distribution does not carry, so they
are a plain module here. Their content is byte for byte what the research test file at the adopted
revision holds (see PROVENANCE.md), which is why the committed vectors still regenerate identically.
"""


def raised(outcome: dict):
    """The exception a `{"__raise__": msg}` outcome stands for. `__kind__` names its class, so the engine's
    error context carries that name as `error_type`; without it the class is RuntimeError. A class made
    here has no base but Exception, which is all `type(exc).__name__` and `str(exc)` read."""
    kind = outcome.get("__kind__", "RuntimeError")
    if kind == "RuntimeError":
        return RuntimeError(outcome["__raise__"])
    return type(kind, (Exception,), {})(outcome["__raise__"])


def scripted_agent(script: dict):
    used: dict = {}
    def agent(node, instruction, state):
        seq = script.get(node)
        if seq is None:
            return {"text": node}
        index = used.get(node, 0)
        used[node] = index + 1
        outcome = seq[min(index, len(seq) - 1)]
        if isinstance(outcome, dict) and "__raise__" in outcome:
            raise raised(outcome)
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
