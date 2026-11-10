# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The engine fixtures for the options the frozen fixtures leave out: the type gate and the transcript bound.

`gen_conformance.py` runs each of these on the Python engine and appends the result to `conformance/flows.json`
after the frozen cases. A fixture here carries `opts`, the keyword arguments of `run()` (`type_gate`,
`max_transcript`), and its `expect` gains what those options change: `reason` and `violations` (the pending
decision a contract violation leaves), `transcript` (the persisted history after the bound) and
`state_dropped` (what the bound dropped). An engine that does not implement the options skips a case that
has `opts`; one that does must reproduce every key.

A case whose `@state_bound` is malformed has `expect` of `{"error": <the ValueError's message>,
"error_class": "ValueError"}`: the run does not start. The same shape records every refusal the engine
raises instead of returning a result: a worker error no edge handles (the worker's own class and message),
and a route into a node the flow does not define (a bare `KeyError` on the node name).

A worker failure is scripted as `{"__raise__": <message>, "__kind__": <class name>}`; without `__kind__` the
class is RuntimeError. The engine hands the class name to the flow as `error_type`.
"""

GATE_FLOW = """---
name: gate
start: triage
---

## triage
Triage the alert. The edges read `severity` (an enum), `confirmed` (a boolean) and `score` (a number).
-> contain: when severity == "high" and confirmed
-> review: when score >= 0.8
-> close: else
-> held: on error

## contain
-> done: when approved
-> held: else

## review
-> done: always

## close
-> done: always

## held
-> done: always

## done
Done.
"""

TEXT_GATE_FLOW = """---
name: textgate
start: read
---

## read
-> hit: when "error" in text
-> miss: else

## hit
Hit.

## miss
Miss.
"""

BOUND_FLOW = """---
name: bounded
start: spin
---

## spin
@state_bound(transcript=3)
-> spin: when visits < 5
-> out: else

## out
Done.
"""

PLAIN_LOOP_FLOW = """---
name: plainloop
start: spin
---

## spin
-> spin: when visits < 5
-> out: else

## out
Done.
"""

FIRST_BOUND_WINS_FLOW = """---
name: firstwins
start: a
---

## a
-> b: always

## b
@state_bound(transcript=4)
-> c: always

## c
@state_bound(transcript=2)
-> d: always

## d
-> e: always

## e
-> f: always

## f
Done.
"""

REPEATED_BOUND_FLOW = """---
name: repeated
start: spin
---

## spin
@state_bound(transcript=2)
@state_bound(transcript=4)
-> spin: when visits < 7
-> out: else

## out
Done.
"""

ERROR_BOUND_FLOW = """---
name: errorbound
start: work
---

## work
@state_bound(transcript=1)
-> work: on error
-> done: when ok

## done
Done.
"""


ERROR_TYPE_FLOW = """---
name: errortype
start: work
---

## work
-> timed_out: on error when error_type == "TimeoutError"
-> bad_input: on error when error_type in ("ValueError", "KeyError")
-> exact: on error when error_message == "exactly this"
-> runtime: on error when error_type == "RuntimeError"
-> other: on error
-> done: when ok

## timed_out
Timed out.

## bad_input
Bad input.

## exact
Exact.

## runtime
Runtime.

## other
Other.

## done
Done.
"""

ERROR_TYPE_COUNT_FLOW = """---
name: errortypecount
start: work
---

## work
-> work: on error when error_type == "ValueError" and error_count < 3
-> failed: on error when error_type == "ValueError"
-> done: when ok

## failed
Failed.

## done
Done.
"""

GUARD_FLOW = """---
name: guard
start: work
---

## work
-> handled: on error when len(error_message) > 3
-> fallback: on error
-> done: when ok

## handled
Handled.

## fallback
Fallback.

## done
Done.
"""

GUARD_TWO_FLOW = """---
name: guardtwo
start: work
---

## work
-> first: on error when error_message ==
-> second: on error when len(error_message) > 3
-> third: on error when error_type == "ValueError"
-> fallback: on error
-> done: when ok

## first
First.

## second
Second.

## third
Third.

## fallback
Fallback.

## done
Done.
"""

GUARD_LOOP_FLOW = """---
name: guardloop
start: work
---

## work
-> bad: on error when len(error_message) > 3
-> work: on error when error_count < 3
-> failed: on error
-> done: when ok

## bad
Bad.

## failed
Failed.

## done
Done.
"""

GUARD_AFTER_MATCH_FLOW = """---
name: guardaftermatch
start: work
---

## work
-> matched: on error when error_count >= 1
-> never: on error when len(error_message) > 3
-> done: when ok

## matched
Matched.

## never
Never.

## done
Done.
"""

GUARD_OTHER_NODE_FLOW = """---
name: guardother
start: first
---

## first
-> bad: on error when len(error_message) > 3
-> second: on error
-> done: when ok

## second
-> bad: on error when len(error_message) > 3
-> fallback: on error
-> done: when ok

## bad
Bad.

## fallback
Fallback.

## done
Done.
"""

GUARD_NO_HANDLER_FLOW = """---
name: guardnohandler
start: work
---

## work
-> handled: on error when len(error_message) > 3
-> done: when ok

## handled
Handled.

## done
Done.
"""

ERROR_TYPE_ONLY_FLOW = """---
name: errortypeonly
start: work
---

## work
-> timed_out: on error when error_type == "TimeoutError"
-> done: when ok

## timed_out
Timed out.

## done
Done.
"""

NO_HANDLER_FLOW = """---
name: nohandler
start: work
---

## work
-> done: when ok

## done
Done.
"""

GHOST_FLOW = """---
name: ghost
start: work
---

## work
-> ghost: always

## done
Done.
"""

GHOST_START_FLOW = """---
name: ghoststart
start: nowhere
---

## work
-> done: always

## done
Done.
"""

ERROR_GHOST_FLOW = """---
name: errorghost
start: work
---

## work
-> nowhere: on error
-> done: when ok

## done
Done.
"""



def _bound_flow(value: str) -> str:
    return PLAIN_LOOP_FLOW.replace("## spin\n", f"## spin\n@state_bound(transcript={value})\n")


def _fx(name, flow, script, **kw):
    return {"name": name, "flow": flow, "script": script, **kw}


GATE_OK = {"text": "t", "severity": "high", "confirmed": True}

FIXTURES = [
    # -- the type gate
    _fx("type-gate-passes-a-well-typed-output", GATE_FLOW,
        {"triage": [GATE_OK], "contain": [{"text": "c", "approved": True}]}, opts={"type_gate": True}),
    _fx("type-gate-stops-on-a-wrong-type", GATE_FLOW,
        {"triage": [{"text": "t", "severity": "high", "confirmed": "yes"}]}, opts={"type_gate": True}),
    _fx("type-gate-off-routes-the-same-wrong-type", GATE_FLOW,
        {"triage": [{"text": "t", "severity": "high", "confirmed": "yes"}]}, opts={"type_gate": False}),
    _fx("no-options-route-the-same-wrong-type", GATE_FLOW,
        {"triage": [{"text": "t", "severity": "high", "confirmed": "yes"}]}, opts={}),
    _fx("type-gate-lists-every-violation-in-field-order", GATE_FLOW,
        {"triage": [{"text": "t", "score": "hi", "confirmed": "yes", "severity": 7}]}, opts={"type_gate": True}),
    _fx("type-gate-a-boolean-is-not-a-number", GATE_FLOW,
        {"triage": [{"text": "t", "severity": "low", "confirmed": False, "score": True}]}, opts={"type_gate": True}),
    _fx("type-gate-a-list-is-not-a-number", GATE_FLOW,
        {"triage": [{"text": "t", "severity": "low", "confirmed": False, "score": [1, "a"]}]}, opts={"type_gate": True}),
    _fx("type-gate-quotes-in-a-wrong-value", GATE_FLOW,
        {"triage": [{"text": "t", "severity": {"it's": "a \"b\""}, "confirmed": True}]}, opts={"type_gate": True}),
    _fx("type-gate-null-is-not-a-violation", GATE_FLOW,
        {"triage": [{"text": "t", "severity": None, "confirmed": None, "score": None}]}, opts={"type_gate": True}),
    _fx("type-gate-missing-fields-are-not-violations", GATE_FLOW,
        {"triage": [{"text": "t"}]}, opts={"type_gate": True}),
    _fx("type-gate-an-unrouted-value-is-not-a-violation", GATE_FLOW,
        {"triage": [{"text": "t", "severity": "low", "confirmed": True, "score": 0.1}]}, opts={"type_gate": True}),
    _fx("type-gate-stops-at-the-node-that-emits-the-wrong-type", GATE_FLOW,
        {"triage": [GATE_OK], "contain": [{"text": "c", "approved": "yes"}]}, opts={"type_gate": True}),
    _fx("type-gate-runs-before-the-human-handoff", GATE_FLOW,
        {"triage": [{"needs_human": True, "reason": "unsure", "confirmed": "yes"}]}, opts={"type_gate": True}),
    _fx("human-handoff-without-the-gate", GATE_FLOW,
        {"triage": [{"needs_human": True, "reason": "unsure", "confirmed": "yes"}]}, opts={"type_gate": False}),
    _fx("type-gate-runs-before-the-wait", GATE_FLOW,
        {"triage": [{"wait": True, "severity": 3}]}, opts={"type_gate": True}),
    _fx("type-gate-a-plain-outcome-has-only-text", TEXT_GATE_FLOW, {"read": ["an error happened"]}, opts={"type_gate": True}),
    _fx("type-gate-a-plain-outcome-misses-a-field-note", GATE_FLOW, {"triage": ["just text"]}, opts={"type_gate": True}),
    _fx("type-gate-holds-on-reentry", GATE_FLOW, {"contain": [{"text": "c", "approved": 1}]}, start="contain",
        state={"transcript": [], "visits": {"triage": 1}}, opts={"type_gate": True}),
    _fx("type-gate-leaves-an-error-edge-alone", GATE_FLOW,
        {"triage": [{"__raise__": "kapow"}]}, opts={"type_gate": True, "max_transcript": 1}),
    # -- the state bound
    _fx("bound-by-annotation", BOUND_FLOW, {"spin": [{"text": "s"}]}, opts={}),
    _fx("bound-does-not-change-routing", BOUND_FLOW, {"spin": [{"text": "s"}]}, maxSteps=3, opts={}),
    _fx("bound-option-overrides-the-annotation", BOUND_FLOW, {"spin": [{"text": "s"}]}, opts={"max_transcript": 5}),
    _fx("bound-option-without-an-annotation", PLAIN_LOOP_FLOW, {"spin": [{"text": "s"}]}, opts={"max_transcript": 2}),
    _fx("no-bound-keeps-the-whole-transcript", PLAIN_LOOP_FLOW, {"spin": [{"text": "s"}]}, opts={}),
    _fx("bound-option-zero-is-no-bound", BOUND_FLOW, {"spin": [{"text": "s"}]}, opts={"max_transcript": 0}),
    _fx("bound-larger-than-the-history-drops-nothing", PLAIN_LOOP_FLOW, {"spin": [{"text": "s"}]}, opts={"max_transcript": 50}),
    _fx("bound-of-one", PLAIN_LOOP_FLOW, {"spin": [{"text": "s"}]}, opts={"max_transcript": 1}),
    _fx("bound-trims-an-oversized-transcript-on-resume", PLAIN_LOOP_FLOW, {"spin": [{"text": "s"}]}, start="spin",
        state={"visits": {"spin": 3}, "transcript": [{"node": "spin", "outcome": f"old{index}"} for index in range(6)]},
        opts={"max_transcript": 2}),
    _fx("bound-adds-to-what-an-earlier-run-dropped", PLAIN_LOOP_FLOW, {"spin": [{"text": "s"}]}, start="spin",
        state={"visits": {"spin": 3}, "_state_dropped": {"transcript": 4, "path": 2},
               "transcript": [{"node": "spin", "outcome": "old"}]}, opts={"max_transcript": 2}),
    _fx("bound-counts-the-error-entries", ERROR_BOUND_FLOW,
        {"work": [{"__raise__": "once"}, {"text": "w", "ok": True}]}, opts={}),
    _fx("the-first-annotation-in-document-order-binds", FIRST_BOUND_WINS_FLOW, {}, opts={}),
    _fx("a-repeated-annotation-merges-and-the-last-value-wins", REPEATED_BOUND_FLOW, {"spin": [{"text": "s"}]}, opts={}),
    _fx("bound-with-underscores-in-the-number", _bound_flow("1_0"), {"spin": [{"text": "s"}]}, opts={}),
    _fx("bound-with-a-plus-sign-and-leading-zeros", _bound_flow("+003"), {"spin": [{"text": "s"}]}, opts={}),
    _fx("bound-too-large-to-reach", _bound_flow("99999999999999999999999"), {"spin": [{"text": "s"}]}, opts={}),
    _fx("bound-malformed-zero-is-refused", _bound_flow("0"), {"spin": [{"text": "s"}]}, opts={}),
    _fx("bound-malformed-negative-is-refused", _bound_flow("-3"), {"spin": [{"text": "s"}]}, opts={}),
    _fx("bound-malformed-word-is-refused", _bound_flow("many"), {"spin": [{"text": "s"}]}, opts={}),
    _fx("bound-malformed-fraction-is-refused", _bound_flow("2.5"), {"spin": [{"text": "s"}]}, opts={}),
    _fx("bound-malformed-empty-is-refused", _bound_flow(""), {"spin": [{"text": "s"}]}, opts={}),
    _fx("bound-malformed-double-underscore-is-refused", _bound_flow("1__0"), {"spin": [{"text": "s"}]}, opts={}),
    _fx("bound-malformed-bare-name-is-refused", PLAIN_LOOP_FLOW.replace("## spin\n", "## spin\n@state_bound(transcript)\n"),
        {"spin": [{"text": "s"}]}, opts={}),
    _fx("bound-malformed-but-overridden-by-the-option-is-not-read", _bound_flow("many"), {"spin": [{"text": "s"}]},
        opts={"max_transcript": 2}),
    _fx("bound-annotation-without-a-transcript-key-is-refused",
        PLAIN_LOOP_FLOW.replace("## spin\n", "## spin\n@state_bound(history=3)\n"), {"spin": [{"text": "s"}]}, opts={}),
    # -- the error tier reports the worker's error class as error_type
    _fx("error-type-routes-on-a-named-class", ERROR_TYPE_FLOW,
        {"work": [{"__raise__": "slow", "__kind__": "TimeoutError"}]}, opts={}),
    _fx("error-type-routes-on-membership-in-a-tuple", ERROR_TYPE_FLOW,
        {"work": [{"__raise__": "no key", "__kind__": "KeyError"}]}, opts={}),
    _fx("error-type-defaults-to-runtime-error-in-the-corpus", ERROR_TYPE_FLOW,
        {"work": [{"__raise__": "plain"}]}, opts={}),
    _fx("error-type-an-unlisted-class-takes-the-catch-all", ERROR_TYPE_FLOW,
        {"work": [{"__raise__": "odd", "__kind__": "OSError"}]}, opts={}),
    _fx("error-type-is-case-sensitive", ERROR_TYPE_FLOW,
        {"work": [{"__raise__": "odd", "__kind__": "timeouterror"}]}, opts={}),
    _fx("error-type-the-first-handler-in-document-order-wins", ERROR_TYPE_FLOW,
        {"work": [{"__raise__": "exactly this", "__kind__": "ValueError"}]}, opts={}),
    _fx("error-message-routes-when-the-class-matches-no-earlier-handler", ERROR_TYPE_FLOW,
        {"work": [{"__raise__": "exactly this", "__kind__": "OSError"}]}, opts={}),
    _fx("error-type-a-class-name-with-digits-and-underscores", ERROR_TYPE_FLOW,
        {"work": [{"__raise__": "x", "__kind__": "My_Error2"}]}, opts={}),
    _fx("error-type-a-non-ascii-class-name", ERROR_TYPE_FLOW,
        {"work": [{"__raise__": "x", "__kind__": "\u00dcberfehler"}]}, opts={}),
    _fx("error-type-with-an-empty-message", ERROR_TYPE_FLOW,
        {"work": [{"__raise__": "", "__kind__": "TimeoutError"}]}, opts={}),
    _fx("error-type-in-the-transcript-after-a-retry", ERROR_TYPE_COUNT_FLOW,
        {"work": [{"__raise__": "one", "__kind__": "ValueError"}, {"__raise__": "two", "__kind__": "ValueError"},
                  {"__raise__": "three", "__kind__": "ValueError"}]}, opts={}),
    _fx("error-type-recovers-after-a-retry", ERROR_TYPE_COUNT_FLOW,
        {"work": [{"__raise__": "one", "__kind__": "ValueError"}, {"text": "fine", "ok": True}]}, opts={}),
    _fx("error-type-no-matching-handler-propagates-the-class", ERROR_TYPE_ONLY_FLOW,
        {"work": [{"__raise__": "bad", "__kind__": "ValueError"}]}, opts={}),
    _fx("error-type-no-error-edge-propagates-the-default-class", NO_HANDLER_FLOW,
        {"work": [{"__raise__": "boom"}]}, opts={}),
    _fx("error-type-a-later-success-is-not-an-error", ERROR_TYPE_ONLY_FLOW,
        {"work": [{"text": "fine", "ok": True}]}, opts={}),
    # -- an error guard that cannot be evaluated does not match, and the run's state says so (SPEC section 5.3)
    _fx("guard-unevaluable-is-recorded-and-skipped", GUARD_FLOW, {"work": [{"__raise__": "boom"}]}, opts={}),
    _fx("guard-evaluable-leaves-no-record", GUARD_FLOW.replace("len(error_message) > 3", "error_count >= 2"),
        {"work": [{"__raise__": "boom"}]}, opts={}),
    _fx("guard-an-evaluable-guard-that-matches-is-taken", GUARD_FLOW.replace("len(error_message) > 3", "error_count >= 1"),
        {"work": [{"__raise__": "boom"}]}, opts={}),
    _fx("guard-two-unevaluable-guards-are-recorded-in-document-order", GUARD_TWO_FLOW,
        {"work": [{"__raise__": "boom", "__kind__": "OSError"}]}, opts={}),
    _fx("guard-a-later-evaluable-guard-still-matches", GUARD_TWO_FLOW,
        {"work": [{"__raise__": "boom", "__kind__": "ValueError"}]}, opts={}),
    _fx("guard-the-count-in-the-step-is-over-the-whole-state", GUARD_LOOP_FLOW,
        {"work": [{"__raise__": "boom"}, {"__raise__": "boom"}, {"__raise__": "boom"}]}, opts={}),
    _fx("guard-recovery-after-a-recorded-guard", GUARD_LOOP_FLOW,
        {"work": [{"__raise__": "boom"}, {"text": "fine", "ok": True}]}, opts={}),
    _fx("guard-after-the-edge-that-matched-is-never-evaluated", GUARD_AFTER_MATCH_FLOW,
        {"work": [{"__raise__": "boom"}]}, opts={}),
    _fx("guard-records-name-the-node-they-came-from", GUARD_OTHER_NODE_FLOW,
        {"first": [{"__raise__": "boom"}], "second": [{"__raise__": "boom"}]}, opts={}),
    _fx("guard-no-handler-matched-propagates-the-error", GUARD_NO_HANDLER_FLOW,
        {"work": [{"__raise__": "boom"}]}, opts={}),
    _fx("guard-a-resumed-state-brings-its-earlier-records", GUARD_FLOW, {"work": [{"__raise__": "boom"}]}, start="work",
        state={"visits": {}, "transcript": [], "_guard_errors": [
            {"node": "work", "guard": "when len(error_message) > 3", "error": "earlier"},
            {"node": "elsewhere", "guard": "when f(x)", "error": "earlier"}]}, opts={}),
    # -- a route into a node the flow does not define: the reference raises a bare KeyError
    _fx("a-route-into-an-undefined-node-is-a-key-error", GHOST_FLOW, {}, opts={}),
    _fx("a-start-node-the-flow-does-not-define-is-a-key-error", GHOST_START_FLOW, {}, opts={}),
    _fx("a-route-into-an-undefined-node-after-the-last-step-is-max-steps", GHOST_FLOW, {}, maxSteps=1, opts={}),
    _fx("a-resume-into-an-undefined-node-is-a-key-error", GHOST_FLOW, {}, start="gone", opts={}),
    _fx("a-flow-with-no-node-is-a-key-error-on-the-empty-start", "just words, no heading\n", {}, opts={}),
    _fx("a-target-is-case-sensitive-so-a-capitalised-name-is-undefined", GHOST_FLOW.replace("-> ghost", "-> Done"),
        {}, opts={}),
    _fx("a-route-into-an-undefined-node-from-an-error-edge", ERROR_GHOST_FLOW, {"work": [{"__raise__": "x"}]}, opts={}),

    # -- both options
    _fx("gate-and-bound-together", GATE_FLOW,
        {"triage": [GATE_OK], "contain": [{"text": "c", "approved": "yes"}]}, opts={"type_gate": True, "max_transcript": 1}),
]
