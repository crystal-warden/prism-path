# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""`flows.json` carries the engine options the frozen fixtures left out, the type gate and the transcript bound
(`portable/engine_surface_fixtures.py`). These tests hold the corpus to what it is for: a case for the one new
stop value and for each kind of bound, expectations that are the Python engine's own, and the contract it
reads the same one `prismpath.kernel.contract` derives. The Rust conformance binary replays every case
and `prismpath-rs/tests/test_engine_cross_language.rs` runs both engines over them and a random sample."""
import json
from pathlib import Path

from prismpath.kernel import causes
from prismpath.kernel.engine import run
from prismpath.kernel.parser import parse
from prismpath.portable.flow_fixtures import scripted_agent

REPO = Path(__file__).resolve().parents[2]
CORPUS = REPO / "prismpath" / "portable" / "conformance" / "flows.json"


def _cases() -> dict:
    return {case["name"]: case for case in json.loads(CORPUS.read_text(encoding="utf-8"))["cases"]}


def test_the_frozen_cases_come_first_and_are_unchanged():
    names = list(_cases())
    assert names[0] == "chained-comparison"
    assert names[26] == "top-level-tuple-always-truthy"
    assert all("opts" not in case for case in list(_cases().values())[:27])


def test_the_new_stop_value_has_a_case_and_cause_37():
    gated = [case for case in _cases().values() if case["expect"].get("stopped") == "contract_violation"]
    assert len(gated) >= 5
    assert {case["expect"]["cause"] for case in gated} == {causes.NAMES["route:contract-violation"]} == {37}
    assert all(case["opts"].get("type_gate") for case in gated)
    assert all(case["expect"]["violations"] and case["expect"]["pending_node"] for case in gated)


def test_the_gate_has_the_cases_it_needs():
    cases = _cases()
    assert cases["type-gate-off-routes-the-same-wrong-type"]["expect"]["stopped"] == "terminal"
    assert cases["type-gate-null-is-not-a-violation"]["expect"]["stopped"] == "terminal"
    assert cases["type-gate-runs-before-the-human-handoff"]["expect"]["stopped"] == "contract_violation"
    assert cases["human-handoff-without-the-gate"]["expect"]["stopped"] == "needs_human"
    assert len(cases["type-gate-lists-every-violation-in-field-order"]["expect"]["violations"]) == 3


def test_each_kind_of_bound_has_a_case():
    cases = _cases()
    dropped = {name: case["expect"].get("state_dropped") for name, case in cases.items()}
    assert dropped["bound-by-annotation"] == {"transcript": 2}
    assert dropped["bound-option-overrides-the-annotation"] == {}
    assert dropped["bound-option-without-an-annotation"] == {"transcript": 3}
    assert dropped["bound-option-zero-is-no-bound"] == {}
    assert dropped["bound-trims-an-oversized-transcript-on-resume"] == {"transcript": 6}
    assert dropped["bound-adds-to-what-an-earlier-run-dropped"]["transcript"] == 5
    assert dropped["bound-counts-the-error-entries"] == {"transcript": 1}
    assert dropped["the-first-annotation-in-document-order-binds"] == {"transcript": 1}
    refused = [case for case in cases.values() if str(case["expect"].get("error", "")).startswith("@state_bound(")]
    assert len(refused) >= 7 and all(case["expect"]["error_class"] == "ValueError" for case in refused)


def test_the_error_tier_cases_route_on_the_worker_class():
    cases = _cases()
    routed = {name: case["expect"]["path"][-1] for name, case in cases.items() if name.startswith("error-type-routes")}
    assert routed == {"error-type-routes-on-a-named-class": "timed_out",
                      "error-type-routes-on-membership-in-a-tuple": "bad_input"}
    assert cases["error-type-defaults-to-runtime-error-in-the-corpus"]["expect"]["path"][-1] == "runtime"
    assert cases["error-type-is-case-sensitive"]["expect"]["path"][-1] == "other"
    assert cases["error-type-in-the-transcript-after-a-retry"]["expect"]["transcript"][0]["outcome"] == "[error: ValueError: one]"
    # a failure no handler takes propagates as itself: its class and message are what the corpus records
    assert cases["error-type-no-matching-handler-propagates-the-class"]["expect"] == {"error": "bad", "error_class": "ValueError"}
    assert cases["error-type-no-error-edge-propagates-the-default-class"]["expect"] == {"error": "boom", "error_class": "RuntimeError"}


def test_every_case_is_what_the_python_engine_gives_now():
    for name, case in _cases().items():
        if "opts" not in case:
            continue
        state = json.loads(json.dumps(case["state"])) if "state" in case else None
        try:
            res = run(parse(case["flow"]), scripted_agent(case["script"]), max_steps=case.get("maxSteps", 25),
                      start=case.get("start"), state=state, **case["opts"])
        except Exception as error:      # noqa: BLE001 - the refusal the corpus records, whatever its class
            assert case["expect"] == {"error": str(error), "error_class": type(error).__name__}, name
            continue
        assert case["expect"]["path"] == res.path and case["expect"]["stopped"] == res.stopped, name
        assert case["expect"]["transcript"] == res.state["transcript"], name


def test_the_bound_never_changes_a_routing_decision():
    """The persisted transcript is the only thing the window trims; the path, the stop and the visit counters
    are what an unbounded run gives."""
    for name in ("bound-by-annotation", "bound-of-one", "bound-option-without-an-annotation"):
        case = _cases()[name]
        unbounded = run(parse(case["flow"].replace("@state_bound(transcript=3)\n", "")), scripted_agent(case["script"]))
        assert case["expect"]["path"] == unbounded.path and case["expect"]["stopped"] == unbounded.stopped


def test_a_route_into_an_undefined_node_is_a_bare_key_error_on_the_name():
    cases = _cases()
    for name, node in (("a-route-into-an-undefined-node-is-a-key-error", "'ghost'"),
                       ("a-start-node-the-flow-does-not-define-is-a-key-error", "'nowhere'"),
                       ("a-flow-with-no-node-is-a-key-error-on-the-empty-start", "''"),
                       ("a-target-is-case-sensitive-so-a-capitalised-name-is-undefined", "'Done'"),
                       ("a-route-into-an-undefined-node-from-an-error-edge", "'nowhere'")):
        assert cases[name]["expect"] == {"error": node, "error_class": "KeyError"}, name
    last = cases["a-route-into-an-undefined-node-after-the-last-step-is-max-steps"]["expect"]
    assert last["stopped"] == "max_steps" and last["path"] == ["work", "ghost"]


def test_the_steps_hold_how_each_was_routed():
    steps = _cases()["error-type-recovers-after-a-retry"]["expect"]["steps"]
    assert steps == [{"node": "work", "target": "work", "used": "error", "error_type": "ValueError"},
                     {"node": "work", "target": "done", "used": "deterministic", "cond": "when ok"}]


def test_the_guard_cases_record_which_guard_of_which_node_and_the_step_counts_them():
    cases = _cases()
    recorded = cases["guard-unevaluable-is-recorded-and-skipped"]["expect"]
    assert recorded["guard_errors"] == [{"node": "work", "guard": "when len(error_message) > 3"}]
    assert recorded["steps"][0]["guard_errors"] == 1 and recorded["path"] == ["work", "fallback"]
    assert cases["guard-evaluable-leaves-no-record"]["expect"]["guard_errors"] == []
    assert "guard_errors" not in cases["guard-evaluable-leaves-no-record"]["expect"]["steps"][0]
    counted = cases["guard-the-count-in-the-step-is-over-the-whole-state"]["expect"]["steps"]
    assert [step.get("guard_errors") for step in counted] == [1, 2, 3]
    assert cases["guard-no-handler-matched-propagates-the-error"]["expect"] == {"error": "boom", "error_class": "RuntimeError"}
    assert cases["guard-a-resumed-state-brings-its-earlier-records"]["expect"]["steps"][0]["guard_errors"] == 2
