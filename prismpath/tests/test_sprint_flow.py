"""Item #6 (dogfood): the sprint loop as a flow — flows/sprint_loop.md + sprint_flow.py.

Stub seams, REAL git ledger (throwaway state dir). These pin the loop semantics now living in
the document: per-unit proof-commits on gate-green, fix-retries riding the error tier, the
3×-same-error escalation as an edge, and resume-from-ledger skipping proven units.
"""
import subprocess

import pytest

from prismpath import sprint_flow
from prismpath.sprint_flow import GateRed, SprintSeams, run_sprint_flow
from prismpath.ledger import Ledger
from prismpath.parser import parse_file
from prismpath import analysis

HAS_GIT = subprocess.run(["git", "--version"], capture_output=True).returncode == 0
pytestmark = pytest.mark.skipif(not HAS_GIT, reason="git not available")


def _ledger(tmp_path, run="01HSPRINT"):
    return Ledger(flow="sprint_loop", run_id=run, state_dir=tmp_path / "ledger")


def make_seams(units, gate_script=None):
    """Stub seams over a fixed unit list. `gate_script` maps unit id -> a list of gate results
    consumed per attempt (True=green, str=red with that error); default: green first try."""
    log = {"built": [], "fixed": [], "escalated": [], "gated": []}
    attempts: dict = {}

    def pick(state):
        done_units = state.get("_done_units") or set()
        for u in units:
            if u not in done_units:
                state["unit"] = {"id": u}
                return {"text": f"next: {u}", "done": False,
                        "instruction": f"build {u}", "target": f"{u}.js"}
        return {"text": "all proven", "done": True}

    def build(state):
        log["built"].append(state["unit"]["id"])
        return {"text": f"built {state['unit']['id']}"}

    def gate(state):
        u = state["unit"]["id"]
        log["gated"].append(u)
        script = (gate_script or {}).get(u, [True])
        i = attempts.get(u, 0)
        attempts[u] = i + 1
        result = script[min(i, len(script) - 1)]
        if result is True:
            state["gate_report"] = f"gate green for {u}"
            return {"text": "green", "gate_green": True}
        raise GateRed(result)

    def fix(state):
        log["fixed"].append(state["unit"]["id"])
        return {"text": f"fixed {state['unit']['id']}"}

    def escalate(state):
        log["escalated"].append(state["unit"]["id"])
        return {"text": "HELP written"}

    return SprintSeams(pick=pick, build=build, gate=gate, fix=fix, escalate=escalate), log


def test_flow_document_compiles():
    g = parse_file(sprint_flow.DEFAULT_FLOW)
    assert [f for f in analysis.analyze(g) if f.severity == "error"] == []


def test_green_path_proves_every_unit(tmp_path):
    seams, log = make_seams(["auth", "store", "ui"])
    led = _ledger(tmp_path)
    committed = run_sprint_flow(seams, ledger=led)
    assert committed == ["auth", "store", "ui"]
    done = led.done_set()
    assert set(done) == {"auth", "store", "ui"}
    for rec in done.values():
        assert rec["gate"] == "green" and rec["node"] == "gate"
    assert log["fixed"] == [] and log["escalated"] == []


def test_red_gate_retries_via_the_error_tier_then_greens(tmp_path):
    # unit fails twice, fixer runs twice, third gate attempt is green -> proof committed
    seams, log = make_seams(["auth"], gate_script={"auth": ["boom1", "boom2", True]})
    committed = run_sprint_flow(seams, ledger=_ledger(tmp_path))
    assert committed == ["auth"]
    assert log["fixed"] == ["auth", "auth"]          # exactly the two red rounds
    assert log["escalated"] == []


def test_three_failures_escalate_and_do_not_prove(tmp_path):
    # the 3x rule as an edge: error_count reaches 3 -> escalate (needs_human) -> unit unproven,
    # runner drains the rest of the queue instead of head-of-line blocking.
    seams, log = make_seams(["auth", "store"],
                            gate_script={"auth": ["boom", "boom", "boom"], "store": [True]})
    led = _ledger(tmp_path)
    committed = run_sprint_flow(seams, ledger=led)
    assert log["escalated"] == ["auth"]
    assert log["fixed"] == ["auth", "auth"]          # two fixes, then the third failure escalates
    assert committed == ["store"]                    # the healthy unit still proved
    assert set(led.done_set()) == {"store"}


def test_resume_from_ledger_skips_proven_units(tmp_path):
    led = _ledger(tmp_path)
    seams1, _ = make_seams(["auth", "store"])
    assert run_sprint_flow(seams1, ledger=led) == ["auth", "store"]
    # a fresh pass over a LONGER unit list: the ledger's done-set skips the proven two
    seams2, log2 = make_seams(["auth", "store", "ui"])
    assert run_sprint_flow(seams2, ledger=led) == ["ui"]
    assert log2["built"] == ["ui"]                   # auth/store never re-executed


def test_proofs_carry_the_gate_report(tmp_path):
    led = _ledger(tmp_path)
    seams, _ = make_seams(["auth"])
    run_sprint_flow(seams, ledger=led)
    rec = led.done_set()["auth"]
    assert rec["output_hash"].startswith("sha256:")  # content-addressed gate report
