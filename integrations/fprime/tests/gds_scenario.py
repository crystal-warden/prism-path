# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The S1 proposals played into the F Prime guard through the GDS integration test API.

This is an F Prime integration test (the `fprime_test_api` fixture of fprime-gds), run by run_scenario.py against a
GDS that is running the PrismPathRef deployment; it is not collected by the repository's own pytest run, because it
needs F Prime's own pytest plugin and a live deployment. Everything it needs is in the JSON file named by
PRISMPATH_FPRIME_SCENARIO, which the ground side (run_scenario.py) writes: where the guard's files are, the
proposals, and what the Python reference decides for each. It writes what the guard sealed to the file named by
PRISMPATH_FPRIME_RESULT.
"""
import json
import os

PP = "PrismPathRef.ppGuard"
SCENARIO = json.load(open(os.environ["PRISMPATH_FPRIME_SCENARIO"]))
EVENT = {"allow": "Allow", "refuse": "Refuse", "escalate": "Escalate"}


def propose(api, case):
    """Send one proposal through the proposer and return the guard's decision event."""
    if case["partial"]:
        command, args = "PrismPathRef.proposer.PROPOSE_PARTIAL", [case["cmd_class"], case["ground_contact"], case["slew_deg"]]
    else:
        command, args = "PrismPathRef.proposer.PROPOSE", [case["cmd_class"], case["ground_contact"], case["slew_deg"], case["thrust_pct"]]
    decided = [api.get_event_pred(f"{PP}.{name}") for name in EVENT.values()]
    start = api.event_history.size()
    api.send_command(command, args)
    for pred in decided:
        found = api.await_event(pred, start=start, timeout=3)
        if found is not None:
            return found
    raise AssertionError(f"no decision event for {case['name']}")


def set_param(api, name, value):
    api.send_and_assert_command(f"{PP}.{name}_PRM_SET", [value])


def command_event(api, command, event, args=None, completed=True):
    """Send a guard command and return the event it logs. The guard logs from inside the handler, so its event comes
    before the dispatcher's OpCodeDispatched and OpCodeCompleted (or OpCodeError)."""
    start = api.event_history.size()
    api.send_command(command, [])
    found = api.await_event(event, args=args, start=start, timeout=5)
    assert found is not None, f"{command}: no {event}"
    done = "CdhCore.cmdDisp.OpCodeCompleted" if completed else "CdhCore.cmdDisp.OpCodeError"
    assert api.await_event(done, start=start, timeout=5) is not None, f"{command}: not {done}"
    return found


def test_no_policy_refuses_everything_and_receipts_nothing(fprime_test_api):
    api = fprime_test_api
    event = propose(api, SCENARIO["no_policy_case"])
    assert event.get_display_text().startswith("REFUSE") and event.get_args()[1].val == 32
    assert event.get_args()[3].val == -1
    assert api.await_event(f"PrismPathRef.vehicle.Actuated", start=0, timeout=1) is None


def test_a_tampered_table_is_refused_and_a_signed_one_loads(fprime_test_api):
    api = fprime_test_api
    # parameter strings are short (FW_PARAM_STRING_MAX_SIZE, 40), so these are relative to the deployment's directory
    onboard = SCENARIO["onboard"]
    set_param(api, "KEYS_DIR", onboard)
    set_param(api, "RUN_DIR", f"{onboard}/run")
    set_param(api, "POLICY_FILE", f"{onboard}/pp_policy_tampered.tbl")
    rejected = command_event(api, f"{PP}.LOAD_POLICY", f"{PP}.PolicyRejected", [2], completed=False)   # sig:invalid
    assert rejected.get_args()[0].val == 2
    set_param(api, "POLICY_FILE", f"{onboard}/pp_policy.tbl")
    command_event(api, f"{PP}.LOAD_POLICY", f"{PP}.PolicyLoaded", [SCENARIO["version"], None])


def test_the_s1_sequence_is_decided_as_the_reference_decides_it(fprime_test_api):
    api = fprime_test_api
    allowed = []
    for index, case in enumerate(SCENARIO["proposals"]):
        event = propose(api, case)
        want = case["expect"]
        got = event.get_args()
        assert event.get_display_text().startswith(want["kind"].upper()), f"{case['name']}: {event.get_display_text()}"
        if want["kind"] == "allow":
            assert got[2].val == index, f"{case['name']}: receipt {got[2].val}"
            allowed.append(case)
        else:
            assert got[1].val == want["cause"], f"{case['name']}: {event.get_display_text()}"
            assert got[-1].val == index, f"{case['name']}: receipt {got[-1].val}"
    # exactly the allowed proposals reached the vehicle through the dispatcher, in order, with their arguments
    import time
    deadline = time.time() + 5
    actuated = []
    while time.time() < deadline:
        actuated = [e for e in api.event_history.retrieve() if e.get_template().get_full_name() == "PrismPathRef.vehicle.Actuated"]
        if len(actuated) >= len(allowed):
            break
        time.sleep(0.1)
    time.sleep(0.5)
    actuated = [e for e in api.event_history.retrieve() if e.get_template().get_full_name() == "PrismPathRef.vehicle.Actuated"]
    assert len(actuated) == len(allowed), f"{len(actuated)} reached the vehicle, {len(allowed)} were allowed"
    for event, case in zip(actuated, allowed):
        assert [a.val for a in event.get_args()] == [case["cmd_class"], case["ground_contact"], case["slew_deg"], case["thrust_pct"]]


def test_seal_signs_the_run(fprime_test_api):
    api = fprime_test_api
    sealed = command_event(api, f"{PP}.SEAL", f"{PP}.Sealed")
    receipts, root = sealed.get_args()[0].val, sealed.get_args()[1].val
    assert receipts == len(SCENARIO["proposals"])
    command_event(api, f"{PP}.REPORT", f"{PP}.Report", [len(SCENARIO["proposals"]) + 1, None, None, None, receipts])
    json.dump({"receipts": receipts, "root": root}, open(os.environ["PRISMPATH_FPRIME_RESULT"], "w"))
