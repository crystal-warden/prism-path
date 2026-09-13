# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Where the loop is right now, read off the run's own status file and log lines.

The console cannot ask the sprint what stage it is in, so it infers one from the last recorded phase
and the gate's verdict, and scrapes the tail of sprint.log for the lines an operator wants to see.
"""
import json
import os
import re

# the error text a flow validator produces, as against a failing test or a crashed run
_FAIL_VALIDATE = re.compile(r"TypeError|Unknown|duplicate|missing|Expected|Argument", re.I)
_LOG_LINE = re.compile(r"\[(rag|cecli|fix|HELP \d+|reflect)\]\s*(.*)")
_ITERATION_LINE = re.compile(r"\[it \d+ \|.*valid=")

# the loop stage each recorded phase belongs to; anything unrecognized is still proposing
_PHASE_STAGE = {"retrieve": "build", "build": "build",
                "fix": "fix", "review": "validate"}


def _last_phase(proj):
    """The phase of the most recent readable interaction, or empty when there is none."""
    ipath = os.path.join(proj, "interactions.jsonl")
    if not os.path.isfile(ipath):
        return ""
    lines = open(ipath, errors="ignore").read().splitlines()
    for ln in reversed(lines[-5:]):
        try:
            return json.loads(ln).get("phase", "")
        except Exception:
            continue
    return ""


def _recent_log(proj):
    """The operator-facing lines from the tail of sprint.log, stripped of their bracket prefix."""
    recent = []
    lp = os.path.join(proj, "sprint.log")
    if not os.path.isfile(lp):
        return recent
    for ln in open(lp, errors="ignore").read().splitlines()[-40:]:
        line_match = _LOG_LINE.search(ln)
        if line_match:
            recent.append(line_match.group(0).split("] ", 1)[-1][:90]
                          if "] " in line_match.group(0) else line_match.group(0)[:90])
        elif _ITERATION_LINE.search(ln):
            recent.append(ln.split("] ", 1)[-1][:90])
    return recent


def flow_state(state):
    """Derive the loop stage + active pushback edge: propose->accept->build->test/validate->repeat,
    with back-edges when the gate kicks work back to build/fix."""
    proj = state["proj"]
    st = {}
    try:
        st = json.load(open(os.path.join(proj, "status.json")))
    except Exception:
        pass
    phase = _last_phase(proj)
    valid = bool(st.get("valid"))
    err = st.get("last_error") or ""
    # three kinds of failed sprint for the runtime view: the tests failed, the flow did not validate
    # (the error text looks like a validator's), or the run itself failed at runtime
    fail_kind = None
    if not valid and err:
        fail_kind = "test" if "lune test failed" in err else ("validate" if _FAIL_VALIDATE.search(err) else "runtime")
    stage = _PHASE_STAGE.get(phase, "propose")
    if valid:
        stage = "validate"
    return {"stage": stage, "gate_valid": valid, "iteration": st.get("iteration"),
            "fail_kind": fail_kind, "reason": err[:160], "help_open": st.get("help_open"),
            "recent": _recent_log(proj)[-10:]}
