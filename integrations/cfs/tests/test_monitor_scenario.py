# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The runtime monitor scenario (integrations/cfs/monitor): what can be checked without builds, and the run itself.

Without builds: the outcome function the scenario holds the flight run to is the reference decision for every
proposal with the monitor's verdict either way, the C reading layout has the monitor_ok field where the policy and the
command struct say it is (a drift check), the monitor's message ids are clear of the mission's others, and the
generated plan include is current. With a checkout of R2U2 (the compiler and the C library): the property compiles,
and R2U2 run on traces agrees with a Python model of it. With a staged NOS3 build, Docker and R2U2: the whole scenario.
Each part that needs something else skips, saying why.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from prismpath.agent.policy import Policy
from integrations.cfs.ground import reference
from integrations.cfs.monitor import plan, run_monitor_scenario as runner
from integrations.cfs.nos3 import run_nos3_scenario as nos3_runner
from integrations.cfs.prismpath_app.policy import gen_image
from integrations.cfs.tests.run_scenario import reading_payload, topics

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
APP = REPO / "integrations" / "cfs" / "prismpath_app"
MONITOR = REPO / "integrations" / "cfs" / "monitor"
NOS3 = Path(os.environ.get("NOS3_MONITOR_DIR") or REPO / ".cfs-build" / "nos3-monitor")
R2U2 = Path(os.environ.get("R2U2_DIR") or REPO / ".cfs-build" / "r2u2")


# ----------------------------------------------------------------- the outcome function
@pytest.mark.parametrize("p", plan.proposals(), ids=lambda p: f"tag{p.tag}")
@pytest.mark.parametrize("monitor_ok", [True, False])
def test_the_outcome_function_is_the_reference_decision(p, monitor_ok):
    policy = Policy.load(gen_image.CORE)
    d = policy.decide(reference.reading_bytes(reading_payload(plan.reading(p, monitor_ok))))
    assert (d.kind, d.cause_code or 0) == plan.decide(p, monitor_ok), p.what


def test_the_monitor_rule_is_cause_34_and_a_refusal_still_wins():
    steady = plan.PLAN[4]
    assert plan.decide(steady, True) == ("allow", 0), "in contact, within limits: only the monitor can stop it"
    assert plan.decide(steady, False) == ("escalate", 34)
    refused = plan.PLAN[2]
    assert plan.decide(refused, False) == plan.decide(refused, True) == ("refuse", 37)
    # the cause is the registered route:needs-human, not a new one
    assert gen_image.causes.code("route:needs-human") == 34


def test_every_steady_proposal_is_allowed_by_the_rules_without_the_monitor():
    steady = [p for p in plan.PLAN if p.tag >= 5]
    assert len(steady) == plan.STEADY
    assert all(plan.decide(p, True) == ("allow", 0) and p.ground_contact == 1 for p in steady)


def test_the_generated_plan_include_is_what_the_script_stages():
    assert "PP_AUTONOMY_Plan" in plan.render() and f"{{{plan.PLAN[-1].tag}, " in plan.render()


# ----------------------------------------------------------------- drift: the C reading layout and the new field
def _layout():
    text = (APP / "fsw" / "inc" / "prismpath_app_layout.h").read_text()
    return {name: (int(reg), kind, int(off), int(width)) for reg, name, kind, off, width in
            re.findall(r'X\(\s*(\d+),\s*"(\w+)",\s*(\w+),\s*(\d+),\s*(\d+),', text)}


def test_the_layout_has_monitor_ok_as_the_apps_own_bool_where_the_command_struct_puts_it():
    rows = _layout()
    reg, kind, off, width = rows["monitor_ok"]
    assert kind == "MONITOR" and width == 1
    assert [n for n in sorted(rows)] == [n for n, _r in sorted(((n, v[0]) for n, v in rows.items()), key=lambda x: x[1])], \
        "registers follow the sorted field names"
    # the policy's field definition, the layout and the compiled image agree
    defs = gen_image.field_defs(Policy.load(gen_image.CORE).doc)
    assert ("monitor_ok", "bool", 0, 1) in defs and [d[0] for d in defs].index("monitor_ok") == reg
    # the C struct's member, by C's own layout rules, is at the layout's offset
    msg = (APP / "config" / "default_prismpath_app_msg.h").read_text()
    body = re.search(r"typedef struct\s*\{\s*CFE_MSG_CommandHeader_t CommandHeader;(.*?)\}\s*PRISMPATH_APP_ProposedCmd_t;",
                     msg, re.S).group(1)
    offset, at = 0, {}
    for ctype, name in re.findall(r"\b(uint8|uint16)\s+(\w+);", body):
        size = 1 if ctype == "uint8" else 2
        offset += (-offset) % size
        at[name] = offset
        offset += size
    assert at["MonitorOk"] == off
    assert f"PAYLOAD_OFFSET(MonitorOk) == {off}" in (APP / "fsw" / "src" / "prismpath_app.c").read_text()


def test_the_reference_reads_monitor_ok_from_the_apps_byte_and_true_when_absent():
    full = reading_payload(dict(cmd_class=1, ground_contact=1, slew_deg=20, thrust_pct=0, monitor_ok=0))
    assert reference.reading_of(full)["monitor_ok"] is False
    assert reference.reading_of(full[:6])["monitor_ok"] is True          # a short payload: no monitor in the reading
    assert reference.reading_of(reading_payload(dict(cmd_class=1, ground_contact=1, slew_deg=20, thrust_pct=0))
                                )["monitor_ok"] is True


def test_the_verdict_message_ids_are_distinct_and_clear_of_the_apps_others():
    text = (REPO / "integrations/cfs/nos3/mission/prismpath_app_topicid_values.h").read_text()
    tid = {k: int(v, 16) for k, v in re.findall(r"PP_NOS3_PRISMPATH_APP_(\w+)_TOPICID\s+(0x[0-9A-Fa-f]+)", text)}
    verdict = 0x0800 | tid["MONITOR_VERDICT"]
    commands = {0x1800 | v for k, v in tid.items() if k != "MONITOR_VERDICT" and k != "HK_TLM"}
    assert verdict == 0x08C5 and 0x0800 | tid["HK_TLM"] != verdict
    assert plan.MONITOR_CMD_MID == 0x18C6 and plan.MONITOR_CMD_MID not in commands | {nos3_runner.AUTONOMY_CMD_MID}
    defaults = {0x0800 | v for k, v in topics().items() if k != "HK_TLM"} | {0x1800 | v for v in topics().values()}
    assert 0x0800 | topics()["MONITOR_VERDICT"] not in defaults - {0x0800 | topics()["MONITOR_VERDICT"]}
    h = (MONITOR / "pp_monitor" / "fsw" / "src" / "pp_monitor.h").read_text()
    assert int(re.search(r"PP_MONITOR_CMD_MID (0x[0-9A-F]+)", h).group(1), 16) == plan.MONITOR_CMD_MID
    assert int(re.search(r"PP_MONITOR_HALT_CC\s+(\d)", h).group(1)) == plan.MONITOR_HALT_CC
    assert int(re.search(r"PP_MONITOR_RESUME_CC\s+(\d)", h).group(1)) == plan.MONITOR_RESUME_CC


def test_the_mission_ids_are_clear_of_nos3():
    if not (NOS3 / "components").is_dir():
        pytest.skip(f"no NOS3 checkout at {NOS3}")
    used = set()
    for path in list((NOS3 / "components").rglob("*msgids*.h")) + list((NOS3 / "fsw" / "apps").rglob("*msgids*.h")) + \
            list((NOS3 / "cfg" / "nos3_defs").glob("*msgids*.h")):
        if "prismpath" in path.name or path.is_symlink():
            continue
        used |= {int(v, 16) for v in re.findall(r"#define\s+\w+\s+\(?(0x[01]8[0-9A-Fa-f]{2})\b", path.read_text(errors="ignore"))}
    assert used and not {0x08C5, plan.MONITOR_CMD_MID} & used


# ----------------------------------------------------------------- R2U2: the property, held to a model
def _model(status):
    """payload_quiet: no nonzero status in the last QUIET_SECONDS steps (and this one)."""
    return [all(s == 0 for s in status[max(0, t - plan.QUIET_SECONDS):t + 1]) for t in range(len(status))]


@pytest.fixture(scope="module")
def r2u2_cli(tmp_path_factory):
    if not (R2U2 / "monitors" / "c" / "src" / "r2u2.h").exists():
        pytest.skip(f"no R2U2 checkout at {R2U2} (git clone https://github.com/R2U2/r2u2 there)")
    if shutil.which("make") is None or shutil.which("gcc") is None:
        pytest.skip("no make or gcc to build R2U2's command line monitor")
    work = tmp_path_factory.mktemp("r2u2")
    spec = work / "payload_quiet.bin"
    runner.compile_spec(R2U2, spec)
    build = subprocess.run(["make", "-C", str(R2U2 / "monitors" / "c"), "-j4"], capture_output=True, text=True)
    exe = R2U2 / "monitors" / "c" / "build" / "r2u2"
    if build.returncode != 0 or not exe.exists():
        pytest.skip(f"R2U2's C monitor did not build: {build.stderr[-300:]}")
    return exe, spec, work


def _run(r2u2_cli, status):
    exe, spec, work = r2u2_cli
    trace = work / "trace.csv"
    trace.write_text("# status\n" + "\n".join(map(str, status)) + "\n")
    out = subprocess.run([str(exe), str(spec), str(trace)], capture_output=True, text=True, check=True).stdout.split()
    reports = [(int(line.split(":")[1].split(",")[0]), line.endswith(",T")) for line in out]
    # a report (t, v) is the verdict v for every step since the last report, up to t
    return [next(v for t, v in reports if t >= step) for step in range(len(status))], reports


@pytest.mark.parametrize("status", [
    [0] * 12,
    [0] * 8 + [3] * 2 + [0] * 3 + [3] + [0] * 12,
    [3] * 4 + [0] * 10,
    [0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0],
])
def test_r2u2_agrees_with_the_model_of_the_property(r2u2_cli, status):
    got, _reports = _run(r2u2_cli, status)
    assert got == _model(status)


def test_the_violation_is_reported_at_the_step_the_fault_arrives(r2u2_cli):
    _got, reports = _run(r2u2_cli, [0] * 5 + [3] + [0] * 8)
    assert (4, True) in reports
    assert next(t for t, v in reports if not v) == 5, "R2U2 reports the violation on the step the fault arrives"


# ----------------------------------------------------------------- the scenario
def test_scenario_end_to_end():
    exe = NOS3 / "fsw" / "build" / "exe" / "cpu1"
    if not (exe / "core-cpu1").exists() or not (exe / "cf" / "pp_monitor.so").exists():
        pytest.skip(f"no NOS3 build with the monitor app at {NOS3} (run integrations/cfs/monitor/run_monitor_scenario.py)")
    if not (NOS3 / "sims" / "build" / "lib" / "libsample_sim.so").exists() or not (NOS3.parent / "42" / "42").exists():
        pytest.skip("NOS3's simulators or 42 are not built")
    if shutil.which("docker") is None or subprocess.run(["docker", "image", "inspect", nos3_runner.IMAGE],
                                                        capture_output=True).returncode != 0:
        pytest.skip(f"docker or the {nos3_runner.IMAGE} image is not available")
    res = subprocess.run([sys.executable, str(MONITOR / "run_monitor_scenario.py"), "--skip-build", "--nos3", str(NOS3)],
                         capture_output=True, text=True, cwd=REPO, timeout=600)
    assert res.returncode == 0, res.stdout[-4000:] + res.stderr[-2000:]
