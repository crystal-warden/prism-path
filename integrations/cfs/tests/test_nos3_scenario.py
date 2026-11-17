# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The NOS3 scenario (integrations/cfs/nos3): what can be checked without NOS3, and the run itself when a NOS3 build
is staged.

Without NOS3: the autonomy app's plan and fault playbook against the policy (every proposal's reference decision is
the outcome table's), the generated C include is current, the plan shows each kind of decision and keeps the
vehicle effects of allowed and blocked proposals apart, the mission's message ids are clear of the app's defaults,
and the scenario's readers of the simulators' logs parse NOS3's log lines. With a staged NOS3 build and Docker: the
whole scenario (run_nos3_scenario.py --skip-build), which skips, saying why, when either is missing.
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
from integrations.cfs.nos3 import plan, run_nos3_scenario as runner
from integrations.cfs.prismpath_app.policy import gen_image
from integrations.cfs.tests.run_scenario import reading_payload, topics

REPO = Path(__file__).resolve().parents[3]
NOS3 = Path(os.environ.get("NOS3_DIR") or REPO / ".cfs-build" / "nos3")

BOUNDS = {"cmd_class": (0, 10), "ground_contact": (0, 1), "slew_deg": (0, 180), "thrust_pct": (0, 200)}


def decide(p: plan.Proposal):
    policy = Policy.load(gen_image.CORE)
    return policy.decide(reference.reading_bytes(reading_payload(p.reading())))


@pytest.mark.parametrize("p", plan.proposals(), ids=lambda p: f"tag{p.tag}")
def test_outcome_table_is_the_reference_decision(p):
    d = decide(p)
    kind, cause, _why = plan.EXPECTED[p.tag]
    assert (d.kind, d.cause_code or 0) == (kind, cause), p.what


def test_table_covers_exactly_the_proposals():
    tags = [p.tag for p in plan.proposals()]
    assert len(tags) == len(set(tags)) and set(tags) == set(plan.EXPECTED)
    assert all(0 < t < 0x10000 for t in tags), "a tag rides in the command's 16 bit spare word"


def test_readings_are_inside_the_field_definitions():
    """Out of policy here means refused or escalated by a rule, not refused at the boundary."""
    for p in plan.proposals():
        for name, value in p.reading().items():
            low, high = BOUNDS[name]
            assert low <= value <= high, (p.tag, name)


def test_plan_has_every_kind_of_decision():
    kinds = {plan.EXPECTED[p.tag][0] for p in plan.PLAN}
    assert kinds == {"allow", "refuse", "escalate"}
    assert {plan.EXPECTED[p.tag][0] for p in plan.FAULT_RESPONSE} == {"allow", "escalate"}
    assert {p.cmd_class for p in plan.proposals()} >= {plan.ATTITUDE, plan.PAYLOAD}


def test_vehicle_effects_tell_allowed_from_blocked():
    """Each attitude proposal's torque is its own, so the wheel simulator's log says which ones reached it; and every
    payload command comes before the fault, after which NOS3's sample app halts the device."""
    attitude = [p for p in plan.proposals() if p.cmd_class == plan.ATTITUDE]
    torques = [plan.torque(p) for p in attitude]
    assert len(torques) == len(set(torques))
    payload_at = [i for i, p in enumerate(plan.PLAN) if p.cmd_class == plan.PAYLOAD]
    assert payload_at and max(payload_at) < 4, "the scenario injects the fault after the fourth proposal"
    assert all(p.cmd_class != plan.PAYLOAD for p in plan.FAULT_RESPONSE)
    every = [p.tag for p in plan.proposals()]
    want_torques, want_configs = plan.vehicle_effects(plan.allowed(every))
    blocked = [p for p in plan.proposals() if plan.EXPECTED[p.tag][0] != "allow"]
    assert not {plan.torque(p) for p in blocked if p.cmd_class == plan.ATTITUDE} & set(want_torques)
    assert not {p.tag for p in blocked} & set(want_configs)


def test_generated_include_is_current():
    assert plan.INCLUDE.read_text() == plan.render(), "run python -m integrations.cfs.nos3.plan"


def test_mission_message_ids():
    ids = runner.mids()
    assert ids == {"cmd": 0x18C0, "proposed": 0x18C2, "vehicle": 0x18C3}
    app_defaults = {0x1800 | v for v in topics().values()}
    autonomy = int(re.search(r"PP_AUTONOMY_CMD_MID (0x[0-9A-F]+)",
                             (REPO / "integrations/cfs/nos3/pp_autonomy/fsw/src/pp_autonomy.h").read_text()).group(1), 16)
    assert autonomy == runner.AUTONOMY_CMD_MID and autonomy not in ids.values()
    assert not set(ids.values()) & app_defaults


def test_mission_message_ids_are_clear_of_nos3():
    if not (NOS3 / "components").is_dir():
        pytest.skip(f"no NOS3 checkout at {NOS3}")
    used = set()
    for path in list((NOS3 / "components").rglob("*msgids*.h")) + list((NOS3 / "fsw" / "apps").rglob("*msgids*.h")) + \
            list((NOS3 / "cfg" / "nos3_defs").glob("*msgids*.h")):
        if "prismpath" in path.name or path.is_symlink():
            continue
        used |= {int(v, 16) for v in re.findall(r"#define\s+\w+\s+\(?(0x[01]8[0-9A-Fa-f]{2})\b", path.read_text(errors="ignore"))}
    ours = set(runner.mids().values()) | {runner.AUTONOMY_CMD_MID, 0x08C1}
    assert used and not ours & used


def test_log_readers_parse_nos3_lines():
    rw = "2026-11-17 11:24:58.498895 [ DEBUG ] - GenericRWHardwareModel::uart_read_callback:  REQUEST SET_TORQUE=    0.0020"
    assert round(float(runner.TORQUE.search(rw).group(1)) * 10000) == 20
    lines = ["2026-11-17 11:24:59.498288 [ DEBUG ] - SampleHardwareModel::uart_read_callback:  REQUEST  "
             "0xde 0xad 0x03 0x00 0x00 0x00 0x02 0xbe 0xef",
             "2026-11-17 11:24:59.498288 [ DEBUG ] - SampleHardwareModel::uart_read_callback:  REQUEST  "
             "0xde 0xad 0x01 0x00 0x00 0x00 0x00 0xbe 0xef"]
    assert runner.sample_configs(lines) == [2]
    fsw = "EVS Port1 EVS Port1 42/1/PP_AUTONOMY 10: PP_AUTONOMY PROPOSE n=5 tag=101 class=1 contact=0 slew=30 thrust=0"
    assert runner.PROPOSE.search(fsw).groups() == ("5", "101", "1", "0", "30", "0")
    decided = "EVS Port1 EVS Port1 42/1/PRISMPATH_APP 22: PRISMPATH_APP ESCALATE seq=6 rule=4 cause=34 receipt=5"
    assert runner.DECIDE.search(decided).groups()[1:3] == ("ESCALATE", "6")


def test_spacecraft_configuration_from_nos3_minimal(tmp_path):
    if not (NOS3 / "cfg" / "spacecraft" / "sc-minimal-config.xml").exists():
        pytest.skip(f"no NOS3 checkout at {NOS3}")
    fake = tmp_path / "nos3"
    (fake / "cfg" / "spacecraft").mkdir(parents=True)
    shutil.copy(NOS3 / "cfg" / "spacecraft" / "sc-minimal-config.xml", fake / "cfg" / "spacecraft")
    runner.spacecraft_config(fake)
    text = (fake / "cfg" / runner.SC_CONFIG).read_text()
    for tag, on in (("rw", "true"), ("sample", "true"), ("cf", "false"), ("adcs", "false"), ("gui", "false")):
        assert re.search(rf"<{tag}>\s*<enable>{on}</enable>", text), tag


def test_scenario_end_to_end():
    exe = NOS3 / "fsw" / "build" / "exe" / "cpu1"
    if not (exe / "core-cpu1").exists() or not (exe / "cf" / "pp_autonomy.so").exists():
        pytest.skip(f"no NOS3 build with the PrismPath apps at {NOS3} (run integrations/cfs/nos3/run_nos3_scenario.py)")
    if not (NOS3 / "sims" / "build" / "lib" / "libsample_sim.so").exists() or not (NOS3.parent / "42" / "42").exists():
        pytest.skip("NOS3's simulators or 42 are not built")
    if shutil.which("docker") is None or subprocess.run(["docker", "image", "inspect", runner.IMAGE],
                                                        capture_output=True).returncode != 0:
        pytest.skip(f"docker or the {runner.IMAGE} image is not available")
    res = subprocess.run([sys.executable, str(REPO / "integrations/cfs/nos3/run_nos3_scenario.py"), "--skip-build",
                          "--nos3", str(NOS3)], capture_output=True, text=True, cwd=REPO, timeout=600)
    assert res.returncode == 0, res.stdout[-4000:] + res.stderr[-2000:]
