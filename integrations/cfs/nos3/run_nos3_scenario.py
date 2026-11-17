#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Run the PrismPath app in a NOS3 mission, with an autonomy app proposing commands and a fault injected through
NOS3's simulator command bus bridge, and check from the simulators' side what reached the vehicle.

    python integrations/cfs/nos3/run_nos3_scenario.py [--nos3 .cfs-build/nos3] [--keep-run DIR]

It uses a NASA NOS3 checkout in place (NOSA 1.3; nothing of it is copied into this repository) and NOS3's own
container image, and runs headless: no ground station GUI, no COSMOS or YAMCS, no 42 graphics. The steps:

  1. Stage. Link the PrismPath app and the scenario's two apps (pp_autonomy, pp_vehicle) into NOS3's components,
     write a spacecraft configuration from NOS3's minimal one with the reaction wheels on, run NOS3's `make config`
     with it, then add the three apps to the generated targets and startup script and put the PrismPath app's
     message id overrides (mission/) in the generated mission definitions. Only the NOS3 checkout is edited.
  2. Build. NOS3's flight software and simulators, inside NOS3's image, as NOS3's own build scripts do, and NASA's
     42 (cloned beside NOS3 when absent, as NOS3's `make prep` does).
  3. Provision the flight file system with test keys and a signed policy table (integrations/cfs/ground).
  4. Launch, on one private Docker network, each container capped in memory: the NOS Engine server, 42 with no
     graphics, the sample instrument simulator (the payload), the three reaction wheel simulators, the command bus
     bridge, the time driver and the flight software.
  5. The scenario. Enable the payload and wheel 0 (ground commands to NOS3's own apps), start the autonomy app,
     and after four proposals inject a payload fault, STATUS=3 to the sample simulator's command node through the
     bridge. Seal the run.
  6. Check: each decision against plan.EXPECTED and the Python reference; that the fault came in through the
     bridge and the autonomy app answered it with its playbook, decided as the policy says; from the simulators'
     own logs, that the reaction wheel saw exactly the torques of the allowed attitude proposals and the payload
     exactly the configuration words of the allowed payload proposals, and nothing of any refused or escalated
     one; and the downlinked run verifies on the ground, both keys pinned, every receipt replayed.
  7. Tear down every container and the network, put the table back, remove the keys, and check the Docker state
     is what it was before.

Exit status 0 when every check holds, 2 when NOS3 or Docker is not there.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(REPO))

from prismpath.agent.policy import Policy  # noqa: E402
from integrations.cfs.ground import downlink, provision, reference  # noqa: E402
from integrations.cfs.nos3 import plan  # noqa: E402
from integrations.cfs.prismpath_app.policy import gen_image  # noqa: E402
from integrations.cfs.tests.run_scenario import Check, packet, reading_payload  # noqa: E402

IMAGE = "ivvitc/nos3-64:20261021"        # NOS3's own image, as its scripts/env.sh names it (amd64 and arm64)
FORTYTWO_URL = "https://github.com/nasa-itc/42.git"
FORTYTWO_BRANCH = "dev_20260403"         # the branch NOS3's scripts/cfg/prepare.sh clones
NETWORK = "pp-nos3"
SC_CONFIG = "spacecraft/sc-prismpath-config.xml"
APPS = {"prismpath_app": REPO / "integrations" / "cfs" / "prismpath_app",
        "pp_autonomy": HERE / "pp_autonomy", "pp_vehicle": HERE / "pp_vehicle"}
STARTUP = ("CFE_APP, prismpath_app, PRISMPATH_APP_Main, PRISMPATH_APP, 55, 32768, 0x0, 0;\n"
           "CFE_APP, pp_vehicle,    PP_VEHICLE_Main,    PP_VEHICLE,    56, 16384, 0x0, 0;\n"
           "CFE_APP, pp_autonomy,   PP_AUTONOMY_Main,   PP_AUTONOMY,   57, 16384, 0x0, 0;\n\n")
CI_LAB_PORT = 5012                       # NOS3's ci_lab (CI_LAB_BASE_UDP_PORT)
BRIDGE_PORT = 12020                      # the command bus bridge's TCP server
# NOS3's component apps, from their headers
SAMPLE_CMD_MID, SAMPLE_ENABLE_CC = 0x18FA, 2
RW_CMD_MID, RW_ENABLE_CC = 0x1992, 4
AUTONOMY_CMD_MID, AUTONOMY_START_CC = 0x18C4, 1
SEAL_CC = 2
SIMS = ("sample-sim", "generic-reactionwheel-sim0", "generic-reactionwheel-sim1", "generic-reactionwheel-sim2")
MEMORY = {"engine": "512m", "fortytwo": "1g", "sim": "256m", "fsw": "1g", "build": "8g"}


def mids() -> Dict[str, int]:
    """The PrismPath app's message ids in this mission, from the override header."""
    text = (HERE / "mission" / "prismpath_app_topicid_values.h").read_text()
    tid = {k: int(v, 16) for k, v in re.findall(r"PP_NOS3_PRISMPATH_APP_(\w+)_TOPICID\s+(0x[0-9A-Fa-f]+)", text)}
    return {"cmd": 0x1800 | tid["CMD"], "proposed": 0x1800 | tid["PROPOSED_CMD"], "vehicle": 0x1800 | tid["VEHICLE_CMD"]}


# ----------------------------------------------------------------- docker
def sh(cmd: List[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, text=True, capture_output=True, **kw)


def docker_state() -> Dict[str, List[str]]:
    return {"containers": sorted(sh(["docker", "ps", "-a", "--format", "{{.ID}} {{.Names}} {{.Status}}"]).stdout
                                 .replace("Up ", "Up").split("\n")),
            "networks": sorted(sh(["docker", "network", "ls", "--format", "{{.ID}} {{.Name}}"]).stdout.split("\n")),
            "volumes": sorted(sh(["docker", "volume", "ls", "--format", "{{.Name}}"]).stdout.split("\n"))}


def same_state(a: Dict[str, List[str]], b: Dict[str, List[str]]) -> bool:
    def names(rows: List[str]) -> List[str]:
        return sorted(" ".join(r.split()[:2]) for r in rows if r)
    return names(a["containers"]) == names(b["containers"]) and a["networks"] == b["networks"] and \
        a["volumes"] == b["volumes"]


def user() -> List[str]:
    return ["-u", f"{os.getuid()}:{os.getgid()}", "-v", "/etc/passwd:/etc/passwd:ro", "-v", "/etc/group:/etc/group:ro"]


class Mission:
    """The launched containers, removed on close whatever happened."""

    def __init__(self, nos3: Path, fortytwo: Path, log) -> None:
        self.nos3, self.fortytwo, self.log = nos3, fortytwo, log
        self.sim = nos3 / "sims" / "build"
        self.bin = self.sim / "bin"
        self.exe = nos3 / "fsw" / "build" / "exe" / "cpu1"
        self.names: List[str] = []
        self.network = False

    def run(self, name: str, memory: str, mounts: List[Path], workdir: Path, args: List[str], aliases=(),
            extra: Tuple[str, ...] = ()) -> None:
        cmd = ["docker", "run", "-dit", "--name", name, "--network", NETWORK, "--memory", memory,
               "--memory-swap", memory, *user(), "-w", str(workdir)]
        for alias in aliases:
            cmd += ["--network-alias", alias]
        for m in mounts:
            cmd += ["-v", f"{m}:{m}"]
        cmd += [*extra, IMAGE, *args]
        res = sh(cmd)
        if res.returncode != 0:
            raise RuntimeError(f"docker run {name}: {res.stderr.strip()}")
        self.names.append(name)

    def launch(self) -> None:
        res = sh(["docker", "network", "create", NETWORK])
        if res.returncode != 0:
            raise RuntimeError(f"docker network create {NETWORK}: {res.stderr.strip()}")
        self.network = True
        inout = self.fortytwo / "NOS3InOut"
        shutil.rmtree(inout, ignore_errors=True)
        shutil.copytree(self.nos3 / "cfg" / "build" / "InOut", inout)
        self.run("sc01-nos-engine-server", MEMORY["engine"], [self.sim], self.bin,
                 ["/usr/bin/nos_engine_server_standalone", "-f", str(self.bin / "nos_engine_server_config.json")],
                 aliases=("nos-engine-server",), extra=("-h", "nos-engine-server"))
        self.run("sc01-fortytwo", MEMORY["fortytwo"], [self.fortytwo], self.fortytwo,
                 [str(self.fortytwo / "42"), "NOS3InOut"], aliases=("fortytwo",), extra=("-h", "fortytwo"))
        time.sleep(3)
        for sim in SIMS:
            self.run(f"sc01_{sim}", MEMORY["sim"], [self.sim], self.bin,
                     ["./nos3-single-simulator", "-f", "nos3-simulator.xml", sim])
        self.run("nos-sim-bridge", MEMORY["sim"], [self.sim], self.bin,
                 ["./nos3-sim-cmdbus-bridge", "-f", "nos3-simulator.xml"], aliases=("nos-sim-bridge",))
        self.run("nos-time-driver", MEMORY["sim"], [self.sim], self.bin,
                 ["./nos3-single-simulator", "-f", "nos3-simulator.xml", "time"], aliases=("nos-time-driver",))
        time.sleep(2)
        self.run("sc01_nos_fsw", MEMORY["fsw"], [self.nos3, self.exe], self.exe, ["./core-cpu1", "-R", "PO"],
                 aliases=("nos-fsw",),
                 extra=("-h", "nos-fsw", "-e", f"LD_LIBRARY_PATH={self.exe}:/usr/lib:/usr/local/lib",
                        "--sysctl", "fs.mqueue.msg_max=10000", "--ulimit", "rtprio=99", "--cap-add=sys_nice"))

    def logs(self, name: str) -> List[str]:
        res = sh(["docker", "logs", name])
        return [line.rstrip("\r") for line in (res.stdout + res.stderr).split("\n")]

    def ip(self, name: str) -> str:
        res = sh(["docker", "inspect", "-f", f'{{{{(index .NetworkSettings.Networks "{NETWORK}").IPAddress}}}}', name])
        return res.stdout.strip()

    def stats(self) -> Dict[str, str]:
        res = sh(["docker", "stats", "--no-stream", "--format", "{{.Name}} {{.MemUsage}}", *self.names])
        return dict(line.split(" ", 1) for line in res.stdout.strip().split("\n") if line)

    def close(self) -> None:
        for name in reversed(self.names):
            sh(["docker", "rm", "-f", name])
        self.names = []
        if self.network:
            sh(["docker", "network", "rm", NETWORK])
            self.network = False


# ----------------------------------------------------------------- stage and build
def spacecraft_config(nos3: Path) -> None:
    """NOS3's minimal spacecraft with its reaction wheels on and the file and storage apps off."""
    text = (nos3 / "cfg" / "spacecraft" / "sc-minimal-config.xml").read_text()
    for tag, on in (("rw", True), ("cf", False), ("ds", False), ("fm", False), ("lc", False), ("sc", False)):
        text, n = re.subn(rf"(<{tag}>\s*<enable>)(true|false)(</enable>)", rf"\g<1>{'true' if on else 'false'}\g<3>",
                          text, count=1)
        assert n == 1, f"no <{tag}> in NOS3's minimal spacecraft configuration"
    (nos3 / "cfg" / SC_CONFIG).write_text(text)


def stage(nos3: Path, log) -> None:
    for name, src in APPS.items():
        link = nos3 / "components" / name
        if link.is_symlink() or link.exists():
            link.unlink()
        link.symlink_to(src)
    spacecraft_config(nos3)
    res = sh(["make", "config", f"SC1_CFG={SC_CONFIG}"], cwd=nos3)
    if res.returncode != 0:
        raise RuntimeError(f"NOS3 make config failed:\n{res.stdout[-2000:]}{res.stderr[-2000:]}")
    defs = nos3 / "cfg" / "build" / "nos3_defs"
    targets = defs / "targets.cmake"
    text = targets.read_text()
    mark = "# Create Application Platform Include List"
    assert mark in text, "NOS3's targets.cmake changed: no include list marker"
    targets.write_text(text.replace(mark, f"list(APPEND MISSION_GLOBAL_APPLIST {' '.join(APPS)})\n\n{mark}", 1))
    startup = defs / "cpu1_cfe_es_startup.scr"
    text = startup.read_text()
    startup.write_text(text[:text.index("!")] + STARTUP + text[text.index("!"):])
    for header in (HERE / "mission").glob("*.h"):
        shutil.copy(header, defs / header.name)
    log(f"staged {', '.join(APPS)} into NOS3 ({SC_CONFIG}, make config)")


def container_make(nos3: Path, target: str, logfile: Path) -> None:
    cmd = ["docker", "run", "--rm", "--name", f"pp_nos3_build_{target}", "--memory", MEMORY["build"], "--cpus", "12",
           *user(), "-v", f"{REPO}:{REPO}", "-w", str(nos3), IMAGE, "make", "-j12", "-e", "FLIGHT_SOFTWARE=cfs", target]
    with logfile.open("w") as out:
        rc = subprocess.run(cmd, stdout=out, stderr=subprocess.STDOUT).returncode
    if rc != 0:
        raise RuntimeError(f"NOS3 {target} failed; see {logfile}")


def build(nos3: Path, fortytwo: Path, log) -> None:
    t = time.time()
    (nos3 / "fsw" / "build").mkdir(parents=True, exist_ok=True)
    container_make(nos3, "build-fsw", nos3 / "pp_build_fsw.log")
    log(f"built NOS3 flight software with the three apps ({time.time() - t:.0f} s)")
    if not (nos3 / "sims" / "build" / "lib" / "libsample_sim.so").exists():
        t = time.time()
        (nos3 / "sims" / "build").mkdir(parents=True, exist_ok=True)
        container_make(nos3, "build-sim", nos3 / "pp_build_sim.log")
        log(f"built NOS3 simulators ({time.time() - t:.0f} s)")
    if not (fortytwo / "42").exists():
        if not (fortytwo / "Makefile").exists():
            res = sh(["git", "clone", "--depth", "1", "-b", FORTYTWO_BRANCH, FORTYTWO_URL, str(fortytwo)])
            if res.returncode != 0:
                raise RuntimeError(f"cloning 42: {res.stderr.strip()}")
        cmd = ["docker", "run", "--rm", "--name", "pp_nos3_build_42", "--memory", MEMORY["build"], *user(),
               "-v", f"{fortytwo}:{fortytwo}", "-w", str(fortytwo), IMAGE, "make", "-j8"]
        with (fortytwo / "pp_build.log").open("w") as out:
            if subprocess.run(cmd, stdout=out, stderr=subprocess.STDOUT).returncode != 0:
                raise RuntimeError("building 42 failed")
        log("built 42")


# ----------------------------------------------------------------- the scenario
PROPOSE = re.compile(r"PP_AUTONOMY PROPOSE n=(\d+) tag=(\d+) class=(\d+) contact=(\d+) slew=(\d+) thrust=(\d+)")
DECIDE = re.compile(r"PRISMPATH_APP (\d+): PRISMPATH_APP (ALLOW|REFUSE|ESCALATE) seq=(\d+)(.*)$")
TORQUE = re.compile(r"uart_read_callback:\s+REQUEST\s+SET_TORQUE=\s*(-?[0-9.]+)")
SAMPLE_REQ = re.compile(r"SampleHardwareModel::uart_read_callback:\s+REQUEST\s+(.+)$")


def wait_for(mission: Mission, name: str, pattern: str, count: int = 1, timeout: float = 60) -> List[str]:
    rx = re.compile(pattern)
    deadline = time.time() + timeout
    while time.time() < deadline:
        hits = [line for line in mission.logs(name) if rx.search(line)]
        if len(hits) >= count:
            return hits
        time.sleep(0.5)
    tail = "\n".join(mission.logs(name)[-30:])
    raise TimeoutError(f"{name}: no {count} line(s) matching {pattern!r} in {timeout:.0f} s; it ended:\n{tail}")


def sample_configs(lines: List[str]) -> List[int]:
    """The configuration words the payload simulator received (device command 3), in order."""
    out = []
    for line in lines:
        m = SAMPLE_REQ.search(line)
        if not m:
            continue
        raw = bytes(int(b, 16) for b in re.findall(r"(?:0x)?([0-9A-Fa-f]{2})", m.group(1)))
        if len(raw) == 9 and raw[:2] == b"\xde\xad" and raw[2] == 3:
            out.append(int.from_bytes(raw[3:7], "big"))
    return out


def scenario(mission: Mission, keys: Path, downlinked: Path, check: Check, log) -> Dict:
    policy = Policy.load(gen_image.CORE)
    ids = mids()
    fsw = "sc01_nos_fsw"
    wait_for(mission, fsw, r"PRISMPATH_APP initialized, policy active", timeout=120)
    wait_for(mission, fsw, r"PP_AUTONOMY initialized")
    wait_for(mission, fsw, r"PP_VEHICLE initialized")
    check.ok(True, "NOS3 flight software is up with the PrismPath app active on the signed version 2 table")
    target = (mission.ip(fsw), CI_LAB_PORT)
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send(mid: int, fc: int, payload: bytes = b"") -> None:
        tx.sendto(packet(mid, fc, payload), target)
        time.sleep(0.2)

    # the ground enables the payload and reaction wheel 0, as a NOS3 operator does
    send(SAMPLE_CMD_MID, SAMPLE_ENABLE_CC)
    send(RW_CMD_MID, RW_ENABLE_CC, struct.pack("<Bh", 0, 0))
    wait_for(mission, fsw, r"SAMPLE: Device enabled|SAMPLE.*[Ee]nable", timeout=20)
    time.sleep(3)                                                     # a few payload housekeeping cycles
    send(AUTONOMY_CMD_MID, AUTONOMY_START_CC)
    wait_for(mission, fsw, r"PP_AUTONOMY START")
    wait_for(mission, fsw, r"PP_AUTONOMY PROPOSE", count=4, timeout=30)

    # the fault, through NOS3's command bus bridge into the payload simulator's command node
    with socket.create_connection((mission.ip("nos-sim-bridge"), BRIDGE_PORT), timeout=10) as bridge:
        bridge.sendall((json.dumps({"node": plan.FAULT_NODE, "cmd": plan.FAULT_COMMAND}) + "\n").encode())
        time.sleep(1)
    log(f"fault injected: {{\"node\": \"{plan.FAULT_NODE}\", \"cmd\": \"{plan.FAULT_COMMAND}\"}} to the command bus "
        f"bridge (TCP {BRIDGE_PORT})")
    total = len(plan.proposals())
    wait_for(mission, fsw, r"PP_AUTONOMY PLAN DONE", timeout=60)
    wait_for(mission, fsw, r"PRISMPATH_APP (ALLOW|REFUSE|ESCALATE) seq=", count=total, timeout=30)
    time.sleep(3)                                                     # the last commands reach the simulators
    send(ids["cmd"], SEAL_CC)
    sealed = wait_for(mission, fsw, r"PRISMPATH_APP SEALED receipts=", timeout=20)[-1]
    tx.close()

    fsw_lines = mission.logs(fsw)
    proposals = [m.groups() for m in map(PROPOSE.search, fsw_lines) if m]
    decisions = [m.groups() for m in map(DECIDE.search, fsw_lines) if m]
    log(f"\nflight software console ({len(proposals)} proposals, {len(decisions)} decisions):")
    for line in fsw_lines:
        if re.search(r"PP_AUTONOMY (PROPOSE|FAULT|PAYLOAD STATUS)|PRISMPATH_APP (ALLOW|REFUSE|ESCALATE|SEALED)|"
                     r"PP_VEHICLE (ATTITUDE|PAYLOAD|DROPPED)", line):
            log("    " + line.split(": ", 1)[-1] if ": " in line else line)

    # ------------------------------------------------ the decisions, against the table and the reference
    table = plan.by_tag()
    check.ok(len(proposals) == total and len(decisions) == total,
             f"{total} proposals ({len(plan.PLAN)} plan, {len(plan.FAULT_RESPONSE)} playbook), one decision each")
    order: List[int] = []
    for (n, tag, cls, contact, slew, thrust), (eid, kind, seq, rest) in zip(proposals, decisions):
        tag = int(tag)
        order.append(tag)
        p = table.get(tag)
        want_kind, want_cause, why = plan.EXPECTED.get(tag, ("?", 0, "not in the plan"))
        ref = policy.decide(reference.reading_bytes(reading_payload(p.reading()))) if p else None
        cause = re.search(r"cause=(\d+)", rest)
        got_cause = int(cause.group(1)) if cause else 0
        good = p is not None and int(seq) == int(n) and kind.lower() == want_kind and got_cause == want_cause and \
            (int(cls), int(contact), int(slew), int(thrust)) == (p.cmd_class, p.ground_contact, p.slew_deg,
                                                                 p.thrust_pct) and \
            ref.kind == want_kind and (ref.cause_code or 0) == want_cause and f"receipt={int(n) - 1}" in rest
        check.ok(good, f"tag {tag} ({p.what if p else '?'}): {kind}{f' cause {got_cause}' if got_cause else ''}, "
                       f"the table says {want_kind} ({why})")

    # ------------------------------------------------ the fault: through the bridge, answered by the playbook
    sample_lines = mission.logs("sc01_sample-sim")
    bridge_lines = mission.logs("nos-sim-bridge")
    check.ok(any(f"destined for {plan.FAULT_NODE} with command {plan.FAULT_COMMAND}" in line for line in bridge_lines),
             "the command bus bridge forwarded the fault to the payload simulator's command node")
    check.ok(any(f"Received command: {plan.FAULT_COMMAND}" in line for line in sample_lines),
             f"the payload simulator received {plan.FAULT_COMMAND} on its command bus node")
    fault_at = next((i for i, line in enumerate(fsw_lines) if "PP_AUTONOMY FAULT payload status=" in line), None)
    check.ok(fault_at is not None and f"status={plan.FAULT_STATUS}" in fsw_lines[fault_at],
             f"the autonomy app saw the payload's status word turn {plan.FAULT_STATUS} in its housekeeping")
    playbook = [p.tag for p in plan.FAULT_RESPONSE]
    at = [order.index(t) for t in playbook if t in order]
    check.ok(len(at) == len(playbook) and at == sorted(at) and at[-1] - at[0] == len(playbook) - 1 and
             0 < at[0] < len(order) - 1,
             f"the playbook ({', '.join(map(str, playbook))}) was proposed once, together, after the fault and "
             f"before the plan ended (proposal order {order})")
    check.ok([plan.EXPECTED[t][0] for t in playbook] == ["allow", "escalate"],
             "the fault produces the policy's decisions: the 30 deg slew off the sun is allowed, the 75 deg slew to "
             "sun safe with no ground contact is escalated (route:needs-human, 34) and does not reach the wheels")

    # ------------------------------------------------ the vehicle side, from the simulators' own logs
    allowed = plan.allowed(order)
    want_torques, want_configs = plan.vehicle_effects(allowed)
    torques = [round(float(m.group(1)) * 10000) for m in map(TORQUE.search, mission.logs("sc01_generic-reactionwheel-sim0"))
               if m]
    configs = sample_configs(sample_lines)
    others = [line for w in (1, 2) for line in mission.logs(f"sc01_generic-reactionwheel-sim{w}") if TORQUE.search(line)]
    log(f"\nreaction wheel 0 simulator, SET_TORQUE requests (x 10^-4 N m): {torques}")
    log(f"payload simulator, configuration commands: {configs}")
    check.ok(torques == want_torques,
             f"reaction wheel 0 saw exactly the allowed attitude commands' torques {want_torques}, in order")
    check.ok(configs == want_configs,
             f"the payload simulator saw exactly the allowed payload commands' configuration words {want_configs}")
    blocked = [t for t in order if plan.EXPECTED[t][0] != "allow"]
    leaked = [t for t in blocked if (table[t].cmd_class == plan.ATTITUDE and plan.torque(table[t]) in torques) or
              (table[t].cmd_class == plan.PAYLOAD and t in configs)]
    check.ok(not leaked and not others,
             f"nothing refused or escalated (tags {blocked}) reached a simulator; wheels 1 and 2 saw no torque")

    # ------------------------------------------------ the downlink, verified on the ground
    run_dir = mission.exe / "cf" / "pprun"
    check.ok(f"receipts={total} " in sealed, f"the seal signs a root over {total} receipts: {sealed.split(': ')[-1]}")
    if downlinked.exists():
        shutil.rmtree(downlinked)
    downlink.fetch(run_dir, downlinked)
    cli = subprocess.run([sys.executable, "-m", "prismpath", "evidence", "verify", str(downlinked), "--sample", "all",
                          "--pin-authority", str(keys / "authority.pub"), "--pin-instance", str(keys / "instance.pub")],
                         capture_output=True, text=True, cwd=REPO)
    log(f"\n$ prismpath evidence verify <downlink> --sample all --pin-authority <ground>/authority.pub "
        f"--pin-instance <ground>/instance.pub\n"
        f"{(cli.stdout.strip() + cli.stderr.strip()).replace(str(downlinked), '<downlink>')}")
    check.ok(cli.returncode == 0 and "verified" in cli.stdout,
             "prismpath evidence verify accepts the downlinked run, both keys pinned, every receipt replayed")
    try:
        summary = downlink.verify(downlinked, keys)
        check.ok(summary["replayed"] == total and summary["agree"] == total and summary["root_statement"] == "signed",
                 f"all {total} receipts replayed through the reference kernel agree; the root statement is signed "
                 "with the pinned instance key")
    except downlink.Bad as bad:
        check.ok(False, f"the ground verifies the downlinked run: {bad}")
    return {"order": order, "torques": torques, "configs": configs}


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--nos3", type=Path, default=REPO / ".cfs-build" / "nos3", help="the NOS3 checkout")
    parser.add_argument("--fortytwo", type=Path, default=None, help="NASA 42 (default: beside the NOS3 checkout)")
    parser.add_argument("--skip-build", action="store_true", help="use the staged build as it is")
    parser.add_argument("--keep-run", type=Path, default=None, help="keep the downlinked run and keys here")
    parser.add_argument("--leave-running", action="store_true",
                        help="debugging: leave the containers up (remove them with --teardown)")
    parser.add_argument("--teardown", action="store_true", help="remove the containers and network a run left up")
    args = parser.parse_args(argv)
    nos3 = args.nos3.resolve()
    fortytwo = (args.fortytwo or nos3.parent / "42").resolve()
    if not (nos3 / "fsw" / "cfe").is_dir() or not (nos3 / "scripts" / "env.sh").exists():
        print(f"no NOS3 checkout with submodules at {nos3} (see integrations/cfs/nos3/README.md)", file=sys.stderr)
        return 2
    if sh(["docker", "version"]).returncode != 0:
        print("docker is not available", file=sys.stderr)
        return 2
    if args.teardown:
        for name in ["sc01_nos_fsw", "nos-time-driver", "nos-sim-bridge", *[f"sc01_{s}" for s in SIMS],
                     "sc01-fortytwo", "sc01-nos-engine-server"]:
            sh(["docker", "rm", "-f", name])
        sh(["docker", "network", "rm", NETWORK])
        return 0
    started = time.time()

    def log(line: str) -> None:
        print(line, flush=True)

    before = docker_state()
    if sh(["docker", "image", "inspect", IMAGE]).returncode != 0:
        log(f"pulling {IMAGE}")
        if sh(["docker", "pull", IMAGE]).returncode != 0:
            print(f"could not pull {IMAGE}", file=sys.stderr)
            return 2
    check = Check()
    work = Path(tempfile.mkdtemp(prefix="pp-nos3-"))
    keys = (args.keep_run or work) / "keys"
    downlinked = (args.keep_run or work) / "downlink"
    mission = Mission(nos3, fortytwo, log)
    tbl = mission.exe / "cf" / "pp_app_policy.tbl"
    original: Optional[bytes] = None
    try:
        if not args.skip_build:
            stage(nos3, log)
            build(nos3, fortytwo, log)
        original = tbl.read_bytes()
        shutil.rmtree(mission.exe / "cf" / "pprun", ignore_errors=True)    # a new run on a power on reset
        provision.provision(mission.exe, keys)
        log("provisioned the flight file system: test authority and instance keys, the signed version 2 table")
        t = time.time()
        mission.launch()
        log(f"launched {len(mission.names)} containers on {NETWORK}: {', '.join(mission.names)}")
        result = scenario(mission, keys, downlinked, check, log)
        mem = mission.stats()
        log(f"\nmemory in use per container: {mem}")
        log(f"scenario time {time.time() - t:.0f} s")
        result["memory"] = mem
    except (RuntimeError, TimeoutError, OSError) as err:
        check.ok(False, f"the scenario ran to the end: {err}")
    finally:
        if not args.leave_running:
            mission.close()
        if original is not None:
            tbl.write_bytes(original)
        for name in ("pp_authority.pub", "pp_instance.key"):
            (mission.exe / "cf" / name).unlink(missing_ok=True)
        if not args.keep_run:
            shutil.rmtree(work, ignore_errors=True)
    if not args.leave_running:
        after = docker_state()
        check.ok(same_state(before, after),
                 "every container and network the run made is removed; Docker is as it was before the run")
    print("\n" + "\n".join(check.report))
    log(f"\ntotal time {time.time() - started:.0f} s")
    if check.failures:
        print(f"\nFAILED: {len(check.failures)} check(s)")
        return 1
    print(f"\nall {len(check.report)} checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
