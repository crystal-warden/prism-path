#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Run the PrismPath guard end to end in the F Prime reference deployment, and verify its run on the ground.

    python3 integrations/fprime/tests/run_scenario.py [--fprime-venv DIR] [--keys DIR]

Needs a built deployment (`fprime-util build` in integrations/fprime, see the README) and the F Prime tools in a
virtual environment (--fprime-venv, default .cfs-build/fpvenv at the repository root). It

  1. provisions a scratch directory the way a mission would provision the vehicle (integrations/fprime/ground/
     provision.py: the authority public key, the instance key, the signed policy table, a tampered one);
  2. starts the F Prime GDS headless (`fprime-gds -g none`), which runs the PrismPathRef deployment and connects to it;
  3. runs integrations/fprime/tests/gds_scenario.py with pytest and F Prime's own integration test API
     (`fprime_test_api`): a proposal with no policy loaded is refused and not receipted, a tampered table is refused
     as sig:invalid, the signed table loads from the guard's parameters, the S1 sequence of
     integrations/cfs/tests/run_scenario.py is proposed through the Proposer, each decision's event is checked
     against the Python reference, exactly the allowed commands reach the Vehicle through the command dispatcher, and
     the run is sealed;
  4. on the ground, copies the run directory out and checks it: the receipts against the cFS app's (the same bytes
     but for the decider's name, ground/conform.py), and the run with the repository's verifier with both keys pinned
     and every receipt replayed (`prismpath evidence verify RUN --sample all --pin-authority --pin-instance`).

Exit status 0 when every check holds, 2 when there is no build to run.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
FPRIME = HERE.parent
REPO = HERE.parents[2]
sys.path.insert(0, str(REPO))

from integrations.cfs.ground import downlink  # noqa: E402
from integrations.cfs.prismpath_app.policy import gen_image  # noqa: E402
from integrations.cfs.tests import run_scenario as cfs_scenario  # noqa: E402
from integrations.fprime.ground import conform, provision  # noqa: E402
from prismpath.agent.policy import Policy  # noqa: E402

DEPLOYMENT = FPRIME / "build-artifacts" / "Linux" / "PrismPathRef"
DICTIONARY = DEPLOYMENT / "dict" / "PrismPathRefTopologyDictionary.json"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def proposals(policy: Policy) -> list:
    """The S1 sequence as the Proposer's commands, with what the reference decides for each."""
    out = []
    for name, case in cfs_scenario.SEQUENCE:
        kind, cause = cfs_scenario.expected(policy, case)
        if isinstance(case, bytes):                 # the payload shorter than the layout: cmd_class, contact, slew only
            case = dict(cmd_class=case[0], ground_contact=case[1], slew_deg=int.from_bytes(case[2:4], "little"), thrust_pct=0)
            partial = True
        else:
            partial = False
        out.append(dict(case, name=name, partial=partial, expect={"kind": kind, "cause": cause}))
    return out


def tools_present(venv: Path) -> bool:
    return (DEPLOYMENT / "bin" / "PrismPathRef").exists() and (venv / "bin" / "fprime-gds").exists()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--fprime-venv", type=Path, default=REPO / ".cfs-build" / "fpvenv")
    parser.add_argument("--keys", type=Path, default=None, help="the ground's key directory (default: a scratch one)")
    parser.add_argument("--keep", action="store_true", help="keep the scratch directory and say where it is")
    args = parser.parse_args(argv)
    if not tools_present(args.fprime_venv):
        print("no built PrismPathRef deployment or no F Prime tools venv (pass --fprime-venv)")
        return 2
    venv_bin = args.fprime_venv / "bin"

    work = Path(tempfile.mkdtemp(prefix="pp-fprime-"))
    keys = args.keys or work / "keys"
    onboard, run_dir, logs = work / "pp", work / "pp" / "run", work / "logs"
    provision.provision(onboard, keys)
    policy = Policy.load(gen_image.CORE)
    scenario = {"onboard": "pp", "run": "pp/run", "version": gen_image.VERSION, "proposals": proposals(policy),
                "no_policy_case": dict(cmd_class=3, ground_contact=0, slew_deg=0, thrust_pct=0, name="no policy", partial=False)}
    (work / "scenario.json").write_text(json.dumps(scenario))
    port, gui, tts = free_port(), free_port(), free_port()
    env = dict(os.environ, PATH=f"{venv_bin}:{os.environ['PATH']}", PRISMPATH_FPRIME_SCENARIO=str(work / "scenario.json"),
               PRISMPATH_FPRIME_RESULT=str(work / "result.json"))
    failures, report = [], []
    # the GDS does not start the deployment (-n): it would run it from the build directory, and the guard's files are
    # relative to a directory this run owns
    gds = subprocess.Popen(["fprime-gds", "-g", "none", "-n", "-d", str(DEPLOYMENT), "--logs", str(logs), "--gui-port", str(gui),
                            "--ip-port", str(port), "--tts-port", str(tts), "--zmq-transport",
                            f"ipc://{work}/zmq-in", f"ipc://{work}/zmq-out"],
                           cwd=work, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, start_new_session=True)
    app = None
    try:
        time.sleep(6)                               # the GDS starts and listens, then the deployment connects to it
        app = subprocess.Popen([str(DEPLOYMENT / "bin" / "PrismPathRef"), "-a", "127.0.0.1", "-p", str(port)], cwd=work,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        time.sleep(3)
        if gds.poll() is not None:
            print(gds.stdout.read())
            return 1
        test = subprocess.run([str(venv_bin / "python"), "-m", "pytest", str(HERE / "gds_scenario.py"), "-c", os.devnull,
                               "--rootdir", str(work), "-p", "no:cacheprovider", "--tb=short", "--dictionary", str(DICTIONARY),
                               "--tts-port", str(tts), "--zmq-transport",
                               f"ipc://{work}/zmq-in", f"ipc://{work}/zmq-out", "-v"], cwd=work, env=env, capture_output=True, text=True, timeout=300)
        print("\n".join(line for line in test.stdout.splitlines()
                        if ("PASSED" in line or "FAILED" in line or " passed" in line or " failed" in line) and "[Test API]" not in line))
        if test.returncode != 0:
            (work / "gds_scenario.out").write_text(test.stdout + test.stderr)
            print("\n".join(line for line in test.stdout.splitlines() if line.startswith("E ")))
            print(f"(the whole test output is in {work / 'gds_scenario.out'} with --keep)")
            failures.append("the GDS integration test failed")
    finally:
        if app is not None:
            app.send_signal(signal.SIGINT)
            try:
                app.wait(timeout=10)
            except subprocess.TimeoutExpired:
                app.kill()
        try:
            os.killpg(gds.pid, signal.SIGINT)
            gds.wait(timeout=15)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            try:
                os.killpg(gds.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def ok(condition: bool, what: str) -> None:
        report.append(f"  {'ok  ' if condition else 'FAIL'} {what}")
        if not condition:
            failures.append(what)

    if not failures:
        result = json.loads((work / "result.json").read_text())
        ground = downlink.fetch(run_dir, work / "ground")
        payloads = [cfs_scenario.payload_of(case) for _n, case in cfs_scenario.SEQUENCE]
        diffs = conform.compare(ground, policy, gen_image.VERSION, payloads)
        ok(not diffs, f"the guard's {len(payloads)} receipts are the cFS app's receipts byte for byte, decider aside"
           + "".join(diffs))
        try:
            summary = downlink.verify(ground, keys)
            ok(summary["agree"] == len(payloads) and summary["disagree"] == 0 and summary["root_statement"] == "signed",
               f"the ground's verifier replays every receipt through the reference kernel ({summary['agree']} agree, "
               f"{summary['disagree']} disagree) and the root statement is signed")
            ok(summary["root"] == result["root"], "the root in the guard's SEALED event is the run's root")
        except downlink.Bad as bad:
            ok(False, f"the ground refuses the run: {bad}")
        cli = subprocess.run([sys.executable, "-m", "prismpath", "evidence", "verify", str(ground), "--sample", "all",
                              "--pin-authority", str(keys / "authority.pub"), "--pin-instance", str(keys / "instance.pub")],
                             capture_output=True, text=True, cwd=REPO)
        report.append(cli.stdout.rstrip())
        ok(cli.returncode == 0 and "verified" in cli.stdout, "prismpath evidence verify, both keys pinned, every receipt replayed")
    print("\n".join(report))
    if args.keep:
        print(f"kept {work}")
    else:
        shutil.rmtree(work, ignore_errors=True)
    print("run_scenario: all checks passed" if not failures else f"run_scenario: FAILED: {failures}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
