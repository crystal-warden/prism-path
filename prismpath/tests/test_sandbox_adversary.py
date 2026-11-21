# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""An allowed command whose child reaches outside the workspace.

The policy here allows a shell command that changes files inside the workspace to run (the starters ask the person
about one), so `python3 tool.py` and `sh build.sh` are allowed calls. Each script opens a decoy secret under
/var/tmp, writes a file beside it and connects to a listener on the host's own non-loopback address. The same
allowed call is run twice from its hook answer: once as the original command, which is what the hook alone
allowed before the sandbox (and what a person's approval of a question still runs), and once as the rewritten command.
The first reaches all three, the second none, so the gap the sandbox closes stays measured. The decoy holds no
real secret and the listener is the test's own.

The same runs check that the sandboxed run's refusals are recorded as observations bound to the call's
receipt, and `prismpath agent verify` verifies the run with them.
"""
import json
import os
import shutil
import socket
import subprocess
import tempfile
import threading
from pathlib import Path

import pytest

pytest.importorskip("cryptography")
pytest.importorskip("fcntl")

from prismpath.agent import commands  # noqa: E402
from prismpath.agent.profile import STRICTEST, compile_profile  # noqa: E402
from prismpath.agent.run import RunStore  # noqa: E402
from prismpath.kernel import canon2  # noqa: E402
from prismpath.tests.test_agent_cli import _agent_dir, _cli, _hook, _init, world  # noqa: E402,F401
from prismpath.tests.test_sandbox_hook import _WHY, _bash, _output, needs_bwrap  # noqa: E402,F401

RUN_SCRIPT = {"target": "allow", "when": ["and", ["cmp", "tool", "==", ["str", "run_command"]],
                                          ["cmp", "command_class", "==", ["str", "mutating"]],
                                          ["cmp", "git_op", "==", ["str", "none"]],
                                          ["in", "path_scope", [["str", "none"], ["str", "workspace"]]]]}

TOOL_PY = """import json, socket, sys
out = {}
try:
    out["read"] = open(%(secret)r).read().strip()
except OSError as exc:
    out["read"] = None
    sys.stderr.write("read: %%s\\n" %% exc)
try:
    open(%(written)r, "w").write("written")
    out["write"] = True
except OSError as exc:
    out["write"] = False
    sys.stderr.write("write: %%s\\n" %% exc)
try:
    socket.create_connection((%(host)r, %(port)d), timeout=3).close()
    out["connect"] = True
except OSError as exc:
    out["connect"] = False
    sys.stderr.write("connect: %%s\\n" %% exc)
print(json.dumps(out))
"""
BUILD_SH = """#!/bin/sh
cat %(secret)s || echo "build: no secret" >&2
echo written > %(written)s || echo "build: no write" >&2
exec python3 tool.py
"""


def _outside_address() -> str:
    """The host's own address on a real interface, or loopback when it has none."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 9))     # a route lookup, nothing is sent
        return probe.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        probe.close()


class Listener:
    def __init__(self):
        self.address = _outside_address()
        self.sock = socket.socket()
        self.sock.bind(("0.0.0.0", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.connections = 0
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.connections += 1
            conn.close()

    def close(self):
        self.sock.close()


def _install(world, rules):
    """Record a starter's image with `rules` put first, signed by the throwaway authority key."""
    from prismpath.agent.policy import starter_path
    home = _agent_dir(world["home"])
    doc = canon2.loads((home / commands.POLICY_FILE).read_bytes().rstrip(b"\n"))
    doc["rules"] = list(rules) + doc["rules"]
    image = canon2.dumps(doc)
    (home / commands.POLICY_FILE).write_bytes(image)
    (home / commands.ATTESTATION_FILE).write_bytes(commands._attestation(home, image))
    (home / "profiles").mkdir(exist_ok=True)
    return image


@pytest.fixture()
def arena(world):
    """The world with the script-running policy installed, a decoy directory under /var/tmp and a listener."""
    _init(world)
    _install(world, [RUN_SCRIPT])
    decoy = Path(tempfile.mkdtemp(prefix="prismpath-decoy-", dir="/var/tmp"))
    (decoy / "secret.txt").write_text("DECOY-NOT-A-SECRET\n")
    listener = Listener()
    ws = Path(world["ws"])
    values = {"secret": str(decoy / "secret.txt"), "written": str(decoy / "written.txt"),
              "host": listener.address, "port": listener.port}
    (ws / "tool.py").write_text(TOOL_PY % values)
    (ws / "build.sh").write_text(BUILD_SH % values)
    try:
        yield {**world, "decoy": decoy, "listener": listener}
    finally:
        listener.close()
        shutil.rmtree(decoy, ignore_errors=True)


def _run(world, command, cwd):
    return subprocess.run(["/bin/bash", "-c", command], capture_output=True, cwd=cwd, timeout=60,
                          env={"PATH": "/usr/bin:/bin", "HOME": str(world["home"])})


def _reach(world, command, session):
    """(what the unprotected call reached, what the sandboxed call reached, the hook's answer)."""
    answer = _output(_hook(world["home"], {**_bash(world, command), "session_id": session}))
    assert answer["permissionDecision"] == "allow" and "updatedInput" in answer
    decoy, listener = world["decoy"], world["listener"]
    (decoy / "written.txt").unlink(missing_ok=True)
    before = listener.connections
    old = _run(world, command, world["ws"])                       # the hook alone: the original command
    import time
    time.sleep(0.2)
    old_reached = {"read": b"DECOY-NOT-A-SECRET" in old.stdout, "write": (decoy / "written.txt").exists(),
                   "connect": listener.connections > before}
    (decoy / "written.txt").unlink(missing_ok=True)
    before = listener.connections
    new = _run(world, answer["updatedInput"]["command"], world["ws"])
    time.sleep(0.2)
    new_reached = {"read": b"DECOY-NOT-A-SECRET" in new.stdout, "write": (decoy / "written.txt").exists(),
                   "connect": listener.connections > before}
    return old_reached, new_reached, old, new, answer


@needs_bwrap
@pytest.mark.parametrize("command", ["python3 tool.py", "sh build.sh"])
def test_the_hook_alone_reaches_every_outside_resource_and_the_sandbox_reaches_none(arena, command):
    old, new, old_run, new_run, _ = _reach(arena, command, "adv-" + command.split()[0])
    assert old == {"read": True, "write": True, "connect": True}, (old, old_run.stderr)
    assert new == {"read": False, "write": False, "connect": False}, (new, new_run.stdout, new_run.stderr)


@needs_bwrap
def test_the_sandboxed_refusals_are_observations_bound_to_the_receipt_and_the_run_verifies(arena):
    _, _, _, new_run, answer = _reach(arena, "python3 tool.py", "adv-observe")
    home = _agent_dir(arena["home"])
    run = RunStore(home / "runs").get("adv-observe")
    image_sha = __import__("hashlib").sha256((home / commands.POLICY_FILE).read_bytes()).hexdigest()
    seen = run.observations()
    assert len(seen) == 1                       # the unsandboxed run recorded nothing, it had no runner
    obs = seen[0]
    assert obs["receipt"] == 0 and obs["image_sha256"] == image_sha
    assert obs["profile_sha256"] == STRICTEST.hash() == compile_profile((home / commands.POLICY_FILE).read_bytes()).hash()
    kinds = {s["kind"] for s in obs["observed"]["signals"]}
    assert kinds <= {"access-denied", "path-absent", "network-unreachable", "write-refused"} and "network-unreachable" in kinds
    assert obs["observed"]["method"] == "stderr-pattern"
    # the observation changed nothing the policy decides: the receipt is the allow it was
    assert run.summary()["receipts"] == 1
    done = _cli(arena["home"], "agent", "verify", "--json")
    report = json.loads(done.stdout)
    assert done.returncode == 0 and report["verified"] and report["runs"][0]["observations"] == 1


def test_an_unbound_or_altered_observation_is_refused_by_verify(arena):
    _init(arena)
    home = _agent_dir(arena["home"])
    _hook(arena["home"], _bash(arena, "ls"))
    run = RunStore(home / "runs").get("s1")
    image_sha = __import__("hashlib").sha256((home / commands.POLICY_FILE).read_bytes()).hexdigest()
    from prismpath.agent.run import RunError
    profile = json.loads(json.dumps(_profile_hash(home)))
    body = {"method": "stderr-pattern", "exit_status": 1, "timed_out": False,
            "signals": [{"kind": "access-denied", "text": "x: Permission denied"}]}
    with pytest.raises(RunError):
        run.observe(5, image_sha, profile, body)                    # no such receipt
    with pytest.raises(RunError):
        run.observe(0, image_sha, "0" * 64, body)                   # not the profile the call ran under
    run.observe(0, image_sha, profile, body)
    assert run.verify_observations() == 1
    path = run.dir / "observations.jsonl"
    good = path.read_bytes()
    path.write_bytes(good.replace(b"Permission denied", b"Permission granted"))
    with pytest.raises(RunError):
        run.verify_observations()
    path.write_bytes(good.replace(b'"receipt":0', b'"receipt":3'))
    with pytest.raises(RunError):
        run.verify_observations()
    path.write_bytes(good)
    done = _cli(arena["home"], "agent", "verify", "--json")
    assert done.returncode == 0
    path.write_bytes(good.replace(b"Permission denied", b"Permission granted"))
    done = _cli(arena["home"], "agent", "verify", "--json")
    assert done.returncode == 1 and not json.loads(done.stdout)["verified"]


def _profile_hash(home):
    return compile_profile((home / commands.POLICY_FILE).read_bytes()).hash()


def test_observations_are_not_rule_hits_and_the_policy_is_untouched(arena):
    from prismpath.agent import rules
    _init(arena)
    home = _agent_dir(arena["home"])
    before = {p.name: p.read_bytes() for p in home.iterdir() if p.is_file()}
    _hook(arena["home"], _bash(arena, "ls"))
    run = RunStore(home / "runs").get("s1")
    image_sha = __import__("hashlib").sha256((home / commands.POLICY_FILE).read_bytes()).hexdigest()
    base = json.loads(_cli(arena["home"], "agent", "rules", "--json").stdout)
    for _ in range(3):
        run.observe(0, image_sha, _profile_hash(home), {"method": "stderr-pattern", "exit_status": 1, "timed_out": False,
                                                        "signals": [{"kind": "access-denied", "text": "Permission denied"}]})
    after = json.loads(_cli(arena["home"], "agent", "rules", "--json").stdout)
    assert after == base
    assert {p.name: p.read_bytes() for p in home.iterdir() if p.is_file()} == before


@needs_bwrap
def test_an_escalated_script_asks_with_the_rewrite_and_approving_it_reaches_none_of_the_resources(arena):
    from prismpath.agent.policy import starter_path
    home = _agent_dir(arena["home"])               # back to the default policy, which asks about such a script
    image = starter_path("default").read_bytes()
    (home / commands.POLICY_FILE).write_bytes(image)
    (home / commands.ATTESTATION_FILE).write_bytes(commands._attestation(home, image))
    answer = _output(_hook(arena["home"], {**_bash(arena, "sh build.sh"), "session_id": "adv-ask"}))
    assert answer["permissionDecision"] == "ask" and "updatedInput" in answer
    assert "runs inside the PrismPath sandbox" in answer["permissionDecisionReason"]
    decoy, listener = arena["decoy"], arena["listener"]
    (decoy / "written.txt").unlink(missing_ok=True)
    before = listener.connections
    done = _run(arena, answer["updatedInput"]["command"], arena["ws"])     # what an approval runs
    import time
    time.sleep(0.2)
    assert b"DECOY-NOT-A-SECRET" not in done.stdout
    assert not (decoy / "written.txt").exists() and listener.connections == before
    run = RunStore(_agent_dir(arena["home"]) / "runs").get("adv-ask")
    seen = run.observations()
    assert len(seen) == 1 and seen[0]["receipt"] == 0
    assert run.summary()["receipts"] == 1 and run.verify_observations() == 1
