# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""WP8 of docs/design/agent-sandbox-plan.md: the per call sandbox nested inside the outer agent sandbox, and the
table of section 4, where the hook, the per call sandbox and the outer sandbox can disagree.

Under `prismpath agent run` a stand-in program plays Claude Code. It runs the staged hook command for each recorded
input, then runs what the answer says, as Claude Code would (`bash -c` of the rewritten command), and its own
file reads directly, as Claude's Read tool does with no hook in the way. Nothing here reads a real login or key:
the credential is a fake file this test writes. Paths the sandbox must see are under /var/tmp.

The stricter layer wins, and each case that the inner layer stops is recorded as an observation bound to the
receipt. One case is a known gap that no layer closes yet: the agent's own file tool can read the staged model
credential, because the outer sandbox mounts it for the agent itself. `KNOWN_GAP_CREDENTIAL_READ` says so, and the test
asserts the gap is there. A later fix (agent-sandbox-plan, section 2.3 and question 1) must flip it, and the test
then fails until the constant and the plan change with it."""
import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path

import pytest

pytest.importorskip("cryptography")
pytest.importorskip("fcntl")

from prismpath.agent import commands, launcher, run as run_module, sandbox_hook  # noqa: E402
from prismpath.agent.profile import STRICTEST, compile_profile  # noqa: E402
from prismpath.kernel import causes  # noqa: E402
from prismpath.tests import test_agent_cli as cli_tests  # noqa: E402
from prismpath.tests.test_agent_decider import world, _no_real_config_dir  # noqa: E402,F401
from prismpath.tests.test_agent_launcher import needs_socat  # noqa: E402
from prismpath.tests.test_sandbox_adversary import RUN_SCRIPT, _install  # noqa: E402
from prismpath.tests.test_sandbox_exec import needs_bwrap  # noqa: E402


def _nesting_works():
    """Whether this host lets a bwrap sandbox start a second one inside it. Ubuntu 24.04's AppArmor setting (GitHub's
    runners among them) forbids the nested user namespace, and there the launcher denies every shell command with
    cause 129 by design; the tests that need a nested sandbox to run skip, and the deny is asserted instead."""
    import subprocess
    from prismpath.agent import sandbox_exec as _se
    if not os.access(_se.BWRAP, os.X_OK):
        return False
    m = ["--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib"]
    if os.path.isdir("/usr/lib64"):
        m += ["--symlink", "usr/lib64", "/lib64"]
    m += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--unshare-all", "--die-with-parent"]
    try:
        return subprocess.run([_se.BWRAP, *m, "--", _se.BWRAP, *m, "--", "/usr/bin/true"],
                              capture_output=True, timeout=20).returncode == 0
    except Exception:  # noqa: BLE001
        return False


NESTING = _nesting_works()
needs_nesting = pytest.mark.skipif(not NESTING, reason="this host forbids a sandbox inside a sandbox (nested user "
                                                     "namespaces); the launcher denies shell commands there with cause 129")

SANDBOX_CODE = causes.code("agent:sandbox-unavailable")
CREDENTIAL_TEXT = "FAKE-CREDENTIAL-NOT-A-KEY"
CREDENTIAL_IN = f"{launcher.CONFIG_IN}/{launcher.CREDENTIAL_NAME}"

# The known gap of agent-sandbox-plan section 4 and question 1. True while the outer sandbox mounts the model
# credential for the agent's own use, so the agent's own Read tool can read it and only the hook stops that call.
KNOWN_GAP_CREDENTIAL_READ = True

TOOL_PY = """import json, socket, sys
out = {}
for name, path in (("credential", %(credential)r),):
    try:
        out[name] = open(path).read().strip()
    except OSError as exc:
        out[name] = None
        sys.stderr.write("read: %%s\\n" %% exc)
try:
    open("/home/agent/leak.txt", "w").write("x")
    out["write"] = True
except OSError as exc:
    out["write"] = False
    sys.stderr.write("write: %%s\\n" %% exc)
for name, host, port in (("relay", "127.0.0.1", %(port)d), ("outside", "192.0.2.1", 9)):
    try:
        socket.create_connection((host, port), timeout=3).close()
        out[name] = True
    except OSError as exc:
        out[name] = False
        sys.stderr.write("connect: %%s\\n" %% exc)
print(json.dumps(out))
"""

STAND_IN = r'''
import json, os, subprocess
out = {"steps": []}
cfg = os.environ["CLAUDE_CONFIG_DIR"]
command = json.load(open(cfg + "/settings.json"))["hooks"]["PreToolUse"][0]["hooks"][0]["command"]

def sh(cmd):
    done = subprocess.run(["/bin/bash", "-c", cmd], capture_output=True, timeout=120,
                          env={"PATH": "/usr/bin:/bin", "HOME": "/home/agent"})
    return [done.returncode, done.stdout.decode(), done.stderr.decode()]

for item in json.load(open("inputs.json")):
    step = {"name": item["name"]}
    done = subprocess.run(["/bin/sh", "-c", command], input=json.dumps(item["input"]).encode(), capture_output=True)
    step["hook"] = [done.returncode, done.stdout.decode()]
    answer = json.loads(done.stdout or b"{}").get("hookSpecificOutput", {})
    if item.get("input", {}).get("tool_name") == "Bash":
        if item.get("raw"):                     # what the outer sandbox alone lets a shell child do
            step["raw"] = sh(item["input"]["tool_input"]["command"])
        if answer.get("permissionDecision") == "allow":
            step["ran"] = sh(answer.get("updatedInput", item["input"]["tool_input"])["command"])
    if item.get("direct_read"):                 # the agent's own file tool: no hook, only the mounts
        try:
            step["direct_read"] = "read: " + open(item["direct_read"]).read().strip()
        except BaseException as exc:
            step["direct_read"] = "fail: " + type(exc).__name__
    out["steps"].append(step)
json.dump(out, open("out.json", "w"))
'''


def _launch(world, inputs, credential, **kwargs):
    ws = Path(world["ws"])
    (ws / "inputs.json").write_text(json.dumps(inputs))
    (ws / "agent.py").write_text(STAND_IN)
    stages = world["root"] / "stages"
    stages.mkdir(exist_ok=True)
    code = launcher.launch(["/usr/bin/python3", "agent.py"], str(ws), credential=str(credential), stage_base=str(stages),
                           **kwargs)
    assert code == 0
    assert list(stages.iterdir()) == []
    return json.loads((ws / "out.json").read_text())["steps"]


def _answer(step):
    rc, text = step["hook"]
    assert rc == 0
    return json.loads(text)["hookSpecificOutput"]


@pytest.fixture()
def arena(world, monkeypatch):
    home, ws = world["home"], Path(world["ws"])
    monkeypatch.setenv("HOME", str(home))
    for name in ("XDG_CONFIG_HOME", "APPDATA", "CLAUDE_PROJECT_DIR"):
        monkeypatch.delenv(name, raising=False)
    cli_tests._init(world)
    image = _install(world, [RUN_SCRIPT])
    credential = world["root"] / "fake-credential.json"
    credential.write_text(CREDENTIAL_TEXT)
    secret = world["home_b"] / ".ssh" / "config"
    secret.parent.mkdir(parents=True)
    secret.write_text("Host decoy\n")
    (ws / "tool.py").write_text(TOOL_PY % {"credential": CREDENTIAL_IN, "port": 3128})
    return {**world, "image": image, "credential": credential, "ssh": str(secret)}


def _bash(arena, command, session):
    return {"session_id": session, "cwd": arena["ws"], "hook_event_name": "PreToolUse", "tool_name": "Bash",
            "tool_input": {"command": command}}


def _file(arena, tool, path, session, **extra):
    return {"session_id": session, "cwd": arena["ws"], "hook_event_name": "PreToolUse", "tool_name": tool,
            "tool_input": {"file_path": path, **extra}}


# ------------------------------------------------------------------------- the nested per call sandbox
@needs_bwrap
@needs_socat
@needs_nesting
def test_a_rewritten_call_runs_nested_and_the_inner_layer_stops_and_records_what_the_outer_one_allows(arena):
    sess = "nest1"
    steps = _launch(arena, [
        {"name": "tool", "input": _bash(arena, "python3 tool.py", sess), "raw": True},
        {"name": "end", "input": {"session_id": sess, "hook_event_name": "SessionEnd"}},
    ], arena["credential"])
    step = steps[0]
    answer = _answer(step)
    assert answer["permissionDecision"] == "allow"
    rewritten = answer["updatedInput"]["command"]
    assert rewritten.startswith(f"{launcher.HOOK_PYTHON} -I {launcher.RUNNER_IN} "), rewritten     # not a host path
    # the outer sandbox alone: the child reads the credential, writes under the agent's home and reaches the relay
    rc, stdout, stderr = step["raw"]
    raw = json.loads(stdout)
    assert raw["credential"] == CREDENTIAL_TEXT and raw["write"] is True and raw["relay"] is True, (raw, stderr)
    # nested: none of them, and the unrouted address is unreachable
    rc, stdout, stderr = step["ran"]
    nested = json.loads(stdout)
    assert nested == {"credential": None, "write": False, "relay": False, "outside": False}, (nested, stderr)
    assert "PrismPath did not run" not in stderr
    # the inner layer's refusals are one observation bound to the receipt, with the bash profile hash
    home = cli_tests._agent_dir(arena["home"])
    run = run_module.RunStore(home / commands.RUNS_DIR).get(sess)
    entries = run._entries()
    assert len(entries) == 1 and entries[0]["sandbox"]["profile_sha256"] == STRICTEST.hash() == compile_profile(arena["image"]).hash()
    seen = run.observations()
    assert len(seen) == 1
    obs = seen[0]
    assert obs["receipt"] == 0 and obs["profile_sha256"] == STRICTEST.hash()
    assert obs["image_sha256"] == hashlib.sha256(arena["image"]).hexdigest()
    kinds = {s["kind"] for s in obs["observed"]["signals"]}
    assert {"path-absent", "network-unreachable"} <= kinds and obs["observed"]["method"] == "stderr-pattern"
    done = cli_tests._cli(arena["home"], "agent", "verify", "--json")
    report = json.loads(done.stdout)
    assert done.returncode == 0 and report["verified"] is True and report["runs"][0]["observations"] == 1


@needs_bwrap
@needs_socat
@needs_nesting
def test_the_rewrite_cannot_be_walked_around_a_forged_observation_is_refused_and_a_clean_call_records_none(arena):
    sess = "nest2"
    steps = _launch(arena, [{"name": "ls", "input": _bash(arena, "ls src", sess)}], arena["credential"])
    rc, stdout, stderr = steps[0]["ran"]
    assert rc == 0 and "app.py" in stdout
    home = cli_tests._agent_dir(arena["home"])
    run = run_module.RunStore(home / commands.RUNS_DIR).get(sess)
    assert run.observations() == []                                      # nothing was refused, nothing is recorded
    # a claim about another receipt or another profile is refused by the decider's binding, and is not recorded
    from prismpath.agent import observe
    image_sha = hashlib.sha256(arena["image"]).hexdigest()
    for receipt, profile_sha in ((7, STRICTEST.hash()), (0, "0" * 64)):
        body = {"hook_event_name": observe.EVENT, "session_id": sess, "receipt": receipt, "image_sha256": image_sha,
                "profile_sha256": profile_sha, "returncode": 1, "timed_out": False, "stderr": "x: Permission denied"}
        from prismpath.agent.sandbox_hook import Nested
        answer = commands.hook(json.dumps(body).encode(), {**os.environ, "HOME": str(arena["home"])},
                               nested=Nested("/usr/bin/python3", "/x", "/y"))
        assert answer["recorded"] is False and "not recorded" in answer["systemMessage"]
    assert run.observations() == []
    # without a nested decider the stdin hook does not take observation requests at all
    answer = commands.hook(json.dumps(body).encode(), {**os.environ, "HOME": str(arena["home"])})
    assert answer["hookSpecificOutput"]["permissionDecision"] == "deny"


@needs_bwrap
@needs_socat
def test_where_nesting_is_unavailable_every_shell_command_is_denied_with_cause_129_and_the_run_verifies(arena, monkeypatch):
    sess = "nest3"
    off = sandbox_hook.Nested(launcher.HOOK_PYTHON, launcher.RUNNER_IN, launcher.DECIDER_SOCKET_IN, False,
                              "user namespaces are off")
    monkeypatch.setattr(launcher, "probe_nested", lambda outer, workspace: off)
    steps = _launch(arena, [
        {"name": "ls", "input": _bash(arena, "ls src", sess)},
        {"name": "ask", "input": _bash(arena, "ls | wc -l", sess)},
        {"name": "read", "input": _file(arena, "Read", arena["ws"] + "/README.md", sess)},
        {"name": "end", "input": {"session_id": sess, "hook_event_name": "SessionEnd"}},
    ], arena["credential"])
    for step in steps[:2]:
        answer = _answer(step)
        assert answer["permissionDecision"] == "deny" and "updatedInput" not in answer, answer
        assert f"cause {SANDBOX_CODE} agent:sandbox-unavailable" in answer["permissionDecisionReason"]
        assert "user namespaces are off" in answer["permissionDecisionReason"] and "ran" not in step
    assert _answer(steps[2])["permissionDecision"] == "allow"            # only shell commands need the nested layer
    home = cli_tests._agent_dir(arena["home"])
    assert len(run_module.RunStore(home / commands.RUNS_DIR).get(sess)._entries()) == 1    # the refusals wrote no receipt
    done = cli_tests._cli(arena["home"], "agent", "verify", "--json")
    assert done.returncode == 0 and json.loads(done.stdout)["verified"] is True


@needs_bwrap
@needs_socat
@needs_nesting
def test_the_real_probe_finds_nesting_available_here_and_a_broken_runner_makes_it_unavailable(arena, monkeypatch):
    seen = {}
    real = launcher.probe_nested

    def spy(outer, workspace):
        seen["nested"] = real(outer, workspace)
        return seen["nested"]
    monkeypatch.setattr(launcher, "probe_nested", spy)
    _launch(arena, [{"name": "ls", "input": _bash(arena, "ls src", "nest4")}], arena["credential"])
    assert seen["nested"].available is True and seen["nested"].reason == ""
    monkeypatch.setattr(launcher, "RUNNER_IN", "/opt/pp/prismpath/agent/does_not_exist.py")
    seen.clear()
    _launch(arena, [{"name": "ls", "input": _bash(arena, "ls src", "nest5")}], arena["credential"])
    assert seen["nested"].available is False and "does_not_exist" in seen["nested"].reason


def test_a_profile_that_shows_the_host_is_refused_nested_because_the_view_would_include_the_credential(arena, monkeypatch):
    from prismpath.agent import profile as profile_module
    nested = sandbox_hook.Nested("/usr/bin/python3", "/x", "/y")
    wide = profile_module.Profile(ro_mounts=("/",))
    monkeypatch.setattr(sandbox_hook, "profile_for", lambda home, image: wide)
    with pytest.raises(sandbox_hook.SandboxRefused, match="model credential"):
        sandbox_hook.sandbox_profile_for_call(_bash(arena, "ls", "x"), Path(arena["home"]), b"", nested)
    assert sandbox_hook.sandbox_profile_for_call(_bash(arena, "ls", "x"), Path(arena["home"]), b"") is wide    # not nested: as before


# ----------------------------------------------------------------------------------- the section 4 table
@needs_bwrap
@needs_socat
def test_the_disagreement_table_the_stricter_layer_wins_and_the_known_gap_is_asserted(arena):
    """Each row of agent-sandbox-plan section 4, run under the launcher with the stand-in playing Claude Code."""
    sess = "table"
    ws, ssh = arena["ws"], arena["ssh"]
    steps = _launch(arena, [
        # row 1: hook deny, the sandbox is not reached (a write outside the workspace; and a shell child outside)
        {"name": "deny-write", "input": _file(arena, "Write", arena["decoy"] + "/sentinel.txt", sess, content="x")},
        {"name": "deny-bash", "input": _bash(arena, "rm " + arena["decoy"] + "/sentinel.txt", sess), "raw": False},
        # the agent's own Read tool asks for ~/.ssh/config: the hook denies it, and with no hook the mounts do
        {"name": "read-ssh-tilde", "input": _file(arena, "Read", "~/.ssh/config", sess), "direct_read": "/home/agent/.ssh/config"},
        {"name": "read-ssh", "input": _file(arena, "Read", ssh, sess), "direct_read": ssh},
        # the agent's own Read tool asks for the staged credential: the hook denies it, and with no hook nothing does
        {"name": "read-credential", "input": _file(arena, "Read", CREDENTIAL_IN, sess), "direct_read": CREDENTIAL_IN},
        # row 2: hook ask (the person's no or yes is Claude Code's own record); the answer carries the rewrite
        {"name": "ask", "input": _bash(arena, "ls | wc -l", sess)},
        # row 3: allow and the sandbox allows
        {"name": "allow-allow", "input": _bash(arena, "ls src", sess)},
        {"name": "read-ok", "input": _file(arena, "Read", ws + "/README.md", sess), "direct_read": ws + "/README.md"},
        # row 4: allow and the sandbox blocks (observed; asserted in the nested test too)
        {"name": "allow-blocked", "input": _bash(arena, "python3 tool.py", sess)},
        {"name": "end", "input": {"session_id": sess, "hook_event_name": "SessionEnd"}},
    ], arena["credential"])
    by = {s["name"]: s for s in steps}
    # row 1: the call never runs and the refusal is the receipt
    for name in ("deny-write", "deny-bash"):
        answer = _answer(by[name])
        assert answer["permissionDecision"] == "deny" and "ran" not in by[name], name
        assert "Receipt" in answer["permissionDecisionReason"], name
    assert os.path.exists(arena["decoy"] + "/sentinel.txt")
    # the Read of ~/.ssh/config: the hook does not allow it (the `~` spelling is a question for the person, a path
    # outside the workspace is a refusal), and under the outer sandbox the agent's home is a tmpfs with no .ssh
    assert _answer(by["read-ssh-tilde"])["permissionDecision"] in ("ask", "deny")
    assert by["read-ssh-tilde"]["direct_read"] == "fail: FileNotFoundError"
    assert _answer(by["read-ssh"])["permissionDecision"] == "deny"
    assert by["read-ssh"]["direct_read"] == "fail: FileNotFoundError"
    # the Read of the staged credential: the hook denies it. The outer sandbox alone cannot: THE KNOWN GAP
    assert _answer(by["read-credential"])["permissionDecision"] == "deny"
    gap = by["read-credential"]["direct_read"] == f"read: {CREDENTIAL_TEXT}"
    assert gap is KNOWN_GAP_CREDENTIAL_READ, (
        "the outer sandbox no longer lets the agent's own file tool read the staged credential: the known gap is "
        "closed, so flip KNOWN_GAP_CREDENTIAL_READ and update section 4 of docs/design/agent-sandbox-plan.md")
    if not NESTING:
        # a host that forbids the nested sandbox: every shell row is refused with cause 129, never run under the outer
        # profile alone, and the run still verifies; the file tool rows above hold either way
        for name in ("ask", "allow-allow", "allow-blocked"):
            out = _answer(by[name])
            assert out["permissionDecision"] == "deny" and "129" in out["permissionDecisionReason"], name
            assert "ran" not in by[name], name
        done = cli_tests._cli(arena["home"], "agent", "verify", "--json")
        assert done.returncode == 0 and json.loads(done.stdout)["verified"] is True
        return
    # row 2: ask carries the rewrite, so an approval still runs nested
    ask = _answer(by["ask"])
    assert ask["permissionDecision"] == "ask" and ask["updatedInput"]["command"].startswith(
        f"{launcher.HOOK_PYTHON} -I {launcher.RUNNER_IN} ") and "ran" not in by["ask"]
    # row 3: runs, a receipt, nothing observed
    assert _answer(by["allow-allow"])["permissionDecision"] == "allow" and by["allow-allow"]["ran"][0] == 0
    assert by["read-ok"]["direct_read"].startswith("read: # demo")
    # row 4: runs, and every refusal is an observation of that receipt
    assert json.loads(by["allow-blocked"]["ran"][1])["credential"] is None
    run = run_module.RunStore(cli_tests._agent_dir(arena["home"]) / commands.RUNS_DIR).get(sess)
    receipts = run._entries()
    observed = run.observations()
    assert len(observed) == 1
    blocked = [i for i, e in enumerate(receipts) if e.get("sandbox")]
    assert len(blocked) == 3 and observed[0]["receipt"] == blocked[-1]      # ask, ls and the blocked call carry the profile hash
    # row 5: the rewrite never gives a wider view than the oracle's profile for this image
    oracle = compile_profile(arena["image"])
    for name in ("ask", "allow-allow", "allow-blocked"):
        text = _answer(by[name])["updatedInput"]["command"]
        import shlex
        parts = shlex.split(text)
        assert json.loads(parts[parts.index("--profile") + 1]) == oracle.to_object(), name
    assert tuple(oracle.ro_mounts) == STRICTEST.ro_mounts and not oracle.network
    done = cli_tests._cli(arena["home"], "agent", "verify", "--json")
    report = json.loads(done.stdout)
    assert done.returncode == 0 and report["verified"] is True and report["runs"][0]["observations"] == 1
