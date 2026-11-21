# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The Landlock backend of the per call sandbox (prismpath/agent/landlock.py, agent-sandbox-plan sections 4 to 6).

The claim under test is that the choice of backend never widens anything: bubblewrap and Landlock deny the same
accesses from the adversary cases of WP5 and WP8 (a decoy outside the workspace, a write outside, the fake model
credential, a connect), and where the host forbids a sandbox inside a sandbox the launcher runs the call under Landlock
and the same cases are stopped there, recorded with the backend that ran.

Landlock tests skip where the kernel has no Landlock, unless PRISMPATH_REQUIRE_LANDLOCK=1, which CI sets: then a
host without it fails the tests instead (the workflow also fails the job if any of them is reported skipped).
"""
import json
import os
import socket
import threading
from pathlib import Path

import pytest

from prismpath.agent import landlock, sandbox_exec
from prismpath.agent.profile import STRICTEST, Profile
from prismpath.agent.sandbox_exec import SandboxUnavailable

REQUIRE = os.environ.get("PRISMPATH_REQUIRE_LANDLOCK") == "1"
ABI = landlock.abi_version()
needs_landlock = pytest.mark.skipif(ABI < 1 and not REQUIRE, reason="this kernel has no Landlock")
needs_abi4 = pytest.mark.skipif(ABI < 4, reason="Landlock ABI 4 (TCP rules) needs Linux 6.7")


def _bwrap_ok() -> bool:
    try:
        sandbox_exec.run_sandboxed(["/usr/bin/true"], os.getcwd())
        return True
    except SandboxUnavailable:
        return False


needs_bwrap_here = pytest.mark.skipif(not _bwrap_ok(), reason="bwrap cannot start here")

# what every adversary case must come to, whatever backend ran it
ALL_DENIED = {"read": None, "write": False, "credential": None, "connect": False, "unix": False}

ADVERSARY = r'''
import json, os, socket, sys
out = {}
def attempt(name, fn):
    try:
        out[name] = fn()
    except OSError as exc:
        out[name] = None if name in ("read", "credential") else False
        sys.stderr.write("%%s: %%s\n" %% (name, exc))
attempt("read", lambda: open(%(decoy)r).read().strip())
attempt("credential", lambda: open(%(credential)r).read().strip())
def write():
    open(%(written)r, "w").write("x")
    return True
attempt("write", write)
def tcp():
    socket.create_connection(("127.0.0.1", %(port)d), timeout=3).close()
    return True
attempt("connect", tcp)
def unix():
    s = socket.socket(socket.AF_UNIX); s.settimeout(3); s.connect(%(sock)r); s.close()
    return True
attempt("unix", unix)
inside = {}
try:
    open("made.txt", "w").write("ok"); inside["write"] = True
except OSError:
    inside["write"] = False
try:
    inside["read"] = open("made.txt").read()
except OSError:
    inside["read"] = None
out["inside"] = inside
print(json.dumps(out))
'''


@pytest.fixture()
def arena():
    """A workspace, and outside it (all under /var/tmp, which a sandbox can see) a decoy, a fake credential, a path to
    write, a TCP listener on loopback and a unix socket listener. Nothing here is a real secret."""
    import shutil
    import tempfile
    root = Path(tempfile.mkdtemp(prefix="pp-landlock-", dir="/var/tmp"))
    ws = root / "ws"
    ws.mkdir()
    (root / "decoy.txt").write_text("DECOY")
    (root / "credential.json").write_text("FAKE-CREDENTIAL-NOT-A-KEY")
    sock_path = str(root / "decider.sock")
    tcp = socket.socket()
    tcp.bind(("127.0.0.1", 0))
    tcp.listen(8)
    unx = socket.socket(socket.AF_UNIX)
    unx.bind(sock_path)
    unx.listen(8)
    stop = threading.Event()

    def accept(server):
        server.settimeout(0.2)
        while not stop.is_set():
            try:
                server.accept()[0].close()
            except OSError:
                pass
    threads = [threading.Thread(target=accept, args=(s,), daemon=True) for s in (tcp, unx)]
    for t in threads:
        t.start()
    script = ADVERSARY % {"decoy": str(root / "decoy.txt"), "credential": str(root / "credential.json"),
                          "written": str(root / "written.txt"), "port": tcp.getsockname()[1], "sock": sock_path}
    (ws / "tool.py").write_text(script)
    try:
        yield {"root": root, "ws": ws, "port": tcp.getsockname()[1]}
    finally:
        stop.set()
        for t in threads:
            t.join(2)
        tcp.close()
        unx.close()
        shutil.rmtree(root, ignore_errors=True)


def _adversary(arena, backend, **switches):
    ws = arena["ws"]
    (ws / "made.txt").unlink(missing_ok=True)
    if backend == "landlock":
        done = sandbox_exec.run_landlock("python3 tool.py", ws, Profile(timeout_s=60), stdin=b"", **switches)
    else:
        done = sandbox_exec.run_backend("bwrap", "python3 tool.py", ws, Profile(timeout_s=60), stdin=b"", mount=str(ws))
    assert done.backend == backend
    assert done.returncode == 0, done.stderr.decode()
    result = json.loads(done.stdout)
    # a write outside is judged by what reached the host: bubblewrap lets it land on a throwaway tmpfs it made for the
    # workspace's parent directories, Landlock refuses it, and neither changes the host
    written = arena["root"] / "written.txt"
    result["write"] = written.exists()
    written.unlink(missing_ok=True)
    return result, done


def _denied(result):
    return {k: v for k, v in result.items() if k != "inside"}


# ------------------------------------------------------------------------------------------ the two backends agree
@needs_landlock
def test_landlock_stops_every_adversary_case_and_still_works_inside_the_workspace(arena):
    result, done = _adversary(arena, "landlock")
    assert _denied(result) == ALL_DENIED, (result, done.stderr)
    assert result["inside"] == {"write": True, "read": "ok"}
    assert not (arena["root"] / "written.txt").exists()


@needs_bwrap_here
def test_bwrap_stops_every_adversary_case_and_still_works_inside_the_workspace(arena):
    result, done = _adversary(arena, "bwrap")
    assert _denied(result) == ALL_DENIED, (result, done.stderr)
    assert result["inside"] == {"write": True, "read": "ok"}
    assert not (arena["root"] / "written.txt").exists()


@needs_landlock
@needs_bwrap_here
def test_both_backends_deny_the_same_set_of_accesses(arena):
    """The backend must not widen anything: for each adversary case, what one denies the other denies, and what the
    workspace allows is the same."""
    landlocked, _ = _adversary(arena, "landlock")
    bwrapped, _ = _adversary(arena, "bwrap")
    assert landlocked == bwrapped == {**ALL_DENIED, "inside": {"write": True, "read": "ok"}}


@needs_landlock
def test_a_decoy_in_the_workspace_is_readable_and_one_beside_it_is_not(arena):
    (arena["ws"] / "inside.txt").write_text("in")
    done = sandbox_exec.run_landlock(f"cat inside.txt; cat {arena['root']}/decoy.txt", arena["ws"], stdin=b"")
    assert done.stdout == b"in" and b"Permission denied" in done.stderr and done.returncode != 0


# ----------------------------------------------------------------------------------------------- each layer alone
@needs_landlock
def test_with_every_network_layer_off_the_listener_is_reachable_so_the_other_tests_mean_something(arena):
    result, _ = _adversary(arena, "landlock", net_rules=False, seccomp=False)
    assert result["connect"] is True and result["unix"] is True      # the control: only the file rules were left
    assert result["read"] is None and result["write"] is False and result["credential"] is None


@needs_landlock
def test_the_seccomp_filter_alone_stops_a_tcp_connect_and_a_unix_socket_connect(arena):
    """The path taken before Landlock ABI 4: no socket, so nothing to connect with."""
    result, _ = _adversary(arena, "landlock", net_rules=False)
    assert result["connect"] is False and result["unix"] is False


@needs_abi4
def test_landlocks_own_tcp_rules_alone_stop_a_tcp_connect(arena):
    result, done = _adversary(arena, "landlock", seccomp=False)
    assert result["connect"] is False and b"connect" in done.stderr
    assert result["unix"] is True       # Landlock does not handle a unix socket by path before ABI 9 (seccomp does)
    bind = sandbox_exec.run_landlock(
        "python3 -c \"import socket; socket.socket().bind(('127.0.0.1', 0))\"", arena["ws"], stdin=b"", seccomp=False)
    assert bind.returncode != 0 and b"PermissionError" in bind.stderr


@needs_landlock
def test_a_process_cannot_trace_another_or_open_an_io_uring(arena):
    ws = arena["ws"]
    code = ("import ctypes; l = ctypes.CDLL(None, use_errno=True); "
            "print(l.syscall(%d, 0, 0, 0, 0), ctypes.get_errno())")
    for number in (landlock._DENIED["ptrace"][1 if landlock._machine() == "aarch64" else 0],
                   landlock._DENIED["io_uring_setup"][0]):
        done = sandbox_exec.run_landlock("python3 -c '%s'" % (code % number), ws, stdin=b"")
        assert done.stdout.split() == [b"-1", b"1"], (number, done.stdout, done.stderr)    # EPERM


# -------------------------------------------------------------------------------------------- how the runner behaves
@needs_landlock
def test_the_command_sees_no_proc_of_another_process_no_tmp_and_a_clean_environment(arena):
    done = sandbox_exec.run_landlock("ls /proc/1 2>&1; ls /tmp 2>&1; ls /etc 2>&1; env | sort", arena["ws"], stdin=b"")
    text = done.stdout.decode()
    assert text.count("Permission denied") == 3
    env = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
    assert {"PATH", "HOME", "LANG", "TMPDIR", "PWD"} >= set(env) - {"GIT_CONFIG_NOSYSTEM", "GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL",
                                                                    "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL", "_", "SHLVL", "OLDPWD"}
    assert env["HOME"] == env["TMPDIR"] and "PROXY" not in text.upper()


@needs_landlock
def test_the_scratch_directory_is_private_to_the_call_and_removed_afterwards(arena):
    done = sandbox_exec.run_landlock("echo z > $TMPDIR/f && cat $TMPDIR/f && echo $TMPDIR", arena["ws"], stdin=b"")
    lines = done.stdout.decode().split()
    assert lines[0] == "z" and not os.path.exists(lines[1])


@needs_landlock
def test_a_time_limit_ends_the_command_and_what_it_left_running(arena):
    started = arena["ws"] / "pid.txt"
    done = sandbox_exec.run_landlock("sleep 300 & echo $! > pid.txt; sleep 300", arena["ws"], Profile(timeout_s=1), stdin=b"")
    assert done.timed_out
    pid = int(started.read_text())
    import time
    for _ in range(100):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.05)
    else:
        pytest.fail("a background process outlived the call")


@needs_landlock
def test_a_background_process_does_not_outlive_a_command_that_returns(arena):
    done = sandbox_exec.run_landlock("sleep 300 & echo $! > pid.txt", arena["ws"], Profile(timeout_s=20), stdin=b"")
    assert done.returncode == 0 and not done.timed_out
    pid = int((arena["ws"] / "pid.txt").read_text())
    import time
    for _ in range(100):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.05)
    pytest.fail("a background process outlived the call")


@needs_landlock
def test_the_process_limit_stops_a_fork_past_it(arena):
    done = sandbox_exec.run_landlock("for i in $(seq 40); do sleep 5 & done; wait", arena["ws"],
                                     Profile(max_processes=8, timeout_s=30), stdin=b"")
    assert b"retry" in done.stderr or b"Resource temporarily unavailable" in done.stderr or b"Cannot fork" in done.stderr


@needs_landlock
def test_exit_status_and_standard_error_come_back(arena):
    done = sandbox_exec.run_landlock("echo out; echo err >&2; exit 7", arena["ws"], stdin=b"")
    assert (done.returncode, done.stdout, done.stderr, done.backend) == (7, b"out\n", b"err\n", "landlock")


@needs_landlock
def test_a_profile_with_a_network_is_refused_and_nothing_runs(arena):
    for profile in (Profile(network=True), Profile(net="proxy_model")):
        with pytest.raises(SandboxUnavailable, match="no network"):
            sandbox_exec.run_landlock("echo ran > ran.txt", arena["ws"], profile, stdin=b"")
    assert not (arena["ws"] / "ran.txt").exists()


@needs_landlock
def test_a_writable_toolchain_directory_is_refused_because_landlock_cannot_make_part_of_a_directory_read_only(arena):
    (arena["ws"] / ".toolchain").mkdir()
    with pytest.raises(SandboxUnavailable, match=r"\.toolchain"):
        sandbox_exec.run_landlock("echo ran > ran.txt", arena["ws"], stdin=b"")
    assert not (arena["ws"] / "ran.txt").exists()


def test_a_named_backend_that_is_not_there_is_never_replaced_by_another(arena, monkeypatch):
    monkeypatch.setattr(landlock, "abi_version", lambda: 0)
    with pytest.raises(SandboxUnavailable):
        sandbox_exec.run_backend("landlock", "echo ran > ran.txt", arena["ws"], Profile(), stdin=b"")
    monkeypatch.setattr(sandbox_exec, "BWRAP", "/nonexistent/bwrap")
    with pytest.raises(SandboxUnavailable):
        sandbox_exec.run_backend("auto", "echo ran > ran.txt", arena["ws"], Profile(), stdin=b"")       # neither backend
    with pytest.raises(SandboxUnavailable):
        sandbox_exec.run_backend("bwrap", "echo ran > ran.txt", arena["ws"], Profile(), stdin=b"")
    assert not (arena["ws"] / "ran.txt").exists()


@needs_landlock
def test_auto_falls_back_to_landlock_only_when_bwrap_could_not_start(arena, monkeypatch):
    monkeypatch.setattr(sandbox_exec, "BWRAP", "/nonexistent/bwrap")
    done = sandbox_exec.run_backend("auto", "echo hi", arena["ws"], Profile(), stdin=b"")
    assert done.backend == "landlock" and done.stdout == b"hi\n"


# ------------------------------------------------------------------------------------------- the seccomp program
def _bpf(program: bytes, arch: int, nr: int) -> int:
    """A tiny interpreter for the filter's four opcodes, to check its logic on both machines from either one."""
    import struct
    insns = [struct.unpack("=HBBI", program[i:i + 8]) for i in range(0, len(program), 8)]
    acc, pc = 0, 0
    while True:
        op, jt, jf, k = insns[pc]
        if op == 0x20:
            acc = arch if k == 4 else nr
        elif op == 0x15:
            pc += jt if acc == k else jf
        elif op == 0x35:
            pc += jt if acc >= k else jf
        elif op == 0x06:
            return k
        else:
            raise AssertionError(op)
        pc += 1


@pytest.mark.parametrize("machine,arch", [("x86_64", 0xC000003E), ("aarch64", 0xC00000B7)])
def test_the_seccomp_program_refuses_what_it_names_allows_the_rest_and_kills_a_foreign_architecture(machine, arch):
    program = landlock.seccomp_program(machine)
    column = 0 if machine == "x86_64" else 1
    eperm = 0x00050000 | 1
    for name, numbers in landlock._DENIED.items():
        assert _bpf(program, arch, numbers[column]) == eperm, name
    for allowed in (0, 1, 2, 3, 56, 57, 59, 63, 93, 221):       # whatever is not named, e.g. read, write, close
        if allowed not in {n[column] for n in landlock._DENIED.values()}:
            assert _bpf(program, arch, allowed) == 0x7FFF0000
    other = 0xC00000B7 if machine == "x86_64" else 0xC000003E
    assert _bpf(program, other, 0) == 0x80000000
    if machine == "x86_64":
        assert _bpf(program, arch, 0x40000000 + 41) == 0x80000000       # the x32 spelling of socket


def test_the_syscall_numbers_match_the_kernel_headers_where_the_headers_are_installed():
    import re
    for column, path in ((1, "/usr/include/asm-generic/unistd.h"), (0, "/usr/include/x86_64-linux-gnu/asm/unistd_64.h")):
        if not os.path.exists(path):
            continue
        table = dict(re.findall(r"#define __NR_(\w+)\s+(\d+)\s*$", open(path).read(), re.M))
        if column == 1 and "socket" in table and table["socket"] != "198":
            continue
        for name, numbers in landlock._DENIED.items():
            if name in table:
                assert int(table[name]) == numbers[column], (path, name)


# ------------------------------------------------------------------------------------------ under the launcher
pytest.importorskip("cryptography")
pytest.importorskip("fcntl")

from prismpath.agent import commands, launcher, run as run_module  # noqa: E402
from prismpath.tests import test_agent_cli as cli_tests  # noqa: E402
from prismpath.tests.test_agent_decider import world, _no_real_config_dir  # noqa: E402,F401
from prismpath.tests.test_agent_launcher import needs_socat  # noqa: E402
from prismpath.tests.test_agent_nested import (  # noqa: E402,F401
    CREDENTIAL_TEXT, NESTING, SANDBOX_CODE, _answer, _bash, _launch, arena as nested_arena, needs_nesting)

NESTED_ALL_DENIED = {"credential": None, "write": False, "relay": False, "outside": False}


def _nested_run(arena, session, backends, monkeypatch):
    """One `python3 tool.py` under the launcher with only `backends` allowed to be probed, and what came of it."""
    monkeypatch.setattr(launcher, "BACKENDS", backends)
    seen = {}
    real = launcher.probe_nested

    def spy(outer, workspace):
        seen["nested"] = real(outer, workspace)
        return seen["nested"]
    monkeypatch.setattr(launcher, "probe_nested", spy)
    steps = _launch(arena, [
        {"name": "tool", "input": _bash(arena, "python3 tool.py", session), "raw": True},
        {"name": "end", "input": {"session_id": session, "hook_event_name": "SessionEnd"}},
    ], arena["credential"])
    return steps[0], seen["nested"]


def _check_nested(arena, step, nested, session, backend):
    assert nested.available is True and nested.backend == backend and nested.reason == ""
    answer = _answer(step)
    assert answer["permissionDecision"] == "allow"
    assert f"--backend {backend} " in answer["updatedInput"]["command"]
    raw = json.loads(step["raw"][1])        # the outer sandbox alone leaks all of it
    assert raw["credential"] == CREDENTIAL_TEXT and raw["write"] is True and raw["relay"] is True
    rc, stdout, stderr = step["ran"]
    assert json.loads(stdout) == NESTED_ALL_DENIED, (stdout, stderr)
    assert "PrismPath did not run" not in stderr
    home = cli_tests._agent_dir(arena["home"])
    run = run_module.RunStore(home / commands.RUNS_DIR).get(session)
    entries = run._entries()
    assert entries[0]["sandbox"] == {"profile_sha256": STRICTEST.hash(), "backend": backend}      # the receipt says which
    seen = run.observations()
    assert len(seen) == 1 and seen[0]["profile_sha256"] == STRICTEST.hash()
    assert seen[0]["observed"]["backend"] == backend                                              # and so does the observation
    done = cli_tests._cli(arena["home"], "agent", "verify", "--json")
    assert done.returncode == 0 and json.loads(done.stdout)["verified"] is True
    return seen[0]


@needs_landlock
@needs_socat
def test_where_nesting_is_forced_off_the_call_runs_under_landlock_and_every_adversary_case_is_stopped(nested_arena, monkeypatch):
    step, nested = _nested_run(nested_arena, "ll1", ("landlock",), monkeypatch)
    obs = _check_nested(nested_arena, step, nested, "ll1", "landlock")
    kinds = {s["kind"] for s in obs["observed"]["signals"]}
    assert "access-denied" in kinds


@needs_bwrap_here
@needs_socat
@needs_nesting
def test_where_nesting_works_the_call_runs_under_bubblewrap_and_every_adversary_case_is_stopped(nested_arena, monkeypatch):
    step, nested = _nested_run(nested_arena, "bw1", ("bwrap",), monkeypatch)
    _check_nested(nested_arena, step, nested, "bw1", "bwrap")


@needs_landlock
@needs_bwrap_here
@needs_socat
@needs_nesting
def test_the_default_order_prefers_bubblewrap_and_the_two_backends_stop_the_same_calls(nested_arena, monkeypatch):
    first, nested = _nested_run(nested_arena, "pref", launcher.sandbox_exec.BACKENDS, monkeypatch)
    assert nested.backend == "bwrap"
    second, _ = _nested_run(nested_arena, "pref2", ("landlock",), monkeypatch)
    assert json.loads(first["ran"][1]) == json.loads(second["ran"][1]) == NESTED_ALL_DENIED


@needs_socat
def test_with_no_working_backend_every_shell_command_is_denied_with_cause_129(nested_arena, monkeypatch):
    monkeypatch.setattr(launcher, "BACKENDS", ())
    steps = _launch(nested_arena, [{"name": "ls", "input": _bash(nested_arena, "ls src", "none1")}], nested_arena["credential"])
    answer = _answer(steps[0])
    assert answer["permissionDecision"] == "deny" and "updatedInput" not in answer and "ran" not in steps[0]
    assert f"cause {SANDBOX_CODE} agent:sandbox-unavailable" in answer["permissionDecisionReason"]


def test_an_observation_that_names_another_backend_than_the_receipt_is_refused(tmp_path):
    from prismpath.agent.run import Run, RunError
    entry = {"receipt": {"image_sha256": "a" * 64}, "sandbox": {"profile_sha256": "b" * 64, "backend": "landlock"}}
    Run._check_binding(entry, "a" * 64, "b" * 64, {"backend": "landlock"})
    Run._check_binding(entry, "a" * 64, "b" * 64, {})
    with pytest.raises(RunError, match="other than the one"):
        Run._check_binding(entry, "a" * 64, "b" * 64, {"backend": "bwrap"})
    old = {"receipt": {"image_sha256": "a" * 64}, "sandbox": {"profile_sha256": "b" * 64}}       # written before backends
    Run._check_binding(old, "a" * 64, "b" * 64, {"backend": "bwrap"})
    with pytest.raises(RunError):
        Run._check_binding(old, "a" * 64, "b" * 64, {"backend": "landlock"})
