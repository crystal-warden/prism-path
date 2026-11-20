# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The compiled sandbox profile against the oracle: the sandbox may be stricter than the policy, never looser.

A corpus of operations is defined here, apart from both the classifier and the profile compile, the way
`net_cert.py` defines its canonical reading apart from the C. Each operation is two things written down by hand:

  * the call an agent would make for it (a classifier call: a file read, a file write, a command), and
  * the act a process performs for it, with a check of whether its effect happened (the secret was read, the file
    was written, the connection was made, the push reached its remote).

Each operation is then taken three ways:

  oracle    the call is read into a reading with the classifier, against a world that has the workspace and an
            allowed remote `origin`, and decided by the Lean oracle (`formal/.lake/build/bin/core-oracle`, the way
            `formal/diff/core_diff.py` runs it) under the default policy. Where the oracle is not built the
            reference path (`Policy.decide`, which `core_diff` holds to the oracle) decides, and the output says so.
  sandbox   the act runs under the profile `compile_profile` gives the same image, in bwrap.
  plain     the act runs with no sandbox. This is the control: every act must have its effect there, or a blocked
            act would prove nothing about the sandbox.

The test fails if the sandbox lets an act have its effect that the oracle refuses or escalates. Where the oracle
allows an operation and the sandbox stops it, the sandbox is stricter, which is the safe direction. Each such
case is printed with its reason, never hidden. The push to an allowed remote is the known one: the starters allow
it, the profile has no network, and the remote is outside the workspace.

The secrets and the remote live under /var/tmp, which the sandbox does not mount (its /tmp is a private tmpfs and
only /usr and the workspace are mounted), so a blocked act is a block by the sandbox and not by file permissions.
"""
import os
import shutil
import socket
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional

import pytest

ROOT = Path(__file__).resolve().parents[2]
if not (ROOT / "formal" / "diff" / "core_diff.py").exists():
    pytest.skip("formal/diff is not beside this package (an installed wheel)", allow_module_level=True)
sys.path.insert(0, str(ROOT / "formal" / "diff"))
import core_diff  # noqa: E402
from prismpath.agent import classifier, sandbox_exec  # noqa: E402
from prismpath.agent.policy import Policy, starter_path  # noqa: E402
from prismpath.agent.profile import STRICTEST, Profile, compile_profile  # noqa: E402
from prismpath.agent.sandbox_exec import SandboxUnavailable, run_sandboxed  # noqa: E402

SECRET = "pp-secret-8f3a"
REMOTE = "origin"


def _bwrap_works() -> str:
    if not sandbox_exec.available():
        return f"no {sandbox_exec.BWRAP}"
    try:
        run_sandboxed(["/usr/bin/true"], os.getcwd())
    except SandboxUnavailable as exc:
        return f"bwrap cannot start here: {exc}"
    return ""


_WHY = _bwrap_works()
pytestmark = pytest.mark.skipif(bool(_WHY), reason=_WHY or "bwrap works")


def _lan_address() -> Optional[str]:
    """The host's own non loopback address (no packet is sent: connecting a UDP socket only picks a route)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("192.0.2.1", 9))
            address = probe.getsockname()[0]
    except OSError:
        return None
    return None if address.startswith("127.") else address


@dataclass
class World:
    ws: Path            # the workspace
    outside: Path       # a directory beside it, on a path the sandbox does not mount
    home: Path          # a decoy home with a .ssh
    port: int           # a listener on the host's loopback and all its addresses
    lan: Optional[str]
    bare: Path          # the allowed remote, a bare repository outside the workspace


@pytest.fixture(scope="module")
def world():
    base = Path(tempfile.mkdtemp(prefix="pp-diff-", dir="/var/tmp"))
    ws, home, bare = base / "ws", base / "home", base / "remote.git"
    (ws).mkdir()
    (home / ".ssh").mkdir(parents=True)
    (ws / "notes.txt").write_text(SECRET + "\n")
    (base / "secret.txt").write_text(SECRET + "\n")
    (home / ".ssh" / "id_rsa").write_text(SECRET + "\n")
    os.symlink(base / "secret.txt", ws / "link_out")
    server = socket.socket()
    server.bind(("", 0))
    server.listen(16)
    git = shutil.which("git")
    if git:
        env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "GIT_CONFIG_NOSYSTEM": "1"}
        for argv in ([git, "init", "-q", "--bare", str(bare)], [git, "-C", str(ws), "init", "-q", "-b", "main"],
                     [git, "-C", str(ws), "remote", "add", REMOTE, str(bare)],
                     [git, "-C", str(ws), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "x"]):
            subprocess.run(argv, check=True, env=env, capture_output=True)
    yield World(ws, base, home, server.getsockname()[1], _lan_address(), bare)
    server.close()
    shutil.rmtree(base, ignore_errors=True)


@dataclass
class Op:
    name: str
    call: Dict
    act: Callable[[World], List[str]]           # the argv of the act
    effect: Callable[[World, subprocess.CompletedProcess], bool]   # did what the act aims at happen
    needs: Callable[[World], bool] = lambda w: True


def _py(code: str) -> List[str]:
    return ["python3", "-c", code]


def _connect(host: str, port: int) -> List[str]:
    return _py(f"import socket; socket.create_connection(({host!r}, {port}), timeout=2); print('connected')")


def _read(path):
    return lambda w: ["cat", path(w)]


def _got_secret(_w, done):
    return done.returncode == 0 and SECRET.encode() in done.stdout


def _connected(_w, done):
    return done.returncode == 0 and b"connected" in done.stdout


def _wrote(target):
    return lambda w, _done: target(w).exists() and target(w).read_text().strip() == "written"


def _write(target):
    return lambda w: ["bash", "-c", f"echo written > {target(w)}"]


def _push_reached(w, _done):
    refs = subprocess.run(["git", "-C", str(w.bare), "show-ref"], capture_output=True)
    return refs.returncode == 0 and b"refs/heads/main" in refs.stdout


CORPUS = [
    Op("read a workspace file", {"tool": "read_file", "args": {"path": "{ws}/notes.txt"}},
       _read(lambda w: w.ws / "notes.txt"), _got_secret),
    Op("write a workspace file", {"tool": "write_file", "args": {"path": "{ws}/made.txt", "content": ""}},
       _write(lambda w: w.ws / "made.txt"), _wrote(lambda w: w.ws / "made.txt")),
    Op("read /etc/passwd", {"tool": "read_file", "args": {"path": "/etc/passwd"}},
       lambda w: ["bash", "-c", "grep -q root: /etc/passwd && echo " + SECRET],
       _got_secret),
    Op("read ~/.ssh/id_rsa (a decoy home)", {"tool": "read_file", "args": {"path": "{home}/.ssh/id_rsa"}},
       _read(lambda w: w.home / ".ssh" / "id_rsa"), _got_secret),
    Op("write outside the workspace", {"tool": "write_file", "args": {"path": "{outside}/dropped.txt", "content": ""}},
       _write(lambda w: w.outside / "dropped.txt"), _wrote(lambda w: w.outside / "dropped.txt")),
    Op("read a .. path out of the workspace", {"tool": "read_file", "args": {"path": "{ws}/../secret.txt"}},
       _read(lambda w: f"{w.ws}/../secret.txt"), _got_secret),
    Op("write a .. path out of the workspace", {"tool": "write_file", "args": {"path": "{ws}/../dropped_dotdot.txt", "content": ""}},
       _write(lambda w: f"{w.ws}/../dropped_dotdot.txt"), _wrote(lambda w: w.outside / "dropped_dotdot.txt")),
    Op("read through a symlink out of the workspace", {"tool": "read_file", "args": {"path": "{ws}/link_out"}},
       _read(lambda w: w.ws / "link_out"), _got_secret),
    Op("write through a symlink out of the workspace", {"tool": "write_file", "args": {"path": "{ws}/link_out", "content": ""}},
       _write(lambda w: w.ws / "link_out"), lambda w, _d: (w.outside / "secret.txt").read_text().strip() == "written"),
    Op("connect to loopback", {"tool": "run_command", "args": {"argv": ["curl", "http://127.0.0.1:{port}/"]}},
       lambda w: _connect("127.0.0.1", w.port), _connected),
    Op("connect to a remote address", {"tool": "run_command", "args": {"argv": ["curl", "http://{lan}:{port}/"]}},
       lambda w: _connect(w.lan, w.port), _connected, needs=lambda w: bool(w.lan)),
    Op("git push to the allowed remote", {"tool": "run_command", "args": {"argv": ["git", "push", REMOTE, "HEAD"]}},
       lambda w: ["git", "push", "-q", REMOTE, "HEAD"], _push_reached, needs=lambda w: bool(shutil.which("git"))),
]

# why the sandbox is stricter than the oracle, where it is: the reason is a fact about this corpus, so a new
# stricter case with no reason here fails the test and must be explained.
REASONS = {
    "git push to the allowed remote": "the starters allow a push to a remote the owner named, but the profile has no network "
                                      "and the remote is outside the workspace, so the push cannot reach it",
}


def _fill(value, w: World):
    if isinstance(value, str):
        return value.format(ws=w.ws, outside=w.outside, home=w.home, port=w.port, lan=w.lan)
    if isinstance(value, list):
        return [_fill(v, w) for v in value]
    if isinstance(value, dict):
        return {k: _fill(v, w) for k, v in value.items()}
    return value


def _env(w: World):
    return {"PATH": "/usr/bin:/bin", "HOME": str(w.home), "GIT_CONFIG_NOSYSTEM": "1", "GIT_AUTHOR_NAME": "t",
            "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}


def _reset(w: World):
    for path in (w.ws / "made.txt", w.outside / "dropped.txt", w.outside / "dropped_dotdot.txt"):
        path.unlink(missing_ok=True)
    (w.outside / "secret.txt").write_text(SECRET + "\n")
    if shutil.which("git") and w.bare.exists():
        subprocess.run(["git", "-C", str(w.bare), "update-ref", "-d", "refs/heads/main"], capture_output=True)


def _oracle_runs(policy: Policy, readings: List[bytes]):
    """([runs], source): the oracle's decision for each reading, or the reference's when no oracle is built."""
    if core_diff.ORACLE.exists():
        out = core_diff.lean_leg([{"id": "differential", "image": policy.image, "readings": readings}])
        rows = out["differential"]["readings"]
        return [row.get("verdict") == "route" and row.get("target") == "allow" for row in rows], "Lean oracle"
    return [policy.decide(reading).runs for reading in readings], "reference path (Lean oracle not built; marked)"


def _compare(world: World, profile: Profile, ops=CORPUS):
    """One row per operation: (name, oracle allows, sandbox lets it happen, plain lets it happen, source)."""
    policy = Policy(starter_path("default").read_bytes())
    config = classifier.Config.for_workspace(world.ws, (REMOTE,))
    live = [op for op in ops if op.needs(world)]
    readings = [policy.reading_bytes(classifier.classify(_fill(op.call, world), config)) for op in live]
    oracle, source = _oracle_runs(policy, readings)
    rows = []
    for op, allowed in zip(live, oracle):
        argv = _fill(op.act(world), world)
        _reset(world)
        plain = subprocess.run(argv, capture_output=True, cwd=world.ws, env=_env(world), timeout=30)
        plain_effect = op.effect(world, plain)
        _reset(world)
        done = run_sandboxed(argv, world.ws, profile, mount=str(world.ws))
        sandbox_effect = op.effect(world, subprocess.CompletedProcess(argv, done.returncode, done.stdout, done.stderr))
        rows.append((op.name, allowed, sandbox_effect, plain_effect, source))
    _reset(world)
    return rows


def _report(rows, title):
    print(f"\n{title}: {len(rows)} operations, decided by the {rows[0][4]}")
    print(f"  {'operation':<46} {'oracle':<7} {'sandbox':<8} verdict")
    for name, allowed, sandboxed, _plain, _src in rows:
        verdict = ("agree" if allowed == sandboxed else
                   "STRICTER: " + REASONS.get(name, "(no reason recorded)") if allowed else "LOOSER than the oracle")
        print(f"  {name:<46} {'allow' if allowed else 'refuse':<7} {'allowed' if sandboxed else 'stopped':<8} {verdict}")


def test_the_corpus_is_real_unsandboxed_every_act_has_its_effect(world):
    """The control. If an act failed with no sandbox, its being stopped in the sandbox would mean nothing."""
    rows = _compare(world, STRICTEST)
    assert rows and all(plain for _n, _a, _s, plain, _src in rows), [r[0] for r in rows if not r[3]]


def test_the_sandbox_allows_nothing_the_oracle_refuses_and_every_stricter_case_is_listed(world, capsys):
    profile = compile_profile(starter_path("default").read_bytes())
    assert profile == STRICTEST
    rows = _compare(world, profile)
    with capsys.disabled():
        _report(rows, "profile differential (the compiled profile of agent_default)")
    looser = [name for name, allowed, sandboxed, _p, _s in rows if sandboxed and not allowed]
    assert not looser, f"the sandbox let these happen that the oracle refuses: {looser}"
    stricter = [name for name, allowed, sandboxed, _p, _s in rows if allowed and not sandboxed]
    assert all(name in REASONS for name in stricter), [n for n in stricter if n not in REASONS]
    assert "read a workspace file" not in stricter and "write a workspace file" not in stricter   # the workspace works
    if shutil.which("git"):
        assert "git push to the allowed remote" in stricter                                       # the known one


def test_the_comparison_would_catch_a_sandbox_that_is_too_loose(world, capsys):
    """A profile that mounts the host and shares the network lets the oracle's refusals through, and the same
    comparison reports them: the check is not satisfied by a comparison that cannot fail."""
    loose = Profile(ro_mounts=("/",), host_write=True, network=True)
    rows = _compare(world, loose)
    with capsys.disabled():
        _report(rows, "negative control (a profile with the host mounted and a network)")
    looser = {name for name, allowed, sandboxed, _p, _s in rows if sandboxed and not allowed}
    assert {"read ~/.ssh/id_rsa (a decoy home)", "write outside the workspace",
            "read through a symlink out of the workspace"} <= looser
