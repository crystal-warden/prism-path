# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The bubblewrap runner: what a command can reach is set by the profile, and it fails closed."""
import os
import socket

import pytest

from prismpath.agent import sandbox_exec
from prismpath.agent.sandbox_exec import SandboxProfile, SandboxUnavailable, run_sandboxed


def _bwrap_works() -> str:
    """'' when bwrap runs here, else the reason it cannot."""
    if not os.access(sandbox_exec.BWRAP, os.X_OK):
        return f"no {sandbox_exec.BWRAP}"
    try:
        run_sandboxed(["/usr/bin/true"], os.getcwd())
    except SandboxUnavailable as exc:
        return f"bwrap cannot start here (user namespaces unavailable?): {exc}"
    return ""


_WHY = _bwrap_works()
needs_bwrap = pytest.mark.skipif(bool(_WHY), reason=_WHY or "bwrap works")


@needs_bwrap
def test_echo_runs_and_its_output_comes_back(tmp_path):
    done = run_sandboxed(["echo", "ok"], tmp_path)
    assert (done.returncode, done.stdout.strip()) == (0, b"ok")


@needs_bwrap
def test_a_host_file_outside_the_system_prefix_is_not_there(tmp_path):
    # /etc is not in the profile's read only paths (only /usr is), so the host's /etc/hostname is not visible.
    assert os.path.exists("/etc/hostname"), "pick another host-only file on this machine"
    done = run_sandboxed(["cat", "/etc/hostname"], tmp_path)
    assert done.returncode != 0 and b"No such file" in done.stderr


@needs_bwrap
def test_a_write_outside_the_workspace_fails_and_one_inside_lands(tmp_path):
    outside = tmp_path.parent / "pp-sandbox-outside-marker"
    outside.unlink(missing_ok=True)
    assert run_sandboxed(["touch", str(outside)], tmp_path).returncode != 0
    assert not outside.exists()
    assert run_sandboxed(["touch", "/usr/pp-marker"], tmp_path).returncode != 0   # system prefix is read only
    assert run_sandboxed(["sh", "-c", "echo hi > made.txt"], tmp_path).returncode == 0
    assert (tmp_path / "made.txt").read_text() == "hi\n"


@needs_bwrap
def test_with_the_network_off_a_connect_fails(tmp_path):
    code = "import socket; socket.create_connection(('1.1.1.1', 53), timeout=3)"
    done = run_sandboxed(["python3", "-c", code], tmp_path, SandboxProfile(timeout_s=20))
    assert done.returncode != 0 and not done.timed_out


@needs_bwrap
def test_network_on_shares_the_host_network_namespace(tmp_path):
    # No outside traffic: a loopback listener on the host is reachable only when the namespace is shared.
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        code = f"import socket; socket.create_connection(('127.0.0.1', {port}), timeout=3)"
        assert run_sandboxed(["python3", "-c", code], tmp_path, SandboxProfile(network=True)).returncode == 0
        assert run_sandboxed(["python3", "-c", code], tmp_path, SandboxProfile(network=False)).returncode != 0


@needs_bwrap
def test_the_time_limit_stops_a_long_command(tmp_path):
    done = run_sandboxed(["sleep", "30"], tmp_path, SandboxProfile(timeout_s=1))
    assert done.timed_out


def test_missing_bwrap_is_an_error_and_nothing_runs(tmp_path, monkeypatch):
    monkeypatch.setattr(sandbox_exec, "BWRAP", str(tmp_path / "no-such-bwrap"))
    marker = tmp_path / "ran"
    with pytest.raises(SandboxUnavailable, match="missing"):
        run_sandboxed(["touch", str(marker)], tmp_path)
    assert not marker.exists()


def test_a_bwrap_that_cannot_start_the_sandbox_is_an_error(tmp_path, monkeypatch):
    fake = tmp_path / "bwrap"
    fake.write_text("#!/bin/sh\necho 'bwrap: No permissions to create new namespace' >&2\nexit 1\n")
    fake.chmod(0o755)
    monkeypatch.setattr(sandbox_exec, "BWRAP", str(fake))
    with pytest.raises(SandboxUnavailable, match="did not start"):
        run_sandboxed(["echo", "ok"], tmp_path)


def test_the_argv_has_no_network_share_by_default(tmp_path):
    assert "--share-net" not in sandbox_exec.bwrap_argv(tmp_path, SandboxProfile(), ["true"])
    assert "--share-net" in sandbox_exec.bwrap_argv(tmp_path, SandboxProfile(network=True), ["true"])
