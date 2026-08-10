"""The code-node sandbox: the envelope is enforced (memory / timeout / network / filesystem), and
absence is loud (refuse fail-closed; override runs un-sandboxed but stamps the outcome). Behavioral
tests spawn bwrap; they skip cleanly where bwrap is unavailable."""
import os

import pytest

from prismpath import sandbox as sb
from prismpath.code_nodes import Envelope
from prismpath.tests import _sandbox_probes as probes

requires_bwrap = pytest.mark.skipif(sb.find_bwrap() is None, reason="bwrap not available")


@requires_bwrap
def test_in_envelope_runs():
    out = sb.SandboxRunner()(probes.ok, Envelope(timeout_s=10, mem_mb=256), "n", "", {})
    assert out["v"] == 1


@requires_bwrap
def test_memory_ceiling_blocks():
    with pytest.raises(sb.SandboxError):
        sb.SandboxRunner()(probes.hog_memory, Envelope(mem_mb=256, timeout_s=15), "n", "", {})


@requires_bwrap
def test_timeout_blocks():
    with pytest.raises(sb.SandboxError):
        sb.SandboxRunner()(probes.sleep_long, Envelope(timeout_s=2, mem_mb=256), "n", "", {})


@requires_bwrap
def test_network_blocked_by_default():
    with pytest.raises(sb.SandboxError):
        sb.SandboxRunner()(probes.open_socket, Envelope(net=False, timeout_s=10, mem_mb=256), "n", "", {})


@requires_bwrap
def test_write_to_readonly_root_blocked():
    # fs=none: the whole root is bound read-only, so a write outside /tmp must FAIL, not silently
    # mutate the host. Target a repo-root path that should never come to exist.
    target = os.path.join(sb._REPO_ROOT, "SANDBOX_ESCAPE_SHOULD_NOT_EXIST.txt")
    try:
        with pytest.raises(sb.SandboxError):
            sb.SandboxRunner()(probes.write_file, Envelope(fs="none", timeout_s=10, mem_mb=256),
                               "n", "", {"target": target})
        assert not os.path.exists(target)            # containment held: nothing was written to the host
    finally:
        if os.path.exists(target):                   # defensive: never leave an escape artifact behind
            os.remove(target)


@requires_bwrap
def test_tmp_write_is_ephemeral_not_host_visible():
    # /tmp is a fresh tmpfs inside the sandbox: a write there succeeds (its parent, /tmp, exists) but
    # does NOT persist to the host. Target /tmp directly — the nested tmpfs is empty, so deeper paths
    # would fail on a missing parent, which would be the wrong reason.
    target = f"/tmp/prismpath_sbtest_{os.getpid()}.txt"
    try:
        out = sb.SandboxRunner()(probes.write_file, Envelope(fs="none", timeout_s=10, mem_mb=256),
                                 "n", "", {"target": target})
        assert out["text"] == "wrote"
        assert not os.path.exists(target)            # discarded with the tmpfs — never reached the host
    finally:
        if os.path.exists(target):                   # defensive: containment broke; don't leave litter
            os.remove(target)


@requires_bwrap
def test_scratch_persists_only_when_rw(tmp_path):
    # fs=rw + a scratch bind is the ONLY way a code node's writes reach the host, and only inside it.
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    target = str(scratch / "out.txt")
    r = sb.SandboxRunner(scratch_dir=str(scratch))
    out = r(probes.write_file, Envelope(fs="rw", timeout_s=10, mem_mb=256), "n", "", {"target": target})
    assert out["text"] == "wrote"
    assert (scratch / "out.txt").read_text() == "sandbox-was-here"


@requires_bwrap
def test_lambda_rejected():
    with pytest.raises(sb.SandboxError):
        sb.SandboxRunner()(lambda n, i, s: {"v": 1}, Envelope(), "n", "", {})


def test_loud_absence_refuses():
    r = sb.SandboxRunner(allow_unsandboxed=False)
    r.bwrap = None                                   # simulate bwrap-absent
    with pytest.raises(sb.SandboxUnavailable):
        r(probes.ok, Envelope(), "n", "", {})


def test_override_runs_unsandboxed_with_marker():
    r = sb.SandboxRunner(allow_unsandboxed=True)
    r.bwrap = None
    out = r(probes.ok, Envelope(), "n", "", {})
    assert out["v"] == 1 and out.get("_sandbox") == "off"
