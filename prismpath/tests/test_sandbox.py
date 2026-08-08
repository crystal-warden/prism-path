"""The code-node sandbox: the envelope is enforced (memory / timeout / network), and absence is loud
(refuse fail-closed; override runs un-sandboxed but stamps the outcome). Behavioral tests spawn bwrap;
they skip cleanly where bwrap is unavailable."""
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
