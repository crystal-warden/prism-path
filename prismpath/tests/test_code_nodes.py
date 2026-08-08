"""Code nodes as governed workers: routing on a code outcome, the static envelope gate, and the
fail-closed contract (no undeclared code, no un-governed execution)."""
import pytest

from prismpath import code_nodes as cn
from prismpath.engine import run
from prismpath.parser import parse

DECLARED = ("---\nname: d\nstart: a\n---\n"
            "## a\n@code(net=false, fs=none, timeout_s=5, mem_mb=128)\nrun the code\n"
            "-> b: when v > 1\n-> c: else\n## b\ndone\n## c\ndone\n")
BAD_ENV = ("---\nname: e\nstart: a\n---\n"
           "## a\n@code(timeout_s=abc, fs=weird, bogus=1)\nx\n-> b: else\n## b\ndone\n")
UNDECLARED = "---\nname: u\nstart: a\n---\n## a\nx\n-> b: else\n## b\ndone\n"


def _handler_v(v):
    return lambda node, instruction, state: {"v": v, "text": f"v={v}"}


# ── routing on a code node's outcome ──────────────────────────────────────────
def test_routes_on_code_outcome():
    g = parse(DECLARED)
    agent = cn.code_agent(g, {"a": _handler_v(2)}, runner=cn.in_process_runner)
    assert run(g, agent).path == ["a", "b"]          # v=2 > 1 -> b
    agent0 = cn.code_agent(g, {"a": _handler_v(0)}, runner=cn.in_process_runner)
    assert run(g, agent0).path == ["a", "c"]          # else -> c


# ── the static gate (portable, verifiable) ────────────────────────────────────
def test_static_gate_accepts_valid_envelope():
    assert cn.check_code_nodes(parse(DECLARED)) == []


def test_static_gate_flags_invalid_envelope():
    probs = cn.check_code_nodes(parse(BAD_ENV))
    assert probs
    joined = " ".join(probs)
    assert "timeout_s" in joined and "fs" in joined and "bogus" in joined


def test_parse_envelope_defaults_and_values():
    g = parse(DECLARED)
    env, probs = cn.parse_envelope(g.nodes["a"].annotations["code"])
    assert probs == [] and env.net is False and env.fs == "none" and env.timeout_s == 5 and env.mem_mb == 128


# ── fail-closed contract (call the agent directly; the engine's error tier would swallow it) ──
def test_refuses_handler_on_undeclared_node():
    g = parse(UNDECLARED)
    agent = cn.code_agent(g, {"a": _handler_v(2)}, runner=cn.in_process_runner)
    with pytest.raises(cn.CodeNodeError):
        agent("a", "x", {})


def test_refuses_without_a_runner():
    g = parse(DECLARED)
    agent = cn.code_agent(g, {"a": _handler_v(2)})   # no runner supplied
    with pytest.raises(cn.CodeNodeError):
        agent("a", "x", {})


def test_non_handler_node_passes_through():
    g = parse(DECLARED)
    agent = cn.code_agent(g, {"a": _handler_v(2)}, runner=cn.in_process_runner)
    assert agent("b", "done", {}) == {"text": "b"}   # 'b' has no handler -> text passthrough
