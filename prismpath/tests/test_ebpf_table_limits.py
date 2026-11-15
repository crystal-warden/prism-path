# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Regression: a table past the eBPF evaluator's bounds is refused where it is built and where it loads.

Found in October 2026 by the reading boundary audit. The in kernel evaluator clamps instead of failing:
past its program bound it stopped reading a program, and past its stack bound it dropped a push. The
bounds then were 64 words and a stack of 4, so `when x not in [0..32]` (66 words) lost its final OR and
NOT in the kernel and decided the inverse of the policy, and `when a and (b and (c and (d and e)))`
(depth 5) ignored `e`. The host reference clamps the same way, so certification never saw it.

The evaluator now carries what the C interpreter carries: an operand stack of 64 (one bit a slot) and a
program or node as long as the maps hold. What is still refused is the depth past 64, which the C
interpreter refuses too, and a table past a map capacity. Both are refused here and by the loader,
never clamped. The build side check runs everywhere; the loader check runs wherever the loader is built,
which CI's substrates job does just before it runs this file.
"""
import importlib.util
import subprocess
import sys

import pytest

from prismpath.tests._repo import repo_file

_ebpf = repo_file("prismpath-ebpf")
repo_file("prismpath-ebpf", "ppt_common.h")      # the bounds are read from it; a wheel ships the directory without it
sys.path.insert(0, str(repo_file("prismpath-hw")))
from prismpath.kernel import ppt_compile as pc  # noqa: E402

_spec = importlib.util.spec_from_file_location("ebpf_table_limits", _ebpf / "ebpf_table_limits.py")
limits = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(limits)


def _chain(depth: int) -> bytes:
    """A one edge table whose program pushes `depth` atoms, then folds them: the stack reaches `depth`.
    The source language cannot nest this deep (predicates cap the nesting at 50), so it is built by hand."""
    image = pc.TableImage(max_steps=1)
    field = image.field("x")
    prog = [image.atom(field, pc.OP_NE, pc.TY_INT, value) for value in range(depth)] + [pc.OPC_AND] * (depth - 1)
    image.nodes = [("p", [(1, "chain", prog)]), ("t", [])]
    image.start = 0
    return image.serialize()


def _long_list(members: int) -> bytes:
    return pc.compile_predicate("when x not in [" + ", ".join(str(member) for member in range(members)) + "]").serialize()


OVER = {
    "depth 65": _chain(65),
    "a program past the word capacity": _long_list(2100),
}
FITS = {
    "depth 64": _chain(64),
    "depth 5, once refused": pc.compile_predicate("when a and (b and (c and (d and e)))").serialize(),
    "66 words, once refused": _long_list(33),
    "2,000 words": _long_list(1000),
}


def test_the_bounds_come_from_the_header_the_kernel_is_built_from():
    constants = limits.header_constants()
    assert (constants["MAX_PROG_PER_EDGE"], constants["STACK_MAX"], constants["MAX_EDGES_PER_NODE"]) == (4096, 64, 1024)
    assert constants["MAX_PROG_PER_EDGE"] == constants["MAX_PROG_WORDS"] and constants["MAX_EDGES_PER_NODE"] == constants["MAX_EDGES"]


@pytest.mark.parametrize("name", sorted(OVER))
def test_an_over_limit_table_is_refused_at_build(name):
    with pytest.raises(ValueError, match="outside the eBPF evaluator's limits"):
        limits.require_within_limits(OVER[name])


@pytest.mark.parametrize("name", sorted(FITS))
def test_a_table_at_the_limit_is_accepted(name):
    assert limits.table_refusals(FITS[name]) == []


def test_a_malformed_program_is_refused():
    table = bytearray(pc.compile_predicate("when x > 3").serialize())
    program_start = len(table) - 2                  # one atom word, the last two bytes of the table
    table[program_start:program_start + 2] = (0x8001).to_bytes(2, "little")   # AND with no operands
    assert any("fewer than two operands" in reason for reason in limits.table_refusals(bytes(table)))


def _loader():
    loader = _ebpf / "loader"
    if not loader.exists():
        pytest.skip("the eBPF loader is not built here (make -C prismpath-ebpf)")
    return loader


@pytest.mark.parametrize("name", sorted(OVER))
def test_the_loader_refuses_an_over_limit_table(name, tmp_path):
    table_path = tmp_path / "over.ppt"
    table_path.write_bytes(OVER[name])
    result = subprocess.run([str(_loader()), str(table_path)], capture_output=True, text=True, timeout=60)
    assert result.returncode != 0
    assert "parse_image:" in result.stderr          # named by the loader, never clamped


@pytest.mark.parametrize("name", sorted(FITS))
def test_the_loader_parses_a_table_at_the_limit(name, tmp_path):
    table_path = tmp_path / "fits.ppt"
    table_path.write_bytes(FITS[name])
    result = subprocess.run([str(_loader()), str(table_path)], capture_output=True, text=True, timeout=60)
    assert "parse_image:" not in result.stderr
    assert "bad/truncated image" not in result.stderr
