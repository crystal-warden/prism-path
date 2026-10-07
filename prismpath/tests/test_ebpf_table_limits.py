# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Regression: a table past the eBPF evaluator's bounds is refused where it is built and where it loads.

Found in October 2026 by the reading boundary audit. The in kernel evaluator clamps instead of failing:
past MAX_PROG_PER_EDGE words it stops reading a program, and past STACK_MAX it drops a push. The shared
compiler emits such tables because the C and FPGA targets allow more, so `when x not in [0..32]` (66
words) lost its final OR and NOT in the kernel and decided the inverse of the policy, and `when a and (b
and (c and (d and e)))` (depth 5) ignored `e`. The host reference clamps the same way, so certification
never saw it. The build side check runs everywhere; the loader check runs wherever the loader is built,
which CI's substrates job does just before it runs this file.
"""
import importlib.util
import subprocess
import sys

import pytest

from prismpath.tests._repo import repo_file

_ebpf = repo_file("prismpath-ebpf")
sys.path.insert(0, str(repo_file("prismpath-hw")))
import ppt_compile as pc  # noqa: E402

_spec = importlib.util.spec_from_file_location("ebpf_table_limits", _ebpf / "ebpf_table_limits.py")
limits = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(limits)

OVER = {
    "66 words": "when x not in [" + ", ".join(str(member) for member in range(33)) + "]",
    "depth 5": "when a and (b and (c and (d and e)))",
}
FITS = {
    "64 words": "when x not in [" + ", ".join(str(member) for member in range(32)) + "]",
    "depth 4": "when a and (b and (c and d))",
}


def _table(condition: str) -> bytes:
    return pc.compile_predicate(condition).serialize()


def test_the_bounds_come_from_the_header_the_kernel_is_built_from():
    constants = limits.header_constants()
    assert (constants["MAX_PROG_PER_EDGE"], constants["STACK_MAX"], constants["MAX_EDGES_PER_NODE"]) == (64, 4, 64)


@pytest.mark.parametrize("name", sorted(OVER))
def test_an_over_limit_table_is_refused_at_build(name):
    with pytest.raises(ValueError, match="outside the eBPF evaluator's limits"):
        limits.require_within_limits(_table(OVER[name]))


@pytest.mark.parametrize("name", sorted(FITS))
def test_a_table_at_the_limit_is_accepted(name):
    assert limits.table_refusals(_table(FITS[name])) == []


def test_a_malformed_program_is_refused():
    table = bytearray(_table("when x > 3"))
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
    table_path.write_bytes(_table(OVER[name]))
    result = subprocess.run([str(_loader()), str(table_path)], capture_output=True, text=True, timeout=60)
    assert result.returncode != 0
    assert "parse_image: edge 0" in result.stderr


@pytest.mark.parametrize("name", sorted(FITS))
def test_the_loader_parses_a_table_at_the_limit(name, tmp_path):
    table_path = tmp_path / "fits.ppt"
    table_path.write_bytes(_table(FITS[name]))
    result = subprocess.run([str(_loader()), str(table_path)], capture_output=True, text=True, timeout=60)
    assert "parse_image:" not in result.stderr
    assert "bad/truncated image" not in result.stderr
