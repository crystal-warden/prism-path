# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The compiler's own guard rails, the ones the substrates trust and cannot check for themselves.

An edge program reaches the C target, the embedded evaluator and the fabric as a bare word list with
no length field of its own, so the only place a malformed one can be caught is here, in the compiler
that emits it. That check has to survive `python -O`, which is why it is a raise and not an assert.
"""
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import ppt_compile as pc                                   # noqa: E402


def test_a_well_formed_program_reports_its_peak_depth():
    prog = [0, 0, pc.OPC_AND]                              # two atoms folded by one AND
    assert pc.TableImage._stack_depth(prog) == 2


@pytest.mark.parametrize("prog, final_depth", [
    ([], 0),                                               # empty: the evaluators would have nothing to return
    ([0, 0], 2),                                           # a value left on the stack
    ([0, pc.OPC_AND], 0),                                  # a fold with nothing under it
])
def test_a_malformed_program_is_refused_by_a_raise(prog, final_depth):
    with pytest.raises(ValueError) as caught:
        pc.TableImage._stack_depth(prog)
    assert f"final depth {final_depth}" in str(caught.value)


def test_the_refusal_survives_python_dash_oh():
    """python -O drops asserts, so the guard is checked in a real optimized interpreter, not here."""
    program = ("import sys; sys.path.insert(0, %r); import ppt_compile as pc\n"
               "try:\n"
               "    pc.TableImage._stack_depth([])\n"
               "except ValueError:\n"
               "    print('refused')\n" % str(HERE))
    done = subprocess.run([sys.executable, "-O", "-c", program], capture_output=True, text=True)
    assert done.stdout.strip() == "refused", done.stderr
