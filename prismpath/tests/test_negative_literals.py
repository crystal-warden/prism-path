# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Negative (and unary-plus) integer literals fold into the predicate language and the Level M
fragment; a sign on a float or a field name stays outside it. check / eval / classifier / compiler
must all agree (SPEC §4.3-§4.4)."""
import ast

import pytest

from prismpath import predicates as P
from prismpath import model_check as mc


@pytest.mark.parametrize("cond, ctx, expect", [
    ("when x >= -1282", {"x": -5}, True),
    ("when x >= -1282", {"x": -2000}, False),
    ("when x == -3", {"x": -3}, True),
    ("when x != -3", {"x": 0}, True),
    ("when -1 < x", {"x": 5}, True),            # constant-OP-field, flipped orientation
    ("when +7 == x", {"x": 7}, True),           # unary plus folds too
    ("when x in [-3, -1, 2]", {"x": -1}, True),
    ("when x in [-3, -1, 2]", {"x": 0}, False),
])
def test_negative_ints_evaluate(cond, ctx, expect):
    assert P.check_predicate(cond) == []        # accepted by the static sandbox
    assert P.eval_condition(cond, ctx) is expect
    assert mc.is_level_m(cond)[0] is True        # and it is in the Level M fragment


@pytest.mark.parametrize("cond", [
    "when x >= -0.0",       # negative FLOAT: not the integer fragment
    "when x >= -3.5",
    "when -y < x",          # negation of a FIELD is arithmetic, not a constant
    "when x >= -foo",
])
def test_signs_on_non_ints_stay_rejected(cond):
    assert P.check_predicate(cond) != []         # sandbox still rejects
    with pytest.raises(P.PredicateError):
        P.eval_condition(cond, {"x": 1, "y": 2, "foo": 3})
    assert mc.is_level_m(cond) == (False, "disallowed-or-unparseable")


def test_fold_only_touches_signed_int_constants():
    def folded(src):
        return ast.dump(P.fold_unary_signs(ast.parse(src, mode="eval")).body)
    assert "Constant(value=-5)" in folded("x >= -5")
    assert "Constant(value=5)" in folded("x >= +5")
    assert "Constant(value=5)" in folded("x >= -(-5)")   # bottom-up
    # a sign on a float or a name is left as a UnaryOp for the sandbox to reject
    assert "UnaryOp" in folded("x >= -0.5")
    assert "UnaryOp" in folded("x >= -y")
    # bool is not an int here: -True must not become a threshold constant
    assert "UnaryOp" in folded("x >= -True")


def test_compiles_to_a_table():
    import sys
    from pathlib import Path
    hw = Path(__file__).resolve().parent.parent.parent / "prismpath-hw"
    if not (hw / "ppt_compile.py").exists():
        pytest.skip("prismpath-hw/ppt_compile not present")
    sys.path.insert(0, str(hw))
    import ppt_compile as pc
    img = pc.compile_predicate("when x >= -1282")        # no SubsetError
    assert img.serialize()[:4] == b"PPTM"
    # the negative constant is stored as a signed i32 in the atom
    assert any(a[3] == -1282 for a in img.atoms)
