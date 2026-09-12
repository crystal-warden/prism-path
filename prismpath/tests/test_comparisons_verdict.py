# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""VERDICT.md must agree with the generated matrix on every per dimension verdict, and its wrong
prediction table must match the pre registered predictions against the computed cells."""
import json
import re
from pathlib import Path

import pytest

from prismpath.tests._repo import repo_file

HERE = repo_file("prismpath", "comparisons")
pytestmark = pytest.mark.skipif(not (HERE / "results" / "prismpath").exists(), reason="results not generated")


def _matrix():
    from prismpath.comparisons.matrix import build_matrix
    return build_matrix(HERE / "results")


def _verdict_table():
    text = (HERE / "VERDICT.md").read_text()
    rows = {}
    for line in text.splitlines():
        match = re.match(r"^\| (A\d|B\d) \| .* \| (DISTINCT|NOT-DISTINCT|LOSES|HOLDS|OPEN) \| (DISTINCT|NOT-DISTINCT|LOSES|HOLDS|OPEN) \|$", line)
        if match:
            rows[match.group(1)] = (match.group(2), match.group(3))
    return rows


def test_verdict_matches_matrix():
    matrix = _matrix()
    rows = _verdict_table()
    assert set(rows) == set(matrix["verdicts"]), (set(rows) ^ set(matrix["verdicts"]))
    for dim, (_pred, computed) in rows.items():
        assert computed == matrix["verdicts"][dim], (dim, computed, matrix["verdicts"][dim])


def test_wrong_predictions_are_all_listed():
    matrix = _matrix()
    pre = (HERE / "PREREGISTRATION.md").read_text()
    tbl = pre[pre.index("| dim | prismpath | opa |"):]
    pred = {}
    for line in tbl.splitlines()[2:]:
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if not re.match(r"^[AB]\d$", cells[0]):
            break
        pred[cells[0]] = dict(zip(["prismpath", "opa", "cedar", "cerbos", "openfga", "openlane", "verdict"], cells[1:]))
    wrong = set()
    for dim, row in pred.items():
        for system in ["prismpath", "opa", "cedar", "cerbos", "openfga", "openlane"]:
            if row[system].split()[0].split(",")[0] != matrix["matrix"][dim][system]["grade"]:
                wrong.add((dim, system))
        if row["verdict"].split()[0] != matrix["verdicts"][dim]:
            wrong.add((dim, "verdict"))
    text = (HERE / "VERDICT.md").read_text()
    sec = text[text.index("## 4. Predictions that were wrong"):text.index("## 5.")]
    listed = set(re.findall(r"^\| (A\d|B\d) \| (\w+) \|", sec, flags=re.M))
    assert listed == wrong, ("listed - wrong", listed - wrong, "wrong - listed", wrong - listed)
    assert f"{len(wrong)}" in text or len(wrong) == 13
