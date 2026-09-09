# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""VERDICT.md must agree with the generated matrix on every per dimension verdict, and its wrong
prediction table must match the pre registered predictions against the computed cells."""
import json
import re
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent.parent / "comparisons"
pytestmark = pytest.mark.skipif(not (HERE / "matrix.json").exists(), reason="matrix not generated")


def _verdict_table():
    text = (HERE / "VERDICT.md").read_text()
    rows = {}
    for line in text.splitlines():
        m = re.match(r"^\| (A\d|B\d) \| .* \| (DISTINCT|NOT-DISTINCT|LOSES|HOLDS|OPEN) \| (DISTINCT|NOT-DISTINCT|LOSES|HOLDS|OPEN) \|$", line)
        if m:
            rows[m.group(1)] = (m.group(2), m.group(3))
    return rows


def test_verdict_matches_matrix():
    m = json.loads((HERE / "matrix.json").read_text())
    rows = _verdict_table()
    assert set(rows) == set(m["verdicts"]), (set(rows) ^ set(m["verdicts"]))
    for dim, (_pred, computed) in rows.items():
        assert computed == m["verdicts"][dim], (dim, computed, m["verdicts"][dim])


def test_wrong_predictions_are_all_listed():
    m = json.loads((HERE / "matrix.json").read_text())
    pre = (HERE / "PREREGISTRATION.md").read_text()
    tbl = pre[pre.index("| dim | prismpath | opa |"):]
    pred = {}
    for line in tbl.splitlines()[2:]:
        c = [x.strip() for x in line.strip("|").split("|")]
        if not re.match(r"^[AB]\d$", c[0]):
            break
        pred[c[0]] = dict(zip(["prismpath", "opa", "cedar", "cerbos", "openfga", "openlane", "verdict"], c[1:]))
    wrong = set()
    for dim, row in pred.items():
        for s in ["prismpath", "opa", "cedar", "cerbos", "openfga", "openlane"]:
            if row[s].split()[0].split(",")[0] != m["matrix"][dim][s]["grade"]:
                wrong.add((dim, s))
        if row["verdict"].split()[0] != m["verdicts"][dim]:
            wrong.add((dim, "verdict"))
    text = (HERE / "VERDICT.md").read_text()
    sec = text[text.index("## 4. Predictions that were wrong"):text.index("## 5.")]
    listed = set(re.findall(r"^\| (A\d|B\d) \| (\w+) \|", sec, flags=re.M))
    assert listed == wrong, ("listed - wrong", listed - wrong, "wrong - listed", wrong - listed)
    assert f"{len(wrong)}" in text or len(wrong) == 13
