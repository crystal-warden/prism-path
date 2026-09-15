# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Group B result files exist for every system and dimension, obey the schema, and the pre registered
losses are computed as LOSES by the matrix (PREREGISTRATION.md sections 6 and 8)."""
import json
from pathlib import Path

import pytest

from prismpath.tests._repo import repo_file

HERE = repo_file("prismpath", "comparisons")
RESULTS = HERE / "results"
SYSTEMS = ("prismpath", "opa", "cedar", "cerbos", "openfga", "openlane")

pytestmark = pytest.mark.skipif(not (RESULTS / "prismpath").exists(), reason="results not generated")


@pytest.mark.parametrize("dim", ["B1", "B2", "B3", "B4", "B5"])
def test_every_system_has_the_row(dim):
    for system in SYSTEMS:
        files = list((RESULTS / system).glob(f"{dim}__*.json"))
        assert files, (system, dim)
        for path in files:
            doc = json.loads(path.read_text())
            assert doc["grade"] in ("NATIVE", "WITH-WORK", "NOT")
            if doc["grade"] == "WITH-WORK":
                assert doc["glue"] and doc["glue"]["loc"] <= 300 and doc["glue"]["hours"] <= 8


def test_group_b_rows_are_losses():
    from prismpath.comparisons.matrix import build_matrix
    matrix = build_matrix(RESULTS)
    for dim in ("B1", "B2", "B3", "B4", "B5"):
        assert matrix["verdicts"][dim] == "LOSES", (dim, matrix["verdicts"][dim])


def test_prismpath_b1_is_not_and_names_the_constructs():
    docs = [json.loads(path.read_text()) for path in (RESULTS / "prismpath").glob("B1__*.json")]
    grades = {doc["scenario"]: doc["grade"] for doc in docs}
    assert grades["owner_write_1"] == "NOT" and grades["group_read_1"] == "NOT"
    assert grades["manager_hours_write_1"] == "WITH-WORK"
    assert min(grades.values(), key=("NOT", "WITH-WORK", "NATIVE").index) == "NOT"
