# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Tests for prismpath.comparisons.matrix."""

import json
import pytest
from pathlib import Path
from prismpath.comparisons.matrix import build_matrix, main, SYSTEMS, DIMENSIONS


def make_result_file(
    results_dir: Path,
    system: str = "prismpath",
    dimension: str = "A1",
    policy: str = "pol1",
    scenario: str = "scen1",
    expected: str | None = "allow",
    observed: str = "allow",
    match: bool = True,
    grade: str = "NATIVE",
    idiomatic: bool = True,
    glue: dict | None = None,
    evidence_path: str = "corpus/prismpath/a1.py",
    harness_commit: str = "abc1234",
    run_at: str = "2026-09-08T12:00:00Z",
    notes: str = "",
    measurements: dict | None = None,
    override_filename: str | None = None,
    override_fields: dict | None = None,
) -> Path:
    sys_dir = results_dir / system
    sys_dir.mkdir(parents=True, exist_ok=True)
    filename = override_filename or f"{dimension}__{policy}__{scenario}.json"
    filepath = sys_dir / filename

    data = {
        "system": system,
        "system_version": "1.0.0",
        "dimension": dimension,
        "policy": policy,
        "scenario": scenario,
        "expected": expected,
        "observed": observed,
        "match": match,
        "grade": grade,
        "idiomatic": idiomatic,
        "glue": glue,
        "evidence_path": evidence_path,
        "harness_commit": harness_commit,
        "run_at": run_at,
        "notes": notes,
    }
    if measurements is not None:
        data["measurements"] = measurements
    if override_fields:
        data.update(override_fields)

    filepath.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return filepath


def test_empty_results_dir(tmp_path: Path):
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    out_dir = tmp_path / "out"

    # (a) empty results dir yields matrix with UNTESTED cells and OPEN verdicts, exits 0
    m = build_matrix(results_dir)
    assert all(
        cell["grade"] == "UNTESTED"
        for dim in m["matrix"]
        for cell in m["matrix"][dim].values()
    )
    assert all(v == "OPEN" for v in m["verdicts"].values())

    code = main(["--results", str(results_dir), "--out", str(out_dir)])
    assert code == 0
    assert (out_dir / "MATRIX.md").exists()
    assert (out_dir / "matrix.json").exists()


def test_distinct_verdict_progression(tmp_path: Path):
    results_dir = tmp_path / "results"

    # (b) prismpath NATIVE on A3 and opa/cedar/cerbos/openfga NOT on A3 (openlane untested) yields OPEN;
    # once openlane is also NOT, verdict is DISTINCT
    make_result_file(results_dir, system="prismpath", dimension="A3", grade="NATIVE")
    make_result_file(results_dir, system="opa", dimension="A3", grade="NOT")
    make_result_file(results_dir, system="cedar", dimension="A3", grade="NOT")
    make_result_file(results_dir, system="cerbos", dimension="A3", grade="NOT")
    make_result_file(results_dir, system="openfga", dimension="A3", grade="NOT")

    m1 = build_matrix(results_dir)
    assert m1["verdicts"]["A3"] == "OPEN"

    make_result_file(results_dir, system="openlane", dimension="A3", grade="NOT")
    m2 = build_matrix(results_dir)
    assert m2["verdicts"]["A3"] == "DISTINCT"


def test_not_scenario_overrides_native(tmp_path: Path):
    results_dir = tmp_path / "results"

    # (c) one NOT scenario among NATIVE scenarios makes the cell NOT
    make_result_file(results_dir, system="prismpath", dimension="A1", policy="p1", scenario="s1", grade="NATIVE")
    make_result_file(results_dir, system="prismpath", dimension="A1", policy="p1", scenario="s2", grade="NATIVE")
    make_result_file(results_dir, system="prismpath", dimension="A1", policy="p1", scenario="s3", grade="NOT")

    m = build_matrix(results_dir)
    cell = m["matrix"]["A1"]["prismpath"]
    assert cell["grade"] == "NOT"
    assert cell["counts"] == {"NATIVE": 2, "WITH-WORK": 0, "NOT": 1}


def test_with_work_without_glue_fails(tmp_path: Path):
    results_dir = tmp_path / "results"

    # (d) a WITH-WORK file without glue fails validation with nonzero exit
    make_result_file(results_dir, system="prismpath", dimension="A1", grade="WITH-WORK", glue=None)

    with pytest.raises(ValueError):
        build_matrix(results_dir)

    out_dir = tmp_path / "out"
    code = main(["--results", str(results_dir), "--out", str(out_dir)])
    assert code != 0


def test_filename_disagrees_with_fields_fails(tmp_path: Path):
    results_dir = tmp_path / "results"

    # (e) a filename that disagrees with its fields fails validation
    make_result_file(
        results_dir,
        system="prismpath",
        dimension="A1",
        policy="p1",
        scenario="s1",
        override_fields={"dimension": "A2"}
    )

    with pytest.raises(ValueError):
        build_matrix(results_dir)

    out_dir = tmp_path / "out"
    code = main(["--results", str(results_dir), "--out", str(out_dir)])
    assert code != 0


def test_byte_identical_regeneration(tmp_path: Path):
    results_dir = tmp_path / "results"
    out_dir1 = tmp_path / "out1"
    out_dir2 = tmp_path / "out2"

    # (f) regeneration is byte identical
    make_result_file(results_dir, system="prismpath", dimension="A1", grade="NATIVE")
    make_result_file(results_dir, system="opa", dimension="A1", grade="NOT")

    code1 = main(["--results", str(results_dir), "--out", str(out_dir1)])
    code2 = main(["--results", str(results_dir), "--out", str(out_dir2)])
    assert code1 == 0
    assert code2 == 0

    json1 = (out_dir1 / "matrix.json").read_bytes()
    json2 = (out_dir2 / "matrix.json").read_bytes()
    assert json1 == json2

    md1 = (out_dir1 / "MATRIX.md").read_bytes()
    md2 = (out_dir2 / "MATRIX.md").read_bytes()
    assert md1 == md2


def test_b1_cedar_native_prismpath_with_work_yields_loses(tmp_path: Path):
    results_dir = tmp_path / "results"

    # (g) B1 with cedar NATIVE and prismpath WITH-WORK yields LOSES
    glue_obj = {
        "description": "Custom adapter",
        "components": ["adapter.py"],
        "loc": 50,
        "hours": 2.5
    }
    make_result_file(results_dir, system="prismpath", dimension="B1", grade="WITH-WORK", glue=glue_obj)
    make_result_file(results_dir, system="cedar", dimension="B1", grade="NATIVE")

    m = build_matrix(results_dir)
    assert m["verdicts"]["B1"] == "LOSES"
