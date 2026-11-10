# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The contract corpus (conformance/contract.json) is what portable/gen_contract_fixtures.py writes from
prismpath.kernel.contract now, and the committed vectors
cover each kind of problem and each way the contract reads an expression the sandbox refuses. The crate
replays every case (prismpath-rs/tests/test_contract.rs)."""
import importlib.util
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PORTABLE = REPO / "prismpath" / "portable"


def _generator():
    spec = importlib.util.spec_from_file_location("gen_contract_fixtures", PORTABLE / "gen_contract_fixtures.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _committed() -> dict:
    return json.loads((PORTABLE / "conformance" / "contract.json").read_text(encoding="utf-8"))


def test_the_corpus_is_what_the_generator_writes_now():
    text = json.dumps(_generator().generate(), indent=1, sort_keys=True, ensure_ascii=False) + "\n"
    committed = (PORTABLE / "conformance" / "contract.json").read_text(encoding="utf-8")
    assert committed == text, "contract.json is stale; run python -m prismpath.portable.gen_contract_fixtures"


def test_the_corpus_has_a_case_for_each_kind_of_problem_and_type():
    doc = _committed()
    problems = [problem for case in doc["validate"] for problem in case["problems"]]
    for kind in ("type:", "missing:", "note:"):
        assert any(problem.startswith(kind) for problem in problems), kind
    types = {spec["type"] for case in doc["derive"] for fields in case["contract"].values() for _, spec in fields}
    assert types == {"boolean", "number", "enum", "unknown"}
    assert any("conflict" in spec for case in doc["derive"] for fields in case["contract"].values() for _, spec in fields)


def test_names_are_unique():
    doc = _committed()
    for key in ("derive", "validate"):
        names = [case["name"] for case in doc[key]]
        assert len(names) == len(set(names)), key
