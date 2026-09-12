# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Phase 2 of the layer comparison: every translator reproduces the corpus expectations.

PrismPath's own translator runs everywhere (no external binary). The comparator translators need
the pinned toolchain (prismpath/comparisons/.toolchain/, see toolchain/install.sh) and skip without
it, so bare CI still gates the corpus side and the committed conformance reports, while a box with
the toolchain re-derives every comparator's conformance from the real binaries.
"""
import json
from pathlib import Path

import pytest

from prismpath.comparisons import check_translators as ct
from prismpath.comparisons.harness import SYSTEMS_DIR, TOOLCHAIN_BIN, load_policies
from prismpath.tests._repo import repo_file

BINARY = {"opa": "opa", "cedar": "cedar", "cerbos": "cerbos", "openfga": "openfga"}


def _committed(system: str) -> dict:
    f = repo_file("prismpath", "comparisons", "systems", system, "generated", "conformance.json")
    return json.loads(f.read_text(encoding="utf-8"))


def test_prismpath_translator_conforms():
    repo_file("prismpath", "comparisons", "systems", "prismpath", "generated", "conformance.json")
    rep = ct.check_system("prismpath", load_policies(), write=False)
    assert rep["summary"]["MISMATCH"] == 0, [r for r in rep["rows"] if r["class"] == "MISMATCH"]
    dropped = sorted({r["expected"]["rule"] for r in rep["rows"] if r["class"] == "DROPPED"})
    assert dropped == ["r3", "r4"], "only the pre registered inexpressible B1 rules may be dropped"
    stuck = [r for r in rep["rows"] if r["policy"] == "sensor_interlock" and r["kind"] == "undeclared_missing"]
    assert stuck and all(r["observed"]["observed"] == "no_match" and r["observed"]["cause"] == 36 for r in stuck)
    human = [r for r in rep["rows"] if r["scenario"] == "escalate_human_requested_1"]
    assert human[0]["observed"]["cause"] == 34


def test_prismpath_generated_flows_are_level_m():
    repo_file("prismpath", "comparisons", "systems", "prismpath", "generated", "conformance.json")
    for meta in (SYSTEMS_DIR / "prismpath" / "generated").glob("*/TRANSLATION.json"):
        m = json.loads(meta.read_text(encoding="utf-8"))
        if m["expressible"]:
            assert "Level M: yes" in m["notes"], m["policy"]


@pytest.mark.parametrize("system", sorted(BINARY))
def test_comparator_translator_conforms(system):
    repo_file("prismpath", "comparisons", "systems", system, "generated", "conformance.json")
    if not (TOOLCHAIN_BIN / BINARY[system]).exists():
        pytest.skip(f"{system} toolchain not installed")
    rep = ct.check_system(system, load_policies(), write=False)
    assert rep["summary"]["MISMATCH"] == 0, [r for r in rep["rows"] if r["class"] == "MISMATCH"]


@pytest.mark.parametrize("system", ["prismpath", "opa", "cedar", "cerbos", "openfga"])
def test_committed_conformance_report_is_clean(system):
    rep = _committed(system)
    assert rep["summary"]["MISMATCH"] == 0
    assert rep["summary"]["MATCH"] + rep["summary"]["PROBE"] + rep["summary"]["DROPPED"] + rep["summary"]["UNEXPRESSIBLE"] == 66
    for row in rep["rows"]:
        assert row["class"] in ("MATCH", "PROBE", "DROPPED", "UNEXPRESSIBLE")


def test_every_translation_carries_citations_and_notes():
    repo_file("prismpath", "comparisons", "systems", "prismpath", "generated", "conformance.json")
    for meta in SYSTEMS_DIR.glob("*/generated/*/TRANSLATION.json"):
        m = json.loads(meta.read_text(encoding="utf-8"))
        assert m["citations"], meta
        assert m["notes"], meta
        assert isinstance(m["idiomatic"], bool)
