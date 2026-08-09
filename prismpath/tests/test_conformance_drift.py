"""Drift guards — pin the numbers the FPGA/eBPF declared-subset claims derive from, so a corpus or
classifier change turns a test RED instead of silently making a published number wrong.

The number chain over the frozen `predicates.json` (1067 vectors):
  * **129 cases / 124 distinct conditions** are Level M per `model_check.is_level_m` — the in-package
    CLASSIFIER authority (what `verify --level-m` and `capability_report` use). Pinned here (CI-run).
  * **126** of those conditions also compile to a v0 PPT table (`prismpath-hw/ppt_compile`); the 129-vs-126
    gap is a classifier-vs-compiler nuance (cf. evidence #76), tracked separately, needs the hw build.
  * **114** of the 1067 vectors are runnable on the i32 table (read fields representable) — the declared
    subset BOTH the FPGA C-target and the eBPF target certify (asserted where the cert runs; needs interp).

Why this file exists: an eBPF cert once reported 66 from an over-strict context filter and nothing caught
it (reconciled to 114 to match the FPGA). These pins make the next such drift loud.
"""
import json
from pathlib import Path

from prismpath import model_check as mc
from prismpath.parser import parse_file

_CONF = Path(__file__).resolve().parent.parent / "portable" / "conformance"
_GALLERY = Path(__file__).resolve().parent.parent / "gallery"


def _cases():
    return json.loads((_CONF / "predicates.json").read_text())["cases"]


def test_corpus_size_pinned():
    assert len(_cases()) == 1067


def test_level_m_fragment_count_pinned():
    """If this changes, a corpus or classifier edit shifted the Level M fragment — deliberate or not.
    Update the pin AND reconcile the FPGA/eBPF declared-subset numbers (README, evidence #72/#77)."""
    lm = [c for c in _cases() if mc.is_level_m(c["cond"])[0]]
    assert len(lm) == 129, f"Level M case count drifted to {len(lm)} (was 129)"
    assert len({c["cond"] for c in lm}) == 124


def test_capability_levelm_flow():
    """A P0 Level M flow compiles to every target, including Level M hardware (FPGA C-table / eBPF)."""
    rep = mc.capability_report(parse_file(str(_GALLERY / "incident_severity" / "incident_severity.md")))
    assert rep["tier"] == "P0"
    assert rep["level_m"] is True
    assert rep["targets"]["level_m_hardware"]["status"] == "yes"


def test_capability_semantic_flow():
    """A flow with reachable semantic edges is NOT hardware-compilable — the capability matrix must say so
    (guards against a regression that would over-claim 'runs on silicon/kernel')."""
    rep = mc.capability_report(parse_file(str(_GALLERY / "support_triage" / "support_triage.md")))
    assert rep["tier"] != "P0"
    assert rep["targets"]["level_m_hardware"]["status"] == "no"
