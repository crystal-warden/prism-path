"""Drift guards — pin the numbers the FPGA/eBPF declared-subset claims derive from, so a corpus or
classifier change turns a test RED instead of silently making a published number wrong.

The number chain over the frozen `predicates.json` (1067 vectors):
  * **118 cases / 113 distinct conditions** are Level M per `model_check.is_level_m` — the in-package
    CLASSIFIER authority (what `verify --level-m` and `capability_report` use). Pinned here (CI-run).
    Float constants are rejected: the Level M / i32 match-action fragment has no float value domain, so
    a `field OP <float>` condition is NOT table-compilable — the classifier used to over-claim these as
    Level M, a soundness bug now fixed (SPEC §4.3 "integer, boolean, or string literal").
  * **126 cases / 119 distinct** compile via the PPT compiler (`prismpath-hw/ppt_compile`). The compiler
    accepts 6 chained conditions (`1 < x < 5`, …) the classifier reports as excluded — this is the ONLY
    classifier-vs-compiler gap, and it is SPEC-consistent: §4.3 lists chained comparisons as Excluded
    from the fragment but "SHOULD be desugared by tooling", so the compiler desugars while the classifier
    reports raw §4.3 membership. Neither is wrong; they answer different questions.
  * **114** of the 1067 vectors are runnable on the i32 table (in-fragment condition AND read fields
    representable) — the declared subset BOTH the FPGA C-target and the eBPF target certify (asserted
    where the cert runs; needs interp).

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
    assert len(lm) == 118, f"Level M case count drifted to {len(lm)} (was 118)"
    assert len({c["cond"] for c in lm}) == 113


def test_classifier_compiler_gap_pinned():
    """The classifier (is_level_m) and the PPT compiler (ppt_compile) must disagree on EXACTLY the
    6 chained comparisons and nothing else — chained is §4.3-Excluded but tooling-desugarable, so the
    compiler accepts what the classifier reports as excluded. Any drift here (a new gap, or the gap
    closing) means the two authorities fell out of the SPEC-defined relationship — investigate, don't
    just re-pin. Skips if the hardware compiler isn't on the path (it lives outside the package)."""
    import sys as _sys
    _hw = Path(__file__).resolve().parent.parent.parent / "prismpath-hw"
    if not (_hw / "ppt_compile.py").exists():
        import pytest as _pytest
        _pytest.skip("prismpath-hw/ppt_compile not present")
    _sys.path.insert(0, str(_hw))
    import ppt_compile as pc

    classifier = {c["cond"] for c in _cases() if mc.is_level_m(c["cond"])[0]}
    compiler = set()
    for c in _cases():
        try:
            pc.compile_predicate(c["cond"]); compiler.add(c["cond"])
        except Exception:
            pass
    gap = compiler - classifier
    assert classifier - compiler == set(), "classifier accepts a condition the compiler rejects — a bug"
    assert len(gap) == 6, f"classifier/compiler gap drifted to {len(gap)} (was 6 chained): {sorted(gap)}"
    assert all(mc.is_level_m(cond)[1] == "chained-comparison" for cond in gap), \
        "the only allowed classifier/compiler gap is §4.3-Excluded chained comparisons"


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
