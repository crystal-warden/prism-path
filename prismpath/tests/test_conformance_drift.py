"""Drift guards — pin the numbers the FPGA/eBPF declared-subset claims derive from, so a corpus or
classifier change turns a test RED instead of silently making a published number wrong.

The number chain over the frozen `predicates.json` (1067 vectors):
  * **126 cases / 119 distinct conditions** are Level M per `model_check.is_level_m` — the in-package
    CLASSIFIER authority (what `verify --level-m` and `capability_report` use). Pinned here (CI-run).
    Chained comparisons are normalized into the fragment (SPEC §4.3): the classifier desugars
    `a < b < c` -> `a < b and b < c` via the SAME `_desugar_chains` the PPT compiler imports, so the two
    share one definition and cannot disagree. Float constants are rejected — the i32 fragment has no
    float value domain, so `field OP <float>` is not table-compilable.
  * The PPT compiler (`prismpath-hw/ppt_compile`) accepts the SAME 126 / 119 — **0 classifier-vs-compiler
    disagreements** over the corpus (pinned by `test_classifier_compiler_gap_pinned`).
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
    assert len(lm) == 126, f"Level M case count drifted to {len(lm)} (was 126)"
    assert len({c["cond"] for c in lm}) == 119


def test_classifier_compiler_gap_pinned():
    """The classifier (is_level_m) and the PPT compiler (ppt_compile) must agree EXACTLY over the corpus
    — 0 disagreements in either direction. They share one `_desugar_chains` (the compiler imports it from
    model_check) and one `_classify`, so a flow is Level M per `verify --level-m` iff it compiles to a
    table. Any gap here means the two authorities fell out of sync (e.g. a divergent desugar copy crept
    back) — investigate, don't just re-pin. Skips if the hardware compiler isn't on the path (it lives
    outside the package)."""
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
    assert compiler - classifier == set(), \
        f"compiler accepts conditions the classifier rejects: {sorted(compiler - classifier)}"
    assert classifier - compiler == set(), \
        f"classifier accepts conditions the compiler rejects: {sorted(classifier - compiler)}"


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
