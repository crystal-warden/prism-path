# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Drift guards — pin the numbers the hardware declared-subset claims derive from, so a corpus or
classifier change turns a test RED instead of silently making a published number wrong.

The number chain over the frozen `predicates.json` (1112 vectors, corpus v2 with the October 2026 reading
boundary cases added):
  * **169 cases / 152 distinct conditions** are Level M per `model_check.is_level_m` — the in-package
    CLASSIFIER authority (what `verify --level-m` and `capability_report` use). Pinned here (CI-run).
    Chained comparisons are normalized into the fragment (SPEC §4.3): the classifier desugars
    `a < b < c` -> `a < b and b < c` via the SAME `_desugar_chains` the PPT compiler imports, so the two
    share one definition and cannot disagree. Float constants are rejected — the i32 fragment has no
    float value domain, so `field OP <float>` is not table-compilable; a signed INTEGER literal folds
    into the fragment (SPEC §4.3, `predicates.fold_unary_signs`), a signed float or field does not.
  * The PPT compiler (`prismpath-hw/ppt_compile`) accepts the SAME distinct conditions — **0
    classifier-vs-compiler disagreements** over the corpus (pinned by `test_classifier_compiler_gap_pinned`).
  * **147** of the 1112 vectors are runnable on the i32 table (in-fragment condition AND read fields
    representable): the declared subset, frozen case by case in `prismpath-hw/declared_subset.json` and
    gated here and in both certification runners, so it can neither shrink nor grow unreviewed. It was
    124 of 1079 until October 2026, when numeric strings and absence under membership, negation and
    inequality joined it; the C targets and the eBPF evaluator certify all 147. The FPGA, which certified
    the earlier subset, no longer exists, so its rows stand as historical evidence.

Why this file exists: an eBPF cert once reported 66 from an over-strict context filter and nothing caught
it (reconciled to 114 to match the FPGA). These pins make the next such drift loud.
"""
import json
from pathlib import Path

from prismpath.kernel import model_check as mc
from prismpath.kernel.parser import parse_file

_CONF = Path(__file__).resolve().parent.parent / "portable" / "conformance"
_GALLERY = Path(__file__).resolve().parent.parent / "gallery"


def _cases():
    return json.loads((_CONF / "predicates.json").read_text())["cases"]


def test_corpus_size_pinned():
    assert len(_cases()) == 1112


def test_level_m_fragment_count_pinned():
    """If this changes, a corpus or classifier edit shifted the Level M fragment — deliberate or not.
    Update the pin AND reconcile the FPGA/eBPF declared-subset numbers (README, evidence #72/#77)."""
    lm = [case for case in _cases() if mc.is_level_m(case["cond"])[0]]
    assert len(lm) == 169, f"Level M case count drifted to {len(lm)} (was 169)"
    assert len({case["cond"] for case in lm}) == 152


def test_classifier_compiler_gap_pinned():
    """The classifier (is_level_m) and the PPT compiler (ppt_compile) must agree EXACTLY over the corpus
    — 0 disagreements in either direction. They share one `_desugar_chains` (the compiler imports it from
    model_check) and one `_classify`, so a flow is Level M per `verify --level-m` iff it compiles to a
    table. Any gap here means the two authorities fell out of sync (e.g. a divergent desugar copy crept
    back) — investigate, don't just re-pin. Skips if the hardware compiler isn't on the path (it lives
    outside the package)."""
    import sys as _sys
    from prismpath.tests._repo import repo_file
    _hw = repo_file("prismpath-hw")
    _sys.path.insert(0, str(_hw))
    import ppt_compile as pc

    classifier = {case["cond"] for case in _cases() if mc.is_level_m(case["cond"])[0]}
    compiler, target_limited = set(), set()
    for case in _cases():
        try:
            pc.compile_predicate(case["cond"]); compiler.add(case["cond"])
        except pc.SubsetError as error:
            if error.reason == "int-out-of-i32":
                target_limited.add(case["cond"])
        except Exception:
            pass
    assert compiler - classifier == set(), \
        f"compiler accepts conditions the classifier rejects: {sorted(compiler - classifier)}"
    # The one documented gap (SPEC §4.3): Level M's integers span plus or minus 2^53 minus 1, the
    # exactly representable range, while a table holds 32 bit integers, so the compiler refuses a
    # larger constant as a target limit. Any other gap is a disagreement to investigate.
    assert classifier - compiler == target_limited, \
        f"classifier accepts conditions the compiler rejects for another reason: {sorted(classifier - compiler - target_limited)}"
    assert all(mc.is_level_m(cond)[0] for cond in target_limited)


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


def test_the_declared_hardware_subset_neither_shrinks_nor_grows_unreviewed():
    """The selection the table compiler makes today must be exactly the frozen manifest. A subset that
    shrank would let every certification report all of fewer vectors passing; one that grew needs the
    manifest frozen again and the targets recertified. Both runners enforce the same check where they
    certify; this runs it on every CI push, with no interpreter or kernel needed."""
    import sys as _sys
    from prismpath.tests._repo import repo_file
    _sys.path.insert(0, str(repo_file("prismpath-hw")))
    import declared_subset
    shrank, grew = declared_subset.drift(declared_subset.selected_ids(_cases()))
    assert shrank == [], f"the declared subset shrank: {shrank}"
    assert grew == [], f"the declared subset grew; freeze it with declared_subset.py --write: {grew}"
    assert declared_subset.frozen()["count"] == 147 == len(declared_subset.frozen()["case_ids"])
