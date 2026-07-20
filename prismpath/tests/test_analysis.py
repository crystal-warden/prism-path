"""Static-analysis tests — "your flow compiles".

Two halves:
  * every broken fixture in tests/fixtures/broken/ must surface its target check (the corpus is
    the spec — one deliberately-broken flow per failure class);
  * every SHIPPING flow must have zero ERRORS and zero FALSE-POSITIVE warnings (the warnings that
    do fire on real flows are pinned below and are all genuine).
"""
import glob
import os

import pytest

from prismpath.parser import parse, parse_file
from prismpath import analysis

HERE = os.path.dirname(__file__)
BROKEN = os.path.join(HERE, "fixtures", "broken")
FLOWS = os.path.join(os.path.dirname(HERE), "flows")


def _shipping_flows():
    # `.tests.md` files are routing fixtures (Markdown tables), not flows — exclude them.
    return sorted(p for p in glob.glob(os.path.join(FLOWS, "*.md")) if not p.endswith(".tests.md"))


def _codes(graph):
    return {f.code for f in analysis.analyze(graph)}


# --- the broken-flow corpus: filename -> the code it must surface -----------------------
CORPUS = {
    "undefined_target.md": "undefined-target",
    "undefined_start.md": "undefined-start",
    "unsafe_predicate.md": "unsafe-predicate",
    "unreachable_node.md": "unreachable-node",
    "no_terminal.md": "no-terminal",
    "stuck_node.md": "possible-stuck",
    "shadowed_edge.md": "shadowed-edge",
    "shadowed_error_edge.md": "shadowed-error-edge",
    "undeclared_field.md": "undeclared-field",
    "field_only_violation.md": "field-only-violation",
    "unbounded_cycle.md": "unbounded-cycle",
    "always_false.md": "always-false-edge",
    "duplicate_condition.md": "duplicate-condition",
}


@pytest.mark.parametrize("fname,code", sorted(CORPUS.items()))
def test_broken_fixture_surfaces_its_check(fname, code):
    g = parse_file(os.path.join(BROKEN, fname))
    assert code in _codes(g), f"{fname} should surface {code}, got {_codes(g)}"


def test_error_edge_ordering(tmp_path):
    from prismpath.parser import parse
    # correct order: conditional `on error when …` BEFORE the bare catch-all -> no shadowing
    ok = parse("---\nname: e\nstart: w\n---\n## w\nGo.\n-> d: it worked\n"
               "-> retry: on error when error_count < 3\n-> giveup: on error\n## retry\n-> w: always\n"
               "## giveup\n## d\n")
    assert "shadowed-error-edge" not in {f.code for f in analysis.analyze(ok)}
    # wrong order: bare `on error` first makes the later conditional dead
    bad = parse("---\nname: e\nstart: w\n---\n## w\nGo.\n-> d: it worked\n"
                "-> giveup: on error\n-> retry: on error when error_count < 3\n## retry\n-> w: always\n"
                "## giveup\n## d\n")
    assert "shadowed-error-edge" in {f.code for f in analysis.analyze(bad)}


def test_corpus_covers_every_analysis_code():
    # guard against a check with no fixture: every code the analyzer can emit is exercised.
    emitted = set()
    for fname in CORPUS:
        emitted |= _codes(parse_file(os.path.join(BROKEN, fname)))
    known = {"undefined-target", "undefined-start", "unsafe-predicate", "unreachable-node",
             "no-terminal", "possible-stuck", "shadowed-edge", "shadowed-error-edge",
             "undeclared-field", "field-only-violation",
             "unbounded-cycle", "always-false-edge", "duplicate-condition"}
    assert known <= emitted


# --- zero false positives on real flows -------------------------------------------------
# Warnings that genuinely fire on shipping flows (all true positives, verified by hand):
#   bugfix / pr_review — cycles with no visits cap (rely on max_steps)
#   creator2 / release — deterministic-only nodes that aren't provably exhaustive
KNOWN_REAL_WARNINGS = {
    "bugfix.md": {"unbounded-cycle"},
    "pr_review.md": {"unbounded-cycle"},
    "creator2.md": {"possible-stuck"},
    "release.md": {"possible-stuck"},
}


@pytest.mark.parametrize("path", _shipping_flows())
def test_shipping_flows_have_no_errors(path):
    g = parse_file(path)
    errors = [f for f in analysis.analyze(g) if f.severity == "error"]
    assert not errors, f"{os.path.basename(path)} has errors: {[f.message for f in errors]}"


@pytest.mark.parametrize("path", _shipping_flows())
def test_shipping_flow_warnings_are_only_the_known_true_positives(path):
    g = parse_file(path)
    codes = {f.code for f in analysis.analyze(g) if f.severity == "warning"}
    allowed = KNOWN_REAL_WARNINGS.get(os.path.basename(path), set())
    assert codes <= allowed, (
        f"{os.path.basename(path)} produced unexpected warning(s) {codes - allowed} — "
        f"likely a false positive")


# --- targeted unit checks for the trickier reasoning ------------------------------------

def test_complementary_pair_is_exhaustive_no_stuck_warning():
    g = parse("""---
start: t
---
## t
-> done: when tests_pass
-> retry: when visits > 3
-> t: when not tests_pass
## retry
-> done: when always
## done
""")
    assert "possible-stuck" not in _codes(g)   # tests_pass / not tests_pass covers all


def test_two_distinct_flags_are_not_exhaustive_stuck_warning():
    g = parse("""---
start: t
---
## t
-> ok: when passed
-> bad: when failed
## ok
-> done: when always
## bad
-> done: when always
## done
""")
    assert "possible-stuck" in _codes(g)       # passed / failed are different fields


def test_visits_capped_cycle_is_not_flagged():
    g = parse("""---
start: loop
---
## loop
-> done: when visits > 5
-> loop: keep working, not done yet
## done
""")
    assert "unbounded-cycle" not in _codes(g)


def test_always_false_interval_contradiction():
    g = parse("""---
start: a
---
## a
-> x: when visits > 10 and visits < 4
-> done: when always
## x
-> done: when always
## done
""")
    assert "always-false-edge" in _codes(g)


def test_false_keyword_is_not_flagged_as_dead():
    # `false`/`never` deliberately disable an edge — not an "always-false" mistake.
    g = parse("""---
start: a
---
## a
-> x: when false
-> done: when always
## x
-> done: when always
## done
""")
    assert "always-false-edge" not in _codes(g)


def test_findings_json_shape():
    g = parse_file(os.path.join(BROKEN, "no_terminal.md"))
    for f in analysis.analyze(g):
        d = f.as_dict()
        assert set(d) == {"severity", "code", "node", "message"}
        assert d["severity"] in ("error", "warning")
