# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Every conformance case of spec-policy-distribution.md section 20 has a test in each implementation its
row names, and no test names a case that is not there.

A test covers a case when its name or docstring carries `case_NNN`, or when it is an implementation's replay
of the corpus and the corpus holds the case for that implementation. The C core has only the `mesh` and
`cfs` kinds (I1), so a corpus case counts for C only when its PEP is one of those. Python's tests are
prismpath/tests/test_distribution_*.py and tools/tests/test_export.py, the C core's is
prismpath/tests/test_distribution_c.py and Rust's are prismpath-hotswap-rs/tests/test_distribution_*.rs.

`PENDING` lists, per implementation, the cases whose pull request has not landed. Each pull request
shortens it, and a case still listed that has a test fails here, so the list never hides a landed case.
The list goes when every case has its tests."""
import importlib.util
import json
import re
from pathlib import Path

from prismpath.tests._repo import repo_file

ROOT = Path(__file__).resolve().parents[2]
REPO = ROOT / "prismpath"
CASE = re.compile(r"\bcase_(\d{3})\b")
SOURCES = {
    "P": [*sorted((REPO / "tests").glob("test_distribution_*.py")), ROOT / "tools" / "tests" / "test_export.py"],
    "C": [REPO / "tests" / "test_distribution_c.py"],
    "R": sorted((ROOT / "prismpath-hotswap-rs" / "tests").glob("test_distribution_*.rs")),
}
EXCLUDED = {REPO / "tests" / "test_distribution_trace.py", REPO / "tests" / "test_distribution_c.py"}
REPLAYERS = {"P": REPO / "tests" / "test_distribution_corpus.py",
             "R": ROOT / "prismpath-hotswap-rs" / "tests" / "test_distribution_conformance.rs",
             "C": REPO / "tests" / "test_distribution_c.py"}
# Cases whose only test checks the research export and the built packages, which the product tree does not
# carry; the product's own boundary check covers its packages.
RESEARCH_ONLY = {99: ROOT / "tools" / "tests" / "test_export.py"}
C_KINDS = frozenset({"mesh", "cfs"})
PENDING = {
    "P": "30 32-37 45 49 54-65 72-76 80-81 86-98 100 102 104-105 109 113 120-121 123-125 129 131",
    "R": "1-13 16-17 20-24 26 28-29 31 39-44 46-48 50-53 62-63 66-77 79 82 84-85 97 101 104 111 114-115 117-118 "
         "123 126-127 130-131",
    "C": "1-14 20-22 24-29 31 35-42 46-48 50 52-53 60-63 66-74 76-77 79 82 85 97 104-110 112 114 117-123 128 130-132",
}


def _expand(ranges: str) -> set:
    out = set()
    for part in ranges.split():
        low, _, high = part.partition("-")
        out.update(range(int(low), int(high or low) + 1))
    return out


def _spec_cases():
    spec = importlib.util.spec_from_file_location("gen_distribution_corpus",
                                                  REPO / "portable" / "gen_distribution_corpus.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.spec_cases(repo_file("docs", "design", "spec-policy-distribution.md"))


SPEC = _spec_cases()
CORPUS = json.loads((REPO / "portable" / "conformance" / "distribution.json").read_text(encoding="utf-8"))


def _named(impl: str) -> dict:
    """{case: [files]} for the case tokens in `impl`'s test sources."""
    named = {}
    for path in SOURCES[impl]:
        if path.exists() and (impl == "C" or path not in EXCLUDED):
            for number in CASE.findall(path.read_text(encoding="utf-8")):
                named.setdefault(int(number), []).append(path.name)
    return named


def _covered(impl: str) -> set:
    covered = set(_named(impl))
    if REPLAYERS[impl].exists():
        covered |= {case["case"] for case in CORPUS["cases"] if impl in case["runs_on"]
                    and (impl != "C" or case["pep"]["kind"] in C_KINDS)}
    return covered


def test_the_spec_has_132_numbered_cases_each_naming_rules_and_implementations():
    assert sorted(SPEC) == list(range(1, 133))
    assert all(case["rules"].strip() and case["runs_on"] for case in SPEC.values())


def test_every_case_has_a_test_in_each_implementation_it_names_unless_its_pull_request_is_pending():
    held = {number for number, path in RESEARCH_ONLY.items() if not path.exists()}
    missing = {impl: sorted(number for number, case in SPEC.items() if impl in case["runs_on"]
                            and number not in _expand(PENDING[impl]) | held and number not in _covered(impl))
               for impl in "PRC"}
    assert missing == {"P": [], "R": [], "C": []}


def test_no_test_names_a_case_that_does_not_exist_or_does_not_run_there():
    stray = {impl: {number: files for number, files in _named(impl).items()
                    if number not in SPEC or impl not in SPEC[number]["runs_on"]} for impl in "PRC"}
    assert stray == {"P": {}, "R": {}, "C": {}}


def test_the_pending_list_names_only_cases_still_without_a_test():
    stale = {impl: sorted(_expand(PENDING[impl]) & _covered(impl)) for impl in "PRC"}
    assert stale == {"P": [], "R": [], "C": []}
    outside = {impl: sorted(number for number in _expand(PENDING[impl])
                            if impl not in SPEC.get(number, {"runs_on": []})["runs_on"]) for impl in "PRC"}
    assert outside == {"P": [], "R": [], "C": []}


def test_only_case_099_is_research_only():
    assert list(RESEARCH_ONLY) == [99] and RESEARCH_ONLY[99] == ROOT / "tools" / "tests" / "test_export.py"


def test_the_corpus_runs_each_case_where_the_spec_says():
    """I1: each case runs only where its row says, a C case only on a kind the C core has, a Rust case only on
    `host`, and the copies of one case together run everywhere its row names."""
    where = {}
    for case in CORPUS["cases"] + CORPUS["release_ids"]:
        number = case["case"]
        assert number in SPEC and set(case["runs_on"]) <= set(SPEC[number]["runs_on"]), case["name"]
        assert case["name"].startswith(f"{number:03d}_")
        kind = case.get("pep", {}).get("kind", "host")
        assert ("C" not in case["runs_on"] or kind in C_KINDS) and ("R" not in case["runs_on"] or kind == "host")
        where.setdefault(number, set()).update(case["runs_on"])
    assert all(runs == set(SPEC[number]["runs_on"]) for number, runs in where.items()), where


def test_a_replay_that_exists_has_no_not_yet_built_marker():
    """A language whose replay of the corpus exists is not marked in tools/run_corpora.py as not claiming it, so
    the marker of a gap cannot outlive the gap. The table is research's own, so the product skips this."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("run_corpora", repo_file("tools", "run_corpora.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    rows = module.CONSUMERS["portable/distribution"]
    for impl, column in (("P", "py"), ("R", "rs"), ("C", "hw")):
        marked = any(consumer[0] == "none" for consumer in rows[column])
        assert not (REPLAYERS[impl].exists() and marked), (impl, column)
        assert REPLAYERS[impl].exists() or marked, (impl, column)
