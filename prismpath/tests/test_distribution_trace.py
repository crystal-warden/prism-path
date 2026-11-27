# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Every conformance case of spec-policy-distribution.md section 20 has a test in each implementation its
row names, and no test names a case that is not there.

A test covers a case when its name or docstring carries `case_NNN`, or when it is an implementation's replay
of the corpus and the corpus holds the case for that implementation. The C core has only the `mesh` and
`cfs` kinds (I1), so a corpus case counts for C only when its PEP is one of those. Python's tests are
prismpath/tests/test_distribution_*.py, integrations/cfs/tests/test_cfs_dist.py (the `cfs` kind's halves) and
tools/tests/test_export.py, the C core's are
prismpath/tests/test_distribution_c.py, test_distribution_c_cfs.py (its `cfs` kind and the cFS app) and test_distribution_end_to_end.py (the C harness beside the Python PEPs) and Rust's are prismpath-hotswap-rs/tests/test_distribution_*.rs.

Every case has its tests, so no list of open cases is kept, and a case that loses its test in an implementation its
row names fails here."""
import importlib.util
import json
import re
from pathlib import Path

from prismpath.tests._repo import repo_file

ROOT = Path(__file__).resolve().parents[2]
REPO = ROOT / "prismpath"
CASE = re.compile(r"\bcase_(\d{3})\b")
SOURCES = {
    "P": [*sorted((REPO / "tests").glob("test_distribution_*.py")), ROOT / "integrations" / "cfs" / "tests" / "test_cfs_dist.py",
          ROOT / "tools" / "tests" / "test_export.py"],
    "C": [REPO / "tests" / "test_distribution_c.py", REPO / "tests" / "test_distribution_c_cfs.py",
          REPO / "tests" / "test_distribution_parity.py", REPO / "tests" / "test_distribution_end_to_end.py"],
    "R": [*sorted((ROOT / "prismpath-hotswap-rs" / "tests").glob("test_distribution_*.rs")),
          REPO / "tests" / "test_distribution_parity.py"],
}
EXCLUDED = {REPO / "tests" / "test_distribution_trace.py", REPO / "tests" / "test_distribution_c.py",
            REPO / "tests" / "test_distribution_c_cfs.py"}
REPLAYERS = {"P": REPO / "tests" / "test_distribution_corpus.py",
             "R": ROOT / "prismpath-hotswap-rs" / "tests" / "test_distribution_conformance.rs",
             "C": REPO / "tests" / "test_distribution_c.py"}
# Cases whose only test checks the research export and the built packages, which the product tree does not
# carry; the product's own boundary check covers its packages.
RESEARCH_ONLY = {99: ROOT / "tools" / "tests" / "test_export.py"}
C_KINDS = frozenset({"mesh", "cfs"})


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


def test_the_spec_has_287_numbered_cases_each_naming_rules_and_implementations():
    # 144 to 160 are left to the pull requests in flight that number their cases from 144; section 21 starts after them,
    # 289 to 295 are the table comparator's and the change statement's (W8 to W11), and 296 to 301 the install change
    # statement's (IS14, IS15), 302 to 305 the ceiling's preview and staged rollout (CL5 to CL7), 306 and 307 a power
    # loss between a ceiling and its lapse and a ceiling after a lost one (CL3, C10, IS10, IS12), and 308 a withheld
    # artifact at commit (C2, E10)
    assert sorted(SPEC) == [*range(1, 144), *range(161, 309)]
    assert all(case["rules"].strip() and case["runs_on"] for case in SPEC.values())


def test_every_case_has_a_test_in_each_implementation_it_names():
    held = {number for number, path in RESEARCH_ONLY.items() if not path.exists()}
    missing = {impl: sorted(number for number, case in SPEC.items() if impl in case["runs_on"]
                            and number not in held and number not in _covered(impl))
               for impl in "PRC"}
    assert missing == {"P": [], "R": [], "C": []}


def test_no_test_names_a_case_that_does_not_exist_or_does_not_run_there():
    stray = {impl: {number: files for number, files in _named(impl).items()
                    if number not in SPEC or impl not in SPEC[number]["runs_on"]} for impl in "PRC"}
    assert stray == {"P": {}, "R": {}, "C": {}}


def test_only_case_099_is_research_only():
    assert list(RESEARCH_ONLY) == [99] and RESEARCH_ONLY[99] == ROOT / "tools" / "tests" / "test_export.py"


def test_the_corpus_runs_each_case_where_the_spec_says():
    """I1: each case runs only where its row says, a C case only on a kind the C core has, a Rust case only on
    `host`, and the copies of one case together run everywhere its row names."""
    where = {}
    for case in CORPUS["cases"] + CORPUS["release_ids"] + CORPUS["frames"] + CORPUS["widening"] + CORPUS["commits"]:
        number = case["case"]
        assert number in SPEC and set(case["runs_on"]) <= set(SPEC[number]["runs_on"]), case["name"]
        assert case["name"].startswith(f"{number:03d}_")
        kind = case.get("pep", {}).get("kind", case.get("kind", "host"))
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

