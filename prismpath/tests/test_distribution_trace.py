# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Every conformance case of spec-policy-distribution.md section 20 has a test in each implementation its
row names, and no test names a case that is not there.

A test covers a case when its name or docstring carries `case_NNN`, or when it is an implementation's replay
of the corpus and the corpus holds the case for that implementation. The C core has only the `mesh` and
`cfs` kinds (I1), so a corpus case counts for C only when its PEP is one of those. Python's tests are
prismpath/tests/test_distribution_*.py, integrations/cfs/tests/test_cfs_dist.py (the `cfs` kind's halves) and
tools/tests/test_export.py, the C core's are
prismpath/tests/test_distribution_c.py and test_distribution_c_cfs.py (its `cfs` kind and the cFS app) and Rust's are prismpath-hotswap-rs/tests/test_distribution_*.rs.

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
    "P": [*sorted((REPO / "tests").glob("test_distribution_*.py")), ROOT / "integrations" / "cfs" / "tests" / "test_cfs_dist.py",
          ROOT / "tools" / "tests" / "test_export.py"],
    "C": [REPO / "tests" / "test_distribution_c.py", REPO / "tests" / "test_distribution_c_cfs.py"],
    "R": sorted((ROOT / "prismpath-hotswap-rs" / "tests").glob("test_distribution_*.rs")),
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
# Cases one half of which an implementation runs, by its replay of the corpus or by a test that names the case,
# while another half waits for a later pull request. Neither claims them, and they stay in PENDING until that half
# has its test. 60: the C core
# runs the mesh half, and the cfs half, a table taken on the signer's word, waits for the cfs kind in the C core.
# 100: Python's grant writer emits an envelope, and the other older forms' writers wait for PRs 11 and 12.
# 243: the Rust PEP stages, aborts and applies trust statements while reconciling, and taking a controller statement
# waits for the controller key in Rust. 246: the Rust PEP lapses a held release that expires or is revoked while
# reconciling, and the ceiling and fallback runs wait for section 21 in Rust.
PARTIAL = {"P": frozenset(), "R": frozenset({243, 246}), "C": frozenset()}
PARTIAL["P"] = PARTIAL["P"] | frozenset({246, 260, 261, 280})
# 193, 194: Python's action floor writes `would` and counts overrides, and the `xdp` halves (a floor allow counted with
# no `would`, a floor with a `rate` refused) wait for the `xdp` kind (PR 11); 193's `cfs` lines wait for the core run
# writer of section 21 (RC4).
PARTIAL["P"] = PARTIAL["P"] | frozenset({193, 194})
# 225: a `host`, a `mesh` and a `cfs` PEP take or refuse an operator's answer, and the `xdp` third waits for its kind.
# 232: the answers and their `answered` records are built, and the fleet view that shows them is the controller's part.
PARTIAL["P"] = PARTIAL["P"] | frozenset({225, 232})
PENDING = {
    "P": "104-105 161 164 167 170 172-173 179 181 183-185 187 190-191 193-195 203 206 209-211 215 219 221 223 225 228 232 238-239 246 260-261 266 272-273 280",
    "R": "137-138 161-163 165-166 169-172 174-178 182-183 186 188-190 193 195 197 199 201-202 204-205 207 213 215 218 221 223-227 230 233-236 243 246 256-262 265-266 269-272 276-280 281",
    "C": "97 104-105 122 193 202 220 225 230-232 235 256-261 269-271 276-280 281",
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
    return covered - PARTIAL[impl]


def test_the_spec_has_271_numbered_cases_each_naming_rules_and_implementations():
    # 144 to 160 are left to the pull requests in flight that number their cases from 144; section 21 starts after them
    assert sorted(SPEC) == [*range(1, 144), *range(161, 289)]
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


def test_a_case_a_replay_does_not_claim_stays_pending_until_its_other_half_has_a_test():
    assert all(PARTIAL[impl] <= _expand(PENDING[impl]) for impl in "PRC")
