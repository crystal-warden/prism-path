# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Policy distribution gives the same answer in Python, Rust and the C core (spec-policy-distribution.md I1, case 104).

Each shared corpus row that more than one implementation can run is run through every implementation that has it,
and the result lists are compared row by row. Python runs every row. The Rust test binary
(prismpath-hotswap-rs/tests/parity_dump.rs) runs the `host` rows and the C core's host harness (prismpath-hw/dist/
host_check.c) the `mesh` rows, so a `host` row is compared between Python and Rust and a `mesh` row between Python
and C. Corpora and the fields compared:

- distribution.json `cases`: cause, unchanged, time_floor, envelope_id (P, R, C)
- distribution.json `commits`: cause, active_seq (P, R, C)
- distribution.json `widening`: cause (P, R; the C core's widening rule is run by scripts, not by corpus rows)
- install_larger.json `rows`: event, cause (P, R, C)

The distribution corpus's `frames` rows have no Rust implementation, and Python and the C core replay them in
test_distribution_c.py.

The test reports every row that differs, with the corpus, the row and the three results, and does not stop at the
first. Rust is built once with `cargo test` and driven through the environment: PRISMPATH_PARITY_CORPORA names the
directory of the shared corpora and PRISMPATH_PARITY_OUT the file it writes. It skips when cargo or a C compiler is
missing, and fails there when PRISMPATH_REQUIRE_CROSS_LANGUAGE is set."""
import json
import os
import shutil
import subprocess

import pytest

pytest.importorskip("cryptography")

from prismpath.tests import test_distribution_c as C  # noqa: E402
from prismpath.tests import test_distribution_larger as LARGER  # noqa: E402
from prismpath.tests.test_distribution_c import host_check  # noqa: E402,F401  (the fixture that builds the harness)

pytestmark = [pytest.mark.parity, pytest.mark.cross_language]

ROOT = C.ROOT
CORPORA = ROOT / "prismpath" / "portable" / "conformance"
CARGO = shutil.which("cargo")
REQUIRED = bool(os.environ.get("PRISMPATH_REQUIRE_CROSS_LANGUAGE"))


def _fail_or_skip(why: str):
    if REQUIRED:
        pytest.fail(f"PRISMPATH_REQUIRE_CROSS_LANGUAGE is set and {why}")
    pytest.skip(why)


@pytest.fixture(scope="module")
def rust(tmp_path_factory):
    """What the Rust host PEP answers for every corpus row it runs, from one build and one run of its test binary."""
    if CARGO is None:
        _fail_or_skip("there is no cargo, so the Rust implementation is not built here")
    out = tmp_path_factory.mktemp("parity") / "rust.json"
    env = {**os.environ, "PRISMPATH_PARITY_CORPORA": str(CORPORA), "PRISMPATH_PARITY_OUT": str(out)}
    done = subprocess.run([CARGO, "test", "-q", "-p", "prismpath-hotswap-rs", "--test", "parity_dump"], cwd=ROOT,
                          env=env, capture_output=True, text=True, timeout=1800)
    assert done.returncode == 0, done.stdout[-3000:] + done.stderr[-3000:]
    return json.loads(out.read_text(encoding="utf-8"))


def _python_cases(corpus: dict) -> dict:
    return {case["name"]: C._generator().replay(case) for case in corpus["cases"] if "P" in case["runs_on"]}


def _c_cases(host_check, corpus: dict) -> dict:
    return C._run(host_check, [case for case in corpus["cases"] if "C" in case["runs_on"]
                               and case["pep"]["kind"] in C.C_KINDS])


def _c_commits(host_check, corpus: dict, tmp_path) -> dict:
    out = {}
    for entry in corpus["commits"]:
        if "C" in entry["runs_on"] and entry["kind"] == "mesh":
            script = [("provision", C.S, entry["now"])]
            for step in entry["steps"]:
                if step["op"] == "stage":
                    script.append(("stage", step["sealed"], step["body"], entry["now"]))
                else:
                    script.append(("commit", C.S, step["seq"], step["policy_sha256"], entry["now"]))
            last = C._records(C._c_steps(host_check, script, hold=False)[-1])[-1]
            out[entry["name"]] = {"cause": last.cause, "active_seq": last.active_seq}
    return out


def _guard(run):
    try:
        return run()
    except Exception as error:  # a row an implementation cannot run is a difference to report, not a stop
        return {"error": f"{type(error).__name__}: {error}"}


def _compare(corpus: str, rows: list, results: dict, fields: tuple, differing: list) -> int:
    """Compare each row's results among the implementations that have it. `results` is {implementation: {row: result}}.
    A row that fewer than two implementations ran is not a comparison."""
    compared = 0
    for row in rows:
        have = {impl: found[row] for impl, found in results.items() if row in found}
        if len(have) < 2:
            continue
        compared += 1
        keyed = {impl: {key: result.get(key, "<missing>") for key in fields} if "error" not in result else result
                 for impl, result in have.items()}
        if len({json.dumps(item, sort_keys=True) for item in keyed.values()}) > 1:
            differing.append(f"{corpus} {row}: " + "; ".join(f"{impl}={json.dumps(item, sort_keys=True)}"
                                                             for impl, item in sorted(keyed.items())))
    return compared


def test_case_104_the_corpus_gives_the_same_results_in_python_rust_and_the_c_core(host_check, rust, tmp_path):
    """case_104: I1. Every corpus row more than one implementation runs gives the same result in each."""
    corpus = json.loads((CORPORA / "distribution.json").read_text(encoding="utf-8"))
    larger = json.loads((CORPORA / "install_larger.json").read_text(encoding="utf-8"))
    generator = C._generator()
    differing, compared = [], {}

    python = {case["name"]: _guard(lambda case=case: generator.replay(case)) for case in corpus["cases"]
              if "P" in case["runs_on"]}
    compared["cases"] = _compare("distribution.cases", sorted(python), {
        "P": python, "R": rust["cases"], "C": _c_cases(host_check, corpus)},
        ("cause", "unchanged", "time_floor", "envelope_id"), differing)

    python = {entry["name"]: _guard(lambda entry=entry: generator.replay_commits(entry)) for entry in corpus["commits"]
              if "P" in entry["runs_on"]}
    compared["commits"] = _compare("distribution.commits", sorted(python), {
        "P": python, "R": rust["commits"], "C": _c_commits(host_check, corpus, tmp_path)},
        ("cause", "active_seq"), differing)

    python = {entry["name"]: _guard(lambda entry=entry: generator.replay_widening(entry)) for entry in corpus["widening"]
              if "P" in entry["runs_on"] and entry["kind"] == "host"}
    compared["widening"] = _compare("distribution.widening", sorted(python), {"P": python, "R": rust["widening"]},
                                    ("cause",), differing)

    python_host, python_mesh, c_mesh = {}, {}, {}
    for number, row in enumerate(larger["rows"]):
        for kind, into in (("host", python_host), ("mesh", python_mesh)):
            if kind in row["kinds"]:
                directory = tmp_path / f"larger_{number}_{kind}"
                directory.mkdir()
                into[row["name"]] = _guard(lambda row=row, kind=kind, directory=directory:
                                           LARGER.replay(row, kind, directory))
        if "mesh" in row["kinds"]:
            c_mesh[row["name"]] = _guard(lambda row=row: C._larger_replay(host_check, row))
    names = [row["name"] for row in larger["rows"]]
    compared["larger host"] = _compare("install_larger.host", names, {"P": python_host, "R": rust["larger"]},
                                       ("event", "cause"), differing)
    compared["larger mesh"] = _compare("install_larger.mesh", names, {"P": python_mesh, "C": c_mesh},
                                       ("event", "cause"), differing)

    assert sum(compared.values()) >= 250, compared                  # the corpora were really run
    assert differing == [], f"{len(differing)} rows differ (compared {compared}):\n" + "\n".join(differing)
