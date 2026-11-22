#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""One command for every frozen conformance corpus against every implementation that consumes it.

    python tools/run_corpora.py            run everything, print one line per corpus x implementation
    python tools/run_corpora.py --check    only the consumer table: no test is run (a few seconds)
    python tools/run_corpora.py --only rust --only go     restrict the implementations that run
    python tools/run_corpora.py --allow-skips             do not set PRISMPATH_REQUIRE_CROSS_LANGUAGE

The corpora are the JSON files under prismpath/portable/conformance and prismpath/telemetry/conformance.
Each implementation either consumes a corpus, through the test targets named in CONSUMERS below, or is
declared not to claim it with a reason. The table is checked against the tree, so a corpus added
without a consumer decision, a consumer that no longer mentions its corpus, or a claim with no
runnable target fails the run. Each distinct command runs once and every corpus it serves reports
that command's result, marked `shared` when more than one corpus rides on it. The commands are the ones
the other CI jobs run; this tool does not reimplement any of them, it calls them and gathers the counts.

Implementations: py (pytest), rs (cargo test and the conformance binary), js (the node runners and
node --test), go (go test) and hw (the C target through make cert; needs gcc and make).

Line states: PASS, PART (passed, and the run itself reports cases it does not take, shown with the reason),
GEN (Python writes the corpus and no Python test reads it back), N/A (not claimed, with the reason), FAIL.

Exit status is 0 only if every command passed and the table is complete.
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PORTABLE = "prismpath/portable/conformance"
TELEMETRY = "prismpath/telemetry/conformance"
IMPLS = ("py", "rs", "js", "go", "hw")

# A consumer is a (kind, argument..., evidence file) description. The evidence file is the source that
# must mention the corpus file name, so a table row cannot outlive the code it describes.
#   ("pytest", [test files])                    evidence: the first test file that names the corpus
#   ("cargo", package, test name, evidence)     cargo test -p package --test name
#   ("bin", evidence)                           the prismpath-rs conformance binary
#   ("node", script, evidence)                  node script <corpus dir>
#   ("nodetest", evidence)                      node --test of the portable port's unit tests
#   ("go", evidence)                            go test in prismpath-go
#   ("make", evidence)                          make -C prismpath-hw cert
#   ("generator", script)                       Python is the source of the corpus; no consumer test exists
#   ("none", reason)                            the implementation does not claim the corpus
PY_RUN = "prismpath/tests/test_portable_runners.py"


def pytest(*files):
    return ("pytest", list(files))


def cargo(package, test, evidence):
    return ("cargo", package, test, evidence)


NONE_JS = ("none", "no JavaScript consumer: the port covers the kernel, Level M, reach, capability, crypto agility, canon/2, the Merkle tree and receipt bundles only")
NONE_GO = ("none", "the Go kernel covers the predicate and flow corpora, the field definitions refusal and canon/2 only")
NONE_HW = ("none", "the C target certifies the declared subset of the predicate and flow corpora only")
NONE_REPRO = ("none", "recorded Python bytes are the reference: the Rust test reads this corpus, Python writes it")

CONSUMERS: dict[str, dict[str, list[tuple]]] = {
    "portable/canon2": {
        "py": [pytest("prismpath/tests/test_canon2.py")],
        "rs": [cargo("prismpath-rs", "test_canon2", "prismpath-rs/tests/test_canon2.rs")],
        "js": [("node", "run_vectors.mjs", "prismpath/portable/run_vectors.mjs")],
        "go": [("go", "prismpath-go/conformance_test.go")],
        "hw": [NONE_HW]},
    "portable/capability": {
        "py": [pytest("prismpath/tests/test_capability_conformance.py", PY_RUN)],
        "rs": [cargo("prismpath-rs", "test_proof", "prismpath-rs/tests/test_proof.rs")],
        "js": [("node", "run_capability.mjs", "prismpath/portable/run_capability.mjs")],
        "go": [NONE_GO], "hw": [NONE_HW]},
    "portable/causes": {
        "py": [pytest("prismpath/tests/test_causes_rs.py")],
        "rs": [cargo("prismpath-rs", "test_causes", "prismpath-rs/tests/test_causes.rs")],
        "js": [NONE_JS], "go": [NONE_GO], "hw": [NONE_HW]},
    "portable/connector": {
        "py": [("generator", "prismpath/portable/gen_connector_fixtures.py")],
        "rs": [cargo("prismpath-rs", "test_connector", "prismpath-rs/tests/test_connector.rs")],
        "js": [NONE_JS], "go": [NONE_GO], "hw": [NONE_HW]},
    "portable/context": {
        "py": [("generator", "prismpath/portable/gen_context_fixtures.py")],
        "rs": [cargo("prismpath-rs", "test_context", "prismpath-rs/tests/test_context.rs")],
        "js": [NONE_JS], "go": [NONE_GO], "hw": [NONE_HW]},
    "portable/contract": {
        "py": [pytest("prismpath/tests/test_contract_corpus.py")],
        "rs": [cargo("prismpath-rs", "test_contract", "prismpath-rs/tests/test_contract.rs")],
        "js": [NONE_JS], "go": [NONE_GO], "hw": [NONE_HW]},
    "portable/crypto_agility": {
        "py": [pytest("prismpath/tests/test_crypto_agility.py", PY_RUN)],
        "rs": [cargo("prismpath-rs", "test_crypto_agility", "prismpath-rs/tests/test_crypto_agility.rs")],
        "js": [("node", "run_crypto_agility.mjs", "prismpath/portable/run_crypto_agility.mjs")],
        "go": [NONE_GO], "hw": [NONE_HW]},
    "portable/crypto_migration": {
        "py": [pytest("prismpath/tests/test_crypto_migration.py", PY_RUN)],
        "rs": [cargo("prismpath-rs", "test_crypto_agility", "prismpath-rs/tests/test_crypto_agility.rs")],
        "js": [("node", "run_crypto_agility.mjs", "prismpath/portable/run_crypto_agility.mjs")],
        "go": [NONE_GO], "hw": [NONE_HW]},
    "portable/distribution": {
        "py": [pytest("prismpath/tests/test_distribution_corpus.py")],
        "rs": [("none", "the distribution envelope and verifier are not yet in prismpath-hotswap-rs; its replay comes with them")],
        "js": [NONE_JS], "go": [NONE_GO],
        "hw": [("none", "the C core of policy distribution is not yet in prismpath-hw; its replay comes with it")]},
    "portable/durable": {
        "py": [("generator", "prismpath/portable/gen_durable_fixtures.py")],
        "rs": [cargo("prismpath-rs", "test_durable", "prismpath-rs/tests/test_durable.rs")],
        "js": [NONE_JS], "go": [NONE_GO], "hw": [NONE_HW]},
    "portable/field_definitions": {
        "py": [pytest("prismpath/tests/test_field_definitions.py", "prismpath/tests/test_field_definitions_tables.py")],
        "rs": [cargo("prismpath-rs", "test_field_definitions", "prismpath-rs/tests/test_field_definitions.rs")],
        "js": [("nodetest", "prismpath/portable/prismpath.test.mjs")],
        "go": [("go", "prismpath-go/conformance_test.go")],
        "hw": [NONE_HW]},
    "portable/flows": {
        "py": [pytest("prismpath/tests/test_engine_surface_corpus.py", "prismpath/tests/test_conformance_vectors.py")],
        "rs": [("bin", "prismpath-rs/src/bin/conformance.rs"),
               cargo("prismpath-rs", "test_engine_surface", "prismpath-rs/tests/test_engine_surface.rs")],
        "js": [("node", "run_vectors.mjs", "prismpath/portable/run_vectors.mjs")],
        "go": [("go", "prismpath-go/conformance_test.go")],
        "hw": [("make", "prismpath-hw/run_vectors.py")]},
    "portable/host_trace": {
        "py": [pytest("prismpath/tests/test_host_trace_corpus.py")],
        "rs": [cargo("prismpath-hotswap-rs", "test_host_trace", "prismpath-hotswap-rs/tests/test_host_trace.rs")],
        "js": [NONE_JS], "go": [NONE_GO], "hw": [NONE_HW]},
    "portable/hotswap": {
        "py": [("generator", "prismpath/portable/gen_hotswap_fixtures.py")],
        "rs": [cargo("prismpath-hotswap-rs", "test_hotswap_conformance", "prismpath-hotswap-rs/tests/test_hotswap_conformance.rs")],
        "js": [NONE_JS], "go": [NONE_GO], "hw": [NONE_HW]},
    "portable/level_m": {
        "py": [pytest("prismpath/tests/test_level_m_conformance.py", PY_RUN)],
        "rs": [cargo("prismpath-rs", "test_proof", "prismpath-rs/tests/test_proof.rs")],
        "js": [("node", "run_level_m.mjs", "prismpath/portable/run_level_m.mjs")],
        "go": [NONE_GO], "hw": [NONE_HW]},
    "portable/locked_flows": {
        "py": [pytest("prismpath/tests/test_causes_rs.py")],
        "rs": [("bin", "prismpath-rs/src/bin/conformance.rs"),
               cargo("prismpath-rs", "test_engine_cross_language", "prismpath-rs/tests/test_engine_cross_language.rs")],
        "js": [("node", "run_p1_conformance.mjs", "prismpath/portable/run_p1_conformance.mjs")],
        "go": [NONE_GO], "hw": [NONE_HW]},
    "portable/merkle_consistency": {
        "py": [pytest("prismpath/tests/test_merkle_consistency.py")],
        "rs": [cargo("prismpath-rs", "test_merkle_consistency", "prismpath-rs/tests/test_merkle_consistency.rs")],
        "js": [("none", "no JavaScript consumer: the in page verifier checks receipt bundles, and the collector feed's "
                        "consistency proofs are checked by the console's Python feed reader")],
        "go": [NONE_GO], "hw": [NONE_HW]},
    "portable/merkle_stream": {
        # test_ebpf_merkle.py compiles and runs prismpath-ebpf/test_merkle.c, merkle.h's replay of this corpus
        "py": [pytest("prismpath/tests/test_merkle_stream.py", "prismpath/tests/test_ebpf_merkle.py")],
        "rs": [cargo("prismpath-rs", "test_merkle_stream", "prismpath-rs/tests/test_merkle_stream.rs")],
        "js": [("node", "run_vectors.mjs", "prismpath/portable/run_vectors.mjs")], "go": [NONE_GO],
        "hw": [("none", "the C target in prismpath-hw keeps no ledger; the eBPF ledger's C merkle.h replays this "
                        "corpus through prismpath/tests/test_ebpf_merkle.py")]},
    "portable/parse_limits": {
        "py": [pytest("prismpath/tests/test_parse_limits_corpus.py")],
        "rs": [cargo("prismpath-rs", "test_parse_limits", "prismpath-rs/tests/test_parse_limits.rs")],
        "js": [NONE_JS], "go": [NONE_GO], "hw": [NONE_HW]},
    "portable/predicates": {
        "py": [pytest("prismpath/tests/test_conformance_drift.py", "prismpath/tests/test_conformance_vectors.py")],
        "rs": [("bin", "prismpath-rs/src/bin/conformance.rs")],
        "js": [("node", "run_vectors.mjs", "prismpath/portable/run_vectors.mjs")],
        "go": [("go", "prismpath-go/conformance_test.go")],
        "hw": [("make", "prismpath-hw/run_vectors.py")]},
    "portable/reach": {
        "py": [pytest("prismpath/tests/test_reach_conformance.py", PY_RUN)],
        "rs": [cargo("prismpath-rs", "test_proof", "prismpath-rs/tests/test_proof.rs")],
        "js": [("node", "run_reach.mjs", "prismpath/portable/run_reach.mjs")],
        "go": [NONE_GO], "hw": [NONE_HW]},
    "portable/receipts": {
        "py": [pytest("prismpath/tests/test_receipt_vectors.py")],
        "rs": [cargo("prismpath-hotswap-rs", "test_receipt_verify", "prismpath-hotswap-rs/tests/test_receipt_verify.rs"),
               cargo("prismpath-telemetry-rs", "test_receipts", "prismpath-telemetry-rs/tests/test_receipts.rs")],
        # the merkle and bundle cases, through merkle.mjs and Mission Control's verify.mjs; the rest are skipped
        "js": [("node", "run_vectors.mjs", "prismpath/portable/run_vectors.mjs")], "go": [NONE_GO], "hw": [NONE_HW]},
    "portable/safety": {
        "py": [pytest("prismpath/tests/test_safety_vectors.py")],
        "rs": [("none", "the content guard is outside the kernel by design (prismpath-rs/CONFORMANCE.md, scope boundary)")],
        "js": [NONE_JS], "go": [NONE_GO], "hw": [NONE_HW]},
    "telemetry/boundary": {
        "py": [pytest("prismpath/telemetry/tests/test_boundary_parity.py")],
        "rs": [cargo("prismpath-telemetry-rs", "test_boundary_parity", "prismpath-telemetry-rs/tests/test_boundary_parity.rs")],
        "js": [NONE_JS], "go": [NONE_GO], "hw": [NONE_HW]},
    "telemetry/concentrator": {
        "py": [pytest("prismpath/telemetry/tests/test_profile_corpora.py")],
        "rs": [cargo("prismpath-telemetry-rs", "test_concentrator", "prismpath-telemetry-rs/tests/test_concentrator.rs")],
        "js": [NONE_JS], "go": [NONE_GO], "hw": [NONE_HW]},
    "telemetry/decisions": {
        "py": [pytest("prismpath/telemetry/tests/test_decisions_preserved.py")],
        "rs": [cargo("prismpath-telemetry-rs", "test_conformance_decisions", "prismpath-telemetry-rs/tests/test_conformance_decisions.rs")],
        "js": [NONE_JS], "go": [NONE_GO], "hw": [NONE_HW]},
    "telemetry/defined_wire": {
        "py": [pytest("prismpath/telemetry/tests/test_defined_fields.py")],
        "rs": [cargo("prismpath-telemetry-rs", "test_defined_fields", "prismpath-telemetry-rs/tests/test_defined_fields.rs")],
        "js": [NONE_JS], "go": [NONE_GO], "hw": [NONE_HW]},
    "telemetry/grouped_band": {
        "py": [pytest("prismpath/telemetry/tests/test_spiral_groups.py")],
        "rs": [cargo("prismpath-telemetry-rs", "test_conformance_grouped_band", "prismpath-telemetry-rs/tests/test_conformance_grouped_band.rs")],
        "js": [NONE_JS], "go": [NONE_GO], "hw": [NONE_HW]},
    "telemetry/inputs": {
        "py": [pytest("prismpath/telemetry/tests/test_acceptance.py")],
        "rs": [cargo("prismpath-telemetry-rs", "test_acceptance", "prismpath-telemetry-rs/tests/test_acceptance.rs")],
        "js": [NONE_JS], "go": [NONE_GO], "hw": [NONE_HW]},
    "telemetry/policy_forms": {
        "py": [pytest("prismpath/telemetry/tests/test_policy_forms.py")],
        "rs": [cargo("prismpath-telemetry-rs", "test_policy_forms", "prismpath-telemetry-rs/tests/test_policy_forms.rs")],
        "js": [NONE_JS], "go": [NONE_GO], "hw": [NONE_HW]},
    "telemetry/receipts": {
        "py": [pytest("prismpath/telemetry/tests/test_receipts.py", "prismpath/telemetry/tests/test_profile_corpora.py")],
        "rs": [cargo("prismpath-telemetry-rs", "test_receipts", "prismpath-telemetry-rs/tests/test_receipts.rs"),
               cargo("prismpath-hotswap-rs", "test_receipt_verify", "prismpath-hotswap-rs/tests/test_receipt_verify.rs")],
        "js": [NONE_JS], "go": [NONE_GO], "hw": [NONE_HW]},
    "telemetry/receipt_stream": {
        "py": [pytest("prismpath/telemetry/tests/test_profile_corpora.py")],
        "rs": [cargo("prismpath-telemetry-rs", "test_receipts", "prismpath-telemetry-rs/tests/test_receipts.rs")],
        "js": [NONE_JS], "go": [NONE_GO], "hw": [NONE_HW]},
    "telemetry/refresh": {
        "py": [pytest("prismpath/telemetry/tests/test_profile_corpora.py")],
        "rs": [cargo("prismpath-telemetry-rs", "test_refresh", "prismpath-telemetry-rs/tests/test_refresh.rs")],
        "js": [NONE_JS], "go": [NONE_GO], "hw": [NONE_HW]},
    "telemetry/replay": {
        "py": [pytest("prismpath/telemetry/tests/test_profile_corpora.py")],
        "rs": [cargo("prismpath-telemetry-rs", "test_replay", "prismpath-telemetry-rs/tests/test_replay.rs")],
        "js": [NONE_JS], "go": [NONE_GO], "hw": [NONE_HW]},
    "telemetry/spiral": {
        "py": [pytest("prismpath/telemetry/tests/test_spiral.py")],
        "rs": [cargo("prismpath-telemetry-rs", "test_conformance_spiral", "prismpath-telemetry-rs/tests/test_conformance_spiral.rs")],
        "js": [NONE_JS], "go": [NONE_GO], "hw": [NONE_HW]},
}


def corpus_files() -> list[str]:
    found = []
    for prefix, directory in (("portable", PORTABLE), ("telemetry", TELEMETRY)):
        for path in sorted((ROOT / directory).glob("*.json")):
            found.append(f"{prefix}/{path.stem}")
    return found


def corpus_path(corpus: str) -> str:
    prefix, stem = corpus.split("/")
    return f"{PORTABLE if prefix == 'portable' else TELEMETRY}/{stem}.json"


def evidence_of(consumer: tuple, corpus: str) -> list[str]:
    kind = consumer[0]
    if kind == "pytest":
        return list(consumer[1])
    if kind == "cargo":
        return [consumer[3]]
    if kind in ("bin", "nodetest", "go", "make"):
        return [consumer[1]]
    if kind == "node":
        return [consumer[2]]
    if kind == "generator":
        return [consumer[1]]
    return []


def check_table() -> list[str]:
    """Problems in the consumer table itself, without running anything."""
    problems = []
    on_disk = corpus_files()
    for corpus in on_disk:
        if corpus not in CONSUMERS:
            problems.append(f"{corpus}: a corpus on disk with no row in CONSUMERS")
    for corpus in CONSUMERS:
        if corpus not in on_disk:
            problems.append(f"{corpus}: a row in CONSUMERS for a corpus that is not on disk")
            continue
        name = Path(corpus_path(corpus)).name
        stem = Path(name).stem  # a drift test may reach the corpus through its generator module, gen_<stem>
        for impl in IMPLS:
            rows = CONSUMERS[corpus].get(impl)
            if not rows:
                problems.append(f"{corpus}/{impl}: no decision (a consumer, a generator note or a reason)")
                continue
            for consumer in rows:
                if consumer[0] == "none":
                    if len(consumer[1]) < 20:
                        problems.append(f"{corpus}/{impl}: the reason for not consuming is too short to be one")
                    continue
                files = evidence_of(consumer, corpus)
                for evidence in files:
                    if not (ROOT / evidence).is_file():
                        problems.append(f"{corpus}/{impl}: evidence file {evidence} does not exist")
                if consumer[0] == "generator":
                    continue
                # for a group of pytest files at least one has to name the corpus; any other kind has one file
                texts = [(ROOT / e).read_text(encoding="utf-8", errors="replace") for e in files if (ROOT / e).is_file()]
                mentions = [t for t in texts if name in t or f"gen_{stem}" in t]
                # the node wrappers and the portable test runner reach the corpus through the runner script
                if not mentions and consumer[0] not in ("node", "make"):
                    problems.append(f"{corpus}/{impl}: none of {files} mentions {name}")
    return problems


# ---------------------------------------------------------------------------------------------- running

class Result:
    def __init__(self, ok: bool, detail: str, skips: list[str]):
        self.ok, self.detail, self.skips = ok, detail, skips


def run(command: list[str], cwd: Path, env: dict[str, str], timeout: int = 1800) -> tuple[int, str]:
    process = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
    return process.returncode, process.stdout + "\n" + process.stderr


def summarize_pytest(code: int, text: str) -> Result:
    tail = [line for line in text.splitlines() if re.search(r"\d+ (passed|failed|skipped|error)", line)]
    counts = tail[-1].strip(" =") if tail else "no pytest summary"
    skips = sorted({re.sub(r"^SKIPPED \[\d+\] ", "", line) for line in text.splitlines() if line.startswith("SKIPPED")})
    return Result(code == 0, counts, skips)


def summarize_cargo(code: int, text: str) -> Result:
    passed = failed = ignored = 0
    for match in re.finditer(r"test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored", text):
        passed += int(match[1]); failed += int(match[2]); ignored += int(match[3])
    skips = sorted({line.strip() for line in text.splitlines() if "SKIP" in line})
    if ignored:
        skips.append(f"{ignored} test(s) marked ignored")
    return Result(code == 0 and failed == 0 and passed > 0, f"{passed} passed, {failed} failed", skips)


def summarize_runner(code: int, text: str) -> Result:
    """The node runners, the Rust binary, the C target and go: keep their own N/N lines."""
    lines = [line.strip() for line in text.splitlines()
             if re.search(r"\d+\s*/\s*\d+|\bpass\b.*\bFAIL\b|CONFORMANT|^ok\s|^PASS$", line)]
    keep = [line for line in lines if not line.startswith("excluded") and "NON" not in line.split("CONFORMANT")[0]][:6]
    skips = sorted({line for line in lines if "skipped" in line or "excluded" in line})
    return Result(code == 0, " | ".join(keep[:4]) or f"exit {code}", skips)


def summarize_nodetest(code: int, text: str) -> Result:
    counts = dict(re.findall(r"^[#ℹ] (pass|fail|skipped) (\d+)", text, re.M))
    detail = ", ".join(f"{counts.get(key, '0')} {key}" for key in ("pass", "fail", "skipped"))
    return Result(code == 0, detail, [f"{counts['skipped']} node test(s) skipped"] if counts.get("skipped", "0") != "0" else [])


def build_command(consumer: tuple, py: str) -> tuple[str, list[str], Path, "callable"]:
    kind = consumer[0]
    if kind == "pytest":
        return ("pytest " + " ".join(consumer[1]),
                [py, "-m", "pytest", "-q", "-rs", "-p", "no:cacheprovider", *consumer[1]], ROOT, summarize_pytest)
    if kind == "cargo":
        return (f"cargo test -p {consumer[1]} --test {consumer[2]}",
                ["cargo", "test", "-p", consumer[1], "--test", consumer[2], "--", "--nocapture"], ROOT, summarize_cargo)
    if kind == "bin":
        return ("cargo run conformance",
                ["cargo", "run", "-q", "-p", "prismpath-rs", "--bin", "conformance", "--", str(ROOT / PORTABLE)],
                ROOT, summarize_runner)
    if kind == "node":
        return (f"node {consumer[1]}", ["node", f"prismpath/portable/{consumer[1]}", PORTABLE], ROOT, summarize_runner)
    if kind == "nodetest":
        return ("node --test prismpath.test.mjs", ["node", "--test", "prismpath/portable/prismpath.test.mjs"],
                ROOT, summarize_nodetest)
    if kind == "go":
        return ("go test", ["go", "test", "-count=1", "./...", "-v"], ROOT / "prismpath-go", summarize_runner)
    if kind == "make":
        return ("make cert", ["make", "-C", "prismpath-hw", "cert"], ROOT, summarize_runner)
    raise ValueError(kind)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="validate the consumer table only")
    parser.add_argument("--only", action="append", choices=IMPLS, help="run only this implementation (repeatable)")
    parser.add_argument("--allow-skips", action="store_true", help="do not require the cross-language legs to run")
    parser.add_argument("--python", default=sys.executable, help="interpreter for pytest and PRISMPATH_PYTHON")
    args = parser.parse_args()

    problems = check_table()
    for problem in problems:
        print(f"TABLE  {problem}")
    if args.check or problems:
        print(f"consumer table: {len(CONSUMERS)} corpora, {len(problems)} problem(s)")
        return 1 if problems else 0

    env = dict(os.environ)
    env.setdefault("PRISMPATH_PYTHON", args.python)
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    if not args.allow_skips:
        env["PRISMPATH_REQUIRE_CROSS_LANGUAGE"] = "1"
    wanted = set(args.only or IMPLS)
    tools_needed = {"rs": "cargo", "js": "node", "go": "go", "hw": "make"}

    cache: dict[str, Result] = {}
    shared: dict[str, int] = {}
    for corpus, per_impl in CONSUMERS.items():
        for impl in wanted:
            for consumer in per_impl[impl]:
                if consumer[0] not in ("none", "generator"):
                    shared[build_command(consumer, args.python)[0]] = shared.get(build_command(consumer, args.python)[0], 0) + 1

    failures = 0
    print(f"{'corpus':28} {'impl':3}  result")
    for corpus, per_impl in CONSUMERS.items():
        for impl in IMPLS:
            if impl not in wanted:
                continue
            for consumer in per_impl[impl]:
                if consumer[0] == "none":
                    print(f"{'N/A':5}{corpus:28} {impl:3}  not claimed: {consumer[1]}")
                    continue
                if consumer[0] == "generator":
                    print(f"{'GEN':5}{corpus:28} {impl:3}  Python writes this corpus ({consumer[1]}); no Python consumer test reads it back")
                    continue
                label, command, cwd, summarize = build_command(consumer, args.python)
                tool = tools_needed.get(impl)
                if tool and shutil.which(tool) is None:
                    failures += 1
                    print(f"{'FAIL':5}{corpus:28} {impl:3}  {tool} is not installed, so {label} could not run")
                    continue
                if label not in cache:
                    code, text = run(command, cwd, env)
                    cache[label] = summarize(code, text)
                    if not cache[label].ok:
                        cache[label].detail += "\n" + "\n".join(text.splitlines()[-12:])
                result = cache[label]
                note = f" (shared by {shared[label]})" if shared[label] > 1 else ""
                state = "PASS" if result.ok and not result.skips else ("PART" if result.ok else "FAIL")
                # PART: the run passed but itself reports cases it did not take (the 80 engine option flows the JS and Go kernels do not run, the vectors outside the C target's declared subset)
                if state == "FAIL":
                    failures += 1
                skip_note = f"  [skips: {'; '.join(result.skips)[:300]}]" if result.skips else ""
                print(f"{state:5}{corpus:28} {impl:3}  {label}: {result.detail}{note}{skip_note}")
    print(f"corpora: {len(CONSUMERS)}, commands run: {len(cache)}, failures: {failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
