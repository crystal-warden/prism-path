# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""A differential run as evidence (docs/design/spec-verified-core.md, section 11), at CI size.

The Python reference and the Rust port each produce a run of the same cases with test keys generated
for the test: image attestations under the authority key, a canon/2 receipt per decision, and one root
statement over the receipts under the instance key, all canon/2. Each verifier checks the other's run, every receipt
is replayed through the oracle, and a run altered in any part is refused. The oracle is built by `lake
build` in formal/; without it the test skips, unless PRISMPATH_REQUIRE_CORE_ORACLE is set.
"""
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if not (ROOT / "formal" / "diff" / "core_evidence.py").exists():
    pytest.skip("formal/diff is not beside this package (an installed wheel)", allow_module_level=True)
pytest.importorskip("cryptography")
sys.path.insert(0, str(ROOT / "formal" / "diff"))
import core_diff  # noqa: E402
import core_evidence  # noqa: E402

CASES = 400
SEED = 11


def _oracle():
    if not core_diff.ORACLE.exists():
        if os.environ.get("PRISMPATH_REQUIRE_CORE_ORACLE"):
            pytest.fail(f"PRISMPATH_REQUIRE_CORE_ORACLE is set and {core_diff.ORACLE} is not built")
        pytest.skip("the Lean oracle is not built (cd formal && lake build)")


def _rust_example():
    target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
    binary = target / "debug" / "examples" / "core_evidence"
    if not binary.exists():
        if not shutil.which("cargo"):
            if os.environ.get("PRISMPATH_REQUIRE_CORE_ORACLE"):
                pytest.fail("PRISMPATH_REQUIRE_CORE_ORACLE is set and there is no cargo for the Rust verifier")
            pytest.skip("no cargo for the Rust producer and verifier")
        subprocess.run(["cargo", "build", "-q", "-p", "prismpath-hotswap-rs", "--example", "core_evidence"], cwd=ROOT,
                       check=True)
    return binary


@pytest.fixture(scope="module")
def runs(tmp_path_factory):
    _oracle()
    base = tmp_path_factory.mktemp("core_evidence")
    cases = base / "cases.jsonl"
    core_evidence.write_cases(core_diff.generate(CASES, SEED), cases)
    core_evidence.produce(cases, base / "run-py", base / "keys-py")
    rust = _rust_example()
    produced = subprocess.run([str(rust), "produce", "--from", str(cases), "--out", str(base / "run-rs"),
                               "--keys", str(base / "keys-rs")], capture_output=True, text=True)
    assert produced.returncode == 0, produced.stdout + produced.stderr
    return base, rust


def _rust_verify(rust, run, *pins):
    return subprocess.run([str(rust), "verify", str(run), "--sample", "all", *pins], capture_output=True, text=True)


def test_each_verifies_its_own_and_the_others_run(runs):
    base, rust = runs
    for run, keys in (("run-py", "keys-py"), ("run-rs", "keys-rs")):
        pins = ["--pin-authority", str(base / keys / "authority.pub"), "--pin-instance", str(base / keys / "instance.pub")]
        summary = core_evidence.verify(base / run, sample=None, pin_authority=pins[1], pin_instance=pins[3])
        assert summary["root_statement"] == "signed" and summary["disagree"] == 0 and summary["agree"] > 0, summary
        assert summary["replayed"] == summary["receipts"] > CASES, summary
        checked = _rust_verify(rust, base / run, *pins)
        assert checked.returncode == 0 and "root statement signed" in checked.stdout and " 0 disagree" in checked.stdout, \
            checked.stdout + checked.stderr


def test_the_two_runs_receipt_the_same_decisions(runs):
    """The reference and the port decide every case alike, so their receipts are the same bytes but for the
    decider; their keys, signatures and root statements differ."""
    base, _rust = runs
    python = (base / "run-py" / "receipts.jsonl").read_bytes().replace(b'"decider":"python"', b'"decider":"X"')
    rust = (base / "run-rs" / "receipts.jsonl").read_bytes().replace(b'"decider":"rust"', b'"decider":"X"')
    assert python == rust
    assert (base / "run-py" / "cases.jsonl").read_bytes() == (base / "run-rs" / "cases.jsonl").read_bytes()
    assert (base / "run-py" / "authority.pub").read_bytes() != (base / "run-rs" / "authority.pub").read_bytes()


def _altered(base, run, name, change, tmp_path):
    copy = tmp_path / f"{run}-{name}"
    shutil.copytree(base / run, copy)
    path = copy / name
    path.write_bytes(change(path.read_bytes()))
    return copy


def _flip_decision(data: bytes) -> bytes:
    return data.replace(b'"decision":"route","format"', b'"decision":"refuse","format"', 1)


def _flip_signature(data: bytes) -> bytes:
    at = data.index(b'"sig":"') + len(b'"sig":"')
    return data[:at] + (b"1" if data[at:at + 1] == b"0" else b"0") + data[at + 1:]


ALTERATIONS = [
    ("receipts.jsonl", _flip_decision, "root statement"),
    ("receipts.jsonl", lambda data: data[: data.rindex(b"\n", 0, len(data) - 1) + 1], "root statement"),
    ("cases.jsonl", lambda data: data.replace(b'"readings":["7b', b'"readings":["5b', 1), "cases.jsonl"),
    ("images.jsonl", lambda data: _flip_signature(data), "images.jsonl"),
    ("run.json", lambda data: data.replace(b'"excluded":[', b'"excluded":["none",', 1), "root statement"),
    ("instance.pub", lambda data: bytes(32 - len(data)) + data[::-1], "keys"),
    ("receipts.roots.jsonl", _flip_signature, "root statement"),
    # the clock as a float of seconds: canon/2 refuses a float, so the statement does not read
    ("receipts.roots.jsonl", lambda data: re.sub(rb'"time_us":(\d+)', lambda m: b'"time_us":' + m.group(1)[:-6] + b"." +
                                                m.group(1)[-6:], data), "root statement"),
    # a later clock: the signature no longer covers the body
    ("receipts.roots.jsonl", lambda data: re.sub(rb'"time_us":(\d+)', lambda m: b'"time_us":' + str(int(m.group(1)) + 1)
                                                .encode(), data), "root statement"),
    # the same members spelled with whitespace: not the canonical canon/2 bytes
    ("receipts.roots.jsonl", lambda data: data.replace(b'","', b'", "', 1), "root statement"),
    # a second statement appended
    ("receipts.roots.jsonl", lambda data: data + data, "root statement"),
]


@pytest.mark.parametrize("name,change,why", ALTERATIONS, ids=[f"{item[0]}-{index}" for index, item in enumerate(ALTERATIONS)])
def test_an_altered_run_is_refused_by_both(runs, tmp_path, name, change, why):
    base, rust = runs
    for run in ("run-py", "run-rs"):
        copy = _altered(base, run, name, change, tmp_path)
        assert (copy / name).read_bytes() != (base / run / name).read_bytes(), (name, run)
        with pytest.raises(core_evidence.Bad):
            core_evidence.verify(copy, sample=20)
        checked = _rust_verify(rust, copy)
        assert checked.returncode == 1 and "REFUSED" in checked.stdout, (name, run, checked.stdout)


def test_a_receipt_resigned_with_a_wrong_decision_fails_the_replay(runs, tmp_path):
    """Whoever holds the instance key can sign anything, so the root statement alone does not make a
    decision true: the replay through the oracle is what refuses a signed false receipt."""
    from prismpath.kernel import canon2
    from prismpath.ledgers import root_statement
    base, rust = runs
    copy = tmp_path / "resigned"
    shutil.copytree(base / "run-py", copy)
    lines = (copy / "receipts.jsonl").read_bytes().split(b"\n")[:-1]
    for number, line in enumerate(lines):
        receipt = canon2.loads(line)
        if receipt["decision"] == "route":
            receipt["target"] = receipt["target"] + "x"
            lines[number] = canon2.dumps(receipt)
            break
    (copy / "receipts.jsonl").write_bytes(b"".join(line + b"\n" for line in lines))
    leaves = [core_evidence.sha256_hex(line) for line in lines]
    instance = root_statement.InstanceKey.load(str(base / "keys-py" / "instance.key"))
    statement = core_evidence.make_root_statement(instance, root_statement.merkle_root(leaves), len(leaves),
                                                  (copy / "run.json").read_bytes().rstrip(b"\n"))
    (copy / "receipts.roots.jsonl").write_bytes(canon2.dumps(statement) + b"\n")
    with pytest.raises(core_evidence.Bad, match="differ from the oracle"):
        core_evidence.verify(copy, sample=None)
    checked = _rust_verify(rust, copy)
    assert checked.returncode == 1 and "differs from the oracle" in checked.stdout, checked.stdout


def test_a_foreign_pin_is_refused(runs):
    base, rust = runs
    with pytest.raises(core_evidence.Bad, match="pinned"):
        core_evidence.verify(base / "run-py", sample=5, pin_authority=str(base / "keys-rs" / "authority.pub"),
                             pin_instance=str(base / "keys-py" / "instance.pub"))
    checked = _rust_verify(rust, base / "run-rs", "--pin-authority", str(base / "keys-rs" / "authority.pub"),
                           "--pin-instance", str(base / "keys-py" / "instance.pub"))
    assert checked.returncode == 1 and "pinned" in checked.stdout, checked.stdout


def test_the_root_statement_is_canon2_with_an_integer_clock(runs):
    """The whole run is canon/2: the root statement reads under canon/2, is its own canonical spelling, holds
    integers and strings only, its time an integer count of microseconds, and is signed over its own domain
    prefix, so the canon/1 statement format of audit logs is not accepted in its place."""
    from prismpath.kernel import canon2
    base, _rust = runs
    for run in ("run-py", "run-rs"):
        line = (base / run / "receipts.roots.jsonl").read_bytes().rstrip(b"\n")
        statement = canon2.loads(line)
        assert canon2.dumps(statement) == line
        assert statement["format"] == core_evidence.ROOT_FORMAT and set(statement) == set(core_evidence.ROOT_MEMBERS)
        assert type(statement["time_us"]) is int and statement["time_us"] > 1_700_000_000 * 10 ** 6
        for name in ("run.json", "images.jsonl", "receipts.jsonl", "cases.jsonl"):
            for row in (base / run / name).read_bytes().split(b"\n")[:-1]:
                assert canon2.dumps(canon2.loads(row)) == row, (run, name)


def test_a_canon1_root_statement_is_refused(runs, tmp_path):
    """The audit log's statement format (canon/1, an ISO time, its own domain) signed over the same root with
    the run's instance key does not pass as the run's root statement."""
    import json
    from prismpath.ledgers import root_statement
    base, rust = runs
    copy = tmp_path / "canon1"
    shutil.copytree(base / "run-py", copy)
    lines = (copy / "receipts.jsonl").read_bytes().split(b"\n")[:-1]
    leaves = [core_evidence.sha256_hex(line) for line in lines]
    instance = root_statement.InstanceKey.load(str(base / "keys-py" / "instance.key"))
    statement = root_statement.make_statement(
        instance, log=core_evidence.LOG_CORE_RUN, seq=0, root=root_statement.merkle_root(leaves), leaves=len(leaves),
        prev="", trigger="core-run",
        policy={"core_run_sha256": core_evidence.sha256_hex((copy / "run.json").read_bytes().rstrip(b"\n"))})
    (copy / "receipts.roots.jsonl").write_text(json.dumps(statement, sort_keys=True) + "\n")
    with pytest.raises(core_evidence.Bad, match="root statement"):
        core_evidence.verify(copy, sample=5)
    checked = _rust_verify(rust, copy)
    assert checked.returncode == 1 and "root statement" in checked.stdout, checked.stdout


def _image(fields, *whens):
    from prismpath.kernel import canon2
    return canon2.dumps({"format": "prismpath.core/1", "fields": fields,
                         "rules": [{"target": f"t{number}", "when": when} for number, when in enumerate(whens)]})


# images at the edges of the ported check: a counter read first, a counter after an earlier problem, a counter
# in a definition's name, a decimal past the digit bound (the threshold on no field), integers spelled wider
# than Python converts by default, an exponent with leading zeros, and the order of definitions
EDGE_IMAGES = [
    _image({"x": "int"}, ["cmp", "visits", ">=", ["num", 1]], ["cmp", "x", ">", ["num", 2]]),
    _image({"x": "int"}, ["cmp", "x", "==", ["num", "2.5"]], ["cmp", "visits", ">=", ["num", 1]]),
    _image({"x": "int"}, ["and", ["cmp", "x", "==", ["num", "99999999999999999999"]], ["truthy", "error_count"]]),
    _image({"x": "int"}, ["and", ["truthy", "error_count"], ["cmp", "x", "==", ["num", 2]]]),
    _image({"x": "bogus"}, ["truthy", "visits"]),
    _image({"visits": "int"}, ["truthy", "x"]),
    _image({"r": "fixed scale=10 rounding=exact"}, ["cmp", "r", "==", ["num", "0." + "1" * 29]]),
    _image({"r": "fixed scale=10 rounding=exact"}, ["cmp", "r", "==", ["num", "1" * 5000]]),
    _image({"r": "fixed scale=10 rounding=exact"}, ["cmp", "r", "==", ["num", "-" + "9" * 5000]]),
    _image({"r": "fixed scale=10 rounding=exact"}, ["cmp", "r", "==", ["num", "0." + "0" * 60 + "1"]]),
    _image({"r": "fixed scale=10 rounding=exact"}, ["cmp", "r", "==", ["num", "0.0" + "0" * 60]]),
    _image({"r": "fixed scale=10 rounding=exact"}, ["cmp", "r", "==", ["num", "1e000000000000000000000000001"]]),
    _image({"r": "fixed scale=10 rounding=exact"}, ["cmp", "r", "==", ["num", "9" * 28 + "e30"]]),
    _image({"x": "int min=" + "0" * 5000 + "1"}, ["cmp", "x", "==", ["num", 1]]),
    _image({"x": "int max=" + "9" * 5000}, ["cmp", "x", "==", ["num", 1]]),
    _image({"b": "int", "a": "int min=5 max=1"}, ["cmp", "b", "==", ["num", 1]]),
    _image({"a": "category absent=allowed"}, ["cmp", "a", "==", ["str", "q"]], ["truthy", "visits"]),
]


def test_the_ported_policy_check_is_the_oracles(runs):
    """The producers decide `engine-counter` exclusions with the oracle's own check of an image, ported from Lean
    to Python (`core_policy`) and to Rust (`oracle_policy`); on every image of the run and on the edge images
    above, both ports name what the oracle names: accepted, or the cause, code, field and reason."""
    base, rust = runs
    cases = core_evidence.read_cases(base / "cases.jsonl")
    cases += [{"id": f"edge{number}", "image": image, "flow": None, "flow_why": None, "readings": []}
              for number, image in enumerate(EDGE_IMAGES)]
    source = base / "scope-cases.jsonl"
    from prismpath.kernel import canon2
    source.write_bytes(b"".join(canon2.dumps({"case": case["id"], "image": case["image"].hex(), "flow": case["flow"],
                                              "readings": []}) + b"\n" for case in cases))
    lines = subprocess.run([str(rust), "policy", "--from", str(source)], capture_output=True, check=True).stdout
    counts = core_evidence.scope_check(core_evidence.read_cases(source), rust_lines=lines.split(b"\n")[:-1])
    assert counts["first"] is None, counts
    assert counts["python"]["agree"] == counts["rust"]["agree"] == len(cases), counts
    assert counts["counter"] > 0 and counts["accepted"] > 0, counts
    edge = core_evidence.oracle_policies(core_evidence.read_cases(source)[-len(EDGE_IMAGES):])
    assert [item[0] if item else None for item in edge[:6]] == [
        "policy:engine-counter", "image:unknown-type", "policy:threshold", "policy:engine-counter", "policy:definition",
        "policy:definition"], edge


def test_only_the_oracles_counter_refusals_are_excluded(runs):
    """A case is excluded as `engine-counter` exactly when the oracle refuses its image for reading an engine
    counter; an image that mentions a counter but is refused for an earlier problem is receipted, with the
    oracle's refusal."""
    from prismpath.kernel import canon2
    base, _rust = runs
    cases = core_evidence.read_cases(base / "cases.jsonl")
    want = core_evidence.oracle_policies(cases)
    excluded = {row["case"]: row["why"] for row in canon2.loads((base / "run-py" / "run.json").read_bytes().rstrip(b"\n"))["excluded"]}
    for case, policy in zip(cases, want):
        counter = policy is not None and policy[0] == "policy:engine-counter"
        assert (excluded.get(case["id"]) == "engine-counter") == counter, (case["id"], policy, excluded.get(case["id"]))
    mentions = [case for case in cases if b'"visits"' in case["image"] or b'"error_count"' in case["image"]]
    receipted = [case for case in mentions if case["id"] not in excluded]
    assert receipted, "the CI run holds images that mention a counter and are receipted"
