# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The frozen receipt verification vectors (portable/conformance/receipts.json).

Signed root statements, audit logs, receipt bundles, flow manifests and the canonical JSON under them,
each with the verdict the Python reference gives, so a second implementation can be held to it. Three
guarantees, enforced on every run:

  1. NO SILENT DRIFT. Regenerating the set from the live reference reproduces the committed file
     byte for byte. The keys are derived from fixed labels and the clocks are fixed, so this is
     exact, and a change in what the reference decides shows up as a diff to review.
  2. THE FILE MEANS WHAT IT SAYS. Every committed case, replayed from its own data through the live
     Python verifiers, gives the committed verdict.
  3. THE RUST VERIFIER AGREES. `prismpath-hotswap-rs` replays the same file and must give every
     verdict (skipped where cargo is not installed; CI runs the crate's tests directly as well).
"""
import json
import shutil
import subprocess

import pytest

pytest.importorskip("cryptography")

from prismpath.tests._repo import repo_file  # noqa: E402

VECTORS = repo_file("prismpath", "portable", "conformance", "receipts.json")
CARGO = shutil.which("cargo")


def _generator():
    import importlib.util
    spec = importlib.util.spec_from_file_location("gen_receipt_fixtures", VECTORS.parent.parent / "gen_receipt_fixtures.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GEN = _generator()
DOC = json.loads(VECTORS.read_text(encoding="utf-8"))
CASES = DOC["cases"]


def test_no_silent_drift():
    assert GEN.render() == VECTORS.read_text(encoding="utf-8"), (
        "receipts.json no longer matches what the live reference produces. If the change is intended, "
        "run `python prismpath/portable/gen_receipt_fixtures.py` and review the diff.")


def test_the_set_covers_every_kind_and_every_named_tamper():
    kinds = {case["kind"] for case in CASES}
    assert kinds == {"canon", "merkle", "trail", "bundle", "flow", "floor", "separation"}
    findings = {finding["finding"] for case in CASES if case["kind"] == "trail" for finding in case["expect"]["findings"]}
    assert findings >= {"bad_format", "key_id_mismatch", "bad_signature", "unpinned_key", "authority_key", "chain_broken",
                        "leaf_count_regressed", "log_truncated", "root_mismatch", "no_statements", "interrupted_statement"}
    statuses = {case["expect"]["status"] for case in CASES if case["kind"] == "trail"}
    assert statuses == {"signed", "signed-unpinned", "unsigned", "invalid"}
    causes = {cause for case in CASES if case["kind"] == "flow" for cause in case["expect"]["causes"]}
    assert causes == {"sig:missing", "sig:invalid", "sig:revoked-key", "manifest:key-id-mismatch", "manifest:bad-format",
                      "flow:sha256-mismatch", "flow:version-replay"}
    assert any(case["kind"] == "flow" and case["expect"]["ok"] for case in CASES)


def _ids(kind):
    return [pytest.param(case, id=case["name"]) for case in CASES if case["kind"] == kind]


@pytest.mark.parametrize("case", _ids("canon"))
def test_canon(case):
    from prismpath import canon
    assert canon.canonical_compact(json.loads(case["json"])).decode("ascii") == case["expect"]


@pytest.mark.parametrize("case", _ids("merkle"))
def test_merkle(case):
    from prismpath.ledgers import ledger_ots, root_statement as rs
    assert rs.merkle_root(case["leaves"]) == case["root"]
    root, paths = ledger_ots.merkle_root_and_paths(case["leaves"])
    assert [[list(step) for step in path] for path in paths] == case["paths"]
    for leaf, path in zip(case["leaves"], case["paths"], strict=True):
        assert ledger_ots.verify_leaf(leaf, path, root)


@pytest.mark.parametrize("case", _ids("trail"))
def test_trail(case):
    pinned = [bytes.fromhex(key) for key in case["pinned"]]
    assert GEN.reference_trail(case["log_text"], case["statements_text"], pinned) == case["expect"]


@pytest.mark.parametrize("case", _ids("bundle"))
def test_bundle(case):
    pinned = [bytes.fromhex(key) for key in case["pinned"]]
    assert GEN.reference_bundle(case["bundle"], pinned) == case["expect"]


@pytest.mark.parametrize("case", _ids("flow"))
def test_flow(case):
    got = GEN.reference_flow(case["flow_text"].encode("utf-8"), case["manifest_text"],
                             None if case["sig_hex"] is None else bytes.fromhex(case["sig_hex"]),
                             [bytes.fromhex(key) for key in case["pubs"]], case["revoked"], case["floor"])
    assert got == case["expect"]


@pytest.mark.parametrize("case", _ids("floor"))
def test_floor(case, tmp_path):
    from prismpath.hotswap import flow_authority as fa
    floor = fa.VersionFloor(str(tmp_path / "flow_versions.json"))
    admitted = []
    for step in case["steps"]:
        admitted.append(floor.admits(step["manifest"]))
        floor.accept(step["manifest"])
    assert {"admits": admitted, "entries": floor.entries} == case["expect"]


@pytest.mark.parametrize("case", _ids("separation"))
def test_separation(case):
    from prismpath.ledgers import root_statement as rs
    key = None
    if case["instance_key_id"] is not None:
        key = rs.InstanceKey(None, b"\x00" * 32)
        key.key_id = case["instance_key_id"]
        key.fingerprint = rs.fingerprint(key.key_id)
    try:
        rs.check_separation(key, case["authority_key_ids"])
        got = {"ok": True}
    except ValueError:
        got = {"ok": False}
    assert got == case["expect"]


@pytest.mark.skipif(CARGO is None, reason="cargo not installed: the Rust verifier is untested here")
def test_the_rust_verifier_agrees_on_every_case():
    crate = repo_file("prismpath-hotswap-rs")
    process = subprocess.run([CARGO, "test", "--manifest-path", str(crate / "Cargo.toml"), "--test", "test_receipt_verify", "-q"],
                             capture_output=True, text=True, timeout=900)
    assert process.returncode == 0, f"prismpath-hotswap-rs disagrees with the Python reference:\n{process.stdout[-3000:]}\n{process.stderr[-2000:]}"
