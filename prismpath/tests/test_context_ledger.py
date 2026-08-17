# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""context_ledger — the attestable context surface for frozen models: chaining, Merkle root,
manifest binding, tamper evidence, and the structural privacy property (hashes only, ever)."""
import hashlib
import json

from prismpath import ledger_airgap
from prismpath.context_ledger import GENESIS, ContextLedger, verify_chain


def _ledger():
    led = ContextLedger()
    led.commit("system", "You are a careful assistant. Defer dosing to clinicians.")
    led.commit("retrieval", "monograph: acetaminophen pediatric guidance v7")
    led.commit("user", "my child weighs 19kg, how much should I give?")
    return led


def test_chain_binds_order_and_content():
    led = _ledger()
    assert verify_chain(led.segments)
    assert led.head() != GENESIS
    # deterministic: same content -> same head
    assert _ledger().head() == led.head()


def test_edit_reorder_and_deletion_all_flip_the_chain():
    led = _ledger()
    edited = [dict(s) for s in led.segments]
    edited[1]["leaf"] = hashlib.sha256(b"swapped monograph").hexdigest()
    assert not verify_chain(edited)

    reordered = [dict(led.segments[i]) for i in (1, 0, 2)]
    for i, s in enumerate(reordered):
        s["idx"] = i
    assert not verify_chain(reordered)

    deleted = [dict(led.segments[i]) for i in (0, 2)]
    deleted[1]["idx"] = 1
    assert not verify_chain(deleted)


def test_root_and_inclusion_proof():
    led = _ledger()
    root = led.root()
    assert len(root) == 64
    p = led.prove(1)
    assert p["root"] == root
    from prismpath import ledger_ots
    assert ledger_ots.verify_leaf(p["leaf"], p["path"], root)


def test_attest_binds_policy_gate_model_and_verifies():
    led = _ledger()
    m = led.attest("sha256:deadbeef", "steering_policy@v4", "NousResearch/Meta-Llama-3.1-8B-Instruct")
    assert ledger_airgap.verify_manifest(m)
    assert m["root"] == led.root()
    assert m["ingestion_hashes"] == led.leaves
    assert m["policy_hash"] == "sha256:deadbeef"
    assert m["gate_id"] == "steering_policy@v4"
    assert m["label"].endswith(led.head())          # order commitment rides in the label
    # tampering with any bound field breaks the content address
    bad = dict(m)
    bad["root"] = "e" * 64
    assert not ledger_airgap.verify_manifest(bad)


def test_privacy_no_content_in_ledger_or_manifest():
    led = _ledger()
    secret_text = "my child weighs 19kg, how much should I give?"
    artifact = json.dumps({"segments": led.segments,
                           "manifest": led.attest(None, None, "model-x")})
    assert secret_text not in artifact
    assert "19kg" not in artifact


def test_salted_segment_defeats_guessing():
    plain = ContextLedger()
    plain.commit("user", "yes")
    salted = ContextLedger()
    salted.commit("user", "yes", salt_secret="enclave-secret")
    guess = hashlib.sha256(b"yes").hexdigest()
    assert plain.segments[0]["leaf"] == guess          # unsalted low-entropy IS guessable
    assert salted.segments[0]["leaf"] != guess         # salted is not
    assert salted.segments[0]["salted"] is True


def test_empty_ledger_is_well_defined():
    led = ContextLedger()
    assert led.head() == GENESIS
    assert led.root() == ""
    assert verify_chain([])
