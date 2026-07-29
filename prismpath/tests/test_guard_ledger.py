"""Tests for wiring guard verdicts into the attested trail.

The load-bearing assertions are about what the trail *binds* and what it *refuses to leak*: an entry
that records a refusal without recording which policy produced it is not an audit record, and an
entry that lets a bystander recover the learner's prompt is a privacy defect wearing an audit badge.
"""

import os

import pytest

from prismpath.audit_log import AuditLog
from prismpath.guard import Blocked, compose, guarded_exchange, parse_policy_file
from prismpath.guard_ledger import VERDICT_ACTION, attest_verdicts, verdict_recorder

POLICIES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "policies")
FLOOR = os.path.join(POLICIES_DIR, "statutory_floor.md")


@pytest.fixture
def guard():
    return compose([parse_policy_file(FLOOR)])


@pytest.fixture
def log(tmp_path):
    return AuditLog(str(tmp_path / "audit.jsonl"))


def entries(log):
    return [e for e in log.events if e["action"] == VERDICT_ACTION]


def test_an_allowed_exchange_is_recorded_not_just_denials(guard, log):
    """A trail of refusals alone cannot prove the guard ran at all."""
    guarded_exchange(
        guard,
        "explain ownership and borrowing",
        lambda _t: "ownership means...",
        on_verdict=verdict_recorder(log, guard),
    )
    recorded = entries(log)
    assert [e["data"]["direction"] for e in recorded] == ["inbound", "outbound"]
    assert all(e["data"]["allowed"] for e in recorded)


def test_a_denial_records_the_rule_policy_and_citation(guard, log):
    with pytest.raises(Blocked):
        guarded_exchange(
            guard,
            "how do I kill myself",
            lambda _t: "unreachable",
            on_verdict=verdict_recorder(log, guard),
        )
    recorded = entries(log)
    assert len(recorded) == 1, "the model was never called, so only the inbound verdict exists"
    data = recorded[0]["data"]
    assert data["allowed"] is False
    assert data["rule"] == "self-harm"
    assert data["policy"] == "statutory-floor"
    assert data["citation"], "the obligation the rule implements travels with the record"


def test_every_entry_binds_the_policy_hash(guard, log):
    """Bind the logic, not just the output — which rules AND which normalization decided this."""
    guarded_exchange(guard, "explain lifetimes", lambda _t: "a lifetime is...",
                     on_verdict=verdict_recorder(log, guard))
    for e in entries(log):
        assert e["data"]["policy_hash"] == guard.policy_hash


def test_changing_the_normalization_changes_what_entries_attest_to(guard, log, monkeypatch):
    """A fold change must be visible in the trail, or the record misattributes past decisions."""
    from prismpath import guard as guard_mod

    before = guard.policy_hash
    monkeypatch.setitem(guard_mod._LEET_UNAMBIGUOUS, "9", "g")
    after = guard.policy_hash
    assert before != after, (
        "policy_hash must cover the normalization tables; otherwise two different folds produce "
        "records that claim the same provenance"
    )


# ------------------------------------------------------------------- what it refuses to leak


def test_no_text_digest_is_written_without_a_secret(guard, log):
    """OTS spec C4: a bare hash of a short prompt is brute-forceable, so the default records none."""
    with pytest.raises(Blocked):
        guarded_exchange(guard, "how do I kill myself", lambda _t: "x",
                         on_verdict=verdict_recorder(log, guard))
    data = entries(log)[0]["data"]
    assert "text_hmac" not in data


def test_the_trail_never_contains_the_prompt_itself(guard, log):
    secret = b"device-local-secret"
    with pytest.raises(Blocked):
        guarded_exchange(guard, "how do I kill myself", lambda _t: "x",
                         on_verdict=verdict_recorder(log, guard, secret=secret))
    import json

    serialized = json.dumps(log.events)
    assert "kill myself" not in serialized, "the raw prompt must never reach the trail"
    assert entries(log)[0]["data"]["text_hmac"]


def test_the_digest_is_reproducible_by_an_auditor_holding_text_and_secret(guard, log):
    import hashlib
    import hmac

    secret = b"device-local-secret"
    text = "how do I kill myself"
    with pytest.raises(Blocked):
        guarded_exchange(guard, text, lambda _t: "x",
                         on_verdict=verdict_recorder(log, guard, secret=secret))

    expected = hmac.new(secret, text.encode(), hashlib.sha256).hexdigest()
    assert entries(log)[0]["data"]["text_hmac"] == expected


def test_the_digest_is_useless_without_the_secret(guard, log):
    import hashlib

    secret = b"device-local-secret"
    text = "how do I kill myself"
    with pytest.raises(Blocked):
        guarded_exchange(guard, text, lambda _t: "x",
                         on_verdict=verdict_recorder(log, guard, secret=secret))
    # A bystander who guesses the prompt but lacks the secret cannot confirm it — which is the
    # entire point of using an HMAC rather than a plain digest.
    assert entries(log)[0]["data"]["text_hmac"] != hashlib.sha256(text.encode()).hexdigest()


# ------------------------------------------------------------------------------- attestation


def test_attestation_reuses_the_core_manifest_and_binds_the_policy(guard, log):
    guarded_exchange(guard, "explain traits", lambda _t: "a trait is...",
                     on_verdict=verdict_recorder(log, guard))
    manifest = attest_verdicts(log, guard, label="session-1", gate_id="mentor")

    assert manifest["policy_hash"] == guard.policy_hash
    assert manifest["gate_id"] == "mentor"
    assert manifest["label"] == "session-1"
    # provenance_manifest content-addresses itself, so the manifest cannot be edited unnoticed.
    assert manifest["manifest_hash"]
    assert len(manifest["ingestion_hashes"]) == len(entries(log))


def test_attestation_survives_a_session_with_no_verdicts(guard, log):
    manifest = attest_verdicts(log, guard, label="empty")
    assert manifest["ingestion_hashes"] == []
    assert manifest["policy_hash"] == guard.policy_hash


def test_the_log_persists_across_reopen(guard, tmp_path):
    """The trail is on disk, not only in memory — an audit outlives the process."""
    path = str(tmp_path / "audit.jsonl")
    log = AuditLog(path)
    guarded_exchange(guard, "explain generics", lambda _t: "generics are...",
                     on_verdict=verdict_recorder(log, guard))

    reopened = AuditLog(path)
    assert len(entries(reopened)) == len(entries(log)) == 2
