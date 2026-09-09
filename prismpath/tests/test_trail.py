# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The operator's trail verb: a window over an audit log, summarised in cause code terms, with the
Merkle root checked; and the overlay line an attestation carries."""
import json

from prismpath import audit_log, trail


def _log(tmp_path):
    log = audit_log.AuditLog(str(tmp_path / "audit.jsonl"))
    for i, (outcome, rule, cause) in enumerate([("allow", "r6", 0), ("deny", "r1", 0), ("abstain", "r3", 0),
                                                 ("escalate_human", "r5", 0), ("escalate_human", "r4", 34)]):
        log.append("gate", "decision", {"seq": i, "outcome": outcome, "rule": rule, "cause": cause})
    log.append("policy_host", "swap", {"from_hash": None, "to_hash": "ab" * 32, "version": 2, "overlay_of": "network_admission", "result": "accepted"})
    log.append("policy_host", "swap_rejected", {"reasons": ["version:not-monotonic:1<=2"]})
    log.append("policy_host", "attestation", {"active": "ab" * 32, "version": 2, "overlay_of": "network_admission", "ts": 0})
    return log


def test_trail_counts_and_causes(tmp_path):
    _log(tmp_path)
    rep = trail.run(str(tmp_path / "audit.jsonl"))
    assert rep["events"] == 8 and rep["decisions"] == 5
    assert rep["outcomes"]["escalate_human"] == 2
    assert rep["causes"]["34 route:needs-human"] == 1 and rep["causes"]["0 clean"] == 4
    assert rep["log"]["verifies"] is True
    text = trail.render(rep)
    assert "overlay of network_admission" in text and "swap refused: version:not-monotonic:1<=2" in text


def test_trail_window_last(tmp_path):
    _log(tmp_path)
    rep = trail.run(str(tmp_path / "audit.jsonl"), last=3)
    assert rep["events"] == 3 and rep["decisions"] == 0 and len(rep["swaps"]) == 3


def test_trail_root_moves_when_a_record_is_altered(tmp_path):
    before = _log(tmp_path).current_root()
    p = tmp_path / "audit.jsonl"
    lines = p.read_text().splitlines()
    ev = json.loads(lines[1]); ev["data"]["outcome"] = "allow"; lines[1] = json.dumps(ev)
    p.write_text("\n".join(lines) + "\n")
    rep = trail.run(str(p))
    assert rep["log"]["merkle_root"] != before   # an anchored root from before the edit no longer matches


def test_cli_trail_is_in_the_operator_group():
    from prismpath import cli
    ops = dict(cli.PERSONAS)
    assert "trail" in ops["Operator: run the system day to day, swap and attest policy (Mission Control is the console; this is the scripted path)"]
