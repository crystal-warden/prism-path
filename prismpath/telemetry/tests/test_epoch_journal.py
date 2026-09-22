# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The epoch journal across restarts: retained readings come back and the chain verifies; an
interruption during sealing, during acknowledgment and during deletion is finished or reported on
recovery, never silent; a replayed or forged acknowledgment deletes nothing before or after a
restart; a disk limit records the gap before the bytes go; a corrupt data file is a named loss."""
import json
import os
from pathlib import Path

import pytest

from prismpath.telemetry import ackchannel
from prismpath.telemetry import epoch_journal as journal_module
from prismpath.telemetry import zeckendorf as zeck

SECRET = b"shared"


def _bits(seed):
    return zeck.encode_stream(list(range(1 + seed, 40 + seed)))


def _journal(tmp_path, **options):
    return journal_module.EpochJournal(str(tmp_path / "journal"), block_bits=64, max_data_epochs=5, **options)


def _signed(root, seq):
    return ackchannel.sign_ack(SECRET, root, seq)


def test_retained_readings_survive_a_restart(tmp_path):
    journal = _journal(tmp_path)
    for seed in range(3):
        journal.seal(_bits(seed))
    chain = journal.chain()
    retained = journal.retained()
    reopened = _journal(tmp_path)
    assert reopened.recovery_report() == []
    assert reopened.chain() == chain and reopened.verify_chain()
    assert reopened.retained() == retained, "every retained reading is recoverable"


def test_interruption_during_sealing_is_reported_and_leaves_no_phantom_epoch(tmp_path, monkeypatch):
    journal = _journal(tmp_path)
    journal.seal(_bits(0))
    chain_before = journal.chain()

    def crash_before_chain_line(path, record):
        raise OSError(5, "power loss between the data file and the chain line")
    monkeypatch.setattr(journal_module, "_append_line", crash_before_chain_line)
    with pytest.raises(OSError):
        journal.seal(_bits(1))
    monkeypatch.undo()
    assert os.path.exists(journal._data_path(1)), "the data file landed before the crash"
    reopened = _journal(tmp_path)
    findings = {finding["finding"] for finding in reopened.recovery_report()}
    assert "orphan_data" in findings
    assert reopened.chain() == chain_before and reopened.verify_chain()
    assert not os.path.exists(reopened._data_path(1)), "the orphan is removed, not adopted"
    reopened.seal(_bits(1))
    assert len(reopened.chain()) == 2


def test_torn_chain_line_is_discarded_and_reported(tmp_path):
    journal = _journal(tmp_path)
    journal.seal(_bits(0))
    journal.seal(_bits(1))
    with open(journal._chain_path(), "a", encoding="utf-8") as handle:
        handle.write('{"epoch_id": 2, "merkle_root": "abc')
    reopened = _journal(tmp_path)
    assert any(finding["finding"] == "interrupted_seal" for finding in reopened.recovery_report())
    assert len(reopened.chain()) == 2 and reopened.verify_chain()


def test_interruption_during_acknowledgment_completes_on_recovery(tmp_path, monkeypatch):
    journal = _journal(tmp_path)
    for seed in range(3):
        journal.seal(_bits(seed))
    receiver = journal_module.DurableAckReceiver(journal, SECRET)
    root = journal.chain()[1]

    def crash_before_deletion(chained_root):
        raise OSError(5, "power loss after the state write, before deletion")
    monkeypatch.setattr(journal, "_apply_ack_to_files", crash_before_deletion)
    with pytest.raises(OSError):
        receiver.on_ack(root, 1, _signed(root, 1))
    monkeypatch.undo()
    assert os.path.exists(journal._data_path(0)) and os.path.exists(journal._data_path(1)), "nothing deleted yet"
    reopened = _journal(tmp_path)
    completed = [finding for finding in reopened.recovery_report() if finding["finding"] == "completed_ack"]
    assert completed and sorted(completed[0]["epochs"]) == [0, 1]
    assert not os.path.exists(reopened._data_path(0)) and not os.path.exists(reopened._data_path(1))
    assert reopened.retained().keys() == {2} and reopened.verify_chain()
    assert reopened.gaps() == [], "an acknowledged drop is not a gap"


def test_interruption_during_deletion_finishes_on_recovery(tmp_path, monkeypatch):
    journal = _journal(tmp_path)
    for seed in range(3):
        journal.seal(_bits(seed))
    root = journal.chain()[1]
    real_remove = journal._remove_data
    calls = []

    def remove_first_only(epoch_id):
        calls.append(epoch_id)
        if len(calls) == 2:
            raise OSError(5, "power loss halfway through deletion")
        real_remove(epoch_id)
    monkeypatch.setattr(journal, "_remove_data", remove_first_only)
    with pytest.raises(OSError):
        journal_module.DurableAckReceiver(journal, SECRET).on_ack(root, 1, _signed(root, 1))
    monkeypatch.undo()
    assert not os.path.exists(journal._data_path(0)) and os.path.exists(journal._data_path(1))
    reopened = _journal(tmp_path)
    assert any(finding["finding"] == "completed_ack" and finding["epochs"] == [1] for finding in reopened.recovery_report())
    assert not os.path.exists(reopened._data_path(1)) and reopened.retained().keys() == {2}


def test_replayed_and_forged_acknowledgments_delete_nothing_across_a_restart(tmp_path):
    journal = _journal(tmp_path)
    for seed in range(4):
        journal.seal(_bits(seed))
    receiver = journal_module.DurableAckReceiver(journal, SECRET)
    first_root, later_root = journal.chain()[0], journal.chain()[2]
    assert receiver.on_ack(first_root, 1, _signed(first_root, 1))["accepted"]
    reopened = _journal(tmp_path)
    reopened_receiver = journal_module.DurableAckReceiver(reopened, SECRET)
    replay = reopened_receiver.on_ack(later_root, 1, _signed(later_root, 1))
    assert replay == {"accepted": False, "reason": "stale-seq", "dropped": 0}, "the persisted sequence makes the replay stale after the restart"
    forged = reopened_receiver.on_ack(later_root, 2, "0" * 64)
    assert forged["accepted"] is False and forged["reason"] == "bad-tag"
    assert reopened.retained().keys() == {1, 2, 3}, "a replayed acknowledgment cannot delete additional data"
    assert reopened_receiver.on_ack(later_root, 2, _signed(later_root, 2))["dropped"] == 2


def test_disk_limit_records_the_gap_before_the_bytes_go(tmp_path):
    journal = _journal(tmp_path, max_bytes=600)
    for seed in range(4):
        journal.seal(_bits(seed))
    assert journal._data_bytes_on_disk() <= 600
    assert journal.gaps(), "an unacknowledged epoch forced out is a named gap"
    gap_records = [json.loads(line) for line in open(journal._gaps_path(), encoding="utf-8") if line.strip()]
    assert [record["epoch_id"] for record in gap_records] == journal.gaps()
    reopened = _journal(tmp_path, max_bytes=600)
    assert reopened.gaps() == journal.gaps() and reopened.verify_chain()


def test_corrupt_data_file_is_a_named_loss_and_the_chain_still_verifies(tmp_path):
    journal = _journal(tmp_path)
    for seed in range(2):
        journal.seal(_bits(seed))
    with open(journal._data_path(0), "wb") as handle:
        handle.write(b'["11"]')
    reopened = _journal(tmp_path)
    assert any(finding["finding"] == "corrupt_data" and finding["epoch_id"] == 0 for finding in reopened.recovery_report())
    assert reopened.gaps() == [0] and reopened.retained().keys() == {1} and reopened.verify_chain()


def test_chain_hole_refuses_to_open(tmp_path):
    journal = _journal(tmp_path)
    for seed in range(3):
        journal.seal(_bits(seed))
    lines = open(journal._chain_path(), encoding="utf-8").read().splitlines()
    lines[1] = "garbage"
    Path(journal._chain_path()).write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(journal_module.JournalCorrupt):
        _journal(tmp_path)
