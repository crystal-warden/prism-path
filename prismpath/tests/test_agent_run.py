# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Receipts across processes: one signed core run per session, appended by separate processes."""
import multiprocessing
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytest.importorskip("cryptography")
pytest.importorskip("fcntl")

from prismpath.agent import classifier, policy, run as runmod  # noqa: E402
from prismpath.ledgers import core_evidence  # noqa: E402

POL = policy.Policy.load()


def _reading(n):
    cfg = classifier.Config.for_workspace(Path("/tmp/ws"))
    return POL.reading_bytes(classifier.classify({"tool": "list_dir", "args": {"path": f"d{n}"}}, cfg))


def _append(args):
    root, session, n = args
    reading = _reading(n)
    return runmod.RunStore(Path(root)).open(session, POL.image).append(reading, POL.decide(reading).verdict)


def test_200_concurrent_appends_from_separate_processes_make_one_verifiable_run(tmp_path):
    ctx = multiprocessing.get_context("spawn")
    with ctx.Pool(16, maxtasksperchild=1) as pool:
        indexes = pool.map(_append, [(str(tmp_path), "s1", n) for n in range(200)], chunksize=1)
    assert sorted(indexes) == list(range(200))
    keys = tmp_path / "keys"
    run = runmod.RunStore(tmp_path).get("s1")
    summary = run.verify(keys)
    assert summary["receipts"] == 200 and summary["replayed"] == 200 and summary["disagree"] == 0
    assert summary["root_statement"] == "signed"


def test_two_sessions_are_separate_runs(tmp_path):
    store = runmod.RunStore(tmp_path)
    for session, count in (("a", 2), ("b", 3)):
        run = store.open(session, POL.image)
        for n in range(count):
            reading = _reading(n)
            run.append(reading, POL.decide(reading).verdict)
    keys = tmp_path / "keys"
    assert store.sessions() == ["a", "b"]
    assert store.get("a").verify(keys)["receipts"] == 2 and store.get("b").verify(keys)["receipts"] == 3
    assert store.open("../escape", POL.image).dir.parent == tmp_path


def test_another_image_is_refused(tmp_path):
    runmod.RunStore(tmp_path).open("s", POL.image)
    with pytest.raises(runmod.RunError):
        runmod.RunStore(tmp_path).open("s", POL.image + b" ")


_WRITER = """
import sys
from pathlib import Path
from prismpath.agent import classifier, policy, run as runmod
pol = policy.Policy.load()
cfg = classifier.Config.for_workspace(Path('/tmp/ws'))
run = runmod.RunStore(Path(sys.argv[1])).open('k', pol.image)
n = 0
while True:
    raw = pol.reading_bytes(classifier.classify({'tool': 'list_dir', 'args': {'path': 'd%d' % n}}, cfg))
    print(run.append(raw, pol.decide(raw).verdict), flush=True)
    n += 1
"""


def test_a_killed_writer_leaves_a_run_the_next_seal_makes_verifiable(tmp_path):
    proc = subprocess.Popen([sys.executable, "-c", _WRITER, str(tmp_path)], stdout=subprocess.PIPE)
    acked = []
    for line in proc.stdout:
        acked.append(int(line))
        if len(acked) >= 25:
            break
    proc.send_signal(signal.SIGKILL)
    acked.extend(int(x) for x in proc.stdout.read().split())
    proc.wait()
    run = runmod.RunStore(tmp_path).get("k")
    assert run.is_open()
    summary = run.verify(tmp_path / "keys")
    assert summary["receipts"] >= len(acked) >= 25 and summary["disagree"] == 0
    assert not run.is_open()


def test_a_half_written_last_line_is_detected_and_no_completed_receipt_is_lost(tmp_path):
    run = runmod.RunStore(tmp_path).open("t", POL.image)
    for n in range(3):
        raw = _reading(n)
        run.append(raw, POL.decide(raw).verdict)
    good = (run.dir / runmod.JOURNAL).read_bytes()
    (run.dir / runmod.JOURNAL).write_bytes(good + good.split(b"\n")[0][:40])      # a writer killed mid-line
    assert run.verify(tmp_path / "keys")["receipts"] == 3
    assert (run.dir / runmod.JOURNAL).read_bytes() == good
    assert (run.dir / runmod.TORN).read_bytes().startswith(good.split(b"\n")[0][:40])
    raw = _reading(9)                                                           # later appends still land
    assert run.append(raw, POL.decide(raw).verdict) == 3
    assert run.verify(tmp_path / "keys")["receipts"] == 4


def test_a_damaged_complete_line_is_refused_not_dropped(tmp_path):
    run = runmod.RunStore(tmp_path).open("t", POL.image)
    for n in range(2):
        raw = _reading(n)
        run.append(raw, POL.decide(raw).verdict)
    path = run.dir / runmod.JOURNAL
    lines = path.read_bytes().split(b"\n")
    lines[0] = lines[0].replace(b'"reading":"', b'"reading":"0', 1)
    path.write_bytes(b"\n".join(lines))
    with pytest.raises(runmod.RunCorrupt):
        run.seal(tmp_path / "keys")


def test_sealing_twice_is_idempotent_and_an_append_after_the_seal_reseals(tmp_path):
    run = runmod.RunStore(tmp_path).open("t", POL.image)
    raw = _reading(0)
    run.append(raw, POL.decide(raw).verdict)
    keys = tmp_path / "keys"
    run.seal(keys, time_us=1)
    before = (run.dir / "receipts.roots.jsonl").read_bytes()
    run.seal(keys, time_us=2)
    assert (run.dir / "receipts.roots.jsonl").read_bytes() == before and not run.is_open()
    raw = _reading(1)
    run.append(raw, POL.decide(raw).verdict)
    assert run.is_open()
    assert core_evidence.verify(run.dir, sample=None)["receipts"] == 1    # the old seal still stands as it was
    assert run.verify(keys)["receipts"] == 2


def test_a_tampered_byte_in_a_sealed_run_fails_verification(tmp_path):
    run = runmod.RunStore(tmp_path).open("t", POL.image)
    for n in range(3):
        raw = _reading(n)
        run.append(raw, POL.decide(raw).verdict)
    keys = tmp_path / "keys"
    run.verify(keys)
    path = run.dir / "receipts.jsonl"
    data = bytearray(path.read_bytes())
    data[len(data) // 2] ^= 1
    path.write_bytes(bytes(data))
    with pytest.raises(core_evidence.Bad):
        core_evidence.verify(run.dir, sample=None, pin_authority=keys / "authority.pub", pin_instance=keys / "instance.pub")


def test_the_append_cost_is_reported(tmp_path, capsys):
    run = runmod.RunStore(tmp_path).open("c", POL.image)
    raw = _reading(0)
    verdict = POL.decide(raw).verdict
    start = time.perf_counter()
    for _ in range(200):
        run.append(raw, verdict)
    ms = (time.perf_counter() - start) / 200 * 1000
    print(f"append: {ms:.2f} ms")
    assert ms < 500


def _big_run(tmp_path, count):
    """A run of `count` valid receipts, its journal written directly (an append per receipt would spend the
    test's time in fsync), and no validated-prefix record yet."""
    from prismpath.kernel import canon2
    run = runmod.RunStore(tmp_path).open("big", POL.image)
    raw = _reading(0)
    run.append(raw, POL.decide(raw).verdict)
    entry = canon2.loads((run.dir / runmod.JOURNAL).read_bytes().rstrip(b"\n"))
    out = bytearray()
    for n in range(count):
        entry["i"] = entry["receipt"]["idx"] = entry["receipt"]["reading"] = n
        out += canon2.dumps(entry) + b"\n"
    (run.dir / runmod.JOURNAL).write_bytes(bytes(out))
    (run.dir / runmod.PREFIX).unlink()
    return run, raw, POL.decide(raw).verdict


def test_an_append_to_a_5000_receipt_run_costs_what_an_append_to_a_new_run_costs(tmp_path, capsys):
    run, raw, verdict = _big_run(tmp_path, 5000)
    assert run.append(raw, verdict) == 5000          # no record: the whole journal is validated once
    start = time.perf_counter()
    for k in range(50):
        assert run.append(raw, verdict) == 5001 + k
    ms = (time.perf_counter() - start) / 50 * 1000
    print(f"append at 5000 receipts: {ms:.2f} ms")
    assert ms < 25                                   # a full validation of 5000 lines took about 700 ms


def test_an_outcome_finds_its_receipt_by_tool_use_id_without_validating_the_whole_journal(tmp_path, monkeypatch):
    run, raw, verdict = _big_run(tmp_path, 5000)
    first = run.append(raw, verdict, extras=runmod.Extras(tool_use_id="toolu_first"))      # validates the journal once, then the record holds
    run.append(raw, verdict, extras=runmod.Extras(tool_use_id="toolu_dup"))
    run.append(raw, verdict)                                          # a line with no id
    last = run.append(raw, verdict, extras=runmod.Extras(tool_use_id="toolu_dup"))          # the same id again: the later receipt is the one found
    monkeypatch.setattr(runmod.Run, "_entries", lambda self: pytest.fail("a full rescan of the journal"))
    start = time.perf_counter()
    got = run.outcome_of_hook("toolu_last", "PostToolUse", "Read")
    assert got["outcome"] == "unbound" and got["reason"] == "no-receipt"          # an id no receipt has, found by a backward read
    got = run.outcome_of_hook("toolu_dup", "PostToolUse", "Read")
    assert got["outcome"] == "ran" and got["receipt"] == last and got["tool_use_id"] == "toolu_dup"
    got = run.outcome_of_hook("toolu_first", "PostToolUseFailure", "Read", "exit-nonzero")
    assert got["outcome"] == "failed" and got["receipt"] == first            # an old receipt is found as well
    assert run.outcome_of_hook("toolu_first", "PostToolUse", "Read")["reason"] == "duplicate"
    assert run.outcome_of_hook(None, "PostToolUse", "Read")["reason"] == "no-tool-use-id"
    assert (time.perf_counter() - start) < 1.0                       # a full validation of 5000 lines took about 700 ms each
    monkeypatch.undo()
    assert run.verify_outcomes() == 5


def test_an_outcome_reads_a_receipt_appended_after_the_prefix_record_was_written(tmp_path):
    from prismpath.kernel import canon2
    run, raw, verdict = _big_run(tmp_path, 50)
    run.append(raw, verdict)
    path = run.dir / runmod.JOURNAL
    n = run.append(raw, verdict)
    before = (run.dir / runmod.PREFIX).read_bytes()
    line = canon2.loads(path.read_bytes().split(b"\n")[-2])
    line.update(i=n + 1)
    line["receipt"].update(idx=n + 1, reading=n + 1)
    line["tool_use_id"] = "toolu_late"
    with open(path, "ab") as handle:                                  # a line a crashed append wrote before its record
        handle.write(canon2.dumps(line) + b"\n")
    assert (run.dir / runmod.PREFIX).read_bytes() == before
    got = run.outcome_of_hook("toolu_late", "PostToolUse", "Read")
    assert got["outcome"] == "ran" and got["receipt"] == n + 1
    path.write_bytes(path.read_bytes()[:-1])                          # a torn tail is dropped, never matched
    assert run.outcome_of_hook("toolu_late", "PostToolUse", "Read")["outcome"] == "unbound"


def test_a_route_table_and_an_allowed_host_list_digest_are_kept_on_the_line_and_reported(tmp_path):
    run, raw, verdict = _big_run(tmp_path, 3)
    run.append(raw, verdict, extras=runmod.Extras(routes_sha256="a" * 64))
    run.append(raw, verdict, extras=runmod.Extras(hosts_sha256="b" * 64))
    assert run.bound_digests() == {"routes_sha256": ["a" * 64], "hosts_sha256": ["b" * 64]}
    with pytest.raises(runmod.RunError):
        run.append(raw, verdict, extras=runmod.Extras(routes_sha256="not-a-digest"))
    run.append(raw, verdict, extras=runmod.Extras(routes_sha256="c" * 64))
    assert run.bound_digests()["routes_sha256"] == ["a" * 64, "c" * 64]      # a run resumed under another table says so


def test_a_tampered_prefix_the_append_did_not_read_is_refused_at_the_seal(tmp_path):
    run, raw, verdict = _big_run(tmp_path, 5000)
    run.append(raw, verdict)
    path = run.dir / runmod.JOURNAL
    data = bytearray(path.read_bytes())
    at = data.index(b'"reading":"', 1000) + len(b'"reading":"')
    data[at] = ord("0") if data[at] != ord("0") else ord("1")
    path.write_bytes(bytes(data))
    assert run.append(raw, verdict) == 5001          # the append trusts the prefix it validated before
    with pytest.raises(runmod.RunCorrupt):
        run.seal(tmp_path / "keys")
    with pytest.raises(runmod.RunCorrupt):
        run.verify(tmp_path / "keys")


def test_a_record_that_does_not_match_the_journal_falls_back_to_full_validation(tmp_path):
    run, raw, verdict = _big_run(tmp_path, 300)
    run.append(raw, verdict)
    path = run.dir / runmod.JOURNAL
    lines = path.read_bytes().split(b"\n")[:-1]
    path.write_bytes(b"\n".join(lines[:100]) + b"\n")                   # the journal is shorter than the record
    assert run.append(raw, verdict) == 100
    lines = path.read_bytes().split(b"\n")[:-1]
    lines[-1] = lines[-1].replace(b'"reading":"', b'"reading":"0', 1)   # the recorded last line differs
    path.write_bytes(b"\n".join(lines) + b"\n")
    with pytest.raises(runmod.RunCorrupt):
        run.append(raw, verdict)
    (run.dir / runmod.PREFIX).write_bytes(b"not a record")
    with pytest.raises(runmod.RunCorrupt):
        run.append(raw, verdict)
