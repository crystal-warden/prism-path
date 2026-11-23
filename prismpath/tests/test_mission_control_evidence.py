# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Mission Control's evidence readers (`prismpath.mission_control.evidence`) and its cause decoder
(`prismpath.mission_control.causes_view`), the transport agnostic half of the auditing interface.

Every reader is a function over paths under the evidence roots the launch named. The tests hold each one to
the verifier it wraps (`trail.run`, `verify_receipt_bundle`, `core_evidence.verify`, `flow_authority
.verify_flow`) and treat every file as hostile: a path outside the roots, a traversal, a symlink that leaves
them, a file larger than the bound, a line that is not canonical canon/2, a tampered receipt and a false one
signed again with the instance key. No reader writes, which the tests check by listing the roots before and
after. The run directories are produced for the test from `fixtures/core_evidence/cases.jsonl` with test
keys, so the suite runs from an installed wheel with no research tooling."""
import os
import shutil
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from prismpath.hotswap import flow_authority, policy_pack  # noqa: E402
from prismpath.kernel import canon2, causes  # noqa: E402
from prismpath.ledgers import audit_log, core_evidence, root_statement  # noqa: E402
from prismpath.mission_control import config as mc_config  # noqa: E402

try:
    from prismpath.mission_control import causes_view, evidence
except ImportError:                       # main before WP3: every test below fails on this
    causes_view = evidence = None

CASES = Path(__file__).resolve().parent / "fixtures" / "core_evidence" / "cases.jsonl"
FLOW = "---\nname: f\nstart: a\n---\n## a\n-> b: when score > 5\n-> c: else\n## b\nDone.\n## c\nDone.\n"


@pytest.fixture(autouse=True)
def _module_present():
    assert evidence is not None and causes_view is not None, \
        "prismpath.mission_control.evidence and causes_view do not exist yet"


@pytest.fixture
def keys(tmp_path):
    """An instance key outside the evidence roots, as a deployment keeps it."""
    made = root_statement.keygen(str(tmp_path / "keys"), "instance")
    return root_statement.InstanceKey.load(made["private"]), root_statement.load_public(made["public"])


@pytest.fixture
def root(tmp_path, monkeypatch):
    """One evidence root, named the way MC_EVIDENCE names it."""
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    monkeypatch.setattr(mc_config.SETTINGS, "evidence_roots", [str(evidence_root)])
    return evidence_root


def _signed_log(path, key, decisions=((2, "refuse"), (0, "route"), (34, "escalate"), (2, "refuse"))):
    """A run's audit log signed after every append, with decisions that carry registered causes."""
    log = audit_log.AuditLog(str(path), instance_key=key, sign_appends=True)
    for code, outcome in decisions:
        log.append("engine", "decision", {"outcome": outcome, "cause": code, "rule": "r1"})
    return log


def _listing(base):
    """Every path under `base` with its size and mtime: what a reader that never writes leaves unchanged."""
    out = {}
    for dirpath, dirnames, filenames in os.walk(base):
        for name in dirnames + filenames:
            full = os.path.join(dirpath, name)
            stat = os.lstat(full)
            out[os.path.relpath(full, base)] = (stat.st_size, stat.st_mtime_ns)
    return out


def _lines(path):
    return Path(path).read_bytes().split(b"\n")[:-1]


# ----------------------------------------------------------------- confinement
def test_a_path_outside_the_roots_is_refused(root, tmp_path, keys):
    outside = tmp_path / "elsewhere" / "run.audit.jsonl"
    outside.parent.mkdir()
    _signed_log(outside, keys[0])
    for call in (lambda: evidence.trail_report(str(outside)), lambda: evidence.receipt_view(str(outside), 0),
                 lambda: evidence.raw_lines(str(outside), 0, 1), lambda: evidence.cause_series(str(outside), 60)):
        with pytest.raises(evidence.EvidenceRefused) as refused:
            call()
        assert refused.value.reason == "outside-roots"


def test_a_traversal_out_of_a_root_is_refused(root, tmp_path, keys):
    (tmp_path / "secret.jsonl").write_bytes(b"not yours\n")
    with pytest.raises(evidence.EvidenceRefused) as refused:
        evidence.raw_lines(str(root / ".." / "secret.jsonl"), 0, 1)
    assert refused.value.reason == "outside-roots"
    with pytest.raises(evidence.EvidenceRefused):
        evidence.raw_lines("../secret.jsonl", 0, 1)             # relative to the root, and still outside


def test_a_symlink_that_leaves_the_roots_is_refused(root, tmp_path, keys):
    outside = tmp_path / "outside.audit.jsonl"
    _signed_log(outside, keys[0])
    (root / "inside.audit.jsonl").symlink_to(outside)
    (tmp_path / "outdir").mkdir()
    _signed_log(tmp_path / "outdir" / "run.audit.jsonl", keys[0])
    (root / "linked").symlink_to(tmp_path / "outdir", target_is_directory=True)
    with pytest.raises(evidence.EvidenceRefused) as refused:
        evidence.trail_report(str(root / "inside.audit.jsonl"))
    assert refused.value.reason == "outside-roots"
    with pytest.raises(evidence.EvidenceRefused):
        evidence.raw_lines(str(root / "linked" / "run.audit.jsonl"), 0, 1)
    listed = {entry["path"] for entry in evidence.discover_logs()["logs"]}
    assert not any("inside" in path or "linked" in path for path in listed), listed


def test_no_roots_means_nothing_is_readable(tmp_path, keys, monkeypatch):
    monkeypatch.setattr(mc_config.SETTINGS, "evidence_roots", [])
    log_path = tmp_path / "run.audit.jsonl"
    _signed_log(log_path, keys[0])
    with pytest.raises(evidence.EvidenceRefused) as refused:
        evidence.trail_report(str(log_path))
    assert refused.value.reason == "outside-roots"
    assert evidence.discover_logs() == {"roots": [], "logs": [], "runs": [], "feeds": [], "truncated": False}


def test_a_file_larger_than_the_bound_is_refused(root, keys, monkeypatch):
    log_path = root / "run.audit.jsonl"
    _signed_log(log_path, keys[0])
    monkeypatch.setattr(mc_config.SETTINGS, "max_evidence_bytes", 64)
    for call in (lambda: evidence.trail_report(str(log_path)), lambda: evidence.receipt_view(str(log_path), 0),
                 lambda: evidence.raw_lines(str(log_path), 0, 1), lambda: evidence.cause_series(str(log_path), 60)):
        with pytest.raises(evidence.EvidenceRefused) as refused:
            call()
        assert refused.value.reason == "too-large"


def test_a_statements_file_larger_than_the_bound_is_refused(root, keys, monkeypatch):
    log_path = root / "run.audit.jsonl"
    _signed_log(log_path, keys[0])
    statements = Path(root_statement.statements_path_for(str(log_path)))
    monkeypatch.setattr(mc_config.SETTINGS, "max_evidence_bytes", os.path.getsize(log_path) + 1)
    assert statements.stat().st_size > mc_config.SETTINGS.max_evidence_bytes
    with pytest.raises(evidence.EvidenceRefused) as refused:
        evidence.trail_report(str(log_path))
    assert refused.value.reason == "too-large"


def test_a_symlink_swapped_in_after_confinement_is_not_followed(root, tmp_path):
    """The read opens the confined path without following a final symlink, so a link put in its place
    between the check and the open is refused rather than read."""
    (tmp_path / "target.jsonl").write_bytes(b"outside\n")
    (root / "swapped.jsonl").symlink_to(tmp_path / "target.jsonl")
    with pytest.raises(evidence.EvidenceRefused) as refused:
        evidence._read_bounded(str(root / "swapped.jsonl"), 1024)
    assert refused.value.reason == "outside-roots"


def test_a_directory_or_a_missing_file_is_refused(root):
    (root / "adir").mkdir()
    with pytest.raises(evidence.EvidenceRefused) as refused:
        evidence.raw_lines(str(root / "adir"), 0, 1)
    assert refused.value.reason == "not-a-file"
    with pytest.raises(evidence.EvidenceRefused) as refused:
        evidence.raw_lines(str(root / "absent.jsonl"), 0, 1)
    assert refused.value.reason == "not-found"


# ----------------------------------------------------------------- discovery
def test_discover_lists_logs_with_their_statements_and_runs(root, keys):
    (root / "deploy").mkdir()
    _signed_log(root / "deploy" / "run.audit.jsonl", keys[0])
    audit_log.AuditLog(str(root / "deploy" / "swaps.log")).append("host", "swap", {"version": 1})
    core_evidence.produce(CASES, root / "runs" / "one", root.parent / "run-keys")
    found = evidence.discover_logs()
    logs = {Path(entry["path"]).name: entry for entry in found["logs"]}
    assert set(logs) == {"run.audit.jsonl", "swaps.log"}, logs
    assert logs["run.audit.jsonl"]["statements"].endswith("run.audit.roots.jsonl")
    assert logs["swaps.log"]["statements"] is None
    assert [Path(run["path"]).name for run in found["runs"]] == ["one"]
    assert found["roots"] == [os.path.realpath(root)]


def test_discover_is_bounded(root, keys, monkeypatch):
    for number in range(5):
        audit_log.AuditLog(str(root / f"r{number}.audit.jsonl")).append("a", "decision", {"cause": 0})
    monkeypatch.setattr(mc_config.SETTINGS, "max_tree_entries", 3)
    found = evidence.discover_logs()
    assert len(found["logs"]) <= 3 and found["truncated"] is True


# ----------------------------------------------------------------- the trail
def test_a_signed_log_reports_signed_under_its_pinned_key(root, keys):
    log_path = root / "run.audit.jsonl"
    _signed_log(log_path, keys[0])
    before = _listing(root)
    report = evidence.trail_report(str(log_path), pinned=[keys[1]])
    assert report["verdict_of"] == "console"
    assert report["log"]["verifies"] is True and report["signing"]["status"] == "signed"
    assert report["signing"]["findings"] == []
    assert report["sha256"] == core_evidence.sha256_hex(log_path.read_bytes())
    decoded = {entry["code"]: entry for entry in report["causes_decoded"]}
    assert decoded[2]["name"] == "sig:invalid" and decoded[2]["class"] == "authority"
    assert decoded[0]["clean"] is True
    assert evidence.trail_report(str(log_path))["signing"]["status"] == "signed-unpinned"
    assert _listing(root) == before


def test_a_log_with_a_tampered_line_reports_invalid_and_names_the_finding(root, keys):
    log_path = root / "run.audit.jsonl"
    _signed_log(log_path, keys[0])
    lines = _lines(log_path)
    event = canon2.loads(lines[1])
    event["data"]["outcome"] = "refuse"                   # canonical bytes, other content
    lines[1] = canon2.dumps(event)
    log_path.write_bytes(b"".join(line + b"\n" for line in lines))
    report = evidence.trail_report(str(log_path), pinned=[keys[1]])
    assert report["signing"]["status"] == "invalid"
    assert "root_mismatch" in {finding["finding"] for finding in report["signing"]["findings"]}


def test_a_line_that_is_not_canonical_canon2_is_refused_not_respelled(root, keys):
    log_path = root / "run.audit.jsonl"
    _signed_log(log_path, keys[0])
    lines = _lines(log_path)
    lines[2] = lines[2].replace(b'":', b'": ', 1)          # the same value, a spelling canon/2 does not write
    log_path.write_bytes(b"".join(line + b"\n" for line in lines))
    report = evidence.trail_report(str(log_path), pinned=[keys[1]])
    assert report["log"]["verifies"] is False and report["signing"]["status"] == "invalid"
    assert {"finding": "bad_format", "log_lines": [3]} in report["signing"]["findings"]
    assert report["skipped"][0]["line"] == 3 and "not-canonical" in report["skipped"][0]["why"]


def test_bytes_that_are_not_utf8_are_a_finding_not_a_crash(root, keys):
    log_path = root / "run.audit.jsonl"
    _signed_log(log_path, keys[0])
    with open(log_path, "ab") as handle:
        handle.write(b'{"\xff\xfe": 1}\n')
    report = evidence.trail_report(str(log_path))
    assert report["signing"]["status"] == "invalid" and report["log"]["verifies"] is False


def test_a_pin_that_is_not_a_key_is_refused(root, keys):
    log_path = root / "run.audit.jsonl"
    _signed_log(log_path, keys[0])
    with pytest.raises(evidence.EvidenceRefused) as refused:
        evidence.trail_report(str(log_path), pinned=[b"short"])
    assert refused.value.reason == "bad-pin"


def test_the_window_is_passed_to_the_trail(root, keys):
    log_path = root / "run.audit.jsonl"
    _signed_log(log_path, keys[0])
    assert evidence.trail_report(str(log_path), last=2)["events"] == 2
    with pytest.raises(evidence.EvidenceRefused) as refused:
        evidence.trail_report(str(log_path), since="not a time")
    assert refused.value.reason == "bad-request"


# ----------------------------------------------------------------- one receipt
def test_a_receipt_view_decodes_the_receipt_and_its_bundle_verifies(root, keys):
    log_path = root / "run.audit.jsonl"
    _signed_log(log_path, keys[0])
    view = evidence.receipt_view(str(log_path), 0, pinned=[keys[1]])
    assert view["event"]["idx"] == 0 and view["cause"]["name"] == "sig:invalid"
    assert view["log"] == os.path.realpath(log_path) and view["evidence_root"] == os.path.realpath(root)
    assert view["cause"]["class"] == causes.cause_class(2)
    assert view["raw"] == _lines(log_path)[0]
    assert view["leaf"] == core_evidence.sha256_hex(view["raw"])
    assert view["statement"]["leaves"] >= 1 and view["path"] == view["bundle"]["path"]
    assert view["verdict"]["status"] == "signed" and view["verdict"]["verdict_of"] == "console"
    assert root_statement.verify_receipt_bundle(view["bundle"], [keys[1]])["ok"] is True
    assert "prismpath trail --verify-bundle" in view["command"]
    altered = dict(view["bundle"], leaf="00" * 32)
    assert root_statement.verify_receipt_bundle(altered, [keys[1]])["ok"] is False


def test_a_receipt_no_statement_covers_has_no_bundle(root):
    log_path = root / "run.audit.jsonl"
    audit_log.AuditLog(str(log_path)).append("engine", "decision", {"outcome": "refuse", "cause": 36})
    view = evidence.receipt_view(str(log_path), 0)
    assert view["bundle"] is None and "no root statement covers" in view["uncovered"]
    assert view["cause"]["name"] == "route:stuck"
    assert audit_log.verify(view["leaf"], view["path"], view["root"]) is True


def test_a_receipt_index_out_of_range_is_refused(root, keys):
    log_path = root / "run.audit.jsonl"
    _signed_log(log_path, keys[0])
    for index in (-1, 4, True, "0"):
        with pytest.raises(evidence.EvidenceRefused) as refused:
            evidence.receipt_view(str(log_path), index)
        assert refused.value.reason == "bad-request"


def test_a_receipt_view_skips_a_line_that_does_not_read(root, keys):
    """The receipt index counts events, as the log does, so a refused line does not shift the raw bytes."""
    log_path = root / "run.audit.jsonl"
    _signed_log(log_path, keys[0])
    lines = _lines(log_path)
    log_path.write_bytes(b"".join(line + b"\n" for line in [lines[0], b'{"bad": 1.5}', *lines[1:]]))
    view = evidence.receipt_view(str(log_path), 1)
    assert view["raw"] == lines[1] and view["event"]["idx"] == 1


# ----------------------------------------------------------------- raw bytes
def test_raw_lines_are_the_bytes_as_written(root, keys):
    log_path = root / "run.audit.jsonl"
    _signed_log(log_path, keys[0])
    raw = evidence.raw_lines(str(log_path), 1, 2)
    assert raw["lines"] == _lines(log_path)[1:3] and raw["total"] == 4 and raw["start"] == 1
    statements = root_statement.statements_path_for(str(log_path))
    assert evidence.raw_lines(statements, 0, 100)["lines"] == _lines(statements)


def test_raw_lines_are_bounded(root, keys, monkeypatch):
    log_path = root / "run.audit.jsonl"
    _signed_log(log_path, keys[0])
    monkeypatch.setattr(evidence, "MAX_RAW_LINES", 2)
    assert len(evidence.raw_lines(str(log_path), 0, 50)["lines"]) == 2
    for start, count in ((-1, 1), (0, -1), (0, 0)):
        with pytest.raises(evidence.EvidenceRefused):
            evidence.raw_lines(str(log_path), start, count)


# ----------------------------------------------------------------- the cause series
def test_the_cause_series_counts_by_cause_and_action_per_bucket(root):
    log_path = root / "run.audit.jsonl"
    text = b""
    for number, (seconds, action, cause) in enumerate(((0, "decision", 2), (30, "decision", 2), (59, "swap", None),
                                                       (60, "decision", 34), (185, "decision", 0))):
        data = {"cause": cause} if cause is not None else {"version": 1}
        event = {"idx": number, "id": str(number), "ts_us": (1_000_020 + seconds) * 1_000_000, "actor": "a",
                 "action": action, "data": data, "encoding": "canon/2"}
        text += canon2.dumps(event) + b"\n"
    log_path.write_bytes(text)
    series = evidence.cause_series(str(log_path), 60)
    buckets = {bucket["start"]: bucket for bucket in series["buckets"]}
    assert sorted(buckets) == [1_000_020 // 60 * 60 + offset for offset in (0, 60, 180)]
    first = buckets[1_000_020 // 60 * 60]
    assert first["by_cause"] == {"2": 2} and first["by_action"] == {"decision": 2, "swap": 1}
    assert series["causes"]["34"]["name"] == "route:needs-human"
    assert series["causes"]["0"]["clean"] is True
    with pytest.raises(evidence.EvidenceRefused):
        evidence.cause_series(str(log_path), 0)


def test_the_cause_series_bounds_its_bucket_count(root, monkeypatch):
    log_path = root / "run.audit.jsonl"
    text = b""
    for number, seconds in enumerate((0, 10_000)):
        event = {"idx": number, "id": str(number), "ts_us": seconds * 1_000_000, "actor": "a",
                 "action": "decision", "data": {"cause": 2}, "encoding": "canon/2"}
        text += canon2.dumps(event) + b"\n"
    log_path.write_bytes(text)
    monkeypatch.setattr(evidence, "MAX_BUCKETS", 100)
    with pytest.raises(evidence.EvidenceRefused) as refused:
        evidence.cause_series(str(log_path), 1)
    assert refused.value.reason == "bad-request"


# ----------------------------------------------------------------- evidence runs
@pytest.fixture
def run(root, tmp_path):
    """A core run under the root, produced by `core_evidence.produce` with test keys kept outside it."""
    keys_dir = tmp_path / "run-keys"
    core_evidence.produce(CASES, root / "run", keys_dir)
    (root / "pins").mkdir()
    shutil.copy(keys_dir / "authority.pub", root / "pins" / "authority.pub")
    shutil.copy(keys_dir / "instance.pub", root / "pins" / "instance.pub")
    return root / "run", keys_dir, {"authority": str(root / "pins" / "authority.pub"),
                                    "instance": str(root / "pins" / "instance.pub")}


def test_a_produced_run_verifies_under_pinned_keys(run, root):
    run_dir, _keys, pins = run
    before = _listing(root)
    report = evidence.run_report(str(run_dir), pins)
    assert report["ok"] is True and report["status"] == "signed" and report["verdict_of"] == "console"
    assert report["disagree"] == 0 and report["replayed"] == min(report["receipts"], mc_config.SETTINGS.evidence_sample)
    unpinned = evidence.run_report(str(run_dir))
    assert unpinned["ok"] is False and "dist:hatch-refused" in unpinned["problem"]     # D1: unpinned is a hatch
    assert _listing(root) == before


def test_the_replay_sample_is_bounded_by_the_setting(run, monkeypatch):
    run_dir, _keys, pins = run
    monkeypatch.setattr(mc_config.SETTINGS, "evidence_sample", 7)
    assert evidence.run_report(str(run_dir), pins, sample=1000)["replayed"] == 7
    assert evidence.run_report(str(run_dir), pins, sample=3)["replayed"] == 3


def test_a_false_receipt_resigned_with_the_instance_key_fails(run, monkeypatch):
    """Whoever holds the instance key can sign anything; the replay through the reference refuses it."""
    run_dir, keys_dir, pins = run
    lines = _lines(run_dir / "receipts.jsonl")
    at = next(number for number, line in enumerate(lines) if b'"decision":"route"' in line)
    receipt = canon2.loads(lines[at])
    receipt["target"] = receipt["target"] + "x"
    lines[at] = canon2.dumps(receipt)
    (run_dir / "receipts.jsonl").write_bytes(b"".join(line + b"\n" for line in lines))
    manifest_bytes = (run_dir / "run.json").read_bytes().rstrip(b"\n")
    leaves = [core_evidence.sha256_hex(line) for line in lines]
    instance = root_statement.InstanceKey.load(str(keys_dir / "instance.key"))
    statement = core_evidence.make_root_statement(instance, root_statement.merkle_root(leaves), len(leaves), manifest_bytes)
    (run_dir / "receipts.roots.jsonl").write_bytes(canon2.dumps(statement) + b"\n")
    monkeypatch.setattr(mc_config.SETTINGS, "evidence_sample", 100_000)     # replay every receipt
    report = evidence.run_report(str(run_dir), pins)
    assert report["ok"] is False and report["status"] == "invalid"
    assert "replayed decisions differ from the reference kernel" in report["problem"]


def test_a_tampered_receipt_in_a_run_fails_the_merkle_root(run):
    run_dir, _keys, pins = run
    lines = _lines(run_dir / "receipts.jsonl")
    (run_dir / "receipts.jsonl").write_bytes(b"".join(line + b"\n" for line in lines[:-1]))
    report = evidence.run_report(str(run_dir), pins)
    assert report["ok"] is False and "Merkle root" in report["problem"]


def test_a_run_json_that_is_not_canonical_is_refused(run):
    run_dir, _keys, pins = run
    text = (run_dir / "run.json").read_bytes()
    (run_dir / "run.json").write_bytes(text.replace(b'":', b'": ', 1))
    report = evidence.run_report(str(run_dir), pins)
    assert report["ok"] is False and "canonical" in report["problem"]


def test_a_wrong_pinned_key_fails(run, root, tmp_path):
    run_dir, _keys, pins = run
    other = root_statement.keygen(str(root / "other"), "instance")
    report = evidence.run_report(str(run_dir), {"authority": pins["authority"], "instance": other["public"]})
    assert report["ok"] is False and "pinned instance key" in report["problem"]


def test_a_run_file_that_is_a_symlink_out_of_the_roots_is_refused(run, tmp_path):
    run_dir, _keys, pins = run
    moved = tmp_path / "moved-cases.jsonl"
    shutil.move(run_dir / "cases.jsonl", moved)
    (run_dir / "cases.jsonl").symlink_to(moved)
    with pytest.raises(evidence.EvidenceRefused) as refused:
        evidence.run_report(str(run_dir), pins)
    assert refused.value.reason == "outside-roots"


def test_a_run_larger_than_the_bound_is_refused(run, monkeypatch):
    run_dir, _keys, pins = run
    monkeypatch.setattr(mc_config.SETTINGS, "max_evidence_bytes", 1024)
    with pytest.raises(evidence.EvidenceRefused) as refused:
        evidence.run_report(str(run_dir), pins)
    assert refused.value.reason == "too-large"


def test_a_pin_outside_the_roots_is_refused(run, tmp_path):
    run_dir, keys_dir, _pins = run
    with pytest.raises(evidence.EvidenceRefused) as refused:
        evidence.run_report(str(run_dir), {"instance": str(keys_dir / "instance.pub")})
    assert refused.value.reason == "outside-roots"


def test_a_run_that_changes_while_it_is_verified_is_refused(run, monkeypatch):
    run_dir, _keys, pins = run
    verify = core_evidence.verify

    def verify_then_grow(*args, **kwargs):
        summary = verify(*args, **kwargs)
        with open(run_dir / "receipts.jsonl", "ab") as handle:
            handle.write(b"\n")
        return summary

    monkeypatch.setattr(core_evidence, "verify", verify_then_grow)
    with pytest.raises(evidence.EvidenceRefused) as refused:
        evidence.run_report(str(run_dir), pins)
    assert refused.value.reason == "changed-while-read"


def test_a_directory_that_is_not_a_run_is_reported_not_raised(root):
    (root / "notarun").mkdir()
    report = evidence.run_report(str(root / "notarun"))
    assert report["ok"] is False and "the run has no run.json" in report["problem"]


# ----------------------------------------------------------------- flow manifests
@pytest.fixture
def flow(root):
    flow_path = root / "flows" / "f.md"
    flow_path.parent.mkdir()
    flow_path.write_text(FLOW, encoding="utf-8")
    policy_pack.keygen(str(root / "authority"), "authority")
    return flow_path, str(root / "authority" / "authority.key"), str(root / "authority" / "authority.pub")


def test_a_flow_with_no_manifest_is_unsigned(flow):
    flow_path, _priv, pub = flow
    status = evidence.manifest_status(str(flow_path), [pub])
    assert status["status"] == "unsigned" and status["flow_sha256"] == flow_authority.flow_sha256(str(flow_path))


def test_a_signed_flow_is_signed_under_its_pinned_key_and_stale_once_edited(flow):
    flow_path, priv, pub = flow
    flow_authority.sign_flow(str(flow_path), 1, priv, pub)
    status = evidence.manifest_status(str(flow_path), [pub])
    assert status["status"] == "signed" and status["version"] == 1 and status["causes"] == []
    assert evidence.manifest_status(str(flow_path))["status"] == "unchecked"
    flow_path.write_text(FLOW + "\n", encoding="utf-8")
    stale = evidence.manifest_status(str(flow_path), [pub])
    assert stale["status"] == "stale" and stale["causes"][0]["name"] == "flow:sha256-mismatch"
    assert stale["manifest_flow_sha256"] != stale["flow_sha256"]


def test_a_manifest_signed_by_another_key_is_invalid(flow, root):
    flow_path, priv, pub = flow
    flow_authority.sign_flow(str(flow_path), 1, priv, pub)
    policy_pack.keygen(str(root / "other"), "authority")
    status = evidence.manifest_status(str(flow_path), [str(root / "other" / "authority.pub")])
    assert status["status"] == "invalid" and status["causes"][0]["name"] == "sig:invalid"


def test_a_manifest_symlinked_out_of_the_roots_is_refused(flow, tmp_path):
    flow_path, priv, pub = flow
    flow_authority.sign_flow(str(flow_path), 1, priv, pub)
    json_path, _sig = flow_authority.manifest_paths(str(flow_path))
    shutil.move(json_path, tmp_path / "m.json")
    os.symlink(tmp_path / "m.json", json_path)
    with pytest.raises(evidence.EvidenceRefused) as refused:
        evidence.manifest_status(str(flow_path), [pub])
    assert refused.value.reason == "outside-roots"


def test_manifest_status_takes_its_own_roots(tmp_path, monkeypatch):
    """Authoring asks about a flow in the followed project, which it names as the root."""
    monkeypatch.setattr(mc_config.SETTINGS, "evidence_roots", [])
    project = tmp_path / "project"
    project.mkdir()
    (project / "f.md").write_text(FLOW, encoding="utf-8")
    assert evidence.manifest_status(str(project / "f.md"), roots=[str(project)])["status"] == "unsigned"
    with pytest.raises(evidence.EvidenceRefused):
        evidence.manifest_status(str(project / "f.md"))


# ----------------------------------------------------------------- the cause decoder
def test_every_registered_cause_renders_by_code_and_by_name():
    for code, (name, class_name, description) in causes.CODES.items():
        by_code, by_name = causes_view.render(code), causes_view.render(name)
        assert by_code == by_name
        assert by_code == {"code": code, "name": name, "class": class_name, "description": description,
                           "registered": True, "clean": False, "label": f"{code} {name}"}


def test_the_clean_code_and_the_unregistered_render_as_themselves():
    assert causes_view.render(0)["clean"] is True and causes_view.render(0)["label"] == "0 clean"
    assert causes_view.render(255) == {"code": 255, "name": None, "class": None, "description": None,
                                       "registered": False, "clean": False, "label": "255 unregistered"}
    assert causes_view.render("no:such-cause")["registered"] is False
    assert causes_view.render(None)["label"] == "unrecorded"
    for hostile in (True, 1.5, [2], {"code": 2}, "<script>"):
        rendered = causes_view.render(hostile)
        assert rendered["registered"] is False and rendered["code"] is None


def test_the_registry_view_is_the_registry():
    view = causes_view.registry()
    assert view["sha256"] == causes.registry_sha256()
    assert [entry["code"] for entry in view["causes"]] == sorted(causes.CODES)
