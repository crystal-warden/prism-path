# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Exports of the controller's state records and findings (prismpath/distribution/export.py): OpenTelemetry
events, OCSF 1.10.0 and in-toto Statement v1 in DSSE. Each export of each event kind is checked back against the
signed record it came from, and changing a field or a byte of the record fails the check."""
import base64
import hashlib
import json
import sys
import types
from dataclasses import replace

import pytest

pytest.importorskip("cryptography")

from prismpath.distribution import export, state_record
from prismpath.distribution.controller import Controller
from prismpath.distribution.state_record import (
    InstallEntry,
    ReconcilingEntry,
)
from prismpath.tests import _dist
from prismpath.tests._dist import STREAM
from prismpath.tests.test_distribution_controller import NEW, OLD, Fleet

CONTROLLER = _dist.instance_key("C").public_raw


def _public(fleet, name):
    return fleet.points[name].key.public_raw


def _committed(tmp_path, names=("p1",)):
    """A fleet that committed a first install (larger by comparison) and then a change of the host table (larger
    by rule), and then lapsed at the expiry of both releases."""
    fleet = Fleet(tmp_path, names=names)
    fleet.put(OLD, 1)
    fleet.controller.offer("fleet", STREAM, 1)
    for _ in range(3):
        fleet.round()
    fleet.put(NEW, 2, widen=True)
    fleet.controller.offer("fleet", STREAM, 2)
    for _ in range(3):
        fleet.round()
    return fleet


def _lapse(fleet):
    fleet.clock.now = _dist.EXPIRES + 100
    fleet.round()


def _otel(fleet):
    events = []
    assert export.otel_events(fleet.controller, events.append) == len(events)
    return events


def _states(events, event):
    return [one for one in events if one["event_name"] == export.STATE_EVENT
            and one["attributes"]["prismpath.dist.record.event"] == event]


def _findings(events, code):
    return [one for one in events if one["event_name"] == export.FINDING_EVENT
            and one["attributes"]["prismpath.dist.finding"] == code]


def _flip_record(text):
    data = bytearray(base64.b64decode(text))
    data[40] ^= 1
    return base64.b64encode(bytes(data)).decode("ascii")


# ------------------------------------------------------------------ OpenTelemetry

def test_each_state_event_exports_as_an_otel_event_that_checks_against_its_signed_record(tmp_path):
    fleet = _committed(tmp_path)
    _lapse(fleet)
    events = _otel(fleet)
    public = _public(fleet, "p1")
    kept = fleet.member("p1").records
    assert {"provisioned", "staged", "committed", "beat", "lapsed"} <= set(kept)
    for event in ("provisioned", "staged", "committed", "beat", "lapsed"):
        (one,) = _states(events, event)
        record = export.check_otel(one, public)
        assert record.event == event and one["timestamp"] == record.time * 10 ** 9
        assert base64.b64decode(one["attributes"]["prismpath.dist.record"]) == bytes.fromhex(kept[event])
        assert one["attributes"]["prismpath.dist.record.seq"] == record.active_seq
        assert one["attributes"]["prismpath.dist.controller.group"] == "fleet"
    (lapsed,) = _states(events, "lapsed")
    assert lapsed["severity_text"] == "WARN" and lapsed["attributes"]["prismpath.dist.record.state"] == "no-policy"
    assert lapsed["attributes"]["prismpath.dist.record.cause_code"] is not None
    (commit,) = _states(events, "committed")
    assert commit["severity_text"] == "INFO" and json.loads(json.dumps(commit)) == commit


def test_an_otel_event_whose_fields_or_bytes_are_changed_does_not_check(tmp_path):
    fleet = _committed(tmp_path)
    (commit,) = _states(_otel(fleet), "committed")
    public = _public(fleet, "p1")
    changed = json.loads(json.dumps(commit))
    changed["attributes"]["prismpath.dist.record.seq"] = 9
    with pytest.raises(export.Bad, match="fields"):
        export.check_otel(changed, public)
    flipped = json.loads(json.dumps(commit))
    flipped["attributes"]["prismpath.dist.record"] = _flip_record(commit["attributes"]["prismpath.dist.record"])
    with pytest.raises(export.Bad, match="SHA-256"):
        export.check_otel(flipped, public)
    del flipped["attributes"]["prismpath.dist.record.sha256"]
    with pytest.raises(export.Bad, match="does not verify"):
        export.check_otel(flipped, public)
    with pytest.raises(export.Bad, match="does not verify"):
        export.check_otel(commit, _dist.instance_key("other").public_raw)


def test_findings_export_with_the_record_they_were_filed_on_or_the_last_accepted_one(tmp_path):
    fleet = Fleet(tmp_path, names=("p1",))
    controller, public = fleet.controller, _public(fleet, "p1")
    assert controller.receive(fleet.record("p1")) is None
    other = fleet.record("p1", active_seq=7)                       # a policy other than the expected one
    assert controller.receive(other) == "fleet:policy-mismatch"
    record = state_record.read(fleet.record("p1"), public)
    forged = state_record.build(replace(record, counter=record.counter + 5), _dist.instance_key("A"))
    assert controller.receive(forged) == "fleet:state-invalid"
    stranger = _dist.instance_key("S")
    alien = state_record.build(replace(record, pep_id=state_record.pep_id(stranger.public_raw)), stranger)
    assert controller.receive(alien) == "fleet:state-invalid"
    fleet.clock.now += 3 * 30
    controller.tick()
    events = _otel(fleet)

    (mismatch,) = _findings(events, "fleet:policy-mismatch")
    assert mismatch["attributes"]["prismpath.dist.finding.record_role"] == "filed-on"
    assert export.check_otel(mismatch, public).active_seq == 7
    assert base64.b64decode(mismatch["attributes"]["prismpath.dist.record"]) == other
    assert mismatch["severity_text"] == "ERROR"
    assert mismatch["attributes"]["prismpath.dist.finding.cause_code"] is not None

    (silent,) = _findings(events, "fleet:silent")
    (invalid,) = [one for one in _findings(events, "fleet:state-invalid")
                  if one["attributes"].get("prismpath.dist.pep_public")]
    assert silent["attributes"]["prismpath.dist.finding.record_role"] == "last-accepted"
    assert export.check_otel(silent, public).active_seq == 7       # the last record accepted, the mismatched one
    assert base64.b64decode(invalid["attributes"]["prismpath.dist.record"]) == forged
    with pytest.raises(export.Bad):                                 # signed by another key, as its finding says
        export.check_otel(invalid, public)
    unknown = [one for one in _findings(events, "fleet:state-invalid")
               if one["attributes"]["prismpath.dist.finding.record_role"] == "not-enrolled"]
    assert len(unknown) == 1 and base64.b64decode(unknown[0]["attributes"]["prismpath.dist.record"]) == alien
    assert state_record.read(alien, stranger.public_raw).pep_id == state_record.pep_id(stranger.public_raw)

    assert controller.receive(fleet.record("p1", active_seq=0)) is None      # the expected release again
    events = _otel(fleet)
    assert not [one for one in events if one["event_name"] == export.FINDING_EVENT
                and one["attributes"].get("prismpath.dist.pep_public")]
    assert fleet.member("p1").evidence == {}


def test_the_reconciling_and_install_entries_and_status_3_export_in_full(tmp_path):
    fleet = Fleet(tmp_path, names=("p1",))
    controller, public = fleet.controller, _public(fleet, "p1")
    entry = ReconcilingEntry(owed="lapsed", cause="dist:expired", running_policy=b"\x01" * 16,
                             running_release=b"\x02" * 16, running_seq=3, floor=b"\x00" * 16)
    install = InstallEntry(install_id=b"\x07" * 16, trust_seq=2, subject="install.floor", answers=4, overrides=1)
    controller.receive(fleet.record("p1", "install-applied", extensions=install.extension()))
    controller.receive(fleet.record("p1", "reconciling", state="reconciling", extensions=entry.extension()))
    events = _otel(fleet)
    (reconciling,) = _states(events, "reconciling")
    attributes = reconciling["attributes"]
    assert export.check_otel(reconciling, public).reconciling == entry
    assert attributes["prismpath.dist.record.status"] & 0x03 == 3
    assert attributes["prismpath.dist.record.reconciling.owed"] == "lapsed"
    assert attributes["prismpath.dist.record.reconciling.cause"] == "dist:expired"
    assert attributes["prismpath.dist.record.reconciling.running_release"] == "02" * 16
    assert attributes["prismpath.dist.record.reconciling.running_seq"] == 3
    (finding,) = _findings(events, "dist:reconciling")
    assert export.check_otel(finding, public).state == "reconciling"
    (applied,) = _states(events, "install-applied")
    assert export.check_otel(applied, public).install == install
    assert applied["attributes"]["prismpath.dist.record.install.id"] == "07" * 16
    assert applied["attributes"]["prismpath.dist.record.install.subject"] == "install.floor"
    assert (applied["attributes"]["prismpath.dist.record.install.floor_answers"],
            applied["attributes"]["prismpath.dist.record.install.floor_overrides"]) == (4, 1)


def test_the_epoch_of_the_record_and_the_controller_statement_epoch_are_both_exported(tmp_path):
    fleet = _committed(tmp_path)
    (commit,) = _states(_otel(fleet), "committed")
    record = export.check_otel(commit, _public(fleet, "p1"))
    assert commit["attributes"]["prismpath.dist.record.epoch"] == record.epoch
    assert commit["attributes"]["prismpath.dist.controller.epoch"] == fleet.controller.epoch_of(STREAM)
    assert commit["attributes"]["prismpath.dist.controller.policy_sha256"][:32] == bytes(record.active_policy).hex()


def test_otel_events_reach_an_sdk_logger_through_to_otel_sink(tmp_path, monkeypatch):
    """The adapter to the OpenTelemetry logs API, against a stand in for the API module, so it runs without the SDK."""
    class LogRecord:
        def __init__(self, **args):
            self.args = args

    logs = types.ModuleType("opentelemetry._logs")
    logs.LogRecord, logs.SeverityNumber = LogRecord, int
    monkeypatch.setitem(sys.modules, "opentelemetry", types.ModuleType("opentelemetry"))
    monkeypatch.setitem(sys.modules, "opentelemetry._logs", logs)
    emitted = []
    logger = types.SimpleNamespace(emit=emitted.append)
    fleet = _committed(tmp_path)
    count = export.otel_events(fleet.controller, export.to_otel_sink(logger))
    assert count == len(emitted) > 0
    names = {one.args["event_name"] for one in emitted}
    assert names == {export.STATE_EVENT} or names == {export.STATE_EVENT, export.FINDING_EVENT}
    assert all("prismpath.dist.record" in one.args["attributes"] for one in emitted)


# ------------------------------------------------------------------ OCSF

def test_a_commit_and_a_lapse_export_as_ocsf_5019_and_a_finding_as_2004_with_the_record_in_raw_data(tmp_path):
    fleet = _committed(tmp_path)
    _lapse(fleet)
    events = export.ocsf_events(fleet.controller)
    public = _public(fleet, "p1")
    states = [one for one in events if one["class_uid"] == export.DEVICE_CONFIG_STATE_CHANGE]
    assert sorted(one["activity_name"] for one in states) == ["Commit", "Lapse"]
    for one in states:
        record = export.check_ocsf(one, public)
        assert one["category_uid"] == 5 and one["activity_id"] == 99 and one["type_uid"] == 501999
        assert one["metadata"]["version"] == "1.10.0" and one["metadata"]["product"]["name"] == "PrismPath"
        assert one["time"] == record.time * 1000 and one["device"]["uid"] == bytes(record.pep_id).hex()
        assert one["raw_data_hash"] == {"algorithm_id": 3, "algorithm": "SHA-256",
                                        "value": hashlib.sha256(base64.b64decode(one["raw_data"])).hexdigest()}
        assert record.event == {"Commit": "committed", "Lapse": "lapsed"}[one["activity_name"]]
    findings = [one for one in events if one["class_uid"] == export.DETECTION_FINDING]
    assert findings and all(one["category_uid"] == 2 and one["type_uid"] == 200401 for one in findings)
    for one in findings:
        assert one["finding_info"]["title"] == one["unmapped"]["prismpath.dist.finding"]
        assert export.check_ocsf(one, public).pep_id == bytes.fromhex(one["device"]["uid"])
    assert not [one for one in events if one["unmapped"].get("prismpath.dist.record.event") in ("beat", "staged")]


def test_an_ocsf_event_that_is_not_its_record_does_not_check(tmp_path):
    fleet = _committed(tmp_path)
    (commit,) = [one for one in export.ocsf_events(fleet.controller) if one["class_uid"] == 5019]
    public = _public(fleet, "p1")
    renamed = json.loads(json.dumps(commit))
    renamed["activity_name"] = "Lapse"
    with pytest.raises(export.Bad, match="commit or lapse"):
        export.check_ocsf(renamed, public)
    moved = json.loads(json.dumps(commit))
    moved["device"]["uid"] = "00" * 16
    with pytest.raises(export.Bad, match="device"):
        export.check_ocsf(moved, public)
    edited = json.loads(json.dumps(commit))
    edited["unmapped"]["prismpath.dist.record.policy"] = "00" * 16
    with pytest.raises(export.Bad, match="fields"):
        export.check_ocsf(edited, public)
    flipped = json.loads(json.dumps(commit))
    flipped["raw_data"] = _flip_record(commit["raw_data"])
    with pytest.raises(export.Bad):
        export.check_ocsf(flipped, public)


# ------------------------------------------------------------------ in-toto

def test_each_commit_exports_as_an_in_toto_statement_signed_by_the_controller_instance_key(tmp_path):
    fleet = _committed(tmp_path, names=("p1", "p2"))
    envelopes = export.intoto_envelopes(fleet.controller)
    assert len(envelopes) == 2                                      # one commit kept per PEP, none of any other event
    for envelope in envelopes:
        statement = json.loads(base64.b64decode(envelope["payload"]))
        pep = statement["predicate"]["fields"]["pep"]
        name = next(name for name, pep_id in fleet.ids.items() if pep_id == pep)
        opened = export.check_intoto(envelope, CONTROLLER, _public(fleet, name))
        record = state_record.read(base64.b64decode(opened["predicate"]["record"]), _public(fleet, name))
        assert record.event == "committed" and record.active_seq == 2
        assert opened["predicateType"] == export.PREDICATE_TYPE
        assert opened["subject"][0]["digest"]["sha256"] == hashlib.sha256(base64.b64decode(
            opened["predicate"]["record"])).hexdigest()
        policy = opened["predicate"]["controller"]["policy_sha256"]
        assert {"name": f"prismpath-dist-policy/{policy}", "digest": {"sha256": policy}} in opened["subject"]
        assert envelope["signatures"][0]["keyid"] == _dist.instance_key("C").key_id
        with pytest.raises(export.Bad, match="signature"):
            export.check_intoto(envelope, _dist.instance_key("other").public_raw, _public(fleet, name))
        with pytest.raises(export.Bad, match="does not verify"):
            export.check_intoto(envelope, CONTROLLER, _dist.instance_key("other").public_raw)


def test_an_in_toto_statement_resigned_over_changed_fields_does_not_check(tmp_path):
    from prismpath.ledgers import intoto
    fleet = _committed(tmp_path)
    (envelope,) = export.intoto_envelopes(fleet.controller)
    statement = json.loads(base64.b64decode(envelope["payload"]))
    statement["predicate"]["fields"]["seq"] = 1
    changed = intoto.sign_statement(statement, _dist.instance_key("C"))
    with pytest.raises(export.Bad, match="fields"):
        export.check_intoto(changed, CONTROLLER, _public(fleet, "p1"))
    statement = json.loads(base64.b64decode(envelope["payload"]))
    statement["subject"][0]["digest"]["sha256"] = "00" * 32
    with pytest.raises(export.Bad, match="SHA-256"):
        export.check_intoto(intoto.sign_statement(statement, _dist.instance_key("C")), CONTROLLER, _public(fleet, "p1"))


# ------------------------------------------------------------------ scope: a widening only when scope grew

def test_only_a_rollout_whose_scope_grew_exports_as_a_widening(tmp_path):
    """The first install is larger by comparison and exports as a widening. The second release is larger only by
    the host rule that any table change counts, and never exports as a widening, nor does a change, not larger."""
    fleet = Fleet(tmp_path, names=("p1",))
    fleet.put(OLD, 1)
    fleet.controller.offer("fleet", STREAM, 1)
    for _ in range(3):
        fleet.round()
    (first,) = _states(_otel(fleet), "committed")
    assert first["attributes"]["prismpath.dist.controller.scope"] == export.WIDENING
    assert first["attributes"]["prismpath.dist.controller.widening"] is True
    fleet.put(NEW, 2, widen=True)
    fleet.controller.offer("fleet", STREAM, 2)
    for _ in range(3):
        fleet.round()
    for doc in (_states(_otel(fleet), "committed")[0]["attributes"],
                [one for one in export.ocsf_events(fleet.controller) if one["class_uid"] == 5019][0]["unmapped"]):
        assert doc["prismpath.dist.controller.scope"] == "larger by rule"
        assert doc["prismpath.dist.controller.widening"] is False
    (envelope,) = export.intoto_envelopes(fleet.controller)
    assert json.loads(base64.b64decode(envelope["payload"]))["predicate"]["controller"]["widening"] is False

    assert export.scope_of({"scope": export.CHANGE_NOT_LARGER, "widening": "larger by comparison"}) == \
        export.CHANGE_NOT_LARGER
    assert export.scope_of({"scope": export.WIDENING}) == export.WIDENING
    assert export.scope_of({"widening": "larger by comparison"}) == export.WIDENING
    assert export.scope_of({"widening": "larger by rule"}) == "larger by rule"
    assert export.scope_of({"widening": ""}) == "" == export.scope_of({"scope": ""})
    rollout = fleet.controller.rollouts[-1]
    rollout.document = lambda: {"scope": export.CHANGE_NOT_LARGER}          # the mark the change statement gives
    (change,) = _states(_otel(fleet), "committed")
    assert change["attributes"]["prismpath.dist.controller.scope"] == export.CHANGE_NOT_LARGER
    assert change["attributes"]["prismpath.dist.controller.widening"] is False


# ------------------------------------------------------------------ the rest

def test_the_kept_records_and_evidence_survive_a_restart_and_export_the_same(tmp_path):
    fleet = _committed(tmp_path)
    fleet.controller.receive(fleet.record("p1", active_seq=7))
    before = {form: export.export(fleet.controller, form) for form in ("otel", "ocsf")}
    fleet.controller.save()
    again = Controller(str(fleet.dir), _dist.instance_key("C"), clock=fleet.clock)
    assert {form: export.export(again, form) for form in ("otel", "ocsf")} == before
    assert again.members[fleet.ids["p1"]].evidence == fleet.member("p1").evidence != {}


def test_a_64_bit_field_past_2_to_the_53_is_a_decimal_string():
    key = _dist.instance_key("p1")
    record = state_record.StateRecord(event="beat", state="no-policy", cause=None,
                                      pep_id=state_record.pep_id(key.public_raw), counter=2 ** 60, time=5,
                                      stream=state_record.stream_prefix(STREAM))
    fields = export.record_fields(state_record.read(state_record.build(record, key), key.public_raw))
    assert fields["counter"] == str(2 ** 60) and fields["time"] == 5


def test_a_held_install_statement_exports_as_a_finding_with_its_sealed_envelope(tmp_path):
    from prismpath.tests.test_distribution_install_controller import (
        FLOOR,
        WIDER,
        _ids,
        _set,
    )
    from prismpath.tests.test_distribution_install_controller import (
        Fleet as InstallFleet,
    )
    fleet = InstallFleet(tmp_path)
    pairs = _set(fleet.first, FLOOR, WIDER)
    fleet.put(pairs)
    assert fleet.controller.install_findings
    held = [one for one in _otel(fleet) if one["attributes"].get("prismpath.dist.finding.record_role") == "statement"]
    assert sorted(one["attributes"]["prismpath.dist.controller.envelope_id"] for one in held) == sorted(_ids(pairs))
    for one in held:
        sealed = base64.b64decode(one["attributes"]["prismpath.dist.record"])
        assert sealed == fleet.controller.sealed(one["attributes"]["prismpath.dist.controller.envelope_id"])
        assert one["attributes"]["prismpath.dist.finding"] == "dist:install-widened"
    findings = [one for one in export.ocsf_events(fleet.controller) if one["class_uid"] == 2004
                and one["unmapped"].get("prismpath.dist.finding.record_role") == "statement"]
    assert len(findings) == len(held) and all(one["raw_data"] for one in findings)


def test_dist_fleet_export_writes_json_lines_at_the_controller(tmp_path, capsys):
    from cryptography.hazmat.primitives import serialization

    from prismpath import cli
    fleet = _committed(tmp_path)
    fleet.controller.save()
    key = tmp_path / "controller.key"
    key.write_bytes(_dist.GEN.test_key("C").private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                          serialization.NoEncryption()))
    parser = cli.build_parser()
    for form in export.FORMATS:
        args = parser.parse_args(["dist", "fleet", "--dir", str(fleet.dir), "--key", str(key), "--export", form])
        assert args.func(args) == 0
        lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
        assert lines
        for doc in lines:
            if form == "intoto":
                export.check_intoto(doc, CONTROLLER, _public(fleet, "p1"))
            elif form == "ocsf" and doc["unmapped"].get("prismpath.dist.finding.record_role") in ("filed-on",
                                                                                                   "last-accepted"):
                export.check_ocsf(doc, _public(fleet, "p1"))
            elif form == "otel" and doc["event_name"] == export.STATE_EVENT:
                export.check_otel(doc, _public(fleet, "p1"))
    with pytest.raises(SystemExit):
        parser.parse_args(["dist", "fleet", "--dir", str(fleet.dir), "--key", str(key), "--export", "syslog"])
