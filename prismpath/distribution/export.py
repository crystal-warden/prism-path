# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Exports of the controller's state records and findings (owner decision 14, the plan's sections 7.6 and 7.7):
OpenTelemetry events, OCSF 1.10.0 JSON and in-toto Statement v1 in DSSE.

Export happens at the controller and never on a PEP. The signed record stays the evidence: every export carries
the record's signed bytes, base64, and `check_otel`, `check_ocsf` and `check_intoto` read those bytes again under
the PEP's enrolled instance key and refuse an export whose fields are not the record's. What an export adds from
the controller (the group, the stream's name, the controller's epoch id, whether a record was fresh, the scope of
the rollout a commit ends) is the controller's reading and is named apart under `prismpath.dist.controller.*`.

What is exported is the fleet view's: per PEP the last accepted record of each event (`Member.records`), and each
open finding with the record it was filed on (`Member.evidence`) or, for one filed with no record such as
`fleet:silent`, the PEP's last accepted record marked `last-accepted`. A record from no enrolled PEP is a finding
with its bytes and no key to check them by, and a held install statement (H13) is a finding with its sealed
envelope. A commit, a lapse or a finding cleared between two exports is not in the later one.

Scope. A rollout's scope is exported as the controller computes it, and `prismpath.dist.controller.widening` is
true only when the scope is `widening`, a release that allows more than the one it replaces. A change that is not
larger is never exported as a widening. A state kept before the scope mark (W11) has the older mark: `larger by
comparison` reads as a widening, and `larger by rule`, which says only that a table changed, is exported under
that name and never as a widening.

Integers. A 64 bit field is a JSON integer up to 2^53 - 1 and a decimal string above it, the canon/2 rule, so no
reader rounds it. The record bytes always hold the exact value.

The OCSF mapping is NOT CHECKED against the OCSF 1.10.0 schema files, which were not at hand: it is written from
the class and attribute names of the OCSF categories and classes as published (5019 Device Config State Change in
Discovery, 2004 Detection Finding in Findings). The activity of 5019 is 99 `Other`, named `Commit` or `Lapse`,
so it holds whatever that class's activity enumeration is. Every PrismPath field is under `unmapped`.
"""
from __future__ import annotations

import base64
import hashlib
from collections.abc import Callable, Iterator
from typing import Any

from prismpath.distribution import install, state_record
from prismpath.distribution.kinds import Refused
from prismpath.kernel import causes
from prismpath.ledgers import intoto

STATE_EVENT, FINDING_EVENT = "prismpath.dist.state", "prismpath.dist.finding"
OCSF_VERSION = "1.10.0"
DEVICE_CONFIG_STATE_CHANGE, DETECTION_FINDING = 5019, 2004
PREDICATE_TYPE = "https://prismpath.dev/attestations/dist-commit/v1"
FORMATS = ("otel", "ocsf", "intoto")
WIDENING, CHANGE_NOT_LARGER = "widening", "change, not larger"
_OLD_MARKS = {"larger by comparison": WIDENING, "larger by rule": "larger by rule"}
HIGH = frozenset({"fleet:state-invalid", "fleet:state-replay", "fleet:policy-mismatch", "wire:codebook-mismatch"})
SAFE_INTEGER = 2 ** 53 - 1
PREFIX = "prismpath.dist."
PRODUCT = {"name": "PrismPath", "vendor_name": "Crystal Warden Supply Chain Labs LLC",
           "feature": {"name": "policy distribution controller"}}
_OCSF_SEVERITY = {1: "Informational", 3: "Medium", 4: "High"}
_OTEL_SEVERITY = {1: (9, "INFO"), 3: (13, "WARN"), 4: (17, "ERROR")}


class Bad(ValueError):
    """An export that does not check against the signed record or statement it carries."""


def _int(value: int):
    return value if value <= SAFE_INTEGER else str(value)


def _b64(data: bytes) -> str:
    return base64.b64encode(bytes(data)).decode("ascii")


def _unb64(text: Any) -> bytes:
    if not isinstance(text, str):
        raise Bad("the record is not a base64 string")
    try:
        raw = base64.b64decode(text.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError):
        raise Bad("the record is not valid base64") from None
    if _b64(raw) != text:
        raise Bad("the record is not in canonical base64 spelling")
    return raw


def record_fields(record: state_record.StateRecord) -> dict[str, Any]:
    """Every field of a state record, flat, as every export writes it: hashes as 32 hex digits, the cause by name
    and code, the status byte and its bits, the install entry (H10, type 3) and the reconciling entry (H14)."""
    out: dict[str, Any] = {
        "event": record.event, "state": record.state, "status": record.status, "pep": bytes(record.pep_id).hex(),
        "counter": _int(record.counter), "time": _int(record.time), "epoch": _int(record.epoch),
        "stream_prefix": bytes(record.stream).hex(), "policy": bytes(record.active_policy).hex(),
        "release": bytes(record.active_release).hex(), "seq": _int(record.active_seq), "floor": _int(record.floor),
        "staged_release": bytes(record.staged_release).hex(), "staged_seq": _int(record.staged_seq),
        "trust_seq": _int(record.trust_seq), "staged": record.staged, "dev_build": record.dev_build,
        "held": record.held, "fallback": record.fallback, "body_size": len(record.body),
        "extensions_size": len(record.extensions)}
    if record.cause:
        out["cause"], out["cause_code"] = record.cause, causes.code(record.cause)
    entry = record.install
    if entry is not None:
        out.update({"install.id": bytes(entry.install_id).hex(), "install.trust_seq": entry.trust_seq,
                    "install.subject": entry.subject, "install.floor_answers": entry.answers,
                    "install.floor_overrides": entry.overrides})
    running = record.reconciling
    if running is not None:
        out.update({"reconciling.owed": running.owed, "reconciling.running_policy": bytes(running.running_policy).hex(),
                    "reconciling.running_release": bytes(running.running_release).hex(),
                    "reconciling.running_seq": _int(running.running_seq), "reconciling.floor": bytes(running.floor).hex()})
        if running.cause:
            out["reconciling.cause"], out["reconciling.cause_code"] = running.cause, causes.code(running.cause)
    return out


def scope_of(rollout: dict) -> str:
    """What a rollout does to the scope a PEP allows, as the controller marked it: `widening`, `change, not
    larger`, the older `larger by rule`, or empty for none marked."""
    if "scope" in rollout:
        return rollout["scope"] or ""
    return _OLD_MARKS.get(rollout.get("widening") or "", "")


# ------------------------------------------------------------------ what the fleet view holds
def items(controller) -> Iterator[dict]:
    """Each state record and finding the controller holds, as neutral items: `kind` is `state` or `finding`,
    `record` the signed bytes or None, and `fields` the record's fields beside the controller's own reading."""
    now = int(controller.clock())
    for pep, member in sorted(controller.members.items()):
        public = bytes.fromhex(member.public)
        about = {"controller.kind": member.kind, "controller.stream": member.stream,
                 "controller.group": member.group, "controller.epoch": _int(controller.epoch_of(member.stream)),
                 "controller.expected_seq": _int(member.expected[2]), "pep_public": member.public}
        last = member.last or {}
        records = sorted(((bytes.fromhex(data), event) for event, data in member.records.items()),
                         key=lambda one: _read(one[0], public).counter)
        for data, _event in records:
            record = _read(data, public)
            fields = dict(about)
            if last.get("counter") == record.counter:
                fields["controller.unverified"] = bool(last.get("unverified"))
                fields["controller.no_controller_key"] = bool(last.get("no_controller_key"))
            if record.event == "committed":
                scope = _commit_scope(controller, member, record)
                if scope is not None:
                    fields["controller.scope"] = scope
                    fields["controller.widening"] = scope == WIDENING
                fields.update(_full_hashes(controller, member, record))
            yield {"kind": "state", "pep": pep, "public": public, "record": data, "record_fields": record_fields(record),
                   "fields": fields, "time": record.time, "observed": now}
        newest = records[-1][0] if records else None
        for code, detail in sorted(member.findings.items()):
            evidence = member.evidence.get(code)
            data, role = (bytes.fromhex(evidence), "filed-on") if evidence else (newest, "last-accepted")
            yield _finding(pep, public, code, detail, data, role if data is not None else "none", about, now)
    for entry in controller.unknown:
        data = bytes.fromhex(entry["record"]) if entry.get("record") else None
        yield _finding(entry["pep"], None, entry["finding"], entry["detail"], data,
                       "not-enrolled" if data is not None else "none",
                       {"controller.count": entry["count"]}, now, at=int(entry["at"]))
    for key, detail in sorted(controller.install_findings.items()):
        info = controller.install_sets.get(key)
        envelopes = sorted(info["statements"].values()) if info else [key]
        for envelope_id in envelopes:
            sealed = controller.sealed(envelope_id)
            yield _finding("", None, install.WIDENED, detail, sealed, "statement" if sealed else "none",
                           {"controller.install_item": key, "controller.envelope_id": envelope_id,
                            **({"controller.stream": info["stream"], "controller.install_kind": info["kind"]}
                               if info else {})}, now, uid=f"install:{key}:{envelope_id}")


def _read(data: bytes, public: bytes) -> state_record.StateRecord:
    try:
        return state_record.read(data, public)
    except Refused as refused:
        raise Bad(f"a kept record does not verify under the enrolled key: {refused}") from None


def _finding(pep: str, public: bytes | None, code: str, detail: str, data: bytes | None, role: str,
             about: dict, now: int, at: int | None = None, uid: str | None = None) -> dict:
    fields = {**about, "finding": code, "finding.detail": detail, "finding.record_role": role}
    number = causes.code(code)
    if number is not None:
        fields["finding.cause_code"], fields["finding.cause_class"] = number, causes.cause_class(code)
    record = None
    if data is not None and public is not None and role in ("filed-on", "last-accepted"):
        try:
            record = record_fields(state_record.read(data, public))
        except Refused:
            record = None                         # a record filed as state-invalid does not verify, by its finding
    time = at if at is not None else (int(record["time"]) if record and role == "filed-on" else now)
    return {"kind": "finding", "pep": pep, "public": public, "record": data, "record_fields": record, "fields": fields,
            "time": time, "observed": now, "uid": uid or f"{pep or 'unreadable'}:{code}"}


def _commit_scope(controller, member, record) -> str | None:
    """The scope of the latest rollout of the member's stream whose release and `seq` the commit names."""
    release = bytes(record.active_release).hex()
    found = [one for one in controller.rollouts if one.stream == member.stream and one.seq == record.active_seq
             and one.release[:32] == release and member.pep in one.members]
    return scope_of(found[-1].document()) if found else None


def _full_hashes(controller, member, record) -> dict:
    """The full SHA-256 of the committed policy and release, from the envelopes the controller stored, where one
    matches the record's prefixes."""
    policy, release = bytes(record.active_policy).hex(), bytes(record.active_release).hex()
    for info in controller.stored.values():
        if (info["stream"] == member.stream and info["seq"] == record.active_seq and info.get("policy", "")[:32] == policy
                and info.get("release", "")[:32] == release):
            return {"controller.policy_sha256": info["policy"], "controller.release_id": info["release"]}
    return {}


def _severity(item: dict) -> int:
    if item["kind"] == "finding":
        return 4 if item["fields"]["finding"] in HIGH else 3
    return 3 if item["record_fields"]["event"] in ("lapsed", "rolled-back", "fallback", "refused") else 1


def _attributes(item: dict) -> dict[str, Any]:
    out = {PREFIX + "record." + key: value for key, value in (item["record_fields"] or {}).items()}
    out.update({PREFIX + key: value for key, value in item["fields"].items()})
    if item["record"] is not None:
        out[PREFIX + "record"] = _b64(item["record"])
        out[PREFIX + "record.sha256"] = hashlib.sha256(item["record"]).hexdigest()
    return {key: value for key, value in out.items() if value is not None}


def _message(item: dict) -> str:
    if item["kind"] == "finding":
        return f"{item['fields']['finding']} on {item['pep'] or 'an unreadable sender'}: {item['fields']['finding.detail']}"
    fields = item["record_fields"]
    return (f"{item['pep']} {fields['event']}, state {fields['state']}, seq {fields['seq']} policy {fields['policy']}"
            + (f", cause {fields['cause']}" if "cause" in fields else ""))


# ------------------------------------------------------------------ OpenTelemetry events
def otel_events(controller, sink: Callable[[dict], None]) -> int:
    """Emit each item as an OTel-shaped event dict to `sink`, the pattern of `prismpath.ledgers.otel`: an
    `event_name` of `prismpath.dist.state` or `prismpath.dist.finding`, nanosecond timestamps, a severity number
    and text, a body and flat attributes with the cause code, the hashes, `seq` and the record. Returns the count."""
    count = 0
    for item in items(controller):
        number, text = _OTEL_SEVERITY[_severity(item)]
        sink({"event_name": STATE_EVENT if item["kind"] == "state" else FINDING_EVENT,
              "timestamp": int(item["time"]) * 10 ** 9, "observed_timestamp": item["observed"] * 10 ** 9,
              "severity_number": number, "severity_text": text, "body": _message(item),
              "attributes": _attributes(item), "resource": {"service.name": "prismpath-dist-controller"}})
        count += 1
    return count


def to_otel_sink(logger) -> Callable[[dict], None]:
    """Adapt event dicts to OpenTelemetry log records on `logger` (needs `pip install opentelemetry-sdk`). An API
    without `event_name` gets the name as the `event.name` attribute."""
    from opentelemetry._logs import LogRecord, SeverityNumber

    def sink(event: dict) -> None:
        args = dict(timestamp=event["timestamp"], observed_timestamp=event["observed_timestamp"],
                    severity_number=SeverityNumber(event["severity_number"]), severity_text=event["severity_text"],
                    body=event["body"])
        try:
            record = LogRecord(event_name=event["event_name"], attributes=dict(event["attributes"]), **args)
        except TypeError:
            record = LogRecord(attributes={**event["attributes"], "event.name": event["event_name"]}, **args)
        logger.emit(record)
    return sink


# ------------------------------------------------------------------ OCSF 1.10.0
def ocsf_events(controller) -> list[dict]:
    """A commit or a lapse as Device Config State Change (5019) and each finding as Detection Finding (2004), with
    the signed record base64 in `raw_data` and its SHA-256 in `raw_data_hash`. Other events of a record go to the
    OTel export only, since section 7.6 maps these two. Unchecked against the schema files (module docstring)."""
    out = []
    for item in items(controller):
        if item["kind"] == "state" and item["record_fields"]["event"] not in ("committed", "lapsed"):
            continue
        severity = _severity(item)
        event: dict[str, Any] = {
            "time": int(item["time"]) * 1000, "severity_id": severity, "severity": _OCSF_SEVERITY[severity],
            "message": _message(item),
            "metadata": {"version": OCSF_VERSION, "product": dict(PRODUCT), "logged_time": item["observed"] * 1000,
                         "uid": (f"{item['pep']}:{item['record_fields']['counter']}" if item["kind"] == "state"
                                 else item["uid"])},
            "unmapped": _attributes(item)}
        if item["record"] is not None:
            event["raw_data"] = _b64(item["record"])
            event["raw_data_hash"] = {"algorithm_id": 3, "algorithm": "SHA-256",
                                      "value": hashlib.sha256(item["record"]).hexdigest()}
        device = {"uid": item["pep"], "type_id": 99, "type": f"PrismPath {item['fields'].get('controller.kind', 'PEP')} PEP"}
        if item["kind"] == "state":
            activity = "Commit" if item["record_fields"]["event"] == "committed" else "Lapse"
            event.update({"class_uid": DEVICE_CONFIG_STATE_CHANGE, "class_name": "Device Config State Change",
                          "category_uid": 5, "category_name": "Discovery", "activity_id": 99, "activity_name": activity,
                          "type_uid": DEVICE_CONFIG_STATE_CHANGE * 100 + 99,
                          "type_name": f"Device Config State Change: {activity}", "device": device})
        else:
            code = item["fields"]["finding"]
            event.update({"class_uid": DETECTION_FINDING, "class_name": "Detection Finding", "category_uid": 2,
                          "category_name": "Findings", "activity_id": 1, "activity_name": "Create",
                          "type_uid": DETECTION_FINDING * 100 + 1, "type_name": "Detection Finding: Create",
                          "status_id": 1, "status": "New",
                          "finding_info": {"uid": item["uid"], "title": code, "desc": item["fields"]["finding.detail"],
                                           "types": [code]},
                          "resources": [{"uid": item["pep"] or item["fields"].get("controller.envelope_id", ""),
                                         "type": device["type"] if item["pep"] else "PrismPath install statement"}]})
            if item["pep"]:
                event["device"] = device
        out.append(event)
    return out


# ------------------------------------------------------------------ in-toto
def intoto_envelopes(controller) -> list[dict]:
    """An in-toto Statement v1 about each commit the controller holds, in a DSSE envelope signed by the
    controller's instance key through `prismpath.ledgers.intoto`. The subject is the signed record by its SHA-256,
    and the committed policy and release by their full SHA-256 where the controller stored them. The predicate
    carries the record base64, its fields and the controller's reading."""
    if controller.instance_key is None:
        raise ValueError("an in-toto export is signed by the controller's instance key")
    out = []
    for item in items(controller):
        if item["kind"] != "state" or item["record_fields"]["event"] != "committed":
            continue
        fields = item["fields"]
        subject = [{"name": f"prismpath-dist-state/{item['pep']}/{item['record_fields']['counter']}",
                    "digest": {"sha256": hashlib.sha256(item["record"]).hexdigest()}}]
        for name, key in (("policy", "controller.policy_sha256"), ("release", "controller.release_id")):
            if len(fields.get(key, "")) == 64:
                subject.append({"name": f"prismpath-dist-{name}/{fields[key]}", "digest": {"sha256": fields[key]}})
        predicate = {"record": _b64(item["record"]), "fields": item["record_fields"],
                     "controller": {key.removeprefix("controller."): value
                                    for key, value in fields.items()},
                     "controller_key_id": controller.instance_key.key_id}
        statement = {"_type": intoto.STATEMENT_TYPE, "subject": subject, "predicateType": PREDICATE_TYPE,
                     "predicate": predicate}
        out.append(intoto.sign_statement(statement, controller.instance_key))
    return out


def export(controller, form: str) -> list[dict]:
    """The export `form` (`otel`, `ocsf` or `intoto`) of what the controller holds, as JSON documents."""
    if form == "otel":
        events: list[dict] = []
        otel_events(controller, events.append)
        return events
    if form == "ocsf":
        return ocsf_events(controller)
    if form == "intoto":
        return intoto_envelopes(controller)
    raise ValueError(f"an export is one of {', '.join(FORMATS)}")


# ------------------------------------------------------------------ checked back against the signed record
def _check_record(text: Any, digest: str | None, instance_public: bytes, fields: dict) -> state_record.StateRecord:
    data = _unb64(text)
    if digest is not None and hashlib.sha256(data).hexdigest() != digest:
        raise Bad("the record's SHA-256 is not the one the export names")
    try:
        record = state_record.read(data, bytes(instance_public))
    except Refused as refused:
        raise Bad(f"the record does not verify under the instance key: {refused}") from None
    if record_fields(record) != fields:
        raise Bad("the export's record fields are not the signed record's")
    return record


def _record_of(attributes: dict) -> dict:
    head = PREFIX + "record."
    return {key[len(head):]: value for key, value in attributes.items()
            if key.startswith(head) and key != head + "sha256"}


def check_otel(event: dict, instance_public: bytes) -> state_record.StateRecord:
    """The signed record an OTel event carries, once it verifies under the PEP's instance key and every
    `prismpath.dist.record.*` attribute is the record's. `Bad` otherwise."""
    attributes = event.get("attributes", {})
    record = _check_record(attributes.get(PREFIX + "record"), attributes.get(PREFIX + "record.sha256"),
                           instance_public, _record_of(attributes))
    if event.get("event_name") == STATE_EVENT and event.get("timestamp") != record.time * 10 ** 9:
        raise Bad("the event's time is not the record's")
    return record


def check_ocsf(event: dict, instance_public: bytes) -> state_record.StateRecord:
    """The signed record in an OCSF event's `raw_data`, once it verifies under the PEP's instance key, its hash
    is `raw_data_hash` and the fields under `unmapped` are its own. A 5019 event is a commit or a lapse and names
    the record's PEP as its device. `Bad` otherwise."""
    record = _check_record(event.get("raw_data"), (event.get("raw_data_hash") or {}).get("value"), instance_public,
                           _record_of(event.get("unmapped", {})))
    if event.get("class_uid") == DEVICE_CONFIG_STATE_CHANGE:
        wanted = {"committed": "Commit", "lapsed": "Lapse"}.get(record.event)
        if wanted is None or event.get("activity_name") != wanted or event.get("time") != record.time * 1000:
            raise Bad("a Device Config State Change that is not the record's commit or lapse")
        if event.get("device", {}).get("uid") != bytes(record.pep_id).hex():
            raise Bad("the device is not the record's PEP")
    return record


def check_intoto(envelope: dict, controller_public: bytes, instance_public: bytes) -> dict:
    """The statement of an in-toto export, once its DSSE signature verifies under the controller's instance key,
    the record in its predicate verifies under the PEP's, is a commit, is the first subject by its SHA-256, and
    its fields are the predicate's. `Bad` otherwise."""
    try:
        statement = intoto.open_statement(envelope, controller_public, PREDICATE_TYPE)
    except intoto.Bad as bad:
        raise Bad(str(bad)) from None
    predicate, subject = statement["predicate"], statement["subject"]
    if not isinstance(predicate, dict) or not isinstance(subject, list) or not subject:
        raise Bad("the statement has no predicate or no subject")
    record = _check_record(predicate.get("record"), subject[0].get("digest", {}).get("sha256"), instance_public,
                           predicate.get("fields"))
    if record.event != "committed":
        raise Bad("an in-toto export is about a commit")
    return statement
