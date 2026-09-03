"""Emit port: schema validity across the status matrix, negative-schema tests (the gate must BITE),
and the load-bearing invariants — provenance embedding, deterministic RFC-4122 v5 uuids, token-safe ids."""
import json, re
import pytest
import emit
from sample import record, FIXED_NOW

STATUSES = ["met", "partially-met", "not-met"]
UUID_V5 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


# ---------------- validity across the status matrix ----------------
@pytest.mark.parametrize("statuses", [
    ["met"], ["not-met"], ["partially-met"],
    ["met", "met"], ["not-met", "not-met"],
    ["met", "not-met", "partially-met"],
])
def test_all_formats_valid(statuses):
    recs = [record("3.1.%d" % (i + 1), "C%d" % i, s, [] if s == "met" else ["3.1.%d[a]" % (i + 1)])
            for i, s in enumerate(statuses)]
    out = emit.emit(recs, fmt="both", now=FIXED_NOW)
    for name, r in out.items():
        assert r["valid"] is True, (name, r["errors"][:4])


def test_empty_results_still_valid():
    out = emit.emit([], fmt="both", now=FIXED_NOW)
    for name, r in out.items():
        assert r["valid"] is True, (name, r["errors"][:4])


def test_all_met_poam_has_placeholder_item():
    doc = emit.emit_oscal_poam([record("3.1.1", "C", "met")], now=FIXED_NOW)
    items = doc["plan-of-action-and-milestones"]["poam-items"]
    assert len(items) == 1 and items[0]["title"] == "No open items"


# ---------------- negative-schema tests: validate() must REJECT ----------------
def test_poam_missing_metadata_rejected(records):
    doc = emit.emit_oscal_poam(records, now=FIXED_NOW)
    del doc["plan-of-action-and-milestones"]["metadata"]        # metadata is required
    ok, errs = emit.validate(doc, "poam")
    assert ok is False and errs


def test_ar_bad_status_enum_rejected(records):
    doc = emit.emit_oscal_ar(records, now=FIXED_NOW)
    doc["assessment-results"]["results"][0]["findings"][0]["target"]["status"]["state"] = "MAYBE"
    ok, errs = emit.validate(doc, "ar")
    assert ok is False and errs


def test_cdx_bad_version_type_rejected(records):
    doc = emit.emit_cyclonedx(records, now=FIXED_NOW)
    doc["version"] = "not-an-integer"                           # `version` must be an integer
    ok, errs = emit.validate(doc, "cyclonedx")
    assert ok is False and errs


def test_cdx_bad_bomformat_enum_rejected(records):
    doc = emit.emit_cyclonedx(records, now=FIXED_NOW)
    doc["bomFormat"] = "NotCycloneDX"                           # bomFormat is enum-constrained
    ok, errs = emit.validate(doc, "cyclonedx")
    assert ok is False and errs


def test_cdx_missing_bomformat_rejected(records):
    doc = emit.emit_cyclonedx(records, now=FIXED_NOW)
    del doc["bomFormat"]
    ok, errs = emit.validate(doc, "cyclonedx")
    assert ok is False and errs


# ---------------- provenance-embedding invariant ----------------
def test_ar_embeds_every_manifest(records):
    doc = emit.emit_oscal_ar(records, now=FIXED_NOW)
    blob = json.dumps(doc)
    for r in records:
        assert r["manifest"]["manifest_hash"] in blob


def test_cdx_embeds_every_manifest(records):
    doc = emit.emit_cyclonedx(records, now=FIXED_NOW)
    blob = json.dumps(doc)
    for r in records:
        assert r["manifest"]["manifest_hash"] in blob


def test_poam_embeds_only_open_controls(records):
    doc = emit.emit_oscal_poam(records, now=FIXED_NOW)
    blob = json.dumps(doc)
    for r in records:
        present = r["manifest"]["manifest_hash"] in blob
        assert present == (r["status"] != "met")               # met controls excluded from POA&M


# ---------------- uuid determinism + RFC-4122 v5 ----------------
def test_emit_is_deterministic(records):
    a = json.dumps(emit.emit(records, "both", now=FIXED_NOW, do_validate=False))
    b = json.dumps(emit.emit(records, "both", now=FIXED_NOW, do_validate=False))
    assert a == b


def test_poam_uuid_is_v5(records):
    doc = emit.emit_oscal_poam(records, now=FIXED_NOW)
    assert UUID_V5.match(doc["plan-of-action-and-milestones"]["uuid"])
    for it in doc["plan-of-action-and-milestones"]["poam-items"]:
        assert UUID_V5.match(it["uuid"])


def test_different_records_different_uuid():
    a = emit.emit_oscal_poam([record("3.1.1", "C", "not-met", ["x"])], now=FIXED_NOW)
    b = emit.emit_oscal_poam([record("3.1.2", "C", "not-met", ["x"])], now=FIXED_NOW)
    assert a["plan-of-action-and-milestones"]["uuid"] != b["plan-of-action-and-milestones"]["uuid"]


# ---------------- token-safe finding target ids ----------------
def test_finding_target_id_is_token_safe(records):
    doc = emit.emit_oscal_ar(records, now=FIXED_NOW)
    for f in doc["assessment-results"]["results"][0]["findings"]:
        tid = f["target"]["target-id"]
        assert re.match(r"^[A-Za-z_]", tid), tid                # OSCAL TokenDatatype must not start with a digit


# ---------------- cyclonedx conformance mapping ----------------
def test_cdx_conformance_scores(records):
    doc = emit.emit_cyclonedx(records, now=FIXED_NOW)
    by_req = {m["requirement"]: m["conformance"]["score"] for m in doc["declarations"]["attestations"][0]["map"]}
    assert by_req["req-3.1.1"] == 1.0                            # met
    assert by_req["req-3.1.5"] == 0.0                            # not-met
    assert by_req["req-3.1.12"] == 0.0                           # partially-met -> non-conformant
