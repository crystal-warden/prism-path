#!/usr/bin/env python3
"""Sink dual-emitter (#65) — serialize compliance assessment results into standards-native reports.

Two audiences, one attested source of truth:
  * OSCAL  (NIST-native)  -> Assessment Results (AR) + Plan of Action & Milestones (POA&M).
                            What a CMMC C3PAO / FedRAMP assessor ingests.
  * CycloneDX 1.6 Attestations (OWASP) -> the signed/DevSecOps supply-chain audience.

Both carry the SAME PrismPath Flow-Ledger provenance (the manifest_hash, policy_hash, gate_id,
knowledge-base hash, and per-request ingestion hashes) so the report is bound to the exact attested
decision that produced it. This module is pure serialization — no LLM, no gemma, no domain adjudication.
Validation against the cached NIST OSCAL + CycloneDX JSON schemas is the CI gate (see validate()).

A `result` record (what the adapter's Sink hands us) is:
  {control_id, title, boundary, status in {met,partially-met,not-met},
   gap_summary, unmet_objective_ids:[...], manifest:{provenance_manifest() dict}}
"""
import os, json, uuid, hashlib, argparse

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA_DIR = os.path.join(HERE, "schemas")
OSCAL_VERSION = "1.1.3"
PP_NS = "https://crystalwarden.io/ns/prismpath"                 # our OSCAL prop namespace
# fixed namespace so every uuid is a deterministic RFC-4122 v5 (schema requires v4/v5)
_NS = uuid.uuid5(uuid.NAMESPACE_URL, "prismpath.compliance.emit")

def _uuid(seed):
    return str(uuid.uuid5(_NS, seed))

def _tok(cid):
    """Token-safe id (OSCAL TokenDatatype must start with a letter/underscore; control ids start with a digit)."""
    return "control-" + str(cid)

def _now(now=None):
    if now:
        return now
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

def _is_met(status):
    return status == "met"

# ---------- provenance -> OSCAL props / CycloneDX properties ----------
def _prov_fields(manifest):
    m = manifest or {}
    return [
        ("prismpath-flow-ledger-manifest", m.get("manifest_hash", "")),
        ("prismpath-determination-root", m.get("root", "")),
        ("prismpath-policy-hash", m.get("policy_hash", "")),
        ("prismpath-gate-id", m.get("gate_id", "")),
        ("prismpath-knowledge-base-hash", m.get("knowledge_base_hash", "")),
        ("prismpath-ingestion-hashes", ",".join(m.get("ingestion_hashes", []) or [])),
        ("prismpath-attested-at", m.get("created", "")),
    ]

def _oscal_props(manifest):
    return [{"name": n, "ns": PP_NS, "value": v} for n, v in _prov_fields(manifest) if v]

def _cdx_props(manifest):
    return [{"name": "prismpath:" + n.replace("prismpath-", ""), "value": v}
            for n, v in _prov_fields(manifest) if v]

# ============================ OSCAL POA&M ============================
def emit_oscal_poam(results, now=None, title="NIST SP 800-171 Rev 2 Plan of Action & Milestones"):
    now = _now(now)
    bundle_seed = "poam:" + ":".join(sorted(r["control_id"] for r in results))
    observations, poam_items = [], []
    for r in results:
        if _is_met(r["status"]):
            continue                                            # POA&M tracks only open weaknesses
        cid = r["control_id"]
        obs_uuid = _uuid("obs:" + cid + ":" + r.get("manifest", {}).get("manifest_hash", ""))
        unmet = r.get("unmet_objective_ids", [])
        observations.append({
            "uuid": obs_uuid,
            "description": "Assessment of %s (%s) on boundary '%s': %s. %s" % (
                cid, r["title"], r.get("boundary", "n/a"), r["status"], r.get("gap_summary", "")),
            "methods": ["EXAMINE"],
            "props": _oscal_props(r.get("manifest")),
            "collected": now,
        })
        poam_items.append({
            "uuid": _uuid("poam-item:" + cid + ":" + r.get("manifest", {}).get("manifest_hash", "")),
            "title": "%s %s" % (cid, r["title"]),
            "description": "%s — unmet objectives: %s" % (
                r.get("gap_summary", "control not met"),
                ", ".join(unmet) if unmet else "(control-level)"),
            "props": _oscal_props(r.get("manifest")) + [
                {"name": "status", "ns": PP_NS, "value": r["status"]},
                {"name": "unmet-objective-ids", "ns": PP_NS, "value": ", ".join(unmet)}],
            "related-observations": [{"observation-uuid": obs_uuid}],
        })
    if not poam_items:                                          # schema requires >=1 poam-item
        poam_items.append({
            "uuid": _uuid("poam-item:none:" + bundle_seed),
            "title": "No open items",
            "description": "All assessed controls were determined met; no plan-of-action items are open.",
        })
    poam = {
        "uuid": _uuid(bundle_seed),
        "metadata": {"title": title, "last-modified": now, "version": "0.1.0",
                     "oscal-version": OSCAL_VERSION,
                     "props": [{"name": "generator", "ns": PP_NS, "value": "prismpath-compliance-adapter"}]},
        "poam-items": poam_items,
    }
    if observations:                                            # optional array; OSCAL rejects it empty
        poam["observations"] = observations
    return {"plan-of-action-and-milestones": poam}

# ==================== OSCAL Assessment Results (AR) ====================
def emit_oscal_ar(results, now=None, title="NIST SP 800-171 Rev 2 Assessment Results",
                  ap_href="prismpath://assessment-plan/nist-800171-access-control", rollup=None):
    now = _now(now)
    bundle_seed = "ar:" + ":".join(sorted(r["control_id"] for r in results))
    observations, findings = [], []
    for r in results:
        cid = r["control_id"]
        mh = r.get("manifest", {}).get("manifest_hash", "")
        obs_uuid = _uuid("ar-obs:" + cid + ":" + mh)
        observations.append({
            "uuid": obs_uuid,
            "description": "Examined evidence for %s (%s) on boundary '%s'." % (cid, r["title"], r.get("boundary", "n/a")),
            "methods": ["EXAMINE"],
            "props": _oscal_props(r.get("manifest")),
            "collected": now,
        })
        findings.append({
            "uuid": _uuid("finding:" + cid + ":" + mh),
            "title": "%s %s" % (cid, r["title"]),
            "description": r.get("gap_summary", "") or ("Control %s assessed %s." % (cid, r["status"])),
            "props": _oscal_props(r.get("manifest")) + [
                {"name": "status", "ns": PP_NS, "value": r["status"]}],
            "target": {"type": "objective-id", "target-id": _tok(cid),
                       "title": r["title"],
                       "status": {"state": "satisfied" if _is_met(r["status"]) else "not-satisfied"}},
            "related-observations": [{"observation-uuid": obs_uuid}],
        })
    result = {
        "uuid": _uuid("result:" + bundle_seed),
        "title": title,
        "description": "PrismPath decomposed, escalation-default assessment of NIST 800-171 access-control objectives.",
        "start": now,
        "reviewed-controls": {"control-selections": [{"include-all": {}}]},
    }
    if observations:                                            # optional arrays; OSCAL rejects them empty
        result["observations"] = observations
    if findings:
        result["findings"] = findings
    ar = {"assessment-results": {
        "uuid": _uuid(bundle_seed),
        "metadata": {"title": title, "last-modified": now, "version": "0.1.0",
                     "oscal-version": OSCAL_VERSION,
                     "props": [{"name": "generator", "ns": PP_NS, "value": "prismpath-compliance-adapter"}]},
        "import-ap": {"href": ap_href},
        "results": [result],
    }}
    if rollup:                                                  # system-level SPRS + scope + rollup attestation
        sprs, scope, manifest = rollup.get("sprs", {}), rollup.get("scope", {}), rollup.get("attestation", {})
        props = [
            {"name": "assessment-boundary", "ns": PP_NS, "value": str(scope.get("boundary", ""))},
            {"name": "sampling-method", "ns": PP_NS, "value": str(scope.get("sampling_method", ""))},
            {"name": "system-rollup-manifest", "ns": PP_NS, "value": manifest.get("manifest_hash", "")},
        ]
        if sprs.get("applicable", True) and "deducted_points" in sprs:
            props = [
                {"name": "sprs-partial-deducted-points", "ns": PP_NS, "value": str(sprs.get("deducted_points", ""))},
                {"name": "sprs-ceiling-if-unassessed-met", "ns": PP_NS, "value": str(sprs.get("ceiling_if_unassessed_all_met", ""))},
                {"name": "sprs-n-assessed", "ns": PP_NS, "value": str(sprs.get("n_assessed", ""))},
                {"name": "sprs-caveat", "ns": PP_NS, "value": sprs.get("caveat", "")},
            ] + props
        else:                                                   # standard not SPRS-scored (e.g. Rev 3)
            props.append({"name": "sprs-status", "ns": PP_NS, "value": sprs.get("reason", "not SPRS-scored")})
        result["props"] = props
        ar["assessment-results"]["back-matter"] = {"resources": [{
            "uuid": _uuid("rollup-resource:" + manifest.get("manifest_hash", bundle_seed)),
            "title": "PrismPath system-level rollup attestation",
            "description": ("System rollup bound to the per-control Flow-Ledger attestations. %s" % sprs.get("caveat", sprs.get("reason", ""))),
            "props": [
                {"name": "manifest-hash", "ns": PP_NS, "value": manifest.get("manifest_hash", "")},
                {"name": "root", "ns": PP_NS, "value": manifest.get("root", "")},
                {"name": "bound-control-manifests", "ns": PP_NS, "value": ",".join(manifest.get("ingestion_hashes", []) or [])},
            ],
        }]}
    return ar

# ==================== CycloneDX 1.6 Attestations ====================
def emit_cyclonedx(results, now=None):
    now = _now(now)
    bundle_seed = "cdx:" + ":".join(sorted(r["control_id"] for r in results))
    requirements, amap = [], []
    for r in results:
        cid = r["control_id"]
        rref = "req-" + cid
        # provenance rides on the requirement (the attestation map item has no `properties` slot in 1.6)
        requirements.append({"bom-ref": rref, "identifier": cid, "title": r["title"],
                             "text": r.get("gap_summary", ""),
                             "properties": _cdx_props(r.get("manifest"))})
        met = _is_met(r["status"])
        amap.append({
            "requirement": rref,
            "conformance": {"score": 1.0 if met else 0.0,
                            "rationale": (r.get("gap_summary") or ("Assessed %s." % r["status"]))[:1000]},
            "confidence": {"score": 1.0 if met else 0.5,
                           "rationale": "Escalation-default adjudication; unmet objectives: %s" %
                                        (", ".join(r.get("unmet_objective_ids", [])) or "none")},
        })
    doc = {
        "bomFormat": "CycloneDX", "specVersion": "1.6",
        "serialNumber": "urn:uuid:" + _uuid(bundle_seed), "version": 1,
        "metadata": {"timestamp": now,
                     "tools": {"components": [{"type": "application", "name": "PrismPath compliance adapter",
                                               "version": "0.1.0"}]},
                     "properties": _cdx_props(results[0].get("manifest")) if results else []},
        "definitions": {"standards": [{
            "bom-ref": "std-nist-800-171-r2", "name": "NIST SP 800-171 Rev 2",
            "description": "Protecting Controlled Unclassified Information in Nonfederal Systems and Organizations",
            "owner": "NIST", "requirements": requirements}]},
        "declarations": {
            "assessors": [{"bom-ref": "assessor-prismpath", "thirdParty": False,
                           "organization": {"name": "PrismPath attestable decision-automation engine"}}],
            "attestations": [{
                "summary": "NIST SP 800-171 access-control assessment, each determination bound to a Flow-Ledger attestation.",
                "assessor": "assessor-prismpath",
                "map": amap}],
        },
    }
    return doc

# ============================ validation ============================
import re as _re
def _py_pattern(p):
    """OSCAL/CycloneDX patterns use \\p{...} Unicode property escapes that Python `re` rejects.
    Translate the common ones; fall back to a permissive `.` for any exotic remainder (we keep the
    structural/required/enum checks — only the string char-class check is approximated)."""
    p = p.replace("\\p{L}", "[^\\W\\d_]").replace("\\p{Nd}", "\\d").replace("\\p{N}", "\\d")
    return _re.sub(r"\\p\{[^}]+\}", ".", p)

def _sanitize(node):
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "pattern" and isinstance(v, str) and "\\p{" in v:
                node[k] = _py_pattern(v)
            else:
                _sanitize(v)
    elif isinstance(node, list):
        for x in node:
            _sanitize(x)
    return node

def _load_schema(name):
    return _sanitize(json.load(open(os.path.join(SCHEMA_DIR, name))))

def validate(doc, kind):
    """Validate an emitted doc against its cached NIST/OWASP schema. Returns (ok, [errors])."""
    import jsonschema
    if kind == "poam":
        schema = _load_schema("oscal_poam_schema.json")
    elif kind == "ar":
        schema = _load_schema("oscal_assessment-results_schema.json")
    elif kind == "cyclonedx":
        schema = _load_schema("bom-1.6.schema.json")
    else:
        raise ValueError(kind)
    if kind == "cyclonedx":
        # bom-1.6 $refs sibling files (jsf, spdx) by relative name -> resolve from SCHEMA_DIR
        base = "file://" + SCHEMA_DIR + "/"
        store = {}
        for fn in ("bom-1.6.schema.json", "jsf-0.82.schema.json", "spdx.schema.json"):
            s = _load_schema(fn); store[base + fn] = s
            if "$id" in s:
                store[s["$id"]] = s
        resolver = jsonschema.RefResolver(base_uri=base + "bom-1.6.schema.json", referrer=schema, store=store)
        validator = jsonschema.Draft7Validator(schema, resolver=resolver)
    else:
        validator = jsonschema.Draft202012Validator(schema) \
            if str(schema.get("$schema", "")).find("2020-12") >= 0 else jsonschema.Draft7Validator(schema)
    errs = []
    for e in sorted(validator.iter_errors(doc), key=lambda x: list(x.path)):
        errs.append("/".join(str(p) for p in e.path) + ": " + e.message)
    return (len(errs) == 0, errs)

# ============================ dispatcher ============================
def emit(results, fmt="both", out_dir=None, now=None, do_validate=True, rollup=None):
    """fmt in {oscal, cyclonedx, both}. Writes files to out_dir if given. Returns {name:{doc,path,valid,errors}}.
    rollup (optional) = {"sprs":..., "scope":..., "attestation":manifest} to embed a system-level rollup in the AR."""
    out = {}
    def _make(kind, doc, fname):
        rec = {"doc": doc, "path": None, "valid": None, "errors": []}
        if do_validate:
            rec["valid"], rec["errors"] = validate(doc, kind)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
            rec["path"] = os.path.join(out_dir, fname)
            json.dump(doc, open(rec["path"], "w"), indent=1)
        return rec
    if fmt in ("oscal", "both"):
        out["oscal_poam"] = _make("poam", emit_oscal_poam(results, now), "poam.oscal.json")
        out["oscal_ar"] = _make("ar", emit_oscal_ar(results, now, rollup=rollup), "assessment-results.oscal.json")
    if fmt in ("cyclonedx", "both"):
        out["cyclonedx"] = _make("cyclonedx", emit_cyclonedx(results, now), "bom.cdx.json")
    return out

# ============================ self-test ============================
def _sample_manifest(cid, root="deadbeef"):
    return {"manifest_hash": hashlib.sha256((cid + root).encode()).hexdigest(),
            "root": hashlib.sha256(root.encode()).hexdigest(), "policy_hash": "sha256:nist_ac_flow_v0",
            "gate_id": "nist_800171_access_control@v0", "knowledge_base_hash": "sha256:cat0011223344",
            "ingestion_hashes": ["sha256:bundle" + cid.replace(".", "")], "created": "2026-07-22T00:00:00+00:00"}

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    results = [
        {"control_id": "3.1.1", "title": "Access Control Policy", "boundary": "CUI enclave",
         "status": "met", "gap_summary": "All objectives demonstrated.", "unmet_objective_ids": [],
         "manifest": _sample_manifest("3.1.1")},
        {"control_id": "3.1.5", "title": "Least Privilege", "boundary": "CUI enclave",
         "status": "not-met", "gap_summary": "Least-privilege not enforced on the boundary; no PAM evidence.",
         "unmet_objective_ids": ["3.1.5[a]", "3.1.5[b]"], "manifest": _sample_manifest("3.1.5")},
        {"control_id": "3.1.12", "title": "Monitor Remote Access", "boundary": "CUI enclave",
         "status": "partially-met", "gap_summary": "Remote sessions logged but not monitored in real time.",
         "unmet_objective_ids": ["3.1.12[b]"], "manifest": _sample_manifest("3.1.12")},
    ]
    res = emit(results, fmt="both", out_dir=a.out, now="2026-07-22T12:00:00+00:00")
    summary = {}
    for k, v in res.items():
        summary[k] = {"valid": v["valid"], "n_errors": len(v["errors"]),
                      "errors": v["errors"][:6], "path": v["path"]}
    print(json.dumps(summary, indent=1))
