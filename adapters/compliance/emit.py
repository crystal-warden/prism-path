#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
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

# ---------- the standard a report names ----------
# Each report names the standard its records were assessed against. The default is NIST SP 800-171
# Rev 2, the access control assessment these emitters were written for, so a caller that names no
# standard gets the same documents as before.
DEFAULT_STANDARD = "nist_800171_r2"
STANDARD_LABELS = {
    "nist_800171_r2": {
        "bom_ref": "std-nist-800-171-r2", "name": "NIST SP 800-171 Rev 2", "owner": "NIST",
        "description": "Protecting Controlled Unclassified Information in Nonfederal Systems and Organizations",
        "summary": "NIST SP 800-171 access-control assessment, each determination bound to a Flow-Ledger attestation.",
        "ar_title": "NIST SP 800-171 Rev 2 Assessment Results",
        "ar_description": "PrismPath decomposed, escalation-default assessment of NIST 800-171 access-control objectives.",
        "poam_title": "NIST SP 800-171 Rev 2 Plan of Action & Milestones",
        "ap_href": "prismpath://assessment-plan/nist-800171-access-control"},
    "nist_ssdf": {
        "bom_ref": "std-nist-sp-800-218-v1.1", "name": "NIST SP 800-218 SSDF Version 1.1", "owner": "NIST",
        "description": "Secure Software Development Framework (SSDF) Version 1.1: Recommendations for Mitigating the Risk of Software Vulnerabilities",
        "summary": "SSDF assessment of the evidence a signed policy delivery produces, each determination bound to a Flow-Ledger attestation.",
        "ar_title": "NIST SP 800-218 SSDF Assessment Results",
        "ar_description": "PrismPath assessment of SSDF practices against delivery evidence it checks itself; practices the evidence does not reach are listed as not assessed.",
        "poam_title": "NIST SP 800-218 SSDF Plan of Action & Milestones",
        "ap_href": "prismpath://assessment-plan/nist-ssdf-policy-delivery"},
    "eu_cra_annex_i": {
        "bom_ref": "std-eu-2024-2847-annex-i", "name": "Regulation (EU) 2024/2847 (Cyber Resilience Act) Annex I",
        "owner": "European Union",
        "description": "Essential cybersecurity requirements for products with digital elements",
        "summary": "Cyber Resilience Act Annex I assessment of the evidence a signed policy delivery produces, each determination bound to a Flow-Ledger attestation.",
        "ar_title": "Cyber Resilience Act Annex I Assessment Results",
        "ar_description": "PrismPath assessment of Annex I requirements against delivery evidence it checks itself; requirements the evidence does not reach are listed as not assessed.",
        "poam_title": "Cyber Resilience Act Annex I Plan of Action & Milestones",
        "ap_href": "prismpath://assessment-plan/eu-cra-annex-i-policy-delivery"},
}

def _label(standard):
    if standard not in STANDARD_LABELS:
        raise KeyError("no report labels for standard %s; choose from %s" % (standard, sorted(STANDARD_LABELS)))
    return STANDARD_LABELS[standard]

def _not_assessed_remarks(not_assessed):
    return "Not assessed, because the evidence read does not reach them:\n" + "\n".join(
        "- %s %s: %s" % (item["control_id"], item["title"], item["reason"]) for item in not_assessed)

# ---------- provenance -> OSCAL props / CycloneDX properties ----------
def _prov_fields(manifest):
    manifest_fields = manifest or {}
    return [
        ("prismpath-flow-ledger-manifest", manifest_fields.get("manifest_hash", "")),
        ("prismpath-determination-root", manifest_fields.get("root", "")),
        ("prismpath-policy-hash", manifest_fields.get("policy_hash", "")),
        ("prismpath-gate-id", manifest_fields.get("gate_id", "")),
        ("prismpath-knowledge-base-hash", manifest_fields.get("knowledge_base_hash", "")),
        ("prismpath-ingestion-hashes", ",".join(manifest_fields.get("ingestion_hashes", []) or [])),
        ("prismpath-attested-at", manifest_fields.get("created", "")),
    ]

def _oscal_props(manifest):
    return [{"name": field_name, "ns": PP_NS, "value": field_value} for field_name, field_value in _prov_fields(manifest) if field_value]

def _cdx_props(manifest):
    return [{"name": "prismpath:" + field_name.replace("prismpath-", ""), "value": field_value}
            for field_name, field_value in _prov_fields(manifest) if field_value]

# ============================ OSCAL POA&M ============================
def emit_oscal_poam(results, now=None, title=None, standard=DEFAULT_STANDARD):
    now = _now(now)
    title = title or _label(standard)["poam_title"]
    bundle_seed = "poam:" + ":".join(sorted(record["control_id"] for record in results))
    observations, poam_items = [], []
    for record in results:
        if _is_met(record["status"]):
            continue                                            # POA&M tracks only open weaknesses
        cid = record["control_id"]
        obs_uuid = _uuid("obs:" + cid + ":" + record.get("manifest", {}).get("manifest_hash", ""))
        unmet = record.get("unmet_objective_ids", [])
        observations.append({
            "uuid": obs_uuid,
            "description": "Assessment of %s (%s) on boundary '%s': %s. %s" % (
                cid, record["title"], record.get("boundary", "n/a"), record["status"], record.get("gap_summary", "")),
            "methods": ["EXAMINE"],
            "props": _oscal_props(record.get("manifest")),
            "collected": now,
        })
        poam_items.append({
            "uuid": _uuid("poam-item:" + cid + ":" + record.get("manifest", {}).get("manifest_hash", "")),
            "title": "%s %s" % (cid, record["title"]),
            "description": "%s — unmet objectives: %s" % (
                record.get("gap_summary", "control not met"),
                ", ".join(unmet) if unmet else "(control-level)"),
            "props": _oscal_props(record.get("manifest")) + [
                {"name": "status", "ns": PP_NS, "value": record["status"]},
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
def emit_oscal_ar(results, now=None, title=None, ap_href=None, rollup=None, standard=DEFAULT_STANDARD,
                  not_assessed=None):
    """not_assessed (optional) = [{control_id, title, reason}] for a scoped assessment: the result then
    names only the assessed controls as reviewed, and lists the others in its remarks with the reason."""
    now = _now(now)
    labels = _label(standard)
    title = title or labels["ar_title"]
    ap_href = ap_href or labels["ap_href"]
    bundle_seed = "ar:" + ":".join(sorted(record["control_id"] for record in results))
    observations, findings = [], []
    for record in results:
        cid = record["control_id"]
        mh = record.get("manifest", {}).get("manifest_hash", "")
        obs_uuid = _uuid("ar-obs:" + cid + ":" + mh)
        observations.append({
            "uuid": obs_uuid,
            "description": "Examined evidence for %s (%s) on boundary '%s'." % (cid, record["title"], record.get("boundary", "n/a")),
            "methods": ["EXAMINE"],
            "props": _oscal_props(record.get("manifest")),
            "collected": now,
        })
        findings.append({
            "uuid": _uuid("finding:" + cid + ":" + mh),
            "title": "%s %s" % (cid, record["title"]),
            "description": record.get("gap_summary", "") or ("Control %s assessed %s." % (cid, record["status"])),
            "props": _oscal_props(record.get("manifest")) + [
                {"name": "status", "ns": PP_NS, "value": record["status"]}],
            "target": {"type": "objective-id", "target-id": _tok(cid),
                       "title": record["title"],
                       "status": {"state": "satisfied" if _is_met(record["status"]) else "not-satisfied"}},
            "related-observations": [{"observation-uuid": obs_uuid}],
        })
    result = {
        "uuid": _uuid("result:" + bundle_seed),
        "title": title,
        "description": labels["ar_description"],
        "start": now,
        "reviewed-controls": {"control-selections": [{"include-all": {}}]},
    }
    if not_assessed is not None and results:                    # scoped: name what was reviewed, list the rest
        result["reviewed-controls"] = {"control-selections": [{"include-controls": [
            {"control-id": _tok(record["control_id"])} for record in results]}]}
    if not_assessed:
        result["remarks"] = _not_assessed_remarks(not_assessed)
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
def emit_cyclonedx(results, now=None, standard=DEFAULT_STANDARD, not_assessed=None):
    """not_assessed (optional) = [{control_id, title, reason}]: those requirements are defined in the
    standard with the reason as their text and are left out of the attestation map, so nothing claims
    a conformance score for them."""
    now = _now(now)
    labels = _label(standard)
    bundle_seed = "cdx:" + ":".join(sorted(record["control_id"] for record in results))
    requirements, amap = [], []
    for record in results:
        cid = record["control_id"]
        rref = "req-" + cid
        # provenance rides on the requirement (the attestation map item has no `properties` slot in 1.6)
        requirements.append({"bom-ref": rref, "identifier": cid, "title": record["title"],
                             "text": record.get("gap_summary", ""),
                             "properties": _cdx_props(record.get("manifest"))})
        met = _is_met(record["status"])
        amap.append({
            "requirement": rref,
            "conformance": {"score": 1.0 if met else 0.0,
                            "rationale": (record.get("gap_summary") or ("Assessed %s." % record["status"]))[:1000]},
            "confidence": {"score": 1.0 if met else 0.5,
                           "rationale": "Escalation-default adjudication; unmet objectives: %s" %
                                        (", ".join(record.get("unmet_objective_ids", [])) or "none")},
        })
    for item in not_assessed or []:
        requirements.append({"bom-ref": "req-" + item["control_id"], "identifier": item["control_id"],
                             "title": item["title"], "text": "Not assessed: " + item["reason"]})
    doc = {
        "bomFormat": "CycloneDX", "specVersion": "1.6",
        "serialNumber": "urn:uuid:" + _uuid(bundle_seed), "version": 1,
        "metadata": {"timestamp": now,
                     "tools": {"components": [{"type": "application", "name": "PrismPath compliance adapter",
                                               "version": "0.1.0"}]},
                     "properties": _cdx_props(results[0].get("manifest")) if results else []},
        "definitions": {"standards": [{
            "bom-ref": labels["bom_ref"], "name": labels["name"], "description": labels["description"],
            "owner": labels["owner"], "requirements": requirements}]},
        "declarations": {
            "assessors": [{"bom-ref": "assessor-prismpath", "thirdParty": False,
                           "organization": {"name": "PrismPath attestable decision-automation engine"}}],
            "attestations": [{
                "summary": labels["summary"],
                "assessor": "assessor-prismpath",
                "map": amap}],
        },
    }
    return doc

# ============== CycloneDX 1.6 SBOM for a signed policy pack ==============
# A delivery tool's SBOM does not describe a policy: Zarf catalogs software packages with Syft, and a
# package carrying a signed .ppt gets an SBOM with no artifacts and no files (Zarf 0.87.0, October 2026).
# The policy's provenance is the pack's signed manifest, so this states that manifest as a bill of
# materials: the image as a `data` component with its SHA-256, the pack version, the signing key, the
# envelope, the WCET bound, the table counts and field dictionary, and the authored flow's hash as a part
# when the pack recorded one. It is written only for a pack that verifies, and it is deterministic: the
# serial comes from the image hash and version, the timestamp is the manifest's `created`.

def _pack_properties(manifest):
    entries = [("prismpath:pack_format", manifest["format"]), ("prismpath:key_id", manifest["key_id"]),
               ("prismpath:envelope_id", manifest["envelope_id"]), ("prismpath:wcet_cycles", manifest["wcet_cycles"]),
               ("prismpath:signature", "Ed25519 over the canonical manifest, detached in <image>.manifest.sig")]
    entries += [("prismpath:count:" + name, manifest["counts"][name]) for name in sorted(manifest.get("counts", {}))]
    entries += [("prismpath:field:" + name, manifest["fields"][name]) for name in sorted(manifest.get("fields", {}))]
    for key in ("flow_sha256", "overlay_of"):
        if manifest.get(key):
            entries.append(("prismpath:" + key, manifest[key]))
    if manifest.get("packing"):
        entries += [("prismpath:packing_profile", manifest["packing"]["profile"]),
                    ("prismpath:packing_sidecar_sha256", manifest["packing"]["sidecar_sha256"])]
    return [{"name": name, "value": str(value)} for name, value in entries]

def emit_pack_sbom(manifest, name, supplier=None):
    """The CycloneDX SBOM for a pack whose manifest has already verified; use pack_sbom, which verifies."""
    component = {"type": "data", "bom-ref": "prismpath-policy:" + manifest["image_sha256"], "name": name,
                 "version": str(manifest["version"]),
                 "description": "A compiled PrismPath policy table (PPT image), signed in a pack.",
                 "hashes": [{"alg": "SHA-256", "content": manifest["image_sha256"]}],
                 "properties": _pack_properties(manifest)}
    if supplier:
        component["supplier"] = {"name": supplier}
    if manifest.get("flow_sha256"):
        component["components"] = [{
            "type": "file", "bom-ref": "prismpath-flow:" + manifest["flow_sha256"], "name": name + " authored flow",
            "description": "The flow source the image was compiled from, bound by hash in the signed manifest.",
            "hashes": [{"alg": "SHA-256", "content": manifest["flow_sha256"]}]}]
    return {"bomFormat": "CycloneDX", "specVersion": "1.6",
            "serialNumber": "urn:uuid:" + _uuid("pack-sbom:%s:%s" % (manifest["image_sha256"], manifest["version"])),
            "version": 1,
            "metadata": {"timestamp": manifest["created"],
                         "tools": {"components": [{"type": "application", "name": "PrismPath compliance adapter",
                                                   "version": "0.1.0"}]},
                         "component": component}}

def pack_sbom(ppt_path, pubkey_paths, revoked=frozenset(), name=None, supplier=None):
    """Verify the pack, then describe it, then validate the description. Returns {"ok": True, "sbom": doc}
    or {"ok": False, "reasons": [...]}: the verification's refusal, or the schema's. A refused pack
    never gets a bill of materials that would describe bytes nobody signed."""
    from prismpath.hotswap import policy_pack
    ok, reasons, manifest = policy_pack.verify_pack(ppt_path, pubkey_paths, revoked)
    if not ok or manifest is None:
        return {"ok": False, "reasons": reasons}
    doc = emit_pack_sbom(manifest, name or os.path.splitext(os.path.basename(ppt_path))[0], supplier)
    valid, errors = validate(doc, "cyclonedx")
    if not valid:
        return {"ok": False, "reasons": ["sbom:schema:" + error for error in errors]}
    return {"ok": True, "sbom": doc}

# ==================== CycloneDX 1.6 VEX for reachability verdicts ====================
# A reachability analysis states, per advisory, whether the product runs the vulnerable code. The
# verdicts arrive in the OpenVEX vocabulary the analysis is written in and leave in CycloneDX's:
# affected is `exploitable`, under investigation is `in_triage`, and the two not affected
# justifications become `code_not_reachable` and `code_not_present`. A not affected verdict without
# a justification is refused, because a bare "not affected" is the claim VEX exists to qualify.
VEX_STATES = {"affected": "exploitable", "not_affected": "not_affected", "under_investigation": "in_triage",
              "fixed": "resolved"}
VEX_JUSTIFICATIONS = {"vulnerable_code_not_in_execute_path": "code_not_reachable",
                      "component_not_present": "code_not_present"}

def emit_vex(verdicts, component, now=None):
    """verdicts = [{id, state, justification?, detail, source_name?, source_url?, properties?: {name: value}}],
    component = {name, version, purl?}: the product the verdicts are about."""
    now = _now(now)
    product_ref = "product:" + component["name"]
    product = {"type": "application", "bom-ref": product_ref, "name": component["name"],
               "version": str(component.get("version", "unversioned"))}
    if component.get("purl"):
        product["purl"] = component["purl"]
    vulnerabilities = []
    for verdict in verdicts:
        if verdict["state"] not in VEX_STATES:
            raise ValueError("unknown VEX state %s" % verdict["state"])
        analysis = {"state": VEX_STATES[verdict["state"]], "detail": verdict.get("detail", "")[:10000]}
        if verdict["state"] == "not_affected":
            if verdict.get("justification") not in VEX_JUSTIFICATIONS:
                raise ValueError("not_affected for %s needs a justification from %s" % (verdict["id"], sorted(VEX_JUSTIFICATIONS)))
            analysis["justification"] = VEX_JUSTIFICATIONS[verdict["justification"]]
        entry = {"bom-ref": "vex:" + verdict["id"], "id": verdict["id"], "analysis": analysis,
                 "affects": [{"ref": product_ref}]}
        if verdict.get("source_name"):
            entry["source"] = {"name": verdict["source_name"]}
            if verdict.get("source_url"):
                entry["source"]["url"] = verdict["source_url"]
        if verdict.get("properties"):
            entry["properties"] = [{"name": "prismpath:" + name, "value": str(value)}
                                   for name, value in sorted(verdict["properties"].items())]
        vulnerabilities.append(entry)
    seed = "vex:%s:%s:" % (component["name"], component.get("version", "")) + ":".join(
        sorted("%s=%s" % (verdict["id"], verdict["state"]) for verdict in verdicts))
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:" + _uuid(seed), "version": 1,
            "metadata": {"timestamp": now,
                         "tools": {"components": [{"type": "application", "name": "PrismPath compliance adapter",
                                                   "version": "0.1.0"}]},
                         "component": product},
            "vulnerabilities": vulnerabilities}

# ============================ validation ============================
import re as _re
def _py_pattern(pattern):
    """OSCAL/CycloneDX patterns use \\p{...} Unicode property escapes that Python `re` rejects.
    Translate the common ones; fall back to a permissive `.` for any exotic remainder (we keep the
    structural/required/enum checks — only the string char-class check is approximated)."""
    pattern = pattern.replace("\\p{L}", "[^\\W\\d_]").replace("\\p{Nd}", "\\d").replace("\\p{N}", "\\d")
    return _re.sub(r"\\p\{[^}]+\}", ".", pattern)

def _sanitize(node):
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "pattern" and isinstance(value, str) and "\\p{" in value:
                node[key] = _py_pattern(value)
            else:
                _sanitize(value)
    elif isinstance(node, list):
        for item in node:
            _sanitize(item)
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
            sibling_schema = _load_schema(fn); store[base + fn] = sibling_schema
            if "$id" in sibling_schema:
                store[sibling_schema["$id"]] = sibling_schema
        resolver = jsonschema.RefResolver(base_uri=base + "bom-1.6.schema.json", referrer=schema, store=store)
        validator = jsonschema.Draft7Validator(schema, resolver=resolver)
    else:
        validator = jsonschema.Draft202012Validator(schema) \
            if str(schema.get("$schema", "")).find("2020-12") >= 0 else jsonschema.Draft7Validator(schema)
    errs = []
    for error in sorted(validator.iter_errors(doc), key=lambda error: list(error.path)):
        errs.append("/".join(str(path_part) for path_part in error.path) + ": " + error.message)
    return (len(errs) == 0, errs)

# ============================ dispatcher ============================
def emit(results, fmt="both", out_dir=None, now=None, do_validate=True, rollup=None, standard=DEFAULT_STANDARD,
         not_assessed=None):
    """fmt in {oscal, cyclonedx, both}. Writes files to out_dir if given. Returns {name:{doc,path,valid,errors}}.
    rollup (optional) = {"sprs":..., "scope":..., "attestation":manifest} to embed a system-level rollup in the AR.
    standard names the catalog the records were assessed against (a key of STANDARD_LABELS); not_assessed
    lists the requirements a scoped assessment did not reach, as emit_oscal_ar and emit_cyclonedx take it."""
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
        out["oscal_poam"] = _make("poam", emit_oscal_poam(results, now, standard=standard), "poam.oscal.json")
        out["oscal_ar"] = _make("ar", emit_oscal_ar(results, now, rollup=rollup, standard=standard,
                                                    not_assessed=not_assessed), "assessment-results.oscal.json")
    if fmt in ("cyclonedx", "both"):
        out["cyclonedx"] = _make("cyclonedx", emit_cyclonedx(results, now, standard=standard,
                                                             not_assessed=not_assessed), "bom.cdx.json")
    return out

# ============================ self-test ============================
def _sample_manifest(cid, root="deadbeef"):
    return {"manifest_hash": hashlib.sha256((cid + root).encode()).hexdigest(),
            "root": hashlib.sha256(root.encode()).hexdigest(), "policy_hash": "sha256:nist_ac_flow_v0",
            "gate_id": "nist_800171_access_control@v0", "knowledge_base_hash": "sha256:cat0011223344",
            "ingestion_hashes": ["sha256:bundle" + cid.replace(".", "")], "created": "2026-07-22T00:00:00+00:00"}

def _pack_sbom_main(args):
    from prismpath.hotswap import policy_pack
    result = pack_sbom(args.pack_sbom, args.pub, policy_pack.load_revoked(args.revoked),
                       name=args.name, supplier=args.supplier)
    if not result["ok"]:
        print(json.dumps(result, indent=1))
        return 1
    out_path = args.sbom_out or (args.pack_sbom + ".cdx.json")
    with open(out_path, "w") as handle:
        json.dump(result["sbom"], handle, indent=1, sort_keys=True)
        handle.write("\n")
    print(json.dumps({"ok": True, "sbom": out_path, "serialNumber": result["sbom"]["serialNumber"]}, indent=1))
    return 0

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--out", default=None)
    ap.add_argument("--pack-sbom", dest="pack_sbom", metavar="PPT",
                    help="write the CycloneDX SBOM of this signed pack (verified first); needs --pub")
    ap.add_argument("--pub", nargs="+", help="authority public key(s) the pack must verify against")
    ap.add_argument("--revoked", default=None, help="revocation list JSON of key ids")
    ap.add_argument("--name", default=None, help="the component name (default the image file name)")
    ap.add_argument("--supplier", default=None, help="the supplier recorded on the component")
    ap.add_argument("--sbom-out", dest="sbom_out", default=None, help="where to write it (default <ppt>.cdx.json)")
    args = ap.parse_args()
    if args.pack_sbom:
        if not args.pub:
            ap.error("--pack-sbom needs --pub")
        raise SystemExit(_pack_sbom_main(args))
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
    res = emit(results, fmt="both", out_dir=args.out, now="2026-07-22T12:00:00+00:00")
    summary = {}
    for format_name, emission in res.items():
        summary[format_name] = {"valid": emission["valid"], "n_errors": len(emission["errors"]),
                                "errors": emission["errors"][:6], "path": emission["path"]}
    print(json.dumps(summary, indent=1))
