#!/usr/bin/env python3
"""Compliance adapter (#2) — the domain code behind PrismPath's ports for NIST 800-171 assessment.

NO compliance vocabulary lives in the core engine; it lives HERE, behind the ports (ADAPTER_CONTRACT.md).
The Attestation port REUSES the core `ledger_airgap` (#53) — proving it is shared core, not re-implemented.
"""
import os, sys, json, hashlib, requests
sys.path.insert(0, "/home/cwadmin/cwprojects/prismpath")
from prismpath import ledger_airgap, deferral  # CORE attestation + deferral ports (adapter→core OK; core→adapter is the leak)

GEMMA = "http://127.0.0.1:8888/v1/chat/completions"; MODEL = "gemma4"
HERE = os.path.dirname(os.path.abspath(__file__))
# ---------- Retrieval port: runtime-selectable control catalog (the engine is catalog-agnostic) ----------
STANDARDS = {
    "nist_800171_r2": os.path.join(HERE, "catalog", "nist_800171_r2.json"),   # CMMC's current basis (Rev 2)
    "nist_800171_r3": os.path.join(HERE, "catalog", "nist_800171_r3.json"),   # NIST's current official (Rev 3)
    "nist_800171_ac": os.path.join(HERE, "catalog", "nist_800171_ac.json"),   # legacy AC-only subset
}
_ACTIVE = os.environ.get("PRISMPATH_STANDARD", "nist_800171_r2")
_CAT_CACHE = {}

def use_standard(std):
    """Select which control catalog the assessment runs against (before running the audit)."""
    global _ACTIVE
    if std not in STANDARDS:
        raise KeyError(f"unknown standard {std}; choose from {sorted(STANDARDS)}")
    _ACTIVE = std
    return _ACTIVE

def active_standard():
    return _ACTIVE

def list_standards():
    out = {}
    for s, p in STANDARDS.items():
        try:
            m = json.load(open(p)).get("_meta", {})
            out[s] = {"revision": m.get("revision"), "controls": m.get("controls"), "families": m.get("families")}
        except FileNotFoundError:
            out[s] = {"error": "catalog file missing"}
    return out

def _catalog():
    if _ACTIVE not in _CAT_CACHE:
        _CAT_CACHE[_ACTIVE] = json.load(open(STANDARDS[_ACTIVE]))
    return _CAT_CACHE[_ACTIVE]

def get_control(control_id):
    c = _catalog()["controls"].get(control_id)
    if not c:
        raise KeyError(f"control {control_id} not in catalog {_ACTIVE}")
    return {"id": control_id, **c}

def catalog_hash():
    body = {"standard": _ACTIVE, "controls": _catalog()["controls"]}
    return "sha256:" + hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()[:16]

def catalog_weights():
    """DoD SPRS point values from the active catalog (Rev 2 only; empty for standards without weights)."""
    return {cid: c["dod_am_weight"] for cid, c in _catalog()["controls"].items() if "dod_am_weight" in c}

# ---------- Ingestion port: control-assessment request (control id + evidence bundle) ----------
def load_request(path):
    return json.load(open(path))

def iter_requests(dir_):
    for f in sorted(os.listdir(dir_)):
        if f.endswith(".json"):
            yield load_request(os.path.join(dir_, f))

def bundle_hash(req):
    body = json.dumps({"control_id": req.get("control_id"), "boundary": req.get("boundary"),
                       "evidence": req.get("evidence")}, sort_keys=True).encode()
    return "sha256:" + hashlib.sha256(body).hexdigest()[:16]

# ---------- Adjudicator port: determination schema + escalation-default LLM adjudication ----------
DETERMINATION_SCHEMA = {"type": "object", "properties": {
    "status": {"type": "string", "enum": ["met", "partially-met", "not-met"]},
    "unmet_objective_ids": {"type": "array", "items": {"type": "string"}},
    "gap_summary": {"type": "string"}},
    "required": ["status", "unmet_objective_ids", "gap_summary"]}

def _gemma(prompt, schema, name, concise=False):
    p = prompt + ("\nReturn ONE compact JSON object; gap_summary under 25 words." if concise else "")
    body = {"model": MODEL, "temperature": 0, "max_tokens": 640, "messages": [{"role": "user", "content": p}],
            "response_format": {"type": "json_schema", "json_schema": {"name": name, "schema": schema}}}
    r = requests.post(GEMMA, json=body, timeout=180); r.raise_for_status()
    try:
        return json.loads(r.json()["choices"][0]["message"]["content"])
    except Exception:
        return _gemma(prompt, schema, name, True) if not concise else None

# Assessment-method profile per family — mirrors the routing in flows/nist_800171_generic.md.
# Classified by family NAME (robust across revisions; the 'SA' digraph means different families in R2 vs R3).
def _method_profile(control):
    fam = (control.get("family_name") or "").lower()
    def has(*ks):
        return any(k in fam for k in ks)
    if has("risk assessment"):                                          # policy/process, not the CA family
        return "procedural"
    if has("security assessment", "assessment and authorization"):
        return "operational"
    if has("access control", "audit", "configuration", "identification",
            "communications", "comms", "information integrity", "media"):
        return "technical"
    if has("awareness", "personnel", "planning", "acquisition", "supply chain"):
        return "procedural"
    if has("incident", "maintenance", "physical"):
        return "operational"
    return "general"

_PROFILE_GUIDANCE = {
    "technical": ("This family is assessed chiefly by EXAMINING and TESTING enforcing configuration. Treat an "
                  "objective as satisfied ONLY when the evidence shows the control CONFIGURED AND ENFORCED on the "
                  "boundary (settings, policy-as-code, screenshots of enforced state, scan/test output). A written "
                  "policy that merely describes intent does NOT satisfy a technical objective."),
    "procedural": ("This family is assessed chiefly by EXAMINING policy/procedure AND INTERVIEWING personnel. Treat "
                   "an objective as satisfied ONLY when a CURRENT documented policy/procedure exists AND there is "
                   "corroboration it is operative (interview notes, records of the process being performed). A policy "
                   "no one demonstrably follows does NOT satisfy the objective."),
    "operational": ("This family is assessed by confirming the process runs IN PRACTICE (examine + interview + "
                    "test/observe). Treat an objective as satisfied ONLY when the process is EVIDENCED OPERATING on "
                    "the boundary (exercise records, logs, maintenance tickets, physical-access observations). "
                    "Documented intent without evidence of operation does NOT satisfy it."),
    "general": ("Assess each objective against the assessment methods it calls for; treat it as satisfied ONLY when "
                "positively evidenced on the boundary by those methods."),
}

def adjudicate(control, req):
    objs = "\n".join(f"  - {o['id']}: {o['text']}" for o in control["objectives"])
    ev = "\n".join(f"  - [{e.get('type', 'evidence')}] {e.get('text', '')}" for e in req.get("evidence", [])) or "  (no evidence submitted)"
    profile = _method_profile(control)
    methods = ", ".join(control.get("methods", [])) or "Examine"
    prompt = (f"You are a NIST SP 800-171 assessor evaluating control {control['id']} — {control['title']} "
              f"against the assessed boundary '{req.get('boundary', '(unspecified)')}'.\n"
              f"800-171A assessment methods for this control: {methods}.\n"
              f"{_PROFILE_GUIDANCE[profile]}\n"
              f"Assessment objectives:\n{objs}\nSubmitted evidence:\n{ev}\n\n"
              "The control is NOT MET unless the evidence POSITIVELY DEMONSTRATES each objective on the assessed "
              "boundary, using the assessment methods above. Intent-only policy without the corroboration the method "
              "requires, evidence outside the boundary, or a missing objective each mean that objective is NOT "
              "satisfied. In unmet_objective_ids list the id of EVERY objective the evidence does not positively "
              "demonstrate. status = 'met' only if that list is empty; 'partially-met' if some but not all objectives "
              "are unmet; 'not-met' if all or most objectives are unmet or the control intent is unmet. Give a "
              "one-line gap_summary.")
    return _gemma(prompt, DETERMINATION_SCHEMA, "determination")

# ---------- Action/Sink port: POA&M writer + finding record ----------
def write_result(control, req, determination, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    cid = control["id"]
    unmet = set(determination.get("unmet_objective_ids", []))
    rec = {"control_id": cid, "title": control["title"], "boundary": req.get("boundary"),
           "status": determination["status"], "gap_summary": determination["gap_summary"],
           "objectives_assessed": [o["id"] for o in control["objectives"]],
           "unmet_objectives": [o for o in control["objectives"] if o["id"] in unmet]}
    if determination["status"] == "met":
        rec["record_type"] = "finding_met"
        path = os.path.join(out_dir, f"finding_{cid}.json")
    else:
        rec["record_type"] = "poam"
        rec["weaknesses"] = rec["unmet_objectives"]
        rec["remediation"] = "TBD — address the listed weaknesses"; rec["milestone"] = "TBD"; rec["poam_status"] = "open"
        path = os.path.join(out_dir, f"poam_{cid}.json")
    json.dump(rec, open(path, "w"), indent=1)
    return path, rec["record_type"]

# ---------- Attestation port: REUSE the core Flow-Ledger provenance (#53) ----------
GENERIC_FLOW = os.path.join(HERE, "flows", "nist_800171_generic.md")

def active_flow_hash(path=GENERIC_FLOW):
    """Hash the actual decision-flow content, so the attestation binds the exact policy graph used."""
    return "sha256:" + hashlib.sha256(open(path, "rb").read()).hexdigest()[:16]

def attest(control, req, determination, flow_hash=None):
    return ledger_airgap.provenance_manifest(
        root_hex=hashlib.sha256(json.dumps(determination, sort_keys=True).encode()).hexdigest(),
        label=f"assess:{control['id']}",
        policy_hash=flow_hash or active_flow_hash(), gate_id="nist_800171_generic@v1",
        ingestion_hashes=[bundle_hash(req)], knowledge_base_hash=catalog_hash())

# ---------- Sink port (report emitter): standards-native OSCAL + CycloneDX (#65) ----------
sys.path.insert(0, HERE)
import emit as _emit      # pure serialization, adapter-local; carries the Flow-Ledger provenance into each report
import rollup as _rollup  # system-level aggregation: partial SPRS + scope + rollup attestation

def result_record(control, req, determination, manifest):
    """Normalize an adjudicated determination + its attestation manifest into an emit() record."""
    return {"control_id": control["id"], "title": control["title"], "boundary": req.get("boundary"),
            "status": determination["status"], "gap_summary": determination.get("gap_summary", ""),
            "unmet_objective_ids": determination.get("unmet_objective_ids", []), "manifest": manifest}

def emit_reports(records, fmt="both", out_dir=None):
    """Sink: serialize a batch of assessment records to the chosen standard(s), each schema-validated.
    fmt in {oscal, cyclonedx, both}; OSCAL emits an Assessment-Results + POA&M pair."""
    return _emit.emit(records, fmt=fmt, out_dir=out_dir)

def rollup_report(records, scope_meta, out_dir=None, fmt="both"):
    """System-level Sink: partial SPRS score + assessment scope + a rollup attestation whose inputs are
    the per-control manifest hashes, then emit the standard(s) with the rollup embedded in the OSCAL AR."""
    weights = catalog_weights()
    if weights:
        sprs = _rollup.sprs_partial(records, weights)
    else:                                                       # e.g. Rev 3 — not scored by the DoD methodology
        sprs = {"applicable": False, "standard": active_standard(),
                "reason": ("SPRS scoring is defined by the DoD Assessment Methodology for NIST 800-171 Rev 2 "
                           "only; standard '%s' is not SPRS-scored." % active_standard())}
    scope = _rollup.build_scope(scope_meta)
    manifest, summary = _rollup.system_attestation(records, sprs, scope, catalog_hash())
    emitted = _emit.emit(records, fmt=fmt, out_dir=out_dir,
                         rollup={"sprs": sprs, "scope": scope, "attestation": manifest})
    summary_path = _rollup.write_summary(sprs, scope, manifest, summary, out_dir) if out_dir else None
    return {"sprs": sprs, "scope": scope, "rollup_manifest": manifest["manifest_hash"],
            "bound_control_manifests": manifest["ingestion_hashes"], "summary_path": summary_path,
            "emitted": {k: {"valid": v["valid"], "n_errors": len(v["errors"]), "path": v["path"]}
                        for k, v in emitted.items()}}

# ---------- Deferral port wiring: HITL review + missing-evidence discovery ----------
_DEFER = deferral.FileDeferralStore(os.path.join(HERE, "deferrals"))

def sufficient_evidence(req):
    """v1: an empty evidence bundle is insufficient — triggers the discovery loop."""
    return bool(req.get("evidence"))

def defer_for_review(control, req, determination, reason="borderline / compensating-control — senior review"):
    """HITL: attest the AI determination FIRST (immutable), THEN defer for human review."""
    ai_prov = attest(control, req, determination)
    unit = f"assess:{control['id']}:{bundle_hash(req)}"
    _DEFER.defer(unit, reason=f"human_review: {reason}",
                 state={"flow": "nist_800171_access_control", "control_id": control["id"], "boundary": req.get("boundary")},
                 prior_output={"determination": determination, "ai_provenance": ai_prov})
    return {"unit_id": unit, "ai_status": determination["status"], "ai_manifest": ai_prov["manifest_hash"], "status": "pending_review"}

def resolve_review(unit_id, new_status, unmet_objective_ids, actor, rationale, out_dir):
    """Auditor resumes a review → attest the OVERRIDE as a superseding commit + write the final record."""
    rec = _DEFER.resume(unit_id, resolution={"status": new_status, "actor": actor}, actor=actor)
    ai_prov = rec["prior_output"]["ai_provenance"]           # the immutable AI manifest
    ai_det = rec["prior_output"]["determination"]
    control = get_control(rec["state"]["control_id"])
    final_det = {"status": new_status, "unmet_objective_ids": unmet_objective_ids,
                 "gap_summary": f"HUMAN OVERRIDE ({actor}): {rationale}. AI concluded '{ai_det['status']}'."}
    ov = ledger_airgap.override_manifest(ai_prov, overrider_id=actor, rationale=rationale,
                                         new_root_hex=hashlib.sha256(json.dumps(final_det, sort_keys=True).encode()).hexdigest())
    unmet = set(unmet_objective_ids)
    out = {"control_id": control["id"], "title": control["title"], "final_status": new_status,
           "gap_summary": final_det["gap_summary"],
           "unmet_objectives": [o for o in control["objectives"] if o["id"] in unmet],
           "override": {"actor": actor, "rationale": rationale, "ai_original_status": ai_det["status"],
                        "ai_manifest": ai_prov["manifest_hash"], "override_manifest": ov["manifest_hash"],
                        "supersedes": ov["supersedes"]}}
    os.makedirs(out_dir, exist_ok=True)
    kind = "finding" if new_status == "met" else "poam"
    path = os.path.join(out_dir, f"{kind}_{control['id']}_overridden.json")
    json.dump(out, open(path, "w"), indent=1)
    return {"unit_id": unit_id, "ai_status": ai_det["status"], "final_status": new_status, "overrider": actor,
            "ai_manifest": ai_prov["manifest_hash"][:16], "override_manifest": ov["manifest_hash"][:16],
            "supersedes_ai": ov["supersedes"] == ai_prov["manifest_hash"], "record": os.path.relpath(path, HERE)}

def translate_missing(control, unmet_ids=None):
    """Translation layer (Gap 1): turn a control + its unmet objectives into a catalog-driven,
    objective-specific evidence request. unmet_ids=None means the whole control (e.g. an empty bundle)."""
    targets = set(unmet_ids) if unmet_ids else {o["id"] for o in control["objectives"]}
    requests = [{"objective_id": o["id"], "objective": o["text"],
                 "ask": o.get("discovery_query", "Provide evidence that %s." % o["text"])}
                for o in control["objectives"] if o["id"] in targets]
    return {"control_id": control["id"], "evidence_types": control.get("evidence_types", []),
            "requests": requests}

def defer_for_evidence(control, req, missing=None, unmet_ids=None):
    """Discovery: evidence insufficient → route a catalog-driven evidence request (deferred), do NOT fail.
    If `missing` is not given it is GENERATED from the catalog Translation layer (evidence_types +
    per-objective asks); passing a string still works for callers that want a hand-written ask."""
    if missing is None:
        missing = translate_missing(control, unmet_ids)
    reason = missing if isinstance(missing, str) else "%d objective(s)" % len(missing["requests"])
    unit = f"assess:{control['id']}:{bundle_hash(req)}"
    _DEFER.defer(unit, reason=("request_evidence: %s" % reason)[:200],
                 state={"flow": "nist_800171_access_control", "control_id": control["id"], "boundary": req.get("boundary")},
                 prior_output={"request": missing, "objective_ids": [o["id"] for o in control["objectives"]]})
    return {"unit_id": unit, "status": "pending_evidence", "request": missing}

def resolve_evidence(unit_id, new_evidence, out_dir):
    """Client uploads the requested evidence → resume → re-adjudicate with the new bundle."""
    rec = _DEFER.resume(unit_id, resolution={"evidence_received": True}, actor="client")
    control = get_control(rec["state"]["control_id"])
    req = {"control_id": control["id"], "boundary": rec["state"]["boundary"], "evidence": new_evidence}
    det = adjudicate(control, req)
    if det is None:
        return {"unit_id": unit_id, "error": "adjudication failed"}
    path, rt = write_result(control, req, det, out_dir)
    prov = attest(control, req, det)
    return {"unit_id": unit_id, "status": det["status"], "record": rt, "manifest": prov["manifest_hash"][:16]}
