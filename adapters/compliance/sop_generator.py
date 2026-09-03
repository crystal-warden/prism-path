#!/usr/bin/env python3
"""SOP / policy document generator — the remediation half of the compliance adapter.

When a control requires a documented policy or procedure the tenant does not have, this generates a
draft from a standardized, objective-grounded template filled by a structured intake. It is
deterministic: a curated question set fills the template, no model required (an LLM can later conduct
an adaptive interview or polish prose, the same honest hybrid used for adjudication).

The generated document is objective-complete BY CONSTRUCTION and machine-checked against the active
catalog: every 800-171A objective of the spec's controls maps to a section, so a completed template
addresses every objective. `verify_coverage` proves this against the real catalog and catches spec
drift.

Honest boundary: a generated policy is documentation, not proof the process operates. For procedural
and operational objectives the escalation-default rule still applies. The tenant must adopt the
policy, operate it, and retain records that it runs. Unanswered questions are marked TODO, never
fabricated.

Specs live as data (`sop_specs/*.json`); the engine is family-agnostic. No compliance vocabulary in
the core.
"""
import os
import json
import glob

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC_DIR = os.path.join(HERE, "sop_specs")

# Shared organizational profile: answered once, reused across every document the tenant generates.
PROFILE_QUESTIONS = {
    "org_name": "What is the organization's legal name?",
    "system_name": "What is the name of the system in scope?",
    "boundary": "How is the system boundary (the assessed environment) described?",
    "cui_description": "What Controlled Unclassified Information does the system handle?",
}

GENERATED_NOTICE = (
    "> This document was generated from a standardized, objective-grounded template. It is a draft to "
    "adopt and operate, not evidence by itself. A documented policy satisfies the documentation an "
    "assessment objective calls for; the procedural and operational objectives are satisfied only when "
    "the organization performs the process and retains records that it runs. Items marked TODO still "
    "require an answer."
)


def list_documents():
    return sorted(os.path.splitext(os.path.basename(p))[0]
                  for p in glob.glob(os.path.join(SPEC_DIR, "*.json")))


def load_spec(doc_id):
    path = os.path.join(SPEC_DIR, doc_id + ".json")
    if not os.path.exists(path):
        raise KeyError("no SOP spec %r; have %s" % (doc_id, list_documents()))
    return json.load(open(path))


def _resolve_get_control(get_control):
    if get_control is not None:
        return get_control
    import compliance_adapter
    return compliance_adapter.get_control


def _get_control_for(spec, get_control):
    """Resolve controls against the spec's own standard, so a SOP for a non-800-171 framework (its
    controls named in a different catalog) checks against the right catalog regardless of what is
    active. Falls back to the active-standard get_control."""
    if get_control is not None:
        return get_control
    import compliance_adapter as _ca
    std = spec.get("standard")
    if std and std != _ca.active_standard() and std in _ca.STANDARDS:
        cat = json.load(open(_ca.STANDARDS[std]))["controls"]

        def gc(cid):
            c = cat.get(cid)
            if not c:
                raise KeyError("control %s not in catalog %s" % (cid, std))
            return {"id": cid, **c}
        return gc
    return _ca.get_control


def verify_coverage(spec, get_control=None):
    """Machine-check the spec's objective coverage against its standard's catalog. In the default
    coverage_mode 'full' the guarantee is objective-complete: every objective of the spec's controls
    maps to exactly one section (the 800-171 policy guarantee). A spec may declare coverage_mode
    'partial' when its controls split objectives across mechanisms (a policy documents only the
    documentation objectives; the config and operational objectives are met by the register and task
    records) — then unmapped objectives are reported but do not fail completeness, while extra or
    duplicated mappings still do."""
    gc = _get_control_for(spec, get_control)
    catalog_set = set()
    for cid in spec["controls"]:
        catalog_set.update(o["id"] for o in gc(cid)["objectives"])
    mapped = [oid for s in spec["sections"] for oid in s.get("objectives", [])]
    mapped_set = set(mapped)
    dupes = sorted({oid for oid in mapped_set if mapped.count(oid) > 1})
    missing = sorted(catalog_set - mapped_set)    # objectives no section addresses
    extra = sorted(mapped_set - catalog_set)      # mapped ids not in the catalog (spec drift)
    mode = spec.get("coverage_mode", "full")
    complete = not (extra or dupes) and (mode == "partial" or not missing)
    return {"controls": list(spec["controls"]), "n_objectives": len(catalog_set),
            "mapped": len(mapped_set), "missing": missing, "extra": extra, "duplicated": dupes,
            "coverage_mode": mode, "complete": complete}


def _prompt_map(spec):
    prompts = dict(PROFILE_QUESTIONS)
    for s in spec["sections"]:
        for q in s.get("questions", []):
            prompts[q["key"]] = q["prompt"]
    return prompts


def intake(spec):
    """The full structured question set: the shared profile questions plus each section's questions,
    each tagged with where its answer belongs. Answer these to fill the template."""
    items = [{"key": k, "prompt": PROFILE_QUESTIONS[k], "scope": "profile"}
             for k in spec.get("org_profile_keys", [])]
    for s in spec["sections"]:
        for q in s.get("questions", []):
            items.append({"key": q["key"], "prompt": q["prompt"],
                          "scope": "document", "section": s["id"]})
    return items


class _Fill(dict):
    """format_map helper: fills present answers, marks any missing key as a visible TODO carrying
    its question, and records the missing key. Never fabricates a value."""
    def __init__(self, answers, missing, prompts):
        super().__init__(answers)
        self._missing = missing
        self._prompts = prompts

    def __missing__(self, key):
        self._missing.add(key)
        return "[TODO: %s]" % self._prompts.get(key, key)


def generate(spec, answers, get_control=None):
    """Fill the template from answers. Missing answers become visible TODO placeholders (never
    fabricated) and are returned in `unanswered`. The generated markdown carries an honest-boundary
    notice and a control-objective coverage appendix. Returns markdown, unanswered keys, and the
    coverage report."""
    prompts = _prompt_map(spec)
    missing = set()
    out = ["# %s" % spec["title"], "", GENERATED_NOTICE, ""]
    for s in spec["sections"]:
        out.append("## %s" % s["heading"])
        out.append(s["body"].format_map(_Fill(answers, missing, prompts)))
        out.append("")

    cov = verify_coverage(spec, get_control)
    out.append("## Appendix A. Control Objective Coverage")
    out.append("")
    if cov["coverage_mode"] == "partial":
        out.append("This policy addresses the documentation objectives of %s. The remaining objectives of "
                   "those controls are met by configuration evidence (the register) and operational "
                   "records, not by this document." % ", ".join(spec["controls"]))
    else:
        out.append("Every assessment objective of %s is addressed by a section of this document."
                   % ", ".join(spec["controls"]))
    out.append("")
    out.append("| Section | Objectives addressed |")
    out.append("|---|---|")
    for s in spec["sections"]:
        objs = ", ".join(s.get("objectives", [])) or "(context; no objective)"
        out.append("| %s | %s |" % (s["heading"], objs))
    out.append("")
    if not cov["complete"]:
        out.append("> COVERAGE WARNING: this template does not currently map every objective "
                   "(missing: %s; extra: %s; duplicated: %s). Fix the spec before relying on it."
                   % (cov["missing"] or "none", cov["extra"] or "none", cov["duplicated"] or "none"))
        out.append("")

    return {"markdown": "\n".join(out), "unanswered": sorted(missing), "coverage": cov,
            "title": spec["title"], "controls": list(spec["controls"])}
