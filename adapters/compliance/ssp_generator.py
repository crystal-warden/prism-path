#!/usr/bin/env python3
"""System Security Plan (SSP) generator — the master NIST SP 800-171 document.

The SSP describes the system, its boundary, the CUI it handles, and how each of the 110 requirements is
implemented. PrismPath does not hand-write it: the system sections come from the organization profile,
and the control-implementation section is generated from the live assessment — each requirement's
implementation status, the responsible role, and the policy that governs it — so the SSP stays
consistent with the actual posture and regenerates whenever the assessment or the policies change.

Same template/instance model as the policy generator: with no profile and no verdicts it renders a
reusable blank (every field a TODO); with a filled profile and a real assessment it renders the
organization's SSP. A generated SSP is a living document to maintain, not evidence by itself.
"""
import compliance_adapter as _ca
import sop_generator as _sg

_OWNER = {"technical": "System / Security Administrator", "procedural": "ISSM / Policy Owner",
          "operational": "Operations / Process Owner", "general": "ISSM"}
_STATUS = {"met": "Implemented", "partially-met": "Partially Implemented",
           "not-met": "Planned (POA&M)", "insufficient": "Planned (POA&M)"}

# SSP profile = the shared org profile plus SSP-specific identification fields.
SSP_PROFILE_QUESTIONS = dict(_sg.PROFILE_QUESTIONS)
SSP_PROFILE_QUESTIONS.update({
    "system_owner": "Who is the system owner?",
    "security_lead": "Who is the security lead (ISSM/ISSO)?",
    "assessment_date": "What is the assessment date?",
    "sprs_score": "What is the current SPRS score?",
})

NOTICE = ("This System Security Plan was generated from the live assessment and the organization "
          "profile. It is a living document to maintain, not evidence by itself: each requirement is "
          "implemented only when the described control operates and its records are retained. Fields "
          "marked TODO still require an answer.")


def _numkey(cid):
    return [int(p) for p in cid.split(".")]


def _owner(control):
    return _OWNER.get(_ca._method_profile(control), "ISSM")


def _sop_index():
    """control id -> the title of the 800-171 policy that governs it."""
    idx = {}
    for doc in _sg.list_documents():
        try:
            spec = _sg.load_spec(doc)
        except Exception:
            continue
        if spec.get("standard", "nist_800171_r2") != "nist_800171_r2":
            continue
        for cid in spec.get("controls", []):
            idx.setdefault(cid, spec.get("title", doc))
    return idx


def _impl_note(verdict, sop_title):
    if verdict == "met":
        return "Implemented; determination met."
    if verdict == "partially-met":
        return "Partially implemented; remaining objectives tracked on the POA&M."
    if sop_title:
        return "Planned. Adopt and operate the %s, then retain records; tracked on the POA&M." % sop_title
    return "Planned; tracked on the POA&M."


def generate_ssp(profile=None, verdicts=None):
    """Render the SSP. profile fills the system sections (blank fields become TODO); verdicts drive the
    control-implementation section (absent -> a blank TODO structure, the reusable template)."""
    profile = profile or {}
    _ca.use_standard("nist_800171_r2")
    catalog = _ca._catalog()["controls"]
    sop_idx = _sop_index()

    def f(k):
        return profile.get(k) or "[TODO: %s]" % SSP_PROFILE_QUESTIONS.get(k, k)

    L = ["# System Security Plan", "", "> " + NOTICE, "",
         "Standard: NIST SP 800-171 Rev 2 (CMMC Level 2).", ""]
    L += ["## 1. System Identification", "",
          "| Field | Value |", "|---|---|",
          "| Organization | %s |" % f("org_name"),
          "| System name | %s |" % f("system_name"),
          "| System owner | %s |" % f("system_owner"),
          "| Security lead (ISSM/ISSO) | %s |" % f("security_lead"),
          "| Assessment date | %s |" % f("assessment_date"),
          "| Current SPRS score | %s |" % f("sprs_score"), ""]
    L += ["## 2. System Environment and Boundary", "",
          "The assessment boundary (the CUI environment) is described as: %s." % f("boundary"),
          "", "Confirm the component inventory (hardware, software, and services that store, process, or "
          "transmit CUI), the network boundary, and the data flows in or attached to this section.", ""]
    L += ["## 3. Controlled Unclassified Information", "",
          "CUI handled by the system: %s." % f("cui_description"), ""]
    L += ["## 4. Roles and Responsibilities", "",
          "The system owner (%s) is accountable for the system; the security lead (%s) owns the security "
          "posture; control-level responsibility is assigned per requirement in Section 5." % (
              f("system_owner"), f("security_lead")), ""]
    L += ["## 5. Control Implementation", "",
          "One row per NIST 800-171 Rev 2 requirement: implementation status, the responsible role, the "
          "policy that governs it, and the implementation summary.", "",
          "| Control | Title | Status | Responsible role | Governing policy | Implementation |",
          "|---|---|---|---|---|---|"]
    tally = {}
    for cid in sorted(catalog, key=_numkey):
        c = _ca.get_control(cid)
        v = (verdicts or {}).get(cid)
        tally[v] = tally.get(v, 0) + 1
        status = _STATUS.get(v, "[TODO: status]") if verdicts else "[TODO: status]"
        sop_title = sop_idx.get(cid, "")
        impl = _impl_note(v, sop_title) if verdicts else "[TODO: describe how this requirement is implemented]"
        L.append("| %s | %s | %s | %s | %s | %s |" % (
            cid, c["title"], status, _owner(c), sop_title or "(no policy mapped)", impl))
    L += ["", "## 6. Assessment Status", ""]
    if verdicts:
        L.append("Current posture: " + ", ".join("%s %d" % (k, n) for k, n in sorted(tally.items()) if k) + ".")
        L.append("SPRS score: %s. See the POA&M for the prioritized remediation path." % f("sprs_score"))
    else:
        L.append("[TODO: summarize the assessment result and SPRS score once the system is assessed.]")
    L += ["", "## 7. Related Documents", "",
          "- Policy and procedure set (one per 800-171 family): the policy document package.",
          "- Plan of Action and Milestones (POA&M): the prioritized remediation for every open requirement.",
          "- Assessment Scope: the CUI, asset categories, and boundary.", ""]
    return {"markdown": "\n".join(L), "controls": len(catalog), "status_tally": tally}


if __name__ == "__main__":
    print(generate_ssp()["markdown"][:1500])
