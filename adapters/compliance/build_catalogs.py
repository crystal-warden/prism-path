#!/usr/bin/env python3
"""#69 — build the two runtime-selectable catalogs from their sources, normalized into the adapter schema.

  nist_800171_r2.json  <- tbusillo OSCAL mirror (UNOFFICIAL community transcription of NIST SP 800-171 Rev 2
                          / 800-171A / DoD Assessment Methodology): 110 controls, 308 objectives, methods, DoD
                          SPRS weights. Curated AC evidence_types/discovery_query (#67) merged back in.
  nist_800171_r3.json  <- NIST usnistgov/oscal-content Rev 3 catalog (OFFICIAL): controls + statements +
                          inline 800-171A r3 assessment-objectives + assessment-methods + ODPs. No DoD weights
                          (SPRS is a Rev-2 construct) -> not SPRS-scored.

Schema (both): {_meta, families:{digraph:name}, controls:{cid:{family,family_name,title,control,objectives:
[{id,text,methods?}],methods,evidence_types,dod_am_weight?,odps?}}}. Objectives carry discovery_query.
"""
import json, os, re, sys

SRC = "/tmp"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "catalog")
CURATED_AC = os.path.join(OUT, "nist_800171_ac.json")


def _load(p):
    return json.load(open(p))


def _discovery(text):
    return "Provide evidence that %s" % text.rstrip(".") + "."


# ============================ Rev 2 (mirror) ============================
def build_r2():
    fams = {f["internal_id"]: f for f in _load(os.path.join(SRC, "cprt_control_families.json"))["families"]
            if not f.get("is80053")}
    fam_digraph = {fid: f["digraph"] for fid, f in fams.items()}
    families = {f["digraph"]: f["name"] for f in fams.values()}
    ctls = [c for c in _load(os.path.join(SRC, "cprt_controls_with_dod_assessment_weight.json"))["controls"]
            if not c["internal_id"].startswith("53.")]
    objs = [o for o in _load(os.path.join(SRC, "cprt_assessment_objectives.json"))["objectives"]
            if not o["control_internal_id"].startswith("53.")]
    methods = _load(os.path.join(SRC, "cprt_assessment_objects_methods_by_control.json"))

    # per-control method + assessment-object (evidence) unions
    cmethods, cobjects = {}, {}
    for m in methods:
        cid = m["control"]
        cmethods.setdefault(cid, set()).add(m["assessmentMethod"])
        for ob in m.get("assessmentObjects", []):
            cobjects.setdefault(cid, set()).add(ob)

    # objectives grouped by control, id 3.1.1.a -> 3.1.1[a]
    by_ctl = {}
    for o in objs:
        cid = o["control_internal_id"]
        letter = o["internal_id"][len(cid) + 1:]                # after "3.1.1."
        oid = "%s[%s]" % (cid, letter)
        by_ctl.setdefault(cid, []).append({"id": oid, "text": o["objective"].rstrip(".") + ".",
                                           "discovery_query": _discovery(o["objective"])})

    # merge curated AC discovery_query / evidence_types from #67
    curated = _load(CURATED_AC)["controls"] if os.path.exists(CURATED_AC) else {}

    controls = {}
    for c in ctls:
        cid = c["internal_id"]
        fam_dg = fam_digraph.get(c["family_internal_id"], "?")
        cobj = by_ctl.get(cid, [])
        cur = curated.get(cid, {})
        cur_dq = {o["id"]: o.get("discovery_query") for o in cur.get("objectives", [])}
        for o in cobj:                                          # prefer curated per-objective ask where present
            if cur_dq.get(o["id"]):
                o["discovery_query"] = cur_dq[o["id"]]
        evidence = cur.get("evidence_types") or sorted(cobjects.get(cid, []))
        controls[cid] = {
            "family": fam_dg, "family_name": families.get(fam_dg, ""),
            "title": cur.get("title") or c["description"][:80].rstrip(". ") ,
            "control": c["description"],
            "objectives": cobj,
            "methods": sorted(cmethods.get(cid, [])),
            "evidence_types": evidence,
            "dod_am_weight": int(c["dod_am_weight"]),
        }
    out = {"_meta": {
        "standard": "nist_800171_r2", "revision": "2",
        "families": len(families), "controls": len(controls),
        "source": "tbusillo/nist-800-171-oscal (community OSCAL rendering)",
        "provenance": "UNOFFICIAL community transcription of NIST SP 800-171 Rev 2, 800-171A, and the DoD "
                      "Assessment Methodology. NIST no longer publishes Rev 2 machine-readable. VERIFY against "
                      "the source NIST/DoD PDFs before any assessment use.",
        "sprs": "dod_am_weight per control = DoD Assessment Methodology point value (5/3/1); base 110.",
        "methods_note": "methods are control-level (union across the 800-171A assessment objects); not split per objective."},
        "families": families, "controls": controls}
    json.dump(out, open(os.path.join(OUT, "nist_800171_r2.json"), "w"), indent=1)
    return len(controls), sum(len(c["objectives"]) for c in controls.values()), len(families)


# ============================ Rev 3 (official OSCAL) ============================
FAM_DIGRAPH_R3 = {
    "3.1": "AC", "3.2": "AT", "3.3": "AU", "3.4": "CM", "3.5": "IA", "3.6": "IR", "3.7": "MA",
    "3.8": "MP", "3.9": "PS", "3.10": "PE", "3.11": "RA", "3.12": "CA", "3.13": "SC", "3.14": "SI",
    "3.15": "PL", "3.16": "SA", "3.17": "SR"}


def _norm_id(oscal_id):
    # SP_800_171_03.01.01 -> 3.1.1 ; strip prefix, drop leading zeros per dotted segment
    m = re.search(r"(\d{2}(?:\.\d{2})+)$", oscal_id)
    if not m:
        return oscal_id
    return ".".join(str(int(x)) for x in m.group(1).split("."))


def _obj_id_r3(part_id, cid):
    # assessment-objective_DS-A.03.01.01.b.01 -> 3.1.1[b.01]
    m = re.search(r"\d{2}(?:\.\d{2})+\.([a-z0-9.]+)$", part_id)
    return "%s[%s]" % (cid, m.group(1)) if m else part_id.replace("assessment-objective_", "")


def _prose(part):
    txt = part.get("prose", "") or ""
    for sp in part.get("parts", []):
        txt = (txt + " " + _prose(sp)).strip()
    return txt


def build_r3():
    cat = _load(os.path.join(SRC, "rev3_catalog.json"))["catalog"]

    def walk(g):
        for c in g.get("controls", []):
            yield g, c
        for sg in g.get("groups", []):
            yield from walk(sg)

    families, controls = {}, {}
    for grp in cat["groups"]:
        for g, ctl in walk(grp):
            cid = _norm_id(ctl["id"])
            fam = cid.rsplit(".", 1)[0] if cid.count(".") >= 2 else cid
            dg = FAM_DIGRAPH_R3.get(fam, fam)
            families[dg] = g.get("title", "")
            parts = ctl.get("parts", [])
            statement = " ".join(_prose(p) for p in parts if p.get("name") == "statement").strip()
            objectives = []
            for p in parts:
                if p.get("name") == "assessment-objective":
                    prose = _prose(p)
                    if prose:
                        objectives.append({"id": _obj_id_r3(p.get("id", ""), cid),
                                           "text": prose, "discovery_query": _discovery(prose)})
            methods, evobjs = set(), set()
            for p in parts:
                if p.get("name") == "assessment-method":
                    for pr in p.get("props", []):
                        if pr.get("name") == "method" and pr.get("value"):
                            methods.add(pr["value"].title())        # EXAMINE -> Examine
                    for sp in p.get("parts", []):
                        if sp.get("name") == "assessment-objects":
                            for line in (sp.get("prose", "") or "").split("\n\n"):
                                line = line.strip()
                                if line:
                                    evobjs.add(line)
            odps = [pp.get("id") for pp in ctl.get("params", [])]
            controls[cid] = {
                "family": dg, "family_name": g.get("title", ""),
                "title": ctl.get("title", ""), "control": statement or ctl.get("title", ""),
                "objectives": objectives, "methods": sorted(methods),
                "evidence_types": sorted(evobjs)[:15], "odps": odps}
    out = {"_meta": {
        "standard": "nist_800171_r3", "revision": "3",
        "families": len(families), "controls": len(controls),
        "source": "usnistgov/oscal-content NIST_SP800-171_rev3_catalog.json (OFFICIAL NIST OSCAL)",
        "provenance": "Official NIST OSCAL Rev 3 catalog incl. inline 800-171A r3 assessment objectives, "
                      "methods, and organization-defined parameters (ODPs).",
        "sprs": "NOT SPRS-scored: the DoD Assessment Methodology point system is defined for Rev 2 only.",
        "evidence_types_note": "derived from the 800-171A r3 assessment-objects (capped at 15/control).",
        "methods_note": "Examine/Interview/Test from the assessment-method 'method' prop per control."},
        "families": families, "controls": controls}
    json.dump(out, open(os.path.join(OUT, "nist_800171_r3.json"), "w"), indent=1)
    return len(controls), sum(len(c["objectives"]) for c in controls.values()), len(families)


if __name__ == "__main__":
    r2 = build_r2()
    r3 = build_r3()
    print(json.dumps({"r2": {"controls": r2[0], "objectives": r2[1], "families": r2[2]},
                      "r3": {"controls": r3[0], "objectives": r3[1], "families": r3[2]}}, indent=1))
