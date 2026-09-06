# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""OSCAL Catalog Interoperability for Compliance Adapter.

Provides import_oscal and export_oscal for translating between OSCAL catalog dicts
and the adapter catalog schema.
"""
import re
import uuid


FAM_DIGRAPH_R3 = {
    "3.1": "AC", "3.2": "AT", "3.3": "AU", "3.4": "CM", "3.5": "IA", "3.6": "IR", "3.7": "MA",
    "3.8": "MP", "3.9": "PS", "3.10": "PE", "3.11": "RA", "3.12": "CA", "3.13": "SC", "3.14": "SI",
    "3.15": "PL", "3.16": "SA", "3.17": "SR"
}


def _norm_id(oscal_id):
    """Normalize control ID (e.g., SP_800_171_03.01.01 or 03.01.01 -> 3.1.1)."""
    if not oscal_id:
        return ""
    m = re.search(r"(\d+(?:\.\d+)+)$", oscal_id)
    if m:
        return ".".join(str(int(x)) for x in m.group(1).split("."))
    return oscal_id


def _obj_id(part_id, cid):
    """Extract or normalize objective ID from part ID."""
    if not part_id:
        return ""
    # Match NIST OSCAL Rev 3 pattern: assessment-objective_DS-A.03.01.01.b.01 -> 3.1.1[b.01]
    m = re.search(r"\d{2}(?:\.\d{2})+\.([a-z0-9.]+)$", part_id)
    if m:
        return f"{cid}[{m.group(1)}]"
    if part_id.startswith("assessment-objective_"):
        return part_id[len("assessment-objective_"):]
    return part_id


def _prose(part):
    """Recursively extract and combine prose from a part and its subparts."""
    txt = part.get("prose", "") or ""
    for sp in part.get("parts", []):
        sub = _prose(sp)
        if sub:
            txt = (txt + " " + sub).strip()
    return txt.strip()


def _discovery(text):
    return "Provide evidence that %s" % text.rstrip(".") + "."


def import_oscal(oscal):
    """Import an OSCAL catalog dict into the adapter catalog schema."""
    cat = oscal.get("catalog", oscal) if isinstance(oscal, dict) else {}

    def walk(g):
        for c in g.get("controls", []):
            yield g, c
        for sg in g.get("groups", []):
            yield from walk(sg)

    families = {}
    controls = {}

    for grp in cat.get("groups", []):
        for g, ctl in walk(grp):
            cid = _norm_id(ctl.get("id", ""))
            if not cid:
                continue

            gid = g.get("id", "")
            gtitle = g.get("title", "")

            # Determine family digraph and family name
            if gid in FAM_DIGRAPH_R3:
                dg = FAM_DIGRAPH_R3[gid]
            elif gid and re.match(r"^[A-Z]{2,4}$", gid):
                dg = gid
            else:
                fam = cid.rsplit(".", 1)[0] if cid.count(".") >= 2 else cid
                dg = FAM_DIGRAPH_R3.get(fam, fam)

            fam_name = gtitle or dg
            families[dg] = fam_name

            parts = ctl.get("parts", [])
            statement = " ".join(_prose(p) for p in parts if p.get("name") == "statement").strip()

            objectives = []
            obj_idx = 1
            for p in parts:
                if p.get("name") == "assessment-objective":
                    prose_text = _prose(p)
                    if prose_text:
                        pid = p.get("id", "")
                        oid = _obj_id(pid, cid) if pid else f"{cid}_obj_{obj_idx}"
                        obj_dict = {
                            "id": oid,
                            "text": prose_text,
                            "discovery_query": _discovery(prose_text),
                        }
                        objectives.append(obj_dict)
                        obj_idx += 1

            controls[cid] = {
                "family": dg,
                "family_name": fam_name,
                "title": ctl.get("title", ""),
                "control": statement or ctl.get("title", ""),
                "objectives": objectives,
            }

    return {
        "_meta": {
            "standard": "oscal_imported",
            "families": len(families),
            "controls": len(controls),
        },
        "families": families,
        "controls": controls,
    }


def export_oscal(catalog):
    """Export adapter catalog schema to an OSCAL catalog dict."""
    families = catalog.get("families", {})
    controls = catalog.get("controls", {})

    family_map = dict(families)
    for c in controls.values():
        fam = c.get("family")
        fam_name = c.get("family_name")
        if fam and fam not in family_map:
            family_map[fam] = fam_name or fam

    controls_by_fam = {}
    for cid, ctl in controls.items():
        fam = ctl.get("family", "OTHER")
        controls_by_fam.setdefault(fam, []).append((cid, ctl))

    groups = []
    for fam_id, fam_name in family_map.items():
        fam_ctls = controls_by_fam.get(fam_id, [])
        oscal_controls = []
        for cid, ctl in fam_ctls:
            parts = []
            stmt_text = ctl.get("control", "")
            if stmt_text:
                parts.append({
                    "name": "statement",
                    "prose": stmt_text
                })
            for obj in ctl.get("objectives", []):
                part_dict = {
                    "name": "assessment-objective",
                    "id": obj.get("id", ""),
                    "prose": obj.get("text", "")
                }
                parts.append(part_dict)

            oscal_ctl = {
                "id": cid,
                "title": ctl.get("title", ""),
                "parts": parts
            }
            oscal_controls.append(oscal_ctl)

        groups.append({
            "id": fam_id,
            "title": fam_name,
            "controls": oscal_controls
        })

    meta = catalog.get("_meta", {})
    std = meta.get("standard", "imported-catalog")
    # deterministic uuid so the same catalog exports byte-stable (import ignores it, round-trip holds)
    cat_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, "prismpath:catalog:" + str(std)))
    return {"catalog": {
        "uuid": cat_uuid,
        "metadata": {"title": str(std), "version": str(meta.get("revision", "1")),
                     "oscal-version": "1.1.3"},
        "groups": groups,
    }}
