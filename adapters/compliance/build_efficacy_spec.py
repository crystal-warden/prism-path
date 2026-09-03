#!/usr/bin/env python3
"""Extract a stratified control set (with real 800-171A objectives) from the Rev 2 catalog to ground
the agy-generated efficacy corpus. 3 controls per method profile x the difficulty tiers we ask agy for."""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import compliance_adapter as ca

ca.use_standard("nist_800171_r2")

SELECTED = {
    "technical":   ["3.1.5", "3.5.3", "3.13.1"],
    "procedural":  ["3.2.1", "3.9.1", "3.11.1"],
    "operational": ["3.6.1", "3.7.1", "3.10.1"],
}

spec = {"standard": "nist_800171_r2", "difficulties": ["easy", "medium", "hard"], "controls": []}
missing = []
for profile, cids in SELECTED.items():
    for cid in cids:
        try:
            c = ca.get_control(cid)
        except KeyError:
            missing.append(cid); continue
        prof = ca._method_profile(c)
        spec["controls"].append({
            "control_id": cid, "title": c["title"], "family": c.get("family"),
            "family_name": c.get("family_name"), "method_profile": prof,
            "intended_profile": profile, "profile_matches": prof == profile,
            "control_statement": c["control"], "methods": c.get("methods", []),
            "evidence_types": c.get("evidence_types", []),
            "objectives": [{"id": o["id"], "text": o["text"]} for o in c["objectives"]],
        })
out_dir = os.path.join(HERE, "efficacy")
os.makedirs(out_dir, exist_ok=True)
json.dump(spec, open(os.path.join(out_dir, "spec.json"), "w"), indent=1)
print(json.dumps({"n_controls": len(spec["controls"]), "missing": missing,
                  "profile_mismatches": [c["control_id"] for c in spec["controls"] if not c["profile_matches"]],
                  "sample": {c["control_id"]: {"profile": c["method_profile"], "n_obj": len(c["objectives"])}
                             for c in spec["controls"]}}, indent=1))
