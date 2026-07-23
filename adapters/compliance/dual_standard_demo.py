#!/usr/bin/env python3
"""#69 proof (deterministic): the engine is catalog-agnostic — the assessor picks the standard before the audit."""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import compliance_adapter as ca

out = {"available_standards": ca.list_standards()}

ca.use_standard("nist_800171_r2")
c = ca.get_control("3.1.5")
out["rev2"] = {"active": ca.active_standard(), "control": "3.1.5", "title": c["title"],
               "dod_weight": c.get("dod_am_weight"), "methods": c.get("methods"),
               "n_objectives": len(c["objectives"]), "n_weighted_controls": len(ca.catalog_weights()),
               "catalog_hash": ca.catalog_hash()}

ca.use_standard("nist_800171_r3")
c3 = ca.get_control("3.1.1")
out["rev3"] = {"active": ca.active_standard(), "control": "3.1.1", "title": c3["title"],
               "n_objectives": len(c3["objectives"]), "n_odps": len(c3.get("odps", [])),
               "methods": c3.get("methods"), "n_weighted_controls": len(ca.catalog_weights()),
               "catalog_hash": ca.catalog_hash(),
               "sprs_scored": bool(ca.catalog_weights())}

print(json.dumps(out, indent=1))
