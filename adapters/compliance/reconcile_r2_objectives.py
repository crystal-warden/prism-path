#!/usr/bin/env python3
"""Reconcile the R2 catalog's assessment objectives to the verified NIST SP 800-171 Rev 2
corpus.

The prior R2 catalog objectives came from an UNOFFICIAL community OSCAL mirror and carried
308 assessment objectives; the published NIST SP 800-171A Rev 2 has 320. This overlays the
verified 320-objective corpus (control statements + 800-171A objectives, verbatim-checked)
onto the existing catalog, preserving everything the mirror got right and the adapter depends
on: the DoD SPRS weights (dod_am_weight), control-level methods, evidence_types, the family
digraphs, and any curated per-objective discovery_query.

Only the objective set (and any control statement that differs from the verified text) is
changed. Rerunnable and idempotent. Source corpus defaults to the prismpath-grc workspace;
pass a directory as argv[1] to override.
"""
import json, os, glob, sys, yaml

HERE = os.path.dirname(os.path.abspath(__file__))
CATALOG = os.path.join(HERE, "catalog", "nist_800171_r2.json")
CORPUS_DIR = sys.argv[1] if len(sys.argv) > 1 else \
    "/home/cwadmin/cwprojects/prismpath-grc/frameworks/nist-800-171r2"


def _discovery(text):
    return "Provide evidence that %s" % text.rstrip(".") + "."


def load_corpus(d):
    controls = {}
    for f in sorted(glob.glob(os.path.join(d, "*.yaml"))):
        if os.path.basename(f) == "index.yaml":
            continue
        doc = yaml.safe_load(open(f)) or {}
        for c in doc.get("controls", []):
            controls[c["id"]] = c
    return controls


def main():
    cat = json.load(open(CATALOG))
    corpus = load_corpus(CORPUS_DIR)
    if not corpus:
        sys.exit("no corpus controls loaded from %s" % CORPUS_DIR)

    # preserve any curated discovery_query, keyed by objective id
    old_dq = {}
    for ctl in cat["controls"].values():
        for o in ctl.get("objectives", []):
            if o.get("discovery_query"):
                old_dq[o["id"]] = o["discovery_query"]

    total_obj = 0
    stmt_changes = []
    missing_in_corpus = []
    for cid, ctl in cat["controls"].items():
        cc = corpus.get(cid)
        if not cc:
            missing_in_corpus.append(cid)
            total_obj += len(ctl.get("objectives", []))
            continue
        new_objs = []
        for o in cc.get("objectives", []):
            oid = o["ref"]
            txt = (o.get("text") or "").rstrip(".") + "."
            new_objs.append({"id": oid, "text": txt,
                             "discovery_query": old_dq.get(oid) or _discovery(txt)})
        ctl["objectives"] = new_objs
        total_obj += len(new_objs)
        corp_stmt = (cc.get("statement") or "").strip()
        cat_stmt = (ctl.get("control") or "").strip()
        if corp_stmt and corp_stmt != cat_stmt:
            stmt_changes.append((cid, cat_stmt, corp_stmt))
            ctl["control"] = corp_stmt

    cat["_meta"]["objectives"] = total_obj
    cat["_meta"]["objectives_source"] = \
        "verified NIST SP 800-171A Rev 2 corpus (320 objectives), verbatim-checked"
    cat["_meta"]["provenance"] = (
        "Control statements and assessment objectives reconciled to the verified NIST SP 800-171 "
        "Rev 2 / 800-171A corpus (320 objectives; source prismpath-grc/frameworks/nist-800-171r2). "
        "DoD SPRS weights (dod_am_weight) remain PROVISIONAL and must be verified against the "
        "official DoD Assessment Methodology before any SPRS submission.")
    json.dump(cat, open(CATALOG, "w"), indent=1)

    print(json.dumps({"controls": len(cat["controls"]), "objectives": total_obj,
                      "statement_changes": len(stmt_changes),
                      "controls_missing_in_corpus": missing_in_corpus}, indent=1))
    for cid, old, new in stmt_changes:
        print("  stmt %s:\n    - %s\n    + %s" % (cid, old, new))


if __name__ == "__main__":
    main()
