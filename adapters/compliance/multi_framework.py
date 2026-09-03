#!/usr/bin/env python3
"""Multi-framework assessment — assess the environment once, report the posture across every framework
the engine can reach.

This is the campaign thesis made concrete. One pass of the unified determination over 800-171 produces
the verdicts; from those same verdicts, without re-assessing, the report answers:

  * NIST SP 800-171 Rev 2 itself (the tally, the SPRS score, the FAIR risk),
  * the CMMC 2.0 level statuses (via cmmc, its own scoring rule per level), and
  * every crosswalked framework (via crosswalk, fail closed, partial coverage shown honestly).

Nothing is re-derived twice by hand and nothing is faked: a framework appears only if a mapping with a
stated authority reaches it, and a mapping that is partial says so. Add a crosswalk file and that
framework joins the report automatically.
"""
import compliance_adapter as _ca
import unified as _un
import cmmc as _cmmc
import crosswalk as _cw
import rollup as _rollup
import fair_risk as _fr


def assess_environment(posture, completions=None, as_of=None, use_llm=False):
    """Assess once against 800-171, then report across 800-171, CMMC levels, and crosswalked frameworks."""
    _ca.use_standard("nist_800171_r2")
    facts = (posture or {}).get("facts") or {}
    boundary = (posture or {}).get("boundary", "(unspecified)")
    req_base = {"facts": facts, "boundary": boundary}

    verdicts = {}
    for cid in _ca._catalog()["controls"]:
        det = _un.full_determination(_ca.get_control(cid), dict(req_base, control_id=cid),
                                     completions=completions, as_of=as_of, use_llm=use_llm)
        verdicts[cid] = det["status"]

    tally = {}
    for v in verdicts.values():
        tally[v] = tally.get(v, 0) + 1
    records = [{"control_id": c, "status": v} for c, v in verdicts.items()]
    weights = _ca.catalog_weights()
    sprs = _rollup.sprs_partial(records, weights) if weights else {}
    risk = _fr.risk_register(verdicts)

    cmmc_levels = [_cmmc.assess_level(lv, posture, completions, as_of, use_llm) for lv in (1, 2, 3)]

    reached = []
    for name in _cw.list_crosswalks():
        x = _cw.load_crosswalk(name)
        if "nist_800171_r2" not in (x["a"], x["b"]):
            continue
        rep = _cw.propagate(x, "nist_800171_r2", verdicts)
        cov = _cw.coverage(x)
        reached.append({"framework": rep["target_framework"], "crosswalk": name,
                        "n_targets": rep["n_targets"], "tally": rep["tally"],
                        "complete": cov["complete"], "authority": cov["authority"]})

    return {
        "boundary": boundary,
        "assessed_standard": "nist_800171_r2",
        "nist_800171": {"n_controls": len(verdicts), "tally": tally},
        "sprs": {"score_if_all_assessed": sprs.get("ceiling_if_unassessed_all_met"),
                 "base": sprs.get("base"), "caveat": sprs.get("caveat")},
        "fair": {"aggregate_ale": risk["aggregate_ale"]},
        "cmmc": [{"level": l["level"], "name": l["name"], "status": l["status"],
                  "sprs_score": l.get("sprs_score")} for l in cmmc_levels],
        "frameworks_reached": reached,
    }


def demo(use_llm=False):
    import posture_connector as _pc
    import control_tasks as _ct
    _ca.use_standard("nist_800171_r2")
    posture = _pc.load_sample("example_host")
    completions = [
        _ct.record_completion("ir-capability-test", "3.6.3", "2026-08-15", "ISSM", "aar.pdf"),
        _ct.record_completion("vulnerability-scan", "3.11.2", "2026-08-28", "SecOps", "scan.html"),
        _ct.record_completion("security-role-training", "3.2.2", "2026-06-01", "ISSM", "training.csv"),
    ]
    return assess_environment(posture, completions=completions, as_of="2026-09-03", use_llm=use_llm)


def render_text(r):
    L = ["Multi-framework posture  |  boundary: %s  |  assessed: %s"
         % (r["boundary"], r["assessed_standard"])]
    t = r["nist_800171"]["tally"]
    L.append("  NIST 800-171 R2 : %d controls  %s" % (r["nist_800171"]["n_controls"], t))
    L.append("  SPRS            : %s / %s   |   FAIR aggregate ALE: $%s"
             % (r["sprs"]["score_if_all_assessed"], r["sprs"].get("base"),
                format(r["fair"]["aggregate_ale"]["likely"], ",")))
    for c in r["cmmc"]:
        extra = ("  SPRS %s" % c["sprs_score"]) if c["sprs_score"] is not None else ""
        L.append("  CMMC L%-2d %-12s: %s%s" % (c["level"], c["name"], c["status"].upper(), extra))
    for f in r["frameworks_reached"]:
        L.append("  -> %-16s: %d controls reached  %s  [%s]"
                 % (f["framework"], f["n_targets"], f["tally"], "complete" if f["complete"] else "partial"))
    return "\n".join(L)


if __name__ == "__main__":
    print(render_text(demo()))
