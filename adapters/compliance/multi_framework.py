#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Multi-framework assessment — assess the environment once, report the posture across every framework
the engine can reach.

This is the campaign thesis made concrete. One pass of the unified determination over 800-171 produces
the determinations; from those same determinations, without re-assessing, the report answers:

  * NIST SP 800-171 Rev 2 itself (the tally, the SPRS score, the FAIR risk),
  * the CMMC 2.0 level statuses (via cmmc, its own scoring rule per level), and
  * every crosswalked framework (via crosswalk, fail closed, partial coverage shown honestly).

Nothing is re-derived twice by hand and nothing is faked: a framework appears only if a mapping with a
stated authority reaches it, and a mapping that is partial says so. Add a crosswalk file and that
framework joins the report automatically.
"""
from adapters.compliance import compliance_adapter as _ca
from adapters.compliance import unified as _un
from adapters.compliance import cmmc as _cmmc
from adapters.compliance import crosswalk as _cw
from adapters.compliance import rollup as _rollup
from adapters.compliance import fair_risk as _fr


def assess_environment(posture, completions=None, as_of=None, use_llm=False):
    """Assess once against 800-171, then report across 800-171, CMMC levels, and crosswalked frameworks."""
    _ca.use_standard("nist_800171_r2")
    facts = (posture or {}).get("facts") or {}
    boundary = (posture or {}).get("boundary", "(unspecified)")
    req_base = {"facts": facts, "boundary": boundary}

    determinations = {}
    for cid in _ca._catalog()["controls"]:
        det = _un.full_determination(_ca.get_control(cid), dict(req_base, control_id=cid),
                                     completions=completions, as_of=as_of, use_llm=use_llm)
        determinations[cid] = det["status"]

    tally = {}
    for determination in determinations.values():
        tally[determination] = tally.get(determination, 0) + 1
    records = [{"control_id": control_id, "status": determination}
               for control_id, determination in determinations.items()]
    weights = _ca.catalog_weights()
    sprs = _rollup.sprs_partial(records, weights) if weights else {}
    risk = _fr.risk_register(determinations)

    cmmc_levels = [_cmmc.assess_level(lv, posture, completions, as_of, use_llm) for lv in (1, 2, 3)]

    reached = []
    for name in _cw.list_crosswalks():
        crosswalk = _cw.load_crosswalk(name)
        if "nist_800171_r2" not in (crosswalk["a"], crosswalk["b"]):
            continue
        rep = _cw.propagate(crosswalk, "nist_800171_r2", determinations)
        cov = _cw.coverage(crosswalk)
        reached.append({"framework": rep["target_framework"], "crosswalk": name,
                        "n_targets": rep["n_targets"], "tally": rep["tally"],
                        "complete": cov["complete"], "authority": cov["authority"]})

    return {
        "boundary": boundary,
        "assessed_standard": "nist_800171_r2",
        "nist_800171": {"n_controls": len(determinations), "tally": tally},
        "sprs": {"score_if_all_assessed": sprs.get("ceiling_if_unassessed_all_met"),
                 "base": sprs.get("base"), "caveat": sprs.get("caveat")},
        "fair": {"aggregate_ale": risk["aggregate_ale"]},
        "cmmc": [{"level": level["level"], "name": level["name"], "status": level["status"],
                  "sprs_score": level.get("sprs_score")} for level in cmmc_levels],
        "frameworks_reached": reached,
    }


def demo(use_llm=False):
    from adapters.compliance import posture_connector as _pc
    from adapters.compliance import control_tasks as _ct
    _ca.use_standard("nist_800171_r2")
    posture = _pc.load_sample("example_host")
    completions = [
        _ct.record_completion("ir-capability-test", "3.6.3", "2026-08-15", "ISSM", "aar.pdf"),
        _ct.record_completion("vulnerability-scan", "3.11.2", "2026-08-28", "SecOps", "scan.html"),
        _ct.record_completion("security-role-training", "3.2.2", "2026-06-01", "ISSM", "training.csv"),
    ]
    return assess_environment(posture, completions=completions, as_of="2026-09-03", use_llm=use_llm)


def render_text(posture):
    lines = ["Multi-framework posture  |  boundary: %s  |  assessed: %s"
             % (posture["boundary"], posture["assessed_standard"])]
    tally = posture["nist_800171"]["tally"]
    lines.append("  NIST 800-171 R2 : %d controls  %s" % (posture["nist_800171"]["n_controls"], tally))
    lines.append("  SPRS            : %s / %s   |   FAIR aggregate ALE: $%s"
                 % (posture["sprs"]["score_if_all_assessed"], posture["sprs"].get("base"),
                    format(posture["fair"]["aggregate_ale"]["likely"], ",")))
    for level in posture["cmmc"]:
        extra = ("  SPRS %s" % level["sprs_score"]) if level["sprs_score"] is not None else ""
        lines.append("  CMMC L%-2d %-12s: %s%s" % (level["level"], level["name"], level["status"].upper(), extra))
    for framework in posture["frameworks_reached"]:
        lines.append("  -> %-16s: %d controls reached  %s  [%s]"
                     % (framework["framework"], framework["n_targets"], framework["tally"],
                        "complete" if framework["complete"] else "partial"))
    return "\n".join(lines)


if __name__ == "__main__":
    print(render_text(demo()))
