#!/usr/bin/env python3
"""CMMC 2.0 level packaging over the NIST SP 800-171 engine.

CMMC assesses the SAME 800-171 controls; the levels change the SCOPE and the SCORING rule, not the
engine. This module expresses the three levels as views over the active Rev 2 catalog and the unified
determination, so one assessment answers "what is my CMMC status" per level without a second engine.

  Level 1 (Foundational): the 17 FAR 52.204-21 basic safeguarding practices. Annual self-assessment,
      every practice must be MET, POA&Ms are not permitted. Reported met / not-met.
  Level 2 (Advanced): all 110 Rev 2 requirements. Self or C3PAO assessment, scored with the DoD
      Assessment Methodology (SPRS, base 110). A conditional status is possible via a POA&M when the
      score clears the floor and no high-value requirement is open.
  Level 3 (Expert): Level 2 plus selected NIST SP 800-172 enhanced requirements. Requires the 800-172
      catalog, which is not yet loaded; assess_level(3) reports that dependency rather than guessing.

Every mapping here is authoritative data (control membership, the scoring threshold), flagged for
verification against the current CMMC scoping guidance and 32 CFR Part 170. Nothing is model-adjudicated:
a level status is a deterministic function of the per-control verdicts, and insufficient is scored as
not-met (fail closed), never assumed met.
"""
import compliance_adapter as _ca
import unified as _un
import rollup as _rollup

# CMMC 2.0 Level 1 = FAR 52.204-21(b)(1) basic safeguarding, expressed as NIST SP 800-171 Rev 2 control
# ids. 17 practices. Verify against the current CMMC Level 1 scoping guidance.
L1_CONTROLS = ["3.1.1", "3.1.2", "3.1.20", "3.1.22", "3.5.1", "3.5.2", "3.8.3",
               "3.10.1", "3.10.3", "3.10.4", "3.10.5", "3.13.1", "3.13.5",
               "3.14.1", "3.14.2", "3.14.4", "3.14.5"]

POAM_MIN_SCORE = 88          # of 110 (>= 80%): the conditional-status floor. Verify vs 32 CFR Part 170.
LEVEL_NAME = {1: "Foundational", 2: "Advanced", 3: "Expert"}


def _numkey(cid):
    return [int(p) for p in cid.split(".")]


def level_controls(level):
    """Control ids in scope for a CMMC level, over the active catalog (Rev 2). Level 3 returns None
    because it needs the 800-172 catalog, which assess_level handles."""
    allc = _ca._catalog()["controls"]
    if level == 1:
        missing = [c for c in L1_CONTROLS if c not in allc]
        if missing:
            raise KeyError("CMMC L1 controls absent from the active catalog: %s" % missing)
        return list(L1_CONTROLS)
    if level == 2:
        return sorted(allc, key=_numkey)
    if level == 3:
        return None
    raise ValueError("CMMC has levels 1, 2, 3; got %r" % (level,))


def _verdicts(cids, req_base, completions, as_of, use_llm):
    out = {}
    for cid in cids:
        control = _ca.get_control(cid)
        det = _un.full_determination(control, dict(req_base, control_id=cid),
                                     completions=completions, as_of=as_of, use_llm=use_llm)
        out[cid] = det["status"]
    return out


def _tally(verdicts):
    t = {"met": 0, "partially-met": 0, "not-met": 0, "insufficient": 0}
    for v in verdicts.values():
        t[v] = t.get(v, 0) + 1
    return t


def _poam(records, weights, score):
    """POA&M eligibility for a conditional CMMC L2 status: score at or above the floor, and no open
    requirement worth more than one point. 'open' is any status other than met (insufficient counts as
    not-met). The exact POA&M-ineligible set and the closeout window are verified externally."""
    open_high = sorted((r["control_id"] for r in records
                        if r["status"] != "met" and (weights.get(r["control_id"]) or 0) > 1), key=_numkey)
    eligible = score is not None and score >= POAM_MIN_SCORE and not open_high
    return {"threshold": POAM_MIN_SCORE, "score": score, "eligible": eligible,
            "blocking_high_value_controls": open_high,
            "note": "A conditional CMMC L2 status needs a self-assessment score >= %d/110 and no open "
                    "requirement worth more than 1 point. Insufficient is scored as not-met. Verify the "
                    "POA&M-ineligible set and the 180-day closeout against 32 CFR Part 170." % POAM_MIN_SCORE}


def assess_level(level, posture, completions=None, as_of=None, use_llm=False):
    """Assess one CMMC level over a scanned posture. Returns the level status, tally, and per-control
    verdicts, scored by that level's own rule. Deterministic given the verdicts."""
    if level == 3:
        return {"level": 3, "name": LEVEL_NAME[3], "assessable": False, "status": "unavailable",
                "depends_on": "nist_800172",
                "reason": "CMMC Level 3 adds selected NIST SP 800-172 enhanced requirements; the 800-172 "
                          "catalog is not yet loaded. Levels 1 and 2 are fully assessable."}
    facts = (posture or {}).get("facts") or {}
    boundary = (posture or {}).get("boundary", "(unspecified)")
    req_base = {"facts": facts, "boundary": boundary}
    cids = level_controls(level)
    verdicts = _verdicts(cids, req_base, completions, as_of, use_llm)
    tally = _tally(verdicts)
    report = {"level": level, "name": LEVEL_NAME[level], "assessable": True,
              "standard": _ca.active_standard(), "boundary": boundary,
              "in_scope": len(cids), "tally": tally,
              "controls": [{"control_id": c, "verdict": verdicts[c]} for c in cids]}
    if level == 1:
        failing = sorted((c for c, v in verdicts.items() if v != "met"), key=_numkey)
        report.update({
            "status": "met" if not failing else "not-met",
            "practices_total": len(cids), "practices_met": tally["met"], "failing_practices": failing,
            "scoring": "Annual self-assessment: every practice must be met; POA&Ms are not permitted. "
                       "Insufficient is treated as not-met."})
    else:  # level 2 = all 110
        records = [{"control_id": c, "status": v} for c, v in verdicts.items()]
        weights = _ca.catalog_weights()
        sprs = _rollup.sprs_partial(records, weights) if weights else {}
        score = sprs.get("ceiling_if_unassessed_all_met")     # all 110 assessed -> this is the exact score
        poam = _poam(records, weights, score) if weights else {"eligible": False, "note": "no weight table"}
        if tally["met"] == len(cids):
            status = "met"
        elif poam.get("eligible"):
            status = "conditional"
        else:
            status = "not-met"
        report.update({
            "status": status, "sprs_score": score, "sprs_max": sprs.get("base", 110),
            "requirements_met": tally["met"], "poam": poam,
            "scoring": "DoD Assessment Methodology (SPRS, base 110). All 110 assessed, so the score is "
                       "exact, not an optimistic ceiling. Insufficient is scored as not-met."})
    return report


def assess(posture, completions=None, as_of=None, use_llm=False, levels=(1, 2, 3)):
    """Assess the requested CMMC levels over one posture and return a combined report."""
    _ca.use_standard("nist_800171_r2")
    return {"standard": "nist_800171_r2", "boundary": (posture or {}).get("boundary", "(unspecified)"),
            "levels": [assess_level(lv, posture, completions, as_of, use_llm) for lv in levels]}


def demo(use_llm=False):
    """Assess CMMC L1/L2/L3 over the sample host posture plus a few task completions."""
    import posture_connector as _pc
    import control_tasks as _ct
    _ca.use_standard("nist_800171_r2")
    posture = _pc.load_sample("example_host")
    completions = [
        _ct.record_completion("ir-capability-test", "3.6.3", "2026-08-15", "ISSM", "aar.pdf"),
        _ct.record_completion("vulnerability-scan", "3.11.2", "2026-08-28", "SecOps", "scan.html"),
        _ct.record_completion("security-role-training", "3.2.2", "2026-06-01", "ISSM", "training.csv"),
    ]
    return assess(posture, completions=completions, as_of="2026-09-03", use_llm=use_llm)


def render_text(report):
    L = ["CMMC 2.0 assessment  |  standard: %s  |  boundary: %s" % (report["standard"], report["boundary"])]
    for lv in report["levels"]:
        if not lv.get("assessable", True):
            L.append("  L%d %-12s %-11s  requires %s" % (lv["level"], lv["name"], lv["status"], lv["depends_on"]))
        elif lv["level"] == 1:
            extra = "" if lv["status"] == "met" else "  failing: " + ", ".join(lv["failing_practices"][:6])
            L.append("  L1 %-12s %-11s  %d/%d practices met%s"
                     % (lv["name"], lv["status"].upper(), lv["practices_met"], lv["practices_total"], extra))
        else:
            L.append("  L2 %-12s %-11s  SPRS %s/%s  %d/%d met  POA&M-eligible: %s"
                     % (lv["name"], lv["status"].upper(), lv["sprs_score"], lv["sprs_max"],
                        lv["requirements_met"], lv["in_scope"], lv["poam"]["eligible"]))
    return "\n".join(L)


if __name__ == "__main__":
    print(render_text(demo()))
