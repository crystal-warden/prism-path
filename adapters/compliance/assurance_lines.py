#!/usr/bin/env python3
"""Three-lines-of-defense assurance — the Assurance & Enablement layer of the GRC Alignment Model.

Traditional assurance has each line test the same controls independently: the first line (control owners)
attests, the second line (risk and compliance) re-checks, the third line (internal audit) tests again, and
the governing body reconciles conflicting conclusions. That is the "assurance fatigue" the model names.

Integrated assurance replaces it with ONE signed, replayable determination per control that serves every
line through a role-appropriate view of the SAME evidence. Tested once, assured across the lines, with
independence preserved precisely because the evidence is cryptographically signed and independently
verifiable — the third line verifies the receipt rather than re-running the test. This module makes that
concrete: it assigns each control's assurance across the four lines and quantifies the de-duplication.
"""
import compliance_adapter as _ca

_OWNER = {"technical": "System / Security Administrator", "procedural": "ISSM / Policy Owner",
          "operational": "Operations / Process Owner", "general": "ISSM"}


def _first_line_owner(control):
    return _OWNER.get(_ca._method_profile(control), "ISSM")


def assurance_for_control(control_id, verdict, signed=False, standard=None):
    """How one control's single determination is assured across all four lines from the same evidence."""
    if standard:
        _ca.use_standard(standard)
    control = _ca.get_control(control_id)
    third = ("independently verifies the signed, replayable receipt (no re-test needed)" if signed
             else "must re-test, because there is no signed receipt to verify")
    return {
        "control_id": control_id, "title": control["title"], "verdict": verdict, "signed": signed,
        "shared_evidence": ("one signed determination" if signed else "one determination"),
        "lines": [
            {"line": "first_line", "name": "First Line (Management / Control Owner)",
             "owner": _first_line_owner(control),
             "responsibility": "owns and operates the control; attests the determination"},
            {"line": "second_line", "name": "Second Line (Risk & Compliance)",
             "responsibility": "monitors the determination and aggregates the posture; sets policy"},
            {"line": "third_line", "name": "Third Line (Independent Internal Audit)",
             "responsibility": third},
            {"line": "governing_body", "name": "Governing Body / Board",
             "responsibility": "receives the rolled-up posture and risk-appetite status for oversight"},
        ],
    }


# The three assurance lines that would each independently test a control in the traditional model.
_TESTING_LINES = 3


def assurance_summary(n_controls, n_signed):
    """The de-duplication integrated assurance buys: one determination per control serves all three lines
    instead of each line testing every control."""
    traditional = n_controls * _TESTING_LINES
    integrated = n_controls
    return {"controls": n_controls, "signed_determinations": n_signed,
            "traditional_line_assessments": traditional, "integrated_assessments": integrated,
            "assessments_deduplicated": traditional - integrated,
            "reduction": ("%d%%" % round(100 * (traditional - integrated) / traditional) if traditional else "0%"),
            "note": "One signed determination per control serves the first, second, and third lines and the "
                    "governing body. The traditional model re-tests each control per line (assurance "
                    "fatigue). Independence is preserved because the third line verifies the signed receipt "
                    "rather than re-testing, and the evidence is cryptographically checkable."}


def demo(use_llm=False):
    import unified as _un
    import posture_connector as _pc
    _ca.use_standard("nist_800171_r2")
    posture = _pc.load_sample("example_host")
    req_base = {"facts": posture.get("facts", {}), "boundary": posture.get("boundary")}
    controls = _ca._catalog()["controls"]
    verdict_311 = _un.full_determination(_ca.get_control("3.1.1"), dict(req_base, control_id="3.1.1"))["status"]
    n = len(controls)
    return {"summary": assurance_summary(n, n),                       # every determination signed
            "example_control": assurance_for_control("3.1.1", verdict_311, signed=True)}


def render_text(d):
    s, c = d["summary"], d["example_control"]
    L = ["Three-lines-of-defense assurance:"]
    L.append("  %d controls -> %d signed determinations serve all 3 lines + the board"
             % (s["controls"], s["signed_determinations"]))
    L.append("  traditional (each line tests each control): %d assessments;  integrated: %d;  %s fewer"
             % (s["traditional_line_assessments"], s["integrated_assessments"], s["reduction"]))
    L.append("")
    L.append("  %s (%s) — verdict %s, %s:" % (c["control_id"], c["title"][:44], c["verdict"], c["shared_evidence"]))
    for ln in c["lines"]:
        who = ("  [%s]" % ln["owner"]) if ln.get("owner") else ""
        L.append("    %-42s %s%s" % (ln["name"], ln["responsibility"], who))
    return "\n".join(L)


if __name__ == "__main__":
    print(render_text(demo()))
