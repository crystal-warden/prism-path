"""Adjudicator method-depth: each control is classified to an assessment-method profile (matching the
generic flow's routing), and the profile's evidence guidance is injected into the adjudication prompt."""
import pytest
import compliance_adapter as ca


@pytest.mark.parametrize("family_name,expected", [
    ("Access Control", "technical"),
    ("Audit and Accountability", "technical"),
    ("Configuration Management", "technical"),
    ("Identification and Authentication", "technical"),
    ("System and Communications Protection", "technical"),
    ("System and Comms Protection", "technical"),
    ("System and Information Integrity", "technical"),
    ("Media Protection", "technical"),
    ("Awareness and Training", "procedural"),
    ("Personnel Security", "procedural"),
    ("Planning", "procedural"),
    ("System and Services Acquisition", "procedural"),
    ("Supply Chain Risk Management", "procedural"),
    ("Risk Assessment", "procedural"),
    ("Incident Response", "operational"),
    ("Maintenance", "operational"),
    ("Physical Protection", "operational"),
    ("Security Assessment", "operational"),
    ("Security Assessment and Monitoring", "operational"),
    ("Totally Unmapped Family", "general"),
])
def test_profile_by_family_name(family_name, expected):
    assert ca._method_profile({"family_name": family_name}) == expected


def test_risk_vs_security_assessment_not_confused():
    # both contain 'assessment' but must route to different profiles
    assert ca._method_profile({"family_name": "Risk Assessment"}) == "procedural"
    assert ca._method_profile({"family_name": "Security Assessment"}) == "operational"


@pytest.mark.parametrize("std", ["nist_800171_r2", "nist_800171_r3"])
def test_full_catalog_has_no_general_leak(std):
    ca.use_standard(std)
    generals = [cid for cid, c in ca._catalog()["controls"].items()
                if ca._method_profile({"id": cid, **c}) == "general"]
    assert generals == [], generals                            # every real family maps to a real profile


@pytest.mark.parametrize("cid,expected", [
    ("3.1.1", "technical"), ("3.6.1", "operational"), ("3.11.1", "procedural"), ("3.12.1", "operational")])
def test_real_r2_controls_classify(cid, expected):
    ca.use_standard("nist_800171_r2")
    assert ca._method_profile(ca.get_control(cid)) == expected


def test_prompt_injects_profile_guidance_and_methods(monkeypatch):
    """adjudicate() builds a profile-specific prompt — capture it without hitting gemma."""
    captured = {}

    def fake_gemma(prompt, schema, name, concise=False):
        captured["prompt"] = prompt
        return {"status": "not-met", "unmet_objective_ids": [], "gap_summary": "x"}

    monkeypatch.setattr(ca, "_gemma", fake_gemma)
    ca.use_standard("nist_800171_r2")
    ca.adjudicate(ca.get_control("3.1.5"), {"control_id": "3.1.5", "boundary": "b", "evidence": []})
    assert "EXAMINING and TESTING enforcing configuration" in captured["prompt"]   # technical profile
    assert "assessment methods for this control:" in captured["prompt"]


def test_prompt_profile_differs_by_family(monkeypatch):
    captured = {}
    monkeypatch.setattr(ca, "_gemma", lambda p, s, n, concise=False: captured.__setitem__("p", p) or
                        {"status": "met", "unmet_objective_ids": [], "gap_summary": "x"})
    ca.use_standard("nist_800171_r2")
    ca.adjudicate(ca.get_control("3.9.1"), {"control_id": "3.9.1", "boundary": "b", "evidence": []})  # PS procedural
    assert "INTERVIEWING personnel" in captured["p"]
