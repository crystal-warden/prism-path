#!/usr/bin/env python3
"""AI-use register connector — the fact source for the AI-governance inventory controls.

Like the configuration scanners, this turns an organization's AI-use register (who uses AI, which tools
are approved, what data is entered, which vendors embed AI, and the decision impact of each use) into
machine-readable facts the deterministic checks decide. One register section, one fact, conservatively:
an absent or empty section yields a false or absent fact, never an assumed-present one, so a missing
inventory reads as not-met, not met. Fail closed is the whole point: you do not get credit for an
inventory you have not shown.

The register itself is the tenant's structured record; facts_from_register maps it to the facts, and
load_sample gives a realistic partially-mature register for the demo and tests.
"""

FACT_KEYS = [
    "ai_user_inventory_exists", "ai_process_inventory_exists", "approved_ai_tools_list_exists",
    "unapproved_ai_tool_use_controlled", "ai_data_inventory_exists", "ai_prohibited_data_controls_enforced",
    "ai_vendor_inventory_exists", "ai_decision_impact_classified", "ai_high_risk_uses_tiered",
    "ai_evidence_integrity_protected",
]


def facts_from_register(reg):
    """Map an AI-use register dict to the inventory facts. A section that is absent or empty is False
    (not demonstrated), never assumed present. Classification facts are True only when EVERY recorded
    use carries the field, so a partial inventory does not read as complete."""
    reg = reg or {}
    uses = reg.get("uses") or []

    def present(section):
        return bool(reg.get(section))

    def every_use_has(field):
        return bool(uses) and all(field in u and u[field] not in (None, "") for u in uses)

    return {
        "ai_user_inventory_exists": present("users"),
        "ai_process_inventory_exists": present("processes"),
        "approved_ai_tools_list_exists": present("approved_tools"),
        "unapproved_ai_tool_use_controlled": bool(reg.get("unapproved_tool_control_enforced")),
        "ai_data_inventory_exists": present("data_flows"),
        "ai_prohibited_data_controls_enforced": bool(reg.get("prohibited_data_controls_enforced")),
        "ai_vendor_inventory_exists": present("vendors"),
        "ai_decision_impact_classified": every_use_has("decision_impact"),
        "ai_high_risk_uses_tiered": every_use_has("risk_tier"),
        "ai_evidence_integrity_protected": bool(reg.get("evidence_signing_enabled")),
    }


# A realistic partially-mature register: inventories and approvals in place, evidence signed, but the
# prohibited-data controls and per-use risk tiering are not yet done (a common real gap).
_SAMPLE = {
    "org": "Crystal Warden Supply Chain Labs LLC",
    "users": [{"role": "analyst"}, {"role": "engineer"}, {"role": "ISSM"}],
    "processes": [{"name": "supplier performance triage"}, {"name": "document drafting"}],
    "approved_tools": [{"name": "Claude"}, {"name": "internal PrismPath governor"}],
    "unapproved_tool_control_enforced": True,
    "data_flows": [{"tool": "Claude", "data": "non-CUI supplier metrics"}],
    "prohibited_data_controls_enforced": False,                 # gap: no enforced CUI/PII block yet
    "vendors": [{"name": "Anthropic", "capability": "LLM"}],
    "uses": [
        {"name": "supplier triage", "decision_impact": "advisory", "risk_tier": "low"},
        {"name": "document drafting", "decision_impact": "none"},   # gap: no risk_tier -> tiering incomplete
    ],
    "evidence_signing_enabled": True,                           # PrismPath signs determinations already
}


def load_sample(name="example_org"):
    """A realistic AI-use register posture for the demo/tests."""
    return {"boundary": "Crystal Warden AI use (all business units)",
            "facts": facts_from_register(_SAMPLE),
            "provenance": {"source": "ai_register", "register": name}}
