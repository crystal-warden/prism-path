---
name: nist_800171_access_control
start: observe
---

<!--
Compliance adapter (#2) — first vertical slice. Decomposed control-assessment flow for the NIST
SP 800-171 Access Control family (3.1.x), structurally mirroring wazuh_triage_decomposed.md.

Transfers from the SOC arc:
  - per-control adjudication nodes  ≈ per-tactic nodes (#54)
  - escalation-default framing      → the auditor's burden of proof: NOT MET unless evidenced
  - retrieval of assessment objectives (800-171A) as one-directional decision CRITERIA (#58 rule)
  - determination {met, partially-met, not-met}  ≈ {contain, watch, ignore}
  - Sink = finding + POA&M; Attestation binds control-catalog hash + evidence-bundle hash (#53)

Ports (see ADAPTER_CONTRACT.md): Ingestion=control+evidence; Retrieval=objectives; Adjudicator=this
node's determination; Sink=record_poam/record_met; Attestation=@checkpoint. NO compliance vocabulary
lives in the core engine — only in this adapter.
-->

## observe
Fetch the next control-assessment request: a NIST 800-171 Access Control control id (3.1.x) and the
tenant's evidence bundle (policies, configurations, screenshots, logs, signed attestations) scoped to
the assessed system boundary.
-> idle: when no_request
-> enrich: when always

## enrich
Retrieve this control's assessment objectives and procedures (NIST SP 800-171A) and index the evidence
bundle against them. The retrieved objectives and the cited evidence feed the adjudication node as
DECISION CRITERIA, one item at a time — never as an undifferentiated context dump (the dilution rule).
-> route: when always

## route
Route to the adjudication node for this control's sub-family. The exact sub-family need not be perfect;
what matters is that every access-control request reaches an escalation-default adjudicator.
-> adjudicate_least_privilege: least privilege, authorized access, need-to-know, or account management (3.1.1, 3.1.2, 3.1.5, 3.1.6, 3.1.7)
-> adjudicate_flow_enforcement: information-flow enforcement, separation of duties, or unsuccessful-logon handling (3.1.3, 3.1.4, 3.1.8)
-> adjudicate_session_control: session lock, session termination, or concurrent-session control (3.1.10, 3.1.11)
-> adjudicate_remote_access: remote access, wireless, mobile-device, or external-system connections (3.1.12, 3.1.13, 3.1.14, 3.1.16, 3.1.18, 3.1.20)
-> general_control: the control does not fit the sub-families above — assess it directly against its retrieved objectives

## adjudicate_least_privilege
A NIST 800-171 Access Control (least-privilege) assessment. The control is **NOT MET** unless the
evidence POSITIVELY DEMONSTRATES each assessment objective, on the assessed system boundary. Intent-only
policy without implementing configuration, evidence that does not cover the boundary, or a missing
objective all mean NOT MET. Return `met` only when every objective is evidenced; `partially-met` when
some but not all are; `not-met` otherwise. Return a structured determination (status, per-objective
finding, evidence citation or gap).
-> record_met: when determination == "met"
-> record_poam: when determination == "partially-met"
-> record_poam: when determination == "not-met"
-> record_poam: when always

## adjudicate_flow_enforcement
An information-flow / separation-of-duties assessment. NOT MET unless each objective is positively
evidenced on the boundary (enforced flow controls, documented duty separation, configured logon
handling — not merely described). Recommend met / partially-met / not-met. Return a structured
determination with per-objective evidence or gap.
-> record_met: when determination == "met"
-> record_poam: when determination == "partially-met"
-> record_poam: when determination == "not-met"
-> record_poam: when always

## adjudicate_session_control
A session-control assessment (lock, termination, concurrent-session limits). NOT MET unless each
objective is demonstrated by configuration evidence covering the boundary, not policy language alone.
Recommend met / partially-met / not-met. Return a structured determination.
-> record_met: when determination == "met"
-> record_poam: when determination == "partially-met"
-> record_poam: when determination == "not-met"
-> record_poam: when always

## adjudicate_remote_access
A remote-access / external-connection assessment. NOT MET unless each objective is positively evidenced
across every in-scope access path (remote, wireless, mobile, external systems); an unassessed path = a
gap = NOT MET for that objective. Recommend met / partially-met / not-met. Return a structured
determination.
-> record_met: when determination == "met"
-> record_poam: when determination == "partially-met"
-> record_poam: when determination == "not-met"
-> record_poam: when always

## general_control
No sub-family matched. Assess directly against this control's retrieved objectives under the same
burden of proof: NOT MET unless each objective is positively evidenced on the assessed boundary.
Return a structured determination (status, per-objective finding, evidence or gap).
-> record_met: when determination == "met"
-> record_poam: when determination == "partially-met"
-> record_poam: when determination == "not-met"
-> record_poam: when always

## record_poam
Write the finding and a Plan of Action & Milestones (POA&M) entry for the gap: the control id, the
unmet or partially-met objectives, the missing or insufficient evidence, and a remediation placeholder
with a milestone date. This is the compliance sink — never assert a control met without evidence.
-> report: when always

## record_met
Record the control as MET, citing the specific evidence that satisfied each assessment objective.
-> report: when always

## report
@checkpoint(unit=control.id, proof=determination)
Write the assessment record: control id, determination, per-objective evidence citations or gaps, and
the decision path taken (which adjudication node). Bind the control-catalog hash and the evidence-bundle
hash into the Flow-Ledger so the determination is provable against the exact controls and evidence
assessed. Reaching this node means the control is fully assessed.
-> end: when always

## end
Assessment complete.

## idle
No pending control-assessment requests.
