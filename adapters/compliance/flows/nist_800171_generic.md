---
name: nist_800171_generic
start: observe
---

<!--
Compliance adapter (#2) — family-agnostic assessment flow. Supersedes the AC-only slice
(nist_800171_access_control.md) so the playbook matches the catalog's full breadth: all 14 families of
NIST SP 800-171 Rev 2 (and all 17 of Rev 3). The engine is catalog-agnostic — adjudicate() draws each
control's objectives + assessment methods from the ACTIVE catalog (use_standard), so this one flow
covers every family under whichever revision the assessor selected.

Decomposition (per the #54 thesis): route by the ASSESSMENT-METHOD PROFILE the family demands, not by an
arbitrary control grouping. 800-171A assesses each objective by Examine / Interview / Test; families
differ in which methods carry the burden of proof. Routing by that profile gives each adjudicator the
right evidence lens instead of one monolithic prompt.

Ports (see ADAPTER_CONTRACT.md): Ingestion=control+evidence; Retrieval=objectives+methods from the active
catalog; Adjudicator=these escalation-default nodes; Sink=record_poam/record_met; Attestation=@checkpoint
binding the active standard's catalog hash + evidence-bundle hash. NO compliance vocabulary in the core.
-->

## observe
Fetch the next control-assessment request: a control id from the active NIST SP 800-171 catalog (Rev 2 or
Rev 3) and the tenant's evidence bundle (policies, configurations, screenshots, logs, interview notes,
test results, signed attestations) scoped to the assessed system boundary.
-> idle: when no_request
-> enrich: when always

## enrich
Retrieve this control's assessment objectives, procedures, and assessment methods (800-171A) from the
active catalog, and index the evidence bundle against them. The retrieved objectives and their cited
evidence feed the adjudicator as DECISION CRITERIA, one item at a time — never as an undifferentiated
context dump (the dilution rule).
-> check_evidence: when always

## check_evidence
Determine whether the bundle contains any evidence to assess against the retrieved objectives. If it is
empty, the discovery loop requests evidence rather than silently failing the control.
-> request_evidence: when no_evidence
-> route: when always

## request_evidence
Route a catalog-driven, objective-specific evidence request to the tenant for the missing objectives (the
Translation layer), then await resubmission. Bound the loop with the per-node `visits` counter so it can
never run forever: after repeated unanswered requests, record the gap.
-> record_poam: when visits > 3
-> check_evidence: the tenant provided additional evidence
-> record_poam: the tenant confirmed there is no further evidence

## route
Route by the assessment-method profile the control's family demands. The exact profile need not be
perfect; what matters is that every request reaches an escalation-default adjudicator with the right
evidence lens.
-> adjudicate_technical: the family is assessed chiefly by EXAMINING and TESTING enforcing configuration (Access Control, Audit & Accountability, Configuration Management, Identification & Authentication, System & Communications Protection, System & Information Integrity, Media Protection)
-> adjudicate_procedural: the family is assessed chiefly by EXAMINING policy and INTERVIEWING personnel (Awareness & Training, Personnel Security, Planning, Risk Assessment, System & Services Acquisition, Supply Chain Risk Management)
-> adjudicate_operational: the family is assessed by confirming a process runs IN PRACTICE via examine, interview, and test/observe (Incident Response, Maintenance, Physical Protection, Security Assessment)
-> general_control: the family does not clearly match the profiles above — assess directly against the retrieved objectives

## adjudicate_technical
A technical-configuration assessment. The control is **NOT MET** unless the evidence POSITIVELY
DEMONSTRATES each objective through enforcing configuration on the assessed boundary — examined settings
and, where the method calls for it, a test/observation confirming enforcement. Intent-only policy without
implementing configuration, evidence that does not cover the boundary, or a missing objective each mean
NOT MET. Return `met` only when every objective is evidenced, `partially-met` when some are, `not-met`
otherwise, with a per-objective finding citing the evidence or naming the gap.
-> record_met: when determination == "met"
-> record_poam: when determination == "partially-met"
-> record_poam: when determination == "not-met"
-> record_poam: when always

## adjudicate_procedural
A policy-and-process assessment. NOT MET unless each objective is evidenced by a documented, current
policy/procedure AND corroboration that it is operative (interview notes, records of execution) on the
assessed boundary — a written policy alone does not satisfy an objective that requires the process to be
performed. Return met / partially-met / not-met with a per-objective finding citing evidence or gap.
-> record_met: when determination == "met"
-> record_poam: when determination == "partially-met"
-> record_poam: when determination == "not-met"
-> record_poam: when always

## adjudicate_operational
An operational assessment: the control is satisfied only if the process is evidenced running in practice.
NOT MET unless each objective is demonstrated by examination PLUS interview and/or a test or observation
confirming the process operates on the assessed boundary (e.g. an incident-response exercise record, a
maintenance log, a physical-access observation). Documentation of intent without evidence of operation is
NOT MET. Return met / partially-met / not-met with a per-objective finding.
-> record_met: when determination == "met"
-> record_poam: when determination == "partially-met"
-> record_poam: when determination == "not-met"
-> record_poam: when always

## general_control
No method profile matched. Assess directly against this control's retrieved objectives under the same
burden of proof: NOT MET unless each objective is positively evidenced on the assessed boundary by the
assessment methods the objective calls for. Return a structured determination (status, per-objective
finding, evidence or gap).
-> record_met: when determination == "met"
-> record_poam: when determination == "partially-met"
-> record_poam: when determination == "not-met"
-> record_poam: when always

## record_poam
Write the finding and a Plan of Action & Milestones (POA&M) entry for the gap: the control id, the unmet
or partially-met objectives, the missing or insufficient evidence, and a remediation placeholder with a
milestone date. This is the compliance sink — never assert a control met without evidence.
-> report: when always

## record_met
Record the control as MET, citing the specific evidence that satisfied each assessment objective.
-> report: when always

## report
@checkpoint(unit=control.id, proof=determination)
Write the assessment record: control id, determination, per-objective evidence citations or gaps, the
active standard/revision, and the decision path taken (which adjudicator). Bind the active catalog hash
and the evidence-bundle hash into the Flow-Ledger so the determination is provable against the exact
controls and evidence assessed, under the exact revision selected.
-> end: when always

## end
Assessment complete.

## idle
No pending control-assessment requests.
