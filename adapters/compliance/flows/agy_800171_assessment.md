---
name: agy_800171_assessment
start: ingest_request
---

## ingest_request
Observe and ingest the control assessment request, including the control ID and tenant evidence bundle scoped to a system boundary.
-> get_criteria: always

## get_criteria
Retrieve the 800-171A assessment objectives and required assessment methods for the control.
-> check_evidence: always

## check_evidence
Check if there is any evidence provided in the bundle.
-> request_evidence: when no_evidence
-> adjudicate: else

## request_evidence
Request more evidence from the tenant to satisfy the missing objectives or methods.
-> record_gap: when visits >= 3
-> check_evidence: the tenant provided additional evidence
-> record_gap: the tenant stated they have no further evidence

## adjudicate
Review the evidence against the objectives. Determine if the evidence positively demonstrates each objective on the boundary by the required method.
-> record_met: when determination == "met"
-> record_partially_met: when determination == "partially_met"
-> record_gap: when determination == "not_met"
-> request_evidence: the evidence is insufficient to make a determination
-> record_gap: the evidence only provides intent or policy without implementation
-> record_gap: the evidence is out of scope
-> record_gap: an objective is entirely missing

## record_met
Record a met-record for the control.
-> attest: always

## record_partially_met
Record a finding and create a POA&M for the gaps where objectives were not met.
-> attest: always

## record_gap
Record a finding and create a POA&M for the control.
-> attest: always

## attest
Finalize the report and attest to the results.
