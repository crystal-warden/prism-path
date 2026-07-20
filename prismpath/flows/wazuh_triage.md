---
name: wazuh_triage
start: observe
---

## observe
Fetch the highest-priority unprocessed alert from the Wazuh indexer. Summarize what
happened: which agent, which rule fired, at what level, and any source address.
-> idle: when no_alert
-> enrich: when always

## enrich
Gather context around the alert: how many related alerts came from the same agent in the
last 24 hours, how often this exact rule has fired, and any prior history for the source
address. Produce a short context brief for the analyst.
-> vector_prefilter: when always

## vector_prefilter
Embed the alert and cosine-match it against the corpus of alerts the LLM already
adjudicated. If it is near-identical (similarity >= threshold) to a high-confidence prior
verdict, reuse that verdict's action and SKIP the LLM classify entirely. Otherwise fall
through to classify. This is the escalation-reduction gate.
-> stage_containment: when cached_action == "contain"
-> watchlist: when cached_action == "watch"
-> benign: when cached_action == "ignore"
-> classify: when always

## classify
Judge the alert in its context and return a structured verdict (threat class, active-threat,
confidence 0..1, recommended action). Weigh evidence over the raw severity number.
-> stage_containment: when rule_level >= 12
-> stage_containment: when recommended_action == "contain"
-> watchlist: when recommended_action == "watch"
-> benign: when recommended_action == "ignore"
-> watchlist: when always

## stage_containment
Draft a containment action as an OPNsense firewall rule proposal with a full reasoning
chain. Write it to the staging directory for human approval. NEVER apply anything to the
firewall — staging the draft is the only permitted action.
-> verify_staged: when always

## verify_staged
Confirm the draft actually exists on disk, is non-empty, and carries the reasoning chain
and a PENDING approval marker. The staged file is the definition of done, not the claim.
-> report: when staged_ok
-> escalate_human: when not staged_ok

## watchlist
Record the source and rule on the watchlist so recurrence is visible, and note what
escalation would look like if it repeats.
-> report: when always

## benign
Store the pattern as benign so future triage recognizes it and alert fatigue goes down.
-> report: when always

## escalate_human
Something failed while staging the containment draft. Write an escalation note with
everything the human needs to act manually.
-> report: when always

## report
@checkpoint(unit=alert.id, proof=verdict)
Write the triage report: the alert, the context, the decision path taken, and the action
staged or recorded. Mark the alert as processed. Reaching this node means the alert is fully
triaged — under SPRINT_LEDGER=1 it becomes one git proof-commit keyed on the alert id.
-> end: when always

## end
Cycle complete.

## idle
No unprocessed alerts at or above the minimum level. Nothing to do.
