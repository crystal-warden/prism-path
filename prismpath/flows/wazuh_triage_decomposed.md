---
name: wazuh_triage_decomposed
start: observe
---

<!--
Decomposed SOC triage flow — the productization of the #54/#56 result.

Replaces the single monolithic `classify` node of wazuh_triage.md with a decision GRAPH:
  signature_gate (deterministic IOC) -> route (embedder, attack-vs-benign) -> escalation-defaulted per-tactic node

Measured on 64 malicious + 48 benign (triage_corpus_v0), same inputs:
  A  single-shot classify        recall 0.844 / benign 0.938 ... 0.792
  D  this decomposed graph        recall 0.969-0.984 / benign 0.938
The win is on BOTH axes and holds when a learned embedder does the routing (no ground-truth
label): the binary attack/benign gate is 100%, fine tactic is 45% but harmless because every
attack node shares the escalation-default contract. See SUPPORTING_EVIDENCE.md rows #54/#56.

WHY it works: a flat prompt must compromise across malicious and benign; narrow nodes each tune
to their sub-population. The escalation-default contract removes the "it could be normal admin"
off-ramp that made monolithic-with-context WORSE (#1/#2/#3).
-->

## observe
Fetch the highest-priority unprocessed alert from the Wazuh indexer. Summarize what
happened: which agent, which rule fired, at what level, and any source address.
-> idle: when no_alert
-> enrich: when always

## enrich
Gather context around the alert: how many related alerts came from the same agent in the
last 24 hours, how often this exact rule has fired, and any prior history for the source
address. Produce a short context brief. NOTE: this context feeds the DETERMINISTIC gates
below (rule_level, prefilter, signatures) and the report — it is NOT injected into the
adjudication prompt. Pushing correlated context into the triage LLM measurably degrades it
(#1/#2/#3); correlation belongs here, upstream, not in the model's prompt.
-> vector_prefilter: when always

## vector_prefilter
Embed the alert and cosine-match it against the corpus of alerts already adjudicated. If it
is near-identical (similarity >= threshold) to a high-confidence prior verdict, reuse that
verdict's action and SKIP the rest. Otherwise fall through. This is the escalation-reduction
gate.
-> stage_containment: when cached_action == "contain"
-> watchlist: when cached_action == "watch"
-> benign: when cached_action == "ignore"
-> signature_gate: when always

## signature_gate
Deterministic, un-rationalizable IOC check — NO LLM. Scan the alert's command line, image,
and details for high-confidence malicious signatures: mimikatz / sekurlsa, ntds.dit /
ntdsutil / dcsync / drsuapi, LSASS memory dump (comsvcs/procdump), cleared security log
(wevtutil cl / event 1102), encoded or obfuscated PowerShell (-encodedcommand, FromBase64,
DownloadString, IEX), rubeus / kerberoast / pass-the-hash, SAM/hash dump, known C2 tooling
(Cobalt Strike, Meterpreter, PsExesvc). A hit is an immediate containment — the model never
gets a chance to reason it away. Measured: fires on 12.5% of malicious, 0 benign false
positives.
-> stage_containment: when signature_hit
-> route: when always

## route
Route the alert to an adjudication node by embedding it and cosine-matching to the learned
per-tactic centroids. The EXACT tactic need not be right — what matters is the attack-vs-benign
split, which the embedder does perfectly (100% on 64+48); a mis-tactic'd attack still lands on
an escalation-default node and still escalates. Alerts unlike any attack centroid route to
general_adjudicate.
-> adjudicate_credential_access: the technique targets credentials — LSASS, NTDS/DCSync, SAM, Kerberos tickets, cached secrets
-> adjudicate_lateral_movement: remote execution or movement — DCOM/WMI/PsExec, RDP, PowerShell Remoting, admin shares, pass-the-hash
-> adjudicate_execution: code execution — script hosts, LOLBins, scheduled tasks, service creation, wmic/mshta/rundll32
-> adjudicate_persistence: persistence — run keys, autoruns, accessibility features, WMI subscriptions, startup items, new services
-> adjudicate_privilege_escalation: privilege escalation — token or UAC abuse, named-pipe impersonation, kernel/driver or exploit
-> adjudicate_defense_evasion: defense evasion — clearing logs, disabling controls, obfuscation, masquerading, test-signing
-> adjudicate_discovery: discovery or recon — enumerating shares, users, groups, domain, systems, or network
-> adjudicate_c2_exfil: command-and-control or exfiltration — beaconing, tunneling, DNS abuse, external data transfer
-> general_adjudicate: routine operational activity or ordinary homelab noise with no attack technique — normal logons, service starts, updates, scheduled maintenance, benign administration

## adjudicate_credential_access
A credential-access detection fired. Treat it as a TRUE positive requiring action (contain or
watch) UNLESS you can cite SPECIFIC positive evidence of an authorized process. Credential
theft rarely has a benign explanation — access to LSASS, NTDS, SAM, or ticket material is
high-fidelity. Recommend ignore ONLY with concrete justification. Return a structured verdict
(threat class, active-threat, confidence, recommended action).
-> stage_containment: when recommended_action == "contain"
-> watchlist: when recommended_action == "watch"
-> benign: when recommended_action == "ignore"
-> watchlist: when always

## adjudicate_lateral_movement
A lateral-movement detection fired. Treat it as a TRUE positive requiring action UNLESS you can
cite SPECIFIC positive evidence of an authorized administrative process. "It could be normal
admin activity" is NOT sufficient — DCOM, WMI, PsExec, RDP, and PowerShell Remoting deliberately
mimic legitimate admin, so absence of obvious malice is not benignity. Recommend ignore ONLY with
concrete justification. Return a structured verdict.
-> stage_containment: when recommended_action == "contain"
-> watchlist: when recommended_action == "watch"
-> benign: when recommended_action == "ignore"
-> watchlist: when always

## adjudicate_execution
An execution detection fired. Treat it as a TRUE positive requiring action UNLESS you can cite
SPECIFIC positive evidence of an authorized process. LOLBins and script hosts are dual-use;
"could be a legitimate script" is NOT sufficient without evidence. Recommend ignore ONLY with
concrete justification. Return a structured verdict.
-> stage_containment: when recommended_action == "contain"
-> watchlist: when recommended_action == "watch"
-> benign: when recommended_action == "ignore"
-> watchlist: when always

## adjudicate_persistence
A persistence detection fired. Treat it as a TRUE positive requiring action UNLESS you can cite
SPECIFIC positive evidence of an authorized change (a known deployment, admin, or install).
Persistence mechanisms are how footholds survive reboot — weight them heavily. Recommend ignore
ONLY with concrete justification. Return a structured verdict.
-> stage_containment: when recommended_action == "contain"
-> watchlist: when recommended_action == "watch"
-> benign: when recommended_action == "ignore"
-> watchlist: when always

## adjudicate_privilege_escalation
A privilege-escalation detection fired. Treat it as a TRUE positive requiring action UNLESS you
can cite SPECIFIC positive evidence of an authorized process. Token abuse, UAC bypass, and
impersonation are rarely benign. Recommend ignore ONLY with concrete justification. Return a
structured verdict.
-> stage_containment: when recommended_action == "contain"
-> watchlist: when recommended_action == "watch"
-> benign: when recommended_action == "ignore"
-> watchlist: when always

## adjudicate_defense_evasion
A defense-evasion detection fired. Treat it as a TRUE positive requiring action UNLESS you can
cite SPECIFIC positive evidence of an authorized process. Clearing logs, disabling controls, and
masquerading are adversary behaviors with few benign analogues — weight them heavily. Recommend
ignore ONLY with concrete justification. Return a structured verdict.
-> stage_containment: when recommended_action == "contain"
-> watchlist: when recommended_action == "watch"
-> benign: when recommended_action == "ignore"
-> watchlist: when always

## adjudicate_discovery
A discovery/recon detection fired. Treat it as a signal requiring action (usually watch, contain
if aggressive or domain-wide) UNLESS you can cite SPECIFIC positive evidence of an authorized
inventory or admin task. Single benign enumerations happen; bursts or domain-admin enumeration do
not. Recommend ignore ONLY with concrete justification. Return a structured verdict.
-> stage_containment: when recommended_action == "contain"
-> watchlist: when recommended_action == "watch"
-> benign: when recommended_action == "ignore"
-> watchlist: when always

## adjudicate_c2_exfil
A command-and-control or exfiltration detection fired. Treat it as a TRUE positive requiring
action UNLESS you can cite SPECIFIC positive evidence of an authorized channel. Beaconing,
tunneling, DNS abuse, and external transfers are high-fidelity. Recommend ignore ONLY with
concrete justification. Return a structured verdict.
-> stage_containment: when recommended_action == "contain"
-> watchlist: when recommended_action == "watch"
-> benign: when recommended_action == "ignore"
-> watchlist: when always

## general_adjudicate
No attack-tactic detection matched — this routed as ordinary operational activity. Assess
whether it indicates a real security threat requiring action, or routine operational noise.
Judge in a BALANCED way — do not force escalation; routine alerts should resolve to ignore or
watch. Return a structured verdict.
-> stage_containment: when recommended_action == "contain"
-> watchlist: when recommended_action == "watch"
-> benign: when recommended_action == "ignore"
-> benign: when always

## stage_containment
Draft a containment action as an OPNsense firewall rule proposal with a full reasoning chain,
including which decision node adjudicated it. Write it to the staging directory for human
approval. NEVER apply anything to the firewall — staging the draft is the only permitted action.
-> verify_staged: when always

## verify_staged
Confirm the draft actually exists on disk, is non-empty, and carries the reasoning chain and a
PENDING approval marker. The staged file is the definition of done, not the claim.
-> report: when staged_ok
-> escalate_human: when not staged_ok

## watchlist
Record the source and rule on the watchlist so recurrence is visible, and note what escalation
would look like if it repeats.
-> report: when always

## benign
Store the pattern as benign so future triage recognizes it and alert fatigue goes down.
-> report: when always

## escalate_human
Something failed while staging the containment draft. Write an escalation note with everything
the human needs to act manually.
-> report: when always

## report
@checkpoint(unit=alert.id, proof=verdict)
Write the triage report: the alert, the upstream context, the DECISION PATH taken (signature
gate / routed tactic node / general), the verdict, and the action staged or recorded. Mark the
alert as processed. The decision path is part of the record — this is the per-node auditable
trail. Under SPRINT_LEDGER=1 it becomes one git proof-commit keyed on the alert id.
-> end: when always

## end
Cycle complete.

## idle
No unprocessed alerts at or above the minimum level. Nothing to do.
