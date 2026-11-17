# Regulatory mapping of PrismPath evidence

*Maintainer reference, checked 2026-11-16. Data: `docs/standards/crosswalks/`. Referee: `prismpath/tests/test_regulatory_mapping.py`.*

PrismPath is not a compliance product and does not make a system compliant. It produces evidence about the decisions a governed system makes and about the policy that made them. This page says which provisions and controls each piece of evidence supports and, for each, what it does not satisfy on its own. Nothing here is legal advice or an assessment. A provider, deployer or assessor decides what the evidence is worth for a given system.

## The evidence

Nine kinds of evidence are mapped, defined in `docs/standards/taxonomies/evidence_items.json`.

| Evidence | What it is |
|---|---|
| receipt | The per decision record with its policy version, time and cause byte, a leaf of the audit log's Merkle tree |
| root-statement | A log's Merkle root signed with the deployment's instance key and chained to the one before |
| signed-policy-image | The compiled policy and its signed manifest, verified before it can decide |
| policy-attestation | The host's record that the verified policy image is in force, with the pack SBOM |
| rollback-refusal | The refusal of an older signed policy image or flow manifest, with its cause and audit event |
| escalation-to-person | A decision handed to a person and not run, recorded with its escalation cause |
| cause-code | The registered reason a decision refused, parked or escalated |
| mission-control-audit-log | The console's append only log of intent and result events for control actions |
| anchor | An optional third party timestamp of a root statement |

## EU AI Act, Regulation (EU) 2024/1689

Articles 12, 14 and 15 are requirements on high-risk AI systems, Article 19 binds their providers and Article 26 binds their deployers. A system that is not high-risk has none of these duties under the Act. Regulation (EU) 2026/1744, the Digital Omnibus on AI, moved the date of application of Sections 1 to 3 of Chapter III, which hold all five articles, to 2 December 2027 for systems classified as high-risk under Annex III and to 2 August 2028 for those under Annex I. Article 50 transparency was not moved and has applied since 2 August 2026. The articles are paraphrased in `docs/standards/taxonomies/eu_ai_act.json`.

| Evidence | Provisions | Supports | Does not satisfy on its own |
|---|---|---|---|
| receipt | 12(1), 12(2)(a) to (c), 19(1), 26(6) | An automatically generated event record with the cause and policy version | Logging of the AI system's wider operation, a retention period of at least six months, or the provider's choice of events for its intended purpose |
| root-statement | 12(1), 19(1), 26(6) | Offline check that kept logs were not removed or rewritten | Any requirement. The articles do not ask for tamper evidence, so this goes beyond them |
| signed-policy-image | 15(1), 15(5) | A measure against alteration of how the system behaves through its policy | Attacks on data, model, inputs or outputs, and the accuracy declarations of 15(3) |
| policy-attestation | 12(2)(a), 15(5) | Tying each receipt to the policy in force | The judgment whether a change is a substantial modification |
| rollback-refusal | 15(5) | Refusing a replayed older signed policy | Resilience to faults under 15(4) |
| escalation-to-person | 14(1), 14(4)(d), 14(4)(e) | A decision point that waits for a person, and a stop of an agent or lineage | The person's interface, training, awareness of automation bias (14(4)(b)) and assignment (26(2)), and a stop for the whole system |
| cause-code | 12(2)(a), 15(4) | A machine readable reason on each refusal or escalation | A risk assessment under Article 79(1) |
| mission-control-audit-log | 12(2)(a), 26(5) | A record of changes to the governing policy and a way to read decisions | The AI system's own log. The actor is a console interface and session, not an identified person |
| anchor | none | Nothing the articles ask for | Not applicable |

## NIST AI RMF 1.0

`prismpath_evidence__nist_ai_rmf.json` reuses the existing AI governance catalog and its crosswalk to the AI RMF. Where an edge names `via_ai_governance`, it repeats every subcategory that `adapters/compliance/crosswalks/ai_governance__nist_ai_rmf.json` reaches from those controls, and the referee checks that. The receipt edge is linked to AI-GOV MS-1 and GV-1, the escalation edge to GV-1 and MG-2, the cause edge to MG-2 and the root statement edge to MS-1. The other subcategories (MEASURE 2.4, MEASURE 2.7, MAP 3.5, MANAGE 2.4) are added here, and the maintainer reviewed and kept them on 2026-11-16. The AI RMF is voluntary and its subcategories describe organizational practice, so each edge says what stays with the organization.

## NIST AI 600-1

`prismpath_evidence__nist_ai_600_1.json` maps to three of the twelve risks and leaves the others to the model and its data, where a decision layer has no part. Information Security (2.9) and Value Chain and Component Integration (2.12) are served by the signed policy image, the rollback refusal, the receipts and the cause codes. Human-AI Configuration (2.7) is served by escalation to a person. The suggested actions of the profile are not mapped, so no claim is made against them.

## NIST SP 800-53 Rev 5, AU and SI families

`prismpath_evidence__nist_800_53_r5.json` is limited to the AU and SI families. The receipt, root statement and Mission Control audit log support AU-2, AU-3, AU-5, AU-6, AU-9, AU-10 and AU-12 in part. The signed policy image, attestation and rollback refusal support SI-6, SI-7 and its enhancements, SI-10 and SI-17. The cause code supports AU-3, AU-6, SI-4 and SI-11. An anchor supports AU-8 for a root statement and not for every record. The escalation to a person has no AU or SI control. Three limits recur. The instance key lives on the deployment, so a party who controls the deployment controls what it signs. The console's actor is an interface and session and not a person. PrismPath sets no retention period, so AU-11 is not mapped.

## Reading the data

The crosswalks use the shape of `adapters/compliance/crosswalks/` (`id`, `a`, `b`, `complete`, `authority`, `edges` with `a` and `b`) and add a `rationale` or a `none` reason, a `does_not_satisfy` statement on every edge and a `pinned` list of the data they cite. They are all `complete: false`. They are not fed to the propagation engine in `adapters/compliance/crosswalk.py`, because an edge here says what evidence bears on a provision and not that a control is met. Every id they name is checked against the pinned lists in `docs/standards/taxonomies/`. The cause code to OWASP, ATLAS and CWE mapping is a separate file, `docs/standards/cause-crosswalk.json`, described in `docs/standards/README.md`.

## Not verified

The text of Articles 12, 14, 15, 19 and 26 was read in the Regulation as published and is paraphrased, so any use that needs the words should read the Official Journal. NIST AI RMF subcategory ids come from the existing adapter source list and were not re-fetched. The AI RMF subcategories added here, the nearest fit ATLAS and CWE choices the crosswalk marks as such, and the 800-53 judgments about partial support were reviewed by the maintainer on 2026-11-16 and have had no outside review.
