# PrismPath Texas AI Governance Pack

> **NOTICE — REVIEW ASSISTANCE ONLY, NOT VALIDATED.** This pack is a work aid for operationalizing and
> reviewing AI-governance controls. It is **not a determination of legal compliance and not legal
> advice.** Control text, statutory citations, and applicability are curated and **not fully
> validated**; verify them against the enrolled statutes and qualified legal counsel before any
> reliance or external use. Released in this state deliberately, to assist review, not to certify.

Operationalizes controls aligned to Texas AI governance law and produces evidence of how they were
applied. A content pack on the PrismPath deterministic GRC engine, not a separate product.

## Legal posture (read first)

This pack is **aligned-to, not certified-against**. It is **not legal advice** and does not determine
legal compliance. Control text, statutory citations, and applicability are **curated from primary and
authoritative secondary sources and must be verified against the enrolled statutes and legal counsel
before reliance.** It operationalizes controls and generates evidence; a lawyer, an auditor, and the
organization remain accountable for compliance.

Two statutes are in scope:

- **TRAIGA (HB 149)**, effective 2026-01-01. Broad intent-based *prohibitions* apply to nearly everyone;
  but the consumer-notice, social-scoring, and biometric provisions bind **government entities**, and the
  one affirmative private-sector disclosure duty is on **healthcare providers**. Adoption of the **NIST AI
  RMF** (or a comparable recognized standard) is a statutory **safe harbor**.
- **SB 1964**, effective 2025-09-01. Governs **Texas state/local agencies and their vendors**;
  heightened-scrutiny systems (autonomously making or controlling a consequential decision) must document
  security risks, performance, and transparency **before deployment and on every material change**.

## Why applicability is the core, not cosmetic

A control that binds a Texas agency may be **Not Applicable** to a commercial SaaS deployer. Every control
carries an `applies_to` tag over four actor types (`commercial`, `healthcare`, `government`,
`gov_vendor`). Coverage in this pack: government 20, gov_vendor 15, commercial 8, healthcare 6 (of 21),
which reflects the real statutory reach. The engine's applicability-determination writes N/A with
justification for out-of-scope controls, the same discipline used in the CMMC work, so a customer is never
graded against provisions that do not bind them.

## Mechanism routing (where the wedge lives)

Each objective declares a `mechanism` that routes it to one of the three planes:

| mechanism | plane | count | what it means |
|---|---|---|---|
| `documented` | LLM adjudication on policy | 24 | a policy/plan/assessment satisfies it |
| `operational` | control-task records | 12 | a recurring process is performed and evidenced |
| `config` | deterministic enforcement | 7 | PrismPath **enforces and evidences it at the decision boundary** |

The 24 documented + 12 operational are what any GRC tool can do. The **7 config objectives are the
differentiator**, the controls PrismPath can actually enforce and prove, not just describe:

- **TX-OVS-1[b]** the decision layer **abstains or escalates** on out-of-authorized-bounds output, so AI
  output is never the sole principal basis for a consequential decision (SB 1964's human-oversight test).
- **TX-CHG-2[a][b]** governing policy/model versions are **authorized before use** and each decision
  **carries its governing version**, so "which version governed which decisions across changes" is
  reconstructable. SB 1964 Sec. 2054.703(b) requires re-assessment on every material change; this is the
  receipt that proves the transition was governed. Most GRC tooling cannot produce it.
- **TX-PROHIB-1[b]/3[b], TX-DISC-1[b]/2[b]** prohibited-use refusal, generative guardrails, and disclosure
  actually delivered, not merely policy'd.

## Safe-harbor evidence path

`texas_ai` -> `ai_governance` -> `nist_ai_rmf` (crosswalks `texas_ai__ai_governance` +
`ai_governance__nist_ai_rmf`). Running the `ai_governance` assessment and mapping it forward evidences the
recognized-standard adoption that TRAIGA rewards with safe-harbor protection (TX-SAFE-1).

## Status

Built: the control catalog (`catalog/texas_ai.json`, 21 controls / 9 families, registered as standard
`texas_ai`), the safe-harbor crosswalk (`crosswalks/texas_ai__ai_governance.json`, all 21 mapped).

Next (in priority order):
1. **Applicability filter** in the engine: `applicable_controls(actor)` so an assessment scopes to an
   actor and writes N/A + justification for the rest. This is the pack's headline capability.
2. **Machine-checkable wiring for the 7 `config` objectives**: deterministic checks + evidence classes
   (scanned vs attested) for abstain/escalate, version authorization, and disclosure-delivery signals.
3. **Policy templates** (SOP specs): AI disclosure, human-oversight, material-change/re-evaluation,
   redress, and vendor-clause policies (several AI-gov specs already exist and are reused).
4. **Demo assessment** for a commercial deployer and for a governmental entity, showing applicability
   scoping and the config-enforced differentiators.
5. **Counsel review** of every statutory citation and applicability tag before any external use.
