-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
/-
  FQBridge.lean -- Figueroa quantization as a sound relevance criterion and an admissible transformation.

  This is the only file in lean-governance that imports the FQ project. It connects FQ's proved
  `decision_preservation` theorem to the general theory over the policy's ACTUAL action domain, not a single
  dummy action. `Governance.lean` itself imports nothing; that separation is the point, and it is why this
  bridge is a separate file with its own dependency on FQ.

  Scope of the authority modeled here. A Level M policy routes a reading to `route p r : Option Action`, the
  action a rule selects, or `none` when no rule matches. Authored outcomes are the route targets, so an
  abstain, escalate, refuse, or deny that a policy names is an ordinary action in this domain, preserved here
  exactly as an affirmative action is. We model authority per action as a Boolean, whether the policy routes
  the reading to that action, so the action argument ranges over the policy's whole authored action domain.
  `route = none` is the engine's `stuck`, cause 36, no authored route matched, and it makes every action's
  outcome false, the fail closed reading. This captures deterministic Level M routing authorization only. It
  does not model the framework verdicts the runtime emits outside the authored node set (refuse as `stuck`,
  needs_human, max_steps, contract_violation, and the state host park codes), which are carried on the receipt
  in a separate codomain, and we do not equate `none` with any of them.

  Build (needs the FQ project's environment; see check.sh):
    lean -o Governance.olean Governance.lean
    LEAN_PATH="$(cd ../../../../../formal && lake env printenv LEAN_PATH):$(pwd)" lean FQBridge.lean
-/
import Governance
import FQ

namespace Governance.FQBridge
open FQ Governance

variable {Action : Type}

/-- The relevance criterion FQ induces: two readings are declared interchangeable when both are well typed
    against the policy's partitions and quantize identically. Well typedness of both is part of the criterion,
    matching the hypotheses of `decision_preservation`. -/
def fqR (p : Policy Action) : Reading → Reading → Prop :=
  fun s t =>
    WellTyped (buildPartitions p) s ∧ WellTyped (buildPartitions p) t
      ∧ quantize (buildPartitions p) s = quantize (buildPartitions p) t

/-- Quantize-equal well typed readings route to the same action. Direct from FQ.decision_preservation. -/
theorem fq_route_eq (p : Policy Action) {s t : Reading} (h : fqR p s t) : route p s = route p t :=
  decision_preservation p s t h.1 h.2.1 h.2.2

variable [DecidableEq Action]

/-- Per-action routing authority: whether policy `p` routes reading `sigma` to action `a`. The outcome type
    is Bool, and the action argument ranges over the policy's action domain. -/
def fqA (p : Policy Action) : Authority Reading Action Bool :=
  fun sigma a => decide (route p sigma = some a)

/-- MULTI-ACTION AUTHORITY EQUIVALENCE. Two readings the criterion relates carry the same authority outcome
    for EVERY action in the policy's action domain, not one selected action. -/
theorem fq_multi_action_equiv (p : Policy Action) {s t : Reading} (h : fqR p s t) :
    simA (fqA p) s t := by
  intro a
  have hr : route p s = route p t := fq_route_eq p h
  simp only [fqA, hr]

/-- RELEVANCE SOUNDNESS. The FQ criterion is sound in the sense of section 6.3: whenever it declares two
    readings interchangeable they carry the same authority for every action. Figueroa quantization is a sound
    relevance criterion for the routing authority, over the whole action domain. -/
theorem fq_sound (p : Policy Action) : Sound (fqA p) (fqR p) := by
  intro s t h a
  have hr : route p s = route p t := fq_route_eq p h
  simp only [fqA, hr]

/-- ADMISSIBILITY. Any transformation that preserves quantization and well typedness on a domain preserves
    the per-action authority for every action, hence is admissible for the routing authority. -/
theorem fq_admissible (p : Policy Action) (D : Domain Reading) (T : Reading → Reading)
    (hwt  : ∀ s, D s → WellTyped (buildPartitions p) s)
    (hwtT : ∀ s, D s → WellTyped (buildPartitions p) (T s))
    (hq   : ∀ s, D s → quantize (buildPartitions p) (T s) = quantize (buildPartitions p) s) :
    Admissible (fqA p) D T := by
  intro s a hs
  have hr : route p (T s) = route p s :=
    decision_preservation p (T s) s (hwtT s hs) (hwt s hs) (hq s hs)
  simp only [fqA, hr]

/-- NON-EXPANSION follows from admissibility on the Boolean per-action codomain, via the general safety
    arrow `admissible_nonexpanding`. -/
theorem fq_nonexpanding (p : Policy Action) (D : Domain Reading) (T : Reading → Reading)
    (hwt  : ∀ s, D s → WellTyped (buildPartitions p) s)
    (hwtT : ∀ s, D s → WellTyped (buildPartitions p) (T s))
    (hq   : ∀ s, D s → quantize (buildPartitions p) (T s) = quantize (buildPartitions p) s) :
    NonExpanding (fqA p) D T :=
  admissible_nonexpanding (fqA p) D T (fq_admissible p D T hwt hwtT hq)

end Governance.FQBridge
