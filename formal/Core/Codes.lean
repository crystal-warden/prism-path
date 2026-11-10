-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import Core.Theorems
/-!
# The verified core: every refusal carries a registered cause

The registry (`prismpath/kernel/causes.py`) is generated into `Core/Causes.lean`; the core spells each
refusal with a code and a name (`Refusal.code`, `Refusal.cause`, `Core/Eval.lean`). These theorems tie
the two together, so no refusal of the core can be printed, put on a receipt or compared without a
registered code (docs/design/spec-verified-core.md, section 5):

* `refusal_registered`: every refusal's (code, name) is a row of the registry;
* `refusal_code_ne_zero`: no refusal carries 0, the code of a clean decision;
* `registry_codes_distinct`: the registry gives each code one name, so the code alone names the cause;
* `verdict_refusal_registered`: whatever the inputs, a refused verdict carries a registered, nonzero code.

Every proof is by `decide` over the generated list: a refusal whose spelling drifts from the registry,
or a registry regenerated without a row the core uses, fails the build.
-/

namespace Core

theorem policyErr_registered (e : PolicyErr) : (e.code, e.cause) ∈ causeRegistry := by
  cases e <;> simp only [PolicyErr.code, PolicyErr.cause] <;> decide

theorem refusal_registered (r : Refusal) : (r.code, r.cause) ∈ causeRegistry := by
  cases r with
  | policy e => exact policyErr_registered e
  | readingUnreadable _ => simp only [Refusal.code, Refusal.cause]; decide
  | readingNotObject => simp only [Refusal.code, Refusal.cause]; decide
  | contract _ _ => simp only [Refusal.code, Refusal.cause]; decide
  | noMatch => simp only [Refusal.code, Refusal.cause]; decide

theorem registry_codes_nonzero : ∀ x ∈ causeRegistry, x.1 ≠ 0 := by decide

theorem registry_codes_distinct : (causeRegistry.map (·.1)).Nodup := by decide

theorem refusal_code_ne_zero (r : Refusal) : r.code ≠ 0 :=
  registry_codes_nonzero _ (refusal_registered r)

/-- The registry's name for a code is the refusal's name: the code alone identifies the cause. -/
theorem refusal_name_of_code (r : Refusal) {n : String} (h : (r.code, n) ∈ causeRegistry) : n = r.cause := by
  have hr := refusal_registered r
  have key : ∀ (l : List (Nat × String)), (l.map (·.1)).Nodup → ∀ c a b, (c, a) ∈ l → (c, b) ∈ l → a = b := by
    intro l hl c a b ha hb
    induction l with
    | nil => cases ha
    | cons x xs ih =>
      simp only [List.map_cons, List.nodup_cons, List.mem_map] at hl
      rcases List.mem_cons.mp ha with ha | ha <;> rcases List.mem_cons.mp hb with hb | hb
      · rw [← ha] at hb; exact (Prod.mk.inj hb).2.symm
      · exact absurd ⟨(c, b), hb, by rw [← ha]⟩ hl.1
      · exact absurd ⟨(c, a), ha, by rw [← hb]⟩ hl.1
      · exact ih hl.2 ha hb
  exact key _ registry_codes_distinct _ _ _ h hr

/-- **Every refusal carries a registered code.** A verdict that refuses carries a nonzero code that is a
row of the cause registry, under the name the registry gives it. -/
theorem verdict_refusal_registered {image reading : Except DocErr J} {r : Refusal}
    (_h : verdict image reading = .refuse r) : r.code ≠ 0 ∧ (r.code, r.cause) ∈ causeRegistry :=
  ⟨refusal_code_ne_zero r, refusal_registered r⟩

end Core
