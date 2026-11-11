-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import Core.Codes
/-!
# The verified core: which cases are outside it

The flow engine's counters, `visits` and `error_count`, are not reading fields: the core is one decision
and reads none (docs/design/spec-verified-core.md, section 1), and the oracle refuses a policy whose first
problem is reading one (`policy:engine-counter`). A differential run excludes such a case from its receipts
(section 11), and it decides that with the oracle's own check of the image, `counterRefusal`, which the
producers port (`formal/diff/core_policy.py`, the Rust example's `oracle_policy`) and which the run holds
to the oracle on every image.

`counter_excluded_refused` is why the exclusion hides nothing: such an image refuses every reading with
`policy:engine-counter`, so no route and no other refusal is left out of the receipts. An image that
mentions a counter but is refused for an earlier problem is not excluded: the oracle refuses it for that
problem, and the implementation must too.
-/

namespace Core

/-! ## The engine counter exclusion -/

/-- The oracle refuses the image because a condition reads an engine counter. -/
def counterRefusal (image : ByteArray) : Bool :=
  match loadPolicy (readCanonical image) with
  | .error (.engineCounter _) => true
  | _ => false

theorem counterRefusal_iff (image : ByteArray) :
    counterRefusal image = true ↔ ∃ f, loadPolicy (readCanonical image) = .error (.engineCounter f) := by
  unfold counterRefusal
  constructor
  · intro h
    split at h
    · rename_i f hf; exact ⟨f, hf⟩
    · cases h
  · rintro ⟨f, hf⟩
    rw [hf]

/-- **The engine counter exclusion is sound.** An image the producers exclude as `engine-counter` refuses
every reading with `policy:engine-counter` (code 93): excluding it hides no route and no other refusal. -/
theorem counter_excluded_refused {image : ByteArray} (h : counterRefusal image = true) (reading : ByteArray) :
    ∃ f, verdictBytes image reading = .refuse (.policy (.engineCounter f)) := by
  obtain ⟨f, hf⟩ := (counterRefusal_iff image).1 h
  exact ⟨f, policy_refusal_refuses_all hf _⟩

end Core
