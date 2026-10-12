-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import FQ.Syntax
import Mathlib.Data.Rat.Floor
import Mathlib.Tactic
/-!
# The conversion lemma (SPEC.md section 4.5)

A `fixed` field carries a source value `x` as the integer `scale * x` settled by its rounding mode,
and a policy compares that integer with thresholds the parser lowered from decimals, `k` standing for
`k / scale`. This file proves the lemma section 4.5 states as its target: floor carries `>=` and `<`
exactly, ceiling carries `>` and `<=`, and an exact conversion carries every comparison. It then lifts
the lemma from one comparison to whole conditions and to the first match route of a policy, which is
what rule 4 of section 4.5 relies on when it accepts a policy.

Source values are rationals. A JSON number written in decimal is one, which is why the shared
conversion reads decimal text exactly and refuses a binary double with a fractional part; the theorem
below is about that exact value. The implementations (`field_definitions.canonical_value`, its Rust
twin) are held to these semantics by the frozen conversion vectors, not by this proof.
-/

namespace FQ.Conversion

open FQ

/-- How a source value between two grid points becomes canonical. -/
inductive Rounding where
  | floor | ceiling | exact
  deriving DecidableEq, Repr

/-- The comparisons a rounding mode carries exactly (SPEC section 4.5, rule 4). Each set is closed
under negation, so `not` needs no rule of its own. -/
def carries : Rounding → Op → Bool
  | .floor, .ge | .floor, .lt => true
  | .ceiling, .gt | .ceiling, .le => true
  | .exact, _ => true
  | _, _ => false

/-- The canonical integer of a source value at a scale, or `none` when the exact mode refuses it as off
the grid. -/
def convert (rounding : Rounding) (scale : ℕ) (x : ℚ) : Option ℤ :=
  match rounding with
  | .floor => some ⌊(scale : ℚ) * x⌋
  | .ceiling => some ⌈(scale : ℚ) * x⌉
  | .exact => if ((scale : ℚ) * x).den = 1 then some ((scale : ℚ) * x).num else none

/-- A comparison of the source value with the authored threshold, in exact arithmetic. -/
def srcCmp (x : ℚ) (op : Op) (t : ℚ) : Bool :=
  match op with
  | .lt => decide (x < t)
  | .le => decide (x ≤ t)
  | .gt => decide (x > t)
  | .ge => decide (x ≥ t)
  | .eq => decide (x = t)
  | .ne => decide (x ≠ t)

theorem exact_value {scale : ℕ} {x : ℚ} {n : ℤ} (hn : convert .exact scale x = some n) :
    (n : ℚ) = (scale : ℚ) * x := by
  simp only [convert] at hn
  split at hn
  · rename_i hden
    simp only [Option.some.injEq] at hn
    subst hn
    exact (Rat.den_eq_one_iff _).mp hden
  · simp at hn

/-- **The conversion lemma.** For a positive integer scale, an integer threshold `k`, and a rational
source value, a comparison the rounding mode carries decides on the canonical integer exactly as the
same comparison decides on the source value against `k / scale`. -/
theorem convert_preserves (rounding : Rounding) {scale : ℕ} (hscale : 0 < scale) (x : ℚ) (op : Op)
    (k : ℤ) {n : ℤ} (hcarries : carries rounding op = true) (hn : convert rounding scale x = some n) :
    cmpVal (.int n) op (.int k) = srcCmp x op ((k : ℚ) / scale) := by
  have hs : (0 : ℚ) < scale := by exact_mod_cast hscale
  cases rounding with
  | floor =>
    simp only [convert, Option.some.injEq] at hn
    subst hn
    cases op <;> simp [carries] at hcarries
    · -- lt: ⌊s x⌋ < k ↔ s x < k ↔ x < k / s
      simp only [cmpVal, srcCmp, decide_eq_decide]
      rw [Int.floor_lt, lt_div_iff₀ hs, mul_comm]
    · -- ge: k ≤ ⌊s x⌋ ↔ k ≤ s x ↔ k / s ≤ x
      simp only [cmpVal, srcCmp, decide_eq_decide, ge_iff_le]
      rw [Int.le_floor, div_le_iff₀ hs, mul_comm]
  | ceiling =>
    simp only [convert, Option.some.injEq] at hn
    subst hn
    cases op <;> simp [carries] at hcarries
    · -- le: ⌈s x⌉ ≤ k ↔ s x ≤ k ↔ x ≤ k / s
      simp only [cmpVal, srcCmp, decide_eq_decide]
      rw [Int.ceil_le, le_div_iff₀ hs, mul_comm]
    · -- gt: k < ⌈s x⌉ ↔ k < s x ↔ k / s < x
      simp only [cmpVal, srcCmp, decide_eq_decide, gt_iff_lt]
      rw [Int.lt_ceil, div_lt_iff₀ hs, mul_comm]
  | exact =>
    have hv := exact_value hn
    have hlt : (n < k) ↔ x < (k : ℚ) / scale := by
      rw [lt_div_iff₀ hs, mul_comm, ← hv]; exact_mod_cast Iff.rfl
    have hle : (n ≤ k) ↔ x ≤ (k : ℚ) / scale := by
      rw [le_div_iff₀ hs, mul_comm, ← hv]; exact_mod_cast Iff.rfl
    have hgt : (k < n) ↔ (k : ℚ) / scale < x := by
      rw [div_lt_iff₀ hs, mul_comm, ← hv]; exact_mod_cast Iff.rfl
    have hge : (k ≤ n) ↔ (k : ℚ) / scale ≤ x := by
      rw [div_le_iff₀ hs, mul_comm, ← hv]; exact_mod_cast Iff.rfl
    have heq : (n = k) ↔ x = (k : ℚ) / scale := by
      rw [eq_div_iff (ne_of_gt hs), mul_comm, ← hv]; exact_mod_cast Iff.rfl
    cases op <;> rw [Bool.eq_iff_iff] <;> simp [cmpVal, srcCmp, valEq, hlt, hle, hgt, hge, heq]

/-! ## From one comparison to a policy -/

/-- A condition over fixed fields only: comparisons with integer thresholds, each one carried by its
field's rounding mode, under `and`, `or` and `not`. This is the shape rule 4 accepts on fixed fields. -/
def FixedCond (rounding : String → Rounding) : Cond → Prop
  | .cmp f op (.int _) => carries (rounding f) op = true
  | .and a b => FixedCond rounding a ∧ FixedCond rounding b
  | .or a b => FixedCond rounding a ∧ FixedCond rounding b
  | .not a => FixedCond rounding a
  | .tt => True
  | _ => False

/-- The condition read against source values and authored thresholds `k / scale`. -/
def evalSrc (scale : String → ℕ) (xs : String → ℚ) : Cond → Bool
  | .cmp f op (.int k) => srcCmp (xs f) op ((k : ℚ) / scale f)
  | .and a b => evalSrc scale xs a && evalSrc scale xs b
  | .or a b => evalSrc scale xs a || evalSrc scale xs b
  | .not a => !(evalSrc scale xs a)
  | .tt => true
  | _ => false

/-- Every field the condition compares carries, in the canonical reading, the conversion of its
source value. -/
def Converted (rounding : String → Rounding) (scale : String → ℕ) (xs : String → ℚ) (canon : Reading) :
    Cond → Prop
  | .cmp f _ _ => ∃ n, convert (rounding f) (scale f) (xs f) = some n ∧ canon f = .int n
  | .and a b => Converted rounding scale xs canon a ∧ Converted rounding scale xs canon b
  | .or a b => Converted rounding scale xs canon a ∧ Converted rounding scale xs canon b
  | .not a => Converted rounding scale xs canon a
  | _ => True

/-- A fixed condition decides on the canonical reading as it decides on the source values. -/
theorem fixed_condition_preserved (rounding : String → Rounding) (scale : String → ℕ)
    (hscale : ∀ f, 0 < scale f) (xs : String → ℚ) (canon : Reading) :
    ∀ c : Cond, FixedCond rounding c → Converted rounding scale xs canon c →
      evalCond canon c = evalSrc scale xs c := by
  intro c
  induction c with
  | cmp f op k =>
    intro hfix hconv
    cases k with
    | int k =>
      obtain ⟨n, hn, hcanon⟩ := hconv
      simp only [evalCond, evalSrc, hcanon]
      exact convert_preserves (rounding f) (hscale f) (xs f) op k hfix hn
    | bool _ => exact absurd hfix (by simp [FixedCond])
    | str _ => exact absurd hfix (by simp [FixedCond])
  | mem _ _ => intro hfix; exact absurd hfix (by simp [FixedCond])
  | nmem _ _ => intro hfix; exact absurd hfix (by simp [FixedCond])
  | truthy _ => intro hfix; exact absurd hfix (by simp [FixedCond])
  | and a b iha ihb =>
    intro hfix hconv
    simp only [evalCond, evalSrc, iha hfix.1 hconv.1, ihb hfix.2 hconv.2]
  | or a b iha ihb =>
    intro hfix hconv
    simp only [evalCond, evalSrc, iha hfix.1 hconv.1, ihb hfix.2 hconv.2]
  | not a ih =>
    intro hfix hconv
    simp only [evalCond, evalSrc, ih hfix hconv]
  | tt => intro _ _; rfl

/-- The first match route of a policy read against source values. -/
def routeSrc {Action : Type} (scale : String → ℕ) (xs : String → ℚ) (p : Policy Action) : Option Action :=
  match p.find? (fun rule => evalSrc scale xs rule.cond) with
  | some rule => some rule.act
  | none => none

/-- **Conversion preserves decisions.** A policy every rule of which is a fixed condition routes the
canonical reading exactly as it routes the source values against the authored thresholds. -/
theorem fixed_policy_preserved {Action : Type} (rounding : String → Rounding) (scale : String → ℕ)
    (hscale : ∀ f, 0 < scale f) (xs : String → ℚ) (canon : Reading) (p : Policy Action)
    (hfix : ∀ rule ∈ p, FixedCond rounding rule.cond)
    (hconv : ∀ rule ∈ p, Converted rounding scale xs canon rule.cond) :
    route p canon = routeSrc scale xs p := by
  unfold route routeSrc
  rw [List.find?_congr (fun rule hrule =>
    fixed_condition_preserved rounding scale hscale xs canon rule.cond (hfix rule hrule) (hconv rule hrule))]
  rfl

/-- Equality and the other comparisons floor does not carry fail: a value strictly between two grid
points lands on the lower one, so `== k` holds on the canonical integer while the source value is not
`k / scale`. The witness: scale 10, source 0.15, threshold 1. -/
example : convert .floor 10 (3 / 20) = some 1 ∧ srcCmp (3 / 20) .eq ((1 : ℤ) / (10 : ℕ) : ℚ) = false := by
  refine ⟨?_, ?_⟩ <;> norm_num [convert, srcCmp]

end FQ.Conversion
