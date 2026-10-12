-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import FQ.Reconstruct
import Mathlib.Tactic
/-!
# Contract (a): the acceptance boundary, strict

I1 and its corollary are stated over well typed readings, the model's own values. The codec does not
receive those. It receives raw JSON values, and the engine decides on them with Python's semantics
(SPEC.md section 4.2): a boolean compares numerically with a number, `3.0` equals `3`, a string never
orders against a number, null equals nothing but null. Between the two stands the acceptance function,
`quantizer.accept_value` and its Rust twin, which since October 2026 every encoder applies.

This file models the raw values, the engine's semantics on them for the Level M atoms, and the
acceptance function, and proves the strict contract: whenever acceptance accepts every field a policy
reads, the engine's route on the raw reading equals its route on the accepted reading, and therefore
(by `reconstruct_route`) equals the route of the decoded reading. Every raw reading acceptance does
not accept is refused, by construction of `accept`; the refusal lemmas at the end name the cases the
reading boundary audit found accepted before.

Scope, stated plainly. Raw numbers are rationals, which JSON decimals and binary doubles are; NaN and
the infinities have no JSON spelling and acceptance refuses them in the implementations. The policy
must be well kinded (`WellKinded`): each field is compared only with constants of its own kind, and
ordered only when numeric. A boolean constant on a numeric field, which the implementations accept and
cut at 0 or 1, is outside this theorem, as is string ordering, which Level M excludes.
-/

namespace FQ

/-- A value as a JSON reader delivers it to the decision boundary. `other` stands for a list or an
object, carrying only its truthiness. -/
inductive Raw where
  | num (q : ℚ)
  | bool (b : Bool)
  | str (s : String)
  | null
  | other (nonempty : Bool)
  deriving DecidableEq, Repr

/-! ## The engine's semantics on raw values (SPEC.md section 4.2, Level M atoms) -/

/-- The number a raw value compares as: a number, or a boolean as 0 or 1. -/
def numView : Raw → Option ℚ
  | .num q => some q
  | .bool b => some (if b then 1 else 0)
  | _ => none

def constNum : Value → Option ℚ
  | .int n => some n
  | .bool b => some (if b then 1 else 0)
  | .str _ => none

/-- Python equality of a raw value with a constant: numbers and booleans by numeric value, strings
exactly, null with nothing (a constant is never null), any other pairing unequal. -/
def rawEq (v : Raw) (c : Value) : Bool :=
  match numView v, constNum c with
  | some a, some b => decide (a = b)
  | _, _ => match v, c with
    | .str s, .str t => s == t
    | _, _ => false

/-- Python comparison of a raw value with a constant; an ordering that cannot be performed is
unsatisfied. -/
def rawCmp (v : Raw) (op : Op) (c : Value) : Bool :=
  match op with
  | .eq => rawEq v c
  | .ne => !(rawEq v c)
  | .lt => match numView v, constNum c with | some a, some b => decide (a < b) | _, _ => false
  | .le => match numView v, constNum c with | some a, some b => decide (a ≤ b) | _, _ => false
  | .gt => match numView v, constNum c with | some a, some b => decide (a > b) | _, _ => false
  | .ge => match numView v, constNum c with | some a, some b => decide (a ≥ b) | _, _ => false

def rawMem (v : Raw) (cs : List Value) : Bool := cs.any (rawEq v)

def rawTruthy : Raw → Bool
  | .num q => q != 0
  | .bool b => b
  | .str s => s != ""
  | .null => false
  | .other nonempty => nonempty

def atomRaw : Cond → Raw → Bool
  | .cmp _ op c, v => rawCmp v op c
  | .mem _ cs, v => rawMem v cs
  | .nmem _ cs, v => !(rawMem v cs)
  | .truthy _, v => rawTruthy v
  | _, _ => false

def evalRaw (r : String → Raw) : Cond → Bool
  | .cmp f op c => rawCmp (r f) op c
  | .mem f cs => rawMem (r f) cs
  | .nmem f cs => !(rawMem (r f) cs)
  | .truthy f => rawTruthy (r f)
  | .and a b => evalRaw r a && evalRaw r b
  | .or a b => evalRaw r a || evalRaw r b
  | .not a => !(evalRaw r a)
  | .tt => true

/-- The engine's first match route on a raw reading. -/
def routeRaw {Action : Type} (p : Policy Action) (r : String → Raw) : Option Action :=
  match p.find? (fun rule => evalRaw r rule.cond) with
  | some rule => some rule.act
  | none => none

/-! ## The acceptance function -/

/-- The integers every reader represents exactly; acceptance refuses a number at or beyond. -/
def safeLimit : ℚ := 2 ^ 53

/-- `accept_value`: the accepted value of a field of a kind, or `none` for a refusal. Every conversion
it makes is one the engine cannot tell apart (an integral number as its integer, a boolean on a numeric
field as 0 or 1, 0 or 1 on a boolean field as false or true); everything else is refused. -/
def accept : Kind → Raw → Option Value
  | .numeric, .num q => if q.den = 1 ∧ |q| < safeLimit then some (.int q.num) else none
  | .numeric, .bool b => some (.int (if b then 1 else 0))
  | .boolean, .bool b => some (.bool b)
  | .boolean, .num q => if q = 0 then some (.bool false) else if q = 1 then some (.bool true) else none
  | .categorical, .str s => some (.str s)
  | _, _ => none

def FieldPartition.kind : FieldPartition → Kind
  | .numeric _ _ => .numeric
  | .boolean _ => .boolean
  | .categorical _ _ => .categorical

/-- An atom compares its field only with constants of the field's kind, and orders only numbers. -/
def Fits : Kind → Cond → Prop
  | .numeric, .cmp _ _ (.int _) => True
  | .numeric, .mem _ cs => ∀ c ∈ cs, ∃ n, c = .int n
  | .numeric, .nmem _ cs => ∀ c ∈ cs, ∃ n, c = .int n
  | .boolean, .cmp _ op (.bool _) => op = .eq ∨ op = .ne
  | .boolean, .mem _ cs => ∀ c ∈ cs, ∃ b, c = .bool b
  | .boolean, .nmem _ cs => ∀ c ∈ cs, ∃ b, c = .bool b
  | .categorical, .cmp _ op (.str _) => op = .eq ∨ op = .ne
  | .categorical, .mem _ cs => ∀ c ∈ cs, ∃ s, c = .str s
  | .categorical, .nmem _ cs => ∀ c ∈ cs, ∃ s, c = .str s
  | _, .truthy _ => True
  | _, _ => False

/-! ## Each accepted value decides as the raw value -/

theorem accept_numeric {v : Raw} {w : Value} (h : accept .numeric v = some w) :
    ∃ n : ℤ, w = .int n ∧ numView v = some (n : ℚ) := by
  cases v with
  | num q =>
    simp only [accept] at h
    split at h
    · rename_i hq
      simp only [Option.some.injEq] at h
      exact ⟨q.num, h.symm, by simp [numView, (Rat.den_eq_one_iff q).mp hq.1]⟩
    · simp at h
  | bool b =>
    simp only [accept, Option.some.injEq] at h
    exact ⟨if b then 1 else 0, h.symm, by cases b <;> simp [numView]⟩
  | str _ => simp [accept] at h
  | null => simp [accept] at h
  | other _ => simp [accept] at h

theorem accept_boolean {v : Raw} {w : Value} (h : accept .boolean v = some w) :
    ∃ b : Bool, w = .bool b ∧ numView v = some (if b then 1 else 0) ∧ rawTruthy v = b := by
  cases v with
  | num q =>
    simp only [accept] at h
    split at h
    · rename_i hq; simp only [Option.some.injEq] at h
      exact ⟨false, h.symm, by simp [numView, hq], by simp [rawTruthy, hq]⟩
    · split at h
      · rename_i _ hq; simp only [Option.some.injEq] at h
        exact ⟨true, h.symm, by simp [numView, hq], by simp [rawTruthy, hq]⟩
      · simp at h
  | bool b =>
    simp only [accept, Option.some.injEq] at h
    exact ⟨b, h.symm, rfl, rfl⟩
  | str _ => simp [accept] at h
  | null => simp [accept] at h
  | other _ => simp [accept] at h

theorem accept_categorical {v : Raw} {w : Value} (h : accept .categorical v = some w) :
    ∃ s : String, w = .str s ∧ v = .str s := by
  cases v with
  | str s => simp only [accept, Option.some.injEq] at h; exact ⟨s, h.symm, rfl⟩
  | num _ => simp [accept] at h
  | bool _ => simp [accept] at h
  | null => simp [accept] at h
  | other _ => simp [accept] at h

theorem rawEq_numeric {v : Raw} {n : ℤ} (hv : numView v = some (n : ℚ)) (c : ℤ) :
    rawEq v (.int c) = valEq (.int n) (.int c) := by
  simp only [rawEq, hv, constNum, valEq]
  rw [Bool.eq_iff_iff]; simp

theorem rawEq_boolean {v : Raw} {b : Bool} (hv : numView v = some (if b then 1 else 0)) (c : Bool) :
    rawEq v (.bool c) = valEq (.bool b) (.bool c) := by
  simp only [rawEq, hv, constNum, valEq]
  cases b <;> cases c <;> simp

theorem rawEq_str (s : String) (c : Value) : rawEq (.str s) c = valEq (.str s) c := by
  cases c <;> simp [rawEq, numView, constNum, valEq]

theorem rawMem_congr {v : Raw} {w : Value} {cs : List Value} (h : ∀ c ∈ cs, rawEq v c = valEq w c) :
    rawMem v cs = memVal w cs := by
  unfold rawMem memVal
  induction cs with
  | nil => rfl
  | cons c rest ih =>
    simp only [List.any_cons, h c (by simp), ih (fun c hc => h c (by simp [hc]))]

theorem rawTruthy_numView {v : Raw} {n : ℤ} (hv : numView v = some (n : ℚ)) : rawTruthy v = (n != 0) := by
  cases v with
  | num q =>
    simp only [numView, Option.some.injEq] at hv
    subst hv
    rw [Bool.eq_iff_iff]; simp [rawTruthy]
  | bool b =>
    simp only [numView, Option.some.injEq] at hv
    have hq : ((if b then 1 else 0 : ℤ) : ℚ) = (n : ℚ) := by rw [← hv]; cases b <;> simp
    have hn : (if b then 1 else 0 : ℤ) = n := by exact_mod_cast hq
    subst hn; cases b <;> rfl
  | str _ => simp [numView] at hv
  | null => simp [numView] at hv
  | other _ => simp [numView] at hv

/-- **Acceptance is faithful.** On an atom that fits its field's kind, an accepted value decides
exactly as the raw value it was accepted from. -/
theorem accept_faithful {k : Kind} {a : Cond} (ha : Fits k a) {v : Raw} {w : Value}
    (hacc : accept k v = some w) : atomRaw a v = atomEval a w := by
  cases k with
  | numeric =>
    obtain ⟨n, rfl, hv⟩ := accept_numeric hacc
    cases a with
    | cmp f op c =>
      cases c with
      | int c =>
        cases op <;> simp [atomRaw, atomEval, rawCmp, cmpVal, rawEq_numeric hv, hv, constNum]
      | bool _ => simp [Fits] at ha
      | str _ => simp [Fits] at ha
    | mem f cs =>
      simp only [atomRaw, atomEval]
      exact rawMem_congr (fun c hc => by obtain ⟨m, rfl⟩ := ha c hc; exact rawEq_numeric hv m)
    | nmem f cs =>
      simp only [atomRaw, atomEval]
      rw [rawMem_congr (fun c hc => by obtain ⟨m, rfl⟩ := ha c hc; exact rawEq_numeric hv m)]
    | truthy f => simp only [atomRaw, atomEval, truthyVal]; exact rawTruthy_numView hv
    | and _ _ => simp [Fits] at ha
    | or _ _ => simp [Fits] at ha
    | not _ => simp [Fits] at ha
    | tt => simp [Fits] at ha
  | boolean =>
    obtain ⟨b, rfl, hv, ht⟩ := accept_boolean hacc
    cases a with
    | cmp f op c =>
      cases c with
      | bool c =>
        rcases ha with rfl | rfl <;> simp [atomRaw, atomEval, rawCmp, cmpVal, rawEq_boolean hv]
      | int _ => simp [Fits] at ha
      | str _ => simp [Fits] at ha
    | mem f cs =>
      simp only [atomRaw, atomEval]
      exact rawMem_congr (fun c hc => by obtain ⟨d, rfl⟩ := ha c hc; exact rawEq_boolean hv d)
    | nmem f cs =>
      simp only [atomRaw, atomEval]
      rw [rawMem_congr (fun c hc => by obtain ⟨d, rfl⟩ := ha c hc; exact rawEq_boolean hv d)]
    | truthy f => simp [atomRaw, atomEval, truthyVal, ht]
    | and _ _ => simp [Fits] at ha
    | or _ _ => simp [Fits] at ha
    | not _ => simp [Fits] at ha
    | tt => simp [Fits] at ha
  | categorical =>
    obtain ⟨s, rfl, rfl⟩ := accept_categorical hacc
    cases a with
    | cmp f op c => cases op <;> simp [atomRaw, atomEval, rawCmp, cmpVal, rawEq_str] <;>
        cases c <;> simp_all [Fits]
    | mem f cs => simp only [atomRaw, atomEval]; exact rawMem_congr (fun c _ => rawEq_str s c)
    | nmem f cs => simp only [atomRaw, atomEval]; rw [rawMem_congr (fun c _ => rawEq_str s c)]
    | truthy f => simp [atomRaw, atomEval, truthyVal, rawTruthy]
    | and _ _ => simp [Fits] at ha
    | or _ _ => simp [Fits] at ha
    | not _ => simp [Fits] at ha
    | tt => simp [Fits] at ha

/-! ## From atoms to the policy -/

theorem evalRaw_atom {r : String → Raw} {a : Cond} {g : String} (h : atomField a = some g) :
    evalRaw r a = atomRaw a (r g) := by
  cases a <;> simp [atomField] at h <;> subst h <;> rfl

theorem evalRaw_congr {r : String → Raw} {x : Reading} : ∀ c : Cond,
    (∀ g a, (g, a) ∈ condAtoms c → atomRaw a (r g) = atomEval a (x g)) → evalRaw r c = evalCond x c := by
  intro c
  induction c with
  | cmp f op k => intro h; rw [evalRaw_atom (g := f) rfl, evalCond_atom (g := f) rfl]; exact h f _ (by simp [condAtoms])
  | mem f cs => intro h; rw [evalRaw_atom (g := f) rfl, evalCond_atom (g := f) rfl]; exact h f _ (by simp [condAtoms])
  | nmem f cs => intro h; rw [evalRaw_atom (g := f) rfl, evalCond_atom (g := f) rfl]; exact h f _ (by simp [condAtoms])
  | truthy f => intro h; rw [evalRaw_atom (g := f) rfl, evalCond_atom (g := f) rfl]; exact h f _ (by simp [condAtoms])
  | and a b iha ihb =>
    intro h
    simp only [evalRaw, evalCond]
    rw [iha (fun g a' h' => h g a' (by simp [condAtoms, h'])), ihb (fun g a' h' => h g a' (by simp [condAtoms, h']))]
  | or a b iha ihb =>
    intro h
    simp only [evalRaw, evalCond]
    rw [iha (fun g a' h' => h g a' (by simp [condAtoms, h'])), ihb (fun g a' h' => h g a' (by simp [condAtoms, h']))]
  | not a ih => intro h; simp only [evalRaw, evalCond]; rw [ih (fun g a' h' => h g a' h')]
  | tt => intro _; rfl

/-- Every atom of the policy fits the kind its field is partitioned as. -/
def WellKinded {Action : Type} (p : Policy Action) : Prop :=
  ∀ g a, (g, a) ∈ policyAtoms p → Fits (kindOf (fieldAtoms p g)) a

/-- Acceptance accepted every field the partitions cover, to the values of `A`. -/
def Accepted (parts : List FieldPartition) (r : String → Raw) (A : Reading) : Prop :=
  ∀ q ∈ parts, accept q.kind (r q.field) = some (A q.field)

theorem kind_partitionOf (f : String) (atoms : List Cond) : (partitionOf f atoms).kind = kindOf atoms := by
  unfold partitionOf
  split <;> simp_all [FieldPartition.kind]

theorem accepted_wellTyped {parts : List FieldPartition} {r : String → Raw} {A : Reading}
    (h : Accepted parts r A) : WellTyped parts A := by
  intro q hq
  have hacc := h q hq
  cases q with
  | numeric f atoms =>
    obtain ⟨n, hn, _⟩ := accept_numeric hacc
    simp only [FieldPartition.field] at hn ⊢; rw [hn]; trivial
  | boolean f =>
    obtain ⟨b, hb, _⟩ := accept_boolean hacc
    simp only [FieldPartition.field] at hb ⊢; rw [hb]; trivial
  | categorical f cs =>
    obtain ⟨s, hs, _⟩ := accept_categorical hacc
    simp only [FieldPartition.field] at hs ⊢; rw [hs]; trivial

/-- The engine routes an accepted raw reading as it routes the accepted values. -/
theorem raw_route_eq {Action : Type} (p : Policy Action) (hk : WellKinded p) {r : String → Raw} {A : Reading}
    (hacc : Accepted (buildPartitions p) r A) : routeRaw p r = route p A := by
  have hcond : ∀ rule ∈ p, evalRaw r rule.cond = evalCond A rule.cond := by
    intro rule hrule
    apply evalRaw_congr
    intro g a hga
    have hmem : (g, a) ∈ policyAtoms p := by
      unfold policyAtoms; rw [List.mem_flatMap]; exact ⟨rule, hrule, hga⟩
    have hq := partition_mem hmem
    have h := hacc _ hq
    rw [partitionOf_field, kind_partitionOf] at h
    exact accept_faithful (hk g a hmem) h
  unfold routeRaw route
  rw [List.find?_congr hcond]
  rfl

/-- **Contract (a), strict.** For a well kinded Level M policy whose partitions name no sentinel, a raw
reading that acceptance accepts on every field the policy reads is routed by the engine exactly as the
decoded reading is: the engine on the raw values equals the engine on the reconstruction of their
Figueroa quantization. Every other raw reading is refused, by construction of `accept`. -/
theorem contract_a {Action : Type} (p : Policy Action) (hk : WellKinded p)
    (hns : NoSentinel (buildPartitions p)) {r : String → Raw} {A : Reading}
    (hacc : Accepted (buildPartitions p) r A) :
    routeRaw p r = route p (reconstruct (buildPartitions p) (quantize (buildPartitions p) A)) := by
  rw [raw_route_eq p hk hacc, reconstruct_route p A (accepted_wellTyped hacc) hns]

/-! ## The refusals the reading boundary audit found accepted before -/

/-- A string that spells a number is refused on a numeric field (acceptance corpus version 2). -/
theorem numeric_string_refused (s : String) : accept .numeric (.str s) = none := rfl

/-- A fraction is refused on a numeric field, never truncated. -/
theorem fraction_refused {q : ℚ} (h : q.den ≠ 1) : accept .numeric (.num q) = none := by
  simp [accept, h]

/-- An integer at or beyond 2^53 is refused, on every path. -/
theorem beyond_exact_refused {q : ℚ} (h : safeLimit ≤ |q|) : accept .numeric (.num q) = none := by
  simp [accept, not_lt.mpr h]

/-- A boolean field is never read by truthiness: a string or a number other than 0 and 1 is refused. -/
theorem boolean_truthiness_refused (s : String) : accept .boolean (.str s) = none := rfl
theorem boolean_two_refused : accept .boolean (.num 2) = none := by simp [accept]

/-- A number on a categorical field is refused rather than read as its string or the other cell. -/
theorem categorical_number_refused (q : ℚ) : accept .categorical (.num q) = none := rfl

/-- Absence is refused on every kind of an inferred field; a defined field carries it explicitly
(FQ.Absence). -/
theorem null_refused (k : Kind) : accept k .null = none := by cases k <;> rfl

end FQ
