-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import Core.Theorems
import FQ.Absence
import FQ.Conversion
/-!
# The verified core and the FQ development

The core's evaluator is a new, executable definition; the FQ development (formal/FQ) proves decision
preservation, absence and the conversion lemma about its own model of Level M. This file joins them:
the core's conditions translate into FQ's `XCond`, the core's canonical readings into FQ's
`OReading`, and the core's evaluation and first match equal FQ's `evalX` and `routeX` on the
translation. So every FQ theorem about routing holds of the policies the core accepts: two canonical
readings with the same quantization get the same route from the core (`core_quantization_preserves`,
from `FQ.absence_preservation`), the decoded reading of a canonical reading routes as the reading
(`core_reconstruct_route`, from `FQ.reconstructX_route`), and a decimal threshold the core lowers on a
`fixed` field decides on the canonical integer as the authored decimal decides on the source value
(`lowered_threshold_preserves`, from `FQ.Conversion.convert_preserves`).
-/

namespace Core.Bridge

open Core

def toOp : Core.Op → FQ.Op
  | .lt => .lt | .le => .le | .gt => .gt | .ge => .ge | .eq => .eq | .ne => .ne

def vVal : V → FQ.Value
  | .int n => .int n
  | .bool b => .bool b
  | .str s => .str s

def litVal : Lit → Option FQ.Value
  | .int n => some (.int n)
  | .bool b => some (.bool b)
  | .str s => some (.str s)
  | .none => none

/-- A core reading as FQ's reading with absence. -/
def toO (get : String → Option V) : FQ.OReading := fun f => (get f).map vVal

def cmpX (f : String) (op : Core.Op) : Lit → FQ.XCond
  | .none => match op with
    | .eq => .isNone f
    | .ne => .not (.isNone f)
    | _ => .not .tt
  | .int n => .atom (.cmp f (toOp op) (.int n))
  | .bool b => .atom (.cmp f (toOp op) (.bool b))
  | .str s => .atom (.cmp f (toOp op) (.str s))

mutual
/-- The translation of a lowered condition into FQ's conditions with absence. -/
def toX : LCond → FQ.XCond
  | .always => .tt
  | .never => .not .tt
  | .truthy f => .atom (.truthy f)
  | .cmp f op k => cmpX f op k
  | .mem f ks => .atom (.mem f (ks.filterMap litVal))
  | .nmem f ks => .atom (.nmem f (ks.filterMap litVal))
  | .not c => .not (toX c)
  | .and cs => toXAll cs
  | .or cs => toXAny cs
def toXAll : List LCond → FQ.XCond
  | [] => .tt
  | c :: cs => .and (toX c) (toXAll cs)
def toXAny : List LCond → FQ.XCond
  | [] => .not .tt
  | c :: cs => .or (toX c) (toXAny cs)
end

def toXPolicy (rules : List (Rule LCond)) : FQ.XPolicy String :=
  rules.map (fun r => { cond := toX r.cond, act := r.target })

theorem eqV_valEq (v : V) (k : Lit) (w : FQ.Value) (hk : litVal k = some w) : eqV v k = FQ.valEq (vVal v) w := by
  cases v <;> cases k <;> simp [litVal] at hk <;> subst hk <;> rfl

theorem memV_memVal (v : V) (ks : List Lit) : (ks.any (eqV v)) = FQ.memVal (vVal v) (ks.filterMap litVal) := by
  induction ks with
  | nil => rfl
  | cons k ks ih =>
    cases hk : litVal k with
    | none =>
      cases k <;> simp [litVal] at hk
      cases v <;> simp [List.filterMap_cons, litVal, eqV, ih]
    | some w =>
      simp only [List.any_cons, List.filterMap_cons, hk, FQ.memVal] at ih ⊢
      rw [eqV_valEq v k w hk, ih]

theorem cmp_agrees (get : String → Option V) (f : String) (op : Core.Op) (k : Lit) :
    cmpV (get f) op k = FQ.evalX (toO get) (cmpX f op k) := by
  cases k with
  | none =>
    cases op <;> simp [cmpX, cmpV, FQ.evalX, toO]
  | int n =>
    cases h : get f with
    | none => cases op <;> simp [cmpX, cmpV, FQ.evalX, FQ.atomX, FQ.atomFieldD, FQ.atomField, FQ.atomAbsent, toO, h, toOp]
    | some v =>
      cases v <;> cases op <;>
        simp [cmpX, cmpV, FQ.evalX, FQ.atomX, FQ.atomFieldD, FQ.atomField, FQ.atomEval, FQ.cmpVal, FQ.valEq,
          toO, h, toOp, vVal, eqV]
  | bool b =>
    cases h : get f with
    | none => cases op <;> simp [cmpX, cmpV, FQ.evalX, FQ.atomX, FQ.atomFieldD, FQ.atomField, FQ.atomAbsent, toO, h, toOp]
    | some v =>
      cases v <;> cases op <;>
        simp [cmpX, cmpV, FQ.evalX, FQ.atomX, FQ.atomFieldD, FQ.atomField, FQ.atomEval, FQ.cmpVal, FQ.valEq,
          toO, h, toOp, vVal, eqV]
  | str s =>
    cases h : get f with
    | none => cases op <;> simp [cmpX, cmpV, FQ.evalX, FQ.atomX, FQ.atomFieldD, FQ.atomField, FQ.atomAbsent, toO, h, toOp]
    | some v =>
      cases v <;> cases op <;>
        simp [cmpX, cmpV, FQ.evalX, FQ.atomX, FQ.atomFieldD, FQ.atomField, FQ.atomEval, FQ.cmpVal, FQ.valEq,
          toO, h, toOp, vVal, eqV]

mutual
/-- **The core evaluates as FQ.** On every reading, a lowered condition has the truth FQ's semantics
with absence gives its translation. -/
theorem evalC_toX (get : String → Option V) : ∀ c : LCond, evalC get c = FQ.evalX (toO get) (toX c)
  | .always => rfl
  | .never => rfl
  | .truthy f => by
    cases h : get f with
    | none => simp [evalC, toX, FQ.evalX, FQ.atomX, FQ.atomFieldD, FQ.atomField, FQ.atomAbsent, toO, h]
    | some v => cases v <;> simp [evalC, toX, FQ.evalX, FQ.atomX, FQ.atomFieldD, FQ.atomField, FQ.atomEval,
        FQ.truthyVal, toO, h, vVal, truthyV]
  | .cmp f op k => by simp only [evalC, toX]; exact cmp_agrees get f op k
  | .mem f ks => by
    cases h : get f with
    | none => simp [evalC, toX, memV, FQ.evalX, FQ.atomX, FQ.atomFieldD, FQ.atomField, FQ.atomAbsent, toO, h]
    | some v =>
      simp only [evalC, toX, memV, FQ.evalX, FQ.atomX, FQ.atomFieldD, FQ.atomField, FQ.atomEval, toO, h,
        Option.getD_some, Option.map_some]
      exact memV_memVal v ks
  | .nmem f ks => by
    cases h : get f with
    | none => simp [evalC, toX, memV, FQ.evalX, FQ.atomX, FQ.atomFieldD, FQ.atomField, FQ.atomAbsent, toO, h]
    | some v =>
      simp only [evalC, toX, memV, FQ.evalX, FQ.atomX, FQ.atomFieldD, FQ.atomField, FQ.atomEval, toO, h,
        Option.getD_some, Option.map_some]
      rw [memV_memVal v ks]
  | .not c => by simp only [evalC, toX, FQ.evalX, evalC_toX get c]
  | .and cs => by simp only [evalC, toX]; exact evalAll_toX get cs
  | .or cs => by simp only [evalC, toX]; exact evalAny_toX get cs
theorem evalAll_toX (get : String → Option V) : ∀ cs : List LCond, evalAll get cs = FQ.evalX (toO get) (toXAll cs)
  | [] => rfl
  | c :: cs => by simp only [evalAll, toXAll, FQ.evalX, evalC_toX get c, evalAll_toX get cs]
theorem evalAny_toX (get : String → Option V) : ∀ cs : List LCond, evalAny get cs = FQ.evalX (toO get) (toXAny cs)
  | [] => by simp [evalAny, toXAny, FQ.evalX]
  | c :: cs => by simp only [evalAny, toXAny, FQ.evalX, evalC_toX get c, evalAny_toX get cs]
end

/-- **The core routes as FQ.** The core's first match is FQ's `routeX` on the translated policy. -/
theorem firstMatch_eq_routeX (get : String → Option V) (rules : List (Rule LCond)) :
    firstMatch get rules = FQ.routeX (toXPolicy rules) (toO get) := by
  induction rules with
  | nil => rfl
  | cons r rs ih =>
    simp only [firstMatch, toXPolicy, List.map_cons, FQ.routeX, List.find?_cons] at ih ⊢
    rw [← evalC_toX get r.cond]
    split
    · rename_i hr; simp [hr]
    · rename_i hr
      simp only [hr]
      exact ih

/-- **Decision preservation for the core.** Two canonical readings with the same quantization (FQ's
partition with absence, built from the field kinds) get the same route from the core. -/
theorem core_quantization_preserves (rules : List (Rule LCond)) (kinds : String → FQ.Kind)
    (absentOK : String → Bool) (get get' : String → Option V)
    (hr : FQ.CanonicalX (FQ.buildX kinds (toXPolicy rules)) absentOK (toO get))
    (hr' : FQ.CanonicalX (FQ.buildX kinds (toXPolicy rules)) absentOK (toO get'))
    (h : FQ.quantizeX (FQ.buildX kinds (toXPolicy rules)) (toO get) =
         FQ.quantizeX (FQ.buildX kinds (toXPolicy rules)) (toO get')) :
    firstMatch get rules = firstMatch get' rules := by
  rw [firstMatch_eq_routeX, firstMatch_eq_routeX]
  exact FQ.absence_preservation _ kinds absentOK _ _ hr hr' h

/-- **Facet carries the core's decision.** The decoded reading of a canonical reading routes as the
reading does under the core's own evaluator. -/
theorem core_reconstruct_route (rules : List (Rule LCond)) (kinds : String → FQ.Kind)
    (absentOK : String → Bool) (get : String → Option V)
    (hr : FQ.CanonicalX (FQ.buildX kinds (toXPolicy rules)) absentOK (toO get))
    (hns : FQ.NoSentinel (FQ.buildX kinds (toXPolicy rules))) :
    FQ.routeX (toXPolicy rules)
        (FQ.reconstructX (FQ.buildX kinds (toXPolicy rules)) (FQ.quantizeX (FQ.buildX kinds (toXPolicy rules)) (toO get))) =
      firstMatch get rules := by
  rw [firstMatch_eq_routeX]
  exact FQ.reconstructX_route _ kinds absentOK _ hr hns

/-! ## Lowering and the conversion lemma -/

/-- The exact value of a decimal literal. -/
def decQ (d : Dec) : ℚ := (if d.neg then -1 else 1) * (d.digits : ℚ) * (10 : ℚ) ^ (d.expWritten - (d.fracLen : ℤ))

theorem scaled_correct (d : Dec) (s : Nat) (k : Int) (h : d.scaled s = some k) : (k : ℚ) = decQ d * s := by
  unfold Dec.scaled at h
  unfold decQ
  by_cases ht : d.expWritten - (d.fracLen : ℤ) ≥ 0
  · simp only [ht, if_true, Option.some.injEq] at h
    subst h
    have hp : ((10 : ℚ) ^ (d.expWritten - (d.fracLen : ℤ))) = (10 : ℚ) ^ (d.expWritten - (d.fracLen : ℤ)).toNat := by
      rw [← zpow_natCast, Int.toNat_of_nonneg ht]
    rw [hp]
    split <;> push_cast <;> ring
  · simp only [ht, if_false] at h
    split at h
    · rename_i hdiv
      simp only [Option.some.injEq] at h
      subst h
      set u := (-(d.expWritten - (d.fracLen : ℤ))).toNat with hu
      have hdvd : 10 ^ u ∣ d.digits * s := Nat.dvd_of_mod_eq_zero (by simpa using hdiv)
      obtain ⟨q, hq⟩ := hdvd
      have hdivq : d.digits * s / 10 ^ u = q := by
        rw [hq, Nat.mul_div_cancel_left _ (by positivity)]
      rw [hdivq]
      have hqQ : (d.digits : ℚ) * s = (10 : ℚ) ^ u * q := by exact_mod_cast hq
      have hneg : (d.expWritten - (d.fracLen : ℤ)) = -(u : ℤ) := by
        rw [hu, Int.toNat_of_nonneg (by omega)]; ring
      have hp : ((10 : ℚ) ^ (d.expWritten - (d.fracLen : ℤ))) = ((10 : ℚ) ^ u)⁻¹ := by
        rw [hneg, zpow_neg, zpow_natCast]
      have h10 : ((10 : ℚ) ^ u) ≠ 0 := by positivity
      have key : (d.digits : ℚ) * ((10 : ℚ) ^ u)⁻¹ * s = q := by
        rw [mul_right_comm, hqQ]; field_simp
      rw [hp]
      split
      · push_cast; rw [← key]; ring
      · push_cast; rw [← key]; ring
    · simp at h

def toRounding : Core.Rounding → FQ.Conversion.Rounding
  | .floor => .floor | .ceiling => .ceiling | .exact => .exact

theorem carries_agree (r : Core.Rounding) (op : Core.Op) (h : carries r (some op) = true) :
    FQ.Conversion.carries (toRounding r) (toOp op) = true := by
  cases r <;> cases op <;> simp_all [carries, FQ.Conversion.carries, toRounding, toOp]

theorem cmpV_int (n : ℤ) (op : Core.Op) (k : ℤ) :
    cmpV (some (.int n)) op (.int k) = FQ.cmpVal (.int n) (toOp op) (.int k) := by
  cases op <;> simp [cmpV, FQ.cmpVal, FQ.valEq, eqV, toOp]

/-- The facts a successful check of a decimal threshold on a fixed field establishes. -/
theorem checkCmp_dec {d : FieldDef} {op : Core.Op} {x : Dec} {l : Lit}
    (hfixed : d.kind = .fixed) (h : checkCmp d op (.dec x) = .ok l) :
    carries d.rounding (some op) = true ∧ ∃ k, x.scaled d.scale = some k ∧ l = .int k := by
  have hc : carries d.rounding (some op) = true := by
    by_contra hc
    have hf : carries d.rounding (some op) = false := by simpa using hc
    simp [checkCmp, hfixed, hf, isNumConst] at h
  refine ⟨hc, ?_⟩
  cases hs : x.scaled d.scale with
  | none => simp [checkCmp, hfixed, hc, isNumConst, lowerNum, hs] at h
  | some v =>
    refine ⟨v, rfl, ?_⟩
    by_cases hr : v < d.lo ∨ v > d.hi
    · simp [checkCmp, hfixed, hc, isNumConst, lowerNum, hs, hr] at h
    · simp [checkCmp, hfixed, hc, isNumConst, lowerNum, hs, hr, bind, Except.bind, pure, Except.pure] at h
      exact h.symm

/-- **Lowering preserves decisions.** A decimal threshold the core accepts on a `fixed` field, lowered
to the integer `k`, decides on the canonical value of any rational source value exactly as the
authored decimal decides on the source value itself (SPEC.md section 4.5, the conversion lemma, now
about the core's own lowering). -/
theorem lowered_threshold_preserves {d : FieldDef} {op : Core.Op} {x : Dec} {k : ℤ}
    (hfixed : d.kind = .fixed) (hscale : 0 < d.scale) (h : checkCmp d op (.dec x) = .ok (.int k))
    (src : ℚ) {n : ℤ} (hn : FQ.Conversion.convert (toRounding d.rounding) d.scale src = some n) :
    cmpV (some (.int n)) op (.int k) = FQ.Conversion.srcCmp src (toOp op) (decQ x) := by
  obtain ⟨hc, k', hk', hl⟩ := checkCmp_dec hfixed h
  simp only [Lit.int.injEq] at hl
  subst hl
  rw [cmpV_int, FQ.Conversion.convert_preserves (toRounding d.rounding) hscale src (toOp op) k
    (carries_agree _ _ hc) hn]
  have hs : (0 : ℚ) < d.scale := by exact_mod_cast hscale
  rw [scaled_correct x d.scale k hk', mul_div_assoc, div_self (ne_of_gt hs), mul_one]

/-! ## The policies the core accepts satisfy FQ's hypotheses -/

def kindOfDef : Core.Kind → FQ.Kind
  | .int | .fixed => .numeric
  | .bool => .boolean
  | .category => .categorical

def kindsOf (defs : List FieldDef) (g : String) : FQ.Kind :=
  match findDef defs g with
  | some d => kindOfDef d.kind
  | none => .numeric

def absentOf (defs : List FieldDef) (g : String) : Bool :=
  match findDef defs g with
  | some d => d.absentOK
  | none => false

mutual
/-- The fields a lowered condition reads. -/
def _root_.Core.LCond.reads : LCond → List String
  | .always | .never => []
  | .truthy f | .cmp f _ _ | .mem f _ | .nmem f _ => [f]
  | .not c => c.reads
  | .and cs | .or cs => readsOf cs
def readsOf : List LCond → List String
  | [] => []
  | c :: cs => c.reads ++ readsOf cs
end

theorem cmpX_fields (f : String) (op : Core.Op) (k : Lit) :
    (∀ q ∈ FQ.xAtoms (cmpX f op k), q.1 = f) ∧ (∀ g ∈ FQ.xNone (cmpX f op k), g = f) := by
  cases k with
  | none => cases op <;> simp [cmpX, FQ.xAtoms, FQ.xNone]
  | int n => simp [cmpX, FQ.xAtoms, FQ.xNone, FQ.atomField]
  | bool b => simp [cmpX, FQ.xAtoms, FQ.xNone, FQ.atomField]
  | str s => simp [cmpX, FQ.xAtoms, FQ.xNone, FQ.atomField]

mutual
theorem toX_fields : ∀ c : LCond,
    (∀ q ∈ FQ.xAtoms (toX c), q.1 ∈ c.reads) ∧ (∀ g ∈ FQ.xNone (toX c), g ∈ c.reads)
  | .always => by simp [toX, FQ.xAtoms, FQ.xNone]
  | .never => by simp [toX, FQ.xAtoms, FQ.xNone]
  | .truthy f => by simp [toX, FQ.xAtoms, FQ.xNone, FQ.atomField, LCond.reads]
  | .cmp f op k => by
    obtain ⟨h1, h2⟩ := cmpX_fields f op k
    refine ⟨fun q hq => ?_, fun g hg => ?_⟩
    · simp [LCond.reads, h1 q hq]
    · simp [LCond.reads, h2 g hg]
  | .mem f ks => by simp [toX, FQ.xAtoms, FQ.xNone, FQ.atomField, LCond.reads]
  | .nmem f ks => by simp [toX, FQ.xAtoms, FQ.xNone, FQ.atomField, LCond.reads]
  | .not c => by
    obtain ⟨h1, h2⟩ := toX_fields c
    exact ⟨fun q hq => by simpa [LCond.reads] using h1 q (by simpa [toX, FQ.xAtoms] using hq),
           fun g hg => by simpa [LCond.reads] using h2 g (by simpa [toX, FQ.xNone] using hg)⟩
  | .and cs => by
    obtain ⟨h1, h2⟩ := toXAll_fields cs
    exact ⟨fun q hq => by simpa [LCond.reads] using h1 q (by simpa [toX] using hq),
           fun g hg => by simpa [LCond.reads] using h2 g (by simpa [toX] using hg)⟩
  | .or cs => by
    obtain ⟨h1, h2⟩ := toXAny_fields cs
    exact ⟨fun q hq => by simpa [LCond.reads] using h1 q (by simpa [toX] using hq),
           fun g hg => by simpa [LCond.reads] using h2 g (by simpa [toX] using hg)⟩
theorem toXAll_fields : ∀ cs : List LCond,
    (∀ q ∈ FQ.xAtoms (toXAll cs), q.1 ∈ readsOf cs) ∧ (∀ g ∈ FQ.xNone (toXAll cs), g ∈ readsOf cs)
  | [] => by simp [toXAll, FQ.xAtoms, FQ.xNone]
  | c :: cs => by
    obtain ⟨a1, a2⟩ := toX_fields c
    obtain ⟨b1, b2⟩ := toXAll_fields cs
    refine ⟨fun q hq => ?_, fun g hg => ?_⟩
    · simp only [toXAll, FQ.xAtoms, List.mem_append] at hq
      rcases hq with hq | hq
      · exact List.mem_append_left _ (a1 q hq)
      · exact List.mem_append_right _ (b1 q hq)
    · simp only [toXAll, FQ.xNone, List.mem_append] at hg
      rcases hg with hg | hg
      · exact List.mem_append_left _ (a2 g hg)
      · exact List.mem_append_right _ (b2 g hg)
theorem toXAny_fields : ∀ cs : List LCond,
    (∀ q ∈ FQ.xAtoms (toXAny cs), q.1 ∈ readsOf cs) ∧ (∀ g ∈ FQ.xNone (toXAny cs), g ∈ readsOf cs)
  | [] => by simp [toXAny, FQ.xAtoms, FQ.xNone]
  | c :: cs => by
    obtain ⟨a1, a2⟩ := toX_fields c
    obtain ⟨b1, b2⟩ := toXAny_fields cs
    refine ⟨fun q hq => ?_, fun g hg => ?_⟩
    · simp only [toXAny, FQ.xAtoms, List.mem_append] at hq
      rcases hq with hq | hq
      · exact List.mem_append_left _ (a1 q hq)
      · exact List.mem_append_right _ (b1 q hq)
    · simp only [toXAny, FQ.xNone, List.mem_append] at hg
      rcases hg with hg | hg
      · exact List.mem_append_left _ (a2 g hg)
      · exact List.mem_append_right _ (b2 g hg)
end

theorem bind_ok {ε α β : Type} {x : Except ε α} {f : α → Except ε β} {b : β}
    (h : (x >>= f) = .ok b) : ∃ a, x = .ok a ∧ f a = .ok b := by
  cases x with
  | error e => simp [bind, Except.bind] at h
  | ok a => exact ⟨a, rfl, by simpa [bind, Except.bind] using h⟩

theorem defined_ok {defs : List FieldDef} {f : String} {d : FieldDef} (h : defined defs f = .ok d) :
    findDef defs f = some d := by
  unfold defined at h
  split at h
  · simp at h
  · split at h
    · rename_i d' hd; simp only [Except.ok.injEq] at h; subst h; exact hd
    · simp at h

mutual
/-- Lowering succeeds only when every field the result reads is defined. -/
theorem lowerCond_reads (defs : List FieldDef) : ∀ (c : Cond) (l : LCond),
    lowerCond defs c = .ok l → ∀ g ∈ l.reads, ∃ d, findDef defs g = some d
  | .always, l, h => by simp [lowerCond] at h; subst h; simp [LCond.reads]
  | .never, l, h => by simp [lowerCond] at h; subst h; simp [LCond.reads]
  | .truthy f, l, h => by
    simp only [lowerCond] at h
    obtain ⟨d, hd, h⟩ := bind_ok h
    obtain ⟨_, _, h⟩ := bind_ok h
    simp only [pure, Except.pure, Except.ok.injEq] at h; subst h
    intro g hg; simp [LCond.reads] at hg; subst hg; exact ⟨d, defined_ok hd⟩
  | .cmp f op k, l, h => by
    simp only [lowerCond] at h
    obtain ⟨d, hd, h⟩ := bind_ok h
    obtain ⟨_, _, h⟩ := bind_ok h
    simp only [pure, Except.pure, Except.ok.injEq] at h; subst h
    intro g hg; simp [LCond.reads] at hg; subst hg; exact ⟨d, defined_ok hd⟩
  | .mem f ks, l, h => by
    simp only [lowerCond] at h
    obtain ⟨d, hd, h⟩ := bind_ok h
    obtain ⟨_, _, h⟩ := bind_ok h
    simp only [pure, Except.pure, Except.ok.injEq] at h; subst h
    intro g hg; simp [LCond.reads] at hg; subst hg; exact ⟨d, defined_ok hd⟩
  | .nmem f ks, l, h => by
    simp only [lowerCond] at h
    obtain ⟨d, hd, h⟩ := bind_ok h
    obtain ⟨_, _, h⟩ := bind_ok h
    simp only [pure, Except.pure, Except.ok.injEq] at h; subst h
    intro g hg; simp [LCond.reads] at hg; subst hg; exact ⟨d, defined_ok hd⟩
  | .not c, l, h => by
    simp only [lowerCond] at h
    obtain ⟨c', hc, h⟩ := bind_ok h
    simp only [pure, Except.pure, Except.ok.injEq] at h; subst h
    intro g hg; exact lowerCond_reads defs c c' hc g (by simpa [LCond.reads] using hg)
  | .and cs, l, h => by
    simp only [lowerCond] at h
    obtain ⟨cs', hc, h⟩ := bind_ok h
    simp only [pure, Except.pure, Except.ok.injEq] at h; subst h
    intro g hg; exact lowerConds_reads defs cs cs' hc g (by simpa [LCond.reads] using hg)
  | .or cs, l, h => by
    simp only [lowerCond] at h
    obtain ⟨cs', hc, h⟩ := bind_ok h
    simp only [pure, Except.pure, Except.ok.injEq] at h; subst h
    intro g hg; exact lowerConds_reads defs cs cs' hc g (by simpa [LCond.reads] using hg)
theorem lowerConds_reads (defs : List FieldDef) : ∀ (cs : List Cond) (ls : List LCond),
    lowerConds defs cs = .ok ls → ∀ g ∈ readsOf ls, ∃ d, findDef defs g = some d
  | [], ls, h => by simp [lowerConds] at h; subst h; simp [readsOf]
  | c :: cs, ls, h => by
    simp only [lowerConds] at h
    obtain ⟨c', hc, h⟩ := bind_ok h
    obtain ⟨cs', hcs, h⟩ := bind_ok h
    simp only [pure, Except.pure, Except.ok.injEq] at h; subst h
    intro g hg
    simp only [readsOf, List.mem_append] at hg
    rcases hg with hg | hg
    · exact lowerCond_reads defs c c' hc g hg
    · exact lowerConds_reads defs cs cs' hcs g hg
end

theorem lowerRules_reads (defs : List FieldDef) : ∀ (rs : List (Rule Cond)) (rs' : List (Rule LCond)),
    lowerRules defs rs = .ok rs' → ∀ r ∈ rs', ∀ g ∈ r.cond.reads, ∃ d, findDef defs g = some d
  | [], rs', h => by simp [lowerRules] at h; subst h; simp
  | r :: rs, rs', h => by
    simp only [lowerRules] at h
    obtain ⟨c, hc, h⟩ := bind_ok h
    obtain ⟨rest, hrest, h⟩ := bind_ok h
    simp only [pure, Except.pure, Except.ok.injEq] at h; subst h
    intro q hq g hg
    rcases List.mem_cons.mp hq with rfl | hq
    · exact lowerCond_reads defs _ c hc g hg
    · exact lowerRules_reads defs rs rest hrest q hq g hg

theorem loadPolicy_reads {doc : Except DocErr J} {p : Checked} (hp : loadPolicy doc = .ok p) :
    ∀ r ∈ p.rules, ∀ g ∈ r.cond.reads, ∃ d, findDef p.defs g = some d := by
  unfold loadPolicy at hp
  split at hp
  · simp at hp
  · obtain ⟨img, _, hp⟩ := bind_ok hp
    unfold checkImage at hp
    obtain ⟨defs, _, hp⟩ := bind_ok hp
    obtain ⟨rules, hrules, hp⟩ := bind_ok hp
    obtain ⟨_, _, hp⟩ := bind_ok hp
    simp only [pure, Except.pure, Except.ok.injEq] at hp
    subst hp
    exact lowerRules_reads defs _ rules hrules

theorem findDef_mem {defs : List FieldDef} {g : String} {d : FieldDef} (h : findDef defs g = some d) :
    d ∈ defs ∧ d.name = g := by
  unfold findDef at h
  exact ⟨List.mem_of_find?_eq_some h, by simpa using List.find?_some h⟩

theorem acceptField_ok {d : FieldDef} {o : Option J} {v : Option V} (h : acceptField d o = .ok v) :
    (v = none → d.absentOK = true) ∧ ∀ w, v = some w →
      (d.kind = .bool ∧ ∃ b, w = .bool b) ∨ (d.kind = .category ∧ ∃ s, w = .str s) ∨
      ((d.kind = .int ∨ d.kind = .fixed) ∧ ∃ n, w = .int n) := by
  cases o with
  | none =>
    by_cases ha : d.absentOK = true
    · simp [acceptField, ha] at h; subst h; simp [ha]
    · simp [acceptField, ha] at h
  | some j =>
    cases j with
    | null =>
      by_cases ha : d.absentOK = true
      · simp [acceptField, ha] at h; subst h; simp [ha]
      · simp [acceptField, ha] at h
    | bool b => cases hk : d.kind <;> simp [acceptField, hk] at h <;> subst h <;> simp
    | str s => cases hk : d.kind <;> simp [acceptField, hk] at h <;> subst h <;> simp
    | int n =>
      cases hk : d.kind <;> simp [acceptField, hk] at h
      all_goals (split at h <;> simp at h; subst h; simp)
    | arr xs => cases hk : d.kind <;> simp [acceptField, hk] at h
    | obj ms => cases hk : d.kind <;> simp [acceptField, hk] at h

/-- **The core's acceptance is FQ's canonical reading.** For every policy the core accepts and every
reading the core's boundary accepts, the reading is canonical in FQ's sense for the partitions of the
policy, with kinds and absence taken from the policy's own definitions. -/
theorem boundary_canonical {doc : Except DocErr J} {p : Checked} (hp : loadPolicy doc = .ok p)
    {ms : List (String × J)} (hb : firstRefused ms p.defs = none) :
    FQ.CanonicalX (FQ.buildX (kindsOf p.defs) (toXPolicy p.rules)) (absentOf p.defs)
      (toO (canonicalGet p.defs ms)) := by
  intro q hq
  obtain ⟨g, hg, rfl⟩ := List.mem_map.mp hq
  -- the field is read by some rule, so it is defined
  have hread : ∃ r ∈ p.rules, g ∈ r.cond.reads := by
    unfold FQ.xPolicyFields at hg
    rw [List.mem_dedup, List.mem_append] at hg
    rcases hg with hg | hg
    · obtain ⟨⟨g', a⟩, hmem, rfl⟩ := List.mem_map.mp hg
      unfold FQ.xPolicyAtoms toXPolicy at hmem
      obtain ⟨xr, hxr, hin⟩ := List.mem_flatMap.mp hmem
      obtain ⟨r, hr, rfl⟩ := List.mem_map.mp hxr
      exact ⟨r, hr, (toX_fields r.cond).1 _ hin⟩
    · obtain ⟨xr, hxr, hin⟩ := List.mem_flatMap.mp hg
      unfold toXPolicy at hxr
      obtain ⟨r, hr, rfl⟩ := List.mem_map.mp hxr
      exact ⟨r, hr, (toX_fields r.cond).2 _ hin⟩
  obtain ⟨r, hr, hgr⟩ := hread
  obtain ⟨d, hd⟩ := loadPolicy_reads hp r hr g hgr
  obtain ⟨hdmem, hdname⟩ := findDef_mem hd
  obtain ⟨v, hv⟩ := firstRefused_none hb d hdmem
  rw [hdname] at hv
  have hget : canonicalGet p.defs ms g = v := by simp [canonicalGet, hd, hv]
  rw [FQ.definedPartition_field]
  simp only [toO, hget, kindsOf, absentOf, hd]
  obtain ⟨hnone, hsome⟩ := acceptField_ok hv
  cases v with
  | none => simpa using hnone rfl
  | some w =>
    rcases hsome w rfl with ⟨hk, b, rfl⟩ | ⟨hk, s, rfl⟩ | ⟨hk, n, rfl⟩
    · simp [hk, kindOfDef, FQ.definedPartition, FQ.HasKind, vVal]
    · simp [hk, kindOfDef, FQ.definedPartition, FQ.HasKind, vVal]
    · rcases hk with hk | hk <;> simp [hk, kindOfDef, FQ.definedPartition, FQ.HasKind, vVal]

/-- **Decision preservation, end to end.** Under any policy the core accepts, two readings the core's
boundary accepts whose Facet quantization is equal get the same verdict from the core. -/
theorem accepted_quantization_preserves {doc : Except DocErr J} {p : Checked} (hp : loadPolicy doc = .ok p)
    {ms ms' : List (String × J)} (hb : firstRefused ms p.defs = none) (hb' : firstRefused ms' p.defs = none)
    (hq : FQ.quantizeX (FQ.buildX (kindsOf p.defs) (toXPolicy p.rules)) (toO (canonicalGet p.defs ms)) =
          FQ.quantizeX (FQ.buildX (kindsOf p.defs) (toXPolicy p.rules)) (toO (canonicalGet p.defs ms'))) :
    verdict doc (.ok (.obj ms)) = verdict doc (.ok (.obj ms')) := by
  have hm := core_quantization_preserves p.rules (kindsOf p.defs) (absentOf p.defs) _ _
    (boundary_canonical hp hb) (boundary_canonical hp hb') hq
  simp [verdict, hp, decideReading, hb, hb', hm]

end Core.Bridge
