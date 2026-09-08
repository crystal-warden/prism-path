-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import FQ.Partition
import Mathlib.Tactic
/-!
# Theorem I1, decision preservation

Numeric core: two integers with the same canonical symbol have the same atom truth vector. The
argument: an atom's truth can change only across a fine boundary (a constant or its successor); a
boundary across which the truth vector changes is retained; the symbol counts retained boundaries at
or below the value, so equal symbols mean no retained boundary lies strictly between the two values,
and the truth vector is constant on the way from one to the other.
-/

namespace FQ

open List

/-! ## Membership plumbing -/

theorem mem_numConsts_raw {atoms : List NumAtom} {c : Int}
    (h : ∃ a ∈ atoms, (∃ op, a = .cmp op c) ∨ (∃ cs, (a = .mem cs ∨ a = .nmem cs) ∧ c ∈ cs) ∨ (a = .truthy ∧ c = 0)) :
    c ∈ atoms.foldr (fun a acc =>
      match a with
      | .cmp _ c => c :: acc
      | .mem cs  => cs ++ acc
      | .nmem cs => cs ++ acc
      | .truthy  => 0 :: acc) [] := by
  induction atoms with
  | nil => obtain ⟨a, ha, _⟩ := h; simp at ha
  | cons b rest ih =>
    obtain ⟨a, ha, hshape⟩ := h
    simp only [List.foldr_cons]
    rcases List.mem_cons.mp ha with rfl | hrest
    · rcases hshape with ⟨op, rfl⟩ | ⟨cs, hb, hc⟩ | ⟨rfl, rfl⟩
      · simp
      · rcases hb with rfl | rfl <;> simp [hc]
      · simp
    · have := ih ⟨a, hrest, hshape⟩
      cases b <;> simp [this]

theorem mem_numConsts {atoms : List NumAtom} {c : Int}
    (h : ∃ a ∈ atoms, (∃ op, a = .cmp op c) ∨ (∃ cs, (a = .mem cs ∨ a = .nmem cs) ∧ c ∈ cs) ∨ (a = .truthy ∧ c = 0)) :
    c ∈ numConsts atoms := by
  have hraw := mem_numConsts_raw h
  unfold numConsts
  generalize hR : atoms.foldr (fun a acc =>
      match a with
      | .cmp _ c => c :: acc
      | .mem cs  => cs ++ acc
      | .nmem cs => cs ++ acc
      | .truthy  => 0 :: acc) [] = raw at hraw ⊢
  have hemp : raw.isEmpty = false := by
    cases raw with
    | nil => simp at hraw
    | cons _ _ => rfl
  simp only [hemp, Bool.false_eq_true, if_false]
  rw [List.mem_eraseDups, List.mem_mergeSort]
  exact hraw

theorem mem_boundaries {consts : List Int} {c : Int} (h : c ∈ consts) :
    c ∈ boundaries consts ∧ c + 1 ∈ boundaries consts := by
  unfold boundaries
  rw [List.mem_eraseDups, List.mem_mergeSort, List.mem_eraseDups, List.mem_mergeSort]
  constructor <;> exact List.mem_flatMap.mpr ⟨c, h, by simp⟩

/-! ## Truth changes only at boundaries -/

theorem map_ne_exists {α β : Type} {f g : α → β} {l : List α} (h : l.map f ≠ l.map g) :
    ∃ a ∈ l, f a ≠ g a := by
  by_contra hc
  push Not at hc
  exact h (List.map_congr_left hc)

/-- A single atom changes truth between `k` and `k + 1` only when `k + 1` is a constant or the
successor of a constant of that atom. -/
theorem atom_step {a : NumAtom} {k : Int} (h : numAtomTrue a k ≠ numAtomTrue a (k + 1)) :
    ∃ c, ((∃ op, a = .cmp op c) ∨ (∃ cs, (a = .mem cs ∨ a = .nmem cs) ∧ c ∈ cs) ∨ (a = .truthy ∧ c = 0))
      ∧ (k + 1 = c ∨ k + 1 = c + 1) := by
  cases a with
  | cmp op c =>
    refine ⟨c, Or.inl ⟨op, rfl⟩, ?_⟩
    cases op <;> simp [numAtomTrue, cmpVal, valEq] at h <;> omega
  | mem cs =>
    simp only [numAtomTrue] at h
    have : ∃ c ∈ cs, k = c ∨ k + 1 = c := by
      by_contra hc
      push Not at hc
      apply h
      have h1 : cs.any (· == k) = false := by
        rw [List.any_eq_false]; intro c hc'; have := hc c hc'; simp; omega
      have h2 : cs.any (· == k + 1) = false := by
        rw [List.any_eq_false]; intro c hc'; have := hc c hc'; simp; omega
      rw [h1, h2]
    obtain ⟨c, hc, hk⟩ := this
    exact ⟨c, Or.inr (Or.inl ⟨cs, Or.inl rfl, hc⟩), by omega⟩
  | nmem cs =>
    simp only [numAtomTrue] at h
    have : ∃ c ∈ cs, k = c ∨ k + 1 = c := by
      by_contra hc
      push Not at hc
      apply h
      have h1 : cs.any (· == k) = false := by
        rw [List.any_eq_false]; intro c hc'; have := hc c hc'; simp; omega
      have h2 : cs.any (· == k + 1) = false := by
        rw [List.any_eq_false]; intro c hc'; have := hc c hc'; simp; omega
      rw [h1, h2]
    obtain ⟨c, hc, hk⟩ := this
    exact ⟨c, Or.inr (Or.inl ⟨cs, Or.inr rfl, hc⟩), by omega⟩
  | truthy =>
    refine ⟨0, Or.inr (Or.inr ⟨rfl, rfl⟩), ?_⟩
    by_contra hc
    apply h
    have e0 : (k != 0) = true := bne_iff_ne.mpr (by omega)
    have e1 : (k + 1 != 0) = true := bne_iff_ne.mpr (by omega)
    show (k != 0) = (k + 1 != 0)
    rw [e0, e1]

theorem truth_step {atoms : List NumAtom} {k : Int}
    (h : truthVec atoms k ≠ truthVec atoms (k + 1)) :
    k + 1 ∈ boundaries (numConsts atoms) := by
  obtain ⟨a, ha, hne⟩ := map_ne_exists h
  obtain ⟨c, hshape, hk⟩ := atom_step hne
  have hc : c ∈ numConsts atoms := mem_numConsts ⟨a, ha, hshape⟩
  obtain ⟨h1, h2⟩ := mem_boundaries hc
  rcases hk with hk | hk
  · rw [hk]; exact h1
  · have : k = c := by omega
    subst this; exact h2

theorem retained_step {atoms : List NumAtom} {k : Int}
    (h : truthVec atoms k ≠ truthVec atoms (k + 1)) :
    k + 1 ∈ retained atoms := by
  unfold retained
  rw [List.mem_filter]
  refine ⟨truth_step h, ?_⟩
  simp only [Int.add_sub_cancel, bne_iff_ne, ne_eq, decide_eq_true_eq]
  exact h

/-! ## Counting -/

theorem countP_le_mono {l : List Int} {v w : Int} (hvw : v ≤ w) :
    l.countP (· ≤ v) ≤ l.countP (· ≤ w) := by
  apply List.countP_mono_left
  intro x _ hx
  simp only [decide_eq_true_eq] at hx ⊢
  omega

theorem countP_lt_of_mem {l : List Int} {v w b : Int} (hb : b ∈ l) (hvb : v < b) (hbw : b ≤ w) :
    l.countP (· ≤ v) < l.countP (· ≤ w) := by
  have hvw : v ≤ w := by omega
  induction l with
  | nil => simp at hb
  | cons x xs ih =>
    rw [List.countP_cons, List.countP_cons]
    rcases List.mem_cons.mp hb with hbx | hx
    · rw [hbx] at hvb hbw
      have hv : ¬ (x ≤ v) := by omega
      have hmono := countP_le_mono (l := xs) hvw
      simp only [hv, hbw, decide_false, decide_true, Bool.false_eq_true, if_false, if_true]
      omega
    · have hlt := ih hx
      by_cases hxv : x ≤ v
      · have hxw : x ≤ w := by omega
        simp only [hxv, hxw, decide_true, if_true]
        omega
      · simp only [hxv, decide_false, Bool.false_eq_true, if_false]
        split_ifs <;> omega

/-! ## The numeric core -/

theorem symbolCount_mono {atoms : List NumAtom} {v w : Int} (hvw : v ≤ w) :
    symbolCount atoms v ≤ symbolCount atoms w := countP_le_mono hvw

theorem truth_const_up {atoms : List NumAtom} (v : Int) :
    ∀ w, v ≤ w → symbolCount atoms v = symbolCount atoms w → truthVec atoms v = truthVec atoms w := by
  intro w hvw
  induction w, hvw using Int.leInduction with
  | base => intro _; rfl
  | succ w hw ih =>
    intro heq
    have h1 : symbolCount atoms v ≤ symbolCount atoms w := symbolCount_mono hw
    have h2 : symbolCount atoms w ≤ symbolCount atoms (w + 1) := symbolCount_mono (by omega)
    have hvw' : symbolCount atoms v = symbolCount atoms w := by omega
    have ht := ih hvw'
    by_cases hstep : truthVec atoms w = truthVec atoms (w + 1)
    · exact ht.trans hstep
    · exfalso
      have hb := retained_step hstep
      have hlt : symbolCount atoms v < symbolCount atoms (w + 1) :=
        countP_lt_of_mem (l := retained atoms) hb (by omega) (le_refl (w + 1))
      omega

/-- Two integers with the same canonical symbol have the same atom truth vector. -/
theorem symbolCount_eq_truthVec {atoms : List NumAtom} {v w : Int}
    (h : symbolCount atoms v = symbolCount atoms w) : truthVec atoms v = truthVec atoms w := by
  rcases le_total v w with hvw | hwv
  · exact truth_const_up v w hvw h
  · exact (truth_const_up w v hwv h.symm).symm

end FQ

namespace FQ

/-! ## From symbols to atoms, per field kind -/

theorem truthVec_eq_atom {atoms : List NumAtom} {v w : Int} (h : truthVec atoms v = truthVec atoms w) :
    ∀ a ∈ atoms, numAtomTrue a v = numAtomTrue a w :=
  List.map_inj_left.mp h

theorem beq_swap {α : Type} [BEq α] [LawfulBEq α] (a b : α) : (a == b) = (b == a) := by
  by_cases h : a = b
  · subst h; rfl
  · rw [beq_eq_false_iff_ne.mpr h, beq_eq_false_iff_ne.mpr (Ne.symm h)]

theorem memVal_int (v : Int) (cs : List Value) : memVal (.int v) cs = (ints cs).any (· == v) := by
  induction cs with
  | nil => rfl
  | cons c rest ih =>
    cases c with
    | int n => simp [memVal, ints, valEq, List.any_cons] at ih ⊢; rw [ih, beq_swap]
    | bool b => simp [memVal, ints, valEq, List.any_cons] at ih ⊢; exact ih
    | str s => simp [memVal, ints, valEq, List.any_cons] at ih ⊢; exact ih

/-- On an integer value, an atom with a numeric shape evaluates as its `NumAtom`. -/
theorem atomEval_int_some {a : Cond} {na : NumAtom} (h : toNumAtom a = some na) (v : Int) :
    atomEval a (.int v) = numAtomTrue na v := by
  cases a with
  | cmp f op c =>
    cases c with
    | int n => simp [toNumAtom] at h; subst h; rfl
    | bool _ => simp [toNumAtom] at h
    | str _ => simp [toNumAtom] at h
  | mem f cs => simp [toNumAtom] at h; subst h; simp [atomEval, numAtomTrue, memVal_int]
  | nmem f cs => simp [toNumAtom] at h; subst h; simp [atomEval, numAtomTrue, memVal_int]
  | truthy f => simp [toNumAtom] at h; subst h; rfl
  | and _ _ => simp [toNumAtom] at h
  | or _ _ => simp [toNumAtom] at h
  | not _ => simp [toNumAtom] at h
  | tt => simp [toNumAtom] at h

/-- An atom with no numeric shape is constant on integer values (a cross kind comparison). -/
theorem atomEval_int_none {a : Cond} (h : toNumAtom a = none) (v w : Int) :
    atomEval a (.int v) = atomEval a (.int w) := by
  cases a with
  | cmp f op c =>
    cases c with
    | int n => simp [toNumAtom] at h
    | bool b => cases op <;> rfl
    | str s => cases op <;> rfl
  | mem f cs => simp [toNumAtom] at h
  | nmem f cs => simp [toNumAtom] at h
  | truthy f => simp [toNumAtom] at h
  | and _ _ => rfl
  | or _ _ => rfl
  | not _ => rfl
  | tt => rfl

theorem numeric_agree {atomsF : List Cond} {v w : Int}
    (h : symbolCount (atomsF.filterMap toNumAtom) v = symbolCount (atomsF.filterMap toNumAtom) w) :
    ∀ a ∈ atomsF, atomEval a (.int v) = atomEval a (.int w) := by
  intro a ha
  have ht := truthVec_eq_atom (symbolCount_eq_truthVec h)
  cases hna : toNumAtom a with
  | none => exact atomEval_int_none hna v w
  | some na =>
    have hmem : na ∈ atomsF.filterMap toNumAtom := List.mem_filterMap.mpr ⟨a, ha, hna⟩
    rw [atomEval_int_some hna, atomEval_int_some hna]
    exact ht na hmem

theorem symbolBool_inj {b b' : Bool} (h : symbolBool b = symbolBool b') : b = b' := by
  cases b <;> cases b' <;> simp [symbolBool] at h ⊢

theorem symbolCat_eq_length_iff (cs : List String) (v : String) : symbolCat cs v = cs.length ↔ v ∉ cs := by
  induction cs with
  | nil => simp [symbolCat]
  | cons c rest ih =>
    simp only [symbolCat, List.length_cons, List.mem_cons]
    by_cases hc : c = v
    · subst hc; simp
    · have hcv : (c == v) = false := by simpa using hc
      simp only [hcv, Bool.false_eq_true, if_false, Nat.add_right_cancel_iff, ih]
      constructor
      · intro hv; exact fun h => h.elim (fun h' => hc h'.symm) hv
      · intro h; exact fun hv => h (Or.inr hv)

theorem symbolCat_lt_length {cs : List String} {v : String} (h : v ∈ cs) : symbolCat cs v < cs.length := by
  induction cs with
  | nil => simp at h
  | cons c rest ih =>
    simp only [symbolCat, List.length_cons]
    by_cases hc : c = v
    · subst hc; simp
    · have hcv : (c == v) = false := by simpa using hc
      simp only [hcv, Bool.false_eq_true, if_false]
      have : v ∈ rest := by
        rcases List.mem_cons.mp h with h' | h'
        · exact absurd h'.symm hc
        · exact h'
      have := ih this
      omega

theorem symbolCat_inj {cs : List String} {v w : String} (h : symbolCat cs v = symbolCat cs w) :
    v = w ∨ (v ∉ cs ∧ w ∉ cs) := by
  induction cs with
  | nil => right; simp
  | cons c rest ih =>
    simp only [symbolCat] at h
    by_cases hcv : c = v
    · subst hcv
      by_cases hcw : c = w
      · left; exact hcw
      · have : (c == w) = false := by simpa using hcw
        simp [this] at h
    · have hcv' : (c == v) = false := by simpa using hcv
      by_cases hcw : c = w
      · subst hcw; simp [hcv'] at h
      · have hcw' : (c == w) = false := by simpa using hcw
        simp only [hcv', hcw', Bool.false_eq_true, if_false, Nat.add_right_cancel_iff] at h
        rcases ih h with heq | ⟨hv, hw⟩
        · left; exact heq
        · right
          constructor
          · intro hm; rcases List.mem_cons.mp hm with h' | h'
            · exact hcv h'.symm
            · exact hv h'
          · intro hm; rcases List.mem_cons.mp hm with h' | h'
            · exact hcw h'.symm
            · exact hw h'

theorem memVal_str (v : String) (cs : List Value) : memVal (.str v) cs = (strs cs).any (· == v) := by
  induction cs with
  | nil => rfl
  | cons c rest ih =>
    cases c with
    | int n => simp [memVal, strs, valEq, List.any_cons] at ih ⊢; exact ih
    | bool b => simp [memVal, strs, valEq, List.any_cons] at ih ⊢; exact ih
    | str t => simp [memVal, strs, valEq, List.any_cons] at ih ⊢; rw [ih, beq_swap]

/-- Every string constant an atom carries is a named categorical constant of its field. -/
theorem mem_catConsts {atomsF : List Cond} {a : Cond} {op : Op} {l : List String}
    (ha : a ∈ atomsF) (hcat : toCatAtom a = some (op, l)) :
    ∀ c ∈ l, c ∈ catConsts (atomsF.filterMap toCatAtom) := by
  intro c hc
  unfold catConsts
  rw [List.mem_eraseDups, List.mem_flatMap]
  exact ⟨(op, l), List.mem_filterMap.mpr ⟨a, ha, hcat⟩, hc⟩

theorem any_strs_false {l : List Value} {cs : List String} {s : String}
    (hsub : ∀ c ∈ strs l, c ∈ cs) (hs : s ∉ cs) : (strs l).any (· == s) = false := by
  rw [List.any_eq_false]
  intro c hc
  have := hsub c hc
  simp only [beq_iff_eq]
  intro heq; subst heq; exact hs this

theorem categorical_agree {atomsF : List Cond} {s s' : String}
    (h : symbolCat (catConsts (atomsF.filterMap toCatAtom)) s = symbolCat (catConsts (atomsF.filterMap toCatAtom)) s') :
    ∀ a ∈ atomsF, atomEval a (.str s) = atomEval a (.str s') := by
  intro a ha
  rcases symbolCat_inj h with heq | ⟨hs, hs'⟩
  · subst heq; rfl
  · cases a with
    | cmp f op c =>
      cases c with
      | int n => cases op <;> rfl
      | bool b => cases op <;> rfl
      | str c0 =>
        have hc0 : c0 ∈ catConsts (atomsF.filterMap toCatAtom) := mem_catConsts ha rfl c0 (by simp)
        have h1 : valEq (.str s) (.str c0) = false := by
          simp only [valEq, beq_eq_false_iff_ne, ne_eq]; intro heq; subst heq; exact hs hc0
        have h2 : valEq (.str s') (.str c0) = false := by
          simp only [valEq, beq_eq_false_iff_ne, ne_eq]; intro heq; subst heq; exact hs' hc0
        cases op <;> simp [atomEval, cmpVal, h1, h2]
    | mem f cs =>
      have hsub : ∀ c ∈ strs cs, c ∈ catConsts (atomsF.filterMap toCatAtom) := mem_catConsts ha rfl
      simp only [atomEval, memVal_str, any_strs_false hsub hs, any_strs_false hsub hs']
    | nmem f cs =>
      have hsub : ∀ c ∈ strs cs, c ∈ catConsts (atomsF.filterMap toCatAtom) := mem_catConsts ha rfl
      simp only [atomEval, memVal_str, any_strs_false hsub hs, any_strs_false hsub hs']
    | truthy f =>
      have he : "" ∈ catConsts (atomsF.filterMap toCatAtom) := mem_catConsts ha rfl "" (by simp)
      have h1 : (s != "") = true := bne_iff_ne.mpr (fun heq => hs (heq ▸ he))
      have h2 : (s' != "") = true := bne_iff_ne.mpr (fun heq => hs' (heq ▸ he))
      show (s != "") = (s' != "")
      rw [h1, h2]
    | and _ _ => rfl
    | or _ _ => rfl
    | not _ => rfl
    | tt => rfl

/-! ## Assembly -/

theorem condAtoms_field {c : Cond} : ∀ {g a}, (g, a) ∈ condAtoms c → atomField a = some g := by
  induction c with
  | cmp f op k => intro g a h; simp [condAtoms] at h; obtain ⟨rfl, rfl⟩ := h; rfl
  | mem f cs => intro g a h; simp [condAtoms] at h; obtain ⟨rfl, rfl⟩ := h; rfl
  | nmem f cs => intro g a h; simp [condAtoms] at h; obtain ⟨rfl, rfl⟩ := h; rfl
  | truthy f => intro g a h; simp [condAtoms] at h; obtain ⟨rfl, rfl⟩ := h; rfl
  | and a b iha ihb => intro g x h; simp only [condAtoms, List.mem_append] at h; rcases h with h | h; exact iha h; exact ihb h
  | or a b iha ihb => intro g x h; simp only [condAtoms, List.mem_append] at h; rcases h with h | h; exact iha h; exact ihb h
  | not a ih => intro g x h; exact ih h
  | tt => intro g a h; simp [condAtoms] at h

theorem evalCond_atom {r : Reading} {a : Cond} {g : String} (h : atomField a = some g) :
    evalCond r a = atomEval a (r g) := by
  cases a <;> simp [atomField] at h <;> subst h <;> rfl

theorem evalCond_congr {x x' : Reading} : ∀ c : Cond,
    (∀ g a, (g, a) ∈ condAtoms c → atomEval a (x g) = atomEval a (x' g)) → evalCond x c = evalCond x' c := by
  intro c
  induction c with
  | cmp f op k => intro h; rw [evalCond_atom (g := f) rfl, evalCond_atom (g := f) rfl]; exact h f _ (by simp [condAtoms])
  | mem f cs => intro h; rw [evalCond_atom (g := f) rfl, evalCond_atom (g := f) rfl]; exact h f _ (by simp [condAtoms])
  | nmem f cs => intro h; rw [evalCond_atom (g := f) rfl, evalCond_atom (g := f) rfl]; exact h f _ (by simp [condAtoms])
  | truthy f => intro h; rw [evalCond_atom (g := f) rfl, evalCond_atom (g := f) rfl]; exact h f _ (by simp [condAtoms])
  | and a b iha ihb =>
    intro h
    simp only [evalCond]
    rw [iha (fun g a' h' => h g a' (by simp [condAtoms, h'])), ihb (fun g a' h' => h g a' (by simp [condAtoms, h']))]
  | or a b iha ihb =>
    intro h
    simp only [evalCond]
    rw [iha (fun g a' h' => h g a' (by simp [condAtoms, h'])), ihb (fun g a' h' => h g a' (by simp [condAtoms, h']))]
  | not a ih => intro h; simp only [evalCond]; rw [ih (fun g a' h' => h g a' h')]
  | tt => intro _; rfl

theorem route_congr {Action : Type} {p : Policy Action} {x x' : Reading}
    (h : ∀ rule ∈ p, evalCond x rule.cond = evalCond x' rule.cond) : route p x = route p x' := by
  unfold route
  rw [List.find?_congr h]

theorem partitionOf_field (f : String) (atoms : List Cond) : (partitionOf f atoms).field = f := by
  unfold partitionOf
  split <;> rfl

/-- The atoms of field `g` in a policy. -/
def fieldAtoms {Action : Type} (p : Policy Action) (g : String) : List Cond :=
  (policyAtoms p).filterMap (fun (g', a) => if g' == g then some a else none)

theorem mem_fieldAtoms {Action : Type} {p : Policy Action} {g : String} {a : Cond}
    (h : (g, a) ∈ policyAtoms p) : a ∈ fieldAtoms p g := by
  unfold fieldAtoms
  rw [List.mem_filterMap]
  exact ⟨(g, a), h, by simp⟩

theorem partition_mem {Action : Type} {p : Policy Action} {g : String} {a : Cond}
    (h : (g, a) ∈ policyAtoms p) : partitionOf g (fieldAtoms p g) ∈ buildPartitions p := by
  unfold buildPartitions
  rw [List.mem_map]
  refine ⟨g, ?_, rfl⟩
  unfold fieldsOf
  rw [List.mem_eraseDups, List.mem_map]
  exact ⟨(g, a), h, rfl⟩

/-- Equal quantizations give equal symbols on every partition. -/
theorem quantize_eq_symbol {parts : List FieldPartition} {x x' : Reading}
    (h : quantize parts x = quantize parts x') :
    ∀ q ∈ parts, symbolOf q (x q.field) = symbolOf q (x' q.field) := by
  intro q hq
  have := (List.map_inj_left.mp h) q hq
  simpa using this

theorem atoms_agree {Action : Type} (p : Policy Action) (x x' : Reading)
    (hx : WellTyped (buildPartitions p) x) (hx' : WellTyped (buildPartitions p) x')
    (h : quantize (buildPartitions p) x = quantize (buildPartitions p) x') :
    ∀ g a, (g, a) ∈ policyAtoms p → atomEval a (x g) = atomEval a (x' g) := by
  intro g a hga
  have hmem := partition_mem hga
  have hsym := quantize_eq_symbol h _ hmem
  have htx := hx _ hmem
  have htx' := hx' _ hmem
  have ha : a ∈ fieldAtoms p g := mem_fieldAtoms hga
  rw [partitionOf_field] at hsym htx htx'
  unfold partitionOf at hsym htx htx'
  split at hsym <;> rename_i hkind
  · -- numeric
    rw [hkind] at htx htx'
    cases hv : x g with
    | int v =>
      cases hw : x' g with
      | int w => exact numeric_agree (by rw [hv, hw] at hsym; simpa [symbolOf] using hsym) a ha
      | bool _ => rw [hw] at htx'; simp at htx'
      | str _ => rw [hw] at htx'; simp at htx'
    | bool _ => rw [hv] at htx; simp at htx
    | str _ => rw [hv] at htx; simp at htx
  · -- boolean
    rw [hkind] at htx htx'
    cases hv : x g with
    | bool b =>
      cases hw : x' g with
      | bool b' =>
        rw [hv, hw] at hsym
        have := symbolBool_inj (by simpa [symbolOf] using hsym)
        subst this; rfl
      | int _ => rw [hw] at htx'; simp at htx'
      | str _ => rw [hw] at htx'; simp at htx'
    | int _ => rw [hv] at htx; simp at htx
    | str _ => rw [hv] at htx; simp at htx
  · -- categorical
    rw [hkind] at htx htx'
    cases hv : x g with
    | str s =>
      cases hw : x' g with
      | str s' => exact categorical_agree (by rw [hv, hw] at hsym; simpa [symbolOf] using hsym) a ha
      | int _ => rw [hw] at htx'; simp at htx'
      | bool _ => rw [hw] at htx'; simp at htx'
    | int _ => rw [hv] at htx; simp at htx
    | bool _ => rw [hv] at htx; simp at htx

/-- **Theorem I1 (decision preservation).** For a Level M policy and two well typed readings with the
same Figueroa quantization, the policy routes them identically. -/
theorem decision_preservation {Action : Type} (p : Policy Action) (x x' : Reading)
    (hx : WellTyped (buildPartitions p) x) (hx' : WellTyped (buildPartitions p) x')
    (h : quantize (buildPartitions p) x = quantize (buildPartitions p) x') :
    route p x = route p x' := by
  apply route_congr
  intro rule hrule
  apply evalCond_congr
  intro g a hga
  apply atoms_agree p x x' hx hx' h
  unfold policyAtoms
  rw [List.mem_flatMap]
  exact ⟨rule, hrule, hga⟩

end FQ
