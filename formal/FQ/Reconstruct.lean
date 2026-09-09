-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import FQ.I1
/-!
# The reconstruct corollary

The paper's statement of I1 "in words": reconstructing any representative of each cell and routing
it reproduces every decision the original reading produced. Formally, for a well typed reading `x`,
`route p (reconstruct parts (quantize parts x)) = route p x`. It follows from `decision_preservation`
once the representative reading is shown to be well typed and to quantize to the same symbols, which
is where the retained boundaries need to be strictly increasing: the representative of a numeric
symbol `s` is the `s`th retained boundary (or one below the first), and its symbol is `s` again only
because the boundaries are sorted with no duplicates.

One well formedness hypothesis: the categorical `other` sentinel is not itself a named constant
(`NoSentinel`), so the representative of the `other` cell quantizes back to the `other` cell.
-/

namespace FQ

open List

/-! ## Retained boundaries are strictly increasing -/

theorem boundaries_sorted (consts : List Int) : (boundaries consts).Pairwise (· < ·) := by
  unfold boundaries
  have hle : ((consts.flatMap (fun c => [c, c + 1])).mergeSort (· ≤ ·)).Pairwise (· ≤ ·) := by
    have := List.pairwise_mergeSort (le := fun a b : Int => decide (a ≤ b))
      (fun a b c hab hbc => by simp only [decide_eq_true_eq] at *; omega)
      (fun a b => by by_cases h : a ≤ b <;> simp [h] <;> omega)
      (consts.flatMap (fun c => [c, c + 1]))
    exact this.imp (fun h => by simpa using h)
  have hsub := List.dedup_sublist ((consts.flatMap (fun c => [c, c + 1])).mergeSort (· ≤ ·))
  have hle' := hle.sublist hsub
  have hnd := List.nodup_dedup ((consts.flatMap (fun c => [c, c + 1])).mergeSort (· ≤ ·))
  exact (hle'.and hnd).imp (fun ⟨h1, h2⟩ => lt_of_le_of_ne h1 h2)

theorem retained_sorted (atoms : List NumAtom) : (retained atoms).Pairwise (· < ·) :=
  (boundaries_sorted (numConsts atoms)).filter _

/-! ## Counting on a strictly increasing list -/

theorem countP_le_below_head {x : Int} {xs : List Int} (h : (x :: xs).Pairwise (· < ·)) :
    (x :: xs).countP (· ≤ x - 1) = 0 := by
  rw [List.countP_eq_zero]
  intro a ha
  simp only [decide_eq_true_eq, not_le]
  rcases List.mem_cons.mp ha with rfl | ha'
  · omega
  · have := List.rel_of_pairwise_cons h ha'
    omega

theorem countP_le_getElem {l : List Int} (h : l.Pairwise (· < ·)) :
    ∀ n (hn : n < l.length), l.countP (· ≤ l[n]) = n + 1 := by
  induction l with
  | nil => intro n hn; simp at hn
  | cons x xs ih =>
    intro n hn
    cases n with
    | zero =>
      simp only [List.getElem_cons_zero, List.countP_cons, le_refl, decide_true, if_true]
      have : xs.countP (· ≤ x) = 0 := by
        rw [List.countP_eq_zero]
        intro a ha
        have := List.rel_of_pairwise_cons h ha
        simp only [decide_eq_true_eq, not_le]; omega
      omega
    | succ m =>
      simp only [List.getElem_cons_succ, List.countP_cons]
      have hm : m < xs.length := by simpa using hn
      have hx : x ≤ xs[m] := by
        have := List.rel_of_pairwise_cons h (List.getElem_mem hm)
        omega
      rw [ih (List.Pairwise.of_cons h) m hm]
      simp [hx]

/-! ## The representative quantizes to its own symbol -/

theorem symbolCount_le_length (atoms : List NumAtom) (v : Int) :
    symbolCount atoms v ≤ (retained atoms).length :=
  List.countP_le_length

theorem symbolCount_repCount (atoms : List NumAtom) (v : Int) :
    symbolCount atoms (representativeOf.repCount atoms (symbolCount atoms v)) = symbolCount atoms v := by
  have hs := retained_sorted atoms
  cases hsym : symbolCount atoms v with
  | zero =>
    simp only [representativeOf.repCount]
    cases hR : retained atoms with
    | nil => simp [symbolCount, hR]
    | cons b rest =>
      simp only [List.head?_cons]
      unfold symbolCount
      rw [hR]
      rw [hR] at hs
      exact countP_le_below_head hs
  | succ n =>
    simp only [representativeOf.repCount]
    have hlen : n + 1 ≤ (retained atoms).length := hsym ▸ symbolCount_le_length atoms v
    have hn : n < (retained atoms).length := by omega
    rw [List.getElem?_eq_getElem hn]
    simp only []
    unfold symbolCount
    exact countP_le_getElem hs n hn

theorem symbolCat_repCat {cs : List String} (hns : otherSentinel ∉ cs) (s : String) :
    symbolCat cs (repCat cs (symbolCat cs s)) = symbolCat cs s := by
  by_cases hmem : s ∈ cs
  · -- the first occurrence: cs[symbolCat cs s] = s
    have key : ∀ (cs : List String), s ∈ cs → cs[symbolCat cs s]? = some s := by
      intro cs hm
      induction cs with
      | nil => simp at hm
      | cons c rest ih =>
        by_cases hc : c = s
        · subst hc; simp [symbolCat]
        · have hcs : (c == s) = false := by simpa using hc
          have hm' : s ∈ rest := by
            rcases List.mem_cons.mp hm with h | h
            · exact absurd h.symm hc
            · exact h
          simp [symbolCat, hcs, ih hm']
    unfold repCat
    rw [key cs hmem]
  · have hlen : symbolCat cs s = cs.length := (symbolCat_eq_length_iff cs s).mpr hmem
    unfold repCat
    rw [hlen, List.getElem?_eq_none (le_refl _)]
    simp only []
    rw [(symbolCat_eq_length_iff cs otherSentinel).mpr hns]

/-! ## Fields of a policy's partitions are distinct -/

theorem buildPartitions_fields_nodup {Action : Type} (p : Policy Action) :
    ((buildPartitions p).map FieldPartition.field).Nodup := by
  unfold buildPartitions
  rw [List.map_map]
  have : (FieldPartition.field ∘ fun f => partitionOf f ((policyAtoms p).filterMap
      (fun (g, a) => if g == f then some a else none))) = id := by
    funext f; simp [partitionOf_field]
  rw [this, List.map_id]
  exact List.nodup_dedup _

theorem find?_field {parts : List FieldPartition} (hnd : (parts.map FieldPartition.field).Nodup)
    {q : FieldPartition} (hq : q ∈ parts) : parts.find? (·.field == q.field) = some q := by
  induction parts with
  | nil => simp at hq
  | cons r rest ih =>
    rcases List.mem_cons.mp hq with rfl | hq'
    · simp
    · have hne : r.field ≠ q.field := by
        simp only [List.map_cons, List.nodup_cons, List.mem_map] at hnd
        intro heq; exact hnd.1 ⟨q, hq', heq.symm⟩
      have hb : (r.field == q.field) = false := by simpa using hne
      rw [List.find?_cons_of_neg (by simp [hb])]
      exact ih (List.nodup_cons.mp (by simpa using hnd)).2 hq'

theorem lookup_quantize {parts : List FieldPartition} (hnd : (parts.map FieldPartition.field).Nodup)
    {q : FieldPartition} (hq : q ∈ parts) (x : Reading) :
    (quantize parts x).lookup q.field = some (symbolOf q (x q.field)) := by
  unfold quantize
  induction parts with
  | nil => simp at hq
  | cons r rest ih =>
    rcases List.mem_cons.mp hq with rfl | hq'
    · simp [List.lookup]
    · have hne : r.field ≠ q.field := by
        simp only [List.map_cons, List.nodup_cons, List.mem_map] at hnd
        intro heq; exact hnd.1 ⟨q, hq', heq.symm⟩
      have hb : (q.field == r.field) = false := by simpa using (Ne.symm hne)
      simp only [List.map_cons, List.lookup, hb]
      exact ih (List.nodup_cons.mp (by simpa using hnd)).2 hq'

/-- No categorical partition names the `other` sentinel. -/
def NoSentinel (parts : List FieldPartition) : Prop :=
  ∀ q ∈ parts, match q with
    | .categorical _ cs => otherSentinel ∉ cs
    | _ => True

/-! ## The corollary -/

theorem reconstruct_wellTyped {parts : List FieldPartition} (hnd : (parts.map FieldPartition.field).Nodup)
    (syms : List (String × Nat)) (hsyms : ∀ q ∈ parts, ∃ s, syms.lookup q.field = some s) :
    WellTyped parts (reconstruct parts syms) := by
  intro q hq
  obtain ⟨s, hs⟩ := hsyms q hq
  simp only [reconstruct, find?_field hnd hq, hs]
  cases q <;> simp [representativeOf]

theorem quantize_reconstruct {parts : List FieldPartition} (hnd : (parts.map FieldPartition.field).Nodup)
    (hns : NoSentinel parts) {x : Reading} (hx : WellTyped parts x) :
    quantize parts (reconstruct parts (quantize parts x)) = quantize parts x := by
  unfold quantize
  apply List.map_congr_left
  intro q hq
  have hl := lookup_quantize hnd hq x
  unfold quantize at hl
  simp only [reconstruct, find?_field hnd hq, hl]
  have ht := hx q hq
  have hn := hns q hq
  cases q with
  | numeric f atoms =>
    simp only [FieldPartition.field] at ht ⊢
    cases hv : x f with
    | int v => simp only [hv, symbolOf, representativeOf]; rw [symbolCount_repCount]
    | bool _ => rw [hv] at ht; simp at ht
    | str _ => rw [hv] at ht; simp at ht
  | boolean f =>
    simp only [FieldPartition.field] at ht ⊢
    cases hv : x f with
    | bool b => cases b <;> simp [symbolOf, representativeOf, symbolBool, repBool]
    | int _ => rw [hv] at ht; simp at ht
    | str _ => rw [hv] at ht; simp at ht
  | categorical f cs =>
    simp only [FieldPartition.field] at ht ⊢
    cases hv : x f with
    | str s => simp only [hv, symbolOf, representativeOf]; rw [symbolCat_repCat hn]
    | int _ => rw [hv] at ht; simp at ht
    | bool _ => rw [hv] at ht; simp at ht

/-- **Corollary (I1 in words).** Routing the reconstructed representative reproduces the decision. -/
theorem reconstruct_route {Action : Type} (p : Policy Action) (x : Reading)
    (hx : WellTyped (buildPartitions p) x) (hns : NoSentinel (buildPartitions p)) :
    route p (reconstruct (buildPartitions p) (quantize (buildPartitions p) x)) = route p x := by
  have hnd := buildPartitions_fields_nodup p
  have hwt : WellTyped (buildPartitions p) (reconstruct (buildPartitions p) (quantize (buildPartitions p) x)) :=
    reconstruct_wellTyped hnd _ (fun q hq => ⟨_, lookup_quantize hnd hq x⟩)
  exact decision_preservation p _ x hwt hx (quantize_reconstruct hnd hns hx)

end FQ
