-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import FQ.I1
import FQ.Reconstruct
/-!
# The reference algorithm equals the canonical form

`symbolAlg` is the reference quantizer's numeric partition as ported from `quantizer.py`: a fine
grid of point and gap cells from the sorted constants, adjacent cells merged when the atom truth
vector at their representatives agrees, then the index of the first cell containing the value.
`symbolCount` is the canonical form Theorem I1 is proven over. This file proves they agree on every
integer, so I1 and its corollaries hold of the reference algorithm itself.

Route: the fine grid is a contiguous chain of integer intervals whose interiors contain no boundary
(`fineGrid_contig`, `fineGrid_noBoundaryInside`), so every atom is constant on each fine cell
(`truth_const_on_fine`); the merge keeps a cell start exactly when the truth vector changes across
it (`merge_starts`), so the merged cell starts are the retained boundaries as a set; the first index
over a contiguous chain is the count of starts at or below the value (`findIdx_contig`); and two
duplicate free lists with the same members have equal counts.
-/

namespace FQ

open List

abbrev FineCell := Option Int × Option Int

/-- A contiguous chain of integer intervals: each bounded cell is non empty, the next cell starts one
above the previous cell's end, and only the last cell is unbounded above. -/
inductive Contig : List FineCell → Prop
  | last (lo : Option Int) : Contig [(lo, none)]
  | cons {lo : Option Int} {h : Int} {hi' : Option Int} {rest : List FineCell}
      (hne : ∀ l, lo = some l → l ≤ h)
      (hc : Contig ((some (h + 1), hi') :: rest)) :
      Contig ((lo, some h) :: (some (h + 1), hi') :: rest)

/-- `Contig.cons` with the next start given by an equation, so `omega` can discharge it. -/
theorem Contig.cons' {lo : Option Int} {h l' : Int} {hi' : Option Int} {rest : List FineCell}
    (hnext : l' = h + 1) (hne : ∀ l, lo = some l → l ≤ h)
    (hc : Contig ((some l', hi') :: rest)) : Contig ((lo, some h) :: (some l', hi') :: rest) := by
  subst hnext; exact Contig.cons hne hc

theorem fineFrom_head (c : Int) (rest : List Int) :
    ∃ hi tl, fineGrid.fineFrom c rest = (some c, hi) :: tl := by
  cases rest with
  | nil => exact ⟨some c, _, rfl⟩
  | cons n rest' =>
    unfold fineGrid.fineFrom
    split <;> exact ⟨some c, _, rfl⟩

theorem fineFrom_contig (c : Int) : ∀ (rest : List Int), (∀ x ∈ rest, c < x) → rest.Pairwise (· < ·) →
    Contig (fineGrid.fineFrom c rest) := by
  intro rest
  induction rest generalizing c with
  | nil =>
    intro _ _
    show Contig [(some c, some c), (some (c + 1), none)]
    exact Contig.cons' rfl (fun l hl => by have := Option.some.inj hl; omega) (Contig.last _)
  | cons n rest' ih =>
    intro hgt hp
    have hcn : c < n := hgt n (by simp)
    have hrest : ∀ x ∈ rest', n < x := fun x hx => List.rel_of_pairwise_cons hp hx
    have ih' := ih n hrest (List.Pairwise.of_cons hp)
    obtain ⟨hi, tl, heq⟩ := fineFrom_head n rest'
    rw [heq] at ih'
    unfold fineGrid.fineFrom
    rw [heq]
    split
    · exact Contig.cons' rfl (fun l hl => by have := Option.some.inj hl; omega)
        (Contig.cons' (by omega) (fun l hl => by have := Option.some.inj hl; omega) ih')
    · exact Contig.cons' (by omega) (fun l hl => by have := Option.some.inj hl; omega) ih'

/-- The fine grid of a non empty strictly increasing constant list is contiguous and opens with an
unbounded first cell. -/
theorem fineGrid_contig {c : Int} {rest : List Int} (hp : (c :: rest).Pairwise (· < ·)) :
    Contig (fineGrid (c :: rest)) := by
  obtain ⟨hi, tl, heq⟩ := fineFrom_head c rest
  have hc := fineFrom_contig c rest (fun x hx => List.rel_of_pairwise_cons hp hx) (List.Pairwise.of_cons hp)
  show Contig ((none, some (c - 1)) :: fineGrid.fineFrom c rest)
  rw [heq] at hc ⊢
  exact Contig.cons' (by omega) (fun l hl => by cases hl) hc

/-! ## Stage two: no boundary lies inside a fine cell, so atoms are constant on it -/

/-- `b` lies strictly above the cell's start and at or below its end. -/
def inside (b : Int) (cell : FineCell) : Prop :=
  (match cell.1 with | some l => l < b | none => True) ∧
  (match cell.2 with | some h => b ≤ h | none => True)

def fineContains (cell : FineCell) (v : Int) : Prop :=
  (match cell.1 with | some l => l ≤ v | none => True) ∧
  (match cell.2 with | some h => v ≤ h | none => True)

theorem mem_boundaries_iff {cs : List Int} {b : Int} :
    b ∈ boundaries cs ↔ ∃ x ∈ cs, b = x ∨ b = x + 1 := by
  unfold boundaries
  rw [List.mem_dedup, List.mem_mergeSort, List.mem_flatMap]
  constructor
  · rintro ⟨x, hx, hb⟩; simp at hb; exact ⟨x, hx, by omega⟩
  · rintro ⟨x, hx, hb⟩; exact ⟨x, hx, by simp; omega⟩

theorem sorted_dedup_mergeSort (l : List Int) : ((l.mergeSort (· ≤ ·)).dedup).Pairwise (· < ·) := by
  have hle : (l.mergeSort (· ≤ ·)).Pairwise (· ≤ ·) := by
    have := List.pairwise_mergeSort (le := fun a b : Int => decide (a ≤ b))
      (fun a b c hab hbc => by simp only [decide_eq_true_eq] at *; omega)
      (fun a b => by by_cases h : a ≤ b <;> simp [h] <;> omega) l
    exact this.imp (fun h => by simpa using h)
  have hle' := hle.sublist (List.dedup_sublist _)
  have hnd := List.nodup_dedup (l.mergeSort (· ≤ ·))
  exact (hle'.and hnd).imp (fun ⟨h1, h2⟩ => lt_of_le_of_ne h1 h2)

theorem numConsts_sorted (atoms : List NumAtom) : (numConsts atoms).Pairwise (· < ·) := by
  unfold numConsts
  exact sorted_dedup_mergeSort _

theorem fineFrom_lo_ge (c : Int) : ∀ (rest : List Int), (∀ x ∈ rest, c < x) → rest.Pairwise (· < ·) →
    ∀ cell ∈ fineGrid.fineFrom c rest, ∃ l, cell.1 = some l ∧ c ≤ l := by
  intro rest
  induction rest generalizing c with
  | nil =>
    intro _ _ cell hc
    simp only [fineGrid.fineFrom, List.mem_cons, List.mem_singleton, List.not_mem_nil, or_false] at hc
    rcases hc with rfl | rfl
    · exact ⟨c, rfl, le_refl _⟩
    · exact ⟨c + 1, rfl, by omega⟩
  | cons n rest' ih =>
    intro hgt hp cell hc
    have hcn : c < n := hgt n (by simp)
    have hrest : ∀ x ∈ rest', n < x := fun x hx => List.rel_of_pairwise_cons hp hx
    unfold fineGrid.fineFrom at hc
    split at hc <;> rename_i hgap
    · simp only [List.mem_cons] at hc
      rcases hc with rfl | rfl | hc
      · exact ⟨c, rfl, le_refl _⟩
      · exact ⟨c + 1, rfl, by omega⟩
      · obtain ⟨l, hl, hle⟩ := ih n hrest (List.Pairwise.of_cons hp) cell hc
        exact ⟨l, hl, by omega⟩
    · simp only [List.mem_cons] at hc
      rcases hc with rfl | hc
      · exact ⟨c, rfl, le_refl _⟩
      · obtain ⟨l, hl, hle⟩ := ih n hrest (List.Pairwise.of_cons hp) cell hc
        exact ⟨l, hl, by omega⟩

/-- Boundaries drawn from `c :: rest` never fall strictly inside a cell of `fineFrom c rest`. -/
theorem fineFrom_noInside (c : Int) : ∀ (rest : List Int), (∀ x ∈ rest, c < x) → rest.Pairwise (· < ·) →
    ∀ b, (b = c ∨ b = c + 1 ∨ ∃ x ∈ rest, b = x ∨ b = x + 1) →
    ∀ cell ∈ fineGrid.fineFrom c rest, ¬ inside b cell := by
  intro rest
  induction rest generalizing c with
  | nil =>
    intro _ _ b hb cell hc
    simp only [List.not_mem_nil, false_and, exists_false, or_false] at hb
    simp only [fineGrid.fineFrom, List.mem_cons, List.mem_singleton, List.not_mem_nil, or_false] at hc
    rcases hc with rfl | rfl <;> simp only [inside] <;> omega
  | cons n rest' ih =>
    intro hgt hp b hb cell hc
    have hcn : c < n := hgt n (by simp)
    have hrest : ∀ x ∈ rest', n < x := fun x hx => List.rel_of_pairwise_cons hp hx
    -- b is at least c, and if it comes from rest it is at least n
    have hb' : b = c ∨ b = c + 1 ∨ (b = n ∨ b = n + 1) ∨ ∃ x ∈ rest', b = x ∨ b = x + 1 := by
      rcases hb with h | h | ⟨x, hx, h⟩
      · exact Or.inl h
      · exact Or.inr (Or.inl h)
      · rcases List.mem_cons.mp hx with rfl | hx'
        · exact Or.inr (Or.inr (Or.inl h))
        · exact Or.inr (Or.inr (Or.inr ⟨x, hx', h⟩))
    have hbn : ∀ x ∈ rest', n < x := hrest
    unfold fineGrid.fineFrom at hc
    split at hc <;> rename_i hgap
    · simp only [List.mem_cons] at hc
      rcases hc with rfl | rfl | hc
      · simp only [inside]; omega
      · simp only [inside]
        rintro ⟨h1, h2⟩
        rcases hb' with h | h | h | ⟨x, hx, h⟩
        · omega
        · omega
        · omega
        · have := hbn x hx; omega
      · -- a cell of fineFrom n rest'
        rcases hb' with h | h | h | h
        · obtain ⟨l, hl, hle⟩ := fineFrom_lo_ge n rest' hbn (List.Pairwise.of_cons hp) cell hc
          simp only [inside, hl]; omega
        · obtain ⟨l, hl, hle⟩ := fineFrom_lo_ge n rest' hbn (List.Pairwise.of_cons hp) cell hc
          simp only [inside, hl]; omega
        · exact ih n hbn (List.Pairwise.of_cons hp) b (by rcases h with h | h; exact Or.inl h; exact Or.inr (Or.inl h)) cell hc
        · exact ih n hbn (List.Pairwise.of_cons hp) b (Or.inr (Or.inr h)) cell hc
    · simp only [List.mem_cons] at hc
      rcases hc with rfl | hc
      · simp only [inside]; omega
      · rcases hb' with h | h | h | h
        · obtain ⟨l, hl, hle⟩ := fineFrom_lo_ge n rest' hbn (List.Pairwise.of_cons hp) cell hc
          simp only [inside, hl]; omega
        · obtain ⟨l, hl, hle⟩ := fineFrom_lo_ge n rest' hbn (List.Pairwise.of_cons hp) cell hc
          simp only [inside, hl]; omega
        · exact ih n hbn (List.Pairwise.of_cons hp) b (by rcases h with h | h; exact Or.inl h; exact Or.inr (Or.inl h)) cell hc
        · exact ih n hbn (List.Pairwise.of_cons hp) b (Or.inr (Or.inr h)) cell hc

theorem fineGrid_noInside {c : Int} {rest : List Int} (hp : (c :: rest).Pairwise (· < ·)) :
    ∀ b ∈ boundaries (c :: rest), ∀ cell ∈ fineGrid (c :: rest), ¬ inside b cell := by
  intro b hb cell hc
  rw [mem_boundaries_iff] at hb
  have hb' : b = c ∨ b = c + 1 ∨ ∃ x ∈ rest, b = x ∨ b = x + 1 := by
    obtain ⟨x, hx, h⟩ := hb
    rcases List.mem_cons.mp hx with rfl | hx'
    · rcases h with h | h; exact Or.inl h; exact Or.inr (Or.inl h)
    · exact Or.inr (Or.inr ⟨x, hx', h⟩)
  have hge : c ≤ b := by
    obtain ⟨x, hx, h⟩ := hb
    rcases List.mem_cons.mp hx with rfl | hx'
    · omega
    · have := List.rel_of_pairwise_cons hp hx'; omega
  change cell ∈ (none, some (c - 1)) :: fineGrid.fineFrom c rest at hc
  rcases List.mem_cons.mp hc with rfl | hc'
  · simp only [inside]; omega
  · exact fineFrom_noInside c rest (fun x hx => List.rel_of_pairwise_cons hp hx) (List.Pairwise.of_cons hp) b hb' cell hc'

theorem truth_const_of_no_step {atoms : List NumAtom} {v w : Int} (hvw : v ≤ w)
    (hstep : ∀ k, v ≤ k → k < w → truthVec atoms k = truthVec atoms (k + 1)) :
    truthVec atoms v = truthVec atoms w := by
  induction w, hvw using Int.leInduction with
  | base => rfl
  | succ w hw ih =>
    have h1 := ih (fun k hk1 hk2 => hstep k hk1 (by omega))
    exact h1.trans (hstep w hw (by omega))

/-- Every atom is constant on each fine cell of the partition's own constants. -/
theorem truth_const_on_fine {atoms : List NumAtom} {c : Int} {rest : List Int}
    (hcs : numConsts atoms = c :: rest) {cell : FineCell} (hc : cell ∈ fineGrid (c :: rest))
    {v w : Int} (hv : fineContains cell v) (hw : fineContains cell w) :
    truthVec atoms v = truthVec atoms w := by
  have hp : (c :: rest).Pairwise (· < ·) := hcs ▸ numConsts_sorted atoms
  obtain ⟨lo, hi⟩ := cell
  have key : ∀ v w, v ≤ w → fineContains (lo, hi) v → fineContains (lo, hi) w → truthVec atoms v = truthVec atoms w := by
    intro v w hvw hv hw
    apply truth_const_of_no_step hvw
    intro k hk1 hk2
    by_contra hne
    have hb : k + 1 ∈ boundaries (numConsts atoms) := truth_step hne
    rw [hcs] at hb
    apply fineGrid_noInside hp (k + 1) hb (lo, hi) hc
    obtain ⟨hv1, hv2⟩ := hv
    obtain ⟨hw1, hw2⟩ := hw
    unfold inside
    cases lo <;> cases hi <;> simp only at hv1 hv2 hw1 hw2 ⊢ <;> refine ⟨?_, ?_⟩ <;> first | trivial | omega
  rcases le_total v w with h | h
  · exact key v w h hv hw
  · exact (key w v h hw hv).symm

/-! ## Stage four: the first containing cell of a contiguous chain is a count of starts -/

def toFine (C : List NumCell) : List FineCell := C.map (fun c => (c.lo, c.hi))

/-- Interval membership as a Bool, matching `NumCell.contains`. -/
def fineContainsB (cell : FineCell) (v : Int) : Bool :=
  (match cell.1 with | some l => decide (l ≤ v) | none => true) &&
  (match cell.2 with | some h => decide (v ≤ h) | none => true)

theorem contains_eq (c : NumCell) (v : Int) : c.contains v = fineContainsB (c.lo, c.hi) v := by
  unfold NumCell.contains fineContainsB
  cases c.lo <;> cases c.hi <;> rfl

theorem fineContainsB_some (lo : Option Int) (h v : Int) :
    fineContainsB (lo, some h) v = true ↔ (∀ l, lo = some l → l ≤ v) ∧ v ≤ h := by
  unfold fineContainsB; cases lo <;> simp

theorem fineContainsB_none (lo : Option Int) (v : Int) :
    fineContainsB (lo, none) v = true ↔ (∀ l, lo = some l → l ≤ v) := by
  unfold fineContainsB; cases lo <;> simp

/-- Later starts of a contiguous chain lie strictly above the first cell's start. -/
theorem contig_starts_ge : ∀ (F : List FineCell), Contig F → ∀ l, F.head?.map Prod.fst = some (some l) →
    ∀ s ∈ (F.drop 1).filterMap Prod.fst, l < s := by
  intro F hF
  induction hF with
  | last lo => intro l _ s hs; simp at hs
  | cons hne hc ih =>
    rename_i lo h hi' rest
    intro l hl s hs
    simp only [List.head?_cons, Option.map_some, Option.some.injEq] at hl
    have hl' := hne l hl
    simp only [List.drop_succ_cons, List.drop_zero, List.filterMap_cons] at hs
    rcases List.mem_cons.mp hs with rfl | hs'
    · omega
    · have := ih (h + 1) (by simp) s (by simpa using hs')
      omega

theorem findIdx_contig_fine : ∀ (F : List FineCell), Contig F → ∀ v,
    (∀ lo hi tl, F = (lo, hi) :: tl → ∀ l, lo = some l → l ≤ v) →
    F.findIdx (fun f => fineContainsB f v) = ((F.drop 1).filterMap Prod.fst).countP (· ≤ v) := by
  intro F hF
  induction hF with
  | last lo =>
    intro v hv
    have hlo : ∀ l, lo = some l → l ≤ v := hv lo none [] rfl
    have : fineContainsB (lo, none) v = true := (fineContainsB_none lo v).mpr hlo
    simp [List.findIdx_cons, this]
  | cons hne hc ih =>
    rename_i lo h hi' rest
    intro v hv
    have hlo : ∀ l, lo = some l → l ≤ v := hv lo (some h) _ rfl
    by_cases hvh : v ≤ h
    · have hin : fineContainsB (lo, some h) v = true := (fineContainsB_some lo h v).mpr ⟨hlo, hvh⟩
      simp only [List.findIdx_cons, hin, cond_true]
      symm
      rw [List.countP_eq_zero]
      intro s hs
      simp only [List.drop_succ_cons, List.drop_zero, List.filterMap_cons] at hs
      simp only [decide_eq_true_eq, not_le]
      rcases List.mem_cons.mp hs with rfl | hs'
      · omega
      · have := contig_starts_ge _ hc (h + 1) (by simp) s (by simpa using hs')
        omega
    · have hout : fineContainsB (lo, some h) v = false := by
        by_contra hc'
        have := (fineContainsB_some lo h v).mp (by simpa using hc')
        exact hvh this.2
      rw [List.findIdx_cons, hout, cond_false]
      rw [ih v (fun lo' hi'' tl heq l hl => by
        simp only [List.cons.injEq, Prod.mk.injEq] at heq
        obtain ⟨⟨h1, _⟩, _⟩ := heq
        rw [← h1] at hl
        have := Option.some.inj hl
        omega)]
      simp only [List.drop_succ_cons, List.drop_zero, List.filterMap_cons, List.countP_cons]
      have : h + 1 ≤ v := by omega
      simp [this]

theorem findIdx_toFine (C : List NumCell) (v : Int) :
    C.findIdx (·.contains v) = (toFine C).findIdx (fun f => fineContainsB f v) := by
  induction C with
  | nil => rfl
  | cons c rest ih =>
    simp only [toFine, List.map_cons, List.findIdx_cons]
    rw [← toFine, ← ih, contains_eq]

theorem starts_toFine (C : List NumCell) :
    ((toFine C).drop 1).filterMap Prod.fst = (C.drop 1).filterMap NumCell.lo := by
  cases C with
  | nil => rfl
  | cons c rest =>
    simp only [toFine, List.map_cons, List.drop_succ_cons, List.drop_zero, List.filterMap_map]
    rfl

theorem findIdx_contig (C : List NumCell) (hC : Contig (toFine C)) (v : Int)
    (hv : ∀ c tl, C = c :: tl → ∀ l, c.lo = some l → l ≤ v) :
    C.findIdx (·.contains v) = ((C.drop 1).filterMap NumCell.lo).countP (· ≤ v) := by
  rw [findIdx_toFine, findIdx_contig_fine _ hC v ?_, starts_toFine]
  intro lo hi tl heq l hl
  cases C with
  | nil => simp [toFine] at heq
  | cons c rest =>
    simp only [toFine, List.map_cons, List.cons.injEq, Prod.mk.injEq] at heq
    obtain ⟨⟨h1, _⟩, _⟩ := heq
    exact hv c rest rfl l (h1 ▸ hl)

/-! ## Stage three: the merge keeps a start exactly when the truth vector changes across it -/

theorem Contig.lo_le_hi {l h : Int} {rest : List FineCell} (hc : Contig ((some l, some h) :: rest)) : l ≤ h := by
  cases hc with
  | cons hne _ => exact hne l rfl

/-- Replacing the first cell's start by one at or below it keeps the chain contiguous. -/
theorem Contig.replace_lo {l1 : Int} {lo2 : Option Int} {hi : Option Int} {rest : List FineCell}
    (hc : Contig ((some l1, hi) :: rest)) (hle : ∀ l2, lo2 = some l2 → l2 ≤ l1) :
    Contig ((lo2, hi) :: rest) := by
  cases hc with
  | last _ => exact Contig.last _
  | cons hne hc' =>
    exact Contig.cons (fun l2 hl2 => le_trans (hle l2 hl2) (hne l1 rfl)) hc'

/-- The starts of a contiguous chain are strictly increasing. -/
theorem contig_starts_sorted : ∀ (F : List FineCell), Contig F → ((F.drop 1).filterMap Prod.fst).Pairwise (· < ·) := by
  intro F hF
  induction hF with
  | last _ => simp
  | cons hne hc ih =>
    rename_i lo h hi' rest
    simp only [List.drop_succ_cons, List.drop_zero, List.filterMap_cons]
    refine List.Pairwise.cons ?_ (by simpa using ih)
    intro s hs
    exact contig_starts_ge _ hc (h + 1) (by simp) s (by simpa using hs)

/-- Membership in the fine cell starts of `fineFrom c rest` is membership in the boundaries of `c :: rest`. -/
theorem mem_fineFrom_starts (c : Int) : ∀ (rest : List Int), (∀ x ∈ rest, c < x) → rest.Pairwise (· < ·) →
    ∀ b, b ∈ (fineGrid.fineFrom c rest).filterMap Prod.fst ↔ (b = c ∨ b = c + 1 ∨ ∃ x ∈ rest, b = x ∨ b = x + 1) := by
  intro rest
  induction rest generalizing c with
  | nil =>
    intro _ _ b
    simp [fineGrid.fineFrom]
  | cons n rest' ih =>
    intro hgt hp b
    have hcn : c < n := hgt n (by simp)
    have hrest : ∀ x ∈ rest', n < x := fun x hx => List.rel_of_pairwise_cons hp hx
    have ih' := ih n hrest (List.Pairwise.of_cons hp) b
    unfold fineGrid.fineFrom
    split <;> rename_i hgap
    · simp only [List.filterMap_cons, List.mem_cons, ih']
      constructor
      · rintro (rfl | rfl | h | h | ⟨x, hx, h⟩)
        · exact Or.inl rfl
        · exact Or.inr (Or.inl rfl)
        · exact Or.inr (Or.inr ⟨n, by simp, Or.inl h⟩)
        · exact Or.inr (Or.inr ⟨n, by simp, Or.inr h⟩)
        · exact Or.inr (Or.inr ⟨x, by simp [hx], h⟩)
      · rintro (rfl | rfl | ⟨x, hx, h⟩)
        · exact Or.inl rfl
        · exact Or.inr (Or.inl rfl)
        · rcases hx with rfl | hx'
          · rcases h with rfl | rfl
            · exact Or.inr (Or.inr (Or.inl rfl))
            · exact Or.inr (Or.inr (Or.inr (Or.inl rfl)))
          · exact Or.inr (Or.inr (Or.inr (Or.inr ⟨x, hx', h⟩)))
    · have hn : n = c + 1 := by omega
      simp only [List.filterMap_cons, List.mem_cons, ih']
      constructor
      · rintro (rfl | h | h | ⟨x, hx, h⟩)
        · exact Or.inl rfl
        · exact Or.inr (Or.inr ⟨n, by simp, Or.inl h⟩)
        · exact Or.inr (Or.inr ⟨n, by simp, Or.inr h⟩)
        · exact Or.inr (Or.inr ⟨x, by simp [hx], h⟩)
      · rintro (rfl | rfl | ⟨x, hx, h⟩)
        · exact Or.inl rfl
        · exact Or.inr (Or.inl (by omega))
        · rcases hx with rfl | hx'
          · rcases h with rfl | rfl
            · exact Or.inr (Or.inl rfl)
            · exact Or.inr (Or.inr (Or.inl rfl))
          · exact Or.inr (Or.inr (Or.inr ⟨x, hx', h⟩))

/-- The change predicate the merge and the canonical form share. -/
def changes (atoms : List NumAtom) (b : Int) : Bool := truthVec atoms (b - 1) != truthVec atoms b

/-- The merge invariant: given a fine suffix `F` continuing the current cell, the output is a
contiguous chain opening at the current cell's start whose later starts are exactly the starts of `F`
across which the truth vector changes. -/
theorem go_spec {atoms : List NumAtom} {c : Int} {rest0 : List Int} (hcs : numConsts atoms = c :: rest0) :
    ∀ (F : List FineCell) (cur : NumCell) (tv : List Bool),
    (∀ cell ∈ F, cell ∈ fineGrid (c :: rest0)) →
    Contig ((cur.lo, cur.hi) :: F) →
    (∀ h, cur.hi = some h → truthVec atoms h = tv) →
    Contig (toFine (mergeCells.go atoms cur tv F)) ∧
    (mergeCells.go atoms cur tv F).head?.map NumCell.lo = some cur.lo ∧
    ((mergeCells.go atoms cur tv F).drop 1).filterMap NumCell.lo = (F.filterMap Prod.fst).filter (changes atoms) := by
  intro F
  induction F with
  | nil =>
    intro cur tv _ hcontig _
    refine ⟨?_, by simp [mergeCells.go], by simp [mergeCells.go]⟩
    simpa [mergeCells.go, toFine] using hcontig
  | cons cell rest ih =>
    intro cur tv hmem hcontig htv
    obtain ⟨lo, hi⟩ := cell
    obtain ⟨clo, chi, crep⟩ := cur
    simp only at hcontig htv
    cases hcontig with
    | cons hne hc =>
      rename_i h
      have hcell : ((some (h + 1), hi) : FineCell) ∈ fineGrid (c :: rest0) := hmem _ (by simp)
      have hmem' : ∀ cell ∈ rest, cell ∈ fineGrid (c :: rest0) := fun x hx => hmem x (by simp [hx])
      have htvh : truthVec atoms h = tv := htv h rfl
      have hend : ∀ h', hi = some h' → truthVec atoms h' = truthVec atoms (h + 1) := by
        intro h' hh'
        subst hh'
        have hle : h + 1 ≤ h' := hc.lo_le_hi
        exact truth_const_on_fine hcs hcell ⟨by simp; omega, by simp⟩ ⟨by simp, by simp; omega⟩
      have hchanges : changes atoms (h + 1) = (truthVec atoms (h + 1) != tv) := by
        unfold changes
        rw [Int.add_sub_cancel, htvh]
        cases hb : (truthVec atoms (h + 1) == tv)
        · simp only [bne, hb, Bool.not_false]
          have : ¬ (tv = truthVec atoms (h + 1)) := fun e => by simp [e] at hb
          simpa using this
        · simp only [bne, hb, Bool.not_true]
          have : tv = truthVec atoms (h + 1) := (beq_iff_eq.mp hb).symm
          simp [this]
      show Contig (toFine (mergeCells.go atoms ⟨clo, some h, crep⟩ tv ((some (h + 1), hi) :: rest))) ∧ _ ∧ _
      have hrep : cellRep (some (h + 1)) hi = h + 1 := rfl
      simp only [mergeCells.go, hrep]
      by_cases hchg : (truthVec atoms (h + 1) == tv) = true
      · rw [if_pos hchg]
        have heq : truthVec atoms (h + 1) = tv := beq_iff_eq.mp hchg
        have hcont' : Contig ((clo, hi) :: rest) := hc.replace_lo (fun l2 hl2 => by have := hne l2 hl2; omega)
        have htv' : ∀ h', hi = some h' → truthVec atoms h' = tv := fun h' hh' => (hend h' hh').trans heq
        obtain ⟨c1, c2, c3⟩ := ih ⟨clo, hi, crep⟩ tv hmem' hcont' htv'
        refine ⟨c1, c2, ?_⟩
        rw [c3]
        have hf : changes atoms (h + 1) = false := by rw [hchanges, heq]; simp
        simp [List.filterMap_cons, List.filter_cons, hf]
      · rw [if_neg hchg]
        have hne' : truthVec atoms (h + 1) ≠ tv := fun e => hchg (beq_iff_eq.mpr e)
        obtain ⟨c1, c2, c3⟩ := ih ⟨some (h + 1), hi, h + 1⟩ (truthVec atoms (h + 1)) hmem' hc hend
        obtain ⟨o, tl, ho⟩ : ∃ o tl, mergeCells.go atoms ⟨some (h + 1), hi, h + 1⟩ (truthVec atoms (h + 1)) rest = o :: tl := by
          cases hO : mergeCells.go atoms ⟨some (h + 1), hi, h + 1⟩ (truthVec atoms (h + 1)) rest with
          | nil => rw [hO] at c2; simp at c2
          | cons o tl => exact ⟨o, tl, rfl⟩
        rw [ho] at c1 c2 c3 ⊢
        simp only [List.head?_cons, Option.map_some, Option.some.injEq] at c2
        refine ⟨?_, by simp, ?_⟩
        · simp only [toFine, List.map_cons] at c1 ⊢
          rw [c2] at c1 ⊢
          exact Contig.cons hne c1
        · have ht : changes atoms (h + 1) = true := by rw [hchanges]; simpa using hne'
          simp only [List.drop_succ_cons, List.drop_zero, List.filterMap_cons, c2, List.filter_cons, ht] at c3 ⊢
          rw [c3]; simp

/-- The merged cells of a numeric partition: a contiguous chain opening unbounded below, whose starts are
exactly the fine starts across which the truth vector changes. -/
theorem numericCells_spec {atoms : List NumAtom} {c : Int} {rest0 : List Int} (hcs : numConsts atoms = c :: rest0) :
    Contig (toFine (numericCells atoms)) ∧
    (numericCells atoms).head?.map NumCell.lo = some none ∧
    ((numericCells atoms).drop 1).filterMap NumCell.lo =
      ((fineGrid.fineFrom c rest0).filterMap Prod.fst).filter (changes atoms) := by
  have hp : (c :: rest0).Pairwise (· < ·) := hcs ▸ numConsts_sorted atoms
  have hfg : fineGrid (c :: rest0) = (none, some (c - 1)) :: fineGrid.fineFrom c rest0 := rfl
  have hcontig := fineGrid_contig hp
  rw [hfg] at hcontig
  unfold numericCells
  rw [hcs, hfg]
  simp only [mergeCells]
  exact go_spec hcs (fineGrid.fineFrom c rest0) ⟨none, some (c - 1), cellRep none (some (c - 1))⟩
    (truthVec atoms (cellRep none (some (c - 1))))
    (fun cell hcell => by rw [hfg]; exact List.mem_cons_of_mem _ hcell)
    hcontig
    (fun h hh => by cases hh; rfl)

/-! ## Stage five: the theorem -/

theorem numConsts_ne_nil (atoms : List NumAtom) : numConsts atoms ≠ [] := by
  unfold numConsts
  intro h
  generalize hraw : atoms.foldr (fun a acc =>
      match a with
      | .cmp _ c => c :: acc
      | .mem cs  => cs ++ acc
      | .nmem cs => cs ++ acc
      | .truthy  => 0 :: acc) [] = raw at h
  have hmem : ∃ y, y ∈ (if raw.isEmpty then [0] else raw) := by
    cases raw with
    | nil => exact ⟨0, by simp⟩
    | cons x xs => exact ⟨x, by simp⟩
  obtain ⟨y, hy⟩ := hmem
  have : y ∈ ((if raw.isEmpty then [0] else raw).mergeSort (· ≤ ·)).dedup := by
    rw [List.mem_dedup, List.mem_mergeSort]; exact hy
  rw [h] at this
  simp at this

/-- **The reference algorithm equals the canonical form.** -/
theorem symbolAlg_eq_symbolCount (atoms : List NumAtom) (v : Int) :
    symbolAlg atoms v = symbolCount atoms v := by
  obtain ⟨c, rest0, hcs⟩ : ∃ c rest0, numConsts atoms = c :: rest0 := by
    cases h : numConsts atoms with
    | nil => exact absurd h (numConsts_ne_nil atoms)
    | cons c rest0 => exact ⟨c, rest0, rfl⟩
  obtain ⟨hcontig, hhead, hstarts⟩ := numericCells_spec hcs
  have hp : (c :: rest0).Pairwise (· < ·) := hcs ▸ numConsts_sorted atoms
  unfold symbolAlg
  rw [findIdx_contig _ hcontig v (fun c0 tl heq l hl => by
    rw [heq] at hhead; simp at hhead; rw [hhead] at hl; cases hl)]
  rw [hstarts]
  unfold symbolCount retained
  apply List.Perm.countP_eq
  apply (List.perm_ext_iff_of_nodup ?_ ?_).mpr
  · intro b
    rw [List.mem_filter, List.mem_filter, hcs]
    constructor
    · rintro ⟨hb, hch⟩
      refine ⟨?_, by simpa [changes] using hch⟩
      rw [mem_boundaries_iff]
      have := (mem_fineFrom_starts c rest0 (fun x hx => List.rel_of_pairwise_cons hp hx) (List.Pairwise.of_cons hp) b).mp hb
      rcases this with hbc | hbc | ⟨x, hx, hb'⟩
      · exact ⟨c, by simp, Or.inl hbc⟩
      · exact ⟨c, by simp, Or.inr hbc⟩
      · exact ⟨x, by simp [hx], hb'⟩
    · rintro ⟨hb, hch⟩
      refine ⟨?_, by simpa [changes] using hch⟩
      rw [mem_boundaries_iff] at hb
      rw [mem_fineFrom_starts c rest0 (fun x hx => List.rel_of_pairwise_cons hp hx) (List.Pairwise.of_cons hp) b]
      obtain ⟨x, hx, hb'⟩ := hb
      rcases List.mem_cons.mp hx with hxc | hx'
      · subst hxc
        rcases hb' with hb1 | hb1
        · exact Or.inl hb1
        · exact Or.inr (Or.inl hb1)
      · exact Or.inr (Or.inr ⟨x, hx', hb'⟩)
  · -- the merged starts are strictly increasing
    have := contig_starts_sorted _ hcontig
    rw [starts_toFine, hstarts] at this
    exact this.nodup
  · exact (retained_sorted atoms).nodup

/-- **I1 for the reference algorithm itself.** Two integers the reference quantizer puts in one cell have
the same atom truth vector. -/
theorem symbolAlg_eq_truthVec {atoms : List NumAtom} {v w : Int}
    (h : symbolAlg atoms v = symbolAlg atoms w) : truthVec atoms v = truthVec atoms w :=
  symbolCount_eq_truthVec (by rwa [symbolAlg_eq_symbolCount, symbolAlg_eq_symbolCount] at h)

end FQ
