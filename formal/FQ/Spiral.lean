-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import Mathlib.Tactic
import FQ.Partition
/-!
# The spiral layout (Tier 6 packing), `prismpath/telemetry/spiral.py`

A node's joint cell space is the mixed radix product of its fields' cell counts. The reference
enumerates it in reflected Gray order, buckets the cells by the route their representative takes,
and lays the buckets out contiguously in route order: the spiral index of a cell is its position in
that layout, and the band of an index is the bucket it falls in. This file proves the layout is a
bijection between cells and indices, and that the band of an index determines the route of its cell.

What is proven here is about the layout as a function of an arbitrary `routeOf`; composing with
`reconstruct_route` (a cell's representative routes as every reading in the cell does) gives the
decision preservation of the band symbol. The Gray adjacency property (consecutive cells differ in
one digit) is a locality optimization, not part of the bijection, and is not proven here.
-/

namespace FQ.Spiral

open List

abbrev Cell := List ℕ

/-- The full mixed radix product, lexicographic. -/
def product : List ℕ → List Cell
  | [] => [[]]
  | r :: rest => (List.range r).flatMap (fun d => (product rest).map (d :: ·))

/-- The reflected Gray enumeration: the sub enumeration alternates direction with each leading digit.
Equal to the reference's iterative `mixed_radix_gray` (checked against it in `FQ/Vectors.lean`). -/
def gray : List ℕ → List Cell
  | [] => [[]]
  | r :: rest => (List.range r).flatMap
      (fun d => (if d % 2 = 0 then gray rest else (gray rest).reverse).map (d :: ·))

theorem perm_flatMap {α β : Type} {l : List α} {f g : α → List β}
    (h : ∀ a ∈ l, (f a).Perm (g a)) : (l.flatMap f).Perm (l.flatMap g) := by
  induction l with
  | nil => simp
  | cons a rest ih =>
    simp only [List.flatMap_cons]
    exact (h a (by simp)).append (ih (fun b hb => h b (by simp [hb])))

/-- The Gray enumeration is a permutation of the product. -/
theorem gray_perm_product : ∀ radices : List ℕ, (gray radices).Perm (product radices) := by
  intro radices
  induction radices with
  | nil => simp [gray, product]
  | cons r rest ih =>
    simp only [gray, product]
    apply perm_flatMap
    intro d _
    split
    · exact ih.map _
    · exact ((List.reverse_perm _).trans ih).map _

theorem mem_product : ∀ (radices : List ℕ) (c : Cell), c ∈ product radices ↔ List.Forall₂ (· < ·) c radices := by
  intro radices
  induction radices with
  | nil => intro c; simp [product]
  | cons r rest ih =>
    intro c
    simp only [product, List.mem_flatMap, List.mem_range, List.mem_map]
    constructor
    · rintro ⟨d, hd, c', hc', rfl⟩
      exact List.forall₂_cons.mpr ⟨hd, (ih c').mp hc'⟩
    · intro h
      cases c with
      | nil => cases h
      | cons d c' =>
        obtain ⟨hd, hc'⟩ := List.forall₂_cons.mp h
        exact ⟨d, hd, c', (ih c').mpr hc', rfl⟩

theorem product_nodup : ∀ radices : List ℕ, (product radices).Nodup := by
  intro radices
  induction radices with
  | nil => simp [product]
  | cons r rest ih =>
    simp only [product]
    rw [List.nodup_flatMap]
    refine ⟨fun d _ => ih.map (fun a b h => List.cons.inj h |>.2), ?_⟩
    have : (List.range r).Pairwise (· ≠ ·) := List.nodup_range
    refine this.imp ?_
    intro a b hab
    intro c hca hcb
    simp only [List.mem_map] at hca hcb
    obtain ⟨_, _, rfl⟩ := hca
    obtain ⟨_, _, h⟩ := hcb
    exact hab (List.cons.inj h).1.symm

theorem gray_nodup (radices : List ℕ) : (gray radices).Nodup :=
  (gray_perm_product radices).nodup_iff.mpr (product_nodup radices)

theorem mem_gray (radices : List ℕ) (c : Cell) : c ∈ gray radices ↔ List.Forall₂ (· < ·) c radices :=
  (gray_perm_product radices).mem_iff.trans (mem_product radices c)

/-! ## Bucketing by route -/

/-- One bucket per route, in route order: the cells (in enumeration order) routing there. -/
def bands (cells : List Cell) (routeOf : Cell → Option String) (routes : List (Option String)) : List (List Cell) :=
  routes.map (fun r => cells.filter (fun c => routeOf c == r))

/-- The layout: the buckets laid out contiguously. A cell's spiral index is its position here. -/
def layout (cells : List Cell) (routeOf : Cell → Option String) (routes : List (Option String)) : List Cell :=
  (bands cells routeOf routes).flatten

/-- The reference's route order: reversed first appearance of the node's targets (baseline central),
an unrouted cell last, keeping only routes some cell takes. -/
def routesFor (p : Policy String) (cells : List Cell) (routeOf : Cell → Option String) : List (Option String) :=
  (((p.map (fun (r : Rule String) => some r.act)).eraseDups.reverse) ++ [none]).filter (fun r => cells.any (fun c => routeOf c == r))

theorem layout_perm {cells : List Cell} {routeOf : Cell → Option String} :
    ∀ (routes : List (Option String)), routes.Nodup → (∀ c ∈ cells, routeOf c ∈ routes) →
    (layout cells routeOf routes).Perm cells := by
  intro routes
  induction routes generalizing cells with
  | nil =>
    intro _ hcov
    cases cells with
    | nil => simp [layout, bands]
    | cons c cs => exact absurd (hcov c (by simp)) (by simp)
  | cons r rs ih =>
    intro hnd hcov
    have hr : r ∉ rs := (List.nodup_cons.mp hnd).1
    have hnd' : rs.Nodup := (List.nodup_cons.mp hnd).2
    simp only [layout, bands, List.map_cons, List.flatten_cons]
    -- the remaining buckets are unchanged when the cells routing to r are removed first
    have hrest : (rs.map (fun r' => cells.filter (fun c => routeOf c == r'))).flatten
        = (rs.map (fun r' => (cells.filter (fun c => !(routeOf c == r))).filter (fun c => routeOf c == r'))).flatten := by
      congr 1
      apply List.map_congr_left
      intro r' hr'
      rw [List.filter_filter]
      apply List.filter_congr
      intro c _
      have : r' ≠ r := fun e => hr (e ▸ hr')
      by_cases h : routeOf c = r'
      · rw [h]
        have h3 : (r' == r) = false := beq_eq_false_iff_ne.mpr this
        simp [h3]
      · simp [h]
    rw [hrest]
    have hcov' : ∀ c ∈ cells.filter (fun c => !(routeOf c == r)), routeOf c ∈ rs := by
      intro c hc
      rw [List.mem_filter] at hc
      have h1 := hcov c hc.1
      have h2 : routeOf c ≠ r := by simpa using hc.2
      rcases List.mem_cons.mp h1 with h | h
      · exact absurd h h2
      · exact h
    have ih' := ih (cells := cells.filter (fun c => !(routeOf c == r))) hnd' hcov'
    simp only [layout, bands] at ih'
    exact ((List.Perm.refl _).append ih').trans (List.filter_append_perm _ cells)

theorem layout_nodup {cells : List Cell} {routeOf : Cell → Option String} {routes : List (Option String)}
    (hnd : routes.Nodup) (hcov : ∀ c ∈ cells, routeOf c ∈ routes) (hcells : cells.Nodup) :
    (layout cells routeOf routes).Nodup :=
  (layout_perm routes hnd hcov).nodup_iff.mpr hcells

theorem mem_layout {cells : List Cell} {routeOf : Cell → Option String} {routes : List (Option String)}
    (hnd : routes.Nodup) (hcov : ∀ c ∈ cells, routeOf c ∈ routes) (c : Cell) :
    c ∈ layout cells routeOf routes ↔ c ∈ cells :=
  (layout_perm routes hnd hcov).mem_iff

theorem length_layout {cells : List Cell} {routeOf : Cell → Option String} {routes : List (Option String)}
    (hnd : routes.Nodup) (hcov : ∀ c ∈ cells, routeOf c ∈ routes) :
    (layout cells routeOf routes).length = cells.length :=
  (layout_perm routes hnd hcov).length_eq

/-! ## The bijection: index of a cell, cell of an index -/

/-- **Bijection, one direction.** The cell at an index has that index. -/
theorem idxOf_getElem_layout {L : List Cell} (hL : L.Nodup) (n : ℕ) (hn : n < L.length) :
    L.idxOf L[n] = n :=
  hL.idxOf_getElem n hn

/-- **Bijection, the other direction.** The index of a cell in the layout is the position of that cell. -/
theorem getElem_idxOf_layout {L : List Cell} {c : Cell} (hc : c ∈ L) :
    L[L.idxOf c]'(List.idxOf_lt_length_iff.mpr hc) = c :=
  List.getElem_idxOf _

/-- The Gray layout of a mixed radix space is a bijection between the cells of the space (`Forall₂ (· < ·)`
against the radices) and the indices below its size. -/
theorem spiral_bijection (radices : List ℕ) (routeOf : Cell → Option String) (routes : List (Option String))
    (hnd : routes.Nodup) (hcov : ∀ c ∈ gray radices, routeOf c ∈ routes) :
    let L := layout (gray radices) routeOf routes
    L.Nodup ∧ (∀ c, c ∈ L ↔ List.Forall₂ (· < ·) c radices) ∧
    (∀ n (hn : n < L.length), L.idxOf L[n] = n) ∧
    (∀ c (hc : c ∈ L), L[L.idxOf c]'(List.idxOf_lt_length_iff.mpr hc) = c) := by
  intro L
  have hnodup : L.Nodup := layout_nodup hnd hcov (gray_nodup radices)
  refine ⟨hnodup, fun c => (mem_layout hnd hcov c).trans (mem_gray radices c), ?_, ?_⟩
  · intro n hn; exact idxOf_getElem_layout hnodup n hn
  · intro c hc; exact getElem_idxOf_layout hc

/-! ## Bands determine routes -/

/-- The band (bucket index) an index falls in. -/
def bandOf : List (List Cell) → ℕ → Option ℕ
  | [], _ => none
  | B :: Bs, n => if n < B.length then some 0 else (bandOf Bs (n - B.length)).map (· + 1)

theorem flatten_mem_band : ∀ (Bs : List (List Cell)) (n : ℕ) (h : n < Bs.flatten.length),
    ∃ b, bandOf Bs n = some b ∧ ∃ hb : b < Bs.length, Bs.flatten[n] ∈ Bs[b] := by
  intro Bs
  induction Bs with
  | nil => intro n h; simp at h
  | cons B Bs ih =>
    intro n h
    simp only [List.flatten_cons] at h ⊢
    by_cases hn : n < B.length
    · refine ⟨0, by simp [bandOf, hn], by simp, ?_⟩
      rw [List.getElem_append_left hn]
      exact List.getElem_mem _
    · have hlen : n - B.length < Bs.flatten.length := by
        simp only [List.length_append] at h; omega
      obtain ⟨b, hb, hblt, hmem⟩ := ih (n - B.length) hlen
      refine ⟨b + 1, by simp [bandOf, hn, hb], by simpa using hblt, ?_⟩
      rw [List.getElem_append_right (by omega)]
      simpa using hmem

/-- **Bands determine routes.** The cell at index `n` of the layout routes to the route of its band. -/
theorem band_route {cells : List Cell} {routeOf : Cell → Option String} {routes : List (Option String)}
    (n : ℕ) (hn : n < (layout cells routeOf routes).length) :
    ∃ b, bandOf (bands cells routeOf routes) n = some b ∧
      ∃ hb : b < routes.length, routeOf (layout cells routeOf routes)[n] = routes[b] := by
  obtain ⟨b, hb, hblt, hmem⟩ := flatten_mem_band (bands cells routeOf routes) n hn
  refine ⟨b, hb, by simpa [bands] using hblt, ?_⟩
  simp only [bands, List.getElem_map, List.mem_filter, beq_iff_eq] at hmem
  exact hmem.2

/-- Two indices in the same band have cells with the same route: the band symbol is decision sufficient. -/
theorem band_eq_route_eq {cells : List Cell} {routeOf : Cell → Option String} {routes : List (Option String)}
    (n m : ℕ) (hn : n < (layout cells routeOf routes).length) (hm : m < (layout cells routeOf routes).length)
    (h : bandOf (bands cells routeOf routes) n = bandOf (bands cells routeOf routes) m) :
    routeOf (layout cells routeOf routes)[n] = routeOf (layout cells routeOf routes)[m] := by
  obtain ⟨b, hb, hblt, hr⟩ := band_route (cells := cells) (routeOf := routeOf) (routes := routes) n hn
  obtain ⟨b', hb', hblt', hr'⟩ := band_route (cells := cells) (routeOf := routeOf) (routes := routes) m hm
  rw [hb, hb'] at h
  have : b = b' := Option.some.inj h
  subst this
  rw [hr, hr']

/-! ## Cell counts, for the radices of a policy's partitions -/

def cellCount : FieldPartition → ℕ
  | .numeric _ atoms => (retained atoms).length + 1
  | .boolean _ => 2
  | .categorical _ cs => cs.length + 1

end FQ.Spiral
