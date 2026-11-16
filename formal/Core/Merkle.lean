-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
/-!
# The evidence tree: RFC 6962's Merkle tree, and why the retired one was not enough

`Core/Evidence.lean` takes the Merkle root of a run's receipts as a parameter (`Crypto.merkle`) and the
tree's collision resistance as a hypothesis (`NoTreeCollision`). This file models the tree the verifiers
compute (`prismpath/ledgers/ledger_ots.py`, `prismpath-rs/src/merkle.rs`): RFC 6962's, where a leaf hashes
as `leafHash` (SHA-256 of 0x00 and the leaf), an inner node as `nodeHash` (SHA-256 of 0x01 and both
children), and a tree over n ≥ 2 leaves splits at `split n`, the largest power of two below n.

* `mth_injective`: two nonempty lists of leaves with one root are the same list, of any lengths, unless the
  hashes exhibit a collision: two leaves with one leaf hash, two pairs of children with one node hash, or a
  leaf hash equal to a node hash. So the tree's half of `NoTreeCollision` holds for every list that exhibits
  no SHA-256 collision, whatever its length.
* `retired_collides`: the tree before it (no domain prefixes, the last node of an odd layer paired with
  itself) gives [a, b, c] and [a, b, c, c] one root for every hash, so a root alone never fixed the number
  of receipts under it, and only the statement's leaf count told the two apart.
* `acc_root_eq_mth`: the streaming form the verifiers use to keep a root as leaves arrive (the peaks of the
  perfect subtrees, added by binary counter carry and folded into a root) gives the same root as `mth` for
  every nonempty list of leaves and every hash, and `accPeaks_length_le` bounds its state at 64 peaks for
  fewer than `2 ^ 64` leaves.

The hash is a parameter; that SHA-256 exhibits no collision on the run's inputs is the hypothesis, as in
`Core/Evidence.lean`. Lean core only, no Mathlib.
-/

namespace Core

namespace Merkle

/-- Double `k` while `2k` is below `n`, at most `fuel` times. -/
def splitGo : Nat → Nat → Nat → Nat
  | 0, k, _ => k
  | fuel + 1, k, n => if 2 * k < n then splitGo fuel (2 * k) n else k

/-- RFC 6962's split for a tree over `n` ≥ 2 leaves: the largest power of two below `n`. -/
def split (n : Nat) : Nat := splitGo n 1 n

theorem splitGo_bounds : ∀ (fuel k n : Nat), 1 ≤ k → k < n → 1 ≤ splitGo fuel k n ∧ splitGo fuel k n < n
  | 0, _, _, h1, h2 => ⟨h1, h2⟩
  | fuel + 1, k, n, h1, h2 => by
    unfold splitGo
    split
    · exact splitGo_bounds fuel (2 * k) n (by omega) (by omega)
    · exact ⟨h1, h2⟩

theorem split_bounds {n : Nat} (h : 2 ≤ n) : 1 ≤ split n ∧ split n < n :=
  splitGo_bounds n 1 n (by omega) (by omega)

/-- The split is the largest power of two below the count, for the counts a test vector uses. -/
example : (List.range 18).map (fun n => split (n + 2)) = [1, 2, 2, 4, 4, 4, 4, 8, 8, 8, 8, 8, 8, 8, 8, 16, 16, 16] := by
  decide

variable {L D : Type}

/-- RFC 6962's Merkle tree hash (section 2.1) over a list of leaves; `empty` for none. -/
def mth (leafHash : L → D) (nodeHash : D → D → D) (empty : D) : List L → D
  | [] => empty
  | [a] => leafHash a
  | a :: b :: rest =>
    have h := split_bounds (n := (a :: b :: rest).length) (by simp)
    nodeHash (mth leafHash nodeHash empty ((a :: b :: rest).take (split (a :: b :: rest).length)))
      (mth leafHash nodeHash empty ((a :: b :: rest).drop (split (a :: b :: rest).length)))
termination_by l => l.length
decreasing_by
  all_goals simp only [List.length_take, List.length_drop]
  all_goals omega

/-- What a collision of the tree's hashes is: two leaves with one leaf hash, two pairs of children with
one node hash, or a leaf hash that is also a node hash. -/
def Collision (leafHash : L → D) (nodeHash : D → D → D) : Prop :=
  (∃ a b, a ≠ b ∧ leafHash a = leafHash b) ∨
    (∃ a b c d, (a ≠ c ∨ b ≠ d) ∧ nodeHash a b = nodeHash c d) ∨
    (∃ a b c, leafHash a = nodeHash b c)

theorem mth_cons_cons (leafHash : L → D) (nodeHash : D → D → D) (empty : D) (a b : L) (rest : List L) :
    mth leafHash nodeHash empty (a :: b :: rest) =
      nodeHash (mth leafHash nodeHash empty ((a :: b :: rest).take (split (a :: b :: rest).length)))
        (mth leafHash nodeHash empty ((a :: b :: rest).drop (split (a :: b :: rest).length))) := by
  rw [mth]

/-- The tree is injective on nonempty lists when its hashes are: one root, one list, of any length. -/
theorem mth_injective_of {leafHash : L → D} {nodeHash : D → D → D} {empty : D}
    (hleaf : ∀ a b, leafHash a = leafHash b → a = b)
    (hnode : ∀ a b c d, nodeHash a b = nodeHash c d → a = c ∧ b = d)
    (hsep : ∀ a b c, leafHash a ≠ nodeHash b c) :
    ∀ (n : Nat) (l₁ l₂ : List L), l₁.length + l₂.length ≤ n → l₁ ≠ [] → l₂ ≠ [] →
      mth leafHash nodeHash empty l₁ = mth leafHash nodeHash empty l₂ → l₁ = l₂
  | 0, l₁, l₂, hn, h₁, _, _ => by
    cases l₁ with
    | nil => exact absurd rfl h₁
    | cons _ _ => simp at hn
  | n + 1, l₁, l₂, hn, h₁, h₂, heq => by
    match l₁, l₂, h₁, h₂ with
    | [a], [b], _, _ => simp only [mth] at heq; rw [hleaf a b heq]
    | [a], b :: c :: rest, _, _ =>
      rw [mth_cons_cons] at heq; simp only [mth] at heq; exact absurd heq (hsep _ _ _)
    | a :: b :: rest, [c], _, _ =>
      rw [mth_cons_cons] at heq; simp only [mth] at heq; exact absurd heq.symm (hsep _ _ _)
    | a :: b :: r₁, c :: d :: r₂, _, _ =>
      rw [mth_cons_cons, mth_cons_cons] at heq
      obtain ⟨hl, hr⟩ := hnode _ _ _ _ heq
      have b₁ := split_bounds (n := (a :: b :: r₁).length) (by simp)
      have b₂ := split_bounds (n := (c :: d :: r₂).length) (by simp)
      have len₁ : (a :: b :: r₁).length = r₁.length + 2 := by simp
      have len₂ : (c :: d :: r₂).length = r₂.length + 2 := by simp
      have ht := mth_injective_of hleaf hnode hsep n _ _
        (by simp only [List.length_take]; omega)
        (by intro h; have := congrArg List.length h; simp only [List.length_take, List.length_nil] at this; omega)
        (by intro h; have := congrArg List.length h; simp only [List.length_take, List.length_nil] at this; omega) hl
      have hd := mth_injective_of hleaf hnode hsep n _ _
        (by simp only [List.length_drop]; omega)
        (by intro h; have := congrArg List.length h; simp only [List.length_drop, List.length_nil] at this; omega)
        (by intro h; have := congrArg List.length h; simp only [List.length_drop, List.length_nil] at this; omega) hr
      rw [← List.take_append_drop (split (a :: b :: r₁).length) (a :: b :: r₁),
        ← List.take_append_drop (split (c :: d :: r₂).length) (c :: d :: r₂), ht, hd]

/-- **One root, one list.** Two nonempty lists of leaves with one RFC 6962 root are the same list, of any
lengths, or the hashes exhibit a `Collision`. -/
theorem mth_injective {leafHash : L → D} {nodeHash : D → D → D} {empty : D} {l₁ l₂ : List L}
    (h₁ : l₁ ≠ []) (h₂ : l₂ ≠ []) (heq : mth leafHash nodeHash empty l₁ = mth leafHash nodeHash empty l₂) :
    l₁ = l₂ ∨ Collision leafHash nodeHash := by
  open Classical in
  by_cases hc : Collision leafHash nodeHash
  · exact Or.inr hc
  · left
    refine mth_injective_of (empty := empty) ?_ ?_ ?_ _ l₁ l₂ (Nat.le_refl _) h₁ h₂ heq
    · intro a b h
      exact Classical.byContradiction fun hab => hc (Or.inl ⟨a, b, hab, h⟩)
    · intro a b c d h
      exact Classical.byContradiction fun habcd =>
        hc (Or.inr (Or.inl ⟨a, b, c, d, by
          by_cases hac : a = c
          · exact Or.inr fun hbd => habcd ⟨hac, hbd⟩
          · exact Or.inl hac, h⟩))
    · intro a b c h
      exact hc (Or.inr (Or.inr ⟨a, b, c, h⟩))

/-- In particular [a, b, c] and [a, b, c, c] have different RFC 6962 roots unless the hashes collide. -/
theorem mth_repeated_last {leafHash : L → D} {nodeHash : D → D → D} {empty : D} (a b c : L)
    (hc : ¬ Collision leafHash nodeHash) :
    mth leafHash nodeHash empty [a, b, c] ≠ mth leafHash nodeHash empty [a, b, c, c] := by
  intro heq
  rcases mth_injective (by simp) (by simp) heq with h | h
  · simp at h
  · exact hc h

/-! ## The streaming form

The verifiers that keep a root as leaves arrive (`root_statement.MerkleAccumulator` in Python,
`merkle::Accumulator` in Rust, `ppt_merkle_acc` in `prismpath-ebpf/merkle.h`) hold no leaves, only the peaks:
the roots of the perfect subtrees, one per set bit of the leaf count. A leaf is pushed as a subtree of height
0 and merges with the shortest peak while the two have one height (binary counter carry); the root folds the
peaks from the shortest up, each taller peak the left child. `acc_root_eq_mth` proves this is RFC 6962's root
for every nonempty list and every hash, and `accPeaks_length_le` that fewer than `2 ^ 64` leaves need at most
64 peaks. -/

theorem splitGo_pow (n h : Nat) (hlo : 2 ^ h < n) (hhi : n ≤ 2 ^ (h + 1)) :
    ∀ (fuel j : Nat), j ≤ h → h - j ≤ fuel → splitGo fuel (2 ^ j) n = 2 ^ h
  | 0, j, hj, hf => by
    have : j = h := by omega
    subst this; rfl
  | fuel + 1, j, hj, hf => by
    unfold splitGo
    split
    · rename_i hlt
      have hj' : j + 1 ≤ h := by
        apply Classical.byContradiction
        intro hne
        have : j = h := by omega
        subst this
        rw [Nat.pow_succ] at hhi
        omega
      rw [show 2 * 2 ^ j = 2 ^ (j + 1) by rw [Nat.pow_succ]; omega]
      exact splitGo_pow n h hlo hhi fuel (j + 1) hj' (by omega)
    · rename_i hge
      have : j = h := by
        apply Classical.byContradiction
        intro hne
        have : 2 ^ (j + 1) ≤ 2 ^ h := Nat.pow_le_pow_right (by omega) (by omega)
        rw [Nat.pow_succ] at this
        omega
      rw [this]

/-- The split is the largest power of two below the count: `2 ^ h` for every `n` with `2 ^ h < n ≤ 2 ^ (h + 1)`. -/
theorem split_pow {n h : Nat} (hlo : 2 ^ h < n) (hhi : n ≤ 2 ^ (h + 1)) : split n = 2 ^ h := by
  have := splitGo_pow n h hlo hhi n 0 (by omega) (by have := @Nat.lt_two_pow_self h; omega)
  simpa [split] using this

/-- A perfect subtree of `2 ^ h` leaves followed by at least one and at most `2 ^ h` more: the tree splits
between them. -/
theorem mth_append (leafHash : L → D) (nodeHash : D → D → D) (empty : D) {s t : List L} {h : Nat}
    (hs : s.length = 2 ^ h) (ht0 : 0 < t.length) (ht : t.length ≤ 2 ^ h) :
    mth leafHash nodeHash empty (s ++ t) =
      nodeHash (mth leafHash nodeHash empty s) (mth leafHash nodeHash empty t) := by
  have hsplit : split (s ++ t).length = s.length := by
    rw [hs]; apply split_pow
    · simp only [List.length_append]; omega
    · simp only [List.length_append, Nat.pow_succ]; omega
  have h2 : 2 ≤ (s ++ t).length := by
    simp only [List.length_append]; have := @Nat.one_le_two_pow h; omega
  match hst : s ++ t, h2 with
  | a :: b :: rest, _ =>
    rw [mth_cons_cons, ← hst, hsplit, List.take_left' rfl, List.drop_left' rfl]

/-- Push a perfect subtree of height `h` and hash `x` onto the peaks (shortest first): while the shortest
peak has the same height the two are siblings and merge one level up, the old peak on the left. Binary
counter carry. -/
def push (nodeHash : D → D → D) : Nat → D → List (Nat × D) → List (Nat × D)
  | h, x, [] => [(h, x)]
  | h, x, (h', p) :: rest => if h' = h then push nodeHash (h + 1) (nodeHash p x) rest else (h, x) :: (h', p) :: rest

/-- Add one leaf hash. -/
def accAddHash (nodeHash : D → D → D) (peaks : List (Nat × D)) (x : D) : List (Nat × D) :=
  push nodeHash 0 x peaks

/-- Add one leaf. -/
def accAdd (leafHash : L → D) (nodeHash : D → D → D) (peaks : List (Nat × D)) (a : L) : List (Nat × D) :=
  accAddHash nodeHash peaks (leafHash a)

/-- The peaks after the leaves, added one at a time from none. -/
def accPeaks (leafHash : L → D) (nodeHash : D → D → D) (leaves : List L) : List (Nat × D) :=
  leaves.foldl (accAdd leafHash nodeHash) []

/-- The root the peaks give: none for none; otherwise the shortest peak, and each taller peak hashed as the
left child of what is folded so far. -/
def peaksRoot (nodeHash : D → D → D) : List (Nat × D) → Option D
  | [] => none
  | (_, p) :: rest => some (rest.foldl (fun acc q => nodeHash q.2 acc) p)

/-- The streaming root over the leaves. -/
def accRoot (leafHash : L → D) (nodeHash : D → D → D) (leaves : List L) : Option D :=
  peaksRoot nodeHash (accPeaks leafHash nodeHash leaves)

/-- `Rep b peaks l`: the peaks, shortest first, are the roots of perfect subtrees whose leaves, tallest
first, are `l`, their heights strictly rising and none below `b`. -/
inductive Rep (leafHash : L → D) (nodeHash : D → D → D) (empty : D) : Nat → List (Nat × D) → List L → Prop
  | nil (b : Nat) : Rep leafHash nodeHash empty b [] []
  | cons {b h : Nat} {ps : List (Nat × D)} {l s : List L} :
      Rep leafHash nodeHash empty (h + 1) ps l → s.length = 2 ^ h → b ≤ h →
      Rep leafHash nodeHash empty b ((h, mth leafHash nodeHash empty s) :: ps) (l ++ s)

section
variable {leafHash : L → D} {nodeHash : D → D → D} {empty : D}

theorem Rep.mono {b b' : Nat} {ps : List (Nat × D)} {l : List L}
    (hr : Rep leafHash nodeHash empty b ps l) (hb : b' ≤ b) : Rep leafHash nodeHash empty b' ps l := by
  cases hr with
  | nil => exact Rep.nil _
  | cons hr hs hbh => exact Rep.cons hr hs (by omega)

theorem Rep.push {h : Nat} {ps : List (Nat × D)} {l s : List L}
    (hr : Rep leafHash nodeHash empty h ps l) (hs : s.length = 2 ^ h) :
    Rep leafHash nodeHash empty h (push nodeHash h (mth leafHash nodeHash empty s) ps) (l ++ s) := by
  induction ps generalizing h l s with
  | nil =>
    cases hr
    exact Rep.cons (Rep.nil _) hs (Nat.le_refl _)
  | cons top rest ih =>
    obtain ⟨h', p⟩ := top
    cases hr with
    | cons hr' hs' hbh =>
      rename_i l' s'
      unfold Merkle.push
      split
      · rename_i heq
        subst heq
        rw [← mth_append leafHash nodeHash empty hs' (by rw [hs]; exact Nat.one_le_two_pow) (by omega)]
        have := ih hr' (s := s' ++ s) (by simp only [List.length_append, Nat.pow_succ]; omega)
        rw [List.append_assoc]
        exact this.mono (by omega)
      · rename_i hne
        exact Rep.cons (Rep.cons hr' hs' (by omega)) hs (Nat.le_refl _)

/-- The fold of the peaks with what is folded so far the root of a shorter tail `t`. -/
theorem Rep.fold {b : Nat} {ps : List (Nat × D)} {l t : List L}
    (hr : Rep leafHash nodeHash empty b ps l) (ht0 : 0 < t.length) (ht : t.length < 2 ^ b) :
    ps.foldl (fun acc q => nodeHash q.2 acc) (mth leafHash nodeHash empty t) =
      mth leafHash nodeHash empty (l ++ t) := by
  induction hr generalizing t with
  | nil => rfl
  | cons hr hs hbh ih =>
    rename_i b' h ps l s
    simp only [List.foldl_cons]
    have hb : 2 ^ b' ≤ 2 ^ h := Nat.pow_le_pow_right (by omega) hbh
    rw [← mth_append leafHash nodeHash empty hs ht0 (by omega), List.append_assoc]
    exact ih (by simp only [List.length_append]; omega)
      (by simp only [List.length_append, Nat.pow_succ]; omega)

theorem Rep.root {b : Nat} {ps : List (Nat × D)} {l : List L} (hr : Rep leafHash nodeHash empty b ps l) :
    peaksRoot nodeHash ps = if l = [] then none else some (mth leafHash nodeHash empty l) := by
  cases hr with
  | nil => rfl
  | cons hr hs hbh =>
    rename_i h ps l s
    have hne : l ++ s ≠ [] := by
      intro he; have := congrArg List.length he
      simp only [List.length_append, List.length_nil, hs] at this; have := @Nat.one_le_two_pow h; omega
    simp only [peaksRoot, hne, if_false]
    have h1 := @Nat.one_le_two_pow h
    have hf := hr.fold (t := s) (by omega) (by rw [hs, Nat.pow_succ]; omega)
    rw [hf]

theorem rep_accPeaks (leaves : List L) :
    Rep leafHash nodeHash empty 0 (accPeaks leafHash nodeHash leaves) leaves := by
  rw [accPeaks, ← List.reverse_reverse leaves]
  induction leaves.reverse with
  | nil => exact Rep.nil 0
  | cons a rest ih =>
    simp only [List.reverse_cons, List.foldl_append, List.foldl_cons, List.foldl_nil]
    have := ih.push (s := [a]) (by simp)
    simpa [accAdd, accAddHash, mth] using this

/-- **The streaming root is the tree's root.** Adding the leaves one at a time by carry and folding the
peaks gives RFC 6962's root over them, for every nonempty list and every hash. -/
theorem acc_root_eq_mth (leaves : List L) (h : leaves ≠ []) :
    accRoot leafHash nodeHash leaves = some (mth leafHash nodeHash empty leaves) := by
  rw [accRoot, (rep_accPeaks (empty := empty) leaves).root, if_neg h]

/-- And none for no leaves, as the tree has no root over none. -/
theorem acc_root_nil : accRoot leafHash nodeHash ([] : List L) = none := rfl

/-- The peaks are few: `k` peaks with no height below `b` hold at least `2 ^ (b + k - 1)` leaves, since their
heights strictly rise. -/
theorem Rep.length_le {b : Nat} {ps : List (Nat × D)} {l : List L} (hr : Rep leafHash nodeHash empty b ps l)
    (hne : ps ≠ []) : 2 ^ (b + ps.length - 1) ≤ l.length := by
  induction hr with
  | nil => exact absurd rfl hne
  | cons hr hs hbh ih =>
    rename_i b' h ps l s
    simp only [List.length_cons, List.length_append, hs]
    cases ps with
    | nil =>
      have : 2 ^ b' ≤ 2 ^ h := Nat.pow_le_pow_right (by omega) hbh
      simp only [List.length_nil]
      rw [show b' + (0 + 1) - 1 = b' by omega]; omega
    | cons q qs =>
      have := ih (by simp)
      simp only [List.length_cons] at this ⊢
      have hle : 2 ^ (b' + (qs.length + 1 + 1) - 1) ≤ 2 ^ (h + 1 + (qs.length + 1) - 1) :=
        Nat.pow_le_pow_right (by omega) (by omega)
      omega

/-- **The state bound.** Over fewer than `2 ^ 64` leaves the accumulator holds at most 64 peaks, so a fixed
array of 64 peaks of 32 bytes (2 KiB) and a 64-bit count is all the state the streaming form needs. -/
theorem accPeaks_length_le (leaves : List L) (hn : leaves.length < 2 ^ 64) :
    (accPeaks leafHash nodeHash leaves).length ≤ 64 := by
  cases hps : accPeaks leafHash nodeHash leaves with
  | nil => simp
  | cons q qs =>
    have hr := rep_accPeaks (leafHash := leafHash) (nodeHash := nodeHash) (empty := q.2) leaves
    rw [hps] at hr
    have hb := hr.length_le (by simp)
    apply Classical.byContradiction
    intro hgt
    have : 2 ^ 64 ≤ 2 ^ (0 + (q :: qs).length - 1) := Nat.pow_le_pow_right (by omega) (by omega)
    omega

end

/-! ## The retired tree -/

/-- One layer of the retired tree: pairs hashed with no prefix, and the last node of an odd layer paired
with itself. -/
def pairUp (hash : D → D → D) : List D → List D
  | [] => []
  | [x] => [hash x x]
  | x :: y :: rest => hash x y :: pairUp hash rest

/-- The retired tree: layers paired up until one node is left, the leaves taken as they are. -/
def retiredGo (hash : D → D → D) (empty : D) : Nat → List D → D
  | _, [] => empty
  | _, [x] => x
  | 0, _ => empty
  | fuel + 1, layer => retiredGo hash empty fuel (pairUp hash layer)

def retired (hash : D → D → D) (empty : D) (leaves : List D) : D := retiredGo hash empty leaves.length leaves

/-- **The retired tree collides by construction.** For every hash, [a, b, c] and [a, b, c, c] have one
root: the first layer of both is [hash a b, hash c c]. -/
theorem retired_collides (hash : D → D → D) (empty a b c : D) :
    retired hash empty [a, b, c] = retired hash empty [a, b, c, c] := rfl

end Merkle

end Core
