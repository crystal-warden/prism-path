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
