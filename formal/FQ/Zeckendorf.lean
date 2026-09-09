-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import Mathlib.Data.Nat.Fib.Zeckendorf
import Mathlib.Tactic
/-!
# The Fibonacci code (Zeckendorf wire), PROTOCOL.md invariant I2

Mirrors `prismpath/telemetry/zeckendorf.py`: a positive integer's code is its Zeckendorf bit vector,
bit `i` (from position 0) standing for the Fibonacci number `F(i+2)` in Mathlib's indexing
(`fib 2 = 1, fib 3 = 2, fib 4 = 3, ...`, the reference's basis `[1, 2, 3, 5, ...]`), followed by a
terminating `1`. Because a Zeckendorf representation never uses two consecutive Fibonacci numbers,
`11` appears in a code only as its last two bits, so a concatenated stream frames itself.

Mathlib supplies the representation (`Nat.zeckendorf`, greedy, indices decreasing with gaps of at
least two, every index at least two) and its sum theorem (`Nat.sum_zeckendorf_fib`). This file
proves the codec round trip (`decode_encode`) and the self framing property (`takeCode_encode`:
the first `11` in `encode n ++ rest` closes `encode n`). Parity with the reference's bit strings is
checked by `#guard` in `FQ/Vectors.lean`.
-/

namespace FQ.Zeck

open Nat List

/-- The gap relation of a Zeckendorf index list: each later index is at least two below. -/
abbrev Gap (a b : ℕ) : Prop := b + 2 ≤ a

instance : Trans Gap Gap Gap := ⟨fun h1 h2 => by unfold Gap at *; omega⟩

/-- The code body: bit `i` is set when `i + 2` is a Zeckendorf index of `n`. Length `greatestFib n - 1`. -/
def body (n : ℕ) : List Bool :=
  (List.range (n.greatestFib - 1)).map (fun i => decide ((i + 2) ∈ n.zeckendorf))

/-- The Fibonacci code: the body then the terminator. -/
def encode (n : ℕ) : List Bool := body n ++ [true]

/-- Sum of `F(k + i + 2)` over the set bits `i` of a body read from offset `k`. -/
def decodeFrom (k : ℕ) : List Bool → ℕ
  | [] => 0
  | b :: rest => (if b then fib (k + 2) else 0) + decodeFrom (k + 1) rest

/-- Decode one code: drop the terminator, sum the body. -/
def decode (code : List Bool) : ℕ := decodeFrom 0 code.dropLast

/-- Take the first code from a stream: everything up to and including the first `11`. -/
def takeCode : List Bool → Option (List Bool × List Bool)
  | [] => none
  | [_] => none
  | b :: c :: rest =>
    if b && c then some ([true, true], rest)
    else (takeCode (c :: rest)).map (fun p => (b :: p.1, p.2))

/-! ## Facts about the Zeckendorf index list -/

theorem zeck_pairwise (n : ℕ) : (n.zeckendorf ++ [0]).Pairwise Gap :=
  (Nat.isZeckendorfRep_zeckendorf n).pairwise

theorem zeck_ge_two {n j : ℕ} (hj : j ∈ n.zeckendorf) : 2 ≤ j := by
  have h := List.pairwise_append.mp (zeck_pairwise n)
  have := h.2.2 j hj 0 (by simp)
  unfold Gap at this; omega

theorem zeck_pairwise' (n : ℕ) : n.zeckendorf.Pairwise Gap :=
  (zeck_pairwise n).sublist (List.sublist_append_left _ _)

theorem zeck_nodup (n : ℕ) : n.zeckendorf.Nodup :=
  (zeck_pairwise' n).imp (fun h => by unfold Gap at h; omega)

theorem zeck_le_greatest {n j : ℕ} (hn : 0 < n) (hj : j ∈ n.zeckendorf) : j ≤ n.greatestFib := by
  rw [Nat.zeckendorf_of_pos hn] at hj
  have hp := zeck_pairwise' n
  rw [Nat.zeckendorf_of_pos hn] at hp
  rcases List.mem_cons.mp hj with rfl | hj'
  · exact le_refl _
  · have := List.rel_of_pairwise_cons hp hj'
    unfold Gap at this; omega

theorem greatest_mem {n : ℕ} (hn : 0 < n) : n.greatestFib ∈ n.zeckendorf := by
  rw [Nat.zeckendorf_of_pos hn]; simp

theorem two_le_greatest {n : ℕ} (hn : 0 < n) : 2 ≤ n.greatestFib :=
  zeck_ge_two (greatest_mem hn)

/-- Two distinct Zeckendorf indices differ by at least two. -/
theorem zeck_gap {n a b : ℕ} (ha : a ∈ n.zeckendorf) (hb : b ∈ n.zeckendorf) (hne : a ≠ b) :
    b + 2 ≤ a ∨ a + 2 ≤ b := by
  have hp : n.zeckendorf.Pairwise (fun x y => y + 2 ≤ x ∨ x + 2 ≤ y) :=
    (zeck_pairwise' n).imp (fun h => Or.inl h)
  haveI : Std.Symm (fun x y : ℕ => y + 2 ≤ x ∨ x + 2 ≤ y) := ⟨by intro a b h; exact Or.symm h⟩
  exact hp.forall ha hb hne

/-! ## The round trip -/

theorem decodeFrom_append (k : ℕ) (l₁ l₂ : List Bool) :
    decodeFrom k (l₁ ++ l₂) = decodeFrom k l₁ + decodeFrom (k + l₁.length) l₂ := by
  induction l₁ generalizing k with
  | nil => simp [decodeFrom]
  | cons b rest ih =>
    simp only [List.cons_append, decodeFrom, List.length_cons]
    rw [ih (k + 1)]
    have : k + 1 + rest.length = k + (rest.length + 1) := by omega
    rw [this]; omega

theorem decodeFrom_range (k L : ℕ) (f : ℕ → Bool) :
    decodeFrom k ((List.range L).map f) = ∑ i ∈ Finset.range L, if f i then fib (k + i + 2) else 0 := by
  induction L with
  | zero => simp [decodeFrom]
  | succ L ih =>
    rw [List.range_succ, List.map_append, decodeFrom_append, ih, Finset.sum_range_succ]
    simp only [List.length_map, List.length_range, List.map_cons, List.map_nil, decodeFrom, add_zero]

theorem body_sum {n : ℕ} (hn : 0 < n) : decodeFrom 0 (body n) = n := by
  unfold body
  rw [decodeFrom_range]
  simp only [zero_add]
  -- the indicator sum over positions is the sum over the index list
  rw [← Finset.sum_filter]
  simp only [decide_eq_true_eq]
  have himg : Finset.image (· + 2) ((Finset.range (n.greatestFib - 1)).filter (fun i => (i + 2) ∈ n.zeckendorf))
      = n.zeckendorf.toFinset := by
    ext j
    simp only [Finset.mem_image, Finset.mem_filter, Finset.mem_range, List.mem_toFinset]
    constructor
    · rintro ⟨i, ⟨_, hi⟩, rfl⟩; exact hi
    · intro hj
      have h2 := zeck_ge_two hj
      have hg := zeck_le_greatest hn hj
      refine ⟨j - 2, ⟨by omega, by rwa [Nat.sub_add_cancel h2]⟩, Nat.sub_add_cancel h2⟩
  have hinj : Set.InjOn (· + 2) ↑((Finset.range (n.greatestFib - 1)).filter (fun i => (i + 2) ∈ n.zeckendorf)) := by
    intro a _ b _ h; simpa using h
  calc ∑ i ∈ (Finset.range (n.greatestFib - 1)).filter (fun i => (i + 2) ∈ n.zeckendorf), fib (i + 2)
      = ∑ j ∈ Finset.image (· + 2) ((Finset.range (n.greatestFib - 1)).filter (fun i => (i + 2) ∈ n.zeckendorf)), fib j := by
        rw [Finset.sum_image hinj]
    _ = ∑ j ∈ n.zeckendorf.toFinset, fib j := by rw [himg]
    _ = (n.zeckendorf.map fib).sum := List.sum_toFinset _ (zeck_nodup n)
    _ = n := Nat.sum_zeckendorf_fib n

/-- **Round trip.** Decoding the Fibonacci code of a positive integer gives it back. -/
theorem decode_encode {n : ℕ} (hn : 0 < n) : decode (encode n) = n := by
  unfold decode encode
  rw [List.dropLast_concat]
  exact body_sum hn

/-! ## Self framing: no `11` inside a body, and a body ends in `1` -/

theorem body_length (n : ℕ) : (body n).length = n.greatestFib - 1 := by simp [body]

theorem body_get {n i : ℕ} (hi : i < n.greatestFib - 1) :
    (body n)[i]'(by rw [body_length]; exact hi) = decide ((i + 2) ∈ n.zeckendorf) := by
  simp [body]

/-- No two adjacent set bits in a body. -/
theorem body_no_double {n i : ℕ} (hi : i + 1 < n.greatestFib - 1) :
    ¬ ((body n)[i]'(by rw [body_length]; omega) = true ∧ (body n)[i + 1]'(by rw [body_length]; exact hi) = true) := by
  rw [body_get (by omega), body_get hi]
  simp only [decide_eq_true_eq]
  rintro ⟨h1, h2⟩
  rcases zeck_gap h1 h2 (by omega) with h | h <;> omega

/-- The last body bit is set: the greatest Fibonacci index is always used. -/
theorem body_last {n : ℕ} (hn : 0 < n) :
    (body n).getLast? = some true := by
  have hg := two_le_greatest hn
  have hlen : 0 < (body n).length := by rw [body_length]; omega
  rw [List.getLast?_eq_getElem? , body_length]
  have hi : n.greatestFib - 1 - 1 < n.greatestFib - 1 := by omega
  rw [List.getElem?_eq_getElem (by rw [body_length]; exact hi), body_get hi]
  have : n.greatestFib - 1 - 1 + 2 = n.greatestFib := by omega
  rw [this]
  simp [greatest_mem hn]

/-- No two adjacent set bits, indexed form. -/
def NoDouble (l : List Bool) : Prop :=
  ∀ i (h : i + 1 < l.length), ¬ (l[i]'(by omega) = true ∧ l[i + 1]'h = true)

theorem body_noDouble (n : ℕ) : NoDouble (body n) := by
  intro i h
  rw [body_length] at h
  exact body_no_double h

theorem noDouble_tail {b : Bool} {l : List Bool} (h : NoDouble (b :: l)) : NoDouble l := by
  intro i hi
  have := h (i + 1) (by simp; omega)
  simpa using this

theorem noDouble_head {b c : Bool} {l : List Bool} (h : NoDouble (b :: c :: l)) : ¬ (b = true ∧ c = true) := by
  have := h 0 (by simp)
  simpa using this

/-- Taking the first code from `l ++ [true] ++ rest` returns `l ++ [true]` when `l` has no `11` and
ends in `1`: the terminator makes the first `11`. -/
theorem takeCode_of_noDouble : ∀ (l : List Bool), NoDouble l → l.getLast? = some true →
    ∀ rest, takeCode (l ++ [true] ++ rest) = some (l ++ [true], rest) := by
  intro l
  induction l with
  | nil => intro _ h; simp at h
  | cons b l ih =>
    intro hnd hlast rest
    cases l with
    | nil =>
      simp at hlast; subst hlast
      simp [takeCode]
    | cons c l' =>
      have hbc : ¬ (b = true ∧ c = true) := noDouble_head hnd
      have ih' := ih (noDouble_tail hnd) (by simpa using hlast) rest
      have hb : (b && c) = false := by
        cases b <;> cases c <;> simp_all
      simp only [List.cons_append] at ih'
      simp only [List.cons_append, takeCode, hb, Bool.false_eq_true, if_false, ih', Option.map_some]

/-- **Self framing (I2).** The first `11` in a stream beginning with `encode n` closes exactly `encode n`. -/
theorem takeCode_encode {n : ℕ} (hn : 0 < n) (rest : List Bool) :
    takeCode (encode n ++ rest) = some (encode n, rest) := by
  unfold encode
  exact takeCode_of_noDouble (body n) (body_noDouble n) (body_last hn) rest


/-! ## Streams -/

/-- Decode a stream by taking codes until none remains; `fuel` bounds the recursion (the stream
length suffices). A trailing run with no terminator is an incomplete frame and is dropped, as in the
reference. -/
def decodeStreamFuel : ℕ → List Bool → List ℕ
  | 0, _ => []
  | fuel + 1, bits =>
    match takeCode bits with
    | none => []
    | some (code, rest) => decode code :: decodeStreamFuel fuel rest

def decodeStream (bits : List Bool) : List ℕ := decodeStreamFuel bits.length bits

theorem encode_length_pos (n : ℕ) : 0 < (encode n).length := by simp [encode]

theorem length_le_length_flatMap_encode (vs : List ℕ) : vs.length ≤ (vs.flatMap encode).length := by
  induction vs with
  | nil => simp
  | cons v rest ih =>
    simp only [List.flatMap_cons, List.length_append, List.length_cons]
    have := encode_length_pos v
    omega

theorem decodeStreamFuel_flatMap (vs : List ℕ) (hpos : ∀ v ∈ vs, 0 < v) :
    ∀ fuel, vs.length ≤ fuel → decodeStreamFuel fuel (vs.flatMap encode) = vs := by
  induction vs with
  | nil =>
    intro fuel _
    cases fuel with
    | zero => rfl
    | succ f => simp [decodeStreamFuel, takeCode]
  | cons v rest ih =>
    intro fuel hf
    cases fuel with
    | zero => simp at hf
    | succ f =>
      have hv : 0 < v := hpos v (by simp)
      simp only [List.flatMap_cons, decodeStreamFuel, takeCode_encode hv, decode_encode hv]
      rw [ih (fun w hw => hpos w (by simp [hw])) f (by simpa using hf)]

/-- **Stream round trip.** A concatenation of Fibonacci codes decodes to exactly the values encoded:
the wire needs no length header and no field tags. -/
theorem decodeStream_flatMap (vs : List ℕ) (hpos : ∀ v ∈ vs, 0 < v) :
    decodeStream (vs.flatMap encode) = vs :=
  decodeStreamFuel_flatMap vs hpos _ (length_le_length_flatMap_encode vs)

end FQ.Zeck
