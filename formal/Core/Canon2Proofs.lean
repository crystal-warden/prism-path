-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import Core.Canon2
import Core.Theorems
/-!
# The verified core: the canon/2 writer and reader, proved inverse

The theorems about `Core.write` / `Core.writeBytes` (Canon2.lean) and the reader `Core.readBytes`
(Json.lean). docs/design/spec-verified-core.md section 3.2 states them in words.
-/

namespace Core

/-! ## UTF-8: the decoder inverts the encoder -/


theorem dec1 (b : UInt8) (rest acc) (h : b.toNat < 128) :
    utf8Decode (b :: rest) acc = utf8Decode rest (Char.ofNat b.toNat :: acc) := by
  cases rest with
  | nil => simp [utf8Decode, h]
  | cons c r => rw [utf8Decode.eq_2]; simp only [h, if_true]

theorem dec2 (b c1 : UInt8) (rest acc) (h : 194 ≤ b.toNat) (h' : b.toNat < 224) (hc : isCont c1 = true) :
    utf8Decode (b :: c1 :: rest) acc = utf8Decode rest (Char.ofNat ((b.toNat - 192) * 64 + contVal c1) :: acc) := by
  rw [utf8Decode]; simp only [hc, if_true, if_neg (show ¬ b.toNat < 128 by omega), if_neg (show ¬ b.toNat < 194 by omega), if_pos h']

theorem dec3 (b c1 c2 : UInt8) (rest acc) (h : 224 ≤ b.toNat) (h' : b.toNat < 240) (hc : isCont c1 = true) (hc2 : isCont c2 = true)
    (hok : ¬ ((b.toNat - 224) * 4096 + contVal c1 * 64 + contVal c2 < 2048 ∨ (55296 ≤ (b.toNat - 224) * 4096 + contVal c1 * 64 + contVal c2 ∧ (b.toNat - 224) * 4096 + contVal c1 * 64 + contVal c2 ≤ 57343))) :
    utf8Decode (b :: c1 :: c2 :: rest) acc = utf8Decode rest (Char.ofNat ((b.toNat - 224) * 4096 + contVal c1 * 64 + contVal c2) :: acc) := by
  rw [utf8Decode]
  simp only [hc, hc2, Bool.and_self, if_true, if_neg (show ¬ b.toNat < 128 by omega), if_neg (show ¬ b.toNat < 194 by omega),
    if_neg (show ¬ b.toNat < 224 by omega), if_pos h']
  rw [if_neg]; simpa using hok

theorem dec4 (b c1 c2 c3 : UInt8) (rest acc) (h : 240 ≤ b.toNat) (h' : b.toNat < 245) (hc : isCont c1 = true) (hc2 : isCont c2 = true) (hc3 : isCont c3 = true)
    (hok : ¬ ((b.toNat - 240) * 262144 + contVal c1 * 4096 + contVal c2 * 64 + contVal c3 < 65536 ∨ (b.toNat - 240) * 262144 + contVal c1 * 4096 + contVal c2 * 64 + contVal c3 > 1114111)) :
    utf8Decode (b :: c1 :: c2 :: c3 :: rest) acc = utf8Decode rest (Char.ofNat ((b.toNat - 240) * 262144 + contVal c1 * 4096 + contVal c2 * 64 + contVal c3) :: acc) := by
  rw [utf8Decode]
  simp only [hc, hc2, hc3, Bool.and_self, if_true, if_neg (show ¬ b.toNat < 128 by omega), if_neg (show ¬ b.toNat < 194 by omega),
    if_neg (show ¬ b.toNat < 224 by omega), if_neg (show ¬ b.toNat < 240 by omega), if_pos h']
  rw [if_neg]; simpa using hok


theorem char_valid (c : Char) : c.toNat < 55296 ∨ (57343 < c.toNat ∧ c.toNat < 1114112) := by
  have h := c.valid
  unfold UInt32.isValidChar Nat.isValidChar at h
  exact h

theorem u8 {x : Nat} (h : x < 256) : (UInt8.ofNat x).toNat = x := by
  simp; omega

theorem cont_of {x : Nat} (h : x < 64) : isCont (UInt8.ofNat (128 + x)) = true ∧ contVal (UInt8.ofNat (128 + x)) = x := by
  unfold isCont contVal
  rw [u8 (show 128 + x < 256 by omega)]
  constructor
  · rw [Bool.and_eq_true, decide_eq_true_eq, decide_eq_true_eq]; omega
  · omega

theorem utf8Decode_char (c : Char) (rest : List UInt8) (acc : List Char) :
    utf8Decode (utf8Char c ++ rest) acc = utf8Decode rest (c :: acc) := by
  have hv := char_valid c
  have hc : Char.ofNat c.toNat = c := Char.ofNat_toNat c
  unfold utf8Char
  by_cases h1 : c.toNat < 128
  · simp only [h1, if_true, List.singleton_append]
    rw [dec1 _ _ _ (by rw [u8 (by omega)]; omega), u8 (by omega), hc]
  by_cases h2 : c.toNat < 2048
  · simp only [h1, h2, if_true, if_false, List.cons_append, List.nil_append]
    have ⟨k1, v1⟩ := cont_of (show c.toNat % 64 < 64 by omega)
    rw [dec2 _ _ _ _ (by rw [u8 (by omega)]; omega) (by rw [u8 (by omega)]; omega) k1, v1, u8 (by omega)]
    rw [show (192 + c.toNat / 64 - 192) * 64 + c.toNat % 64 = c.toNat by omega, hc]
  by_cases h3 : c.toNat < 65536
  · simp only [h1, h2, h3, if_true, if_false, List.cons_append, List.nil_append]
    have ⟨k1, v1⟩ := cont_of (show c.toNat / 64 % 64 < 64 by omega)
    have ⟨k2, v2⟩ := cont_of (show c.toNat % 64 < 64 by omega)
    rw [dec3 _ _ _ _ _ (by rw [u8 (by omega)]; omega) (by rw [u8 (by omega)]; omega) k1 k2
      (by rw [v1, v2, u8 (by omega)]; omega), v1, v2, u8 (by omega)]
    rw [show (224 + c.toNat / 4096 - 224) * 4096 + c.toNat / 64 % 64 * 64 + c.toNat % 64 = c.toNat by omega, hc]
  · simp only [h1, h2, h3, if_false, List.cons_append, List.nil_append]
    have ⟨k1, v1⟩ := cont_of (show c.toNat / 4096 % 64 < 64 by omega)
    have ⟨k2, v2⟩ := cont_of (show c.toNat / 64 % 64 < 64 by omega)
    have ⟨k3, v3⟩ := cont_of (show c.toNat % 64 < 64 by omega)
    rw [dec4 _ _ _ _ _ _ (by rw [u8 (by omega)]; omega) (by rw [u8 (by omega)]; omega) k1 k2 k3
      (by rw [v1, v2, v3, u8 (by omega)]; omega), v1, v2, v3, u8 (by omega)]
    rw [show (240 + c.toNat / 262144 - 240) * 262144 + c.toNat / 4096 % 64 * 4096 + c.toNat / 64 % 64 * 64
      + c.toNat % 64 = c.toNat by omega, hc]

theorem utf8Decode_enc (cs : List Char) (rest : List UInt8) (acc : List Char) :
    utf8Decode (utf8Enc cs ++ rest) acc = utf8Decode rest (cs.reverse ++ acc) := by
  induction cs generalizing acc with
  | nil => simp [utf8Enc]
  | cons c cs ih => simp [utf8Enc, List.append_assoc, utf8Decode_char, ih]

theorem utf8Decode_enc_nil (cs : List Char) : utf8Decode (utf8Enc cs) [] = some cs := by
  have := utf8Decode_enc cs [] []
  simp only [List.append_nil] at this
  rw [this]; unfold utf8Decode; simp


/-! ## Strings: the reader inverts the escaping -/


theorem hexDigit_val : ∀ n, n < 16 → hexVal (hexDigit n) = some n := by decide

theorem ps_raw (c : Char) (rest acc) (h1 : c ≠ '"') (h2 : c ≠ '\\') (h3 : 32 ≤ c.toNat) :
    parseStr (c :: rest) acc = parseStr rest (c :: acc) := by
  rw [parseStr.eq_def]
  split
  · simp_all
  · simp_all
  · simp_all
  · simp_all
  · rename_i c' rest' acc' _ _ _ heq
    simp at heq
    obtain ⟨rfl, rfl⟩ := heq
    simp at *; omega

theorem parseStr_esc (c : Char) (rest acc) : parseStr (escChar c ++ rest) acc = parseStr rest (c :: acc) := by
  have hc : Char.ofNat c.toNat = c := Char.ofNat_toNat c
  unfold escChar
  by_cases e1 : c = '"'
  · subst e1; simp [parseStr]
  by_cases e2 : c = '\\'
  · subst e2; simp [parseStr]
  simp only [e1, e2, if_false]
  by_cases h : c.toNat < 32
  · simp only [h, if_true]
    by_cases b8 : c.toNat = 8
    · have : c = '\x08' := by rw [← hc, b8]
      subst this; simp [parseStr]
    by_cases b9 : c.toNat = 9
    · have : c = '\t' := by rw [← hc, b9]
      subst this; simp [parseStr]
    by_cases b10 : c.toNat = 10
    · have : c = '\n' := by rw [← hc, b10]
      subst this; simp [parseStr]
    by_cases b12 : c.toNat = 12
    · have : c = '\x0c' := by rw [← hc, b12]
      subst this; simp [parseStr]
    by_cases b13 : c.toNat = 13
    · have : c = '\r' := by rw [← hc, b13]
      subst this; simp [parseStr]
    simp only [b8, b9, b10, b12, b13, if_false, List.cons_append, List.nil_append]
    have hx : hex4 '0' '0' (hexDigit (c.toNat / 16)) (hexDigit (c.toNat % 16)) = some c.toNat := by
      simp only [hex4, hexDigit_val _ (show c.toNat / 16 < 16 by omega), hexDigit_val _ (show c.toNat % 16 < 16 by omega)]
      simp [hexVal]; omega
    rw [parseStr.eq_3, hx]
    have hh : isHigh c.toNat = false := by simp [isHigh]; omega
    have hl : isLow c.toNat = false := by simp [isLow]; omega
    simp only [hh, hl, Bool.false_eq_true, if_false, hc]
  · simp only [h, if_false, List.singleton_append]
    exact ps_raw c rest acc e1 e2 (by omega)

theorem parseStr_escStr (cs : List Char) (rest acc) :
    parseStr (escStr cs ++ rest) acc = parseStr rest (cs.reverse ++ acc) := by
  induction cs generalizing acc with
  | nil => simp [escStr]
  | cons c cs ih => simp [escStr, List.append_assoc, parseStr_esc, ih]

theorem parseStr_wStr (s : String) (rest) : parseStr (escStr s.toList ++ '"' :: rest) [] = .ok (s, rest) := by
  rw [parseStr_escStr]; simp [parseStr]


/-! ## Integers -/


/-- What may follow a value in a written document: nothing, or a comma or a closing bracket. -/
def Delim (rest : List Char) : Prop := ∀ c r, rest = c :: r → c = ',' ∨ c = ']' ∨ c = '}'

theorem digit_char {k : Nat} (h : k < 10) : isDigit (Char.ofNat (48 + k)) = true ∧ (Char.ofNat (48 + k)).toNat = 48 + k := by
  have : ∀ k, k < 10 → isDigit (Char.ofNat (48 + k)) = true ∧ (Char.ofNat (48 + k)).toNat = 48 + k := by decide
  exact this k h

theorem natDigits_digits (n : Nat) : ∀ c ∈ natDigits n, isDigit c = true := by
  induction n using Nat.strong_induction_on with
  | _ n ih =>
    rw [natDigits]
    split
    · simp [(digit_char (by omega : n < 10)).1]
    · intro c hc
      simp only [List.mem_append, List.mem_singleton] at hc
      rcases hc with hc | rfl
      · exact ih _ (by omega) c hc
      · exact (digit_char (Nat.mod_lt n (by omega))).1

theorem natDigits_value (n : Nat) : digitsValue (natDigits n) = n := by
  induction n using Nat.strong_induction_on with
  | _ n ih =>
    rw [natDigits]
    split
    · simp only [digitsValue, List.foldl_cons, List.foldl_nil, (digit_char (by omega : n < 10)).2]
      simp
    · rename_i h
      have := ih (n / 10) (by omega)
      unfold digitsValue at this ⊢
      rw [List.foldl_append, this]
      simp only [List.foldl_cons, List.foldl_nil, (digit_char (Nat.mod_lt n (by omega))).2]
      simp; omega

theorem natDigits_head (n : Nat) (h : 0 < n) : ∃ c r, natDigits n = c :: r ∧ c ≠ '0' := by
  induction n using Nat.strong_induction_on with
  | _ n ih =>
    rw [natDigits]
    split
    · refine ⟨_, _, rfl, ?_⟩
      intro e
      have := congrArg Char.toNat e
      have h2 := (digit_char (by omega : n < 10)).2
      rw [this] at h2; simp at h2; omega
    · obtain ⟨c, r, e, hc⟩ := ih (n / 10) (by omega) (by omega)
      exact ⟨c, r ++ _, by rw [e]; rfl, hc⟩

theorem natDigits_zero : natDigits 0 = ['0'] := by rw [natDigits]; rfl

theorem spanDigits_app (ds rest : List Char) (hd : ∀ c ∈ ds, isDigit c = true) (hr : Delim rest) :
    spanDigits (ds ++ rest) = (ds, rest) := by
  induction ds with
  | nil =>
    cases rest with
    | nil => rfl
    | cons c r =>
      rcases hr c r rfl with rfl | rfl | rfl <;> rfl
  | cons c cs ih =>
    simp only [List.cons_append, spanDigits, hd c (by simp), if_true]
    rw [ih (fun x hx => hd x (by simp [hx]))]

theorem parseNum_digits (neg : Bool) (m : Nat) (rest : List Char) (hr : Delim rest)
    (hz : neg = true → m ≠ 0) (hm : (m : Int) ≤ exactLimit) :
    parseNum neg (natDigits m ++ rest) = .ok (.int (if neg then -(m : Int) else m), rest) := by
  have hlim : exactLimit = 9007199254740991 := rfl
  have key : ∀ t, rest = t → parseNum neg (natDigits m ++ t) = .ok (.int (if neg then -(m : Int) else m), t) := by
    intro t ht
    rcases Nat.eq_zero_or_pos m with rfl | hpos
    · have hn : neg = false := by cases neg <;> simp_all
      subst hn
      rw [natDigits_zero]
      rcases t with _ | ⟨c, r⟩
      · simp [parseNum, digitsValue, spanDigits, hlim]
      · rcases hr c r ht with rfl | rfl | rfl <;> simp [parseNum, digitsValue, spanDigits, hlim]
    · obtain ⟨c, r, e, hc⟩ := natDigits_head m hpos
      have hd := natDigits_digits m
      have hv := natDigits_value m
      rw [e] at hd hv ⊢
      have hcd : isDigit c = true := hd c (by simp)
      have hsp : spanDigits (r ++ t) = (r, t) :=
        spanDigits_app r t (fun x hx => hd x (by simp [hx])) (ht ▸ hr)
      have hm' : m ≤ 9007199254740991 := by rw [hlim] at hm; omega
      have gen : ∀ t' : List Char, t' = t → parseNum neg (c :: r ++ t') = .ok (.int (if neg then -(m : Int) else m), t') := by
        intro t' ht'
        subst ht'
        unfold parseNum
        split
        · rename_i r' h; simp at h; exact absurd h.1 hc
        · rename_i c' r' _ h
          simp only [List.cons_append, List.cons.injEq] at h
          obtain ⟨rfl, rfl⟩ := h
          simp only [hcd, if_true, hsp]
          rcases t' with _ | ⟨c2, r2⟩
          · cases neg <;> simp [hv, hlim] <;> (try split_ifs) <;> (first | omega | rfl)
          · rcases hr c2 r2 ht with rfl | rfl | rfl <;> cases neg <;> simp [hv, hlim] <;> (try split_ifs) <;> (first | omega | rfl)
        · simp at *
      exact gen t rfl
  exact key rest rfl

theorem parseNum_wInt (n : Int) (rest : List Char) (hr : Delim rest) (hn : inRange n = true) :
    (if n < 0 then parseNum true (natDigits n.natAbs ++ rest) else parseNum false (natDigits n.natAbs ++ rest))
      = .ok (.int n, rest) := by
  simp only [inRange, Bool.and_eq_true, decide_eq_true_eq] at hn
  split
  · rename_i h
    rw [parseNum_digits true _ rest hr (by omega) (by unfold exactLimit at *; omega)]
    simp only [if_true]; congr; omega
  · rename_i h
    rw [parseNum_digits false _ rest hr (by simp) (by unfold exactLimit at *; omega)]
    simp only [Bool.false_eq_true, if_false]; congr; omega


/-! ## The reader's steps on written text -/


theorem pv_null (f d rest) : pValue (f + 1) d (['n','u','l','l'] ++ rest) = .ok (.null, rest) := by
  simp [pValue, skipWs, isWs]
theorem pv_true (f d rest) : pValue (f + 1) d (['t','r','u','e'] ++ rest) = .ok (.bool true, rest) := by
  simp [pValue, skipWs, isWs]
theorem pv_false (f d rest) : pValue (f + 1) d (['f','a','l','s','e'] ++ rest) = .ok (.bool false, rest) := by
  simp [pValue, skipWs, isWs]
theorem pv_str (f d r) : pValue (f + 1) d ('"' :: r) =
    match parseStr r [] with
    | .ok (s, r') => .ok (.str s, r')
    | .error e => .error e := by
  simp [pValue, skipWs, isWs]; rfl
theorem pv_neg (f d r) : pValue (f + 1) d ('-' :: r) = parseNum true r := by
  simp [pValue, skipWs, isWs]
theorem pv_digit (f d c r) (h : isDigit c = true) : pValue (f + 1) d (c :: r) = parseNum false (c :: r) := by
  have hc : 48 ≤ c.toNat ∧ c.toNat ≤ 57 := by
    simp [isDigit] at h
    exact ⟨h.1, h.2⟩
  have hw : isWs c = false := by
    simp only [isWs, Bool.or_eq_false_iff, beq_eq_false_iff_ne, ne_eq]
    refine ⟨⟨⟨?_, ?_⟩, ?_⟩, ?_⟩ <;> (intro e; subst e; simp at hc)
  have hws : skipWs (c :: r) = c :: r := by
    simp only [skipWs, hw]; rfl
  rw [pValue.eq_def]; simp only [hws]
  split <;> (try (rename_i heq; simp at heq; obtain ⟨rfl, -⟩ := heq; simp at hc))
  · rename_i heq; simp at heq; obtain ⟨rfl, rfl⟩ := heq; simp [h]
  · simp at *
theorem pv_arr_empty (f d rest) (h : d + 1 ≤ maxDepth) : pValue (f + 1) d (['[', ']'] ++ rest) = .ok (.arr [], rest) := by
  simp [pValue, skipWs, isWs]; omega
theorem pv_obj_empty (f d rest) (h : d + 1 ≤ maxDepth) : pValue (f + 1) d (['{', '}'] ++ rest) = .ok (.obj [], rest) := by
  simp [pValue, skipWs, isWs]; omega



def HeadOk (c : Char) : Prop := isWs c = false ∧ c ≠ ']' ∧ c ≠ '}'

theorem headOk_digit {c : Char} (h : isDigit c = true) : HeadOk c := by
  have hc : 48 ≤ c.toNat ∧ c.toNat ≤ 57 := by simp [isDigit] at h; exact ⟨h.1, h.2⟩
  refine ⟨?_, ?_, ?_⟩
  · simp only [isWs, Bool.or_eq_false_iff, beq_eq_false_iff_ne, ne_eq]
    refine ⟨⟨⟨?_, ?_⟩, ?_⟩, ?_⟩ <;> (intro e; subst e; simp at hc)
  · intro e; subst e; simp at hc
  · intro e; subst e; simp at hc

theorem skipWs_head {c : Char} {t : List Char} (h : HeadOk c) : skipWs (c :: t) = c :: t := by
  simp only [skipWs, h.1]; rfl

theorem pv_arr (f d c t) (h : d + 1 ≤ maxDepth) (hc : HeadOk c) :
    pValue (f + 1) d ('[' :: c :: t) = match pValue f (d + 1) (c :: t) with
      | .error e => .error e
      | .ok (v, r'') => pArr f (d + 1) r'' [v] := by
  have h1 : skipWs ('[' :: c :: t) = '[' :: c :: t := skipWs_head (by unfold HeadOk; decide)
  rw [pValue.eq_2, h1]
  simp only
  rw [if_neg (by omega), skipWs_head hc]
  split
  · rename_i heq; simp at heq; exact absurd heq.1 hc.2.1
  · rfl

theorem pv_obj (f d t) (h : d + 1 ≤ maxDepth) :
    pValue (f + 1) d ('{' :: '"' :: t) = pMember f (d + 1) ('"' :: t) [] := by
  have h1 : skipWs ('{' :: '"' :: t) = '{' :: '"' :: t := skipWs_head (by unfold HeadOk; decide)
  have h2 : skipWs ('"' :: t) = '"' :: t := skipWs_head (by unfold HeadOk; decide)
  rw [pValue.eq_2, h1]
  simp only
  rw [if_neg (by omega), h2]
  split
  · rename_i heq; simp at heq
  · rfl

theorem pa_close (g d r acc) : pArr (g + 1) d (']' :: r) acc = .ok (.arr acc.reverse, r) := by
  simp [pArr, skipWs, isWs]
theorem pa_comma (g d r acc) : pArr (g + 1) d (',' :: r) acc = match pValue g d r with
    | .error e => .error e
    | .ok (v, r') => pArr g d r' (v :: acc) := by
  simp [pArr, skipWs, isWs]; rfl



/-! ## The round trip on the spelling -/

mutual
/-- The fuel the reader spends on a written value. -/
def sz : J → Nat
  | .arr xs => 1 + szA xs
  | .obj ms => 1 + szO ms
  | _ => 1
def szA : List J → Nat
  | [] => 1
  | x :: xs => 1 + sz x + szA xs
def szO : List (String × J) → Nat
  | [] => 1
  | (_, v) :: ms => 1 + sz v + szO ms
end

/-- The members of a nonempty object, as written after its `{` or a `,`. -/
def wrMem : List (String × J) → List Char
  | [] => []
  | (k, v) :: ms => wStr k ++ ':' :: (wr v ++ wrObj ms)

theorem natDigits_cons (m : Nat) : ∃ c t, natDigits m = c :: t ∧ isDigit c = true := by
  rcases Nat.eq_zero_or_pos m with rfl | h
  · exact ⟨'0', [], natDigits_zero, by decide⟩
  · obtain ⟨c, t, e, -⟩ := natDigits_head m h
    exact ⟨c, t, e, natDigits_digits m c (by rw [e]; simp)⟩

theorem wr_head (v : J) : ∃ c t, wr v = c :: t ∧ HeadOk c := by
  match v with
  | .null => exact ⟨_, _, rfl, by unfold HeadOk; decide⟩
  | .bool true => exact ⟨_, _, rfl, by unfold HeadOk; decide⟩
  | .bool false => exact ⟨_, _, rfl, by unfold HeadOk; decide⟩
  | .str s => exact ⟨_, _, rfl, by unfold HeadOk; decide⟩
  | .arr [] => exact ⟨_, _, rfl, by unfold HeadOk; decide⟩
  | .arr (_ :: _) => exact ⟨_, _, rfl, by unfold HeadOk; decide⟩
  | .obj [] => exact ⟨_, _, rfl, by unfold HeadOk; decide⟩
  | .obj ((_, _) :: _) => exact ⟨_, _, rfl, by unfold HeadOk; decide⟩
  | .int n =>
    simp only [wr, wInt]
    split
    · exact ⟨_, _, rfl, by unfold HeadOk; decide⟩
    · obtain ⟨c, t, e, hc⟩ := natDigits_cons n.natAbs
      exact ⟨c, t, e, headOk_digit hc⟩

theorem delim_wrArr (xs : List J) (rest : List Char) : Delim (wrArr xs ++ rest) := by
  intro c r h
  cases xs with
  | nil => simp [wrArr] at h; exact Or.inr (Or.inl h.1.symm)
  | cons _ _ => simp [wrArr] at h; exact Or.inl h.1.symm

theorem delim_wrObj (ms : List (String × J)) (rest : List Char) : Delim (wrObj ms ++ rest) := by
  intro c r h
  match ms with
  | [] => simp [wrObj] at h; exact Or.inr (Or.inr h.1.symm)
  | (_, _) :: _ => simp [wrObj] at h; exact Or.inl h.1.symm

theorem fuel_succ {n fuel : Nat} (h : 1 ≤ n) (hf : n ≤ fuel) : ∃ f, fuel = f + 1 ∧ n - 1 ≤ f :=
  ⟨fuel - 1, by omega, by omega⟩

theorem pm_step (g d : Nat) (k : String) (r : List Char) (acc : List (String × J)) :
    pMember (g + 1) d ('"' :: (escStr k.toList ++ '"' :: r)) acc =
      if hasKey k acc then .error .dupKey
      else match skipWs r with
        | ':' :: r'' =>
          match pValue g d r'' with
          | .error e => .error e
          | .ok (v, r3) =>
            match skipWs r3 with
            | '}' :: r4 => .ok (.obj ((k, v) :: acc).reverse, r4)
            | ',' :: r4 => pMember g d r4 ((k, v) :: acc)
            | _ => .error .syntax
        | _ => .error .syntax := by
  have h2 : skipWs ('"' :: (escStr k.toList ++ '"' :: r)) = '"' :: (escStr k.toList ++ '"' :: r) :=
    skipWs_head (by unfold HeadOk; decide)
  rw [pMember.eq_2, h2]
  simp only [parseStr_wStr]
  rfl

theorem hasKey_false_of_nodup {k : String} {v : J} {acc ms : List (String × J)}
    (h : ((acc.reverse ++ (k, v) :: ms).map (·.1)).Nodup) : hasKey k acc = false := by
  cases hk : hasKey k acc
  · rfl
  · have := (hasKey_iff k acc).mp hk
    simp only [List.map_append, List.map_reverse, List.map_cons] at h
    have h' := List.nodup_append.mp h
    exact absurd rfl (h'.2.2 k (by simpa using this) k (by simp))

mutual
theorem rt_value : (v : J) → ∀ (fuel d : Nat) (rest : List Char), wfJ v = true → rangeJ v = true →
    d + depth v ≤ maxDepth → sz v ≤ fuel → Delim rest → pValue fuel d (wr v ++ rest) = .ok (v, rest)
  | .null, fuel, d, rest, _, _, _, hf, _ => by
    obtain ⟨f, rfl, -⟩ := fuel_succ (by simp [sz]) hf
    exact pv_null f d rest
  | .bool true, fuel, d, rest, _, _, _, hf, _ => by
    obtain ⟨f, rfl, -⟩ := fuel_succ (by simp [sz]) hf
    exact pv_true f d rest
  | .bool false, fuel, d, rest, _, _, _, hf, _ => by
    obtain ⟨f, rfl, -⟩ := fuel_succ (by simp [sz]) hf
    exact pv_false f d rest
  | .str s, fuel, d, rest, _, _, _, hf, _ => by
    obtain ⟨f, rfl, -⟩ := fuel_succ (by simp [sz]) hf
    simp only [wr, wStr, List.cons_append, List.append_assoc, List.singleton_append]
    rw [pv_str, parseStr_wStr]
    rfl
  | .int n, fuel, d, rest, _, hr, _, hf, hd => by
    obtain ⟨f, rfl, -⟩ := fuel_succ (by simp [sz]) hf
    have key := parseNum_wInt n rest hd (by simpa [rangeJ] using hr)
    simp only [wr, wInt]
    split
    · rename_i h
      rw [List.cons_append, pv_neg]
      simpa [h] using key
    · rename_i h
      obtain ⟨c, t, e, hc⟩ := natDigits_cons n.natAbs
      rw [e, List.cons_append, pv_digit f d c _ hc, ← List.cons_append, ← e]
      simpa [h] using key
  | .arr [], fuel, d, rest, _, _, hdep, hf, _ => by
    obtain ⟨f, rfl, -⟩ := fuel_succ (by simp [sz]) hf
    exact pv_arr_empty f d rest (by simp [depth, depthL] at hdep; omega)
  | .arr (x :: xs), fuel, d, rest, hw, hr, hdep, hf, _ => by
    obtain ⟨f, rfl, hf'⟩ := fuel_succ (by simp [sz]) hf
    simp only [wfJ, wfList, Bool.and_eq_true] at hw
    simp only [rangeJ, rangeL, Bool.and_eq_true] at hr
    simp only [depth, depthL] at hdep
    simp only [sz, szA] at hf'
    obtain ⟨c, t, e, hc⟩ := wr_head x
    have hx := rt_value x f (d + 1) (wrArr xs ++ rest) hw.1 hr.1 (by omega) (by omega) (delim_wrArr xs rest)
    have hxs := rt_arr xs f (d + 1) rest [x] hw.2 hr.2 (by omega) (by omega) ‹_›
    simp only [wr, List.cons_append, List.append_assoc]
    rw [e, List.cons_append, pv_arr f d c _ (by omega) hc, ← List.cons_append, ← e, hx]
    simpa using hxs
  | .obj [], fuel, d, rest, _, _, hdep, hf, _ => by
    obtain ⟨f, rfl, -⟩ := fuel_succ (by simp [sz]) hf
    exact pv_obj_empty f d rest (by simp [depth, depthM] at hdep; omega)
  | .obj ((k, v) :: ms), fuel, d, rest, hw, hr, hdep, hf, hd => by
    obtain ⟨f, rfl, hf'⟩ := fuel_succ (by simp [sz]) hf
    simp only [wfJ, Bool.and_eq_true] at hw
    simp only [rangeJ] at hr
    simp only [depth] at hdep
    simp only [sz] at hf'
    have hm := rt_mem ((k, v) :: ms) f (d + 1) rest [] (by simp) hw.2 hr (by omega) (by omega) hd
      (by simpa using (keysDistinct_iff _).mp hw.1)
    have e : wr (.obj ((k, v) :: ms)) ++ rest = '{' :: '"' :: (escStr k.toList ++ '"' :: ':' :: (wr v ++ wrObj ms ++ rest)) := by
      simp [wr, wStr]
    rw [e, pv_obj f d _ (by omega)]
    have e2 : wrMem ((k, v) :: ms) ++ rest = '"' :: (escStr k.toList ++ '"' :: ':' :: (wr v ++ wrObj ms ++ rest)) := by
      simp [wrMem, wStr]
    rw [← e2, hm]
    simp
theorem rt_arr : (xs : List J) → ∀ (fuel d : Nat) (rest : List Char) (acc : List J), wfList xs = true →
    rangeL xs = true → d + depthL xs ≤ maxDepth → szA xs ≤ fuel → Delim rest →
    pArr fuel d (wrArr xs ++ rest) acc = .ok (.arr (acc.reverse ++ xs), rest)
  | [], fuel, d, rest, acc, _, _, _, hf, _ => by
    obtain ⟨g, rfl, -⟩ := fuel_succ (by simp [szA]) hf
    simp [wrArr, pa_close]
  | x :: xs, fuel, d, rest, acc, hw, hr, hdep, hf, hd => by
    obtain ⟨g, rfl, hf'⟩ := fuel_succ (by simp only [szA]; omega) hf
    simp only [wfList, Bool.and_eq_true] at hw
    simp only [rangeL, Bool.and_eq_true] at hr
    simp only [depthL] at hdep
    simp only [szA] at hf'
    have hx := rt_value x g d (wrArr xs ++ rest) hw.1 hr.1 (by omega) (by omega) (delim_wrArr xs rest)
    have hxs := rt_arr xs g d rest (x :: acc) hw.2 hr.2 (by omega) (by omega) hd
    simp only [wrArr, List.cons_append, List.append_assoc]
    rw [pa_comma, hx]
    simpa using hxs
theorem rt_mem : (ms : List (String × J)) → ∀ (fuel d : Nat) (rest : List Char) (acc : List (String × J)),
    ms ≠ [] → wfMembers ms = true → rangeM ms = true → d + depthM ms ≤ maxDepth → szO ms ≤ fuel → Delim rest →
    ((acc.reverse ++ ms).map (·.1)).Nodup →
    pMember fuel d (wrMem ms ++ rest) acc = .ok (.obj (acc.reverse ++ ms), rest)
  | [], _, _, _, _, hne, _, _, _, _, _, _ => absurd rfl hne
  | (k, v) :: ms, fuel, d, rest, acc, _, hw, hr, hdep, hf, hd, hnd => by
    obtain ⟨g, rfl, hf'⟩ := fuel_succ (by simp only [szO]; omega) hf
    simp only [wfMembers, Bool.and_eq_true] at hw
    simp only [rangeM, Bool.and_eq_true] at hr
    simp only [depthM] at hdep
    simp only [szO] at hf'
    have hx := rt_value v g d (wrObj ms ++ rest) hw.1 hr.1 (by omega) (by omega) (delim_wrObj ms rest)
    have e : wrMem ((k, v) :: ms) ++ rest = '"' :: (escStr k.toList ++ '"' :: (':' :: (wr v ++ (wrObj ms ++ rest)))) := by
      simp [wrMem, wStr]
    rw [e, pm_step, hasKey_false_of_nodup hnd]
    have hc : skipWs (':' :: (wr v ++ (wrObj ms ++ rest))) = ':' :: (wr v ++ (wrObj ms ++ rest)) :=
      skipWs_head (by unfold HeadOk; decide)
    simp only [Bool.false_eq_true, if_false, hc, hx]
    match ms, hw, hr, hdep, hf', hnd with
    | [], _, _, _, _, _ =>
      have : skipWs (wrObj [] ++ rest) = '}' :: rest := by simp [wrObj, skipWs, isWs]
      simp [this]
    | (k', v') :: ms', hw, hr, hdep, hf', hnd =>
      have : skipWs (wrObj ((k', v') :: ms') ++ rest) = ',' :: (wrMem ((k', v') :: ms') ++ rest) := by
        simp [wrObj, wrMem, skipWs, isWs]
      rw [this]
      simp only
      have := rt_mem ((k', v') :: ms') g d rest ((k, v) :: acc) (by simp) hw.2 hr.2 (by omega) (by omega) hd
        (by simpa using hnd)
      rw [this]
      simp
end


theorem wInt_length (n : Int) : 1 ≤ (wInt n).length := by
  obtain ⟨c, t, e, -⟩ := natDigits_cons n.natAbs
  unfold wInt; split <;> simp [e]

mutual
theorem sz_le : (v : J) → sz v ≤ 2 * (wr v).length
  | .null => by simp [sz, wr]
  | .bool true => by simp [sz, wr]
  | .bool false => by simp [sz, wr]
  | .str s => by simp [sz, wr, wStr]; omega
  | .int n => by have := wInt_length n; simp only [sz, wr]; omega
  | .arr [] => by simp [sz, szA, wr]
  | .arr (x :: xs) => by
    have := sz_le x; have := szA_le xs
    simp only [sz, szA, wr, List.length_cons, List.length_append]; omega
  | .obj [] => by simp [sz, szO, wr]
  | .obj ((k, v) :: ms) => by
    have := sz_le v; have := szO_le ms
    simp only [sz, szO, wr, wStr, List.length_cons, List.length_append]; omega
theorem szA_le : (xs : List J) → szA xs + 1 ≤ 2 * (wrArr xs).length
  | [] => by simp [szA, wrArr]
  | x :: xs => by
    have := sz_le x; have := szA_le xs
    simp only [szA, wrArr, List.length_cons, List.length_append]; omega
theorem szO_le : (ms : List (String × J)) → szO ms + 1 ≤ 2 * (wrObj ms).length
  | [] => by simp [szO, wrObj]
  | (k, v) :: ms => by
    have := sz_le v; have := szO_le ms
    simp only [szO, wrObj, wStr, List.length_cons, List.length_append]; omega
end

/-- **The reader inverts the spelling.** Every value the reader could have produced (no key twice,
integers in range, nesting within the bound), spelled with its members in the order given, reads back
to itself. -/
theorem readChars_wr {v : J} (h : doc v = true) : readChars (wr v) = .ok v := by
  simp only [doc, Bool.and_eq_true, decide_eq_true_eq] at h
  obtain ⟨⟨hw, hr⟩, hd⟩ := h
  have := rt_value v (2 * (wr v).length + 4) 0 [] hw hr (by omega) (by have := sz_le v; omega)
    (by intro c r h; simp at h)
  simp only [List.append_nil] at this
  unfold readChars
  rw [this]
  simp [skipWs, hw]

theorem readBytes_enc {cs : List Char} : readBytes ⟨(utf8Enc cs).toArray⟩ = readChars cs := by
  unfold readBytes
  rw [show (⟨(utf8Enc cs).toArray⟩ : ByteArray).data.toList = utf8Enc cs from List.toList_toArray .., utf8Decode_enc_nil]

/-! ## What the reader returns -/


theorem parseNum_ok {neg : Bool} {cs r : List Char} {v : J} (h : parseNum neg cs = .ok (v, r)) :
    ∃ n, v = .int n ∧ inRange n = true := by
  unfold parseNum at h
  simp only at h
  repeat' split at h
  all_goals (first | (simp at h; done) | skip)
  all_goals
    rename_i hr
    simp only [Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, -⟩ := h
    refine ⟨_, rfl, ?_⟩
    simp only [inRange, Bool.and_eq_true, decide_eq_true_eq]
    simp only [Bool.or_eq_true, decide_eq_true_eq, not_or] at hr
    omega

def Good (d : Nat) (x : J) : Prop := rangeJ x = true ∧ d + depth x ≤ maxDepth

theorem good_arr {d : Nat} {xs : List J} (hd : d + 1 ≤ maxDepth) (h : ∀ x ∈ xs, Good (d + 1) x) : Good d (.arr xs) := by
  induction xs with
  | nil => exact ⟨rfl, by simp [depth, depthL]; omega⟩
  | cons x xs ih =>
    have h1 := h x (by simp)
    have h2 := ih (fun y hy => h y (by simp [hy]))
    simp only [Good, rangeJ, depth] at h1 h2 ⊢
    simp only [rangeL, h1.1, h2.1, Bool.and_self, depthL, true_and]
    omega

theorem good_obj {d : Nat} {ms : List (String × J)} (hd : d + 1 ≤ maxDepth) (h : ∀ m ∈ ms, Good (d + 1) m.2) : Good d (.obj ms) := by
  induction ms with
  | nil => exact ⟨rfl, by simp [depth, depthM]; omega⟩
  | cons m ms ih =>
    obtain ⟨k, v⟩ := m
    have h1 := h (k, v) (by simp)
    have h2 := ih (fun y hy => h y (by simp [hy]))
    simp only [Good, rangeJ, depth] at h1 h2 ⊢
    simp only [rangeM, h1.1, h2.1, Bool.and_self, depthM, true_and]
    omega

theorem reader_good : ∀ fuel,
    (∀ d cs v r, d ≤ maxDepth → pValue fuel d cs = .ok (v, r) → Good d v) ∧
    (∀ d cs acc v r, d ≤ maxDepth → (∀ x ∈ acc, Good d x) → pArr fuel d cs acc = .ok (v, r) → ∃ xs, v = .arr xs ∧ ∀ x ∈ xs, Good d x) ∧
    (∀ d cs acc v r, d ≤ maxDepth → (∀ m ∈ acc, Good d m.2) → pMember fuel d cs acc = .ok (v, r) →
      ∃ ms, v = .obj ms ∧ ∀ m ∈ ms, Good d m.2) := by
  intro fuel
  induction fuel with
  | zero =>
    refine ⟨?_, ?_, ?_⟩ <;> intros <;> simp_all [pValue, pArr, pMember]
  | succ f ih =>
    obtain ⟨ihV, ihA, ihM⟩ := ih
    refine ⟨?_, ?_, ?_⟩
    · intro d cs v r hd h
      rw [pValue.eq_2] at h
      have scalar : ∀ w, rangeJ w = true → depth w = 0 → Good d w := fun w h1 h2 => ⟨h1, by omega⟩
      have num : ∀ {neg cs'}, parseNum neg cs' = .ok (v, r) → Good d v := fun h => by
        obtain ⟨n, rfl, hn⟩ := parseNum_ok h
        exact scalar _ (by simpa [rangeJ] using hn) (by simp [depth])
      split at h
      · simp only [Except.ok.injEq, Prod.mk.injEq] at h; obtain ⟨rfl, -⟩ := h; exact scalar _ rfl rfl
      · simp only [Except.ok.injEq, Prod.mk.injEq] at h; obtain ⟨rfl, -⟩ := h; exact scalar _ rfl rfl
      · simp only [Except.ok.injEq, Prod.mk.injEq] at h; obtain ⟨rfl, -⟩ := h; exact scalar _ rfl rfl
      · split at h
        · simp only [Except.ok.injEq, Prod.mk.injEq] at h; obtain ⟨rfl, -⟩ := h; exact scalar _ rfl rfl
        · simp at h
      · exact num h
      · split at h
        · simp at h
        · rename_i hdd
          split at h
          · simp only [Except.ok.injEq, Prod.mk.injEq] at h; obtain ⟨rfl, -⟩ := h
            exact good_arr (by omega) (by simp)
          · split at h
            · simp at h
            · rename_i v1 r1 h1
              have g1 := ihV (d + 1) _ v1 r1 (by omega) h1
              obtain ⟨xs, rfl, hxs⟩ := ihA (d + 1) _ [v1] v r (by omega) (by simpa using g1) h
              exact good_arr (by omega) hxs
      · split at h
        · simp at h
        · rename_i hdd
          split at h
          · simp only [Except.ok.injEq, Prod.mk.injEq] at h; obtain ⟨rfl, -⟩ := h
            exact good_obj (by omega) (by simp)
          · obtain ⟨ms, rfl, hms⟩ := ihM (d + 1) _ [] v r (by omega) (by simp) h
            exact good_obj (by omega) hms
      · split at h
        · exact num h
        · simp at h
      · simp at h
    · intro d cs acc v r hd hacc h
      rw [pArr.eq_2] at h
      split at h
      · simp only [Except.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, -⟩ := h
        exact ⟨_, rfl, fun x hx => hacc x (by simpa using hx)⟩
      · split at h
        · simp at h
        · rename_i v1 r1 h1
          have g1 := ihV d _ v1 r1 hd h1
          exact ihA d _ (v1 :: acc) v r hd (fun x hx => by
            simp at hx; rcases hx with rfl | hx; exact g1; exact hacc x hx) h
      · simp at h
    · intro d cs acc v r hd hacc h
      rw [pMember.eq_2] at h
      split at h
      · split at h
        · simp at h
        · rename_i k r' _
          split at h
          · simp at h
          · split at h
            · split at h
              · simp at h
              · rename_i v1 r3 h1
                have g1 := ihV d _ v1 r3 hd h1
                have hacc' : ∀ m ∈ (k, v1) :: acc, Good d m.2 := fun m hm => by
                  simp at hm; rcases hm with rfl | hm; exact g1; exact hacc m hm
                split at h
                · simp only [Except.ok.injEq, Prod.mk.injEq] at h; obtain ⟨rfl, -⟩ := h
                  exact ⟨_, rfl, fun m hm => hacc' m (by simp at hm ⊢; tauto)⟩
                · exact ihM d _ _ v r hd hacc' h
                · simp at h
            · simp at h
      · simp at h


/-- **The reader's output is a document.** Every value the reader returns holds no key twice in any
object, only integers within plus or minus 2^53 minus 1, and nests at most `maxDepth` deep; the
value's strings are `String`s, which hold Unicode scalar values only, so no lone surrogate. -/
theorem readChars_doc {cs : List Char} {v : J} (h : readChars cs = .ok v) : doc v = true := by
  have hw := readChars_wf h
  unfold readChars at h
  split at h
  · simp at h
  · rename_i v1 r1 h1
    have g := (reader_good _).1 0 cs v1 r1 (by decide) h1
    split at h
    · split at h
      · simp only [Except.ok.injEq] at h; subst h
        simp only [doc, hw, g.1, Bool.and_self, decide_eq_true_eq, Bool.true_and]
        have := g.2; omega
      · simp at h
    · simp at h

theorem readBytes_doc {b : ByteArray} {v : J} (h : readBytes b = .ok v) : doc v = true := by
  unfold readBytes at h
  split at h
  · simp at h
  · exact readChars_doc h

end Core
