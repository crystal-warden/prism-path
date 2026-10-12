-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import FQ.Contract
import Mathlib.Tactic
/-!
# Contract (b): absence as an explicit cell

The engine reads a missing field as null, and a policy can observe it: `x != 5`, `x not in [1, 2]` and
`not (x < 5)` are all true of an absent `x`. The model of I1 has total readings and no null, so absence
was outside it by declared decision. A flow that defines its fields (SPEC.md section 4.5) makes absence
a value of its own: a field whose definition allows it has one more cell, after every present cell,
whose representative is the absent value, and a policy tests it with `== None`.

This file models that. Readings map each field to a present value or to absence (`none`). Conditions
are the Level M atoms plus `isNone f`, the policy's `f == None` (`f != None` is its negation, which the
engine gives the same truth). Each field's partition takes its kind from the field's definition, never
from its constants, and its symbol for absence is the number of present cells. The theorems: two
canonical readings with the same quantization route identically, absence included; and the decoded
reading routes as the original.

The engine's semantics on an absent field (SPEC.md section 4.2): equality with any constant fails, `!=`
holds, an ordering cannot be performed and fails, membership fails, `not in` holds, truthiness fails.
A list never holds None in a defined flow (section 4.5, rule 5), which the model's constants already
guarantee: `Value` has no null.
-/

namespace FQ

/-- A condition of a flow that defines its fields. -/
inductive XCond where
  | atom (a : Cond)
  | isNone (f : String)
  | and (a b : XCond)
  | or (a b : XCond)
  | not (a : XCond)
  | tt
  deriving DecidableEq, Repr

/-- A reading in which a field may be absent. -/
abbrev OReading := String → Option Value

/-- An atom's truth on an absent field. -/
def atomAbsent : Cond → Bool
  | .cmp _ .ne _ => true
  | .nmem _ _ => true
  | _ => false

/-- The absent cell's semantics are the engine's: on a raw null every atom decides as `atomAbsent`
says, so the model of absence is the engine's null, not a choice made here. -/
theorem atomAbsent_is_engine_null (a : Cond) : atomRaw a .null = atomAbsent a := by
  cases a with
  | cmp f op c => cases op <;> cases c <;> rfl
  | mem f cs =>
    show (cs.any (rawEq .null)) = false
    induction cs with
    | nil => rfl
    | cons c rest ih => cases c <;> simp [List.any_cons, rawEq, numView, constNum, ih]
  | nmem f cs =>
    show (!(cs.any (rawEq .null))) = true
    induction cs with
    | nil => rfl
    | cons c rest ih => cases c <;> simp [List.any_cons, rawEq, numView, constNum, ih]
  | truthy f => rfl
  | and _ _ => rfl
  | or _ _ => rfl
  | not _ => rfl
  | tt => rfl

def atomX (a : Cond) : Option Value → Bool
  | none => atomAbsent a
  | some v => atomEval a v

def atomFieldD (a : Cond) : String := (atomField a).getD ""

def evalX (r : OReading) : XCond → Bool
  | .atom a => atomX a (r (atomFieldD a))
  | .isNone f => (r f).isNone
  | .and a b => evalX r a && evalX r b
  | .or a b => evalX r a || evalX r b
  | .not a => !(evalX r a)
  | .tt => true

structure XRule (Action : Type) where
  cond : XCond
  act : Action

abbrev XPolicy (Action : Type) := List (XRule Action)

def routeX {Action : Type} (p : XPolicy Action) (r : OReading) : Option Action :=
  match p.find? (fun rule => evalX r rule.cond) with
  | some rule => some rule.act
  | none => none

/-! ## Partitions with an absent cell -/

/-- The Level M atoms of a condition with their fields. -/
def xAtoms : XCond → List (String × Cond)
  | .atom a => match atomField a with | some g => [(g, a)] | none => []
  | .isNone _ => []
  | .and a b => xAtoms a ++ xAtoms b
  | .or a b => xAtoms a ++ xAtoms b
  | .not a => xAtoms a
  | .tt => []

/-- The fields a condition tests for absence. -/
def xNone : XCond → List String
  | .isNone f => [f]
  | .and a b => xNone a ++ xNone b
  | .or a b => xNone a ++ xNone b
  | .not a => xNone a
  | _ => []

def xPolicyAtoms {Action : Type} (p : XPolicy Action) : List (String × Cond) :=
  p.flatMap (fun rule => xAtoms rule.cond)

def xPolicyFields {Action : Type} (p : XPolicy Action) : List String :=
  ((xPolicyAtoms p).map (·.1) ++ p.flatMap (fun rule => xNone rule.cond)).dedup

def xFieldAtoms {Action : Type} (p : XPolicy Action) (g : String) : List Cond :=
  (xPolicyAtoms p).filterMap (fun (g', a) => if g' == g then some a else none)

/-- A field's partition with its kind taken from its definition. -/
def definedPartition (k : Kind) (f : String) (atoms : List Cond) : FieldPartition :=
  match k with
  | .numeric => .numeric f (atoms.filterMap toNumAtom)
  | .boolean => .boolean f
  | .categorical => .categorical f (catConsts (atoms.filterMap toCatAtom))

def buildX {Action : Type} (defs : String → Kind) (p : XPolicy Action) : List FieldPartition :=
  (xPolicyFields p).map (fun f => definedPartition (defs f) f (xFieldAtoms p f))

/-- The number of present cells; the absent cell is the next index. -/
def cells : FieldPartition → Nat
  | .numeric _ atoms => (retained atoms).length + 1
  | .boolean _ => 2
  | .categorical _ cs => cs.length + 1

def symbolX (q : FieldPartition) : Option Value → Nat
  | none => cells q
  | some v => symbolOf q v

def quantizeX (parts : List FieldPartition) (r : OReading) : List (String × Nat) :=
  parts.map (fun q => (q.field, symbolX q (r q.field)))

def representativeX (q : FieldPartition) (s : Nat) : Option Value :=
  if s = cells q then none else some (representativeOf q s)

def reconstructX (parts : List FieldPartition) (syms : List (String × Nat)) : OReading :=
  fun f =>
    match parts.find? (·.field == f), syms.lookup f with
    | some q, some s => representativeX q s
    | _, _ => none

/-- A present value of the partition's kind. -/
def HasKind : FieldPartition → Value → Prop
  | .numeric _ _, .int _ => True
  | .boolean _, .bool _ => True
  | .categorical _ _, .str _ => True
  | _, _ => False

/-- A canonical reading: every covered field is a present value of its kind, or absent where its
definition allows absence. -/
def CanonicalX (parts : List FieldPartition) (absentOK : String → Bool) (r : OReading) : Prop :=
  ∀ q ∈ parts, match r q.field with
    | none => absentOK q.field = true
    | some v => HasKind q v

/-! ## Present symbols stay below the absent cell -/

theorem symbolCat_le_length (cs : List String) (s : String) : symbolCat cs s ≤ cs.length := by
  induction cs with
  | nil => simp [symbolCat]
  | cons c rest ih => simp only [symbolCat, List.length_cons]; split <;> omega

theorem present_lt_cells {q : FieldPartition} {v : Value} (h : HasKind q v) : symbolOf q v < cells q := by
  cases q with
  | numeric f atoms =>
    cases v with
    | int n => have := symbolCount_le_length atoms n; simp only [symbolOf, cells]; omega
    | bool _ => simp [HasKind] at h
    | str _ => simp [HasKind] at h
  | boolean f =>
    cases v with
    | bool b => cases b <;> simp [symbolOf, symbolBool, cells]
    | int _ => simp [HasKind] at h
    | str _ => simp [HasKind] at h
  | categorical f cs =>
    cases v with
    | str s => have := symbolCat_le_length cs s; simp only [symbolOf, cells]; omega
    | int _ => simp [HasKind] at h
    | bool _ => simp [HasKind] at h

/-! ## One field: equal symbols give equal atom truth, absence included -/

theorem definedPartition_field (k : Kind) (f : String) (atoms : List Cond) :
    (definedPartition k f atoms).field = f := by
  cases k <;> rfl

theorem present_agree {k : Kind} {f : String} {atomsF : List Cond} {v w : Value}
    (hv : HasKind (definedPartition k f atomsF) v) (hw : HasKind (definedPartition k f atomsF) w)
    (h : symbolOf (definedPartition k f atomsF) v = symbolOf (definedPartition k f atomsF) w) :
    ∀ a ∈ atomsF, atomEval a v = atomEval a w := by
  cases k with
  | numeric =>
    cases v with
    | int n =>
      cases w with
      | int m => exact numeric_agree (by simpa [definedPartition, symbolOf] using h)
      | bool _ => simp [definedPartition, HasKind] at hw
      | str _ => simp [definedPartition, HasKind] at hw
    | bool _ => simp [definedPartition, HasKind] at hv
    | str _ => simp [definedPartition, HasKind] at hv
  | boolean =>
    cases v with
    | bool b =>
      cases w with
      | bool c =>
        have := symbolBool_inj (by simpa [definedPartition, symbolOf] using h)
        subst this; intro _ _; rfl
      | int _ => simp [definedPartition, HasKind] at hw
      | str _ => simp [definedPartition, HasKind] at hw
    | int _ => simp [definedPartition, HasKind] at hv
    | str _ => simp [definedPartition, HasKind] at hv
  | categorical =>
    cases v with
    | str s =>
      cases w with
      | str t => exact categorical_agree (by simpa [definedPartition, symbolOf] using h)
      | int _ => simp [definedPartition, HasKind] at hw
      | bool _ => simp [definedPartition, HasKind] at hw
    | int _ => simp [definedPartition, HasKind] at hv
    | bool _ => simp [definedPartition, HasKind] at hv

/-- Two canonical values of one field with the same symbol are both absent or both present, and every
atom of the field gives them the same truth. -/
theorem field_agree {k : Kind} {f : String} {atomsF : List Cond} {x y : Option Value}
    (hx : ∀ v, x = some v → HasKind (definedPartition k f atomsF) v)
    (hy : ∀ v, y = some v → HasKind (definedPartition k f atomsF) v)
    (h : symbolX (definedPartition k f atomsF) x = symbolX (definedPartition k f atomsF) y) :
    x.isNone = y.isNone ∧ ∀ a ∈ atomsF, atomX a x = atomX a y := by
  cases x with
  | none =>
    cases y with
    | none => exact ⟨rfl, fun _ _ => rfl⟩
    | some w =>
      have := present_lt_cells (hy w rfl)
      simp only [symbolX] at h; omega
  | some v =>
    cases y with
    | none =>
      have := present_lt_cells (hx v rfl)
      simp only [symbolX] at h; omega
    | some w =>
      refine ⟨rfl, fun a ha => ?_⟩
      exact present_agree (hx v rfl) (hy w rfl) (by simpa [symbolX] using h) a ha

/-! ## From fields to the policy -/

theorem xAtoms_field {c : XCond} : ∀ {g a}, (g, a) ∈ xAtoms c → atomField a = some g := by
  induction c with
  | atom a =>
    intro g b h
    simp only [xAtoms] at h
    split at h
    · rename_i g' hg; simp at h; obtain ⟨rfl, rfl⟩ := h; exact hg
    · simp at h
  | isNone _ => intro g a h; simp [xAtoms] at h
  | and a b iha ihb => intro g x h; simp only [xAtoms, List.mem_append] at h; rcases h with h | h; exact iha h; exact ihb h
  | or a b iha ihb => intro g x h; simp only [xAtoms, List.mem_append] at h; rcases h with h | h; exact iha h; exact ihb h
  | not a ih => intro g x h; exact ih h
  | tt => intro g a h; simp [xAtoms] at h

theorem evalX_congr {r r' : OReading} : ∀ c : XCond,
    (∀ g a, (g, a) ∈ xAtoms c → atomX a (r g) = atomX a (r' g)) →
    (∀ f ∈ xNone c, (r f).isNone = (r' f).isNone) → evalX r c = evalX r' c := by
  intro c
  induction c with
  | atom a =>
    intro ha _
    simp only [evalX]
    cases hf : atomField a with
    | none =>
      -- not an atom: false whether the field is present or absent
      have hc : ∀ o : Option Value, atomX a o = false := by
        intro o; cases o <;> cases a <;> simp_all [atomField, atomX, atomAbsent, atomEval]
      rw [hc, hc]
    | some g =>
      have hd : atomFieldD a = g := by simp [atomFieldD, hf]
      rw [hd]
      exact ha g a (by simp [xAtoms, hf])
  | isNone f => intro _ hn; simp only [evalX]; exact hn f (by simp [xNone])
  | and a b iha ihb =>
    intro ha hn
    simp only [evalX]
    rw [iha (fun g x h => ha g x (by simp [xAtoms, h])) (fun f h => hn f (by simp [xNone, h])),
        ihb (fun g x h => ha g x (by simp [xAtoms, h])) (fun f h => hn f (by simp [xNone, h]))]
  | or a b iha ihb =>
    intro ha hn
    simp only [evalX]
    rw [iha (fun g x h => ha g x (by simp [xAtoms, h])) (fun f h => hn f (by simp [xNone, h])),
        ihb (fun g x h => ha g x (by simp [xAtoms, h])) (fun f h => hn f (by simp [xNone, h]))]
  | not a ih => intro ha hn; simp only [evalX]; rw [ih ha hn]
  | tt => intro _ _; rfl

theorem mem_buildX {Action : Type} {defs : String → Kind} {p : XPolicy Action} {g : String}
    (h : g ∈ xPolicyFields p) : definedPartition (defs g) g (xFieldAtoms p g) ∈ buildX defs p :=
  List.mem_map.mpr ⟨g, h, rfl⟩

theorem buildX_fields_nodup {Action : Type} (defs : String → Kind) (p : XPolicy Action) :
    ((buildX defs p).map FieldPartition.field).Nodup := by
  unfold buildX
  rw [List.map_map]
  have : (FieldPartition.field ∘ fun f => definedPartition (defs f) f (xFieldAtoms p f)) = id := by
    funext f; simp [definedPartition_field]
  rw [this, List.map_id]
  exact List.nodup_dedup _

theorem lookup_quantizeX {parts : List FieldPartition} (hnd : (parts.map FieldPartition.field).Nodup)
    {q : FieldPartition} (hq : q ∈ parts) (r : OReading) :
    (quantizeX parts r).lookup q.field = some (symbolX q (r q.field)) := by
  unfold quantizeX
  induction parts with
  | nil => simp at hq
  | cons s rest ih =>
    rcases List.mem_cons.mp hq with rfl | hq'
    · simp
    · have hne : s.field ≠ q.field := by
        simp only [List.map_cons, List.nodup_cons, List.mem_map] at hnd
        intro heq; exact hnd.1 ⟨q, hq', heq.symm⟩
      have hb : (q.field == s.field) = false := by simpa using (Ne.symm hne)
      simp only [List.map_cons, List.lookup, hb]
      exact ih (List.nodup_cons.mp (by simpa using hnd)).2 hq'

theorem symbolX_of_quantizeX {parts : List FieldPartition} {r r' : OReading}
    (h : quantizeX parts r = quantizeX parts r') : ∀ q ∈ parts, symbolX q (r q.field) = symbolX q (r' q.field) := by
  intro q hq
  have := (List.map_inj_left.mp h) q hq
  simpa using this

theorem mem_xFieldAtoms {Action : Type} {p : XPolicy Action} {g : String} {a : Cond}
    (h : (g, a) ∈ xPolicyAtoms p) : a ∈ xFieldAtoms p g := by
  unfold xFieldAtoms
  rw [List.mem_filterMap]
  exact ⟨(g, a), h, by simp⟩

/-- Canonical readings give a defined partition's field present values of its kind. -/
theorem canonical_kind {parts : List FieldPartition} {absentOK : String → Bool} {r : OReading}
    (hr : CanonicalX parts absentOK r) {q : FieldPartition} (hq : q ∈ parts) :
    ∀ v, r q.field = some v → HasKind q v := by
  intro v hv
  have := hr q hq
  rw [hv] at this
  exact this

/-- **Contract (b), absence as an explicit cell.** For a flow that defines its fields, two canonical
readings with the same quantization route identically, whether each field is present or absent. -/
theorem absence_preservation {Action : Type} (p : XPolicy Action) (defs : String → Kind)
    (absentOK : String → Bool) (r r' : OReading)
    (hr : CanonicalX (buildX defs p) absentOK r) (hr' : CanonicalX (buildX defs p) absentOK r')
    (h : quantizeX (buildX defs p) r = quantizeX (buildX defs p) r') :
    routeX p r = routeX p r' := by
  have hsym := symbolX_of_quantizeX h
  -- every field the policy reads agrees, on absence and on every atom
  have hfield : ∀ g ∈ xPolicyFields p,
      (r g).isNone = (r' g).isNone ∧ ∀ a ∈ xFieldAtoms p g, atomX a (r g) = atomX a (r' g) := by
    intro g hg
    have hq := mem_buildX (defs := defs) hg
    have hs := hsym _ hq
    rw [definedPartition_field] at hs
    have hk := canonical_kind hr hq
    have hk' := canonical_kind hr' hq
    rw [definedPartition_field] at hk hk'
    exact field_agree hk hk' hs
  have hcond : ∀ rule ∈ p, evalX r rule.cond = evalX r' rule.cond := by
    intro rule hrule
    apply evalX_congr
    · intro g a hga
      have hmem : (g, a) ∈ xPolicyAtoms p := by
        unfold xPolicyAtoms; rw [List.mem_flatMap]; exact ⟨rule, hrule, hga⟩
      have hg : g ∈ xPolicyFields p := by
        unfold xPolicyFields; rw [List.mem_dedup, List.mem_append, List.mem_map]
        exact Or.inl ⟨(g, a), hmem, rfl⟩
      exact (hfield g hg).2 a (mem_xFieldAtoms hmem)
    · intro f hf
      have hg : f ∈ xPolicyFields p := by
        unfold xPolicyFields; rw [List.mem_dedup, List.mem_append, List.mem_flatMap]
        exact Or.inr ⟨rule, hrule, hf⟩
      exact (hfield f hg).1
  unfold routeX
  rw [List.find?_congr hcond]

/-! ## The decoded reading -/

theorem symbol_representative {q : FieldPartition} (hns : match q with | .categorical _ cs => otherSentinel ∉ cs | _ => True)
    {v : Value} (hv : HasKind q v) : symbolOf q (representativeOf q (symbolOf q v)) = symbolOf q v := by
  cases q with
  | numeric f atoms =>
    cases v with
    | int n => simp only [symbolOf, representativeOf]; rw [symbolCount_repCount]
    | bool _ => simp [HasKind] at hv
    | str _ => simp [HasKind] at hv
  | boolean f =>
    cases v with
    | bool b => cases b <;> simp [symbolOf, representativeOf, symbolBool, repBool]
    | int _ => simp [HasKind] at hv
    | str _ => simp [HasKind] at hv
  | categorical f cs =>
    cases v with
    | str s => simp only [symbolOf, representativeOf]; rw [symbolCat_repCat hns]
    | int _ => simp [HasKind] at hv
    | bool _ => simp [HasKind] at hv

theorem representative_hasKind (q : FieldPartition) (s : Nat) : HasKind q (representativeOf q s) := by
  cases q <;> trivial

theorem representativeX_present {q : FieldPartition} {s : Nat} (h : s < cells q) :
    representativeX q s = some (representativeOf q s) := by
  unfold representativeX
  exact if_neg (Nat.ne_of_lt h)

theorem representativeX_absent (q : FieldPartition) : representativeX q (cells q) = none := by
  unfold representativeX
  exact if_pos rfl

/-- The decode of a canonical reading's quantization has the same quantization, and is canonical. -/
theorem quantizeX_reconstructX {parts : List FieldPartition} (hnd : (parts.map FieldPartition.field).Nodup)
    (hns : NoSentinel parts) {absentOK : String → Bool} {r : OReading} (hr : CanonicalX parts absentOK r) :
    quantizeX parts (reconstructX parts (quantizeX parts r)) = quantizeX parts r ∧
    CanonicalX parts absentOK (reconstructX parts (quantizeX parts r)) := by
  have hdec : ∀ q ∈ parts, reconstructX parts (quantizeX parts r) q.field = representativeX q (symbolX q (r q.field)) := by
    intro q hq
    simp only [reconstructX, find?_field hnd hq, lookup_quantizeX hnd hq r]
  have hdec' : ∀ q ∈ parts,
      reconstructX parts (parts.map (fun q => (q.field, symbolX q (r q.field)))) q.field
        = representativeX q (symbolX q (r q.field)) := hdec
  refine ⟨?_, ?_⟩
  · unfold quantizeX
    apply List.map_congr_left
    intro q hq
    rw [hdec' q hq]
    congr 1
    cases hrq : r q.field with
    | none => rw [show symbolX q none = cells q from rfl, representativeX_absent]; rfl
    | some v =>
      have hk := canonical_kind hr hq v hrq
      have hlt := present_lt_cells hk
      rw [show symbolX q (some v) = symbolOf q v from rfl, representativeX_present hlt]
      exact symbol_representative (hns q hq) hk
  · intro q hq
    show (match reconstructX parts (quantizeX parts r) q.field with
      | none => absentOK q.field = true
      | some v => HasKind q v)
    rw [hdec q hq]
    cases hrq : r q.field with
    | none =>
      have := hr q hq; rw [hrq] at this
      rw [show symbolX q none = cells q from rfl, representativeX_absent]
      exact this
    | some v =>
      have hlt := present_lt_cells (canonical_kind hr hq v hrq)
      rw [show symbolX q (some v) = symbolOf q v from rfl, representativeX_present hlt]
      exact representative_hasKind q _

/-- **Corollary.** The decoded reading of a canonical reading routes as the original, absence
included: Facet carries the policy's decision on every canonical reading of a defined flow. -/
theorem reconstructX_route {Action : Type} (p : XPolicy Action) (defs : String → Kind)
    (absentOK : String → Bool) (r : OReading) (hr : CanonicalX (buildX defs p) absentOK r)
    (hns : NoSentinel (buildX defs p)) :
    routeX p (reconstructX (buildX defs p) (quantizeX (buildX defs p) r)) = routeX p r := by
  obtain ⟨hq, hc⟩ := quantizeX_reconstructX (buildX_fields_nodup defs p) hns hr
  exact absence_preservation p defs absentOK _ r hc hr hq

end FQ
