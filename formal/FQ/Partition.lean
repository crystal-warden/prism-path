-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import FQ.Syntax
import Mathlib.Data.List.Dedup
/-!
# Figueroa quantization: the per field partitions

Mirrors `prismpath/telemetry/quantizer.py` after the September 2026 correction (the reference used
only the ordering and equality constants as cut points; `in` and `not in` lists and the truthiness
cut at zero were omitted, so I1 failed on those atoms; found while stating this file).

Two formulations of the numeric partition:
* `symbolAlg`: the reference algorithm, a fine grid of point and gap cells from the sorted constants,
  adjacent cells merged when their atom truth vectors at the representatives coincide. Executable;
  this is what parity with the Python and Rust implementations is checked against.
* `symbolCount`: the canonical form the theorem is proven over. The fine boundaries are every `c`
  and `c + 1`; a boundary is retained when the atom truth vector differs across it; the symbol is
  the number of retained boundaries at or below the value. `FQ.Bridge` checks the two agree.

Specification decision 3 (see Syntax.lean): "coarsest" (I1b) is a separate statement. Decision 4:
the categorical partition ends in the `other` cell. Decision 5: booleans are two cells.
-/

namespace FQ

/-! ## Atoms of one field -/

/-- One field's view of an atom, constants already restricted to the field's kind. -/
inductive NumAtom where
  | cmp (op : Op) (c : Int)
  | mem (cs : List Int)
  | nmem (cs : List Int)
  | truthy
  deriving DecidableEq, Repr

def numAtomTrue (a : NumAtom) (v : Int) : Bool :=
  match a with
  | .cmp op c => cmpVal (.int v) op (.int c)
  | .mem cs   => cs.any (· == v)
  | .nmem cs  => !(cs.any (· == v))
  | .truthy   => v != 0

def truthVec (atoms : List NumAtom) (v : Int) : List Bool := atoms.map (numAtomTrue · v)

/-- The constants of a field's atoms, the truthiness cut at zero included. This is the correction:
every value an atom can change truth at is a constant here. -/
def numConsts (atoms : List NumAtom) : List Int :=
  let raw := atoms.foldr (fun a acc =>
    match a with
    | .cmp _ c => c :: acc
    | .mem cs  => cs ++ acc
    | .nmem cs => cs ++ acc
    | .truthy  => 0 :: acc) []
  let base := if raw.isEmpty then [0] else raw
  (base.mergeSort (· ≤ ·)).dedup

/-! ## The reference algorithm: fine grid, then merge -/

structure NumCell where
  lo  : Option Int
  hi  : Option Int
  rep : Int
  deriving DecidableEq, Repr

def NumCell.contains (c : NumCell) (v : Int) : Bool :=
  (match c.lo with | some l => l ≤ v | none => true) &&
  (match c.hi with | some h => v ≤ h | none => true)

def cellRep (lo hi : Option Int) : Int :=
  match lo, hi with
  | some l, _ => l
  | none, some h => h
  | none, none => 0

/-- Point cells at each sorted constant and the gaps between them, the leading gap first. -/
def fineGrid : List Int → List (Option Int × Option Int)
  | [] => [(none, none)]
  | c :: rest => (none, some (c - 1)) :: fineFrom c rest
where
  fineFrom (c : Int) : List Int → List (Option Int × Option Int)
    | [] => [(some c, some c), (some (c + 1), none)]
    | n :: rest =>
      if c + 1 ≤ n - 1 then (some c, some c) :: (some (c + 1), some (n - 1)) :: fineFrom n rest
      else (some c, some c) :: fineFrom n rest

/-- Merge adjacent fine cells whose truth vectors at their representatives agree. -/
def mergeCells (atoms : List NumAtom) : List (Option Int × Option Int) → List NumCell
  | [] => []
  | (lo, hi) :: rest => go ⟨lo, hi, cellRep lo hi⟩ (truthVec atoms (cellRep lo hi)) rest
where
  go (cur : NumCell) (tv : List Bool) : List (Option Int × Option Int) → List NumCell
    | [] => [cur]
    | (lo, hi) :: rest =>
      let r := cellRep lo hi
      if truthVec atoms r == tv then go { cur with hi := hi } tv rest
      else cur :: go ⟨lo, hi, r⟩ (truthVec atoms r) rest

def numericCells (atoms : List NumAtom) : List NumCell :=
  mergeCells atoms (fineGrid (numConsts atoms))

/-- The reference symbol: index of the first cell containing the value. -/
def symbolAlg (atoms : List NumAtom) (v : Int) : Nat :=
  (numericCells atoms).findIdx (·.contains v)

def repAlg (atoms : List NumAtom) (s : Nat) : Int :=
  match (numericCells atoms)[s]? with
  | some c => c.rep
  | none => 0

/-! ## The canonical form the theorem is proven over -/

/-- Fine boundaries: every constant and its successor. -/
def boundaries (consts : List Int) : List Int :=
  ((consts.flatMap (fun c => [c, c + 1])).mergeSort (· ≤ ·)).dedup

/-- A boundary is retained when the truth vector differs across it. -/
def retained (atoms : List NumAtom) : List Int :=
  (boundaries (numConsts atoms)).filter (fun b => truthVec atoms (b - 1) != truthVec atoms b)

/-- The canonical symbol: how many retained boundaries lie at or below the value. -/
def symbolCount (atoms : List NumAtom) (v : Int) : Nat :=
  (retained atoms).countP (· ≤ v)

/-! ## Boolean and categorical fields -/

def symbolBool (v : Bool) : Nat := if v then 1 else 0
def repBool (s : Nat) : Bool := s == 1

/-- The named constants in first appearance order; the trailing cell is `other`. -/
def catConsts (atoms : List (Op × List String)) : List String :=
  (atoms.flatMap (·.2)).dedup

/-- Index of the first matching constant, or `consts.length` for the trailing `other` cell. -/
def symbolCat : List String → String → Nat
  | [], _ => 0
  | c :: rest, v => if c == v then 0 else symbolCat rest v + 1

def otherSentinel : String := "\x00__other__"

def repCat (consts : List String) (s : Nat) : String :=
  match consts[s]? with
  | some c => c
  | none => otherSentinel

/-- The field an atom condition reads, `none` for compound conditions and the catch all. -/
def atomField : Cond → Option String
  | .cmp f _ _ => some f | .mem f _ => some f | .nmem f _ => some f | .truthy f => some f
  | _ => none

/-- An atom's truth as a function of the one value it reads. -/
def atomEval : Cond → Value → Bool
  | .cmp _ op c, v => cmpVal v op c
  | .mem _ cs, v   => memVal v cs
  | .nmem _ cs, v  => !(memVal v cs)
  | .truthy _, v   => truthyVal v
  | _, _ => false

/-! ## From a policy to its partitions -/

inductive Kind where
  | numeric | boolean | categorical
  deriving DecidableEq, Repr

/-- One field's partition, carrying what its symbol and representative functions need. -/
inductive FieldPartition where
  | numeric (field : String) (atoms : List NumAtom)
  | boolean (field : String)
  | categorical (field : String) (consts : List String)
  deriving DecidableEq, Repr

def FieldPartition.field : FieldPartition → String
  | .numeric f _ => f | .boolean f => f | .categorical f _ => f

/-- Collect every atom of a condition as (field, atom shape). Ordering, equality, membership, and
truthiness, exactly the shapes `_atoms` in quantizer.py collects. -/
def condAtoms : Cond → List (String × Cond)
  | .cmp f op c  => [(f, .cmp f op c)]
  | .mem f cs    => [(f, .mem f cs)]
  | .nmem f cs   => [(f, .nmem f cs)]
  | .truthy f    => [(f, .truthy f)]
  | .and a b     => condAtoms a ++ condAtoms b
  | .or a b      => condAtoms a ++ condAtoms b
  | .not a       => condAtoms a
  | .tt          => []

def policyAtoms {Action : Type} (p : Policy Action) : List (String × Cond) :=
  p.flatMap (fun r => condAtoms r.cond)

def fieldsOf {Action : Type} (p : Policy Action) : List String :=
  ((policyAtoms p).map (·.1)).dedup

def ints : List Value → List Int
  | [] => []
  | .int n :: rest => n :: ints rest
  | _ :: rest => ints rest

def strs : List Value → List String
  | [] => []
  | .str s :: rest => s :: strs rest
  | _ :: rest => strs rest

/-- Field kind from its constants, as `_classify_kind`: any string constant makes it categorical,
else any integer constant makes it numeric, else boolean. Mixed string and integer constants are
not a Level M field and are classified categorical here; `WellTyped` excludes them. -/
def kindOf (atoms : List Cond) : Kind :=
  let consts : List Value := atoms.flatMap (fun a =>
    match a with
    | .cmp _ _ c => [c]
    | .mem _ cs | .nmem _ cs => cs
    | _ => [])
  if consts.any (fun c => match c with | .str _ => true | _ => false) then .categorical
  else if consts.any (fun c => match c with | .int _ => true | _ => false) then .numeric
  else .boolean

def toNumAtom : Cond → Option NumAtom
  | .cmp _ op (.int c) => some (.cmp op c)
  | .mem _ cs  => some (.mem (ints cs))
  | .nmem _ cs => some (.nmem (ints cs))
  | .truthy _  => some .truthy
  | _ => none

/-- Truthiness of a string is `s != ""`, so on a categorical field it is the atom with constant `""`;
without that constant the empty string and an unnamed string would share the `other` cell and differ
in truth (found while writing this file; the reference omitted it). -/
def toCatAtom : Cond → Option (Op × List String)
  | .cmp _ op (.str c) => some (op, [c])
  | .mem _ cs  => some (.eq, strs cs)
  | .nmem _ cs => some (.ne, strs cs)
  | .truthy _  => some (.ne, [""])
  | _ => none

def partitionOf (field : String) (atoms : List Cond) : FieldPartition :=
  match kindOf atoms with
  | .numeric => .numeric field (atoms.filterMap toNumAtom)
  | .boolean => .boolean field
  | .categorical => .categorical field (catConsts (atoms.filterMap toCatAtom))

def buildPartitions {Action : Type} (p : Policy Action) : List FieldPartition :=
  (fieldsOf p).map (fun f => partitionOf f ((policyAtoms p).filterMap (fun (g, a) => if g == f then some a else none)))

/-! ## Quantize and reconstruct -/

/-- The symbol of a value under one partition (canonical numeric form). Ill typed values take
symbol 0; the theorem assumes well typed readings. -/
def symbolOf : FieldPartition → Value → Nat
  | .numeric _ atoms, .int v   => symbolCount atoms v
  | .boolean _,       .bool b  => symbolBool b
  | .categorical _ cs, .str s  => symbolCat cs s
  | _, _ => 0

def representativeOf : FieldPartition → Nat → Value
  | .numeric _ atoms, s   => .int (repCount atoms s)
  | .boolean _, s         => .bool (repBool s)
  | .categorical _ cs, s  => .str (repCat cs s)
where
  /-- The smallest value with the given canonical symbol: the retained boundary at that index, or
  one below the first retained boundary for symbol 0. -/
  repCount (atoms : List NumAtom) (s : Nat) : Int :=
    match s with
    | 0 => match (retained atoms).head? with | some b => b - 1 | none => 0
    | n + 1 => match (retained atoms)[n]? with | some b => b | none => 0

def quantize (parts : List FieldPartition) (r : Reading) : List (String × Nat) :=
  parts.map (fun p => (p.field, symbolOf p (r p.field)))

def reconstruct (parts : List FieldPartition) (syms : List (String × Nat)) : Reading :=
  fun f =>
    match parts.find? (·.field == f), syms.lookup f with
    | some p, some s => representativeOf p s
    | _, _ => .int 0

/-- A reading is well typed for a partition list when every covered field carries a value of the
field's kind. -/
def WellTyped (parts : List FieldPartition) (r : Reading) : Prop :=
  ∀ p ∈ parts, match p, r p.field with
    | .numeric _ _, .int _ => True
    | .boolean _, .bool _ => True
    | .categorical _ _, .str _ => True
    | _, _ => False

end FQ
