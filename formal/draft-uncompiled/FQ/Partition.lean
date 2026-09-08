-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC

import FQ.Syntax
import FQ.Eval

/-!
# Figueroa Field Partitions and Product Quantization

This module implements per-field partition construction (numeric fine grid with adjacent merge,
boolean two-cell partition, categorical partition with trailing other cell) and computable symbol mapping.

## Specification Decisions (HANDOFF Section 4)

1. Domain is the Integers (Int):
   `NumericCell` endpoints `lo` and `hi` are `Option Int`. fine-grid partitioning operates over closed
   integer intervals and integer gaps.

2. Total Readings:
   Quantization `quantize` maps total readings (`Reading := String → Value`) to per-field symbol indices.

3. Coarsest Partition as Separate Claim (I1b):
   `numericPartition` merges adjacent fine-grid cells with identical atom truth vectors. The property
   that distinct merged cells have distinct truth vectors is stated separately as theorem I1b in `I1.lean`.

4. Categorical Other Cell:
   `CategoricalCell` represents the fallback cell with `const := none` and representative sentinel string `sentinelOther`.

5. Booleans:
   `booleanPartition` builds exactly two cells (0 for false, 1 for true), representing boolean truthiness.
-/

/-- Sentinel string constant representing the categorical 'other' cell. -/
def sentinelOther : String := "\x00__other__"

/-- Closed integer interval cell `[lo, hi]` with open unbounded ends represented by `none`. -/
structure NumericCell where
  lo : Option Int
  hi : Option Int
  rep : Int
  deriving BEq, DecidableEq, Repr

/-- Membership test for numeric cell `[lo, hi]`. -/
def NumericCell.contains (c : NumericCell) (v : Int) : Bool :=
  let loOk := match c.lo with | none => true | some l => v >= l
  let hiOk := match c.hi with | none => true | some h => v <= h
  loOk && hiOk

/-- Compute representative value for numeric interval `(lo, hi)`. -/
def numericCellRep (lo hi : Option Int) : Int :=
  match lo with
  | some l => l
  | none =>
    match hi with
    | some h => h
    | none => 0

/-- Categorical partition cell: exact string constant or `none` for trailing 'other' cell. -/
structure CategoricalCell where
  const : Option String
  rep : String
  deriving BEq, DecidableEq, Repr

/-- Per-field partition structure (numeric, boolean, or categorical). -/
inductive FieldPartition where
  | numeric (field : String) (cells : List NumericCell)
  | boolean (field : String)
  | categorical (field : String) (cells : List CategoricalCell)
  deriving BEq, DecidableEq, Repr

/-- Extract the field name associated with a partition. -/
def FieldPartition.fieldName : FieldPartition → String
  | FieldPartition.numeric f _ => f
  | FieldPartition.boolean f => f
  | FieldPartition.categorical f _ => f

/-- Evaluate truth vector of field atoms for a candidate integer value. -/
def numericAtomTruthVector (atoms : List Atom) (v : Int) : List Bool :=
  atoms.map (fun a => evalAtom a (fun _ => Value.int v))

/-- Helper insertion for integer sorting. -/
def insertSortedInt (x : Int) (l : List Int) : List Int :=
  match l with
  | [] => [x]
  | y :: ys => if x <= y then x :: y :: ys else y :: insertSortedInt x ys

/-- Sort a list of integers. -/
def sortInts (l : List Int) : List Int :=
  l.foldr insertSortedInt []

/-- Remove duplicates from an integer list. -/
def dedupInts (l : List Int) : List Int :=
  match l with
  | [] => []
  | x :: xs => if xs.contains x then dedupInts xs else x :: dedupInts xs

/-- Remove duplicates from a string list. -/
def dedupStrings (l : List String) : List String :=
  match l with
  | [] => []
  | x :: xs => if xs.contains x then dedupStrings xs else x :: dedupStrings xs

/-- Generate fine-grid numeric interval cells from sorted constant cuts. -/
def buildFineGrid (consts : List Int) : List (Option Int × Option Int) :=
  match consts with
  | [] => [(none, none)]
  | c0 :: rest =>
    let firstGap := (none, some (c0 - 1))
    let rec loop (curr : Int) (rem : List Int) : List (Option Int × Option Int) :=
      let pointCell := (some curr, some curr)
      match rem with
      | [] => [pointCell, (some (curr + 1), none)]
      | nxt :: r =>
        let lo := curr + 1
        let hi := nxt - 1
        if lo <= hi then
          pointCell :: (some lo, some hi) :: loop nxt r
        else
          pointCell :: loop nxt r
    firstGap :: loop c0 rest

/-- Merge adjacent fine-grid cells with identical atom truth vectors. -/
def mergeFineGrid (atoms : List Atom) (fine : List (Option Int × Option Int)) : List NumericCell :=
  match fine with
  | [] => []
  | (lo0, hi0) :: rest =>
    let r0 := numericCellRep lo0 hi0
    let tv0 := numericAtomTruthVector atoms r0
    let initCell := { lo := lo0, hi := hi0, rep := r0 : NumericCell }
    let rec loop (currCell : NumericCell) (currTv : List Bool) (rem : List (Option Int × Option Int)) : List NumericCell :=
      match rem with
      | [] => [currCell]
      | (lo, hi) :: r =>
        let rep := numericCellRep lo hi
        let tv := numericAtomTruthVector atoms rep
        if tv == currTv then
          loop { currCell with hi := hi } currTv r
        else
          currCell :: loop { lo := lo, hi := hi, rep := rep } tv r
    loop initCell tv0 rest

/-- Construct numeric field partition from field name, atoms, and extracted constants. -/
def numericPartition (field : String) (atoms : List Atom) (rawConsts : List Int) : FieldPartition :=
  let sortedConsts := sortInts (dedupInts rawConsts)
  let consts := if sortedConsts.isEmpty then [0] else sortedConsts
  let fine := buildFineGrid consts
  let cells := mergeFineGrid atoms fine
  FieldPartition.numeric field cells

/-- Construct boolean field partition (two cells: 0 for false, 1 for true). -/
def booleanPartition (field : String) : FieldPartition :=
  FieldPartition.boolean field

/-- Construct categorical field partition (one cell per constant + trailing 'other' cell). -/
def categoricalPartition (field : String) (rawConsts : List String) : FieldPartition :=
  let consts := dedupStrings rawConsts
  let cells := consts.map (fun c => { const := some c, rep := c : CategoricalCell }) ++
               [{ const := none, rep := sentinelOther : CategoricalCell }]
  FieldPartition.categorical field cells

/-- Map a field value to its partition symbol index. -/
def symbol (p : FieldPartition) (v : Value) : Nat :=
  match p with
  | FieldPartition.numeric _ cells =>
    let intVal := match v with | Value.int i => i | Value.bool b => if b then 1 else 0 | Value.str _ => 0
    let rec findIdx (idx : Nat) (clist : List NumericCell) : Nat :=
      match clist with
      | [] => 0
      | c :: cs => if c.contains intVal then idx else findIdx (idx + 1) cs
    findIdx 0 cells
  | FieldPartition.boolean _ =>
    if evalValueTruthiness v then 1 else 0
  | FieldPartition.categorical _ cells =>
    match v with
    | Value.str s =>
      let rec findIdx (idx : Nat) (clist : List CategoricalCell) : Nat :=
        match clist with
        | [] => cells.length - 1
        | c :: cs =>
          match c.const with
          | some sc => if sc == s then idx else findIdx (idx + 1) cs
          | none => cells.length - 1
      findIdx 0 cells
    | _ => cells.length - 1

/-- Map a partition symbol index back to its representative value. -/
def representative (p : FieldPartition) (sym : Nat) : Value :=
  match p with
  | FieldPartition.numeric _ cells =>
    match cells.get? sym with
    | some c => Value.int c.rep
    | none => Value.int 0
  | FieldPartition.boolean _ =>
    if sym == 1 then Value.bool true else Value.bool false
  | FieldPartition.categorical _ cells =>
    match cells.get? sym with
    | some c => Value.str c.rep
    | none => Value.str sentinelOther

/-- Quantize a total reading across a list of field partitions. -/
def quantize (parts : List FieldPartition) (r : Reading) : String → Nat :=
  fun field =>
    match parts.find? (fun p => p.fieldName == field) with
    | some p => symbol p (r field)
    | none => 0

/-- Reconstruct a representative total reading from field symbol assignments. -/
def reconstruct (parts : List FieldPartition) (syms : String → Nat) : Reading :=
  fun field =>
    match parts.find? (fun p => p.fieldName == field) with
    | some p => representative p (syms field)
    | none => Value.int 0
