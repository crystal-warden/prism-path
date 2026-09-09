-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import Mathlib.Data.Int.Basic
import Mathlib.Data.List.Basic
/-!
# Figueroa quantization: syntax and evaluation of the Level M fragment

The Level M fragment (SPEC.md section 4.3): boolean combinations of atoms `field OP const`,
`field in [scalars]`, `field not in [scalars]`, and bare `field` truthiness. Constants are integers
(the i32 domain of the tables, modeled as `Int`), booleans, or strings. Floats, field against field,
substring `in`, string ordering, runtime collections, and nested containers are outside the fragment
and outside this model.

Specification decisions (recorded here; formal/README.md states the boundary they draw):
1. Readings are integer valued on numeric fields. `Value.int` is `Int`; there is no float. The
   reference quantizer casts with `int()`; that projection is outside the theorem.
2. Readings are total (`Reading := String → Value`) and, for the theorem, well typed: every field a
   partition covers carries a value of the field's kind (`WellTyped`). Cross kind comparisons and
   missing fields are outside the theorem, stated so.
-/

namespace FQ

/-- A scalar constant or reading value. -/
inductive Value where
  | int  (n : Int)
  | bool (b : Bool)
  | str  (s : String)
  deriving DecidableEq, Repr

/-- Comparison operators of the fragment. -/
inductive Op where
  | lt | le | gt | ge | eq | ne
  deriving DecidableEq, Repr

/-- Conditions of the fragment. `tt` is the unconditional catch all (`else`). -/
inductive Cond where
  | cmp    (field : String) (op : Op) (c : Value)
  | mem    (field : String) (cs : List Value)
  | nmem   (field : String) (cs : List Value)
  | truthy (field : String)
  | and    (a b : Cond)
  | or     (a b : Cond)
  | not    (a : Cond)
  | tt
  deriving DecidableEq, Repr

/-- A total reading. -/
abbrev Reading := String → Value

/-- Python truthiness of a scalar. -/
def truthyVal : Value → Bool
  | .int n  => n != 0
  | .bool b => b
  | .str s  => s != ""

/-- Equality of scalars of the same kind; different kinds are unequal here. Cross kind equalities
(Python's `False == 0`) are outside the well typed theorem. -/
def valEq : Value → Value → Bool
  | .int a,  .int b  => a == b
  | .bool a, .bool b => a == b
  | .str a,  .str b  => a == b
  | _, _ => false

/-- `v OP c`. Ordering is defined on integers only; an ordering on any other kind is unsatisfied,
matching the evaluator's "a comparison that cannot be performed is unsatisfied". -/
def cmpVal (v : Value) (op : Op) (c : Value) : Bool :=
  match op with
  | .eq => valEq v c
  | .ne => !(valEq v c)
  | .lt => match v, c with | .int a, .int b => decide (a < b) | _, _ => false
  | .le => match v, c with | .int a, .int b => decide (a ≤ b) | _, _ => false
  | .gt => match v, c with | .int a, .int b => decide (a > b) | _, _ => false
  | .ge => match v, c with | .int a, .int b => decide (a ≥ b) | _, _ => false

def memVal (v : Value) (cs : List Value) : Bool := cs.any (valEq v)

/-- Evaluation of a condition on a total reading. -/
def evalCond (r : Reading) : Cond → Bool
  | .cmp f op c  => cmpVal (r f) op c
  | .mem f cs    => memVal (r f) cs
  | .nmem f cs   => !(memVal (r f) cs)
  | .truthy f    => truthyVal (r f)
  | .and a b     => evalCond r a && evalCond r b
  | .or a b      => evalCond r a || evalCond r b
  | .not a       => !(evalCond r a)
  | .tt          => true

/-- A policy: ordered rules, first true wins (SPEC.md section 3 step 1). -/
structure Rule (Action : Type) where
  cond : Cond
  act  : Action

abbrev Policy (Action : Type) := List (Rule Action)

/-- The decision function `D`: the action of the first rule whose condition holds, `none` when no
rule matches (the engine's `stuck`, cause 36). -/
def route {Action : Type} (p : Policy Action) (r : Reading) : Option Action :=
  match p.find? (fun rule => evalCond r rule.cond) with
  | some rule => some rule.act
  | none => none

end FQ
