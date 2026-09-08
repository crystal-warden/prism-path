-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC

/-!
# Syntax of the Level M Predicate Language and Policies

This module defines the abstract syntax tree (AST) for Level M predicates and match-action policies
for Figueroa Quantization (FQ).

## Specification Decisions (HANDOFF Section 4)

1. Domain is the Integers (Int):
   Numeric constants are integer valued (`Value.int (n : Int)`). Floats and reals are excluded from
   Level M syntax per SPEC Section 4.3 and HANDOFF Section 4.1.

2. Total Readings:
   Readings are total assignments mapping field names (Strings) to Values (`String → Value`).

3. Coarsest Partition as Separate Claim (I1b):
   The syntax isolates cut points per field. Coarsest partition minimality (I1b) is a separate property
   from decision preservation (I1).

4. Categorical Other Cell:
   Categorical constants are strings (`Value.str`), with an implicit trailing fallback cell for unmatched strings.

5. Booleans:
   Boolean values are represented by `Value.bool (b : Bool)`, restricted to truthiness and equality checks.
-/

/-- Scalar values supported in Level M readings and predicate constants. -/
inductive Value where
  | int (n : Int)
  | bool (b : Bool)
  | str (s : String)
  deriving BEq, DecidableEq, Repr

/-- Atom comparison operators supported in Level M fragment. -/
inductive Op where
  | lt     -- <
  | le     -- <=
  | gt     -- >
  | ge     -- >=
  | eq     -- ==
  | ne     -- !=
  | mem    -- in
  | nmem   -- not in
  | truthy -- bare field truthiness
  deriving BEq, DecidableEq, Repr

/-- Constants passed to atom comparisons (scalar value, scalar list, or none for bare truthiness). -/
inductive Const where
  | scalar (v : Value)
  | list (l : List Value)
  | none
  deriving BEq, DecidableEq, Repr

/-- Level M Atom: `field OP const`. -/
structure Atom where
  field : String
  op : Op
  const : Const
  deriving BEq, DecidableEq, Repr

/-- Level M Predicate Condition: boolean combinations of atoms via and/or/not. -/
inductive Cond where
  | atom (a : Atom)
  | and (c1 c2 : Cond)
  | or (c1 c2 : Cond)
  | not (c : Cond)
  deriving BEq, DecidableEq, Repr

/-- Match-action rule: if `cond` matches, yield `action`. -/
structure Rule (Action : Type) where
  cond : Cond
  action : Action
  deriving BEq, DecidableEq, Repr

/-- Level M Policy: ordered list of rules with first-match policy semantics and an optional catch-all action. -/
structure Policy (Action : Type) where
  rules : List (Rule Action)
  catchAll : Option Action
  deriving BEq, DecidableEq, Repr

/-- Field kind classification for partition construction. -/
inductive FieldKind where
  | numeric
  | boolean
  | categorical
  deriving BEq, DecidableEq, Repr

/-- Collect all atoms referenced by a condition tree. -/
def condAtoms : Cond → List Atom
  | Cond.atom a => [a]
  | Cond.and c1 c2 => condAtoms c1 ++ condAtoms c2
  | Cond.or c1 c2 => condAtoms c1 ++ condAtoms c2
  | Cond.not c => condAtoms c

/-- Collect all atoms referenced across all rules in a policy. -/
def policyAtoms {Action : Type} (p : Policy Action) : List Atom :=
  p.rules.bind (fun r => condAtoms r.cond)
