-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC

import FQ.Syntax

/-!
# Evaluation Semantics for Level M Predicates and Policies

This module implements the evaluation logic for atoms, conditions, and first-match policies over total readings.

## Specification Decisions (HANDOFF Section 4)

1. Domain is the Integers (Int):
   `evalAtom` evaluates numeric comparison operators (`<`, `<=`, `>`, `>=`, `==`, `!=`) directly over
   `Int` values (`Value.int`). Cross-type comparisons or non-integer operands evaluate to false.

2. Total Readings:
   Evaluation is defined over `Reading := String → Value`, representing total readings where every field
   is present. Missing field / null handling is outside this core theorem scope.

3. Coarsest Partition as Separate Claim (I1b):
   `evalCond` evaluates predicates boolean-wise. Coarsest partition minimality (I1b) is a separate property.

4. Categorical Other Cell:
   Categorical string comparisons match against explicit string constants; unmatched strings evaluate `==` to false.

5. Booleans:
   `evalValueTruthiness` maps `Value.bool b` to `b`, `Value.int n` to `n != 0`, and `Value.str s` to `s != ""`.
-/

/-- A total reading maps every field name to its value. -/
def Reading := String → Value

/-- Truthiness of a value following SPEC Section 4.2 and quantizer.py semantics. -/
def evalValueTruthiness : Value → Bool
  | Value.int n => n ≠ 0
  | Value.bool b => b
  | Value.str s => s ≠ ""

/-- Check if a value is contained in a list of constants under equality. -/
def valueInList (v : Value) (l : List Value) : Bool :=
  l.contains v

/-- Evaluate an individual Level M atom against a total reading. -/
def evalAtom (a : Atom) (r : Reading) : Bool :=
  let v := r a.field
  match a.op, a.const with
  | Op.lt, Const.scalar (Value.int c) =>
    match v with
    | Value.int i => i < c
    | _ => false
  | Op.le, Const.scalar (Value.int c) =>
    match v with
    | Value.int i => i <= c
    | _ => false
  | Op.gt, Const.scalar (Value.int c) =>
    match v with
    | Value.int i => i > c
    | _ => false
  | Op.ge, Const.scalar (Value.int c) =>
    match v with
    | Value.int i => i >= c
    | _ => false
  | Op.eq, Const.scalar c =>
    v == c
  | Op.ne, Const.scalar c =>
    not (v == c)
  | Op.mem, Const.list l =>
    valueInList v l
  | Op.nmem, Const.list l =>
    not (valueInList v l)
  | Op.truthy, _ =>
    evalValueTruthiness v
  | _, _ => false

/-- Evaluate a boolean condition tree against a total reading. -/
def evalCond (c : Cond) (r : Reading) : Bool :=
  match c with
  | Cond.atom a => evalAtom a r
  | Cond.and c1 c2 => evalCond c1 r && evalCond c2 r
  | Cond.or c1 c2 => evalCond c1 r || evalCond c2 r
  | Cond.not c => not (evalCond c r)

/-- Evaluate a Level M policy with first-match semantics and optional catch-all returning Option Action. -/
def evalPolicy {Action : Type} (p : Policy Action) (r : Reading) : Option Action :=
  let rec loop (rules : List (Rule Action)) : Option Action :=
    match rules with
    | [] => p.catchAll
    | rule :: rest =>
      if evalCond rule.cond r then
        some rule.action
      else
        loop rest
  loop p.rules
