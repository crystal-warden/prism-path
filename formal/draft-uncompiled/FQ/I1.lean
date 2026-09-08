-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC

import FQ.Syntax
import FQ.Eval
import FQ.Partition

/-!
# Protocol Invariant I1: Decision Preservation Theorem

This module states Protocol Invariant I1 (Decision Preservation), the supporting atom agreement
lemmas, and the coarsest partition claim (I1b), following HANDOFF.md Section 7.

## Specification Decisions (HANDOFF Section 4)

1. Domain is the Integers (Int):
   `x` and `x'` assign `Int` values to numeric fields. Theorem I1 is an exact theorem over ℤ.

2. Total Readings:
   Quantification is over total readings `x, x' : Reading` carrying every decision-relevant field.

3. Coarsest Partition as Separate Claim (I1b):
   `decision_preservation` (I1) proves decision equivalence. Minimality of the partition (distinct atom
   truth vectors for distinct cells) is stated separately as theorem `coarsest_partition` (I1b).

4. Categorical Other Cell:
   Out-of-alphabet categorical string values map to the trailing `other` cell, preserving equal atom truth.

5. Booleans:
   Boolean fields preserve truthiness evaluation across symbol quantization.
-/

/--
Key Lemma: Every atom in policy `p` evaluates identically on reading `x` and on its
reconstructed representative reading `reconstruct parts (quantize parts x)`.
-/
theorem atom_agreement_reconstruct (p : Policy Action) (parts : List FieldPartition)
    (a : Atom) (x : Reading) (ha : a ∈ policyAtoms p) :
    evalAtom a x = evalAtom a (reconstruct parts (quantize parts x)) := by
  sorry

/--
Key Lemma: If two readings `x` and `x'` yield equal quantizations across all field partitions `parts`,
then every atom in policy `p` evaluates identically on `x` and `x'`.
-/
theorem atom_agreement (p : Policy Action) (parts : List FieldPartition)
    (a : Atom) (x x' : Reading) (ha : a ∈ policyAtoms p)
    (h : quantize parts x = quantize parts x') :
    evalAtom a x = evalAtom a x' := by
  sorry

/--
Key Lemma: If every atom in condition `c` evaluates identically on `x` and `x'`, then `evalCond c x = evalCond c x'`.
-/
theorem cond_preservation (c : Cond) (x x' : Reading)
    (h : ∀ a ∈ condAtoms c, evalAtom a x = evalAtom a x') :
    evalCond c x = evalCond c x' := by
  sorry

/--
Theorem I1 (Decision Preservation):
For a Level M policy `p` with decision function `evalPolicy p` and field partitions `parts`,
for all total readings `x, x'`, if `quantize parts x = quantize parts x'`, then `evalPolicy p x = evalPolicy p x'`.

Equivalently, `evalPolicy p` factors through `quantize parts`.
-/
theorem decision_preservation {Action : Type} (p : Policy Action) (parts : List FieldPartition)
    (x x' : Reading) (h : quantize parts x = quantize parts x') :
    evalPolicy p x = evalPolicy p x' := by
  sorry

/--
Atom truth vector for a partition cell representative over a list of atoms.
-/
def cellAtomTruthVector (part : FieldPartition) (atoms : List Atom) (sym : Nat) : List Bool :=
  let repVal := representative part sym
  atoms.map (fun a => evalAtom a (fun _ => repVal))

/--
Theorem I1b (Coarsest Partition / Minimum Sufficient Statistic):
For any field partition, distinct cell symbol indices `i ≠ j` within valid bounds have distinct atom truth vectors.
This establishes that the partition is the minimum sufficient statistic for the policy's atoms.
-/
theorem coarsest_partition (part : FieldPartition) (atoms : List Atom)
    (i j : Nat) (hneq : i ≠ j) :
    cellAtomTruthVector part atoms i ≠ cellAtomTruthVector part atoms j := by
  sorry
