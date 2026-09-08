Nothing in this directory has been compiled.

# Figueroa Quantization (FQ) Lean 4 Draft (Uncompiled)

This directory contains an uncompiled Lean 4 formalization draft of Figueroa Quantization (FQ) and Protocol Invariant I1 (Decision Preservation).

## File Manifest

* `lean-toolchain`: Pinning Lean 4 version (`leanprover/lean4:v4.12.0`).
* `lakefile.lean`: Lake package specification referencing Mathlib 4 version `v4.12.0`.
* `FQ/Syntax.lean`: Level M predicate syntax (Value, Op, Const, Atom, Cond, Rule, Policy, FieldKind).
* `FQ/Eval.lean`: Truthiness evaluation, atom evaluation, condition evaluation, and first-match policy evaluation.
* `FQ/Partition.lean`: Fine-grid numeric partitioning with adjacent merge, 2-cell boolean partitioning, categorical partitioning with trailing sentinel other cell, and computable symbol/representative maps.
* `FQ/I1.lean`: Statement of Protocol Invariant I1 (`decision_preservation`), supporting atom agreement lemmas, and coarsest partition theorem I1b (`coarsest_partition`), all with `sorry` proofs.
* `README.md`: This file.

## Specification Decisions (HANDOFF Section 4)

1. Domain is the Integers (Int):
   Readings assign `Int` values to numeric fields (`Value.int (n : Int)`). Real and floating-point values are excluded.

2. Total Readings:
   Quantization and evaluation quantify over total readings (`Reading := String → Value`) where all decision-relevant fields are present.

3. Coarsest Partition as Separate Claim (I1b):
   Theorem `decision_preservation` (I1) is separated from `coarsest_partition` (I1b / minimum sufficient statistic).

4. Categorical Other Cell:
   Categorical string fields map out-of-alphabet string values to the trailing fallback cell with sentinel constant `sentinelOther`.

5. Booleans:
   Boolean fields use a 2-cell partition (0 for false, 1 for true), preserving truthiness evaluation.

## Naming and Syntax Uncertainties for Compiling Session

The following items should be verified during the compiling session once Lean 4 and elan are installed:

1. Lake Package File Syntax (`lakefile.lean`):
   Verify syntax for `require mathlib from git` in Lean 4.12 Lake DSL (`package «FQ»`, `lean_lib «FQ»`).

2. Derive Directives (`FQ/Syntax.lean`, `FQ/Partition.lean`):
   Check if `deriving BEq, DecidableEq, Repr` works directly on `Value`, `Op`, `Const`, `Atom`, `Cond`, `NumericCell`, `CategoricalCell`, and `FieldPartition`.

3. Standard Library List Utilities (`FQ/Eval.lean`, `FQ/Partition.lean`):
   * `List.contains` vs `List.elem` for value lists.
   * `List.find?` for finding partitions by field name.
   * `List.bind` usage in `policyAtoms`.
   * Custom sorting and deduplication helpers (`sortInts`, `dedupInts`, `dedupStrings`) vs Mathlib `List.mergeSort` or `List.dedup`.

4. Option and String Pattern Matching (`FQ/Eval.lean`, `FQ/Partition.lean`):
   * String sentinel constant `"\x00__other__"` representation in Lean 4 String literals.
   * Option pattern matching syntax (`some` / `none`).

5. Theorem Signatures (`FQ/I1.lean`):
   * Verification of type variable binding in `theorem decision_preservation {Action : Type} ...`.
   * Boundary hypothesis formulation for `coarsest_partition` (whether `i, j` bounds need explicit `Fin` framing).

## Review by the handing off session (September 2026), read before compiling

Checked against `adapters/telemetry/quantizer.py` without a Lean compiler. What holds up:
`buildFineGrid` and `mergeFineGrid` mirror `_numeric_partition` step for step (leading open gap,
point cell per constant, gap cell when non empty, representative lo else hi else 0, adjacent merge
by atom truth vector at the representative). The five specification decisions are recorded.

What must change before milestone 1 counts:

1. **The main theorem is false as stated, not merely open.** `decision_preservation` takes
   `parts : List FieldPartition` as a free parameter unrelated to the policy `p`. With an empty list
   `quantize` is constant, so the hypothesis holds for every pair of readings while `evalPolicy`
   differs. The draft has no `buildPartitions : Policy Action → List FieldPartition` (the analogue of
   `_flow_atoms` plus `_classify_kind` plus the three constructors). Add it, and state the theorem
   with `parts := buildPartitions p`, or with the hypothesis `parts = buildPartitions p`. This is the
   exact failure mode HANDOFF section 6 warns about, in the other direction.
2. **`coarsest_partition` (I1b) is false as stated.** It quantifies over any `i ≠ j : Nat` with no
   bound and over an `atoms` list unrelated to the one the partition was built from. State it for the
   partition built from `atoms`, with `i, j < cells.length`.
3. **Toolchain pin is stale.** `lean-toolchain` names `v4.12.0` (a 2024 release) and Mathlib at a
   matching tag. Pin the current stable Lean 4 release and the matching Mathlib commit at install
   time, then record both in `formal/TOOLCHAIN.md`.
4. **Cross kind comparisons.** `Eval.lean` decides `Value.int` against `Value.bool` and similar
   cases by hand. HANDOFF section 3 says to take those from `predicates.json`; the vector bridge
   (milestone 2) is what settles them, so treat the draft's choices as placeholders.

Everything else in this directory is a sketch. Delete the directory once `formal/FQ/` builds.
