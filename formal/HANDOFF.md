# Handoff: a Lean 4 formalization of Figueroa quantization

*Written September 2026 for a fresh session. Branch `formal/lean-fq`, created from `main`. Lean is
not installed on this machine yet; installing it is the first milestone. Read this whole file, then
`docs/research/paper-facet-figueroa-quantization.md` sections 2.1 to 2.3, then
`adapters/telemetry/quantizer.py` end to end (about 220 lines). Those three are the specification.*

## 1. Goal

Turn the paper's Theorem 2.2 from a tested statement into a machine checked one, for Figueroa
quantization (FQ) alone, not the PrismPath system.

The claim, exactly as the paper states it: for a Level M policy `F` with decision function `D` and
Figueroa quantization `𝒬_F`, for all readings `x, x'`, if `𝒬_F(x) = 𝒬_F(x')` then `D(x) = D(x')`.
Equivalently `D` factors as `D̄ ∘ 𝒬_F`. This is PROTOCOL.md invariant **I1 (decision preservation)**.
Every bandwidth number in the evidence ledger (the OTLP ratio in row #95, the two bytes per reading,
the mesh results) is honest only if I1 holds for every reading, and today it is checked on a finite
frozen corpus: 55 readings across four flows in `adapters/telemetry/conformance/decisions.json` and
34 boundary probes in `adapters/fusion/conformance/spiral_fusion.json`, three ways
(`adapters/fusion/tests/test_fusion_spiral.py`). The README says "machine checked, not asserted";
that means tests. The goal is a theorem.

Why this and not more: FQ is small, theorem shaped, and elementary (interval reasoning and case
analysis over integers, no unbounded induction). The WCET envelope in ledger #111 is the cautionary
contrast: its induction step stayed open. Whole system verification is explicitly out of scope.

## 2. Deliverables, in order, each its own commit and its own ledger staging row

0. **Toolchain.** `elan` (user local, `~/.elan`), a pinned Lean 4 toolchain in `formal/lean-toolchain`,
   Mathlib as a `lake` dependency pinned to a commit that matches the toolchain, `lake exe cache get`
   for the Mathlib oleans. Record every pin in `formal/TOOLCHAIN.md` with the exact versions, like
   `prismpath/comparisons/toolchain/TOOLCHAIN.md` does for the comparison binaries. Nothing here goes
   into the main CI matrix (bare CI stays numpy plus pytest); a Lean gate is a documented local
   command first, an optional CI job later.
1. **The statement.** `formal/FQ/*.lean` defining the Level M predicate language over integer
   readings, its evaluation, the per field partition, the product quantization, the representative
   map, and Theorem I1 with the proof left as `sorry`. This is reviewable on its own and settles the
   specification questions in section 4 in writing. Commit it before proving anything.
2. **The bridge.** The Lean definitions must be executable and must reproduce the frozen corpus
   before any theorem counts: the Level M subset of `prismpath/portable/conformance/predicates.json`
   (corpus version 2, 1,079 cases, of which 136 are Level M per ledger #89), every case in
   `decisions.json`, and every probe in `spiral_fusion.json`. Recommended mechanism: a small Python
   generator `formal/gen_vectors.py` that reads the frozen JSON and emits `formal/FQ/Vectors.lean` as
   a list of `example : ... := by decide` facts, so Lean never parses JSON. A model that proves I1 but
   disagrees with the reference on one frozen vector is a proof of the wrong thing; this is the same
   two referee discipline the repo uses everywhere.
3. **The I1 proof.** Zero `sorry`. `#print axioms` on the theorem showing only `propext`,
   `Classical.choice`, and `Quot.sound`.
4. **Spiral.** The Tier 6 band map (`adapters/telemetry/spiral.py`, `spiral_fusion.json`) is a
   bijection from the product of cells onto band indices, so preservation composes: band equality
   implies decision equality.
5. **Zeckendorf.** The wire codec's round trip (`adapters/telemetry/zeckendorf.py`, `packed.py`):
   `decode (encode n) = n` and the code is prefix free (self delimiting `11` terminator). Mathlib
   already has Zeckendorf's uniqueness theorem (`Nat.zeckendorf`); build on it.
6. **Interpreter equivalence is NOT in scope.** Proving the PPT table semantics equal the predicate
   semantics would be the formal backbone of the cross substrate claim, and it is a much larger job.
   Name it as future work.

## 3. What the code actually does (pin the model to this, not to prose)

From `adapters/telemetry/quantizer.py`, read it yourself:

- **Field kinds** are detected from the compared constants: numeric (any int constant), categorical
  (any string constant), boolean (only bool constants or only bare truthiness). A field mixing string
  and int constants raises; a well formed Level M flow never has one.
- **Numeric partition** (`_numeric_partition`): constants `consts = sorted({int(c)})`; if none, `[0]`
  (a truthy only int field splits at zero). Fine cells: `(None, c0-1)`, then for each constant the
  point `(c, c)` and the gap `(c+1, next-1)` when non empty, with `None` as an open end. The
  representative of a cell is its `lo` if finite, else its `hi`, else `0`. Adjacent fine cells whose
  atom truth vectors (over the field's atoms, evaluated at the representative) are identical are
  merged into one cell. Cells are closed integer intervals.
- **Membership** (`FieldPartition.symbol`): numeric does `v = int(value)` then the first cell with
  `lo <= v <= hi` (open ends allowed); boolean is `1 if value else 0`; categorical is the first cell
  whose constant equals the value, else the trailing `other` cell.
- **Quantize** drops fields the flow never tests and, as written, also drops fields absent from the
  reading (`if f in reading`). **Reconstruct** maps each symbol to its cell's representative.
- **Atom truth** (`_atom_true`): `< <= > >= == != in not in truthy`, plain Python semantics.

From `prismpath/predicates.py` (the engine's evaluator, which `D` is built from), established by
running it this session, and pinned by the frozen vectors:

- A comparison over a missing field (null) is unsatisfied: `a == False` with `a` missing is False.
  `not a` is True. `not in` over a missing field is SATISFIED (the one inversion). `and`/`or`
  evaluate every operand. Python cross type facts leak in: `False == 0` is True, `5 == True` is
  False. Do not decide these by hand; take them from `predicates.json`.
- The Level M fragment (SPEC.md section 4.3, classifier `prismpath/model_check.py`): boolean
  combinations of atoms `field OP const` with `const` a signed i32, bool, or string (strings with
  `==`/`!=` only), `field in [scalars]` / `not in`, bare `field` truthiness. Chained comparisons are
  normalized into the fragment. Excluded: floats, field against field, substring `in`, string
  ordering, runtime collections, nested containers, `is`.

## 4. Specification decisions the statement must make explicitly

These are the questions a proof forces that the tests never did. Decide each in the statement file
with a comment saying why.

1. **Domain is the integers.** The quantizer casts every reading with `int()` (quantizer.py:99) and
   builds closed integer cells. So I1 as implemented is a theorem over ℤ, not ℝ. Over the reals it is
   false as built: a reading of 5.5 satisfies `x > 5` directly, truncates to 5, lands in the cell
   whose representative is 5, and fails the same atom; and over the integers `x > 5` and `x >= 6` are
   one boundary while over the reals they are two. State readings as integer valued and name the
   float to integer projection as a step outside the theorem (in practice the fusion bridge scales
   sensor readings to integers before FQ; the ledger's `dev_mg` fields are that). Add a hypothesis
   for the i32 range only where a proof needs it; over ℤ the theorem should not need it.
2. **Total readings.** Version one of I1 quantifies over readings that carry every decision relevant
   field. The engine's null semantics (missing is unsatisfied, `not in` inverts) and quantize's
   silent drop of absent fields are a second theorem about partial readings, or an explicit
   exclusion. Say which.
3. **Coarsest is a separate claim.** I1 needs only that cells refine the atom truth partition.
   "Minimum sufficient statistic" is the converse: distinct cells have distinct atom truth vectors.
   State it as I1b and prove it after I1; it is true by the merge construction but it is not I1.
4. **Categorical `other`.** The trailing cell collapses every value not named by a constant. Its
   representative is an internal sentinel, and any string not in the constants must route
   identically to it; that is part of I1 for categorical fields.
5. **Booleans.** Two cells, representatives `False` and `True`, truthiness of the value. The Python
   `bool == int` facts above mean the Lean value type for a boolean field should be Bool and the
   atom set restricted to what the fragment allows on booleans.

## 5. Constraints carried from the project

- **Verify, never trust.** Draft with agy if useful, but a Lean file counts only when `lake build`
  succeeds here, `sorry` is zero, and `#print axioms` is clean. agy over claims; Lean cannot be over
  claimed. Never run two agy at once.
- **Ledger discipline.** Each landed milestone is a row in `docs/research/supporting-evidence.pending.md`
  in the Claim / Method / Result / Honest scope / Provenance schema
  (`docs/research/LEDGER_STANDARDS.md`), month granularity dates, next free number `#140` unless the
  staging file says otherwise. Hash the built artifacts (`.olean` set or a build log) into a
  `formal/evidence/SHA256SUMS`; OTS anchoring is owner gated.
- **Wording.** Do not change "machine checked, not asserted" in the README, the paper, or PROTOCOL.md
  to "proved" until milestone 3 is sorry free and milestone 2 passes. Then update the paper's section
  2.2, the README, and the B2 row of the comparison (`prismpath/comparisons/`), each citing the row.
- **Style.** Repo docs use no em or en dashes and minimal hyphens (proper names, code, math only).
  Every source file starts with the two line header: `-- SPDX-License-Identifier: Apache-2.0` and
  `-- Copyright 2026 Crystal Warden Supply Chain Labs LLC` (Lean comment syntax).
- **Public bound repo.** The public mirror is generated from this repo; never name private projects,
  never hand edit the mirror.
- **Do not touch** `prismpath/`, `adapters/`, the conformance fixtures, or the comparison branch. The
  formal work reads them and never edits them. If the model disagrees with a fixture, the fixture wins
  until a human decides otherwise, and the disagreement is a finding worth a row.
- **Python floor** is 3.10 for any generator script (CI matrix), local venv is `./.venv` (3.12).

## 6. Context worth knowing

- A second AI model reviewed this idea independently. Its useful points: implementations agreeing
  across substrates shows the implementations agree, a proof shows the property follows from the
  definition; the main risk is formalizing something trivially true (define `D := 𝒬_F` and I1 is
  vacuous), so the value is in getting the model of FQ right and bridging it to the code; and FQ is
  small enough to isolate. It also conflated two things: the cross substrate certifications (124 of
  1,079 vectors, ledger #72 to #108) certify the predicate evaluator on hardware, not FQ; FQ's own
  empirical base is the 55 plus 34 items named in section 1. Keep those apart in any writeup.
- An owner recollection of a value like "3e12" excluded from a universal hardware proof traces to
  ledger #103 and #105: the `big_values` soak policy with thresholds up to ten to the twelfth and
  events past two to the fifty-third, where the Vector codec's f64 path loses precision (stated in
  #103's honest scope), plus the i32 caps of the hardware tables. Realization limits, not an FQ
  counterexample.
- The integer domain finding in section 4.1 was made this session from the code and is the first
  thing the formal statement should settle. It is a specification clarification, not a bug: the
  input contract simply needs to say readings are integers.

## 7. Suggested Lean shape (a starting point, not a mandate)

- `FQ/Syntax.lean`: `inductive Atom | lt | le | gt | ge | eq | ne | mem | nmem | truthy`, constants
  as `Int | Bool | String`, `inductive Cond | atom | and | or | not`, a field indexed by `String` or
  `Fin n`. A `Policy` is an ordered list of `(Cond, action)` with first match semantics (SPEC section
  3 step 1) and an optional catch all; `D` is first match over the list, `none` when nothing matches.
- `FQ/Eval.lean`: `evalAtom`, `evalCond` over a total reading `Field → Value` with a `Value`
  inductive of `int | bool | str`. Cross kind comparisons per the fixtures.
- `FQ/Partition.lean`: the fine grid from the sorted constants, the merge, `symbol`, `representative`,
  all computable (`Decidable` instances) so `decide` and `#eval` work for the bridge.
- `FQ/I1.lean`: `theorem decision_preservation (F) (x x' : Reading) (h : quantize F x = quantize F x') :
  decide F x = decide F x'`, via the lemma that every atom agrees on `x` and on
  `representative (symbol x)`.
- `FQ/Vectors.lean`: generated, never hand edited.

## 8. Definition of done per milestone

| milestone | done when |
|---|---|
| 0 | `lake build` succeeds on an empty project with Mathlib imported; `formal/TOOLCHAIN.md` written |
| 1 | statement file builds with `sorry` only at the theorem; section 4 decisions recorded in comments |
| 2 | generated `Vectors.lean` builds; count of vectors checked equals the frozen counts (136 Level M predicate cases, 55 readings, 34 probes) |
| 3 | `lake build` clean, zero `sorry`, `#print axioms` standard; staging row written; SHA256SUMS over the build |
| 4, 5 | same bar, one row each |

## 9. Draft status

If a directory `formal/draft-uncompiled/` exists beside this file, it holds an agy drafted statement
produced on a machine without Lean. It has never been compiled. Treat it as a sketch to read for
ideas, not as a starting point to trust; delete it once milestone 1 builds.
