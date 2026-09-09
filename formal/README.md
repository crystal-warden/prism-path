# Figueroa quantization, formalized

*A Lean 4 development proving that Figueroa quantization (FQ) preserves decisions, that the shipped
construction computes the proven partition, that the spiral index is a bijection over the cell
space, and that the Fibonacci wire round trips and frames itself. September 2026. Companion to
`docs/research/paper-facet-figueroa-quantization.md` and `PROTOCOL.md`.*

## What is proven

Every theorem below is in `formal/FQ/`, compiles with zero `sorry`, and depends only on Lean's three
standard axioms `propext`, `Classical.choice`, `Quot.sound` (`FQ/Axioms.lean` prints the audit at
every build; `gray_perm_product` needs only `propext` and `Quot.sound`).

| theorem | file | statement in words |
|---|---|---|
| `decision_preservation` | I1.lean | **I1.** Two well typed readings with the same quantization route identically under the policy the partitions were derived from |
| `symbolCount_eq_truthVec` | I1.lean | the numeric core: equal canonical symbol implies equal atom truth vector |
| `coarsest_interval` | I1.lean | **I1b.** Every retained boundary separates adjacent cells with different symbols and different truth vectors: the partition is the coarsest interval partition refining atom truth |
| `reconstruct_route` | Reconstruct.lean | **I1 in words.** Routing the reconstructed representative reproduces the decision |
| `symbolAlg_eq_symbolCount` | AlgEq.lean | the reference algorithm (fine grid, adjacent merge, first containing cell) equals the canonical form on every integer |
| `symbolAlg_eq_truthVec` | AlgEq.lean | I1's numeric core stated directly over the reference algorithm |
| `Spiral.gray_perm_product` | Spiral.lean | the reflected Gray enumeration is a permutation of the mixed radix product |
| `Spiral.spiral_bijection` | Spiral.lean | the route bucketed Gray layout is duplicate free, contains exactly the cells of the space, and index of cell and cell of index invert |
| `Spiral.band_route`, `Spiral.band_eq_route_eq` | Spiral.lean | the band an index falls in determines the route of its cell |
| `Zeck.decode_encode` | Zeckendorf.lean | the Fibonacci code round trips for every positive integer |
| `Zeck.takeCode_encode` | Zeckendorf.lean | **I2.** The first `11` after a code closes exactly that code: the wire frames itself |
| `Zeck.decodeStream_flatMap` | Zeckendorf.lean | a concatenation of codes decodes to exactly the values encoded, with no length header |

Plainly:

- FQ is defined over well typed integer readings: numeric fields carry integers, boolean fields
  booleans, string fields strings, and every field the policy tests is present.
- The supported Level M predicates (`field OP const` with integer, boolean, or string constants;
  `in` and `not in` over scalar lists; bare truthiness; `and`, `or`, `not`) induce, per field, an
  interval partition of the integers, a two cell boolean partition, or a named constants plus
  `other` categorical partition.
- The partition is decision preserving (I1).
- Reconstruction from symbols preserves routing.
- The numeric partition is coarsest within the class of interval partitions (I1b).
- The corrected reference algorithm computes that canonical partition.
- Spiral indexing is a bijection over the resulting cell product, and a band determines a route.
- Fibonacci coding round trips and a stream of codes frames itself (I2).
- The development contains no `sorry`; the dependency audit shows only the standard axioms.
- The formal construction is bridged to the Python and Rust implementations through generated
  conformance checks (`FQ/Vectors.lean`, `#guard`, evaluated at every build): 35 Level M predicate
  cases against the frozen corpus, 90 frozen routes and 164 canonical symbols equal to the corrected
  reference quantizer on every decisions corpus reading, 34 spiral probes, all 108 frozen spiral cells
  at the frozen index, band, and route with the layout derived inside Lean from the policy, the Lean
  Gray order equal to the reference's iterative one, and 300 Fibonacci codes byte identical to the
  reference's strings.

## What is not proven, stated as plainly

- **This is not a verified translation of the Python or Rust source.** The Lean algorithm is a port
  read against `adapters/telemetry/quantizer.py`; its agreement with the code rests on the generated
  checks above and on review, not on a proof about the source text.
- Readings with missing fields (the engine's null semantics, 72 of the 136 Level M corpus vectors),
  cross kind comparisons (13 vectors), and readings with floats (the reference casts with `int()`)
  are outside the model by declared decision.
- The Gray adjacency property (consecutive cells differ in one digit) is a locality optimization and
  is not proven; the bijection does not need it.
- The categorical `other` sentinel is assumed not to be a named constant (`NoSentinel`) for the
  reconstruct corollary.
- Timing, the wire's Merkle layer, hot swap, and everything outside FQ and the Fibonacci code are out
  of scope here by design.

## What the formalization found

Stating the partition against the reference exposed that `quantizer.py` and its Rust mirror used
only ordering and equality constants as cut points. Numeric `in` and `not in` lists, the truthiness
cut at zero alongside other constants, and truthiness on a string field each violated I1 on a one
line policy, in atom forms the frozen corpus never exercised. No shipped flow used them. Fixed on
branch `fix/quantizer-cut-points` (merged here) with the decisions corpus at version 2; ledger rows
#140 to #143.

## Validation, and how to reproduce it

```bash
# toolchain (user local), pinned in lean-toolchain and lake-manifest.json; see TOOLCHAIN.md
curl -sSf https://elan.lean-lang.org/elan-init.sh | sh -s -- -y --default-toolchain leanprover/lean4:v4.33.1
cd formal && lake exe cache get
lake build                         # compiles every module, evaluates every #guard, prints the axiom audit
grep -rn sorry FQ/ FQ.lean         # expect no output
for m in FQ.Syntax FQ.Partition FQ.I1 FQ.Reconstruct FQ.AlgEq FQ.Zeckendorf FQ.Spiral FQ.Bridge FQ.Vectors; do
  lake env leanchecker $m          # independent kernel re-check of the stored proofs
done
cd .. && ./.venv/bin/python formal/gen_vectors.py   # regenerate FQ/Vectors.lean from the frozen corpora
```

The reference suites the bridge depends on: `pytest prismpath/tests`, `pytest adapters/telemetry/tests`,
`pytest adapters/fusion/tests`, `cargo test --workspace`.

## Layout

| file | role |
|---|---|
| `FQ/Syntax.lean` | values, conditions, first match policies, `route` |
| `FQ/Partition.lean` | partitions derived from a policy; reference algorithm and canonical form |
| `FQ/I1.lean` | decision preservation, the numeric core, I1b |
| `FQ/Reconstruct.lean` | the reconstruct corollary |
| `FQ/AlgEq.lean` | reference algorithm equals canonical form |
| `FQ/Spiral.lean` | Gray enumeration, layout, bijection, bands |
| `FQ/Zeckendorf.lean` | the Fibonacci wire on Mathlib's Zeckendorf theorem |
| `FQ/Bridge.lean` | hand written evaluated checks, including the witnessed reference defect |
| `FQ/Vectors.lean` | generated evaluated checks against the frozen corpora and the reference |
| `FQ/Axioms.lean` | the axiom audit |
| `gen_vectors.py` | generator for `FQ/Vectors.lean` |
| `TOOLCHAIN.md` | exact Lean, Lake, Mathlib pins and host |
