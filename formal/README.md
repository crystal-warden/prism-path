# Figueroa quantization, formalized

*A Lean 4 development proving that Figueroa quantization (FQ) preserves decisions, that the shipped
construction computes the proven partition, that the spiral index is a bijection over the cell
space, and that the Fibonacci wire round trips and frames itself (September 2026); and that the
acceptance boundary, absence and fixed point conversion preserve decisions too (October 2026). Companion to
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
| `Conversion.convert_preserves` | Conversion.lean | **The conversion lemma** (SPEC 4.5). Floor carries `>=` and `<`, ceiling carries `>` and `<=`, and an exact conversion carries every comparison: on a rational source value, the canonical integer compares with `k` exactly as the source compares with `k / scale` |
| `Conversion.fixed_policy_preserved` | Conversion.lean | a policy of fixed field conditions, each carried by its rounding mode, routes the canonical reading as it routes the source values against the authored thresholds |
| `accept_faithful` | Contract.lean | on an atom that fits its field's kind, every value acceptance accepts decides exactly as the raw JSON value under the engine's own semantics (booleans numeric, `3.0` equal to `3`) |
| `contract_a` | Contract.lean | **Contract (a), strict.** For a well kinded policy, a raw reading acceptance accepts on every field is routed by the engine exactly as its decoded reading; every other reading is refused by construction, with lemmas naming the refused coercions |
| `atomAbsent_is_engine_null` | Absence.lean | the absent cell's semantics are the engine's null: on a raw null every atom decides as the model says |
| `absence_preservation` | Absence.lean | **Contract (b).** For a flow that defines its fields, two canonical readings with the same quantization route identically, each field present or absent |
| `reconstructX_route` | Absence.lean | the decoded reading of a canonical reading routes as the original, absence included |

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
- A rational source value converted under a fixed field's rounding mode decides exactly as it would
  against the authored decimal thresholds, for the comparisons that mode carries (the conversion
  lemma), and a whole policy of such conditions routes the same.
- The engine's semantics on raw JSON values are modeled, and every value the acceptance function
  accepts decides as the raw value did, so a raw reading acceptance accepts is routed by the engine
  exactly as its decoded reading (contract (a), strict).
- Absence is modeled as an explicit cell after every present cell, with the engine's null semantics,
  and decision preservation holds over canonical readings with absence (contract (b)).
- The development contains no `sorry`; the dependency audit shows only the standard axioms.
- The formal construction is bridged to the Python and Rust implementations through generated
  conformance checks (`FQ/Vectors.lean`, `#guard`, evaluated at every build): 39 Level M predicate
  cases against the frozen corpus, 90 frozen routes and 164 canonical symbols equal to the corrected
  reference quantizer on every decisions corpus reading, 34 spiral probes, all 108 frozen spiral cells
  at the frozen index, band, and route with the layout derived inside Lean from the policy, the Lean
  Gray order equal to the reference's iterative one, 300 Fibonacci codes byte identical to the
  reference's strings, all 52 cases of the frozen acceptance corpus against the model's `accept` (the
  21 accepted ones also against their frozen cell), and the 54 fixed field cases of the frozen
  conversion vectors the model covers against the model's `convert`.

## What is not proven, stated as plainly

- **This is not a verified translation of the Python or Rust source.** The Lean algorithm is a port
  read against `prismpath/telemetry/quantizer.py`; its agreement with the code rests on the generated
  checks above and on review, not on a proof about the source text.
- I1 itself still assumes total, well typed readings. Absence is covered by contract (b), which is
  stated for flows that define their fields; an inferred flow refuses an absent field instead.
- Contract (a) assumes a well kinded policy: each field compared only with constants of its kind and
  ordered only when numeric. A boolean constant on a numeric field, which the implementations accept
  and cut at 0 or 1, and string ordering, which Level M excludes, are outside it. Raw numbers are
  rationals; NaN and the infinities have no JSON spelling and are refused by the implementations,
  which the model does not restate.
- The conversion lemma is proven over the exact rational source value. Reading that value from
  decimal text, the bounds on that text, and the refusal of a binary double with a fraction are the
  implementation's, held to the frozen conversion vectors rather than proven; so is the range check,
  which the bridge checks but the lemma does not need.
- The integration of contracts (a) and (b) with lowering is by composition, not one theorem: the parser
  lowers thresholds (checked against the frozen lowering vectors), the conversion lemma covers the
  conversion, and contract (b) covers the codec on the canonical reading.
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

The reference suites the bridge depends on: `pytest prismpath/tests`, `pytest prismpath/telemetry/tests`,
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
| `FQ/Conversion.lean` | the conversion lemma and its lift to policies |
| `FQ/Contract.lean` | raw values, the engine's semantics on them, acceptance, contract (a) |
| `FQ/Absence.lean` | absence as an explicit cell, contract (b) |
| `FQ/Bridge.lean` | hand written evaluated checks, including the witnessed reference defect |
| `FQ/Vectors.lean` | generated evaluated checks against the frozen corpora and the reference |
| `FQ/Axioms.lean` | the axiom audit |
| `gen_vectors.py` | generator for `FQ/Vectors.lean` |
| `TOOLCHAIN.md` | exact Lean, Lake, Mathlib pins and host |
