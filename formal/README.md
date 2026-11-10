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

## The verified policy core (formal/Core)

Beside FQ, `formal/Core` is the executable semantics of the narrow core PrismPath proves once: one
decision of a Level M policy with field definitions, read from canon/2 documents
(docs/design/spec-verified-core.md). Unlike FQ, which proves properties of a model, these theorems are
about the very function the oracle runs (`Core.verdict`), and the oracle is the reference the other
implementations are differentially tested against. The evaluator depends only on `propext`; the
theorems on the standard three.

| theorem | file | statement in words |
|---|---|---|
| `verdict_total`, `matchSteps_le` | Theorems.lean | **Termination.** Every image and reading has a verdict (structural recursion only); routing evaluates at most the policy's atoms |
| `policy_refusal_refuses_all`, `unreadable_image_refused` | Theorems.lean | **No fail open, policy.** An image that does not read, decode or check refuses every reading with its refusal |
| `unreadable_reading_refused`, `boundary_refusal` | Theorems.lean | **No fail open, reading.** An unreadable reading, or one the boundary refuses, is refused |
| `route_sound`, `route_is_a_target` | Theorems.lean | **No fail open, the allow.** A route exists only for a checked policy and a reading every definition accepts, and names the first rule whose condition holds |
| `verdict_cases`, `policy_refusal_iff`, `verdict_route_or_refuse` | Theorems.lean | **Refusal completeness.** Every input lands in exactly one of six stages, each a route or one refusal of the closed `Refusal` type |
| `verdict_perm`, `verdict_text_perm`, `readChars_wf`, `evalC_congr` | Theorems.lean | **Determinism.** The verdict depends on a reading's members, not their order or spelling |
| `evalC_toX`, `firstMatch_eq_routeX` | Bridge.lean | the core evaluates and routes as FQ's `evalX` and `routeX` |
| `boundary_canonical`, `accepted_quantization_preserves`, `core_reconstruct_route` | Bridge.lean | readings the core accepts are FQ canonical, so equal quantization gives equal verdicts and the decoded reading routes as the reading |
| `scaled_correct`, `lowered_threshold_preserves` | Bridge.lean | a decimal threshold the core lowers decides on the canonical integer as the authored decimal on the source value |
| `refusal_registered`, `refusal_code_ne_zero`, `refusal_name_of_code`, `verdict_refusal_registered` | Codes.lean | **Every refusal carries a registered code.** Each refusal's (code, name) is a row of the cause registry generated from `prismpath/kernel/causes.py`, nonzero, and the code alone names it |
| `loadPolicy_first_problem`, `policy_cause_is_first`, `policy_accepted_iff_no_problem`, `verdict_policy_cause`, `lowerCond_first_atom` | Order.lean | **One cause per refused policy (D7).** The refusal the core computes is the head of `policyProblems`, the problems in the order of spec section 4 (decoding rule by rule, the definitions in code point order, lowering rule by rule and atom by atom, rule 6), and a policy is accepted exactly when that list is empty |
| `counterRefusal_iff`, `counter_excluded_refused` | Scope.lean | **The engine counter exclusion hides nothing.** `counterRefusal`, the check a differential run uses to exclude a case as reading an engine counter, holds exactly when the oracle refuses the image with `policy:engine-counter`, and then every reading is refused with it |
| `verified_receipt_is_verdict`, `receipt_is_verdict_of_hashes`, `verified_run_complete`, `verified_refusal_registered`, `verified_excluded_counter`, `evidence_sound` | Evidence.lean | **Evidence and the semantics.** Over a model of a differential run and its verifier (`verifyRun`, every receipt replayed, both keys pinned), every receipt the verifier accepts records `Core.verdict` on the image and reading whose hashes it carries, every reading of every case not excluded has one, and a recorded refusal is the verdict's registered code; the cryptography is a parameter and its security is stated per object as explicit hypotheses (`Unforgeable`, `NoTreeCollision`, `NoCollision`), never as `sorry` |
| `policyCheck_of_systemBoundary`, `systemBoundary_of_policyCheck`, `policyCheck_refuses_routed`, `policyCheck_eq_systemBoundary`, `route_depends_on_routed` | Boundary.lean | **The two checks of a reading.** The system boundary (every defined field) is at least as strict as the policy check (the routed fields), the two agree when every defined field is routed, and only routed fields can change a route |
| `readBytes_doc`, `read_write`, `readChars_wr`, `canonical_form`, `same_value_same_spelling`, `write_injective`, `readCanonical_iff`, `write_readCanonical`, `readCanonical_unique`, `readCanonical_refuses`, `readCanonical_cause`, `reader_not_canonical` | Canon2Proofs.lean | **The canon/2 encoding layer.** The reader returns only documents; the writer (`writeBytes`, Canon2.lean) and the reader are inverse on canonical values; every accepted document's canonical bytes are a fixed point; the strict reader (`readCanonical`) accepts exactly the canonical spellings, one per value, and refuses everything else with the reader's cause or `notCanonical`; the reader alone accepts non canonical spellings (spec section 3.2) |

The oracle is that evaluator compiled: `lake build` also builds `core-oracle`, and
`.lake/build/bin/core-oracle POLICY.json READING.json ...` prints one JSON line for the policy and one
per reading (spec section 8); `--batch` serves the differential harness.
`canon2-oracle` is the canon/2 writer and readers compiled: `.lake/build/bin/canon2-oracle DOC ...` prints
`ok <c> <hex>` (the canonical bytes, and 1 when the input already is them) or `refuse <rule>` per document;
`--batch` serves `diff/canon2_diff.py`.

## Validation, and how to reproduce it

```bash
# toolchain (user local), pinned in lean-toolchain and lake-manifest.json (Lean 4.33.1, Mathlib v4.33.1)
curl -sSf https://elan.lean-lang.org/elan-init.sh | sh -s -- -y --default-toolchain leanprover/lean4:v4.33.1
cd formal && lake exe cache get
lake build                         # compiles every module, evaluates every #guard, prints the axiom audit
grep -rn sorry FQ/ FQ.lean Core/ Core.lean   # expect no output
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
