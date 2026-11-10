# The verified policy core: Level M with field definitions

*Specification of the narrow core PrismPath proves once and every implementation is held to: one
decision of a match action policy over integers, booleans and strings, with the signed field
definitions that say what each integer means. November 2026, research line, branch `verified-core`.*

This document defines the core precisely enough that its Lean semantics (`formal/Core`), the oracle
compiled from it, and the differential harness that holds the other implementations to it all refer
to one text. Where a rule comes from the Python reference, the reference is cited by file and line on
this branch; where the reference and another implementation disagree on the slice, the disagreement
is listed in section 9 with a reproducer and the side this specification takes. Those are bugs to
settle, not behaviours to prove around.

## 1. Scope

**In the core.**

1. One decision: a policy is an ordered list of rules, each a Level M condition (SPEC.md section 4.3)
   and a target, together with field definitions (SPEC.md section 4.5); a reading is routed to the
   target of the first rule whose condition holds.
2. The field definition grammar, the exact decimal thresholds of `fixed` fields and their lowering to
   canonical integers, and the six policy rules of SPEC.md section 4.5.
3. The canonical boundary on a reading (`field_definitions.accept_canonical`).
4. The document layer: a policy image and a reading are canon/2 documents (section 3), read by one
   reader with its own refusals.
5. A refusal, with a cause, for every input that is not routed.

**Outside the core, stated so.**

- The flow engine: several nodes, `visits` and `error_count`, the error and event tiers, suspension,
  `max_steps`, workers. A condition that reads an engine counter is refused by the core
  (`policy:engine-counter`), since the core has no registers.
- Semantic edges and every router.
- The inferred path of SPEC.md section 4.5 (a flow that defines no fields, whose kinds are inferred from
  its constants). The core reads only defined fields; an undefined field is refused.
- The Markdown flow text and the Python flavoured `when` surface. The core's syntax is the abstract
  syntax of section 2; the surface is a front end that lowers to it, and the harness's renderer
  (section 8) is one such front end.
- Signatures, envelopes, receipts, the `.ppt` table image and the table targets. The table image is a
  compilation target of the core (step 2, section 10), and a table target's narrower integer range
  (`int-out-of-i32`, SPEC.md section 4.3) is a target limit, not a rule of the core.
- Floats of any kind. The core has none, in the image, in readings, or in its arithmetic.

## 2. Abstract syntax

### 2.1 The policy image

A policy image is a canon/2 document (section 3) that is an object with exactly the three keys
`format`, `fields` and `rules`, in any order:

```json
{"format": "prismpath.core/1",
 "fields": {"error_rate": "fixed scale=10000 unit=ratio rounding=floor min=0 max=10000",
            "label": "category absent=allowed"},
 "rules": [{"target": "hit",  "when": ["cmp", "error_rate", ">=", ["num", "0.85"]]},
           {"target": "gone", "when": ["cmp", "label", "==", ["none"]]},
           {"target": "low",  "when": ["and", ["cmp", "error_rate", "<", ["num", "0.25"]],
                                              ["cmp", "label", "==", ["str", "a"]]]},
           {"target": "miss", "when": ["always"]}]}
```

- `format` is the string `prismpath.core/1`.
- `fields` is an object from field name to definition text (section 2.5).
- `rules` is an array of objects with exactly the keys `target` and `when`. A target matches
  `[A-Za-z0-9_-]+`, the target of the flow grammar's edge line (`prismpath/kernel/parser.py:32`).

### 2.2 Conditions

A condition is an array whose first element names its form:

| form | meaning | Level M atom (SPEC.md 4.3) |
|---|---|---|
| `["always"]`, `["never"]` | the catch all rows | the keywords `always`/`else`/... and `false`/`never` (`predicates.py:27-28`) |
| `["truthy", f]` | truthiness of `f` | bare `field` |
| `["cmp", f, op, k]`, `op` one of `< <= > >= == !=` | `f op k`, the field on the left | `field OP constant` |
| `["in", f, [k...]]`, `["not in", f, [k...]]` | membership in a list of constants | `field in [...]` |
| `["not", c]` | negation | `not` |
| `["and", c1, c2, ...]`, `["or", c1, c2, ...]` | at least two operands | `and`, `or`, one n-ary node as Python's `BoolOp` |

A field name in a condition is `[A-Za-z_][A-Za-z0-9_]*` and not a Python hard keyword (SPEC.md 4.1;
`True`, `False` and `None` included); anything else is refused (`policy:not-level-m`, `name`). The
orientation of a comparison (`0.5 <= x`) and chained comparisons (`1 < x < 5`) are surface forms: the
front end writes them as field-left atoms and conjunctions (`level_m.py:86-102`, the one desugaring).

The forms outside the fragment that an image can still state are refused with the registered image
causes: a string constant under an ordering (`string-ordering`) and a membership whose right side is
not a list (`membership-not-in-a-list`, the substring test) are `image:unknown-op` (code 74); a
field reference as a constant (`["field", g]`, `field-vs-field`), a nested list
(`["list", ...]`, `nested-container`), an unknown constant tag, and a decimal literal on a field that
is not `fixed` (`float`) are `image:unknown-type` (code 75). These follow the classifier's reasons
(`level_m.py:18-26`, `_atom_reason` at `level_m.py:42-83`, `_scalar_const` at `level_m.py:32-39`).

### 2.3 Constants

| constant | meaning |
|---|---|
| `["num", n]`, `n` a JSON integer | the integer `n` |
| `["num", s]`, `s` in canonical integer spelling `-?[1-9][0-9]*`, outside the exact range | that integer, at any size (an integer literal of the reference, which Python holds exactly) |
| `["num", s]`, `s` decimal text with a `.` or an exponent | a decimal literal, read exactly (section 2.4) |
| `["bool", b]` | `True` or `False` |
| `["str", s]` | a string, compared by code points |
| `["none"]` | `None`, the absent value |

A string that spells an integer inside the exact range (`"5"`) is refused (`policy:shape`,
`integer-as-string`): canon/2 writes such an integer as a number, so the image has one spelling for
it. Other strings are refused as `number-spelling` (an integer spelling that is not canonical) or
`number-text` (not decimal text at all).

### 2.4 Decimal literals and depth

A decimal literal is the reference's DECIMAL_TEXT, `[+-]?(digits(.digits*)?|.digits)([eE][+-]?digits)?`
(`field_definitions.py:54`), read as the exact rational `± digits × 10^(exponent − fraction length)`
(`decimal_fraction`, `field_definitions.py:188-197`). It has at most 28 significant digits (every
mantissa digit after the leading zeros) and an exponent of at most 30 in magnitude
(`field_definitions.py:55-56`); a literal past either bound is refused (`policy:threshold`, `digits`).

The depth of a condition is the depth the reference's static check measures on its lowered text
(`predicates._depth`, `predicates.py:179-182`, applied at `predicates.py:169`): `truthy` 1, every
comparison and membership 2, `not c` one more than `c`, `and`/`or` one more than its deepest operand,
the keywords 0. A condition deeper than 50 (`predicates.py:32`) is refused (`policy:not-level-m`,
`depth`). The harness confirms the measure: on 20,000 random conditions the core's depth exceeds 50
exactly when `check_predicate` reports the lowered condition nested too deeply.

### 2.5 Field definitions

A definition is a kind word followed by `option=value` words, as the reference's `parse_definition`
reads it (`field_definitions.py:134-178`):

- words are separated by runs of the whitespace Python's `str.split()` splits on (`str.isspace`:
  U+0009 to U+000D, U+001C to U+0020, U+0085, U+00A0, U+1680, U+2000 to U+200A, U+2028, U+2029,
  U+202F, U+205F, U+3000);
- the name is `[A-Za-z_][A-Za-z0-9_]*` and not `visits` or `error_count`;
- the kind is `int`, `fixed`, `bool` or `category`, and the options it takes are those of
  `field_definitions.py:62-67`; an option appears once and has a non-empty value after the first `=`;
- `absent` is `refused` (the default) or `allowed`;
- a `fixed` field has `scale`, an integer from 1 to 10^9, and `rounding`, one of `floor`, `ceiling`,
  `exact`; `unit` is free text and changes no rule;
- `min` and `max` are `[+-]?[0-9]+` (ASCII digits), default to plus or minus 2^53 minus 1, and satisfy
  `−(2^53−1) ≤ min ≤ max ≤ 2^53−1` (`field_definitions.py:170-177`).

Definitions are parsed in code point order of their names; the first that breaks a rule refuses the
policy (`policy:definition`, with the field and one of `name`, `engine-counter`, `empty`,
`unknown-kind`, `not-option`, `option-not-taken`, `option-repeated`, `absent`, `not-integer`, `scale`,
`rounding`, `fixed-needs-scale-and-rounding`, `range`).

## 3. The canon/2 document rules

A policy image and a reading are canon/2 documents. canon/2 is the no float profile of RFC 8785
proposed in the policy language research note: the documents are JSON (RFC 8259) and the reader
refuses, with the cause in parentheses:

1. bytes that are not UTF-8: overlong forms, encoded surrogates, anything past U+10FFFF, truncated
   sequences (`utf8`);
2. text that is not JSON, including `NaN`, `Infinity`, a byte order mark and trailing text (`syntax`);
3. a number with a fraction or an exponent, which is a float whatever its value (`float`);
4. an integer outside plus or minus 2^53 minus 1 (`integer-range`); wider values are decimal strings;
5. the integer written `-0` (`negative-zero`);
6. an object that holds a key twice (`duplicate-key`);
7. a `\u` escape that names half of a surrogate pair alone (`lone-surrogate`);
8. nesting of arrays and objects deeper than 128 (`depth`).

The first rule broken, reading left to right, names the refusal. A policy image that does not read
is refused as `policy:unreadable`; a reading that does not read is refused as `reading:unreadable`.

**What the implementations read today.** No implementation reads canon/2 yet. The Python reference
reads signed documents with `prismpath.canon.loads` (`canon.py:122-133`), which refuses rules 2 and 7
and numbers beyond the double range, and accepts floats, `-0`, wide integers, duplicate keys (the last
wins) and nesting to the interpreter's recursion limit. The Rust port reads with `value::parse_strict`
(`prismpath-rs/src/value.rs:152`), which refuses the same and nesting past 128. A difference that is
only one of rules 3, 4, 5, 6 or 8 is therefore a *reader gap* in section 8: counted, expected until
canon/2 is implemented, never a silent agreement.

## 4. The checks of a policy

After the image reads, the core decodes and checks it in this order; the first failure is the refusal.

1. **Shape and fragment** (section 2): the keys of the image and of each rule, the format tag, each
   definition a string, each condition and constant well formed, each name allowed, each condition no
   deeper than 50. Rules are decoded in order and a condition depth first, left to right.
2. **Definitions** (section 2.5), in code point order of the names.
3. **Lowering and rules 1 to 5** of SPEC.md section 4.5, rule by rule in order, atom by atom left to
   right (`apply_definitions`, `field_definitions.py:506-517`; `lower_expression`,
   `field_definitions.py:335-386`; `_atom_problem`, `field_definitions.py:432-467`):
   - a field an atom reads must be defined (rule 2): `image:field-index-oob` (code 76);
   - `None` only under `==` or `!=` (`ordered`), only on a field that allows absence
     (`absence-refused`), never in a list (`in-list`) (rule 5): `policy:none`;
   - kinds (rule 3): a `bool` field only by truthiness or `==`/`!=` with a boolean, a `category` field
     only by truthiness, `==`/`!=` with a string, or membership in strings, an `int` or `fixed` field
     only with numbers: otherwise `policy:kind-mismatch`;
   - on an `int` field every constant is an integer literal inside `[min, max]`
     (`policy:threshold`, `constant-range`); a decimal literal is a float, `image:unknown-type`;
   - on a `fixed` field every numeric constant is in the field's unit and is lowered to
     `value × scale`; it must be a whole number of units (`off-grid`) and lie in `[min, max]`
     (`out-of-range`), both `policy:threshold`; an integer literal `n` lowers to `n × scale`
     (SPEC.md 4.5, "`error_rate >= 1` means 1.0");
   - on a `fixed` field the rounding mode carries only its operators (rule 4,
     `field_definitions.py:71-75`): `floor` carries `>=` and `<`, `ceiling` carries `>` and `<=`,
     `exact` carries every comparison, membership and truthiness: otherwise `policy:rounding`.
4. **Rule 6**: every field that allows absence is tested with `== None` or `!= None` by some rule,
   checked in code point order: `policy:absence-untested`.

A policy that passes is *checked*: its definitions, and its rules with every constant a canonical
literal (an integer, a boolean, a string, or `None`).

## 5. Refusals and their causes

Every input that is not routed gets exactly one of these refusals. The registered codes are those of
`prismpath/kernel/causes.py`; the rows marked *proposed* have no registered cause yet, and the oracle
prints `"code": null` for them until the registry (which is append only) gains them.

| refusal | cause | code | when |
|---|---|---|---|
| image unreadable | `policy:unreadable` | proposed | section 3, on the image |
| image shape | `policy:shape` | proposed | section 2, the image is not the core's syntax |
| operator outside Level M | `image:unknown-op` | 74 | `causes.py:74`, an atom's operator outside the fragment |
| value type outside Level M | `image:unknown-type` | 75 | `causes.py:75` |
| name or depth outside Level M | `policy:not-level-m` | proposed | section 2.2, 2.4 |
| malformed definition | `policy:definition` | proposed | section 2.5 |
| undefined field | `image:field-index-oob` | 76 | `causes.py:76`, an atom names a field the policy does not declare |
| engine counter read | `policy:engine-counter` | proposed | section 1 |
| kind mismatch | `policy:kind-mismatch` | proposed | rule 3 |
| rounding mode | `policy:rounding` | proposed | rule 4 |
| threshold | `policy:threshold` | proposed | lowering and ranges |
| `None` misused | `policy:none` | proposed | rule 5 |
| absence untested | `policy:absence-untested` | proposed | rule 6 |
| reading unreadable | `reading:unreadable` | proposed | section 3, on the reading |
| reading not an object | `reading:not-object` | proposed | section 6 |
| value refused at the boundary | `route:contract-violation` | 37 | `causes.py:48`, the reading violates the declared definitions; the field and `missing`, `wrong_type` or `out_of_range` |
| no rule holds | `route:no-matching-edge` | 32 | `causes.py:43`, refused for admission |

A policy refusal refuses every reading with the same refusal. The proposed rows would sit in the
envelope class with the pack verifier's structural refusals (`causes.py:65-86`), and the two reading
rows in the routing class; registering them is an owner decision, listed in section 10.

## 6. Evaluation

For a checked policy and a reading that reads:

1. **Object.** The reading must be an object; any other document is `reading:not-object`.
2. **Boundary.** Every defined field, in code point order of the names, is checked against its
   definition (`accept_canonical`, `field_definitions.py:283-304`, in the composition of
   `gen_field_definitions._boundary_refusal`, `prismpath/portable/gen_field_definitions.py:152-158`):
   a missing key or `null` is the absent value, accepted only if the definition allows absence, else
   `missing`; a `bool` field takes a boolean, a `category` field a string, an `int` or `fixed` field an
   integer in `[min, max]` (else `out_of_range`); every other value is `wrong_type`. The first failure
   is `route:contract-violation` with the field and the reason. Keys the policy does not define are
   ignored. Since canon/2 has no float, the reference's `fractional` and `binary_float` reasons cannot
   arise.
3. **Conditions** (SPEC.md 4.2 on canonical values): `truthy` holds on a present value that is a
   non-zero integer, `true`, or a non-empty string; `== None` holds exactly on absence and `!= None`
   exactly on presence; on an absent field `!= k` and `not in` hold and every other atom fails; on a
   present value equality is by kind and value, ordering is defined on integers only, membership is
   equality with some member; `and` and `or` read every operand.
4. **First match** (SPEC.md section 3, step 1): the verdict is `route t` for the target `t` of the
   first rule whose condition holds; when none holds, `route:no-matching-edge`.

## 7. The theorems

Proven in `formal/Core`, with no `sorry` and only Lean's standard axioms (`FQ/Axioms.lean` prints the
audit at every build). The evaluator itself, `Core.verdict`, depends only on `propext`: nothing it
computes goes through `Classical.choice`, which is why the core decodes UTF-8 itself.

**Termination.** `verdict_total`: every image and reading has a verdict; `verdict` and everything it
calls are defined by structural recursion, with no `partial` definition, so this is the kernel's own
guarantee. `matchSteps_le`: routing a reading evaluates at most as many atoms as the policy has, a
bound fixed when the policy is signed.

**No fail open.** `policy_refusal_refuses_all` and `unreadable_image_refused`: an image that does not
read, decode or check refuses every reading with its refusal. `unreadable_reading_refused` and
`boundary_refusal`: under an accepted policy a reading that does not read or that the boundary refuses
is refused. `route_sound`: a route is produced only when the image read and checked, the reading read
as an object and every definition accepted its value, and the route is the target of the first rule
whose condition holds, every earlier one failing. `route_is_a_target`: a route is always a rule's
target.

**Refusal completeness.** `verdict_cases`: every pair of inputs falls in exactly one of six cases,
policy refusal, reading unreadable, reading not an object, boundary refusal, no rule holds, route, each
characterized by the stage that produced it and carrying a refusal of the closed type `Refusal`
(section 5). `policy_refusal_iff`: a policy refusal appears exactly when the policy fails.
`verdict_route_or_refuse`: the verdicts are a closed set. Together with totality: no input yields an
exception, a crash or an undefined result.

**Determinism.** `verdict_perm`, `decideReading_perm` and `verdict_text_perm`: the verdict on a reading
depends on its members and not on their order (the reader guarantees distinct keys, `readChars_wf`).
`evalC_congr`: a condition's truth depends only on the canonical values of the fields.

**The bridge to FQ** (`Core/Bridge.lean`). `evalC_toX` and `firstMatch_eq_routeX`: the core's
evaluation is FQ's `evalX` and `routeX` (formal/FQ/Absence.lean) on the translated policy.
`boundary_canonical`: a reading the core's boundary accepts is canonical in FQ's sense for the
partitions of any policy the core accepts. `accepted_quantization_preserves`: so two readings the core
accepts with the same Facet quantization get the same verdict (from `FQ.absence_preservation`), and
`core_reconstruct_route`: the decoded reading routes as the reading (from `FQ.reconstructX_route`).
`scaled_correct` and `lowered_threshold_preserves`: a decimal threshold the core lowers on a `fixed`
field decides on the canonical integer of any rational source value as the authored decimal decides on
the source value (from `FQ.Conversion.convert_preserves`).

**Not proven, stated as plainly.** That any implementation computes `verdict`: Python, Rust and the
other targets are *conformant* to the oracle by differential testing (section 8), not proven. The
order of the image's `fields` members does not change a verdict, because definitions are read in
sorted order, but the uniqueness of that sort is not yet a theorem. The FQ bridge theorems take FQ's
partitions as FQ defines them; the quantizer's code is held to those by FQ's own bridge vectors.

## 8. The oracle and the differential harness

**The oracle.** `lake exe core-oracle POLICY [READING ...]` (built by `lake build` in `formal/`)
prints one JSON line for the policy, `{"policy":"accepted"}` or `{"policy":"refused","cause":...,
"code":...}`, then one line per reading, `{"verdict":"route","target":...}` or
`{"verdict":"refuse","cause":...,"code":...,"field":...,"reason":...}` with `field` and `reason` only
where the refusal has them. `--batch` reads framed cases (`case <id> <n>` then `n + 1` documents, each
as its byte length and its bytes) and prints one line per case. Every printed value is computed by
`Core.verdict`; `formal/Core/Main.lean` only frames and spells.

**The harness.** `formal/diff/core_diff.py` generates random images and readings, well formed and
malformed, biased toward boundaries (ranges at plus or minus 2^53 minus 1 and at 2^31, scales from 1
to 10^9 and invalid ones, on and off grid decimals, decimals at the digit and exponent bounds, empty
and duplicate lists, conditions at depth 49 to 52, absence, wrong types, odd whitespace in definitions,
strings with escapes and astral characters, floats, `-0`, wide integers, duplicate keys, deep nesting,
invalid UTF-8, malformed and truncated images). Each case runs through the oracle, the Python reference
and the Rust port. The reference and the port read flows, so the harness renders each well formed
image to the flow text it means, with semantics preserving surface variation (orientation, grouping,
tuples, chains); an image without a faithful rendering is compared on the oracle alone. Each difference
is classified as a reader gap (section 3), a scope difference (the inferred path, engine counters,
section 1), or a finding, which is minimised to a small reproducer. A leg is one function from cases
to results, so the JavaScript and Go kernels and the C table interpreter are adapters of a few dozen
lines (section 10).

**Commands.** `python formal/diff/core_diff.py --cases 100000 --seed 1 --report out.json` is the large
run; `prismpath/tests/test_core_diff.py` is the seeded CI sized run (5,000 cases, seed 7, a few
seconds), which fails on any kind of finding not recorded in section 9, on any reading level
disagreement and on any crash. The oracle comes from `lake build` in `formal/`; the Rust leg is the
example `prismpath-rs/examples/core_diff.rs`, built on demand.

**The large run** (100,000 cases, seed 1, 420,486 readings). The oracle accepted 25,348 policies and
refused 74,652; it routed 31,857 readings and refused 13,923 with `route:no-matching-edge`, 43,588 with
`route:contract-violation`, 17,049 as unreadable and 392 as not an object, the rest with their policy's
refusal. Against the Python reference: 142,795 agreements; reader gaps 3,217 float, 3,561 duplicate
key, 8,490 integer range, 2,624 negative zero, 156 depth; scope differences 10,129 inferred path and
168 engine counter; 9,390 excluded (4,030 images `canon.loads` itself refuses, 5,360 with no flow
rendering, all refused by the oracle too); 931 findings, every one D1. Against the Rust port: 139,412
agreements; reader gaps 3,061 float, 3,434 duplicate key, 8,002 integer range, 2,551 negative zero;
scope 10,129 and 165; the same 9,390 excluded; 1,569 findings, 1,182 of them D3 and 387 D1 and D2. No
reading level disagreement and no crash in either leg: on every policy both sides accept, every
reading's route or refusal, with its field and reason, is the oracle's.

## 9. Where the implementations disagree on the slice

Each row is a disagreement the harness or a direct probe shows, with the side this specification
takes. None is fixed on this branch: this step records them.

**D1. The depth bound is not applied to a defined flow (Python).** SPEC.md 4.1 makes a predicate
nested beyond 50 invalid and `check_predicate` refuses it (`predicates.py:169`), but a defined flow
never runs that check: `apply_definitions` classifies with `level_m.is_level_m`, which parses with
`expr_ast` (`predicates.py:249-263`) and has no depth bound. So the reference accepts the policy. At
depth 51 it then evaluates the condition; from depth 52 the evaluator's own bound (`predicates.py:225`)
raises at run time, `first_deterministic` treats the edge as non matching (`engine.py:73-77`), and a
later rule routes. Reproducer: `fields {"x": "int"}`, rule 1 `hit` when `not`×50 applied to
`x >= 3` (depth 52), rule 2 `miss` always, reading `{"x": 5}`: the reference routes `miss`, where the
author's first rule says `hit`. **Specification:** the policy is refused at load (`policy:not-level-m`,
`depth`), at every depth above 50.

**D2. Rust bounds depth by a different measure (Rust).** The Rust predicate parser counts recursion
levels of its own grammar (`prismpath-rs/src/condition.rs:392-505`, `MAX_DEPTH` 50), not the
reference's static depth. A `not` chain is refused from depth 52, a nested `and` from depth 53; at
depth 51 Rust accepts and evaluates, and a nested `and` at depth 52 is accepted and silently never
matches, as in D1. Python and Rust therefore disagree with each other on conditions at depth 52.
Reproducer: as D1 with `not`×50 (Rust refuses, Python routes `miss`), and with an `and` nested to depth
52 (both accept and route `miss`). **Specification:** refuse above 50 by the measure of section 2.4.

**D3. Definition whitespace (Rust).** The reference splits a definition with `str.split()`
(`field_definitions.py:140`) and the front matter value is stripped with `str.strip()`
(`parser.py:108`), both of which treat U+001C to U+001F as whitespace; the Rust twin uses
`split_whitespace` (`prismpath-rs/src/field_definitions.rs:137`), which does not. Reproducer: the
definition `int\u001fmin=0` (or `int\u001f`): the reference accepts an `int` field, Rust refuses
`unknown kind "int\u{1f}min=0"`. **Specification:** the reference's whitespace (section 2.5); Rust is
wrong. U+001C to U+001E also end a line in the reference's `splitlines`, so they cannot reach a
definition through the flow text at all.

**D4. Which fields the boundary checks (reference, two paths).** SPEC.md 4.5 calls a reading canonical
when every defined field *the flow routes on* is canonical, and the Facet quantizer checks only the
fields it partitions (`prismpath/telemetry/quantizer.py:150-160`), while the conformance composition
that both Python and Rust replay checks every defined field (`gen_field_definitions.py:152-158`,
`prismpath-rs/tests/test_field_definitions.rs`). They differ on a policy that defines a field it never
reads. **Specification:** every defined field, the stricter rule and the one the corpus freezes; the
prose of SPEC.md 4.5 should say so, or the definition should be refused as unused. Owner decision.

**D5. The second tier kernels (JavaScript, Go).** Both refuse every flow that defines its fields
(`prismpath/portable/prismpath.mjs:1113-1116`, `prismpath-go/parser.go:107-178`), as SPEC.md 4.5
requires of a kernel that does not implement field definitions. So on the core they agree only on
refusals. **Specification:** conformant by refusal for now; step 2 either implements section 4.5 in
both or records them as refusing kernels in the conformance matrix.

**D6. The table targets (C, FPGA, eBPF).** Constants and registers are signed 32 bit
(`int-out-of-i32`, SPEC.md 4.3), so a checked policy with a constant outside that range compiles to no
table. This is a declared target limit, not a disagreement; the table adapter (step 2) must report it as
a refusal of the compiler, never a different route.

**Reader gaps** (section 3) are the other systematic differences: floats, `-0`, wide integers,
duplicate keys and deep nesting are accepted by the implementations' current readers and refused by
canon/2. They close when canon/2 is implemented, which is the cheap step the research note recommends.

## 10. Next

Step 2 adds the JavaScript and Go kernels (an adapter each, reading the rendered flow; until they
implement section 4.5 they are expected to refuse every defined flow), and the C table interpreter and
the FPGA's C twin (`prismpath-hw/interp.c`, `ppt_eval.h`): compile a checked policy to a `.ppt` image
with `prismpath-hw/ppt_compile.py`, run the readings through the interpreter, compare routes and the
compiler's refusals with the oracle. Then signed images and receipts as the evidence form: the image's
canonical bytes under an Ed25519 signature, and a receipt per verdict binding the image hash, the
reading's canonical bytes and the verdict, so a differential run is itself evidence. Owner decisions
this step leaves open: registering the proposed causes of section 5, D4, and canon/2 itself.
