# The verified policy core: Level M with field definitions

*Specification of the narrow core PrismPath proves once and every implementation is held to: one
decision of a match action policy over integers, booleans and strings, with the signed field
definitions that say what each integer means. November 2026, research line, branch `verified-core`;
step 2 on `verified-core-2`.*

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

**The readers.** canon/2 is the one reader and writer of the core's documents, in three
implementations held to one table: the Lean reader `Core.readBytes` (`formal/Core/Json.lean`), which
defines it; the Python reference `prismpath/kernel/canon2.py` (`loads`, `dumps`); and its Rust twin
`prismpath-rs/src/canon2.rs` (`read`, `write`). The frozen vectors
`prismpath/portable/conformance/canon2.json` (written by `prismpath/portable/gen_canon2_fixtures.py`,
73 byte strings, every rule above at least once and the first rule broken where several are) are
replayed by `prismpath/tests/test_canon2.py`, which also runs every vector through the oracle, and by
`prismpath-rs/tests/test_canon2.rs`. The writer emits RFC 8785 with no float: no whitespace, members in
order of the UTF-16 code units of their keys, strings as raw UTF-8 with only `"`, `\` and the control
characters escaped (`\b \t \n \f \r`, otherwise lowercase `\u00xx`), integers in decimal; it refuses
every value the reader would refuse, so a written document reads back to the same value and its bytes
are a fixed point. In the differential harness both legs read the image and every reading with their
canon/2 reader, so a document level difference is a finding, not a reader gap (section 8).

**canon/1 stays, verify only.** `prismpath.canon` (Python's `json` with the compact and spaced
canonical forms, `canon.loads` refusing NaN, Infinity, lone surrogates and numbers past the double
range) and its Rust twin `value::parse_strict` remain the readers of everything already signed, hashed
or anchored under them: policy packs and envelopes, audit logs and their Merkle leaves, root
statements, anchored roots, attestation manifests, lock hashes, checkpoints and every frozen corpus.
They change in no byte. canon/2 is scoped, in this step, to the core's two documents.

### 3.1 Migration plan for the rest (written down, not done)

Signed bytes cannot be rewritten, so the rest moves by versioning, never by reinterpreting an old
artifact:

1. **A name and a domain tag.** A document that is written under canon/2 says so: the core's image
   carries `prismpath.core/1` (whose definition includes canon/2), and every other artifact that moves
   gains an `encoding: "canon/2"` member, and its signature a `canon/2` domain prefix (root statements
   already carry one), so a verifier never guesses which reader to use.
2. **canon/1 is verify only, forever.** New writers emit canon/2; a verifier keeps the canon/1 reader
   for artifacts that do not name canon/2. Each frozen corpus gains a canon/2 twin beside it; the old
   corpus is not regenerated.
3. **Audit events.** `ts` changes from a float of seconds to an integer count of microseconds since the
   epoch (`ts_us`), the one float that every audit event carries today; an event names its encoding, a
   log may hold both, and an old log verifies under canon/1. Other floats in signed documents (the
   calibrated floors and confidences of routing receipts, measured durations) become integers of a
   stated unit or decimal strings, each in its own reviewed change.
4. **Anchored roots stay valid.** An OpenTimestamps or RFC 3161 anchor covers a Merkle root over
   leaves computed under canon/1; the root is unchanged and its leaves verify under canon/1. A log that
   mixes leaf versions hashes each leaf under the encoding the leaf names.
5. **Packs and envelopes** are re-signed under canon/2 only at their next version; the loader accepts a
   canon/1 pack whose signature verifies, until the owner retires canon/1 signing.
6. **Order.** Python first (one writer, one tag, the twins of the vectors), then Rust; the JavaScript
   and Go kernels and the table targets sign and hash nothing and are not touched. Each step is a
   separate reviewed change with its own corpus twin, and none of it is done on this branch.

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

Every input that is not routed gets exactly one of these refusals, and every one is a registered row of
`prismpath/kernel/causes.py` (append only; rows 89 to 100 were appended for the core in step 2, the
policy refusals in the `envelope` class beside the pack verifier's structural refusals, the two reading
refusals in the `routing` class). The Lean semantics spells each refusal with its code and name
(`Refusal.code`, `Refusal.cause`, `formal/Core/Eval.lean`), and the theorem `refusal_registered` proves
every pair is a row of the registry, which `gen_causes_rs.py` generates into `formal/Core/Causes.lean`
beside the Rust table; so the oracle never prints a refusal without a code. The Python reference
carries the cause on every refusal (`FieldDefinitionError.cause`, `.code`, and `.problems`, each a
`Problem` with its own cause), the Rust port on the graph (`Graph.field_error_cause`,
`field_error_causes`), and the frozen field definition vectors record the cause of every refused
policy, which the Rust replay checks.

| refusal | cause | code | when |
|---|---|---|---|
| image unreadable | `policy:unreadable` | 89 | section 3, on the image |
| image shape | `policy:shape` | 90 | section 2, the image is not the core's syntax |
| operator outside Level M | `image:unknown-op` | 74 | `causes.py:74`, an atom's operator outside the fragment |
| value type outside Level M | `image:unknown-type` | 75 | `causes.py:75` |
| name or depth outside Level M | `policy:not-level-m` | 91 | section 2.2, 2.4 |
| malformed definition | `policy:definition` | 92 | section 2.5 |
| undefined field | `image:field-index-oob` | 76 | `causes.py:76`, an atom names a field the policy does not declare |
| engine counter read | `policy:engine-counter` | 93 | section 1 |
| kind mismatch | `policy:kind-mismatch` | 94 | rule 3 |
| rounding mode | `policy:rounding` | 95 | rule 4 |
| threshold | `policy:threshold` | 96 | lowering and ranges |
| `None` misused | `policy:none` | 97 | rule 5 |
| absence untested | `policy:absence-untested` | 98 | rule 6 |
| reading unreadable | `reading:unreadable` | 99 | section 3, on the reading |
| reading not an object | `reading:not-object` | 100 | section 6 |
| value refused at the boundary | `route:contract-violation` | 37 | `causes.py:48`, the reading violates the declared definitions; the field and `missing`, `wrong_type` or `out_of_range` |
| no rule holds | `route:no-matching-edge` | 32 | `causes.py:43`, refused for admission |

A policy refusal refuses every reading with the same refusal. The image refusals 74 to 76 keep their
pack verifier names: the operator, value type and field index of a table image are the same three
facts about an atom.

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

### 6.1 The system boundary and the policy check (D4, resolved)

Which fields a reading must hold canonically depends on who is checking (owner decision, 2026-11-10).
The two checks have distinct names and both are part of the core:

- **The system boundary** validates the soundness of the *system*: every field the policy defines, in
  code point order, is the reading's contract, whether or not a rule reads it. It is the boundary of
  step 2 above and the one the verdict applies; the frozen field definition vectors replay it.
  Lean `systemBoundary` (`formal/Core/Eval.lean`), Python `field_definitions.system_boundary`, Rust
  `field_definitions::system_boundary`.
- **The policy check** validates the soundness of a *policy*: only the defined fields some rule reads
  (the *routed* fields, `rulesFields` and `Checked.routedDefs` in Lean, `routed_fields` in Python and
  Rust), in code point order. It is what SPEC.md section 4.5 means by a canonical reading ("every
  defined field the flow routes on") and what the Facet quantizer checks for the fields it partitions
  (`prismpath/telemetry/quantizer.py:150-160`); it belongs to policy validation and lint, and it never
  produces a verdict. Lean `policyCheck`, Python `field_definitions.policy_check`, Rust
  `field_definitions::policy_check`.

How they relate is proved in `formal/Core/Boundary.lean`: a reading the system boundary accepts passes
the policy check (`policyCheck_of_systemBoundary`), so a reading the policy check refuses the system
boundary refuses too (`systemBoundary_of_policyCheck`) and the system boundary is at least as strict on
every reading; a policy check refusal names a routed field (`policyCheck_refuses_routed`); on a policy
that routes on every field it defines the two are the same function (`policyCheck_eq_systemBoundary`);
and the route of a reading the system boundary accepts depends only on the values of the routed fields
(`route_depends_on_routed`), which is why the policy check is the right check of a policy and the
system boundary the stricter contract of the system. The oracle's batch mode prints the policy check
beside every verdict, and the differential holds both legs to it (section 8).

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

**The two checks of a reading** (`Core/Boundary.lean`, step 2, section 6.1).
`policyCheck_of_systemBoundary`: a reading the system boundary accepts passes the policy check.
`systemBoundary_of_policyCheck`: a reading the policy check refuses the system boundary refuses, so the
system boundary is at least as strict on every reading. `policyCheck_refuses_routed`: a policy check
refusal names a defined field some rule reads, with the definition's own reason.
`policyCheck_eq_systemBoundary`: on a policy that routes on every field it defines, the two checks are
the same function. `route_depends_on_routed`: two readings the system boundary accepts that hold the
same values on the routed fields get the same verdict (from `evalC_congr_on` and
`firstMatch_congr_on`, a condition's truth depends only on the fields it reads).

**Every refusal carries a registered code** (`Core/Codes.lean`, step 2, section 5).
`refusal_registered`: the (code, name) of every refusal, of every one of the thirteen policy refusals
and the four reading refusals, is a row of the registry generated from `prismpath/kernel/causes.py`
(`Core/Causes.lean`). `refusal_code_ne_zero`: no refusal carries 0, the code of a clean decision.
`registry_codes_distinct` and `refusal_name_of_code`: the registry gives each code one name, so a code
alone names the cause. `verdict_refusal_registered`: whatever the inputs, a refused verdict carries a
registered nonzero code. The proofs are `decide` over the generated list, so a spelling that drifts from
the registry, or a registry regenerated without a row the core uses, fails the build.

**Not proven, stated as plainly.** That any implementation computes `verdict`: Python, Rust and the
other targets are *conformant* to the oracle by differential testing (section 8), not proven. The
order of the image's `fields` members does not change a verdict, because definitions are read in
sorted order, but the uniqueness of that sort is not yet a theorem. The FQ bridge theorems take FQ's
partitions as FQ defines them; the quantizer's code is held to those by FQ's own bridge vectors. That
the reference names the oracle's first cause on a policy with several problems (D7): it names one of
them, which the harness checks, not the first in the order of section 4. The canon/2 readers of Python
and Rust are held to the Lean reader by the frozen vectors and the differential, not by proof.

## 8. The oracle and the differential harness

**The oracle.** `lake exe core-oracle POLICY [READING ...]` (built by `lake build` in `formal/`)
prints one JSON line for the policy, `{"policy":"accepted"}` or `{"policy":"refused","cause":...,
"code":...}`, then one line per reading, `{"verdict":"route","target":...}` or
`{"verdict":"refuse","cause":...,"code":...,"field":...,"reason":...}` with `field` and `reason` only
where the refusal has them; every refusal carries its registered code (section 5). `--batch` reads
framed cases (`case <id> <n>` then `n + 1` documents, each as its byte length and its bytes) and prints
one line per case, each reading's verdict with its policy check beside it (`"policy_check"`, section
6.1) when the policy is accepted and the reading is an object. Every printed value is computed by
`Core.verdict`; `formal/Core/Main.lean` only frames and spells.

**The harness.** `formal/diff/core_diff.py` generates random images and readings, well formed and
malformed, biased toward boundaries (ranges at plus or minus 2^53 minus 1 and at 2^31, scales from 1
to 10^9 and invalid ones, on and off grid decimals, decimals at the digit and exponent bounds, empty
and duplicate lists, conditions at depth 25 and 49 to 53 as `not` chains and as `and` and `or` nested
on the left, the right and alternately, absence, wrong types, Python's whitespace and U+FEFF in
definitions, strings with escapes and astral characters, floats, `-0`, wide integers, duplicate keys,
deep nesting, invalid UTF-8, malformed and truncated images). The reference and the ports read flows,
so the harness renders each well formed image to the flow text it means, with semantics preserving
surface variation (orientation, grouping, tuples, chains); an image without a faithful rendering is
compared on the oracle alone. Each case runs through the oracle and six legs, each an adapter around
the implementation's own functions:

| leg | implementation | composition | documents |
|---|---|---|---|
| `python` | the reference | `parser.parse`, `field_definitions.system_boundary` and `policy_check`, `engine.first_deterministic` | canon/2 (`kernel/canon2.py`) |
| `rust` | `prismpath-rs` | the same, `prismpath-rs/examples/core_diff.rs` | canon/2 (`canon2.rs`) |
| `js` | `prismpath/portable/prismpath.mjs` | `parse`, `firstDeterministic`, `formal/diff/core_diff_js.mjs` | `JSON.parse` after strict UTF-8 |
| `go` | `prismpath-go` | `Parse`, `IsDeterministic`, `EvalCondition`, `prismpath-go/cmd/core_diff` | `encoding/json` after a UTF-8 check |
| `c-interp` | `prismpath-hw/interp.c` | host: the reference checks the policy, reads, applies the system boundary; `ppt_compile.py` compiles and encodes registers; the interpreter picks the edge (`formal/diff/ppt_batch.c`) | canon/2 on the host |
| `c-hdr` | `prismpath-hw/ppt_eval.h`, the embedded evaluator the FPGA's C twin and the firmwares include | the same | canon/2 on the host |

Each difference is classified: `agree`; a scope difference (the inferred path and engine counters,
section 1); a reader gap, only for the two legs with no canon/2 reader (D5); `refusing-kernel` (D5);
`target-limit` (D6: the compiler or the register encoder refuses a value outside 32 bits, or interp.c's
64 deep stack would overflow); `cause-order` (D7, the oracle's cause is among the leg's problems); or a
finding, which is minimised to a small reproducer of the same kind. Every refusal of the four legs that
speak the registry must carry its registered code (`finding:uncoded` otherwise), and the first tier
legs' policy checks must equal the oracle's (`finding:policy-check`).

**Commands.** `python formal/diff/core_diff.py --cases 100000 --seed 1 --report out.json` is the large
run (all six legs by default; `--legs` picks some). `prismpath/tests/test_core_diff.py` is the seeded
CI sized run (5,000 cases, seed 7, every leg whose toolchain is present, a few seconds): it fails on any
kind of finding not recorded in section 9, on any reading level or policy check disagreement, on any
uncoded refusal and on any crash. The oracle comes from `lake build` in `formal/`; the Rust leg is the
example `prismpath-rs/examples/core_diff.rs`, built on demand; the Go and C adapters are compiled into a
private temporary directory per run.

**The large run, step 2** (100,000 cases, seed 1, 419,651 readings). The oracle accepted 24,041 policies
and refused 75,959; it routed 30,380 readings and refused 13,741 with `route:no-matching-edge`, 40,892
with `route:contract-violation`, 15,846 as unreadable and 379 as not an object, the rest with their
policy's refusal; on 18,568 readings the system boundary refused a defined field no rule reads, which
the policy check passed (D4, section 6.1). Per leg (case level policy rows and reading rows together):

| leg | agree | cause-order (D7) | policy-cause (D7) | scope | excluded | other |
|---|---|---|---|---|---|---|
| python | 153,822 | 6,843 | 2,915 | 10,265 inferred, 171 engine counter | 3,181 | none |
| rust | 153,741 | 6,270 | 3,569 | 10,265, 171 | 3,181 | none |
| js | 60,492 | | | 10,265 inferred | 12,902 | 22,035 refusing-kernel; reader gaps 276 float, 160 integer range, 154 negative zero, 33 depth, 26 duplicate key, 17 lone surrogate |
| go | 60,511 | | | 10,265 inferred | 12,902 | 22,035 refusing-kernel; reader gaps 257 float, 160, 154, 33, 26, 17 |
| c-interp | 137,116 | 6,843 | 2,915 (the host's) | 10,265, 171 | 3,181 | target-limit 3,527 at compile, 2,070 on a reading |
| c-hdr | 137,116 | 6,843 | 2,915 (the host's) | 10,265, 171 | 3,181 | target-limit 3,527, 2,070 |

Excluded are the 3,181 images with no flow rendering, all refused by the oracle (for the second tier
legs also the images that do not read, which they have no reader for). No reading level disagreement,
no policy check disagreement, no uncoded refusal and no crash on any leg: on every policy a leg accepts
and the oracle accepts, every reading's route or refusal, with its field and reason, is the oracle's,
and on every policy the table compiled, every register encodable reading routes on both C evaluators
as the oracle routes it. The only findings are D7's, every one a policy both sides refuse.

**The large run, step 1** (for comparison; 100,000 cases, seed 1, 420,486 readings, the step 1
generator). Against the Python reference: 142,795 agreements; reader gaps 3,217 float, 3,561 duplicate
key, 8,490 integer range, 2,624 negative zero, 156 depth; 931 findings, every one D1. Against the Rust
port: 139,412 agreements; reader gaps 3,061 float, 3,434 duplicate key, 8,002 integer range, 2,551
negative zero; 1,569 findings, 1,182 of them D3 and 387 D1 and D2.

## 9. Where the implementations disagree on the slice

Each row is a disagreement the harness or a direct probe shows, with the side this specification
takes. Step 1 recorded D1 to D6; step 2 fixes D1, D2 and D3 (each with regression cases in the frozen
field definition vectors and in the harness's generator), resolves D4 (section 6.1), extends the
harness to the D5 and D6 legs, and records D7.

**D1. The depth bound is not applied to a defined flow (Python).** SPEC.md 4.1 makes a predicate
nested beyond 50 invalid and `check_predicate` refuses it (`predicates.py:169`), but a defined flow
never runs that check: `apply_definitions` classifies with `level_m.is_level_m`, which parses with
`expr_ast` (`predicates.py:249-263`) and has no depth bound. So the reference accepts the policy. At
depth 51 it then evaluates the condition; from depth 52 the evaluator's own bound (`predicates.py:225`)
raises at run time, `first_deterministic` treats the edge as non matching (`engine.py:73-77`), and a
later rule routes. Reproducer: `fields {"x": "int"}`, rule 1 `hit` when `not`×50 applied to
`x >= 3` (depth 52), rule 2 `miss` always, reading `{"x": 5}`: the reference routes `miss`, where the
author's first rule says `hit`. **Specification:** the policy is refused at load (`policy:not-level-m`,
`depth`), at every depth above 50. **Fixed in step 2:** `field_definitions.policy_problems` and
`fragment_problems` apply the reference's own static measure (`predicates._depth`) to every
deterministic condition of a defined flow (`_depth_problem`), so the policy is refused at load with
`policy:not-level-m`. Regressions: the vectors `depth_fifty_one_not_chain`, `depth_fifty_two_not_chain`
(refused) and `depth_fifty_not_chain` (accepted).

**D2. Rust bounds depth by a different measure (Rust).** The Rust predicate parser counts recursion
levels of its own grammar (`prismpath-rs/src/condition.rs:392-505`, `MAX_DEPTH` 50), not the
reference's static depth. A `not` chain is refused from depth 52, a nested `and` from depth 53; at
depth 51 Rust accepts and evaluates, and a nested `and` at depth 52 is accepted and silently never
matches, as in D1. Python and Rust therefore disagree with each other on conditions at depth 52.
Reproducer: as D1 with `not`×50 (Rust refuses, Python routes `miss`), and with an `and` nested to depth
52 (both accept and route `miss`). **Specification:** refuse above 50 by the measure of section 2.4.
**Fixed in step 2.** The direct probe showed the measure differed the other way too: an `and` nested on
the right inside parentheses cost the Rust parser two levels per level, so the port refused a right
nested condition far below 50 that the reference accepts. Now the parser's `depth` counts only the
nesting that is evaluation depth (a `not`, a later operand of `and` or `or`, a comparison's right side),
never a bracket, so its guard fires only where the evaluator (`ev_node`, the reference's `_ev`) refuses
anyway; brackets have their own bound of 200, Python's tokenizer's; and the static bound of SPEC.md 4.1
is the reference's measure, `condition::static_depth`, applied by `check_predicate` and by the policy
rules of a defined flow (`policy:not-level-m`). Regressions: the vectors `depth_fifty_nested_right` and
`depth_fifty_nested_left` (accepted), `depth_fifty_one_nested_right` and `depth_fifty_two_nested_left`
(refused); the harness's generator writes `and` and `or` nested on the left, the right and alternately
from depth 25 to 53.

**D3. Definition whitespace (Rust).** The reference splits a definition with `str.split()`
(`field_definitions.py:140`) and the front matter value is stripped with `str.strip()`
(`parser.py:108`), both of which treat U+001C to U+001F as whitespace; the Rust twin uses
`split_whitespace` (`prismpath-rs/src/field_definitions.rs:137`), which does not. Reproducer: the
definition `int\u001fmin=0` (or `int\u001f`): the reference accepts an `int` field, Rust refuses
`unknown kind "int\u{1f}min=0"`. **Specification:** the reference's whitespace (section 2.5); Rust is
wrong. U+001C to U+001E also end a line in the reference's `splitlines`, so they cannot reach a
definition through the flow text at all. **Fixed in step 2:** `condition::is_py_ws` is now exactly
Python's `str.isspace` (it also wrongly counted U+FEFF, which JavaScript's trim strips and Python's
does not), a definition is split with `condition::py_split`, and the front matter keys and values are
stripped with `py_trim` as the reference strips them, not with JavaScript's trim. Regressions: the
vectors `definition_split_on_python_whitespace` (U+001F, U+3000, U+2000, accepted) and
`definition_with_a_byte_order_mark` (refused); the generator's separators include the rest of
Python's whitespace set and U+FEFF.

**D4. Which fields the boundary checks (reference, two paths). Resolved in step 2 (section 6.1).** SPEC.md 4.5 calls a reading canonical
when every defined field *the flow routes on* is canonical, and the Facet quantizer checks only the
fields it partitions (`prismpath/telemetry/quantizer.py:150-160`), while the conformance composition
that both Python and Rust replay checks every defined field (`gen_field_definitions.py:152-158`,
`prismpath-rs/tests/test_field_definitions.rs`). They differ on a policy that defines a field it never
reads. **Resolution (owner, 2026-11-10):** both are right, for different checkers. The core's runtime
boundary is the *system boundary* (every defined field, as the corpus freezes); the SPEC prose and the
quantizer describe the *policy check* (the routed fields). Section 6.1 defines both, the three
implementations carry both, and the Lean theorems state that the system boundary is at least as strict
and that only routed fields can change a route.

**D5. The second tier kernels (JavaScript, Go).** Both refuse every flow that defines its fields
(`prismpath/portable/prismpath.mjs:1113-1116`, `prismpath-go/parser.go:107-178`), as SPEC.md 4.5
requires of a kernel that does not implement field definitions. So on the core they agree only on
refusals. **Specification:** conformant by refusal for now; step 2 either implements section 4.5 in
both or records them as refusing kernels in the conformance matrix. **Step 2: recorded as refusing
kernels.** Implementing section 4.5 in them is not contained: each would need the definition grammar,
exact decimal lowering on the source spans of the predicate text (the JavaScript kernel in BigInt), the
six policy rules with their causes, the system boundary and the policy check, and a canon/2 reader, a
port of about the size of `prismpath-rs/src/field_definitions.rs` and `canon2.rs` in each language, with
its own conformance replay. Both are legs of the harness now (adapters `formal/diff/core_diff_js.mjs`,
`prismpath-go/cmd/core_diff`): on the large run they refuse all 22,035 defined flows the oracle accepts,
agree on every flow without definitions, and differ otherwise only by reader gaps, documents canon/2
refuses and their runtime's JSON reads.

**D6. The table targets (C, FPGA, eBPF).** Constants and registers are signed 32 bit
(`int-out-of-i32`, SPEC.md 4.3), so a checked policy with a constant outside that range compiles to no
table. This is a declared target limit, not a disagreement; the table adapter (step 2) must report it as
a refusal of the compiler, never a different route. **Step 2: confirmed.** The C legs compile every
checked policy with `prismpath-hw/ppt_compile.py` and run its readings through `interp.c` and
`ppt_eval.h`; 3,527 checked policies of the large run hold a constant outside 32 bits and are refused by
the compiler (`int-out-of-i32`), and 2,070 readings of compiled policies hold a value the 32 bit
registers cannot carry and are refused by the register encoder (`encode_scalar`, the same reason);
neither is ever a route. Every other reading routes as the oracle routes it. The target limit is not a
registered cause of the core: it is the compiler's refusal, and stays outside the core's closed set. The
eBPF target shares the table image and is not run here.

**D7. Which cause names a policy with several problems (Python, Rust).** Found when step 2 made every
leg report its cause. Both sides refuse the same policies and every refusal carries a registered code;
every minimised reproducer of a cause difference (31 kinds for Python, 37 for Rust in the large run of
section 8) is a policy with at least two problems, sometimes in one atom (an undefined field compared
with a decimal is both `image:field-index-oob` and a decimal on a field that is not fixed), and the
kinds `policy:engine-counter vs ...` are the scope difference of section 1 meeting another problem
(the reference does not refuse an engine counter, so it names the policy's other problem). On a policy with several, the specification names
the first in its order (section 4: the whole image decoded, then the definitions in code point order,
then rule by rule and atom by atom), while the reference and the port meet them in their own phases:
the Level M classifier judges a whole condition before its atoms, the lowering of a condition's
decimals runs before its atoms are checked, and a malformed definition stops the definitions before any
atom is read. Both legs therefore report every problem they find (`FieldDefinitionError.problems`,
`Graph.field_error_causes`), including the condition problems no definition changes, and the harness
classifies a case as `cause-order` when the oracle's cause is among them and as the finding
`policy-cause <oracle> vs <leg>` when it is not (the leg stopped before reaching it). Reproducer: `fields
{"x": "int"}`, one rule `["and", ["cmp", "x", "==", ["num", "9007199254740992"]], ["cmp", "x", "==",
["num", "2.5"]]]`: the oracle names `policy:threshold` (`constant-range`, the first atom), the reference
`image:unknown-type` (the classifier sees the float in the second atom first). **Specification:** the
order of section 4 is the one the oracle proves things about; making the reference report exactly that
first cause means checking it atom by atom in the core's order, a restructuring of `apply_definitions`
that this step does not do. Open: either the reference adopts the order, or the cause of a policy
refusal is specified as any one of its problems, with the oracle's as the canonical one.

**Reader gaps (closed).** Step 1 counted floats, `-0`, wide integers, duplicate keys and deep nesting
as reader gaps: the implementations read documents with canon/1, which accepts them. canon/2 is now
the reader of both legs (section 3), so these documents are refused with the oracle's rule and a
difference on them is a finding; the step 2 runs show none.

## 10. Next

Step 2 (this branch) adopted canon/2 for the core's documents (section 3) and wrote down the migration
of the rest (section 3.1), registered every core refusal (section 5), resolved D4 into the system
boundary and the policy check (section 6.1), fixed D1 to D3, ran the JavaScript, Go and C legs (D5,
D6), and proved the new claims (section 7). Next: signed images and receipts as the evidence form (the
image's canon/2 bytes under an Ed25519 signature, a receipt per verdict binding the image hash, the
reading's canonical bytes, the verdict and its cause code, so a differential run is itself evidence);
the eBPF table target as a leg. Owner decisions this step leaves open: D7 (the reference adopts the
order of section 4, or a policy refusal's cause is specified as one of its problems); whether the
JavaScript and Go kernels should implement section 4.5 or stay refusing kernels in the conformance
matrix; and when the canon/2 migration of section 3.1 starts.
