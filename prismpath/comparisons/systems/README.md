# Translators (Phase 2)

One package per system under `systems/<id>/`, each implementing the contract in
[`../harness.py`](../harness.py): `translate(policy)` turns a neutral corpus policy into the
system's native artifacts, and `Runner.decide(input)` asks the real system for one decision. The
gate is `python -m prismpath.comparisons.check_translators`: every translation is written to
`systems/<id>/generated/<policy>/` (a committed, reviewable artifact, the evidence pointer result
files cite) and every scenario is decided by the real system and compared with the corpus
expectation. Reports are in `systems/<id>/generated/conformance.json`.

## Conformance at the Phase 2 freeze (66 decisions per system: 61 scenarios, the loop expanded)

| system | MATCH | MISMATCH | PROBE | DROPPED | UNEXPRESSIBLE | idiomatic |
|---|---|---|---|---|---|---|
| prismpath | 52 | 0 | 5 | 3 | 6 | all |
| opa | 61 | 0 | 5 | 0 | 0 | all |
| cedar | 61 | 0 | 5 | 0 | 0 | all |
| cerbos | 55 | 0 | 5 | 0 | 6 | B1 marked not idiomatic (see below) |
| openfga | 6 | 0 | 0 | 0 | 60 | all |

MISMATCH is a translator defect and fails the gate; there are none. PROBE rows are the
`undeclared_missing` scenarios, whose observed value is the dimension A1 measurement, not a pass or
fail. DROPPED rows are rules a translation declared it cannot express (measured inexpressibility).
UNEXPRESSIBLE means the whole policy is outside the system.

What the probes returned, before anyone grades them. On the three policies with a catch all,
every system lands the missing field in the catch all exactly as the neutral semantics say. On
`sensor_interlock`, which has no catch all by design:

| system | the two no match probes | what that is, verbatim |
|---|---|---|
| prismpath | `no_match`, cause 36 | the engine stops as `stuck` with `route:stuck` on the receipt |
| opa | `undefined` | `opa eval` returns an empty result set; the decision document is undefined |
| cedar | `no_match` | the runner's reading of `DENY` plus "no policies applied to this request" |
| cerbos | `no_match` | the runner's reading of `EFFECT_DENY` with no output; the raw effect is a deny |

The Cedar and Cerbos `no_match` is a translator reading, not a system value: both systems answer
a deny. The raw output is in each `conformance.json` row and is what Phase 3 grades.

## Where each idiom strained (the notes in every `TRANSLATION.json`, summarized)

- **prismpath**: one node, rules as `when` edges in document order, each to its own terminal node
  so the rule identity survives. `human_requested` rides the reserved worker field `needs_human`
  (cause 34). Cannot express field against field (`eq_fields`) or set intersection
  (`intersects`): rules r3 and r4 of the B1 policy are dropped. Role hierarchy is flattened to an
  explicit list. No relationship graph at all.
- **opa**: ordered rules as a single `else` chain, absence via `object.get(input, f, null)`, sets
  for membership. All Group B constructs native; the relationship graph is compiled by hand from the
  corpus model into a `graph.reachable` input, and the translator says so.
- **cedar**: one `permit` per rule with `@id` and `@outcome` annotations, first match emulated by
  conjoining the negation of every earlier condition (Cedar has no ordering; `forbid` is not used
  because it would override regardless of position), `context has` guards everywhere. The outcome
  is not a Cedar decision; it is read from the determining policy id in `authorize -v`. Role
  hierarchy is the entity hierarchy; relationships are one policy per viewer tuple over the
  hierarchy, the expansion of a linked template per tuple.
- **cerbos**: one resource policy per corpus policy, one action `decide`, first match emulated by
  negation as for Cedar, outcomes beyond allow and deny in each rule's `output` block, `has()`
  guards everywhere. Derived roles are the Cerbos idiom for a hierarchy and are emitted, but they
  cannot appear inside a condition and so cannot join the negation chain; the hierarchy is
  flattened in CEL and B1 is marked `idiomatic: false` for it. No relationship store.
- **openfga**: the relationship policy is a one to one translation of the corpus model (assignable
  relations, `group#member` subjects, `viewer from parent`). The four decision policies are not
  expressible: a Check is one boolean for one relation.

## Facts established on the pinned binaries while writing these

- Cerbos has no ordered evaluation: two matching rules with different effects resolve to
  `EFFECT_DENY`. A CEL condition over a missing attribute is an evaluation error, logged as a
  warning, and the rule does not match.
- Cedar signals DENY as exit code 2 with a leading blank line, requires an entities file even when
  empty (a JSON list), and takes the context as a JSON record file.
- OPA `opa eval` on an undefined decision returns an empty result set and exit 0.

## Reproduce

```bash
python -m prismpath.comparisons.check_translators                 # every installed system
python -m prismpath.comparisons.check_translators --system cedar  # one system
```
