# Neutral scenario corpus (frozen at pre-registration)

One corpus, every system runs it. Each file here is one policy with its scenarios, written in a
system neutral JSON so that no comparator is handed a policy already shaped like its own idiom.
Each comparator gets a translator (Phase 2) that turns this form into its native policy language;
the translator is itself evidence of what had to be expressed and where the idiom strained.

## Policy file

```
{
  "id": "expense_approval",            unique id, also the file stem
  "title": "...",
  "dimensions": ["A1", "A2"],           the dimensions this policy exercises
  "level_m_claim": true,                pre-registered: expressible in PrismPath Level M as written
  "fields": { "<name>": {"type": "int|bool|string|list", "values": [...], "note": "..."} },
  "outcomes": ["allow", "deny", ...],   the decision vocabulary this policy uses
  "catch_all": true|false,              whether the last rule is unconditional (see no_match below)
  "rules": [ {"id": "r1", "if": <cond>, "then": "<outcome>", "why": "..."} ],
  "lifecycle": [ ... ],                 optional: stale/tampered policy and input scenarios
  "scenarios": [ ... ]
}
```

Rules are **ordered, first match wins**. That is the neutral semantics every translator must
reproduce; a system that cannot express ordered first match records how it emulated it.

## Condition language

Deliberately small. A condition is one of:

| form | meaning |
|---|---|
| `{"cmp": ["field", "==", 5]}` | compare a field to a constant; ops `== != < <= > >=`; constants int, bool, string |
| `{"in": ["field", ["a", "b"]]}` | field equals one of the listed constants |
| `{"not_in": ["field", [...]]}` | field equals none of the listed constants |
| `{"missing": "field"}` | the input does not carry the field, or carries null |
| `{"present": "field"}` | the input carries a non null value for the field |
| `{"all": [c1, c2, ...]}` | every sub condition holds |
| `{"any": [c1, c2, ...]}` | at least one sub condition holds |
| `{"not": c}` | boolean negation |
| `true` | unconditional (the catch all) |

**Missing values.** A `cmp`, `in`, or `not_in` over a field that is missing or null is
**unsatisfied**, never an error. Only `missing` and `present` can see absence. This is the neutral
semantics; whether a comparator returns undefined, an error, or a default when the input lacks a
field is exactly what dimension A1 measures, so translators must not paper over it.

**Group B extensions** (used only by the B1 and B3 policies, where PrismPath is expected to lose):

| form | meaning |
|---|---|
| `{"role_at_least": ["field", "manager"]}` | the field's role is at or above the named role in the policy's declared `hierarchy` |
| `{"eq_fields": ["field_a", "field_b"]}` | two input fields are equal |
| `{"intersects": ["list_field_a", "list_field_b"]}` | two list fields share at least one element |
| `{"related": ["user", "relation", "object"]}` | the relationship graph, with declared inheritance, derives the tuple |

Relationship tuples in a policy's `model.tuples` are always `[subject, relation, object]` in Zanzibar order, a
`parent` tuple included: `["folder:f1", "parent", "doc:d1"]` says f1 is the parent of d1.

## Outcome vocabulary

Decisions a policy may return: `allow`, `deny`, `observe` (admit and log), `abstain` (insufficient
evidence, nothing acted on), `escalate_human` (a person decides).

Results a run may produce that are not decisions, and that a result file may record as `observed`:
`no_match` (no rule matched and there is no catch all), `refuse_policy` (the policy artifact was
refused: stale or tampered), `refuse_input` (the input failed an integrity check), `error`,
`undefined`, `not_expressible`.

## Scenario

```
{
  "id": "clear_allow_1",
  "kind": "clear_allow | clear_deny | insufficient | escalation | undeclared_missing |
           stale_policy | tampered_policy | tampered_input | ai_worker_loop | expressiveness | relationship",
  "input": { "<field>": value, ... },           null or absence both mean missing
  "expected": {
    "outcome": "<outcome or no_match>",
    "rule": "r3",                                the rule the neutral semantics select, null for no_match
    "prismpath_cause": 0                         pre-registered PrismPath cause code (docs/design/spec-cause-codes.md); 0 = clean
  },
  "note": "why this scenario exists"
}
```

`expected` is computed by the neutral reference evaluator in `../corpus_check.py` and checked in
CI; a scenario whose written expectation disagrees with the neutral semantics fails the test. The
`prismpath_cause` is a **pre-registered prediction**, not a measurement; Phase 3 measures it.

`ai_worker_loop` scenarios carry `"steps": [ {input, expected}, ... ]` instead of one input, plus
`"receipt_expected": {"per_decision": true, "signed": true, "tamper_evident": true, "carries_cause": true}`.

Lifecycle entries carry `"presented"` (what is offered to the enforcement point) instead of
`input`, and the expected outcome is `refuse_policy` or `refuse_input` with a `reason` in
`{stale, tampered, unsigned}`.
