# The PrismPath format · specification

**Spec version 1 (draft).** This document is the normative definition of the PrismPath flow format:
the document grammar, the four edge tiers, the predicate language, the engine contract, and the
portability levels. The **conformance vectors** (`prismpath/portable/conformance/`) are part of this spec:
an implementation conforms to spec version 1 iff it passes every committed vector bit-for-bit.
The Python kernel in this repository is the **reference implementation**; the vectors are
generated from it deterministically (`prismpath/portable/gen_conformance.py`), so the `git diff` of the
vector files is the authoritative record of any semantic change.

The design principle behind every rule here: **the flow is data, not code.** A flow is an inert,
inspectable Markdown document. Everything the ecosystem does; lint, test, lock, calibrate,
prove, port, compile; is possible because the control flow lives in the document, not in a
routing callback.

---

## 1. Document grammar

A flow is one UTF-8 Markdown file.

```markdown
---
name: bugfix          # optional; default "flow"
start: triage         # optional; default = the first node defined
---

## triage                                    ← a NODE
Read the bug report and decide what to do.   ← the node's INSTRUCTION (prose)
@emits(action)                               ← an ANNOTATION (optional)
-> implement: when action == "fix"           ← an EDGE
-> close: it is a duplicate or invalid

## done                                      ← a node with no edges is TERMINAL
```

Normatively:

- **Front matter**: an optional leading `---\n … \n---\n` block of `key: value` lines. `name`
  defaults to `"flow"` **only when absent** (an empty value stays empty); `start` falls back to
  the first node when absent *or empty*.
  Keys of the form `field.<name>` define the flow's fields (§4.5).
- **Node**: a line matching `^\s*##\s+(.+?)\s*$`. The node name is the heading, trimmed,
  lowercased, with spaces replaced by underscores (`Write Code` → `write_code`). A later heading
  with the same normalized name replaces the earlier node.
- **Edge**: a line matching `^\s*-?\s*->\s*([A-Za-z0-9_\-]+)\s*:\s*(.+?)\s*$` inside a node:
  `(target, condition)`. Edge order is significant (see §3).
- **Annotation**: a line matching `^\s*@(\w+)\s*\((.*)\)\s*$` inside a node (`\w` is Unicode).
  Arguments are comma-separated `key=value` pairs and/or bare tokens (mapped to null). Repeated
  annotations of the same name merge (later keys win); they never overwrite wholesale.
- **Instruction**: every other line inside a node, joined and trimmed. It is the prose handed to
  the worker; the engine never interprets it.
- **Terminal node**: a node with zero edges. Reaching one ends the run.
- **Line boundaries** are Python `str.splitlines()` boundaries (`\r\n`, `\r`, `\n`, `\v`, `\f`,
  U+001C to U+001E, U+0085, U+2028, U+2029); implementations must not split on `\n` alone.
- **Whitespace trimming** throughout uses the Python `str.strip()` character class (wider than
  JavaScript `trim()`: it includes U+0085 et al.). Condition-tier classification depends on this.

## 2. The four edge tiers

The condition string's **syntactic form** selects its tier. The partition is total and
non-overlapping; classification uses the trimmed, lowercased condition:

| tier | form | routes when |
|---|---|---|
| **deterministic** | starts with `when `: or is exactly one of `always`, `true`, `else`, `otherwise`, `default`, `_` (always-true) / `false`, `never` (never-true) | the predicate evaluates truthy against the outcome fields (§4) |
| **error** | starts with `on error`, optionally `on error when <expr>` | the worker **raised**; `<expr>` (if any) evaluates truthy against the error context (§5.3) |
| **event** | starts with `on event <name>` or `on timeout` | the suspended run is **resumed** with that event; `on timeout` awaits the reserved event `__timeout__` |
| **semantic** | anything else (natural language) | an embedding/LLM router selects it (§5.2) |

The event *name* preserves the original case of the condition text after `on event`, trimmed.

## 3. Routing semantics

At a non-terminal node, after the worker returns an outcome (§5.1):

1. **Deterministic edges first, in document order; first true wins.** An unsafe or unparseable
   predicate is *non-matching* (never a crash; see §4.4).
2. If none matched and the node has **semantic edges**, a router chooses among them using the
   outcome *text*. Router behavior (embedding similarity, hybrid escalation, thresholds) is
   implementation-defined and out of scope for conformance, **except** in the portable subset
   (§7), where semantic edges are absent or must be refused.
3. If none matched and there are no semantic edges → the run stops as `stuck`.
4. **Error and event edges are inert during normal routing.** They fire only on a raise (§5.3)
   or a resume delivery (§5.4) respectively.

Loop control: the engine maintains `visits[node]` (incremented when a node's worker is about to
run) and exposes `visits` to that node's predicates. A global `max_steps` (default 25) bounds
every run; exhausting it stops the run as `max_steps`.

## 4. The predicate language

The expression after `when ` (and after `on error when `) is a restricted, side-effect-free
language. It is exactly the subset of Python expression syntax listed here; nothing else.

### 4.1 Grammar

- **Names**: `[A-Za-z_][A-Za-z0-9_]*`, resolving to outcome fields plus `visits` (and, in error
  context, the fields of §5.3). An unknown name resolves to null. **Python hard keywords are
  rejected as names** (`class`, `import`, `is`, `lambda`, …); a predicate using one is invalid.
  Soft keywords (`match`, `case`, `type`) are ordinary names. `True`, `False`, `None` are
  constants; lowercase `true`/`false`/`none` are **names** (fields), not constants.
- **Literals**: integers and floats including `0x`/`0o`/`0b` radixes, `_` separators, and
  exponents (complex literals are invalid); strings in single or double quotes with Python's
  escape table (`\n \t \r \0 \a \b \f \v \\ \' \" \xNN \uNNNN`; an unknown escape keeps the
  backslash) and raw-string prefixes `r'…'`/`R"…"` (bytes literals are invalid); list literals
  `[a, b]`; tuple literals `(a, b)` including the empty tuple `()`; `...` (Ellipsis, a truthy
  constant equal to nothing representable in JSON).
- **Operators**: `and`, `or`, `not`; comparisons `== != < <= > >= in not in`, **chained**
  (`1 < x < 5` ≡ `1 < x and x < 5`, evaluated pairwise left-to-right). Parentheses group.
  A **top-level comma** creates a bare tuple (non-empty ⇒ always truthy; legal but a known
  authoring trap; linters should warn).
- **Nothing else.** Calls, attributes, subscripts, arithmetic (including unary minus),
  comprehensions, lambdas, walrus, f-strings, and `is` are invalid. Validity is enforced
  **statically before evaluation**: a predicate containing a disallowed construct is invalid
  even if evaluation could short-circuit around it.
- **Depth**: expressions nested beyond 50 structural levels are invalid. Grouping parentheses
  and precedence do not add depth; each boolean/comparison/`not`/collection nesting level does.

### 4.2 Evaluation semantics

Over JSON-representable values (null, bool, number, string, array, object):

- **Truthiness** (used by bare names, `and`/`or`/`not`, and the final result): null, `false`,
  `0`, `-0.0`, `""`, `[]`, `{}` are falsy; everything else (including NaN) is truthy.
- **Equality (`==`/`!=`)**: booleans compare **numerically** with numbers (`true == 1`,
  `false == 0`); numbers compare by value (`1 == 1.0`); strings exactly; arrays and objects
  structurally; null equals only null; cross-type otherwise is unequal (never an error).
- **Ordering (`< <= > >=`)**: numbers/booleans numerically (NaN comparisons are all
  unsatisfied); strings by **Unicode code point** (not UTF-16 code units); arrays
  lexicographically, stepping past `==`-equal elements even when those elements are themselves
  unorderable (`[null, 1] > [null]` is true by length); any other pairing is **unsatisfied**.
- **Membership (`in`/`not in`)**: string RHS: substring test (LHS must be a string, else
  unsatisfied); array RHS: membership under `==` above; object RHS: key test (LHS must be a
  string); any other RHS is unsatisfied.
- **The totality rule**: a comparison that cannot be performed (missing field, type mismatch,
  incomparable pair) is **unsatisfied**, never an error; *except `not in`*, whose failed test
  is **satisfied** ("unknown → falsy", consistently).
- `and`/`or` evaluate **all** operands (no observable short-circuit; evaluation is pure) and
  return a boolean.
- **The portable numeric domain.** The reference compares integers exactly at any size; kernels that
  hold numbers as IEEE doubles (the JavaScript, Rust and Go kernels) compare them exactly only within
  plus or minus 2^53 minus 1, and a JSON reader may round a larger integer before any comparison
  happens. The conformance vectors therefore stop at that edge, and the decision boundary refuses an
  integer beyond it (the Facet acceptance rules, §4.5). NaN and the infinities have no JSON spelling,
  so their semantics above are pinned by each implementation's own tests rather than by the
  language neutral vectors.

### 4.3 The match-action fragment (Level M) · the synthesizable core

A predicate is in the **match action fragment** iff it is a boolean combination (`and`/`or`/
`not`) of atoms, where every atom is one of:

- `field OP constant` with `OP ∈ {==, !=, <, <=, >, >=}`, `field` a name, and `constant` an
  **integer** (positive or negative; a leading `-`/`+` on an integer literal folds to a signed
  constant), boolean, or string literal (string constants with `==`/`!=` only). **Float literals are
  excluded**: a `field OP <float>` condition is outside the fragment, and a sign on anything other
  than an integer literal (a float, or a field name as in `-x`) does **not** fold and stays outside
  the language. A decimal literal compared with a `fixed` field is not a float; the parser lowers it
  to an integer before classification (§4.5);
- `field in <list of scalar literals>` or its `not in` form;
- a bare `field` (truthiness of a scalar).

**Integer range.** The fragment's integers are those every kernel compares exactly, plus or minus
2^53 minus 1, the range field definitions default to (§4.5). A table target stores each constant
and register as a signed 32 bit integer, so its compiler refuses a constant outside that range
(`int-out-of-i32`) as a target limit, as the eBPF evaluator refuses a program deeper than its stack.
That is the one place the classifier and a table compiler may disagree, and the conformance drift
guard pins that it is the only one.

Fields are worker-emitted scalars plus the engine counters `visits` and `error_count`.
**Excluded** from the fragment: substring `in`, string *ordering*, field-vs-field comparisons,
membership in non-literal (runtime) collections, nested containers.

**Chained comparisons** (`a < b < c`) are **normalized** into the fragment, not excluded: tooling
desugars them to `a < b and b < c` before classifying or compiling, and MUST do so consistently
(the classifier `verify --level-m` and any table compiler share one desugaring, so they cannot
disagree). The desugaring is exact under §4.1 to §4.2; operands are pure and every pairwise
comparison is total, so `and` over the conjuncts evaluates identically to the chain. A chained
comparison is therefore in the fragment iff each desugared conjunct is: `1 < x < 5` is in fragment
(both conjuncts are `field OP integer`); `1 < a < b` is not (the `a < b` conjunct is field-vs-field).

The fragment exists because it is exactly a **match action table**: each atom is a
`(field-selector, operator, constant)` row; a node's ordered deterministic edges are a priority
encoder; `visits`/`error_count` are registers. A flow whose reachable deterministic edges are
all Level M compiles to table-driven targets; XDP/eBPF programs, P4 pipelines, FPGA
block-RAM images interpreted by a fixed circuit; without reinterpreting prose. Implementations
and linters SHOULD be able to report fragment membership per edge.

### 4.4 Failure containment

Predicate evaluation must never raise an arbitrary error out of the engine: an invalid predicate
is a defined rejection (and a non-matching edge at run time); an impossible comparison follows
the totality rule. Static validation (`check`) and evaluation accept **the same language**.

### 4.5 Field definitions and the canonical reading

A flow MAY define the fields it routes on in its front matter, one `field.<name>: <definition>` line
per field. A definition gives the field's kind and, for numbers, what the integer the policy compares
means. Because definitions are part of the policy text, they are bound into whatever hash or
signature covers it, so two endpoints holding the same signed policy cannot disagree about scale, unit,
rounding, range or absence.

```markdown
---
name: triage
field.error_rate: fixed scale=10000 unit=ratio rounding=floor min=0 max=10000
field.rule_level: int min=0 max=15
field.armed: bool
field.label: category absent=allowed
---

## triage
-> contain: when error_rate >= 0.85 and rule_level >= 12
-> unlabeled: when label == None
-> ignore: when not armed
-> watch: else
```

**Binding.** A signed pack built from a defined flow carries the definitions, in one canonical
spelling, as its manifest's field dictionary, together with the hash of the authored flow text, so the
signature covers both the interpretation and the image's canonical integers. An envelope compares the
dictionary entry for entry, so a receiver that declares another scale, unit, rounding, range or absence
rule refuses the pack.

**Grammar.** A definition is a kind word followed by `option=value` pairs separated by spaces, in any
order. Each option may appear once. An unknown kind, an unknown option, an option the kind does not
take, a repeated option, or a value that does not parse makes the whole flow invalid.

| Kind | Canonical value | Options |
|---|---|---|
| `int` | an integer | `min`, `max`, `absent` |
| `fixed` | an integer counting units of `1/scale` | `scale` and `rounding` (both required), `unit`, `min`, `max`, `absent` |
| `bool` | `true` or `false` | `absent` |
| `category` | a string | `absent` |

- `scale` is an integer from 1 to 10^9. A `fixed` field with `scale=10000` carries 0.892 as 8920.
- `rounding` is `floor`, `ceiling` or `exact`. It says how a source value between two grid points
  becomes canonical, and `exact` refuses such a value instead.
- `unit` is a free token naming what the value measures. It changes no rule, and it is bound with the
  rest of the definition.
- `min` and `max` are integers in canonical units with `min <= max`. They default to the exactly
  representable range, plus or minus 2^53 minus 1, and may not exceed it.
- `absent` is `refused` (the default) or `allowed`.
- `visits` and `error_count` are supplied by the engine and are never defined.

**Decimal thresholds and lowering.** On a `fixed` field every numeric literal the flow compares with
it is an exact decimal in the field's unit: `error_rate >= 0.85` means 0.85, and `error_rate >= 1`
means 1.0, not one unit of `1/scale`. Every kernel lowers such literals when it parses the flow,
replacing each with its canonical integer (`error_rate >= 8500`), so evaluation only ever compares
integers. A literal that is not a whole number of units of `1/scale`, or that lowers outside
`[min, max]`, makes the flow invalid. The literal is read from its source text as an exact decimal,
never through a binary double. Float literals stay outside Level M on every other field, so this adds
no floating point semantics to the fragment. A kernel that does not implement this section MUST refuse
any flow that defines its fields, since running one unlowered could compare 8500 with 0.85 and would
skip the rules below. The JavaScript and Go kernels refuse; the Python reference and the Rust kernel
implement it, and table targets receive only lowered integers from the compiler.

**Policy rules.** A flow that defines any field is invalid, and no run, codebook, table or pack is
built from it, unless all of the following hold after lowering.

1. Every deterministic condition is in Level M (§4.3).
2. Every field a deterministic condition reads is defined, except `visits` and `error_count`. A flow is
   either fully defined or defines nothing; there is no partly defined policy.
3. Every atom on a defined field agrees with its kind. An `int` or `fixed` field is compared only with
   integer constants inside its range, a `bool` field only by truthiness or `==` and `!=` with `True`
   or `False`, and a `category` field only by truthiness or with string constants through `==`, `!=`,
   `in` and `not in`.
4. On a `fixed` field the rounding mode decides which atoms are allowed, because only those survive the
   conversion from the source value (the lemma below). With `floor`, only `>=` and `<`. With `ceiling`,
   only `>` and `<=`. With `exact`, every integer atom, including `==`, `!=`, membership and
   truthiness. Orientation does not matter, since `0.5 <= error_rate` is `error_rate >= 0.5`, and
   negation needs no rule of its own because each pair is closed under `not`.
5. `None` appears only as the constant of `==` or `!=`, never in a list, and only on a field whose
   definition allows absence.
6. A field whose definition allows absence is tested with `== None` or `!= None` by at least one edge,
   so the flow states what absence means instead of observing it by accident.

A flow that defines no fields keeps the behavior of the earlier spec: kinds are inferred from the
constants and readings are accepted by the codec's acceptance rules. That path does not carry the
canonical guarantee.

**The canonical reading.** A reading of a defined flow is canonical when every defined field the flow
routes on holds a canonical value of its kind within its range, or is absent and allows absence.
Missing and `None` are one value, **absent**, because the engine reads both as null (§4.2). Absent is
never zero, false, the empty string or any other value. Integers compare by value, so an integral
number written `3.0` is the canonical value 3. A boolean is never a canonical integer, a number is
never a canonical boolean, and a string that spells a number is never a canonical number. The decision
boundary refuses a value that is not canonical, naming the field and the reason, and converts nothing.

**The shared conversion.** Turning a source value into a canonical value is done once, by
`prismpath.kernel.field_definitions.canonical_value`, driven by the signed definition, so no adapter
carries numeric semantics of its own. A source value may be an integer, an exact decimal, or decimal
text such as the original token of a JSON number. For a `fixed` field, with `v = x * scale` in exact
arithmetic, `floor` gives the greatest integer at most `v`, `ceiling` the least integer at least `v`,
and `exact` gives `v` when it is an integer and refuses it as off the grid otherwise. An integral
binary double is the integer it holds and is accepted. A double with a fractional part is refused on a
`fixed` field, because the decimal it was printed from is lost (`0.29 * 100` is 28.999999999999996 in
IEEE double), so a source that publishes doubles must name its serialized decimal text as the
authoritative value. A result outside `[min, max]` is refused. Decimal text has at most 28
significant digits and an exponent of at most 30 in magnitude, so every implementation can compute
exactly with 128 bit integers. The frozen vectors in `prismpath/portable/conformance/field_definitions.json`
pin the conversion, the lowering, the policy rules and the canonical boundary for every implementation.

**The conversion lemma (statement).** For an integer `scale > 0`, an integer threshold `k`, and any
rational `x`:

- `floor(scale * x) >= k` if and only if `x >= k / scale`, and `floor(scale * x) < k` if and only if
  `x < k / scale`;
- `ceiling(scale * x) > k` if and only if `x > k / scale`, and `ceiling(scale * x) <= k` if and only if
  `x <= k / scale`;
- when `scale * x` is an integer, every comparison of it with `k` agrees with the same comparison of
  `x` with `k / scale`.

So a policy that obeys rule 4 decides on the canonical value exactly as it would decide on the source
value against its authored thresholds, and a boolean combination of such atoms does too. The lemma is
proven in Lean (`formal/FQ/Conversion.lean`, `convert_preserves` and `fixed_policy_preserved`), and
the decoded reading of a canonical reading, absence included, routing as the original is proven there
too (`formal/FQ/Absence.lean`).

## 5. The engine contract

### 5.1 Workers and outcomes

A worker is `agent(node_name, instruction, state) → outcome`, where `outcome` is a string or an
object. An object's `text` property (stringified with Python `str()` conventions: `True`,
`None`, `[1, 2]`) is the semantic-routing text; its other properties are the fields predicates
read. A bare string (or non-object) becomes both, via the same stringification. `state` is a
mutable dict owned by the run: the engine seeds `transcript` (list of `{node, outcome}`),
`visits`, `_outcomes` (latest fields per node), and `_errors`; workers may keep private keys.

**Reserved outcome fields:** `text`, `needs_human`, `reason` (§5.5), `wait`, `timeout_s`,
`spawn` (§5.4).

### 5.2 Run results and stop reasons

A run returns `{path, steps, stopped, state, pending}`. `stopped` is one of:

`terminal` · `stuck` · `max_steps` · `needs_human` · `waiting` · `contract_violation`
(the last only when the optional type-gate is enabled). `pending` carries the evidence packet
for suspended runs (node, reason/awaiting, candidate edges, scores where applicable).

### 5.3 The error tier

If the worker raises, the engine builds the error context `{error: true, error_type,
error_message, error_count, visits}`; `error_count` counts raises of *this node* in *this run*
;  and takes the **first** error edge (document order) whose optional `when` clause is satisfied.
A guard whose expression cannot be evaluated (a `PredicateError`) does not match, as in the deterministic tier, and the engine records it in the run state under `_guard_errors`. No matching error edge ⇒ the exception propagates. `error_type` is the implementation-language
exception name and is therefore **not portable**; portable flows route on `error_count` or
`error_message` content.

### 5.4 Suspension: events, timers, fan-out

A worker returning truthy `wait`; or any non-null `spawn` (spawn **implies** wait); suspends
the run as `waiting`; `pending` records the node's awaited event names, `timeout_s`, and the
spawn spec verbatim. Resume delivers a named event and re-enters at the matching `on event`
edge's target (`__timeout__` for `on timeout`). Fan-out/composition semantics (the `@spawn`
annotation, join policies, deterministic child identity) are defined by the reference
implementation's `composer` contract; the engine's normative duty is only the pure passthrough
described here.

### 5.5 Human handoff

A worker returning truthy `needs_human` suspends the run as `needs_human` before routing, with
`reason` (or the outcome text) and the node's candidate edges in `pending`. Resume applies a
human-chosen edge target directly, bypassing routing.

## 6. Annotations (extension slots)

The kernel parses annotations; specific names are contracts of the toolchain: `@checkpoint(unit=…,
proof=…, gate=…)` (per-unit ledger proofs), `@emits(field[, field=type…])` (declared outputs;
provenance and type cross checks), `@field_only()` (routing may consume only declared structured
fields; the security boundary), `@spawn(child=…, over=…, item_id=…, join=…, gate=…)` +
`@expect(fields)` (fan-out/composition structure; the annotation is authoritative over any
runtime spec), `@state_bound(transcript=N)` (flow-scoped sliding-window bound on persisted run
state (transcript and re-seeded history) with deterministic drop accounting; routing state, the
per node counters, is never windowed), `@worker(plugin.name)` (binds the node to a named plugin
worker; the tool binding lives in the document, tooling verifies it resolves against the installed
registry, and dispatched outcomes carry `_worker` provenance; plugins extend the HARNESS only;
routing, predicates, and engine purity are not extensible). Unknown annotations are inert data.

## 7. Portability levels

Computed over **reachable** edges, recursively through `@spawn` children (a tree's level is its
worst member's):

- **P0**: every reachable edge is deterministic/error/event. No ML runtime: the flow runs on
  any conforming kernel; three independent portable kernels (JavaScript, Rust, Go) pass the
  vectors today. A P0 engine must **refuse** flows outside P0 rather than guess.
- **P1**: reachable semantic edges exist and are all pinned in the flow's routing lockfile
  (committed condition vectors + embedder identity `(model, provider, precision)` + fingerprint).
  Runtime needs only an outcome-side embedder.
- **P2**: semantic edges not fully pinned. Full engine required.

Within P0, **Level M** (§4.3) marks the flows whose deterministic edges are entirely in the
match action fragment; the compile-to-hardware subset.

## 8. Conformance

An implementation of spec version 1:

1. MUST pass `prismpath/portable/conformance/predicates.json`; every `(cond, ctx)` case evaluating to the
   recorded `true`/`false`, or rejecting as invalid where the record says `"ERROR"`;
2. MUST pass `prismpath/portable/conformance/flows.json`; every scripted run reproducing the recorded
   `path`, `stopped`, `pending_node`, and `spawn`;
3. MUST implement §1 to §5 as written; MAY omit semantic routing entirely iff it refuses non-P0
   flows (a *P0 kernel*).

The vectors are regenerated only from the reference implementation, deterministically; a spec
version bump accompanies any regeneration that changes an existing case. New cases may be added
within a version.

---

*This spec follows the reference implementation in this repository. Where prose and vectors
disagree, the vectors govern and the prose has a bug; file it.*
