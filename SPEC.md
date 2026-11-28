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
name: bugfix
start: triage
---

## triage
Read the bug report and decide what to do.
@emits(action)
-> implement: when action == "fix"
-> close: it is a duplicate or invalid

## implement
Fix the bug.
-> done: always

## close
Close the report.

## done
Summarize and finish.
```

Here `## triage` is a node, the prose under it is its instruction, `@emits(action)` is an annotation and each
`->` line is an edge. `name` and `start` are both optional (`name` defaults to `"flow"`, `start` to the first
node defined). A node with no edges, like `done`, is terminal. The front matter has no comment syntax: text
after a `#` is part of the value.

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
rule refuses the pack. A flow that is not compiled to an image is authorized by a flow manifest instead
(`prismpath authorize sign`, `prismpath/hotswap/flow_authority.py`), which carries the same dictionary in
the same spelling beside the sha256 of the flow text, a monotonic version and the authority key's
identity, under the same Ed25519 key a pack is signed with.

A pack, a table or a flow also travels to the machines that enforce it in a distribution envelope. What is built in each implementation is in the status table of [`docs/design/spec-policy-distribution.md`](docs/design/spec-policy-distribution.md) section 19.1.

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
skip the rules below. The Python reference and the Rust, JavaScript and Go kernels implement it, and
table targets receive only lowered integers from the compiler.

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

**Signed and hashed documents.** Every document an implementation writes that is hashed or signed (an
audit event and its Merkle leaf, a root statement, a pack or flow manifest, an envelope, a crypto
registry, an attestation or OpenTimestamps manifest, a lock, the policy host's intent and active records,
the epoch journal's records) is canon/2 (docs/DICTIONARY.md "canon/2") and names it with
`"encoding": "canon/2"`; its hash is sha256 over its canon/2 bytes and a signature over it covers the
domain `prismpath.canon/2` followed by a zero byte and those bytes, unless its format names a domain of
its own (`prismpath-root-statement/3`). A reader decides by the document's own tag: canon/2 is read by the
strict canon/2 reader, and a document without the member, or with any other tag, is refused: it is never
read, hashed or verified under another encoding. The strict reader accepts a document only as its exact
canonical canon/2 bytes: a file or a JSON Lines line holds those bytes followed by at most one line feed,
the record terminator, and any other spelling (whitespace, members out of key order, a needless escape, a
carriage return) is refused, never respelled, with the registered cause `document:not-canonical` (code
103) where the reader names causes (a pack or flow manifest, an envelope) and as an unreadable line or a
`bad_format` statement where it reports findings. The core's policy image and reading are held to the same
rule with causes of their own, `policy:not-canonical` (101) and `reading:not-canonical` (102). A document a
person wrote is written through the canonicalize path first (`prismpath canonicalize`, which keeps every
other canon/2 rule); no reader calls it. A lock (version 2) holds its margin and its centroid prior
weight as integers of millionths, `delta_micro` and `centroid_prior_weight_micro`. canon/1, the earlier encoding (Python's `json` with sorted keys,
floats as `repr` writes them), is retired: an implementation MUST NOT write it and MUST NOT read, hash or
verify a document under it, and a reader that meets an untagged document refuses it with a named cause (a
log line is skipped and the log does not verify, a statement is `bad_format`, a pack, manifest or registry
is `manifest:bad-format`, a registry `registry:bad-json`, an envelope `envelope:sig-invalid`). A time in a document is an integer count of
microseconds since the Unix epoch.

**Merkle trees.** Every Merkle root an implementation writes or checks (an audit log's root and its
inclusion paths, a root statement, a core run's receipts, an OpenTimestamps anchor batch, the context
ledger, an epoch's blocks) is RFC 6962's (section 2.1), scheme `rfc6962-sha256`: a leaf, a 32 byte hash of
the receipt, event or block, enters the tree as SHA-256(0x00 || leaf); an inner node is
SHA-256(0x01 || left || right); a tree over n ≥ 2 leaves splits at k, the largest power of two below n, the
tree of the first k leaves on the left and of the rest on the right; the root of one leaf is its leaf hash,
and no leaf or node is ever duplicated. An inclusion path is the siblings from the leaf up, each with the
side it sits on, and a leaf in the shorter right part of an unbalanced tree has a shorter path. The tree
before it (no prefixes, the last node of an odd layer paired with itself), under which [a, b, c] and
[a, b, c, c] had one root, is retired, and the formats that carry roots were bumped with it:
`prismpath-root-statement/3`, `prismpath.core-run-root/2`, `prismpath.intent-observation-root/2`, and an
anchor manifest naming `"merkle": "rfc6962-sha256"`. An implementation MUST refuse a statement in a
retired format (`prismpath-root-statement/2` is the finding `old_merkle_scheme`, `prismpath.core-run-root/1`
is refused by name) and MUST NOT check a retired root under the new tree or mix the two. The vectors are
RFC 6962's own known answers and `prismpath/portable/conformance/receipts.json`.

An implementation that keeps a root as leaves arrive MAY hold, instead of the leaves, the peaks: the roots
of the perfect subtrees the leaves so far fall into, one per set bit of the leaf count, the peak for bit h
over 2^h leaves. A leaf's hash is added as a subtree of height 0 and merged with the peak of each set low
bit in turn, the peak as the left child, until it lands at the first clear bit (binary counter carry); the
root is the shortest peak, folded upward with each taller peak hashed as the left child of what is folded
so far. That is the same root as the tree above for every nonempty list of leaves and every hash
(`formal/Core/Merkle.lean`, `acc_root_eq_mth`), and no root for no leaves. Its state is fixed: fewer than
2^64 leaves leave at most 64 peaks (`accPeaks_length_le`), so 64 peaks of 32 bytes (2 KiB) and a 64-bit
count, with no heap and no recursion. The streaming forms are `root_statement.MerkleAccumulator`,
`prismpath_rs::merkle::Accumulator` and `ppt_merkle_acc` in `prismpath-ebpf/merkle.h`; each gives, after
every leaf, the root over every prefix in `prismpath/portable/conformance/merkle_stream.json`, which the
Python batch tree wrote.

A float is refused in content an implementation hashes but did not write (a connector's data, a decision
outcome, a composer item, a proof, an operator's control data): the caller supplies an integer of a stated
unit or a decimal string, and the implementation writes no spelling of a float of its own. JSON that is not
hashed and not signed (a durable run checkpoint, the connector's JSONL sink lines, the flow authority's
version floor file) stays plain JSON and is never an input to a hash or a signature.


## 9. Rules sources

A rules source is the readable form of a `prismpath.core/1` policy image (docs/design/spec-verified-core.md
section 2). It is a dialect of the flow format of §1 with one decision node, and only
`prismpath/kernel/policy_source.py` (`prismpath policy compile`) reads it. A rules source file is named
`<name>.rules.md`, and its image `<name>.core.json`.

```markdown
---
name: my_rules
field.tool: category
field.path_scope: category
field.kill_by_pattern: bool
---
## core_decision
Rules are read from the top. The first one that holds decides.
-> refuse agent:kill-by-pattern: when kill_by_pattern
-> allow: when tool == "read_file" and path_scope == "workspace"
```

Normatively, as follows.

- **Front matter** is required. The file starts with a line `---` and the block ends at the next line
  `---`. Each non blank line is `key: value`. The keys are `name`, `start`, `description` and
  `field.<name>`, and no other key is accepted. A key written twice is an error. `field.<name>` is a field
  definition as §4.5 writes it. A `category` definition may also list its values as one word after the kind,
  joined by `|` (`category none|protected|unknown`, each value of `[A-Za-z0-9_.:-]`, none twice). A rule that
  compares the field with a string the list does not hold is an error. The list is a check of the compiler
  only. The image carries the definition without it, so a source with a list and the same source without
  it compile to the same bytes. `name`, `description` and `start` are for the reader and are not part of
  the image.
- **Sections** are lines matching `^\s*##\s+(.+?)\s*$`, normalized as §1 normalizes a node name. The start
  section is `start` when given, else the first section. It is `core_decision` in every shipped source. A
  section name may appear once.
- **A rule** is a line matching `^\s*-?\s*->(.*)$` under the start section. A rule anywhere else is an
  error. The text after the arrow takes one of two forms.
  - `refuse <cause>: <condition>` or `escalate <cause>: <condition>`, matching
    `^\s*(refuse|escalate)\s+(\S+?):(?:\s+(.*?))?\s*$`. The cause is a registered name of
    `prismpath/kernel/causes.py`, and the image's target is `refuse_<code>` or `escalate_<code>`. A name
    that is not registered is an error. A cause outside the routing class compiles with a warning, since a
    policy decides calls and the other classes are the refusals of checks outside it.
    `prismpath policy causes` lists the routing causes.
  - `<target>: <condition>`, matching `^\s*([A-Za-z0-9_\-]+)\s*:\s*(.*?)\s*$`. The target `allow` allows.
    A target written as a code (`refuse_105`) or a bare `refuse` or `escalate` is an error. Any other
    target is a route, which compiles with a warning because the agent and the gateway refuse an image that
    names one.
- **A condition** is `always`, `never`, or `when` followed by one expression of the Level M fragment (§4.3)
  over the declared fields. That is a field alone, a comparison of a field with a constant, `in` or `not in` a list
  of constants, joined by `and`, `or`, `not` and parentheses. Constants are numbers, strings, `True`,
  `False` and `None`. A chained comparison is the conjunction of its pairs.
- **Order** is significant. The image's rules are the source's rules in order, and the first rule whose
  condition holds decides. A reading no rule holds for is refused (`route:no-matching-edge`).
- **Notes.** Every other line is a note for the reader and is not part of the image. A note that looks
  like a rule (an arrow spelled `>`, `=>`, `- >` or `→` before allow, refuse or escalate, or a target and
  condition with no arrow) compiles with a warning. An annotation (`@name(...)`) is an error.
- **Line ends.** A file with `\r\n` line ends reads as one with `\n`.

**The image.** Compiling writes the canonical canon/2 bytes of
`{"format": "prismpath.core/1", "fields": {...}, "rules": [{"target": ..., "when": ...}, ...]}` and
checks them with the port of the Lean oracle's `loadPolicy` (`core_policy`). A source the oracle refuses
does not compile, and the error names the line of the rule or the field definition it is about. Two
compiles of one source give the same bytes. Whitespace, notes and the order of the field definitions do
not change the image. The order of the rules and of the constants in a list do. `prismpath policy render`
writes the source of an image, and compiling it gives the same bytes again. Rendering keeps no name,
description or note, so the `.rules.md` file is the source of record and `prismpath policy check SOURCE
IMAGE` checks that an image is still what its source compiles to.

**The flow tools.** A rules source is not a flow. Its rule targets have a space the edge grammar of §1
does not allow, so a flow parser would read every refusal as prose. The reference parser refuses a file
named `*.rules.md` and any document with a line matching `^\s*-?\s*->\s*(refuse|escalate)\s+\S+?:(\s|$)`,
naming `prismpath policy compile`. The canonical rendering of an image (`core_render.render`, targets
written `refuse_<code>`) is a flow and parses as one.

**Targets.** `prismpath policy compile --target agent` also runs the governed agent's checks on the image
(`prismpath/agent/target.py`): every value a rule names is inside its field's reading domain, every
declared field is one the agent's classifier reads with the kind it gives it, the required fields are
declared, every change to a control file and every connection but the model's API is refused, and a
sandbox profile can be built. docs/guides/writing-agent-rules.md lists the fields and their values.

## 10. Policy manifests

A policy manifest is the one signed file that says what a release of a policy is. It is named
`<name>.policy.md`, there is one per stream, and `prismpath/kernel/policy_manifest.py` reads it. The rules
reach no image unless the manifest is signed. It is a flow of §1 that `prismpath authorize sign` signs like any
other, so the signature is a `prismpath-flow-manifest/1` beside it (`<name>.policy.md.manifest.json`).

```markdown
---
name: agent-default
policy.id: agent-default-1
policy.stream: agent-default
policy.seq: 1
policy.targets: agent
policy.rules: agent_default.rules.md
policy.rules_sha256: <sha256 of the rules source file>
policy.image: agent_default.core.json
policy.image_sha256: <sha256 of the image's canonical bytes>
policy.widens: yes
policy.valid_days: 90
---
## manifest
Notes for the reader.
-> refuse_135: always
```

Normatively, as follows.

- **Text.** The file is read as the flow authority hashes it: `\r\n` is a line end, and every other control
  character, a carriage return alone, a line or paragraph separator and a byte order mark included, is an error. So
  the text parsed is the text signed. `prismpath policy manifest check` also requires the sha256 of the text
  it parsed to be the `flow_sha256` of the verified signature.
- **Front matter** is required, between two lines that are exactly `---` (nothing before or after), one
  `key: value` per line, each starting in the first column. Every key starts with `policy.`. The keys `name`,
  `description` (printable text up to 200 characters) and `start` (a name) are also accepted, since they belong to the
  flow. `name` is required and is `policy.stream`: the signed flow takes its name from it, and the flow authority
  keeps its version floor per flow name, so the floor is one per stream. Tying it to `policy.id`, which names one
  release, would give every release a floor of its own, so an older signed manifest of the stream would never be
  refused. Any other key is an error that names its line.
  A `policy.` key or a `---` line below the closing fence is an error, since it would read as a note. A key written twice is an
  error. A refusal names the line of the key, and the whole file when a required key is missing. Every problem is
  reported, not only the first.
- **Values.** A word is `[A-Za-z0-9_.:@/-]`, a name `[A-Za-z0-9_.-]`, a stream `[a-z0-9._/-]{1,64}` and a target
  `[a-z][a-z0-9_-]*`. A sha256 is 64 lowercase hex digits. A number is a whole decimal number with no sign, no
  leading zero and the bounds below. A time is Unix seconds or `YYYY-MM-DDTHH:MM:SSZ`, read as Unix seconds. A path
  is relative to the manifest's directory, with no `..`, `.` or empty part, no drive and no backslash. A list is its
  items joined by `|`, with no item twice, and an empty value is an empty list. `yes` and `no` are booleans.
- **Keys.** Required: `policy.id` (name), `policy.stream` (stream), `policy.seq` (1 to 2^53-1), `policy.targets`
  (list of target, at least one, kept sorted), `policy.rules` and `policy.image` (paths), `policy.rules_sha256` and
  `policy.image_sha256` (sha256), `policy.widens` (yes or no), and exactly one of `policy.expires` (time) and
  `policy.valid_days` (1 to 3650, counted from `policy.not_before` when it is written, else from the `created` time of
  the manifest's signature, as the delegate envelope counts its grant, and never from the time of sealing). Optional:
  `policy.not_before` (time), `policy.replaces` (sha256 of the policy it replaces; `policy.widens: no` needs it, since
  a release that replaces nothing widens), and every other key of the next three items.
- **Side inputs.** A file is a path and its hash, written together or not at all: `policy.egress_hosts`,
  `policy.zones`, `policy.routes`, `policy.identity_bundle`, `policy.identity_map`, `policy.net_dests` and
  `policy.cc_index`, each with `<key>_sha256`. The values are `policy.allowed_remotes` (list of word),
  `policy.max_processes`, `policy.timeout_s`, `policy.shell_many` (each 1 and up), `policy.toolchain_dirs` and
  `policy.ro_mounts` (lists of host path: absolute, `~/` under the home, or `workspace:` under the workspace, no `..`),
  `policy.grant_classes` (list of `[a-z][a-z0-9_]{0,31}`) and `policy.local_model` (word). A key
  that is absent has no value here. The grammar applies no default, a default belongs to the target that reads the
  key. The grammar reads every value key, and the sealing tool refuses each one no target carries yet (below), which in
  this version is all of them, so a manifest to be sealed writes none.
- **Context Cloud.** `policy.cc_protected` (list of names as `agent.zones` holds them: 1 to 512 characters of `[A-Za-z0-9_.:@-]`, no `/`, at most 10,000), `policy.cc_index` with `policy.cc_index_sha256`,
  `policy.cc_freshness_s` (1 and up, the oldest index a reading may use), `policy.cc_required_certainty` (`certain`
  or `likely`) and `policy.cc_engine_agreement` (1 to 64, the engines that must agree, Context Cloud's own answer counting as one). The grammar reads them. What
  a target does with them is its own. The protected set in force is the union of `policy.cc_protected` and the
  `protected` list of the `policy.zones` file: neither wins and neither removes a name from the other. `policy.cc_index`
  pins the sha256 of an index statement (the index's path under the project, the program and package that read it, and
  the schema), not of the SQLite file, which is rebuilt as the code changes and is checked by the per file hashes it
  holds and by `policy.cc_freshness_s`.
- **Information points.** `policy.points` (list of word) names the information points the rules are built with. A rules
  source that declares a field only a point supplies (`tests_pass`, `edit_kind`, `behaviour_preserving`,
  `touches_protected`, `adds_protected_reference`, `cc_certainty`, `cc_engine_agreement`) is a `points` finding unless the point that supplies it is named,
  and `prismpath policy compile --target agent` refuses it, on the line of the field, unless it is given `--point`. A policy
  that allows a reading with `tests_pass` at `not_run` that it refuses at `false` is refused too. `tests_pass` true is never enough
  alone, and the five facts were proven together with `reaches_protected` and `unknown_reason`, so a policy that reads them should also
  require `zone_reach == "none"`. The sealing tool refuses `policy.points` with "no PEP holds this yet": no artifact of a
  release carries the points and no PEP builds its policy with them, so a release sealed from it would be read without
  the points it names.
- **Context Cloud certainty.** The `contextcloud` point supplies two fields besides `zone_reach`. `cc_certainty` is
  `none`, `likely`, `certain` or `unknown`: Context Cloud's strongest answer over the file's functions (`certain` for a
  file that defines protected code). It reads `unknown` on every error, a missing or stale index, an untrusted program
  or index, a bad requirement, and when the answer is incomplete: a function timed out or errored and no function was
  `certain`, which includes a `likely` beside a function that did not answer (that function could have been `certain`).
  `zone_reach` still reads such a `likely` as `likely` does, so the default is unchanged, and only a complete answer is
  cached. `cc_engine_agreement` is `int min=0 max=63`, the number of engines other than Context Cloud that agree with
  the answer, as Context Cloud reports it. It reads 0 on every path today, since `contextcloud reaches --json` names no
  engine beside its own and the point does not read the other engines' answers in the index. A requirement of N
  engines (`policy.cc_engine_agreement`, 1 to 64) is met by Context Cloud and N - 1 others, so 1 means Context Cloud
  alone and 64 needs the field's top value of 63. Rules over these two fields, and over every evidence field, must be
  written as allows (`allow when cc_certainty == "none"`): the compile refuses a policy that decides a field's
  restrictive value, the value it reads when its point cannot answer, more permissively than another value of it
  (refuse < escalate < allow), as `refuse when cc_certainty == "certain"` does, with a finding on the field's line.
  The two requirements can only move a `protected` reading of `zone_reach` to `unknown`, never to `none`
  (`policy.cc_required_certainty` `certain`: a `likely` answer reads `unknown`; `policy.cc_engine_agreement` above 1:
  every `certain` and `likely` answer reads `unknown` until Context Cloud reports that many engines). That narrows
  the decision only for a policy that treats `zone_reach` `unknown` at least as strictly as `protected`; a policy that
  refuses `protected` and escalates `unknown` is loosened by a stricter requirement, so a release that carries a
  requirement must hold that condition (the dominance check applied to `zone_reach`), which the wiring has to enforce.
  The defaults, `likely` and 1, are what the point always read. The point reads the requirements as constructor
  arguments, read only afterwards; no manifest carries them to a running agent yet, and the sealing tool still
  refuses the keys.
- **Domain.** `policy.domain` is reserved, and written it is an error. The domain of a release is the rules
  source's own typed `field.<name>:` lines, which `policy.rules_sha256` already signs, so a second statement of it
  could only repeat them or contradict them. The floor and ceiling per field it was meant to carry bound what a later
  release may widen to, and nothing reads such a bound yet. A signed file carries no syntax whose meaning is not fixed,
  so the key stays reserved until that reader is specified.
- **Body.** The body holds notes and one rule, `-> refuse_135: always` (`dist:bad-format`), under a `##`
  heading. It is written as the canonical rendering writes a target, so the file parses as a flow and the flow parser
  does not refuse it as a rules source. Any other rule line is an error.

**The release check.** `prismpath policy manifest check FILE --pub KEY...` (`policy_manifest.check`) holds when,
in this order, the signature verifies with a trusted authority key (the flow authority, `prismpath authorize
verify`) at a version that is `policy.seq`; `policy.rules` compiles with `prismpath policy compile` to the image byte
for byte, with its final line feed or without; `policy.rules_sha256` is the sha256 of the rules file and
`policy.image_sha256` of the compiled image's bytes without the line feed; every target is one a manifest can be sealed
for and the checks of `prismpath policy compile --target` that its kind registered hold (`target-check`); and every
side input named has the sha256 it says. The signed version and `policy.seq` are one counter, so the version floor's
rule (a version below the one accepted is refused, the same version only with the same text) is the stream's seq rule
as the sealing tool sees it. A signature that does not
hold is the only finding, since nothing the manifest says counts without it. Every file is read from the manifest's
directory, and one that resolves outside it, a link for one, reads as absent. A file is opened without following a
link at its last part, and one over 16 MiB is a finding. With the clock the check also finds a manifest before
`policy.not_before` or past its end (`expired`, `not-yet-valid`). Exit 0 holds, 1 for a finding and 2
for a manifest that does not read. The command seals nothing, and with `--state-dir` it reads the version floor and
never raises it.

**Sealing from a manifest.** `prismpath dist seal --manifest FILE --pub KEY... --key PEM... --out DIR [--held DIR]
--state-dir DIR` runs the release check and seals what it verified (`policy_manifest.verify`, then
`distribution/seal.py`, `seal_manifest`). Nothing is read twice: the check hands on the compiled image, the rules
bytes, each side file's bytes and the signed `created`, `version` and `key_id`, and the tool seals from those. The
image sealed is the compiled image, never the image file's bytes.

- **Targets.** A manifest can be sealed for a target whose kind registered a `derive` (`agent` and `gateway` in this
  version). `host` and `mesh` need a `policy.ppt` and `xdp` a `net.edge`, and the grammar names none of them, so
  `check` finds such a target (`target`). Each target gets its own release: one envelope per artifact its `derive`
  makes, the release id over those artifacts and `targets` that one kind, because a PEP computes the release id over
  the artifacts staged for it (E10, C2). Every release of one manifest carries the same stream, seq, policy hash
  (`policy.image_sha256`), `replaces` and `widens`. `agent` is its `policy.core` and its `egress.hosts`, and
  `agent.zones` when the manifest names zones. `gateway` is its `policy.core` and its `gateway.routes`, and
  `identity.bundle` and `identity.map` when the policy reads `workload` (ID3). A side file is its artifact's body byte
  for byte and is read as that artifact reads it.
- **An absent key.** No `policy.egress_hosts` seals the empty host list, the least a release can reach. No
  `policy.zones` seals no `agent.zones`: the release declares no zone and its release id signs that absence (section 3
  of the distribution spec). That protects nothing, so it is larger than any release that had zones, and the tool
  finds it so (W7) and prints it. A gateway with no `policy.routes` is refused, since it has no route table to fall back
  on. A side file no target reads is refused, and so is every value key no target carries: a signed key no PEP holds
  would read as enforced. In this version no target carries a value key. `policy.max_processes`, `policy.timeout_s`,
  `policy.shell_many`, `policy.toolchain_dirs`, `policy.ro_mounts`, `policy.allowed_remotes`, `policy.local_model`,
  `policy.grant_classes` and every `policy.cc_*` key are refused with "no PEP holds this yet", because no artifact of a
  release holds them and the launcher runs values of its own. They are wired into what a PEP holds in a later version.
- **Times.** `not_before` is `policy.not_before`, else the signing time, and `expires` is the end `policy.expires`
  or `policy.valid_days` gives. So the same manifest and the same held state seal to the same envelopes. (With
  `widens: yes` and no `policy.replaces`, `replaces` comes from the held state, so another held state gives another
  `replaces`.)
- **Widening (W7).** The tool decides `widens` itself. It compares each target's release, whole, with the one it
  replaces in the controller state `--held`, as a PEP that decides compares it (W1). The held release counts only when
  it is whole: every body of it is stored and the release id computed over them is its signed `release`, else the tool
  holds no release to compare with. Only a target kind that decides (W1) is sealed from a manifest, so the tool's
  comparison is never the only one. `widens: no` is refused with
  `dist:widening-unsigned` when the tool finds the release larger or holds no release to compare it with, and is
  sealed with `widens` false only when it finds it not larger. `widens: yes` seals a widening, and the tool never
  signs its widening statement: the owner signs that with `dist widen`, as a separate act (W4, W5). `replaces` is
  `policy.replaces`, else the policy hash of the latest release `--held` holds below this seq for the target, else
  none. A manifest whose targets would replace different policies is refused, since it states one `replaces`. The tool
  prints, per target, the artifacts it found larger than the held release and the optional artifacts the release does
  not carry (`agent.zones` absent, say), so the owner sees them before signing a widening statement.
- **Meta.** Each envelope's `meta` names the manifest and the rules: `manifest_sha256`, the `flow_sha256` the
  manifest's signature covers, on every artifact; `source_sha256`, the sha256 of the rules source, on the
  `policy.core`; and `rules_sha256`, the same hash, on each side artifact, the rules of the release it is sealed with.
  An auditor goes from a receipt's policy hash to the `policy.core` envelope, to the manifest by its hash and to the
  rules source by its hash. No PEP check reads them.
- **The check before signing.** Each artifact is held to its own check (V11) for its target before anything is
  written, and nothing is written unless every envelope is sealed. The envelopes go to `--out` as
  `<target>.<artifact>.sealed` with `<target>.<artifact>.body` beside each, the names a controller's inbox takes.
  `--out` is a new directory or an empty one: one that already holds a `.sealed` or a `.body` file is refused, so the
  envelopes of two releases never sit together, and an `--out` that is a file is refused (exit 2).
- **The floor.** `--state-dir` is required with `--manifest`. A manifest signed at a version below the one sealed
  before, or at the same version with another text, is refused (`flow:version-replay`), and the floor is raised to the
  manifest's version once the envelopes are written. So an older signed manifest of the stream is never sealed again.
  The sealing tool raises it, and the release check only reads it.
- **The flag form.** `dist seal --artifact A --body FILE --stream S --seq N --target T ...` still seals one envelope,
  and prints a note that it is deprecated in favour of `--manifest`. With `--manifest` no release flag is given:
  `--artifact`, `--body`, `--stream`, `--seq`, `--target`, `--not-before`, `--expires`, `--release`, `--policy`,
  `--replaces`, `--widens`, `--yes`, `--meta`, `--qualification` and `--ceiling` each exit 2.

---

*This spec follows the reference implementation in this repository. Where prose and vectors
disagree, the vectors govern and the prose has a bug; file it.*
