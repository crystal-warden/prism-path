# The PrismPath format — specification

**Spec version 1 (draft).** This document is the normative definition of the PrismPath flow format:
the document grammar, the four edge tiers, the predicate language, the engine contract, and the
portability levels. The **conformance vectors** (`prismpath/portable/conformance/`) are part of this spec:
an implementation conforms to spec version 1 iff it passes every committed vector bit-for-bit.
The Python kernel in this repository is the **reference implementation**; the vectors are
generated from it deterministically (`prismpath/portable/gen_conformance.py`), so the `git diff` of the
vector files is the authoritative record of any semantic change.

The design principle behind every rule here: **the flow is data, not code.** A flow is an inert,
inspectable Markdown document. Everything the ecosystem does — lint, test, lock, calibrate,
prove, port, compile — is possible because the control flow lives in the document, not in a
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

- **Front matter** — an optional leading `---\n … \n---\n` block of `key: value` lines. `name`
  defaults to `"flow"` **only when absent** (an empty value stays empty); `start` falls back to
  the first node when absent *or empty*.
- **Node** — a line matching `^\s*##\s+(.+?)\s*$`. The node name is the heading, trimmed,
  lowercased, with spaces replaced by underscores (`Write Code` → `write_code`). A later heading
  with the same normalized name replaces the earlier node.
- **Edge** — a line matching `^\s*-?\s*->\s*([A-Za-z0-9_\-]+)\s*:\s*(.+?)\s*$` inside a node:
  `(target, condition)`. Edge order is significant (see §3).
- **Annotation** — a line matching `^\s*@(\w+)\s*\((.*)\)\s*$` inside a node (`\w` is Unicode).
  Arguments are comma-separated `key=value` pairs and/or bare tokens (mapped to null). Repeated
  annotations of the same name merge (later keys win); they never overwrite wholesale.
- **Instruction** — every other line inside a node, joined and trimmed. It is the prose handed to
  the worker; the engine never interprets it.
- **Terminal node** — a node with zero edges. Reaching one ends the run.
- **Line boundaries** are Python `str.splitlines()` boundaries (`\r\n`, `\r`, `\n`, `\v`, `\f`,
  U+001C–U+001E, U+0085, U+2028, U+2029) — implementations must not split on `\n` alone.
- **Whitespace trimming** throughout uses the Python `str.strip()` character class (wider than
  JavaScript `trim()`: it includes U+0085 et al.). Condition-tier classification depends on this.

## 2. The four edge tiers

The condition string's **syntactic form** selects its tier. The partition is total and
non-overlapping; classification uses the trimmed, lowercased condition:

| tier | form | routes when |
|---|---|---|
| **deterministic** | starts with `when ` — or is exactly one of `always`, `true`, `else`, `otherwise`, `default`, `_` (always-true) / `false`, `never` (never-true) | the predicate evaluates truthy against the outcome fields (§4) |
| **error** | starts with `on error`, optionally `on error when <expr>` | the worker **raised**; `<expr>` (if any) evaluates truthy against the error context (§5.3) |
| **event** | starts with `on event <name>` or `on timeout` | the suspended run is **resumed** with that event; `on timeout` awaits the reserved event `__timeout__` |
| **semantic** | anything else (natural language) | an embedding/LLM router selects it (§5.2) |

The event *name* preserves the original case of the condition text after `on event`, trimmed.

## 3. Routing semantics

At a non-terminal node, after the worker returns an outcome (§5.1):

1. **Deterministic edges first, in document order — first true wins.** An unsafe or unparseable
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
language. It is exactly the subset of Python expression syntax listed here — nothing else.

### 4.1 Grammar

- **Names** — `[A-Za-z_][A-Za-z0-9_]*`, resolving to outcome fields plus `visits` (and, in error
  context, the fields of §5.3). An unknown name resolves to null. **Python hard keywords are
  rejected as names** (`class`, `import`, `is`, `lambda`, …) — a predicate using one is invalid.
  Soft keywords (`match`, `case`, `type`) are ordinary names. `True`, `False`, `None` are
  constants; lowercase `true`/`false`/`none` are **names** (fields), not constants.
- **Literals** — integers and floats including `0x`/`0o`/`0b` radixes, `_` separators, and
  exponents (complex literals are invalid); strings in single or double quotes with Python's
  escape table (`\n \t \r \0 \a \b \f \v \\ \' \" \xNN \uNNNN`; an unknown escape keeps the
  backslash) and raw-string prefixes `r'…'`/`R"…"` (bytes literals are invalid); list literals
  `[a, b]`; tuple literals `(a, b)` including the empty tuple `()`; `...` (Ellipsis, a truthy
  constant equal to nothing representable in JSON).
- **Operators** — `and`, `or`, `not`; comparisons `== != < <= > >= in not in`, **chained**
  (`1 < x < 5` ≡ `1 < x and x < 5`, evaluated pairwise left-to-right). Parentheses group.
  A **top-level comma** creates a bare tuple (non-empty ⇒ always truthy — legal but a known
  authoring trap; linters should warn).
- **Nothing else.** Calls, attributes, subscripts, arithmetic (including unary minus),
  comprehensions, lambdas, walrus, f-strings, and `is` are invalid. Validity is enforced
  **statically before evaluation**: a predicate containing a disallowed construct is invalid
  even if evaluation could short-circuit around it.
- **Depth** — expressions nested beyond 50 structural levels are invalid. Grouping parentheses
  and precedence do not add depth; each boolean/comparison/`not`/collection nesting level does.

### 4.2 Evaluation semantics

Over JSON-representable values (null, bool, number, string, array, object):

- **Truthiness** (used by bare names, `and`/`or`/`not`, and the final result): null, `false`,
  `0`, `-0.0`, `""`, `[]`, `{}` are falsy; everything else (including NaN) is truthy.
- **Equality (`==`/`!=`)** — booleans compare **numerically** with numbers (`true == 1`,
  `false == 0`); numbers compare by value (`1 == 1.0`); strings exactly; arrays and objects
  structurally; null equals only null; cross-type otherwise is unequal (never an error).
- **Ordering (`< <= > >=`)** — numbers/booleans numerically (NaN comparisons are all
  unsatisfied); strings by **Unicode code point** (not UTF-16 code units); arrays
  lexicographically, stepping past `==`-equal elements even when those elements are themselves
  unorderable (`[null, 1] > [null]` is true by length); any other pairing is **unsatisfied**.
- **Membership (`in`/`not in`)** — string RHS: substring test (LHS must be a string, else
  unsatisfied); array RHS: membership under `==` above; object RHS: key test (LHS must be a
  string); any other RHS is unsatisfied.
- **The totality rule** — a comparison that cannot be performed (missing field, type mismatch,
  incomparable pair) is **unsatisfied**, never an error — *except `not in`*, whose failed test
  is **satisfied** ("unknown → falsy", consistently).
- `and`/`or` evaluate **all** operands (no observable short-circuit; evaluation is pure) and
  return a boolean.

### 4.3 The match-action fragment (Level M) — the synthesizable core

A predicate is in the **match-action fragment** iff it is a boolean combination (`and`/`or`/
`not`) of atoms, where every atom is one of:

- `field OP constant` with `OP ∈ {==, !=, <, <=, >, >=}`, `field` a name, and `constant` an
  **integer** (positive or negative — a leading `-`/`+` on an integer literal folds to a signed
  `i32` constant; the table stores `val` as signed `i32`), boolean, or string literal (string
  constants with `==`/`!=` only). The value domain of the fragment is `i32`; **float literals are
  excluded** — a `field OP <float>` condition is outside the fragment (it has no representation on
  the i32 match-action table), and a sign on anything other than an integer literal (a float, or a
  field name as in `-x`) does **not** fold and stays outside the language;
- `field in <list of scalar literals>` or its `not in` form;
- a bare `field` (truthiness of a scalar).

Fields are worker-emitted scalars plus the engine counters `visits` and `error_count`.
**Excluded** from the fragment: substring `in`, string *ordering*, field-vs-field comparisons,
membership in non-literal (runtime) collections, nested containers.

**Chained comparisons** (`a < b < c`) are **normalized** into the fragment, not excluded: tooling
desugars them to `a < b and b < c` before classifying or compiling, and MUST do so consistently
(the classifier `verify --level-m` and any table compiler share one desugaring, so they cannot
disagree). The desugaring is exact under §4.1–§4.2 — operands are pure and every pairwise
comparison is total, so `and` over the conjuncts evaluates identically to the chain. A chained
comparison is therefore in the fragment iff each desugared conjunct is: `1 < x < 5` is in-fragment
(both conjuncts are `field OP integer`); `1 < a < b` is not (the `a < b` conjunct is field-vs-field).

The fragment exists because it is exactly a **match-action table**: each atom is a
`(field-selector, operator, constant)` row; a node's ordered deterministic edges are a priority
encoder; `visits`/`error_count` are registers. A flow whose reachable deterministic edges are
all Level M compiles to table-driven targets — XDP/eBPF programs, P4 pipelines, FPGA
block-RAM images interpreted by a fixed circuit — without reinterpreting prose. Implementations
and linters SHOULD be able to report fragment membership per edge.

### 4.4 Failure containment

Predicate evaluation must never raise an arbitrary error out of the engine: an invalid predicate
is a defined rejection (and a non-matching edge at run time); an impossible comparison follows
the totality rule. Static validation (`check`) and evaluation accept **the same language**.

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
error_message, error_count, visits}` — `error_count` counts raises of *this node* in *this run*
— and takes the **first** error edge (document order) whose optional `when` clause is satisfied.
No matching error edge ⇒ the exception propagates. `error_type` is the implementation-language
exception name and is therefore **not portable**; portable flows route on `error_count` or
`error_message` content.

### 5.4 Suspension: events, timers, fan-out

A worker returning truthy `wait` — or any non-null `spawn` (spawn **implies** wait) — suspends
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
provenance and type cross-checks), `@field_only()` (routing may consume only declared structured
fields — the security boundary), `@spawn(child=…, over=…, item_id=…, join=…, gate=…)` +
`@expect(fields)` (fan-out/composition structure; the annotation is authoritative over any
runtime spec), `@state_bound(transcript=N)` (flow-scoped sliding-window bound on persisted run
state — transcript and re-seeded history — with deterministic drop accounting; routing state, the
per-node counters, is never windowed), `@worker(plugin.name)` (binds the node to a named plugin
worker — the tool binding lives in the document, tooling verifies it resolves against the installed
registry, and dispatched outcomes carry `_worker` provenance; plugins extend the HARNESS only —
routing, predicates, and engine purity are not extensible). Unknown annotations are inert data.

## 7. Portability levels

Computed over **reachable** edges, recursively through `@spawn` children (a tree's level is its
worst member's):

- **P0** — every reachable edge is deterministic/error/event. No ML runtime: the flow runs on
  any conforming kernel — three independent portable kernels (JavaScript, Rust, Go) pass the
  vectors today. A P0 engine must **refuse** flows outside P0 rather than guess.
- **P1** — reachable semantic edges exist and are all pinned in the flow's routing lockfile
  (committed condition vectors + embedder identity `(model, provider, precision)` + fingerprint).
  Runtime needs only an outcome-side embedder.
- **P2** — semantic edges not fully pinned. Full engine required.

Within P0, **Level M** (§4.3) marks the flows whose deterministic edges are entirely in the
match-action fragment — the compile-to-hardware subset.

## 8. Conformance

An implementation of spec version 1:

1. MUST pass `prismpath/portable/conformance/predicates.json` — every `(cond, ctx)` case evaluating to the
   recorded `true`/`false`, or rejecting as invalid where the record says `"ERROR"`;
2. MUST pass `prismpath/portable/conformance/flows.json` — every scripted run reproducing the recorded
   `path`, `stopped`, `pending_node`, and `spawn`;
3. MUST implement §1–§5 as written; MAY omit semantic routing entirely iff it refuses non-P0
   flows (a *P0 kernel*).

The vectors are regenerated only from the reference implementation, deterministically; a spec
version bump accompanies any regeneration that changes an existing case. New cases may be added
within a version.

---

*This spec follows the reference implementation in this repository. Where prose and vectors
disagree, the vectors govern and the prose has a bug — file it.*
