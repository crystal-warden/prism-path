# PPT v1 · the PrismPath Level M table image ("the ISA")

*The binary format a fixed interpreter circuit executes. One interpreter, any conformant flow
as data.*

## Declared subset (stated plainly, never claimed beyond)

The target certifies against exactly the conformance vectors inside this subset:

- **Predicates**: conditions accepted by the evaluator's static gate (`check_predicate`) and
  then by the repo's own Level M classifier; boolean combinations of `field OP constant`,
  `field in/not in [scalar literals]`, bare `field`, and the keyword catch-alls. Chained
  comparisons are mechanically desugared first (`a < b < c` → `a < b and b < c`; the SPEC
  §4.3 SHOULD), which is exact because operands are pure and every pairwise comparison total.
- **Value domain v0**: `None`, booleans, integers in i32, and strings **interned to integer
  IDs** at compile time (Level M only ever compares strings for equality/membership against
  constants, so interning is lossless). **Floats are outside v0**: the bridge converts to
  fixed-point milli-unit integers before values reach the table.
- **Engine subset v0**: the image holds a flow's **reachable deterministic tier** (SPEC §7
  computes portability over reachable edges; the engine cannot visit unreachable nodes).
  Error/event edges are skipped; they are the host's tiers and the fabric is never consulted
  for them; but a reachable **semantic** edge disqualifies the flow (the engine would release
  the semantic tier exactly where the table says stuck). Certified runs never raise, suspend
  (`wait`/`spawn`/`needs_human`), or resume from restored state; outcomes: `terminal`,
  `stuck`, `max_steps`.

A vector outside the subset is *excluded and reported*, never silently skipped.

## Semantics the interpreter must reproduce (engine parity)

Runtime values are `(type, i32)` pairs: `NONE(0)`, `BOOL(1)`, `INT(2)`, `STR(3, intern_id)`.
Intern ID 0 is reserved for `""` (the falsy string). Unknown runtime strings get fresh IDs;
equality against any authored constant is then correctly false, truthiness correctly true.

- `==`: BOOL/INT compare numerically (`True == 1`); STR by intern ID; `NONE == NONE` is true
  (a **missing field is NONE**: the totality rule's central case); any other type pairing is
  false. `!=` is exactly `not ==`.
- `<, <=, >, >=`: satisfied only when both sides are BOOL/INT (numeric); anything else;
  NONE, STR, mismatches; is **unsatisfied** (false), never an error.
- `field in [c1, c2, …]` compiles to `(field == c1) or (field == c2) …` (Python list
  membership uses `==`); empty literal collection compiles to constant false. `not in` is the
  `not` of that; so a missing field is *not-in-satisfied*, matching "unknown → falsy".
- Bare `field`: NONE → false, BOOL → value, INT → `!= 0`, STR → `id != 0`.
- `and`/`or`/`not` over those atom results; no short-circuit is observable (atoms are total).
- Keyword rows: `always`/`true`/`else`/`otherwise`/`default`/`_` → constant-true program;
  `false`/`never` → constant-false.
- A node's ordered deterministic edges are a **priority encoder**: first true wins.
- `visits` is a per node saturating counter owned by the interpreter, incremented on node
  entry *before* evaluation; if the field dictionary contains `visits`, the interpreter writes
  the current node's counter into that register, overriding any worker-emitted value;
  exactly the engine's `ctx = {**fields, "visits": …}`.
- Run loop (mirrors `engine.run`): at most `max_steps` iterations; terminal (no edges) checked
  at the top of each iteration → `terminal`; no edge matches → `stuck`; iterations exhausted →
  `max_steps`.

## Binary layout (little-endian)

```
header (28 bytes):
  u32  magic        "PPTM" (0x4D545050)
  u16  version      1
  u16  n_fields     field registers (compile-time field dictionary)
  u16  n_interns    interned strings authored in the flow (id 0 = "")
  u16  n_atoms
  u16  n_nodes
  u16  n_edges      total, all nodes
  u16  prog_len     total program words
  u16  start_node
  u16  visits_idx   field register auto-written with the node's visits (0xFFFF: none)
  u16  max_steps    engine parity, default 25
  u16  max_stack    deepest program stack use (RTL sizing; compiler-computed)
  u16  pad

atoms  n_atoms × 8B:  u16 field_idx, u8 op, u8 const_type, i32 const_val
nodes  n_nodes × 4B:  u16 edge_off, u16 edge_cnt          (edge_cnt 0 = terminal)
edges  n_edges × 6B:  u16 target, u16 prog_off, u16 prog_cnt
prog   prog_len × u16
```

Atom ops: `EQ=0 NE=1 LT=2 LE=3 GT=4 GE=5 TRUTHY=6`. Atoms are deduplicated flow-wide; in
fabric each atom is one comparator against one field register, all evaluated in parallel.

Program words (per-edge boolean structure; a tiny stack machine; the sum-of-products
alternative stays open until cocotb decides): `< 0x8000` → push atom result;
`0x8000` NOT, `0x8001` AND, `0x8002` OR, `0x8003` push-true, `0x8004` push-false.
Binary AND/OR, left-fold of the n-ary source form. A program's result is its lone stack value.

Every image ships with a JSON **debug view** (field names, intern strings, readable atoms,
disassembled programs, node names); the binary alone is what hardware sees.

## Companion input encodings (C target harness; the RTL testbench reuses them)

- `regs.bin` (single evaluate): `u32 node_idx`, then `n_fields × {i32 type, i32 val}`.
- `script.bin` (scripted run): `u32 n_nodes`, then per node `u32 n_outcomes` followed by that
  many `n_fields × {i32 type, i32 val}` register images. Outcome k of a node's visits uses
  `min(k, n_outcomes-1)`; the vectors' "last repeats" protocol, resolved host-side.
