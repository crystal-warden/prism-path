# The frozen kernel spec — conformance vectors

These files ARE the specification of the portable PrismPath kernel, expressed as data. They are
generated from the **Python reference implementation** by `../gen_conformance.py`
(deterministic: fixed seed, sorted keys — regeneration is byte-identical unless semantics
changed), and any implementation claiming conformance must pass **every case bit-for-bit**:

- **`predicates.json`** — 1,067 `(condition, context) → true | false | "ERROR"` cases for the
  `when`-predicate evaluator: one curated case per semantic sharp edge (the classes a
  61,700-comparison differential fuzz found implementations diverge on — Python keywords as
  field names, `True`-constant vs `true`-field-name, bool/number equality, chained
  comparisons, substring/list/dict membership, truthiness of empty containers, escape tables,
  numeric spellings, list ordering past equal-but-unorderable elements, depth accounting)
  plus a seeded grammar-fuzz sample. `"ERROR"` means the sandbox rejects the predicate
  (PredicateError) — at run time such an edge is non-matching, never a crash.
- **`flows.json`** — 27 full engine fixtures: a flow document plus scripted worker outcomes
  (`script` maps node → outcomes consumed in visit order, last repeats; `{"__raise__": msg}`
  throws, exercising the error tier) → the reference engine's `{path, stopped, pending_node,
  spawn}`.

Verify the shipping JS port:

```
node portable/run_vectors.mjs        # -> CONFORMANT, or one line per mismatch, exit 1
```

Regenerate after an intentional semantics change (the resulting `git diff` is the
spec-change review):

```
python portable/gen_conformance.py
```

The pytest bridge (`tests/test_conformance_vectors.py`) enforces both directions on every
run: the committed vectors must match a fresh regeneration from the live Python code (no
silent reference drift), and the port must pass the committed vectors (no silent port drift).
A future Go / Rust / WASM kernel implements the frozen subset, reads these two files, and is
provably interchangeable — or measurably not.
