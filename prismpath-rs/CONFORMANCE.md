# prismpath-rs — conformance certification against the frozen kernel spec

**Date:** 2026-07-28 · **Verdict: NOT CONFORMANT** · Reproduce with:

```
cargo run --bin conformance -- ../prismpath/portable/conformance
```

## Why this was run rather than shelved

The integration paper recommended parking this crate because "a second implementation is a drift risk
against the Python source of truth," and noted that "its flow schema is not verified against PrismPath's
actual compiled-flow format." That caveat is not a reason to shelve the crate — it is the name of the
test. The corpus exists precisely for this: `portable/conformance/README.md` states that "a future Go /
Rust / WASM kernel implements the frozen subset, reads these two files, and is provably interchangeable
— **or measurably not**."

So it was measured. Either outcome pays: a pass would have given the spec its second independent
implementation (the strongest credibility artifact a format can have — two kernels, one vector corpus,
bit-for-bit) and Journeyman's Tauri backend a native evaluator with no JS bridge. A failure yields an
itemized gap list for free. It failed, and below is the list.

**Baseline for comparison:** the shipping JS port (`portable/prismpath.mjs`) is **CONFORMANT** —
1067/1067 predicates, 27/27 flows. The corpus is valid and the reference is green; the divergence is
the Rust crate's alone.

## Result

| Suite | Result |
|---|---|
| Predicates | **608 / 1067** (57.0%) — 459 diverge |
| Flows | **0 / 27 executable** |

### Predicate divergences, grouped by cause

| Count | Cause | Example |
|---:|---|---|
| 166 | chained / multi-term comparison (>3 tokens) | `when 1 < x < 5` → expected `true`, got `false` |
| 131 | `not in` operator unsupported | `when x not in y` → expected `true`, got `false` |
| 75 | binary comparison semantics | `when "error" in text` → expected `true`, got `false` |
| 51 | index / attribute access, list literals | `when a in ["contain", "watch"]` → expected `true`, got `false` |
| 25 | boolean connective (`and`/`or`/`not`) | `when not nope` → expected `true`, got `false` |
| 9 | other (tuple literals) | `when a in ("contain", "watch")` → expected `true`, got `false` |
| 2 | bare-field truthiness | `when ((((((((((x))))))))))` → expected `true`, got `false` |

The evaluator handles exactly two shapes: a 3-token binary comparison and a 1-token truthiness check.
Everything the spec was frozen to pin down — the semantic sharp edges a 61,700-comparison differential
fuzz surfaced — is outside that window.

### Flow divergences (structural, not tunable)

All 27 fixtures carry the flow as a **Markdown document with YAML frontmatter**. The crate's `Flow` is a
serde struct deserialized from **JSON** and there is no Markdown/frontmatter parser, so the fixtures
cannot even be loaded. Separately, `Engine::run` returns only `Vec<String>` (the path), while the spec
requires `{path, stopped, pending_node, spawn}` — **3 of the 4 required output fields do not exist**.

## What this settles

1. **The crate is not a drift risk against the Python reference.** It is a different, much smaller
   artifact wearing the same name: roughly half a predicate evaluator and none of an engine. "Drift"
   implies two implementations of one spec; this is one implementation and one sketch.
2. **It cannot back Journeyman's Tauri backend today.** A native evaluator with no JS bridge remains
   desirable, but it is a build, not a wiring job.
3. **The conformant kernel to build on right now is `portable/prismpath.mjs`** (1067/1067, 27/27). Any
   near-term flow work — e.g. running Journeyman's Guided Path as a real P0 flow — should target the
   `.mjs` kernel, not this crate.

## What it would take to certify

In dependency order, cheapest first:

1. `not in`, and membership over list/tuple/dict/string with the spec's semantics (~215 cases).
2. Chained comparisons (`a < b < c`) and general multi-term expressions (~166 cases).
3. Boolean connectives and parenthesised grouping (~27 cases).
4. A Markdown + YAML-frontmatter flow parser (unblocks all 27 flow fixtures).
5. `stopped`, `pending_node`, and `spawn` in the engine's result, with the reference's semantics for
   worker outcome scripts and the error tier.

Items 1–3 are self-contained evaluator work checkable case-by-case against `predicates.json`. Items 4–5
are the real engine and should be attempted only once 1–3 are green.

## Note on the certification hook

`Engine::conformance_eval` was added to expose the spec's three-valued `true | false | "ERROR"` result.
`evaluate_condition` collapses errors with `unwrap_or(false)` — correct at run time (a rejected edge is
non-matching, never a crash) but it hides the distinction the corpus checks. No evaluator logic was
changed; the crate's behaviour is reported as-is.
