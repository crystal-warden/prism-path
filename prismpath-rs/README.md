# prismpath-rs

The PrismPath P0 kernel in Rust: the decidable Markdown policy runtime (Level M match action), a
second implementation that runs where Python cannot. Where it answers differently from Python on
purpose, `DIVERGENCES.md` at the repository root lists the place, the reason and the test that holds it.

**What it mirrors.** The Python reference in `prismpath/`, through the portable kernel
`prismpath/portable/prismpath.mjs`. Where Python and JS semantics are subtle this crate copies the `.mjs`
decision, because the corpus is the judge.

**What enforces agreement.** The frozen conformance corpus in `prismpath/portable/conformance/` is
the specification. The crate's only claim to correctness is passing it bit for bit:

```
cargo run --bin conformance -- ../prismpath/portable/conformance
```

`CONFORMANCE.md` records the certified result (1112/1112 predicates, 107/107 flows, 8/8 locked flows) and the exact
command. CI runs `cargo test` for this crate on every push.

**What is here.** `src/lib.rs` (the kernel), `src/contract.rs` (the worker output contract the type gate holds a worker to), `src/durable.rs` (checkpoints, Python canonical JSON),
`src/compose.rs` (fan out), `src/connector.rs` (the connector contract), `src/crypto_agility.rs`
(suite registry proofs), `src/bin/conformance.rs` (the corpus runner). Tests under `tests/` replay the
corpus files by name.

**Related crates.** `prismpath-telemetry-rs` (the Facet wire), `prismpath-hotswap-rs` (signed
policy packs and the PolicyHost), `prismpath-preflight` (the Facet adoption gate). The root
`Cargo.toml` is the workspace.
