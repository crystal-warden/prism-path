# prismpath-rs

The PrismPath P0 kernel in Rust: the decidable Markdown policy runtime (Level M match action), for
places Python cannot run.

**What it mirrors.** `prismpath/portable/prismpath.mjs`, itself a certified port of the Python
reference in `prismpath/`. Where Python and JS semantics are subtle this crate copies the `.mjs`
decision, because the corpus is the judge.

**What enforces agreement.** The frozen conformance corpus in `prismpath/portable/conformance/` is
the specification. The crate's only claim to correctness is passing it bit for bit:

```
cargo run --bin conformance -- ../prismpath/portable/conformance
```

`CONFORMANCE.md` records the certified result (1079/1079 predicates, 27/27 flows) and the exact
command. CI runs `cargo test` for this crate on every push.

**What is here.** `src/lib.rs` (the kernel), `src/durable.rs` (checkpoints, Python canonical JSON),
`src/compose.rs` (fan out), `src/connector.rs` (the connector contract), `src/crypto_agility.rs`
(suite registry proofs), `src/bin/conformance.rs` (the corpus runner). Tests under `tests/` replay the
corpus files by name.

**Related crates.** `prismpath-telemetry-rs` (the Facet wire), `prismpath-hotswap-rs` (signed
policy packs and the PolicyHost), `prismpath-preflight` (the Facet adoption gate). The root
`Cargo.toml` is the workspace.
