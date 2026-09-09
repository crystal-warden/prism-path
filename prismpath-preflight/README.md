# prismpath-preflight

Will your events survive the Facet codec? One command, one report. The adoption gate for the Facet
wire: take a sample of real events and a policy flow, and report how each field fares under
quantization before anything is deployed.

**What it mirrors.** `prismpath/telemetry/preflight.py`, the Python reference tool, with the same
contract. This binary runs on the exact crates the Vector codec is built from
(`prismpath-telemetry-rs`, `prismpath-rs`), so what it reports is what the codec will do, by
construction.

**One documented difference, on purpose.** The Rust value model coerces a non numeric string on a
numeric field to 0 where the Python reference errors; this tool surfaces that as its own finding.
Running both tools on one sample is a free differential test of the whole stack.

**What enforces it.** `tests/e2e.rs` runs the binary end to end including the string coercion
finding; CI runs `cargo test` and `cargo clippy` with warnings as errors on every push.

**Where it fits.** Step 0 of the Vector integration (`integrations/README.md`, "will YOUR events
survive the codec"). Formerly published as `facet-preflight` (yanked): the `facet-*` prefix belongs
to the facet reflection ecosystem on crates.io, which is unrelated to the Facet wire.
