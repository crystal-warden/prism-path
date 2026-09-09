# prismpath-telemetry-rs

The Facet decision telemetry wire in Rust: Figueroa quantization, Zeckendorf coding, the self
healing Merkle transport, epochs, the ack channel, and the spiral layout.

**What it mirrors.** A one to one port of `adapters/telemetry/` in Python, which is the reference of
record. `PORT_SPEC.md` is the porting contract; when in doubt, match Python.

**What enforces agreement.** The frozen corpora under `adapters/telemetry/conformance/`
(`decisions.json` version 2, the boundary and spiral corpora) and the byte level parity fixtures
under `tests/fixtures/`: `test_conformance_decisions.rs` (every reading routes identically after
quantize, code, decode, reconstruct), `test_xwire_parity.rs` (Python wire bits reproduced bit for
bit), `test_boundary_parity.rs`, `test_delivery_parity.rs`, `test_conformance_spiral.rs`. CI runs
`cargo test` and `cargo clippy` with warnings as errors on every push. The formal development in
`formal/` proves the quantization's decision preservation and bridges to the same corpora.

**What is here.** One module per Python module: `quantizer.rs`, `zeckendorf.rs`, `wire.rs`,
`packed.rs`, `selfheal.rs`, `epochs.rs`, `ackchannel.rs`, `spiral.rs`, `decode.rs`.

**Where it is used.** The Vector codec build (`integrations/vector/`), `prismpath-preflight`, and
`prismpath-reflect-bindings` all build on this crate. The protocol itself is `PROTOCOL.md` at the repo
root; the paper is `docs/research/paper-facet-figueroa-quantization.md`.
