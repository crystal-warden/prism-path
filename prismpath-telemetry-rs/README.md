# prismpath-telemetry-rs

The Facet decision telemetry wire in Rust: Figueroa quantization, Zeckendorf coding, the self
healing Merkle transport, epochs, the ack channel, the spiral layout, receipt streams, the replay
window, the refresh profile and the concentrator.

**What it mirrors.** A one to one port of `prismpath/telemetry/` in Python, which is the reference of
record. `PORT_SPEC.md` is the porting contract; when in doubt, match Python, and `DIVERGENCES.md` at the
repository root lists the places where this crate answers differently on purpose.

**What enforces agreement.** The frozen corpora, carried under `tests/fixtures/` as byte identical copies of `prismpath/telemetry/conformance/`,
(`decisions.json` version 2, the boundary and spiral corpora) and the byte level parity fixtures
under `tests/fixtures/`: `test_conformance_decisions.rs` (every reading routes identically after
quantize, code, decode, reconstruct), `test_xwire_parity.rs` (Python wire bits reproduced bit for
bit), `test_boundary_parity.rs`, `test_delivery_parity.rs`, `test_conformance_spiral.rs`. CI runs
`cargo test` and `cargo clippy` with warnings as errors on every push. The formal development in
`formal/` proves the quantization's decision preservation and bridges to the same corpora.

**What is here.** One module per Python module: `quantizer.rs`, `zeckendorf.rs`, `wire.rs`,
`packed.rs`, `selfheal.rs`, `epochs.rs`, `ackchannel.rs`, `spiral.rs`, `decode.rs`, `receipts.rs`
(PROTOCOL.md 2.10), `replay.rs` (2.8), `refresh.rs` (2.7) and `concentrator.rs` (2.9). The wire profile
modules are replayed against `receipts.json` and four corpora generated from the Python modules
(`receipt_stream`, `replay`, `refresh`, `concentrator`; `prismpath/telemetry/gen_profile_corpora.py`), and
`test_cross_language.rs` has Python verify what Rust writes and Rust verify what Python writes.

**Where it is used.** The Vector codec build (`integrations/vector/`), `prismpath-preflight`, and
`prismpath-reflect-bindings` all build on this crate. The protocol itself is `PROTOCOL.md` at the repo
root; the paper is `docs/research/paper-facet-figueroa-quantization.md`.
