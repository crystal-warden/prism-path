# prismpath-telemetry-rs · porting spec (1-1 Rust port of `adapters/telemetry/`)

A faithful, decision preserving Rust reimplementation of the Python telemetry adapter, for environments
where Python cannot run (edge / embedded / P2-restricted). **The Python at `adapters/telemetry/` is the
reference of record; read it for exact semantics; when in doubt, match Python.**

## Crate setup
- Standalone crate `prismpath-telemetry-rs/` (sibling of `prismpath-rs/`; no workspace).
- Depend on the Rust kernel: `prismpath-rs = { path = "../prismpath-rs" }`. Use it for flow parsing
  (`prismpath_rs::parse(text) -> Graph`), routing (`eval_condition(cond, &ctx)`), and the edge surface
  (`Node.edges: Vec<(target, condition)>`, plus `is_deterministic`/`is_semantic`/etc.).
- Other deps: `sha2` (Merkle), `hmac` (ACK), `serde_json` (load the frozen corpora in tests).

## Modules to port (each mirrors the same-named Python file)
| Rust | from Python | must reproduce |
|---|---|---|
| `zeckendorf.rs` | `zeckendorf.py` | Fibonacci self framing codec: `encode`/`decode`/`encode_stream`/`decode_stream`; bit-strings ending in the unique `11`; a trailing terminator-less run is a dropped partial frame. |
| `quantizer.rs` | `quantizer.py` | decision preserving quantizer. Extract each field's `field OP const` atoms from the flow's deterministic edges: you must write a small **condition-atom parser** (`prismpath-rs` does not expose atoms). Build the coarsest decision cells: numeric (representative-eval + adjacent-merge), boolean, categorical (one cell per constant + an `\x00__other__` sentinel). `quantize`/`reconstruct`. |
| `wire.rs` | `wire.py` | reading <-> bitstream through quantizer + zeckendorf; **canonical sorted field order**, symbol+1 on the wire; `route_node`/`decision_nodes`. |
| `packed.rs` | `packed.py` | word-packed byte wire: MSB-first accumulate into 64-bit words, final word zero-padded right, the pad is a droppable partial frame; `pack`/`unpack`/`encode`/`decode`/`padding_overhead`. |
| `spiral.rs` | `spiral.py` | Tier-6 decision-first Fermat-spiral packing: mixed-radix reflected Gray code; contiguous decision-bands ordered center-outward (reverse edge order so the fallthrough/baseline is central); `route_of` by integer band compares; `encode_decision`/`encode_progressive`; `tessellation`. Integer-only geometry (`theta_u32`, `radius2`). |
| `selfheal.rs` | `selfheal.py` | Merkle committed blocks. **Reproduce `prismpath.ledger_ots`'s Merkle root + inclusion proofs BYTE-FOR-BYTE** with `sha2`: study `prismpath/ledger_ots.py::merkle_root_and_paths`/`verify_leaf` for the exact construction (leaf/dup/hash order). `chunk`/`commit`/`verify_block`/`Sender`/`Receiver`/`repair`/`assemble` (a lost/forged block stays a provable gap). |
| `epochs.rs` | `epochs.py` | chained epochs `H(prev‖merkle)`; `seal`/`ack`/`enforce_cap`/`verify_chain`/`retransmittable`/`gaps`. |
| `ackchannel.rs` | `ackchannel.py` | HMAC-SHA256 signed ACKs (`hmac`+`sha2`) matching the Python `hmac` bytes exactly; `sign_ack`/`verify_ack`/`AckReceiver` (drop only on a valid, advancing tag). |
| `decode.rs` | `decode.py` | inspect path: bits -> per reading symbols / reconstructed values / routes. |

## Keep framing pluggable (do NOT build CBOR now)
Put the bit<->byte framing behind a trait (e.g. `Wire`) so a CBOR interop mode can be added later without
touching the decision preserving codec. Fibonacci is the only implementation for now.

## Definition of done · the gate (this is how "1-1" is proven; do not claim done until green)
1. `cargo build` and `cargo clippy` are clean.
2. `cargo test` includes a conformance harness loading the **same frozen corpora the Python passes**:
   - `../adapters/telemetry/conformance/decisions.json`: for each case, parse the flow, build partitions,
     and assert the wire round-trip (quantize → Fibonacci-code → decode → reconstruct) routes every tagged
     reading to the **same route at every decision node** (decision preservation) and reproduces the
     tagged full-precision route (drift).
   - `../adapters/telemetry/conformance/spiral.json`: rebuild the layout from the frozen flow and assert
     `fields`/`radices`/`size`/`bands`/`cells` match the frozen tessellation **exactly**, and each probe
     routes three ways identically (direct, via band-reconstruct, via `route_of(index)`).
3. A **delivery-layer parity** test: for a fixed set of leaves/blocks/keys, the Rust Merkle root,
   inclusion proofs, and HMAC ACK tags equal the Python's byte-for-byte (freeze expected values by running
   the Python once, or compute both and compare).

Report the exact pass counts for each. The corpora are frozen and shared with Python; treat any mismatch
as a port bug, not a corpus bug.
