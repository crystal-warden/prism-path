# SPEC — CBOR interop framing for decision-preserving telemetry

*Design spec for the standards-based framing of the telemetry adapter (`adapters/telemetry/`,
`prismpath-telemetry-rs/`). Status: **spec only, not yet implemented** — the framing seam exists
(`WireCodec` in Rust) but the CBOR codec behind it is the fast-follow. Crystal Warden Labs, 2026-08-10.*

---

## 1. Purpose & scope

The telemetry adapter's compact wire is a bespoke self-framing Fibonacci/spiral stream: excellent bits,
but a consumer needs a PrismPath decoder to read it. This spec defines an **optional** framing that carries
the *same decision symbols* in **CBOR (RFC 8949)**, so any device or tool decodes a frame with an
off-the-shelf CBOR library and **no PrismPath code**.

Two layers, two answers — this is deliberate:

- **The decision-preserving core stays PrismPath-specific.** "Transmit the minimum sufficient statistic
  for *this flow's* routing decisions" is derived from the decidable `.md`; no open standard can compute
  it. This spec does **not** touch that.
- **The framing is where a standard removes integration friction.** CBOR is the interop framing; the
  Fibonacci/spiral wire remains the max-compression default. Same symbols, two framings, chosen per
  deployment.

Honest trade: a CBOR frame is **larger** than the Fibonacci wire (map keys + type headers vs a ~2-bit
code). CBOR buys universal decodability, not compactness. Pick the bespoke wire for the tightest links and
CBOR where an integrator's ease matters more than the last bits.

## 2. What the frame carries

The `.md` flow **is the schema/decoder** (it defines both the field partition and the routing — see the
`decode.py` inspect path). A frame therefore carries only the symbols plus the **flow hash** that names
the partition which decodes them; the consumer resolves symbols → route against that flow (or a published
partition digest).

## 3. Frame format (CDDL, RFC 8610)

Integer map keys keep the frame compact and canonical (RFC 8949 §4.2 core deterministic encoding).

```cddl
; PrismPath decision-preserving telemetry — CBOR interop frame
telemetry-frame = {
  0 : uint,                ; version — this spec is 1
  1 : bytes .size 32,      ; flow-hash — sha256 of the flow .md (the POLICY_HASH the repo already binds);
                           ;   identifies the partition that decodes this frame
  2 : body,                ; the decision payload
  ? 3 : uint,              ; seq — monotonic sequence number (pairs with the self-heal / ACK layer)
  ? 4 : uint,              ; epoch — sealed-window id (chained-epoch retention)
  ? 5 : uint,              ; ts — producer timestamp, epoch seconds
}

body = scalar-symbols / spiral-decision

; SCALAR: one symbol per decision-relevant field, in canonical (sorted field-name) order — the same
; order the Fibonacci wire uses. A symbol is the 0-based index of the field's decision cell; the flow
; maps it to a route. (On the Fibonacci wire the same value is sent as symbol+1; CBOR sends it raw.)
scalar-symbols = [+ uint]

; SPIRAL (Tier-6): the band-id alone is the decision-lossless stream (routes correctly); the optional
; local index is the on-demand within-band refinement that recovers the full quantized magnitude.
spiral-decision = {
  6 : uint,                ; band-id
  ? 7 : uint,              ; within-band local index (progressive refinement)
}
```

### 3.1 Field semantics

| key | name | meaning |
|---|---|---|
| 0 | version | frame version (1) |
| 1 | flow-hash | sha256 of the decoding flow `.md`; provable "which policy decoded this" |
| 2 | body | `scalar-symbols` (per-field cells) **or** `spiral-decision` (band + refinement) |
| 3 | seq | monotonic sequence; the self-heal/ACK layer routes on it (`ackchannel`) |
| 4 | epoch | sealed-window id; enables retention + selective retransmission (`epochs`) |
| 5 | ts | producer timestamp, epoch seconds |
| 6 | band-id | spiral decision band (the cheap decision stream) |
| 7 | local-index | spiral within-band index (fidelity, on demand) |

## 4. Relationship to the Fibonacci wire

Both framings serialize the **same symbols** produced by the decision-preserving quantizer / spiral
layout; only the byte-level framing differs. In `prismpath-telemetry-rs` this is the `WireCodec` trait:
`FibonacciWireCodec` today, a `CborWireCodec` alongside it. Choosing a framing never changes the routing
outcome — decision-preservation is a property of the symbols, not the frame.

## 5. Transport

Framing is orthogonal to transport. A CBOR frame rides any bearer: **CoAP** (RFC 7252) or **MQTT-SN** for
constrained devices, plain UDP/TCP, or a file. This spec defines the payload only.

## 6. Non-goals & honest caveats

- **Not SenML (RFC 8428).** SenML carries *raw measurements*; this adapter sends *quantized decision
  symbols*. Forcing SenML would mean shipping raw values and forfeiting the compression. CBOR is the fit;
  SenML is not.
- **Not a compression win.** CBOR is the *integration* option, larger than the bespoke wire (§1).
- **Not implemented yet.** This is the reviewable interop shape; the codec is the follow-on behind the
  existing `WireCodec` seam.
- **Verification plan (when built):** a CBOR round-trip must route identically to the Fibonacci wire on the
  same frozen corpora (`adapters/telemetry/conformance/`), and a cross-language decode (Python-encode →
  Rust-decode and back) must agree — the same referee-by-corpus discipline the rest of the adapter uses.

## 7. Status & next

Spec published for partner review. Implementation order: add `CborWireCodec` in `prismpath-telemetry-rs`
(and the Python adapter) behind `WireCodec`; gate it with a CBOR conformance test over the frozen corpora;
then document the two-framing choice in the adapter README.
