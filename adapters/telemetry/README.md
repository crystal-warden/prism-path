# adapters/telemetry — decision-preserving telemetry

A bounded adapter that turns a decidable flow's telemetry into the **minimum sufficient statistic for its
decisions**, entropy-codes it on a **self-framing Fibonacci wire**, and (later phases) makes delivery
**self-healing and Merkle-verified** — compression and integrity both derived from, and provably faithful
to, the routing decision. Additive, arch-guard-isolated, zero core changes.

The full design of record lives off-repo (the determination doc); only material backed by something that
runs lands here.

## Status — Phase A (in progress)
- ✅ **Zeckendorf / Fibonacci codec** (`zeckendorf.py`) — the self-framing wire. Every code ends in a
  unique `11`, so a stream is zero-header and self-delimiting; small integers are tiny (`1->11`,
  `2->011`), which is where delta-differenced telemetry lives. Round-trip + framing invariants under test.
- ✅ **Decision-preserving quantizer** (`quantizer.py`) — extracts each field's `field OP const`
  thresholds from the flow and maps a reading to the **coarsest symbol that still resolves every routing
  decision** (minimum sufficient statistic). `quantize` → `reconstruct` routes identically across
  numeric / boolean / categorical fields; symbols are tiny.
- ✅ **Decisions-preserved conformance test** (`wire.py` + `conformance/decisions.json`) — the
  differentiated proof, frozen: 4 flows × 55 boundary-probing readings, each tagged with its
  full-precision route at every decision node. The corpus is replayed two ways — the engine must
  reproduce the frozen routes (drift guard), and the **wire round-trip** (quantize → Fibonacci-code →
  decode → reconstruct) must route to the same target at every node (decision preservation, end-to-end
  through the real codec). Regenerate with `gen_decisions_corpus.py`.
- *(next)* the compression-margin + retransmission **go/no-go benchmarks** — Phase A's make-or-break gate
  (threshold-quant + delta + Fibonacci vs varint/zstd, anomaly case shown; selective-repair vs full
  retransmit under a Gilbert-Elliott loss model).

## Roadmap (phased, benchmark-gated)
- **Phase A** — quantizer + codec + decisions-preserved test + a frozen round-trip / error-injection corpus.
- **Phase B** — self-heal via the existing audit-log MMR + selective retransmission + a decode/inspect path.
- **Phase C** — the FPGA shift-register codec; optional vector-quantization / spatial-packing tier.

## Honest scope
Benchmark-gated (if the compression/retransmission margins don't hold, it stops cheaply). Resilience and
performance are validated under **stated channel models** (e.g. Gilbert-Elliott burst-loss) on real sensor
data and real edge silicon — never claimed as field-/orbit-proven.

## Tests
```
python -m pytest adapters/telemetry
```
