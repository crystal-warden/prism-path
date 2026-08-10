# adapters/telemetry — decision-preserving telemetry

A bounded adapter that turns a decidable flow's telemetry into the **minimum sufficient statistic for its
decisions**, entropy-codes it on a **self-framing Fibonacci wire**, and (later phases) makes delivery
**self-healing and Merkle-verified** — compression and integrity both derived from, and provably faithful
to, the routing decision. Additive, arch-guard-isolated, zero core changes.

The full design of record lives off-repo (the determination doc); only material backed by something that
runs lands here.

## Status — Phase A (in progress)
- **[this commit] Zeckendorf / Fibonacci codec** (`zeckendorf.py`) — the self-framing wire. Every code
  ends in a unique `11`, so a stream is zero-header and self-delimiting; small integers are tiny
  (`1->11`, `2->011`), which is where delta-differenced telemetry lives. Round-trip + framing invariants
  under test.
- *(next)* threshold-derived quantizer (from `model_check`), the **decisions-preserved conformance test**
  (route on full-precision vs reconstructed telemetry; assert identical routing — the differentiated
  proof), then the compression-margin + retransmission go/no-go benchmarks.

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
