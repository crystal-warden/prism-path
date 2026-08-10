# adapters/telemetry — decision-preserving telemetry

A bounded adapter that turns a decidable flow's telemetry into the **minimum sufficient statistic for its
decisions**, entropy-codes it on a **self-framing Fibonacci wire**, and (later phases) makes delivery
**self-healing and Merkle-verified** — compression and integrity both derived from, and provably faithful
to, the routing decision. Additive, arch-guard-isolated, zero core changes.

The full design of record lives off-repo (the determination doc); only material backed by something that
runs lands here.

## Status — Phase A ✅ complete · Phase B in progress
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
- ✅ **Go/no-go benchmarks** (`bench/`, results in `bench/results.md`) — **PASS**. Two sets: a codec
  bake-off and a parametric sweep (value regime × stream scale to 100k + Gilbert-Elliott retransmission).
  Findings: `delta+zz+fib` beats the streaming baselines ~2–3× (batch compressors win on a buffered block
  but aren't self-framing/line-rate); decision-preserving quantization is **magnitude-independent** — on a
  wide-range field with few thresholds it holds ~2 bits/reading while raw scales with magnitude (~16× vs
  fixed); ratios **converge** by N=10k–100k (a too-small test would have undersold it — the sweep proves
  it); selective MMR retransmit is multiples cheaper under sparse burst loss. **Margins hold → Phase A
  validates.**

### Phase B (in progress)
- ✅ **Self-heal core** (`selfheal.py`) — the Fibonacci stream is chunked into Merkle-committed blocks,
  reusing the repo's **real** Merkle primitive (`prismpath.ledger_ots`; `audit_log`'s open-release MMR is
  a stub, so this is the genuine one — batch-per-epoch, OTS-anchorable). A lost block is a detected gap; a
  **forged or corrupted block is rejected** (its inclusion proof fails against the trusted root), never
  silently accepted; selective retransmission fills exactly the gaps and reassembles the stream
  bit-for-bit; an unrecoverable block stays a **provable** gap (`assemble()` refuses a silent hole).
- *(next)* OTS-anchored epoch root + retention (drop-on-ACK, provable pressure-drop) → authenticated ACK
  channel → the `prismpath decode --flow` human-readable inspect path.

## Roadmap (phased, benchmark-gated)
- **Phase A** ✅ — quantizer + codec + decisions-preserved test + go/no-go benchmarks (margins hold).
- **Phase B** — self-heal via the repo's real Merkle (`ledger_ots`; `audit_log` is a stub) + selective
  retransmission + OTS-anchored epoch retention + authenticated ACK + a decode/inspect path.
- **Phase C** — the FPGA shift-register codec; optional vector-quantization / spatial-packing tier.

## Honest scope
Benchmark-gated (if the compression/retransmission margins don't hold, it stops cheaply). Resilience and
performance are validated under **stated channel models** (e.g. Gilbert-Elliott burst-loss) on real sensor
data and real edge silicon — never claimed as field-/orbit-proven.

## Tests
```
python -m pytest adapters/telemetry
```
