# adapters/telemetry — decision-preserving telemetry

A bounded adapter that turns a decidable flow's telemetry into the **minimum sufficient statistic for its
decisions**, entropy-codes it on a **self-framing Fibonacci wire**, and makes delivery **self-healing and
Merkle-verified** — compression and integrity both derived from, and provably faithful to, the routing
decision. Additive, arch-guard-isolated, zero core changes.

The full design of record lives off-repo (the determination doc); only material backed by something that
runs lands here.

## Status — Phase A ✅ · Phase B ✅ · Phase C partial (C1 + C3 landed)
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

### Phase B ✅
- ✅ **Self-heal core** (`selfheal.py`) — the Fibonacci stream is chunked into Merkle-committed blocks,
  reusing the repo's **real** Merkle primitive (`prismpath.ledger_ots`; `audit_log`'s open-release MMR is
  a stub, so this is the genuine one — batch-per-epoch, OTS-anchorable). A lost block is a detected gap; a
  **forged or corrupted block is rejected** (its inclusion proof fails against the trusted root), never
  silently accepted; selective retransmission fills exactly the gaps and reassembles the stream
  bit-for-bit; an unrecoverable block stays a **provable** gap (`assemble()` refuses a silent hole).
- ✅ **Chained epochs + retention** (`epochs.py`) — each sealed window's Merkle root chains to the
  previous (`H(prev‖merkle)`), so a tiny permanent chain of roots gives total ordering + tamper-evidence
  across time while only recent epochs keep raw data. Retention: **drop-on-ACK** (verified up to a root →
  forget the bytes, keep the root), a **retention cap**, and a **provable pressure-drop** (un-acked data
  forced out by the cap is a named gap, never a silent hole). Chain verifies after any drop; sealed roots
  are OTS-anchorable via `ledger_ots`.
- ✅ **Authenticated ACK channel** (`ackchannel.py`) — drop-on-ACK is gated behind an HMAC-SHA256 tag
  over (high-water root, monotonic seq) with a secret shared out-of-band (the pattern `guard_ledger`
  uses). The edge drops only for an ACK that verifies **and** advances the sequence; a forged, tampered,
  wrong-secret, or replayed ACK is ignored and **drops nothing** — closing the data-loss-by-spoof hole
  the doc flags.
- ✅ **Human-readable inspect path** (`decode.py`) — `python decode.py --flow <flow.md> --bits <stream>`
  decodes a captured bitstream back to each reading's symbols, reconstructed values, and the **routing
  decision** the policy makes on it. The `.md` is the decoder (it defines both the partition and the
  routing), so opaque wire traffic is debuggable without bespoke, drifting tooling. Standalone (no core
  change); a `prismpath decode` CLI alias would be a one-liner in `cli.py`.

### Phase C (partial)
- ✅ **Word-packed wire** (`packed.py`) — the real byte format: Fibonacci bits accumulated MSB-first into
  64-bit words, final word zero-padded; the self-framing makes the pad a droppable partial frame, so the
  round-trip is exact with no carried bit-count. Measured padding overhead amortizes from ~39% at N=10 to
  **~0% by N=100k** (the doc's "~3–7%" only bites at tiny streams). Nails the format + correctness; the
  ~10–20× throughput is the C/FPGA path (C2).
- ✅ **Tier-6 decision-first spiral packing** (`spiral.py`, gate in `bench/spiral_bench.py`) — packs a
  multi-var reading onto a Fermat/Vogel spiral whose contiguous index ranges **are** the routes, so the
  wire carries a single **band ID** ("transmit the decision, not the magnitude"); band membership is
  `base ≤ n < base+width` — an integer compare, the Level M atom (`r²=c²·n` ⇒ a radial ring *is* `n < K`).
  Baseline sits at the dense center, severe branches outward; Gray-within-band gives on-demand fidelity
  (progressive). All continuous math (√, golden angle in degrees) is build-time; the edge path is integer
  table + compare. **Gate PASS** (`bench/spiral_results.md`): on multi-dim correlated telemetry the band
  ID routes correctly at **1.9×/2.8×/3.6× fewer bits** than the linear per-field wire for k=2/3/4 (no win
  at k=1 — scalars stay on the layer-2 quantizer, as intended), fidelity parity holds (progressive ≈1×
  linear, so the win is progressiveness not dropped data), correlation makes the decision stream cheaper,
  and the one decision frame survives burst loss better than *k* frames. Frozen `conformance/spiral.json`
  (a mapping bug turns a test RED) + a decisions-preserved proof re-routing each probe three ways.
- *(pending)* C2 FPGA shift-register codec (RTL + Verilator sim local; board synthesis hardware-gated,
  so it can't land without a real-board pass) and C4 optional turbovec-VQ. Not started.

## Roadmap (phased, benchmark-gated)
- **Phase A** ✅ — quantizer + codec + decisions-preserved test + go/no-go benchmarks (margins hold).
- **Phase B** ✅ — self-heal via the repo's real Merkle (`ledger_ots`) + selective retransmission +
  OTS-anchored chained-epoch retention + authenticated ACK + the decode/inspect path.
- **Phase C** — word-packed wire ✅; Tier-6 spiral spatial packing ✅ (benchmark PASS); FPGA
  shift-register codec; optional turbovec-VQ.

## Honest scope
Benchmark-gated (if the compression, retransmission, or routing-accuracy margins don't hold, it stops
cheaply). Resilience and performance are validated under **stated channel models** (e.g. Gilbert-Elliott
burst-loss) on real sensor data and real edge silicon — never claimed as field-/orbit-proven.

## Tests
```
python -m pytest adapters/telemetry
```
The gates are standalone (not pytest); rerun them to reproduce the numbers cited above:
```
python adapters/telemetry/bench/run.py            # Phase A go/no-go -> bench/results.md
python adapters/telemetry/bench/spiral_bench.py   # Tier-6 routing-accuracy gate -> bench/spiral_results.md
```
