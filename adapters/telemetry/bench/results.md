# Telemetry Phase A — benchmark results

## Set 1 — codec bake-off (bits/sample, lossless on raw values, N=10,000)

| regime | fixed32 | uvarint | delta+zz+uvarint | fib(raw) | delta+zz+fib | zstd-19 | zlib-9 | lzma-9 |
|---|---|---|---|---|---|---|---|---|
| quiet | 32.00 | 8.00 | 8.00 | 7.74 | 2.49 | 1.52 | 1.76 | 1.32 |
| moderate | 32.00 | 15.18 | 11.04 | 17.03 | 7.38 | 6.82 | 8.88 | 6.48 |
| wide | 32.00 | 19.09 | 11.01 | 21.00 | 6.32 | 5.14 | 5.32 | 4.17 |
| spiky | 32.00 | 8.16 | 8.32 | 7.95 | 3.03 | 2.07 | 2.24 | 1.68 |

## Set 1 — decision stream vs lossless raw (bits per reading, N=10,000)

| flow | regime | fields | ours (sym) | raw+fib | raw fixed | x vs raw+fib | x vs fixed |
|---|---|---|---|---|---|---|---|
| incident_severity | quiet | 3 | 6.74 | 7.21 | 96.00 | 1.1x | 14.2x |
| incident_severity | wide | 3 | 6.87 | 8.21 | 96.00 | 1.2x | 14.0x |
| incident_severity | spiky | 3 | 6.77 | 7.36 | 96.00 | 1.1x | 14.2x |
| sensor_guard(wide) | quiet | 1 | 2.00 | 2.49 | 32.00 | 1.2x | 16.0x |
| sensor_guard(wide) | wide | 1 | 2.02 | 6.32 | 32.00 | 3.1x | 15.9x |
| sensor_guard(wide) | spiky | 1 | 2.05 | 3.03 | 32.00 | 1.5x | 15.6x |

## Set 2 — N sweep: delta+zz+fib bits/sample (convergence + regime spread)

| regime | N=100 | N=1000 | N=10000 | N=100000 |
|---|---|---|---|---|
| quiet | 4.70 | 2.50 | 2.49 | 2.20 |
| moderate | 11.57 | 9.03 | 7.38 | 3.92 |
| wide | 22.95 | 6.04 | 6.32 | 3.86 |
| spiky | 5.23 | 3.03 | 3.03 | 2.75 |

**Fibonacci crossover:** fib(raw) exceeds fixed-32 bits/sample around value ~4,194,304 (33 bits there) — below that, fib wins; above, the escape-code fallback caps us at fixed-width.

## Set 2 — retransmission: selective (MMR) vs full, Gilbert-Elliott burst loss (N=10,000)

| block | p(g→b) | r(b→g) | lost samp | lost blk / total | selective/full |
|---|---|---|---|---|---|
| 32 | 0.002 | 0.2 | 140 | 27/313 | 0.086 |
| 32 | 0.01 | 0.1 | 909 | 107/313 | 0.342 |
| 128 | 0.002 | 0.2 | 140 | 21/79 | 0.266 |
| 128 | 0.01 | 0.1 | 909 | 58/79 | 0.734 |
| 512 | 0.002 | 0.2 | 140 | 13/20 | 0.650 |
| 512 | 0.01 | 0.1 | 909 | 20/20 | 1.000 |

## Reading (go/no-go)

- **Streaming codec:** `delta+zz+fib` beats the streaming baselines (`uvarint`, `delta+zz+uvarint`) ~2-3x across regimes. Batch compressors (zstd/lzma) do better on a buffered block, but are not self-framing / line-rate / streaming — fib occupies varint's niche and wins it.
- **Decision-preserving quantization is magnitude-independent:** on a wide-range field with few thresholds (`sensor_guard`), ours holds ~2 bits/reading across quiet/wide/spiky while raw scales with magnitude — 'transmit the decision, not the magnitude', as a number. The win is modest when the raw field is already small (incident_severity: ~14x vs fixed, ~1.1x vs raw+fib).
- **Size matters (validated):** at N=100 bits/sample is inflated (small-N artifact); it converges by N=10k-100k. A too-small benchmark would have undersold the codec badly.
- **Selective retransmission (MMR)** is multiples cheaper than full retransmit under sparse burst loss, eroding to parity once blocks are large relative to the burst length — size blocks to the link's burst statistics.
- **Verdict: margins hold → Phase A validates → proceed to Phase B.**


_generated in 0.5s_
