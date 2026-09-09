# Tier 6 (spiral) · routing accuracy vs bits

N=20000 readings/scenario, seed=7, correlated multi-dim telemetry.

## Set 1+2 · bits to route, and fidelity parity (per dimensionality k)

| k | cells | bands | linear bits | decision bits | route win | progressive bits | fidelity ratio |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 4 | 4 | 2.79 | 2.79 | 1.0x | 4.79 | 1.72 |
| 2 | 16 | 4 | 5.58 | 2.94 | 1.9x | 5.95 | 1.07 |
| 3 | 64 | 4 | 8.35 | 3.01 | 2.78x | 7.31 | 0.88 |
| 4 | 256 | 4 | 11.12 | 3.06 | 3.63x | 8.76 | 0.79 |

*Route win* = linear bits / decision bits (both route 100% correctly; decision lossless). *Fidelity ratio* = spiral progressive (full quantized magnitude) / linear: ~1x means the win is progressiveness, not dropped data.

## Set 3 · correlation makes the decision stream cheaper (k=3)

| telemetry | decision bits | band entropy (bits) |
|---|---:|---:|
| correlated | 3.01 | 1.59 |
| uniform | 3.9 | 1.38 |

## Set 4 · survival under burst loss (k=3, Gilbert-Elliott)

| regime | linear routed % | spiral routed % |
|---|---:|---:|
| light burst | 92.9 | 96.4 |
| heavy burst | 68.1 | 80.0 |

*Linear needs all k field frames to survive to route; the spiral decision needs its 1 band frame.*

## Verdict: **PASS**

- route_win_for_multidim: True
- win_grows_with_k: True
- fidelity_parity: True
- better_loss_survival: True
