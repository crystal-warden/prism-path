# Native codec soak: 1,043,442 decisions, zero errors (2026-08-15 to 2026-08-16)

Two independent two instance Vector pipelines (edge encodes with `encoding.codec = "facet"`,
aggregator decodes with `decoding.codec = "facet"` and re emits routed JSON), fed at ~5 events/s
each, run continuously until stopped. Pipeline shape = the committed `vector.toml` /
`vector_edge.toml` pattern with the policy and port swapped per soak; feeders and the stress flow
are in this directory. Every count below is from the decoded output files; "bad lines" means
undecodable output, and there were none.

| | fusion soak | big value soak |
|---|---|---|
| policy | `fusion_triage.md` (4 fields) | `big_values.md` (3 fields, thresholds 10^2 to 10^12) |
| duration | 30 h 57 m | 27 h 05 m |
| decisions decoded | 556,477 | 486,965 |
| bad lines / decode errors / log errors | 0 / 0 / 0 | 0 / 0 / 0 |
| framed wire cost | 2.000 B/event | 1.466 B/event |
| total wire moved | ~1.11 MB | ~0.71 MB |
| memory per Vector instance | 56 MB, flat | 56 MB, flat |

Big value route distribution at 486,965 events: baseline 36.32%, throttle 17.72%, elevated
16.40%, slow_path 14.97%, degraded 7.64%, exfil_alert 3.75%, watch 3.21%. The same distribution
sampled at one sixth of the run matched every route within a tenth of a point: six times the data,
identical shape, across inputs spanning nine orders of magnitude with spikes past 2^53.

The sentence the run earned: **over a million decisions through the native codec in ~31 hours,
zero errors of any kind, flat memory, and the entire wire traffic totaled ~1.8 MB, smaller than
the memory footprint of any single process that moved it.**
