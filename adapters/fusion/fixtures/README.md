# Fixtures — synthetic, offline-CI only

`alerts_synth.ndjson` — 200 flat alert rows with a deterministic level distribution
`{3: 100, 4: 50, 7: 25, 8: 15, 10: 7, 12: 3}` and fake identifiers (`SYN-*`, `synth-node-a`).
Regenerate with any seeded script that preserves that distribution; tests assert it exactly.

These rows exercise the census and bench MECHANICS only. Their byte sizes and any numbers
derived from them are never published — published numbers come exclusively from live runs
against the real backlog, recorded in `evidence/` and `bench/results.md`.
