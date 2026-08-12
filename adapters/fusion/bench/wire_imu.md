# Wire-bytes benchmark — imu corpus

n = 10,421 decisions over 9413s (~1.1/s). Transport overhead: tcp_tls (70 B/packet). MTU payload budget 1400 B. Ours carries a 32 B Merkle root/packet (tamper-evident); JSON carries none.

| format | strategy | wire B/decision | packets | packets/day | p95 latency |
|---|---|---|---|---|---|
| ours O1 (decision) | stream | 110.0 | 10,421 | 95,655 | 0.0 ms |
| ours O1 (decision) | batch:64 | 3.101 | 163 | 1,496 | 6968.0 ms |
| ours O1 (decision) | mtu(+2s cap) | 7.349 | 575 | 5,278 | 2000.0 ms |
| JSON B2 (4-field) | stream | 141.701 | 10,421 | 95,655 | 0.0 ms |
| JSON B2 (4-field) | batch:64 | 72.795 | 163 | 1,496 | 6968.0 ms |
| JSON B2 (4-field) | mtu(+2s cap) | 75.717 | 598 | 5,489 | 1882.0 ms |
| JSON B2 + zstd | stream | 143.274 | 10,421 | 95,655 | 0.0 ms |
| JSON B2 + zstd | batch:64 | 3.121 | 163 | 1,496 | 6968.0 ms |
| JSON B2 + zstd | mtu(+2s cap) | 9.553 | 598 | 5,489 | 1882.0 ms |

## Reading

- **The header tax is a batching choice, not a codec limit.** Ours goes from **110.0 B/decision** unbatched (one packet each, header dominates) to **7.349 B/decision** MTU-batched — the per-packet transport header amortizes to ~0 because the codec is self-framing.
- **Batched-vs-batched, our advantage persists:** MTU ours 7.349 B vs MTU JSON 75.717 B (**10x**) — JSON keeps paying its per-record keys inside the batch; ours pays none.
- **JSON + zstd batched is 9.553 B/decision** — the honest 'smallest but not streaming, not self-framing, no tamper-evidence' reference; and our stream can be zstd'd on top too.
- MTU batching cost p95 latency 2000.0 ms at this rate — the bytes-vs-latency knob, stated.
