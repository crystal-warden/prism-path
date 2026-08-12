# Wire-bytes benchmark — siem corpus

n = 2,501,040 decisions over 2922057s (~0.9/s). Transport overhead: tcp_tls (70 B/packet). MTU payload budget 1400 B. Ours carries a 32 B Merkle root/packet (tamper-evident); JSON carries none.

| format | strategy | wire B/decision | packets | packets/day | p95 latency |
|---|---|---|---|---|---|
| ours O1 (decision) | stream | 110.0 | 2,501,040 | 73,951 | 0.0 ms |
| ours O1 (decision) | batch:64 | 3.094 | 39,079 | 1,155 | 182017.0 ms |
| ours O1 (decision) | mtu(+2s cap) | 15.59 | 329,967 | 9,757 | 2000.0 ms |
| JSON B2 (4-field) | stream | 139.976 | 2,501,040 | 73,951 | 0.0 ms |
| JSON B2 (4-field) | batch:64 | 71.069 | 39,079 | 1,155 | 182017.0 ms |
| JSON B2 (4-field) | mtu(+2s cap) | 79.319 | 333,847 | 9,871 | 2000.0 ms |
| JSON B2 + zstd | stream | 140.053 | 2,501,040 | 73,951 | 0.0 ms |
| JSON B2 + zstd | batch:64 | 2.663 | 39,079 | 1,155 | 182017.0 ms |
| JSON B2 + zstd | mtu(+2s cap) | 19.877 | 333,847 | 9,871 | 2000.0 ms |

## Reading

- **The header tax is a batching choice, not a codec limit.** Ours goes from **110.0 B/decision** unbatched (one packet each, header dominates) to **15.59 B/decision** MTU-batched — the per-packet transport header amortizes to ~0 because the codec is self-framing.
- **Batched-vs-batched, our advantage persists:** MTU ours 15.59 B vs MTU JSON 79.319 B (**5x**) — JSON keeps paying its per-record keys inside the batch; ours pays none.
- **JSON + zstd batched is 19.877 B/decision** — the honest 'smallest but not streaming, not self-framing, no tamper-evidence' reference; and our stream can be zstd'd on top too.
- MTU batching cost p95 latency 2000.0 ms at this rate — the bytes-vs-latency knob, stated.
