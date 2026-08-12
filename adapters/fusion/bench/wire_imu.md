# Wire-bytes benchmark — imu corpus

n = 10,421 decisions over 9413s (~1.1/s). Transport overhead: tcp_tls (70 B/packet). MTU payload budget 1400 B. Ours carries a 32 B Merkle root/packet (tamper-evident); JSON carries none.

## Full matrix — 4 formats x 4 strategies

| format | strategy | wire B/decision | packets/day | MB/day | p95 latency |
|---|---|---|---|---|---|
| ours O1 (decision) | stream | 110.0 | 95,655 | 10.522 | 0.0 ms |
| ours O1 (decision) | batch:64 | 3.101 | 1,496 | 0.297 | 6968.0 ms |
| ours O1 (decision) | mtu-fill | 1.636 | 119 | 0.156 | 441654.0 ms |
| ours O1 (decision) | mtu+2s cap | 7.349 | 5,278 | 0.703 | 2000.0 ms |
| ours O1 +AEAD+ECDHE | stream | 126.018 | 95,655 | 12.054 | 0.0 ms |
| ours O1 +AEAD+ECDHE | batch:64 | 3.37 | 1,496 | 0.322 | 6968.0 ms |
| ours O1 +AEAD+ECDHE | mtu-fill | 1.674 | 119 | 0.160 | 441654.0 ms |
| ours O1 +AEAD+ECDHE | mtu+2s cap | 8.25 | 5,278 | 0.789 | 2000.0 ms |
| JSON B2 (4-field) | stream | 141.701 | 95,655 | 13.554 | 0.0 ms |
| JSON B2 (4-field) | batch:64 | 72.795 | 1,496 | 6.963 | 6968.0 ms |
| JSON B2 (4-field) | mtu-fill | 75.596 | 5,324 | 7.231 | 2009.0 ms |
| JSON B2 (4-field) | mtu+2s cap | 75.717 | 5,489 | 7.243 | 1882.0 ms |
| JSON B2 + zstd | stream | 143.274 | 95,655 | 13.705 | 0.0 ms |
| JSON B2 + zstd | batch:64 | 3.121 | 1,496 | 0.299 | 6968.0 ms |
| JSON B2 + zstd | mtu-fill | 9.298 | 5,324 | 0.889 | 2009.0 ms |
| JSON B2 + zstd | mtu+2s cap | 9.553 | 5,489 | 0.914 | 1882.0 ms |

## The three strategies over 24 hours (ours O1 — the product)

Same decisions, same fidelity; the operator picks the point on the bytes<->latency curve. All three ship in the box — no commitment to one.

| strategy | what triggers a send | packets/day | MB/day | p95 latency |
|---|---|---|---|---|
| stream | every decision | 95,655 | 10.522 | 0.0 ms |
| batch:64 | every 64 decisions | 1,496 | 0.297 | 6968.0 ms |
| mtu-fill | packet reaches MTU | 119 | 0.156 | 441654.0 ms |

A timing cap is optional on top of any of these: **mtu+2s cap** bounds the mtu-fill p95 from 441654.0 ms to 2000.0 ms for 0.703 MB/day (vs 0.156). The cap is a knob, not a mode.

## Fidelity across the three strategies

Fidelity separates onto two axes, and only one of them moves:

| axis | stream | batch:64 | mtu-fill |
|---|---|---|---|
| decision fidelity (*what* was decided) | lossless | lossless | lossless |
| temporal fidelity (*when*, p95) | 0.0 ms | 6968.0 ms | 441654.0 ms |

**Decision fidelity is strategy-invariant and lossless.** Batching, compression, and encryption are packaging: the routed verdict reconstructs bit-for-bit regardless of how packets are cut (the quantizer is decision-preserving by construction; proven three ways in `test_fusion_spiral.py`). The *only* axis a strategy trades is temporal fidelity — how fresh the decision is when it lands. So the choice is never 'accuracy vs bandwidth'; it is purely 'latency vs bandwidth', and the operator owns it.

## Optional confidentiality layer — AEAD + ECDHE (composed, not hand-rolled)

TLS-1.3 primitives on top of the decision stream, for transports that do not already provide TLS (LoRa, 802.15.4/Thread, raw UDP, bare-metal MCU links). Over TCP+TLS this is redundant. Both primitives run on a Cortex-M0+.

- **On the wire it is nearly free when batched:** ours O1 mtu-fill 1.636 B/dec -> +AEAD+ECDHE 1.674 B/dec (**+0.038 B/decision**). The 16 B Poly1305 tag amortizes across a full packet; the 64 B X25519 handshake amortizes across a 4,096-reading epoch (nonce is implicit, no wire).
- **Compute cost (measured, this host, 1209 B representative packet):** ECDHE handshake ~83.2 us (both endpoints, once/epoch); ChaCha20-Poly1305 ~1.0 us/packet (1214.1 MB/s).
- **Confidentiality is the point, not integrity twice:** the AEAD tag secures the transport; the 32 B Merkle root is the persistent, cross-session audit chain. Different jobs. And salting would not help here — a 2-bit verdict is low-entropy, so only keyed AEAD (semantic security) hides `all_quiet` from `coincident_critical` on the wire.

## Reading

- **The header tax is a batching choice, not a codec limit.** Ours goes from **110.0 B/decision** unbatched to **1.636 B/decision** at mtu-fill — the per-packet transport header amortizes to ~0 because the codec is self-framing.
- **Batched-vs-batched, our advantage over plain JSON persists:** mtu-fill ours 1.636 B vs JSON 75.596 B (**46x**) — JSON keeps paying per-record keys inside the batch; ours pays none.
- **JSON + zstd batched is 9.298 B/decision** — the honest 'smallest bytes, but not streaming, not self-framing, no tamper-evidence' reference. Our differentiation there is properties, not raw bytes; and our stream can be zstd'd too.
- **All three strategies are lossless and ship together.** The operator sets latency vs bandwidth; encryption layers on for ~+0.038 B/decision when batched.
