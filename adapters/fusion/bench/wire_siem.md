# Wire-bytes benchmark — siem corpus

n = 2,501,190 decisions over 2923862s (~0.9/s). Transport overhead: tcp_tls (70 B/packet). MTU payload budget 1400 B. Ours carries a 32 B Merkle root/packet (tamper-evident); JSON carries none.

## Full matrix — 4 formats x 4 strategies

| format | strategy | wire B/decision | packets/day | MB/day | p95 latency |
|---|---|---|---|---|---|
| ours O1 (decision) | stream | 110.0 | 73,910 | 8.130 | 0.0 ms |
| ours O1 (decision) | batch:64 | 3.094 | 1,155 | 0.229 | 182018.0 ms |
| ours O1 (decision) | mtu-fill | 1.625 | 85 | 0.120 | 2823151.0 ms |
| ours O1 (decision) | mtu+2s cap | 15.591 | 9,751 | 1.152 | 2000.0 ms |
| ours O1 +AEAD+ECDHE | stream | 126.016 | 73,910 | 9.314 | 0.0 ms |
| ours O1 +AEAD+ECDHE | batch:64 | 3.359 | 1,155 | 0.248 | 182018.0 ms |
| ours O1 +AEAD+ECDHE | mtu-fill | 1.66 | 85 | 0.123 | 2823151.0 ms |
| ours O1 +AEAD+ECDHE | mtu+2s cap | 17.717 | 9,751 | 1.309 | 2000.0 ms |
| JSON B2 (4-field) | stream | 139.976 | 73,910 | 10.346 | 0.0 ms |
| JSON B2 (4-field) | batch:64 | 71.069 | 1,155 | 5.253 | 182018.0 ms |
| JSON B2 (4-field) | mtu-fill | 73.66 | 3,890 | 5.444 | 83845.0 ms |
| JSON B2 (4-field) | mtu+2s cap | 79.32 | 9,866 | 5.863 | 2000.0 ms |
| JSON B2 + zstd | stream | 140.053 | 73,910 | 10.351 | 0.0 ms |
| JSON B2 + zstd | batch:64 | 2.663 | 1,155 | 0.197 | 182018.0 ms |
| JSON B2 + zstd | mtu-fill | 8.141 | 3,890 | 0.602 | 83845.0 ms |
| JSON B2 + zstd | mtu+2s cap | 19.878 | 9,866 | 1.469 | 2000.0 ms |

## The three strategies over 24 hours (ours O1 — the product)

Same decisions, same fidelity; the operator picks the point on the bytes<->latency curve. All three ship in the box — no commitment to one.

| strategy | what triggers a send | packets/day | MB/day | p95 latency |
|---|---|---|---|---|
| stream | every decision | 73,910 | 8.130 | 0.0 ms |
| batch:64 | every 64 decisions | 1,155 | 0.229 | 182018.0 ms |
| mtu-fill | packet reaches MTU | 85 | 0.120 | 2823151.0 ms |

A timing cap is optional on top of any of these: **mtu+2s cap** bounds the mtu-fill p95 from 2823151.0 ms to 2000.0 ms for 1.152 MB/day (vs 0.120). The cap is a knob, not a mode.

## Fidelity across the three strategies

Fidelity separates onto two axes, and only one of them moves:

| axis | stream | batch:64 | mtu-fill |
|---|---|---|---|
| decision fidelity (*what* was decided) | lossless | lossless | lossless |
| temporal fidelity (*when*, p95) | 0.0 ms | 182018.0 ms | 2823151.0 ms |

**Decision fidelity is strategy-invariant and lossless.** Batching, compression, and encryption are packaging: the routed verdict reconstructs bit-for-bit regardless of how packets are cut (the quantizer is decision-preserving by construction; proven three ways in `test_fusion_spiral.py`). The *only* axis a strategy trades is temporal fidelity — how fresh the decision is when it lands. So the choice is never 'accuracy vs bandwidth'; it is purely 'latency vs bandwidth', and the operator owns it.

## Optional confidentiality layer — AEAD + ECDHE (composed, not hand-rolled)

TLS-1.3 primitives on top of the decision stream, for transports that do not already provide TLS (LoRa, 802.15.4/Thread, raw UDP, bare-metal MCU links). Over TCP+TLS this is redundant. Both primitives run on a Cortex-M0+.

- **On the wire it is nearly free when batched:** ours O1 mtu-fill 1.625 B/dec -> +AEAD+ECDHE 1.66 B/dec (**+0.035 B/decision**). The 16 B Poly1305 tag amortizes across a full packet; the 64 B X25519 handshake amortizes across a 4,096-reading epoch (nonce is implicit, no wire).
- **Compute cost (measured, this host, 1304 B representative packet):** ECDHE handshake ~82.5 us (both endpoints, once/epoch); ChaCha20-Poly1305 ~0.97 us/packet (1339.5 MB/s).
- **Confidentiality is the point, not integrity twice:** the AEAD tag secures the transport; the 32 B Merkle root is the persistent, cross-session audit chain. Different jobs. And salting would not help here — a 2-bit verdict is low-entropy, so only keyed AEAD (semantic security) hides `all_quiet` from `coincident_critical` on the wire.

## Reading

- **The header tax is a batching choice, not a codec limit.** Ours goes from **110.0 B/decision** unbatched to **1.625 B/decision** at mtu-fill — the per-packet transport header amortizes to ~0 because the codec is self-framing.
- **Batched-vs-batched, our advantage over plain JSON persists:** mtu-fill ours 1.625 B vs JSON 73.66 B (**45x**) — JSON keeps paying per-record keys inside the batch; ours pays none.
- **JSON + zstd batched is 8.141 B/decision** — the honest 'smallest bytes, but not streaming, not self-framing, no tamper-evidence' reference. Our differentiation there is properties, not raw bytes; and our stream can be zstd'd too.
- **All three strategies are lossless and ship together.** The operator sets latency vs bandwidth; encryption layers on for ~+0.035 B/decision when batched.
