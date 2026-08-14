# Bandwidth · raw alert JSON vs the fused decision wire

Source: live:alert-backlog  ·  population: rule.level >= 7, n = 64,484

Task frame: the aggregator needs the fused verdict, auditably. Baselines ship the
reading and decide centrally; ours decides at the edge and ships the decision code.
The decision streams are decision sufficient, not a lossless alert record: B2 is the
apples-to-apples ratio, B0 the fidelity-class one.

| line | what | total bytes | bytes/alert |
|---|---|---|---|
| B0 | full _source JSON | 194,766,714 | 3020.4 |
| B1 | normalized alert JSON | 42,590,251 | 660.5 |
| B2 | 4-field minimal JSON | 4,388,366 | 68.1 |
| B3 | zlib9_bytes over B0 NDJSON batch | 7,957,163 | 123.4 |
| B3 | zstd19_bytes over B0 NDJSON batch | 4,037,604 | 62.61 |
| B3 | zlib9_bytes over B2 NDJSON batch | 20,147 | 0.31 |
| B3 | zstd19_bytes over B2 NDJSON batch | 14,098 | 0.22 |
| O1 | per field decision stream + epoch apparatus | 97,752 | 1.516 |
| O2 | band-ID stream + epoch apparatus | 33,280 | 0.516 |

O1 detail: payload 773,808 bits, pad 16 bits, epochs 16 (Merkle+chain 1024 B, ACK return-channel 512 B).
O2 detail: payload 257,939 bits, pad 109 bits.

## Loss (selective repair, proofs paid on serve)

| stream | regime | lost/total blocks | repair bytes |
|---|---|---|---|
| O1 | light burst | 40/756 | 17,920 |
| O1 | heavy burst | 167/756 | 74,816 |
| O2 | light burst | 19/252 | 7,296 |
| O2 | heavy burst | 67/252 | 25,728 |

## Reading (go/no-go)

- O1 vs B2 (apples-to-apples): **45x** smaller (gate: >= 10x).
- O1 vs B0 (fidelity-class): **1,992x** smaller (gate: >= 500x).
- O2 <= O1: yes.
- B3 note, stated before anyone else states it: the best batch compressor over the
  minimal JSON (0.22 B/alert) undercuts the streams on pure
  size. It requires buffering the whole batch before a byte ships, is not
  self framing or per reading streamable, and carries no tamper evidence; the
  buffered-batch bound, not a transport. The streams pay their integrity apparatus
  and still land within striking distance of it.
- Overheads are itemized above and included in every ratio; the ACK line is the
  return channel and is reported, not folded in.

## Verdict: **PASS**

_generated in 38.6s_
