# What a heartbeat costs

This note gives the measured size of a signed state record (spec-policy-distribution.md, H1) with and
without the Facet body of H5, on the four agent policies the package ships as starters. It was measured on
2026-11-22 with `prismpath.distribution.heartbeat.body` at the band tier of PROTOCOL.md section 2.6.1.

## How it was measured

For each starter the readings are 64 picks, with a fixed seed, from the classes of its finite reading domain
(`profile.domain_classes`), one value of each class drawn at random. The body was built for the first 0, 1,
16 and 64 of them. A record with no body and no extensions is 212 bytes, which is the 144 byte header, the two
length fields and the 64 byte signature. A record with a body adds the body's length.

## The numbers

| Starter | Decision nodes | Body, 0 decisions | 1 | 16 | 64 | Record with 64 decisions |
|---|---|---|---|---|---|---|
| strict | 1 | 42 | 43 | 55 | 93 | 305 |
| default | 1 | 42 | 43 | 56 | 94 | 306 |
| review | 1 | 42 | 43 | 56 | 97 | 309 |
| session | 1 | 42 | 43 | 55 | 95 | 307 |

All sizes are bytes. The 42 bytes of an empty body are the preamble, which names the policy and the layout,
so even a record with no decision in it lets the controller check the policy by its hash. Each decision then
costs between 6.4 and 6.9 bits, the band of the route the policy's one decision node fired. A heartbeat every
30 seconds that carries its full 64 decisions is about 310 bytes, against 212 bytes for one with no body.

## What it means

The body costs about 100 bytes a record at most on these policies, well inside the 1,024 bytes H1 allows, so
a PEP never drops a decision for room on them. The preamble alone costs 42 bytes a record. A PEP that sends a
record after every decision pays it each time, which is why H5 batches up to 64 decisions into one record.
