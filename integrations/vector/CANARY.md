# Canary a Facet migration

Run Facet beside the pipeline you trust, not instead of it. One Vector source fans out to your
existing sink unchanged and to a Facet sink; an aggregator decodes the Facet wire back to events;
a verifier proves the decoded leg routes **identically** to the raw leg on your real traffic.
Nothing about your current pipeline changes until the verifier says PARITY, and rolling back is
deleting one sink block. Your Vector routes are your codebook, so the canary is also the proof
that the codebook you derived is the policy you already run.

## Step 0: preflight the sample (no Vector needed)

```
python ../../adapters/telemetry/preflight.py <flow.md> <sample.ndjson>
```

Or the Rust twin, which runs on the same crates the codec is built from:

```
cargo run -q -p prismpath-preflight -- <flow.md> <sample.ndjson>
```

One command answers whether your events encode at all, what the wire will cost, and whether every
route survives the round trip. Fix anything it flags before spending a canary on it. If you are
migrating from route or filter transforms you already run, `facet_init.py` drafts the flow from
your `vector.toml` first (the tool drafts, you sign).

## Step 1: fan the edge out to both legs

Add ONE sink beside the one you already have; the source and your existing sink stay untouched.

```toml
[sources.events]            # your existing source, unchanged
type = "stdin"
decoding.codec = "json"

[sinks.raw_leg]             # your existing sink, unchanged: this is the pipeline of record
type = "console"
inputs = ["events"]
encoding.codec = "json"

[sinks.facet_leg]           # the canary: the only new block
type = "socket"
inputs = ["events"]
mode = "tcp"
address = "127.0.0.1:19310"
encoding.codec = "facet"
encoding.policy = "../../adapters/fusion/flows/fusion_triage.md"
```

During the canary you pay for both wires; the Facet leg adds about 2 bytes per event on this
policy. Pin the policy with `encoding.policy_sha256 = "<hex>"` so neither leg can drift to an
edited flow without failing loudly. Nested event shapes map with `encoding.field_paths.<field> =
"json.dot.path"`. In a real deployment the raw capture is whatever sink you already run (file,
S3, your SIEM); here `console` redirected to a file keeps the demo to one binary.

## Step 2: decode the Facet leg

```toml
[sources.facet_in]
type = "socket"
mode = "tcp"
address = "127.0.0.1:19310"
decoding.codec = "facet"
decoding.policy = "../../adapters/fusion/flows/fusion_triage.md"
decoding.route_node = "correlate"        # the decision node whose route you want carried
framing.method = "length_delimited"
framing.length_delimited = {}

[sinks.out]
type = "console"
inputs = ["facet_in"]
encoding.codec = "json"
```

Each decoded event carries the reconstructed decision fields plus `facet_route`, the target the
policy routes to at `route_node`. Capture both legs:

```sh
vector -c canary_agg.toml  > decoded.ndjson &      # aggregator first, so the socket is listening
python3 gen_events.py 400 | vector -c canary_edge.toml > raw.ndjson
```

## Step 3: verify route parity

```
python canary_verify.py <flow.md> --raw raw.ndjson --decoded decoded.ndjson --route-node correlate
```

The verifier replays every raw event through the reference implementation (the same one the codec
is parity tested against), computes the route the policy takes on it, and diffs against what the
decoded leg actually carried: event counts, every position, and the per route distributions. A
live run of exactly the configs above, 400 events across seven routes:

```
| route                 | raw leg | decoded leg |
| all_quiet             | 5       | 5           |
| coincident_critical   | 142     | 142         |
| cyber_containment     | 63      | 63          |
| cyber_watch           | 16      | 16          |
| physical_escalation   | 84      | 84          |
| physical_watch        | 35      | 35          |
| tandem_watch          | 55      | 55          |

**PARITY.** Every decoded route matches the raw leg.
```

Flipping one event's `rule_level` across a threshold makes the verifier name the exact position
and both routes, print NO PARITY, and exit 1, so the check drops straight into CI or a cron
during the soak. Exit 0 means parity; anything else means do not cut over.

## Step 4: cut over, keep the parachute

Once the canary has held parity for as long as your change control wants, point the consumers at
the decoded leg and drop the raw sink block, or keep it fanned out indefinitely: the raw leg IS
the rollback path, and re adding one sink block restores it.

## What a mismatch means

The codec is deterministic, so daylight between the legs is configuration, not chance: a flow
version skew between edge and aggregator (pin `policy_sha256` on both), `field_paths` on the
encoder that the verifier was not given (pass the same `--map`), or raw events the encoder
dropped (`on_missing`) desynchronizing positions, which shows up as count drift.

## Honest scope

- The decoded leg carries cell representatives, not original magnitudes: routes are preserved
  exactly, raw values are not reconstructable. Consumers that need the original bytes keep
  reading the raw leg; that is the design, not a limitation of the canary.
- Positional comparison assumes each leg preserves stream order (true for one source feeding one
  sink over one connection). Across reconnects, trust the count and distribution checks and rerun.
- Numeric fields compare on truncated integers, and integer exactness holds through 2^53
  (IEEE 754 double). Preflight counts how often truncation touches your sample.
