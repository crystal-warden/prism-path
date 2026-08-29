# The Facet protocol: specification

*Facet is PrismPath's decision exchange protocol: it ships the decision, not the data.*

*Naming note: Facet here is a wire protocol and is unrelated to the facet reflection crates in the
Rust ecosystem. PrismPath's own crates live under the `prismpath-*` prefix on crates.io.*

**Protocol version 1 (draft): `Facet/1`.** This document is the normative definition of how Facet
carries decisions between endpoints: the **Figueroa quantization** (the primitive that turns a reading
into a minimal symbol tuple that preserves the policy's decisions) and the framing, codebook agreement,
and tamper evidence that carry it.

**Relationship to the control plane.** PrismPath's control plane *decides*; Facet *carries* what it
decides. One signed policy powers both: the control plane runs it forward to reach a verdict, and Facet
derives its codebook from that same policy, so the wire only ever speaks in the distinctions the policy
can act on. The control plane and the protocol are not two systems bolted together; they are one signed
rulebook read two ways.

It is a companion to [`SPEC.md`](SPEC.md), which defines the PrismPath flow format and the Level M
predicate fragment. Facet *depends on* that spec: the codebook is derived deterministically from a
signed PrismPath policy, so the same design principle holds here: **the policy is data, and the wire
carries only what the policy makes decidable.** As in `SPEC.md`, the committed conformance fixtures and
the decision preservation tests are part of this specification: an implementation conforms to `Facet/1`
iff it reproduces them bit for bit.

The reference implementation is `adapters/telemetry/` (`quantizer.py`, `wire.py`, `zeckendorf.py`,
`packed.py`); the transmission model and the optional confidentiality layer are exercised in
`adapters/fusion/bench/wire.py`; decision preservation is proven in `adapters/fusion/tests/test_fusion_spiral.py`.

---

## 0. Terms

- **Reading**: a mapping of field names to values (an event, a sensor sample, a fused state).
- **Decision relevant field**: a field the policy actually routes on (appears in some `field OP const`
  atom of the Level M fragment). Fields the policy never tests cannot change any decision and are **not
  transmitted**.
- **Cell**: a maximal set of values of one field on which *every* policy atom has constant truth. Two
  values in the same cell route identically through the whole policy.
- **Symbol**: a cell index for one field, numbered from 0.
- **Codebook**: the set of per field partitions (`FieldPartition`) derived from a signed policy. The
  codebook is never transmitted; both endpoints compute it from the shared policy.
- **Epoch**: a fixed length run of readings (default 4096) that bounds codebook validity and, when
  the confidentiality layer is used, the rekeying boundary.

---

## 1. Figueroa quantization (the primitive)

**Definition.** Given a Level M policy, the Figueroa quantization of a reading is the tuple of its
per field **cell indices**, one symbol per decision relevant field, in canonical field order. It is the
**minimum sufficient statistic for the policy's decisions**: which cell each field falls in is exactly
what determines every routing outcome, and nothing else about the reading is transmittable without
carrying information the policy cannot act on.

**Cell derivation (normative).** For each decision relevant field, collect its atoms `field OP const`
(`OP ∈ {< <= > >= == != in "not in" truthy}`) across all deterministic, non semantic edges of the
policy. The compared constants cut the field's domain; the quantization takes the **coarsest** partition
on which every atom's truth is constant, by evaluating a representative of each fine interval and
merging adjacent intervals with identical atom truth vectors. Three field kinds are detected
automatically from the constants:

- **numeric (integer)**: order and/or equality atoms; cells are integer intervals `[lo, hi]`
  (either bound may be open). Representative = the low bound (or high, or 0).
- **boolean**: a bare `field` (truthiness) or `field == True/False`; exactly two cells.
- **categorical**: string `== != in "not in"` atoms; one cell per distinct constant plus a trailing
  **"other"** cell for every unlisted value.

A field mixing string and numeric constants is rejected; well formed Level M policies do not produce
one.

**Guarantee (I1, decision preservation).** Reconstructing *any* representative of each cell and routing
it through the policy reproduces every decision the original reading produced. This is proven three
ways in `test_fusion_spiral.py`; it is the property the whole protocol rests on.

**What is and isn't novel here (honesty).** The idea of a sufficient statistic [Fisher 1922]
(quotienting a state space by decision equivalence) is classical. The contribution named here is
specific and mechanical: deriving that partition **directly and provably from a Level M match action
policy** (the same atoms `model_check` and `ppt_compile` read), so the minimal decidable state code
falls out of the policy itself, with a machine checked guarantee that it never resolves a decision
wrongly. The self framing code in §2.2 is *not* part of this claim; it is a known code (Zeckendorf),
cited there.

---

## 2. The Facet protocol

### 2.1 Codebook agreement (no codebook on the wire)

Both endpoints derive the identical codebook by running `build_partitions` over the **same signed
policy**. The codebook is therefore agreed, not exchanged: the only shared state is the policy, which
is already versioned and integrity bound by the PrismPath pack machinery (`SPEC.md`; the pack's
`registry_hash` / policy hash). A decode is valid **only** under the exact policy that produced the
encode; a version or hash mismatch MUST be rejected, not decoded on a best effort basis (I3). This
binding (a shared, signed, versioned codebook agreed out of band) is what makes Facet a protocol rather
than a mere encoding.

### 2.2 Symbol coding (frames itself, zero header per reading)

Each symbol is transmitted as `symbol + 1` under **Zeckendorf (Fibonacci) coding** [Zeckendorf 1972], a
standard code that delimits itself: its `11` terminator makes each codeword frame itself. Because field
identity is fixed by **canonical (sorted) field order**, and each codeword delimits itself, a reading
carries **no length header and no field tags**: the stream is
`z.encode_stream([symbol+1 for each field in order])`, packed to bytes by `packed.pack`. Decoding
recovers the symbol count from the stream itself and MUST reject a stream whose symbol count differs
from the codebook's field count.

Zeckendorf/Fibonacci coding is prior art; it is used here, not claimed.

### 2.3 Framing, batching, and transport

Facet frames itself **at the reading level**, so batching is lossless: any number of readings
concatenate with zero framing between records. Three interchangeable transmission strategies ship
together and trade only *latency vs. bandwidth*, never fidelity (I5): `stream` (one packet per
decision), `batch:N` (flush every N), and `mtu-fill` (fill to the MTU, with an optional latency cap).
Facet is transport agnostic: it rides over TCP/TLS, UDP/DTLS, 802.15.4/Thread, LoRa, ESP-NOW, or a bare
MCU link. It is **not** a transport: it provides no delivery, ordering, or congestion control, and
depends on the underlying transport for those. For send-on-delta and resident-state streams, where a
lost frame is not merely a freshness cost, the refresh profile (§2.7) bounds the damage.

### 2.4 Tamper evidence

Each packet carries a **32 byte Merkle root** [Merkle 1987] binding its readings into a persistent audit
chain that spans sessions (`ledger_ots` / the airgap Merkle ledger; anchored via OpenTimestamps [OTS]).
This is integrity and non repudiation over time, a different job from the optional AEAD tag per packet
in §2.5, which secures a single transport hop.

### 2.5 Optional confidentiality (composed TLS 1.3 primitives)

For transports without their own TLS, a confidentiality layer composes standard primitives: **X25519
ECDHE** [RFC 7748] (a 64 byte handshake, rekeyed once per epoch) and **ChaCha20-Poly1305 AEAD**
[RFC 8439] (a 16 byte tag per packet; nonce implicit from epoch+index, never on the wire). Amortized
across a full packet and a 4096 reading epoch, this adds a small fraction of a byte per decision. Both
primitives run on a Cortex-M0+. These are TLS 1.3 building blocks used as is (composed, not hand
rolled), and are required precisely because a low entropy verdict (e.g. a 2 bit state) needs keyed AEAD,
not salting, to be hidden on the wire.

### 2.6 The spiral packing profile (optional capability, normative when declared)

A stream MAY declare the Tier 6 spiral packing, which packs a node's joint quantized cell space
onto a single ordered index whose contiguous ranges are the routes (band ID routes at one symbol;
Gray ordered refinement adds magnitude when the link affords it). The profile is derivation, not
configuration: the layout comes entirely from the signed policy, so it satisfies the founding
principle (agreed from the shared policy, never transmitted) exactly as the codebook does.

- **Declaration.** The flow declares `packing: spiral` in its frontmatter; the pack manifest
  carries `"packing": {"profile": "spiral", "sidecar_sha256": ...}` under the signature (see the
  secure hotswap spec §3.1).
- **Authoring rules, checked.** Severity order IS edge declaration order (most severe first), and
  the baseline catch all is the LAST deterministic edge of every packed node. Both are decidable
  and enforced as lint ERRORS on declared flows (`spiral-no-baseline`,
  `spiral-baseline-not-last`): a convention violating flow fails `validate` and cannot be baked,
  in every materialization.
- **Two materializations, one layout.** Capable endpoints DERIVE the layout from the signed policy
  at load. Small targets receive the BAKED sidecar (v1, little endian: per node field partitions,
  numeric and boolean only; band bases, widths, and route map; cell to index map in row major
  order for O(1) lookup) inside the pack they already verify. Derived and baked MUST be byte
  equal; the reference referee is `spiral_pack.verify_derived_equals_baked`, and `verify_pack`
  re hashes the sidecar against the signed manifest at load, so a tampered or missing sidecar
  fails closed.
- **Tier classes.** Band tier frames are decision lossless and ride the highest priority; Gray
  refinement frames are fidelity and yield first. The transport binding maps priority to the
  link's scarcity: cadence on lossy datagram links (band every tick, refinement opportunistic),
  queue precedence on reliable streams. A collapsing link costs fidelity, never the decision.
- **Stream identity is a binding concern.** Where the transport authenticates or identifies the
  sender (ESP-NOW sender MAC, a TCP connection), identity SHOULD ride the transport at zero frame
  cost; where it does not (raw LoRa PHY, files), the binding puts an explicit stream tag in frame.
  The reference datagram binding (ESP-NOW v1) is payload = a Zeckendorf stream of
  `[class, tick, value]`, each offset by one; class 1 band tier, class 2 refinement, class 3
  posture gossip (the joint cell as a fleet coherence beacon).

### 2.7 The refresh profile (bounded staleness under loss; optional capability, normative when declared)

For a stateless per-reading stream, a lost frame costs freshness only (I5). For a **send-on-delta**
stream, or any consumer mirroring a **resident state**, loss is sharper: a lost change frame leaves the
consumer holding a *wrong* state, silently, for unbounded time, because silence and "unchanged" are
indistinguishable on the wire. The refresh profile bounds that window. It changes **cadence, never
bytes**: a keyframe is byte-identical to any other frame, so a stream under this profile is a valid
`Facet/1` stream without it, stream conformance (§4) is unchanged, and the protocol version does not
move.

- **Declaration.** The flow declares two frontmatter keys, `refresh_keyframe_ms` and
  `refresh_stale_ms` (positive integer milliseconds). Frontmatter is part of the signed document, so
  the cadence contract rides under the signature like every other profile; nothing is derived or baked,
  so no sidecar is needed. Checked as lint rules on declared flows: both keys required and integer
  (`refresh-missing-param`, `refresh-bad-param`, ERROR), `stale >= keyframe` (`refresh-stale-bound`,
  ERROR: otherwise a lossless link trips stale between keyframes), and `stale >= 2 * keyframe` SHOULD
  hold (`refresh-stale-tight`, WARNING: below it a single lost keyframe parks the consumer on the
  fail-safe).
- **Sender contract.** A declared sender MUST emit its current full state at least every
  `refresh_keyframe_ms`, even when unchanged, in addition to emitting on change.
- **Consumer contract.** A declared consumer MUST treat received state older than `refresh_stale_ms`
  as stale: it MUST NOT act on the last received value and MUST act on the policy's signed fail-safe
  instead, the same fail-safe the stateful migration path uses. The next valid frame restores fresh
  state. Both transitions (fresh to stale, stale to fresh) SHOULD be receipted with a distinct cause.
- **Baked targets.** Carrying the two parameters inside the pack for targets that do not parse the
  flow document is specified as follow-up work and is not yet normative; endpoints that adopt sender
  emission changes on certified substrates re-certify under the usual discipline.

The reference implementation is `adapters/telemetry/refresh.py` (clockless: callers pass monotonic
milliseconds); the referee is `adapters/fusion/tests/test_refresh_profile.py`, which first demonstrates
the unbounded wrong-state window without the profile, then proves I6 under single loss, burst loss,
total blackout, and recovery.

### 2.8 The replay window (normative for tick-carrying bindings)

Replay is handled at three levels, and the honest statement of each is part of the spec. Under the
keyed layer (§2.5), replay is dead on arrival: the AEAD nonce is implicit from epoch+index, so a
replayed packet fails authentication. On a **bare-profile stream whose transport binding carries a
per-frame tick** (the ESP-NOW spiral binding's `[class, tick, value]`, §2.6), a consumer MUST apply a
tick window: a frame whose tick is not strictly newer than the highest accepted tick is rejected,
except that a binding declaring a reorder tolerance of `W` accepts a late tick iff it lies within the
last `W` ticks and has not been seen (the IPsec/DTLS sliding-window shape; default `W = 0`, exact for
single-hop links that cannot reorder). Rejections carry a distinct cause, `replay-duplicate` or
`replay-stale`, so a receipt can say which check refused the frame. And a **bare datagram stream with
no tick-carrying binding has no replay protection at all**: the keyed layer is the answer there, and
this specification does not pretend otherwise.

The window composes with the refresh profile (§2.7): a captured keyframe replayed after the stream
moved on would otherwise regress the consumer's mirrored state; behind the window it is rejected as
`replay-stale`. The tick is the same monotonic counter the receipt trail carries as `seq` where both
exist; a binding SHOULD NOT run two counters. The window is receiver-side state over bytes already on
the wire: no frame format changes, stream conformance (§4) is unchanged. Not claimed: the window is
replay rejection, not authentication — a forger who can construct valid frames can construct fresh
ticks; origin trust remains the keyed layer's or the transport's job (§6). Reference implementation
`adapters/telemetry/replay.py`; referee `adapters/fusion/tests/test_replay_window.py`.

### 2.9 The concentrator profile (optional capability for bridge uplinks)

The honest arithmetic first: a 2 to 3 byte decision inside a 28 byte IP+UDP envelope is
header-dominated, so on an unconstrained IP link the per-datagram win over a verbose format is
smaller than the payload arithmetic suggests. The concentrator is the answer where fleets uplink
through a bridge: records from many streams concatenate into ONE datagram, amortizing the envelope
across the fleet. A concentrated frame is a sequence of records `[stream_id][reading]`, packed
bit-contiguously and padded to the byte only at the datagram: the stream id is itself
Zeckendorf-coded (ids from 1), and the reading carries no length because the stream's codebook fixes
its field count — codebook binding (I3) does the framing, so the zero-header property survives
aggregation. A stream MAY appear multiple times in one datagram (a burst since the last uplink tick).

- **Registry.** The demultiplexer holds a registry mapping stream id to the stream's signed policy
  (hence its field count and codebook), agreed out of band exactly as the codebook itself (§2.1). The
  id-to-policy binding is bridge configuration and SHOULD ride a signed artifact.
- **Strict, fail-closed, whole-datagram.** An unknown stream id or a record truncated mid-reading
  rejects the ENTIRE datagram with a distinct cause (`concentrator-unknown-stream`,
  `concentrator-truncated`); trailing zero pad is the only legal tail. Partial delivery is forbidden:
  a datagram that demuxes differently at two consumers is worse than a lost one.
- **Composition.** Inner records are the output of existing conforming encoders; this layer never
  re-encodes, so the certified codec paths are untouched. The kernel decode plane (v1) does not parse
  concentrated frames; they demux in userspace or in a future decode-plane revision.

Measured, frozen in the referee (28 byte IP+UDP envelope; link-layer framing varies by medium and is
excluded): a 3-field reading costs 30 bytes per reading as per-node datagrams at any fleet size,
versus 15.50 at fleet 2, 4.30 at fleet 10, and 2.06 at fleet 50 concentrated. At fleet size one the
concentrator is pure cost (the stream id buys nothing) and is not the profile's use case. Reference
implementation `adapters/telemetry/concentrator.py`; referee `adapters/fusion/tests/test_concentrator.py`.

### 2.10 Receipt streams (cause code carriage; optional capability, normative when declared)

A receipt stream carries decision receipts over the wire, making refusal and deviation causes machine readable across endpoints. The profile carries the fields proven by the kernel receipt struct: decision identifiers (`prev_node`, `event`, `next_node`), the frame sequence tick (`seq`), and the refusal or deviation cause byte (`cause`) defined in the cause code registry (`docs/design/spec-cause-codes.md`).

- **Declaration.** A receipt stream is declared the way every stream is declared: the stream's
  signed codebook fixes exactly these five fields and their canonical order, agreed out of band
  like the codebook itself (§2.1). No new frontmatter key and no new mechanism; a consumer whose
  binding carries this field set applies this section's semantics.
- **Canonical field order.** Fields ride in sorted field name order: `cause`, `event`, `next_node`, `prev_node`, `seq`.
- **Cause carriage and density.** The cause code IS the symbol, carried under the standard
  symbol plus one wire mapping (§2.2) with no special casing. Cause 0 (a clean decision) therefore
  rides as wire integer 1 (`11`), the densest code on the wire; the whole u8 registry space (0 to
  255) is representable.
- **Composition.** Receipt streams compose cleanly with existing declared profiles:
  - **Replay window (§2.8).** The `seq` field serves as the tick counter. Receiver tick checking rejects duplicate or stale receipts with `replay-duplicate` or `replay-stale`.
  - **Concentrator (§2.9).** Receipt readings aggregate into concentrated datagrams. Codebook binding and Zeckendorf self framing preserve zero header framing across aggregated receipt streams.
- **Out of scope.** This profile is cause carriage on the wire, not a full audit log schema. Carrying per reading Merkle proof paths, raw 64 bit nanosecond timestamps (`t_ns`), 64 bit policy hashes, or raw sensor payloads on every frame is explicitly out of scope. Session integrity rides the Merkle root (§2.4) and policy binding rides codebook agreement (§2.1).

Reference implementation `adapters/telemetry/receipts.py`; referees
`adapters/telemetry/tests/test_receipts.py` (frozen vectors,
`adapters/telemetry/conformance/receipts.json`) and
`adapters/fusion/tests/test_receipts_profile.py` (profile composition).

---

## 3. Normative invariants

- **I1 (decision preservation).** `reconstruct(quantize(reading))` routes identically to `reading`
  through the policy. (Proven: `test_fusion_spiral.py`.)
- **I2 (frames itself).** A reading carries no length header and no field tags; decode recovers the
  symbol count from the stream and the field identities from canonical order.
- **I3 (codebook binding).** A stream is decodable only under the exact signed policy that produced
  it; a policy version/hash mismatch MUST be rejected.
- **I4 (tamper evidence).** Each packet's Merkle root binds its readings into the audit chain.
- **I5 (strategy invariance).** Decision fidelity is invariant under batching, compression, and
  encryption; only temporal fidelity (freshness) varies with strategy.
- **I6 (bounded staleness, refresh profile only).** Under a declared refresh profile, at any instant a
  consumer's acting state is the sender's current state, a state the sender held within the last
  `refresh_stale_ms`, or the policy's signed fail-safe. (Proven under injected loss:
  `test_refresh_profile.py`.)

---

## 4. Conformance

An implementation conforms to `Facet/1` iff, for the committed policies and fixtures, it (a) builds a
byte identical codebook, (b) produces byte identical Facet streams (Figueroa quantization, then
Zeckendorf coding and word packing), (c) round trips every reading with the decision preserved (I1),
and (d) rejects the negative cases required by I2/I3. The reference implementation is the Python
`adapters/telemetry/` kernel; conformance is defined against its committed outputs, exactly as `SPEC.md`
defines flow format conformance against `prismpath/portable/conformance/`.

---

## 5. Versioning and scope of claims

`Facet/1` is the first protocol version. A change that alters any byte of a conforming stream is a new
protocol version. The codebook additionally carries the policy's own version/hash (§2.1), so a stream
is pinned to *both* the protocol version and the exact policy.

Note that `Facet/1` versions the **wire protocol** (the byte stream) and is a distinct axis from the
**flow format spec version** in `SPEC.md` (the document grammar and predicate language). A policy
authored under one flow format spec version can be carried by any compatible protocol version, and vice
versa.

**Not claimed, on purpose.** Facet is not encryption (confidentiality is an optional, composed
TLS 1.3 layer), not a transport (§2.3), and not general purpose compression: it is smaller than a raw
stream only because it transmits the decision sufficient statistic, and a general compressor applied to
a verbose format can reach fewer bytes while giving up self framing, streaming, and tamper evidence. The
nameable contributions are exactly two: **Figueroa quantization** (the partition, derived from the
policy, that provably preserves decisions) and the **Facet protocol** itself (the agreed codebook wire
that frames itself and shows tampering). Every underlying primitive (Zeckendorf coding, Merkle roots,
X25519, ChaCha20-Poly1305) is standard and cited in §7.

---

## 6. Threat model and trust boundary

Facet's guarantees are precise, and its boundary is deliberate. Three tiers, from outside in:

1. **Source authenticity (out of scope).** Whether a sensor read true, or an upstream did not lie, is
   the data provider's responsibility. Facet is a control plane wire, not a sensor; authenticating the
   origin of a *reading* is neither possible nor claimed here. Garbage in is decided and attested
   faithfully, as garbage.

2. **Integrity after a value enters: tamper *evident*, not tamper *proof*.** Precision matters:
   - The **bare codec is self checking but not integrity.** Because it frames itself (§2.2) a corrupted
     stream is overwhelmingly rejected outright (a broken `11` frame or a symbol out of range), but not
     always: some single bit flips silently alter the decision statistic, and a *well formed* stream for
     a different reading is accepted verbatim, because the codec has no notion of origin. Measured in
     `adapters/fusion/tests/test_wire_tamper.py`.
   - The **keyed layer (§2.5) provides real integrity in transit.** With AEAD, *every* tamper of the
     packet is rejected (Poly1305). This is the guarantee against an active attacker in transit; the
     bare codec is not a substitute for it.
   - The **Merkle root (§2.4), anchored via OpenTimestamps, provides evidence after the fact** relative
     to a commitment no attacker can forge: a tampered reading's leaf no longer verifies against the
     committed root. And **codebook binding (I3)** rejects any stream that does not decode under the
     exact signed policy.

   In short: rejection in real time needs the keyed layer; non repudiation over time comes from the
   anchored root; the bare wire alone is self checking, not integrity. Never describe Facet as
   "tamper proof."

   Replay sits in this tier and follows the same gradient (§2.8): the keyed layer rejects it
   outright; a tick-carrying binding rejects it via the mandatory tick window; a bare datagram
   stream with neither has no replay protection, and no claim to any.

3. **Execution faithfulness (guaranteed).** For the input Facet processes, the action provably matches
   the Figueroa quantization of that value (I1, proven three ways in `test_fusion_spiral.py`), decided
   byte identically on every certified substrate.

One line statement: *Facet decides and attests faithfully over the input it is given; it rejects
tampering in transit under the keyed layer and makes it evident after the fact under the anchored root;
it does not vouch for the truth of the input's source.*

---

## 7. References

Facet composes standard primitives; each is cited here, matching the "used, not claimed" statements
above. The two nameable contributions (Figueroa quantization and the Facet protocol) are absent from
this list on purpose: they are the novel part.

- **[Zeckendorf 1972]** E. Zeckendorf, "Representation des nombres naturels par une somme de nombres de
  Fibonacci ou de nombres de Lucas," *Bull. Soc. Roy. Sci. Liege* 41, 1972. (symbol code that frames itself, §2.2)
- **[Fisher 1922]** R. A. Fisher, "On the mathematical foundations of theoretical statistics,"
  *Phil. Trans. R. Soc. A* 222, 1922. (sufficient statistics, the root idea behind §1)
- **[Merkle 1987]** R. C. Merkle, "A Digital Signature Based on a Conventional Encryption Function,"
  *CRYPTO '87*. (the audit chain root, §2.4)
- **[FIPS 180-4]** NIST, "Secure Hash Standard (SHS)," FIPS PUB 180-4, 2015. (SHA-256, used for the
  Merkle leaves and hash chaining)
- **[OTS]** OpenTimestamps, <https://opentimestamps.org>. (Bitcoin anchoring of the root, §2.4)
- **[RFC 8439]** Y. Nir, A. Langley, "ChaCha20 and Poly1305 for IETF Protocols," RFC 8439, 2018.
  (the optional AEAD, §2.5)
- **[RFC 7748]** A. Langley, M. Hamburg, S. Turner, "Elliptic Curves for Security," RFC 7748, 2016.
  (X25519 ECDHE, §2.5)
- **[SPEC.md]** The PrismPath flow format and Level M predicate fragment, this repository. (the policy
  the codebook is derived from)

---

*Draft `Facet/1`. Provenance: `adapters/telemetry/{quantizer,wire,zeckendorf,packed}.py`,
`adapters/fusion/bench/wire.py`, `adapters/fusion/tests/{test_fusion_spiral,test_wire_tamper}.py`.
Companion to `SPEC.md`.*
