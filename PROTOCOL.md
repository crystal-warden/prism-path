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
depends on the underlying transport for those.

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
