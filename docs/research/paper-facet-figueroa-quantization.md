# Facet and Figueroa Quantization: ship the decision, not the data

**Draft for review.** A companion to the normative specification in [`../../PROTOCOL.md`](../../PROTOCOL.md)
and the flow format spec in [`../../SPEC.md`](../../SPEC.md). Every number in this paper traces to a
committed artifact, cited inline; the reference implementation is `adapters/telemetry/`.

## Abstract

Telemetry systems ship *data* (timestamped, typed records that describe themselves) and then spend
bandwidth, storage, and trust budget defending that data's integrity. We observe that for a system
governed by a **decidable match action policy**, almost none of that data can change a decision, and the
part that can is a small statistic we can characterize exactly. We define **Figueroa quantization**: the
map, derived from the policy and provably preserving its decisions, from a reading to the minimum
sufficient statistic for that policy's decisions, which *cell* of each field's domain the reading
occupies. We then define **Facet**, a wire protocol that carries Figueroa quantized symbols with a
codebook that is *agreed from the shared signed policy rather than transmitted*, a symbol coding that
frames itself, and tamper evidence anchored to an audit chain. On 64,484 representative fused decisions,
the Facet wire is **1.5 bytes/decision, 66.9× smaller than OpenTelemetry (OTLP) protobuf** (exact
measured O1 1.516 B/alert; 67.6× as recorded in the artifact, which rounds O1 to 1.5) and 4.7×
smaller than zstd compressed batched OTLP, while it still frames itself, streams, and shows tampering,
none of which a compressed record format provides. The reduction is *structural*, not a compression
trick: we transmit the decision, not a timestamped attribute bag. Decision preservation is machine
checked three ways against a frozen corpus.

## 1. The problem: telemetry ships the wrong thing

A general telemetry envelope such as OTLP carries, per record, a timestamp, typed attributes, and
repeated string keys. For a fused decision payload this is ~100 bytes/record and is *larger* than
minimal JSON (measured: 1.49×). This is not a defect of OTLP; it is a general observability envelope
doing its job. But when the consumer of the telemetry is a **policy** (a control plane that will route
each record to a decision), the envelope carries enormous redundancy: any two readings that route
identically are, to the policy, the same event. The question this paper answers is: *what is the
smallest thing you can send that preserves every decision, and can you send it without giving up
framing, streaming, or tamper evidence?*

## 2. Background: Level M match action policies

A PrismPath policy is an inert, inspectable document whose routing over a field changes truth only at
the constants that field is compared against (`field OP const`, the Level M fragment; see `SPEC.md`).
This is the property Figueroa quantization exploits, and it is what lets the quantization be *derived
from the policy itself* rather than guessed.

## 3. Figueroa quantization

### 3.1 Definition

Given a Level M policy, the **Figueroa quantization** of a reading is the tuple of its per field **cell
indices**, one symbol per decision relevant field, in canonical field order. A *cell* is a maximal set
of values of a field on which every policy atom has constant truth; two values in one cell route
identically through the entire policy. Fields the policy never tests are dropped: they cannot change a
decision, so they cannot appear on the wire. The result is the **minimum sufficient statistic for the
policy's decisions**: the classical notion of a sufficient statistic (Fisher), specialized to decision
equivalence and, crucially, *derived mechanically from the policy*.

### 3.2 Cell derivation

For each decision relevant field, collect its atoms `field OP const` across all deterministic, non
semantic edges. The constants cut the field's domain into fine intervals; evaluate a representative of
each and **merge adjacent intervals with identical atom truth vectors**, yielding the *coarsest*
partition that preserves every atom's truth. Three field kinds are auto detected: numeric (integer
intervals), boolean (two cells), categorical (one cell per constant plus a trailing "other"). Reference:
`adapters/telemetry/quantizer.py`.

### 3.3 The guarantee: decision preservation

**Reconstructing any representative of each cell and routing it through the policy reproduces every
decision the original reading produced.** This is the property everything rests on, and it is machine
checked three ways on a frozen corpus in `adapters/fusion/tests/test_fusion_spiral.py`: direct
evaluation, the full quantize → wire round trip → reconstruct → evaluation, and cell index → route, all
pinned to a `flow_sha256`, so a mapping bug anywhere flips a frozen entry and the suite goes red.

### 3.4 What is and isn't novel

Sufficient statistics and quotienting a state space by decision equivalence are classical. Unlike standard Vector Quantization (VQ) [Gray 1984], Figueroa quantization does not
place its boundaries to minimize geometric distortion or mean squared error; it places them exactly where
the policy's logic already cuts. The contribution is specific and mechanical: deriving that partition **directly and provably from a Level M
match action policy** (the same atoms the model checker and compiler read), so the minimal decidable
state code falls out of the policy itself with a machine checked guarantee it never mis-resolves a
decision.

## 4. The Facet protocol

Facet carries Figueroa quantized symbols. Its four design choices, specified normatively in
`PROTOCOL.md`:

- **Codebook agreement, not codebook transmission (§2.1).** Both endpoints derive the identical codebook
  by running the partitioner over the *same signed policy*. The only shared state is the policy, already
  versioned and integrity bound by the PrismPath pack machinery. A decode is valid only under the exact
  policy that produced the encode; a mismatch is rejected. This signed, versioned codebook, agreed out
  of band, is what makes Facet a protocol rather than a mere encoding.
- **A symbol coding that frames itself (§2.2).** Each symbol is sent as `symbol+1` under **Zeckendorf
  (Fibonacci) coding**, a standard code that delimits itself [Zeckendorf 1972]. With canonical field
  order, a reading carries no length header and no field tags. Zeckendorf coding is prior art, used, not
  claimed.
- **Lossless batching over any transport (§2.3).** Because it frames itself at the reading level,
  concatenation is lossless, so the `stream`, `batch:N`, and `mtu-fill` strategies trade only latency for
  bandwidth, never fidelity. Facet rides over TCP/TLS, UDP/DTLS, Thread, LoRa, ESP-NOW, or a bare MCU
  link. It is *not* a transport.
- **Tamper evidence and optional confidentiality (§2.4 and §2.5).** A 32 byte Merkle root per packet
  binds readings into an audit chain that spans sessions; an optional layer composes X25519 ECDHE and
  ChaCha20-Poly1305 (TLS 1.3 primitives, rekeyed per epoch) for transports without their own TLS.

## 5. Evaluation

### 5.1 Against OTLP (`adapters/fusion/bench/otlp_baseline.py`, `otlp_results.md`)

Over **n = 64,484** representative fused decisions, batched the way OTLP ships:

| wire | bytes/decision | notes |
|---|---:|---|
| OTLP faithful (protobuf) | 101.372 | industry standard telemetry envelope |
| OTLP faithful + zstd level 19 (batched) | 7.162 | |
| **Facet (O1, per field)** | **1.516** | frames itself, shows tampering |

**Facet is 67.6× smaller than OTLP protobuf** and 4.8× smaller than zstd compressed batched OTLP (as
recorded in `otlp_results.json`, which rounds O1 to 1.5 B/decision; the exact measured O1 of 1.516
B/alert, `results.json` and ledger #84, gives the conservative **66.9×** and **4.7×**, the figures to
quote under hostile review). The
reduction is *structural*: OTLP ships a timestamped, typed attribute bag; Facet ships the decision. A
general compressor on a verbose format narrows the raw byte gap but gives up framing, streaming, and
tamper evidence; the differentiator is those properties, not the byte count alone.

### 5.2 Framing and batching (`adapters/fusion/bench/wire.py`)

Because Facet frames itself, the transport header per packet amortizes to ~0 as a packet fills, so the
"header tax" is a latency choice, not a codec limit; batched against batched, Facet keeps its advantage
over plain JSON because JSON keeps paying per record keys inside the batch. The optional AEAD layer adds
less than a byte per decision when batched (a flat 16 byte tag amortized over a full packet, plus a 64
byte handshake amortized over a 4096 reading epoch).

### 5.3 Decision preservation

Proven three ways against the frozen corpus (§3.3). Decision fidelity is invariant under batching,
compression, and encryption; only temporal fidelity (freshness) varies with strategy.

## 6. Trust boundary

Facet's guarantees are precise, and the boundary is deliberate:

1. **Source authenticity (out of scope).** Whether a sensor read true or an upstream lied is the data
   provider's responsibility. Facet is a control plane wire, not a sensor.
2. **Integrity after a value enters: tamper *evident*, not tamper *proof*.** A Merkle root anchored to
   the audit chain makes alteration evident against a commitment no attacker can forge; the optional
   keyed layer rejects a tampered packet on the hop; codebook binding rejects any stream that does not
   decode under the exact signed policy. Without the keyed layer, integrity is evidence after the fact,
   not rejection in real time. Measured in `adapters/fusion/tests/test_wire_tamper.py`.
3. **Execution faithfulness (guaranteed).** For the input processed, the action provably matches the
   quantization of that value (§3.3), checked for conformance across every substrate.

## 7. Related work

*Sufficient statistics* (Fisher) and decision theoretic quotients are the conceptual root of §3.
*Zeckendorf/Fibonacci coding* [Zeckendorf 1972] is the code that frames itself in §4. *OpenTelemetry/OTLP*
is the general envelope baseline of §5. Self describing wire formats (protobuf, CBOR, JSON) frame per
record; Facet frames per stream via a shared codebook.

Two families of prior art sit closest to the quantization itself. Structurally, Figueroa quantization
shares a clear operational kinship with Product Quantization (PQ) [Jégou et al. 2011] by decomposing a
high dimensional state space into distinct, lower dimensional field subspaces and quantizing each
independently to form a compact tuple. However, it subverts the traditional PQ paradigm: instead of
learning codebooks via clustering algorithms to minimize reconstruction distortion, the codebook falls
out natively from the governing policy, and the optimization objective is the preservation of the final
decision rather than signal reconstruction.

A superficial parallel also exists in supervised discretization techniques (e.g., Fayyad-Irani MDL
binning [Fayyad and Irani 1993] or decision tree feature splitting), which also partition continuous
axes at class boundaries. However, while supervised discretization estimates bins from a labeled training
dataset to minimize empirical class entropy, Figueroa quantization extracts them deterministically from
an explicit, signed match action policy. It requires no statistical fitting or historic corpus; it is
exact by construction, yielding a machine checked proof that every potential decision is preserved.

We are not aware of a prior system that derives a
quantization that provably preserves decisions directly from a decidable match action policy and carries
it over a codebook agreed from the signed policy. The individual ingredients are all standard; we claim
only the composition and the machine checked quantization derived from the policy.

## 8. Conclusion

For a system governed by a decidable policy, the decision sufficient statistic is small, exact, and
derivable from the policy itself. Figueroa quantization computes it with a machine checked guarantee that
it preserves decisions; Facet carries it over a wire that frames itself and shows tampering, whose
codebook is agreed rather than transmitted. The result is a bandwidth reduction of more than an order of
magnitude that is structural rather than a compression trick, with framing, streaming, and audit
properties a compressed record format cannot offer.

## References

- É. Zeckendorf, "Représentation des nombres naturels par une somme de nombres de Fibonacci ou de nombres
  de Lucas," *Bull. Soc. Roy. Sci. Liège*, 1972.
- R. A. Fisher, "On the mathematical foundations of theoretical statistics," 1922 (sufficient statistics).
- R. M. Gray, "Vector Quantization," *IEEE ASSP Magazine*, 1984.
- H. Jégou, M. Douze, and C. Schmid, "Product Quantization for Nearest Neighbor Search," *IEEE Trans. Pattern Anal. Mach. Intell.*, 2011.
- U. M. Fayyad and K. B. Irani, "Multi-Interval Discretization of Continuous-Valued Attributes for Classification Learning," *Proc. IJCAI*, 1993.
- OpenTelemetry Protocol (OTLP) specification.
- PrismPath: `PROTOCOL.md` (Facet/1, normative), `SPEC.md` (flow format, Level M).

---

*Draft. Provenance: `adapters/telemetry/{quantizer,wire,zeckendorf,packed}.py`;
`adapters/fusion/bench/{otlp_baseline.py,otlp_results.md,wire.py}`;
`adapters/fusion/tests/{test_fusion_spiral,test_wire_tamper}.py`. Numbers: `otlp_results.md` (n = 64,484).*
