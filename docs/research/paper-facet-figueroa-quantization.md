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
the Facet wire is **1.516 bytes/decision (integrity apparatus counted), 66.9× smaller than
OpenTelemetry (OTLP) protobuf** and 4.7×
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

**Boundary mechanics and precision.** Open versus closed never survives to the wire, because the
comparison domain is discretized first. Non integer numerics are truncated toward zero before
quantization (the reference and both deployed implementations share this conversion), so every
comparison happens over the integers, where each strict cut converts exactly to a closed bound
(`x < c` is `x <= c - 1`): cells are closed integer intervals, unbounded only at the extremes. The
exactness window is that of the double precision integer range: values are exact through 2^53, and
beyond it both endpoints round identically through f64, so decisions stay consistent while absolute
integer exactness is out of scope. None of this is asserted from design alone: a frozen boundary
corpus (`adapters/telemetry/conformance/boundary.json`) probes every threshold edge at t - 1, t,
and t + 1 across cuts from 10^2 to 10^12, plus 2^53 - 1, 2^53, 2^53 + 2, and 10^15, and twin tests
replay it in the Python reference and the Rust crates; a symbol drift on either side of any
boundary in either implementation turns the suite red.

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

### 3.5 Formal statement

Sections 3.1 to 3.3 stated precisely. A reading is `x = (x₁, …, x_N)` in the product domain
`𝒳 = 𝒳₁ × … × 𝒳_N`, one coordinate per field. A Level M policy `𝒫` decomposes into a finite atom set

```
Atoms(𝒫) = { α₁, …, α_A }
```

where each atom `αⱼ` tests a single field `fⱼ` against a literal constant `cⱼ`, that is
`αⱼ(x) = [ field fⱼ of x  ▷ⱼ  cⱼ ]`, with `▷ⱼ ∈ { <, ≤, >, ≥, =, ≠, ∈, ∉, truthy }` (comparisons that
are field against field, or against a non literal, carry no cut and lie outside the fragment). The
decision is a function of the atom truth vector,

```
D(x) = Δ( α₁(x), …, α_A(x) ),
```

where `Δ` is the flow's first match edge logic.

**Definition (Figueroa quantization).** For each field `f` let `A_f` be the atoms over `f`, and define
`u ~_f u'` iff `α(u) = α(u')` for every `α ∈ A_f`. Let

```
q_f : 𝒳_f → 𝒞_f = 𝒳_f / ~_f
```

send a value to its class. `q_f` is the coarsest partition of `𝒳_f` on which every atom of `A_f` is
constant; for a numeric field it is a monotone step function that increments at each constant compared
against `f`, with adjacent intervals of identical atom truth merged (§3.2). The Figueroa quantization is
the product map over the decision relevant fields (a field with `A_f = ∅` is dropped, as it cannot
change a decision):

```
𝒬_F : 𝒳 → 𝒞 = 𝒞₁ × … × 𝒞_N,      𝒬_F(x) = ( q₁(x₁), …, q_N(x_N) ).
```

**Theorem (decision preservation).** For all `x, x' ∈ 𝒳`,  `𝒬_F(x) = 𝒬_F(x')  ⟹  D(x) = D(x')`.

*Proof.* `𝒬_F(x) = 𝒬_F(x')` gives `q_f(x_f) = q_f(x_f')` for every field `f`, so by the definition of
`~_f` every atom agrees: `αⱼ(x) = αⱼ(x')` for all `j`. The atom truth vectors coincide, hence
`D(x) = Δ(atoms(x)) = Δ(atoms(x')) = D(x')`. Equivalently `D` factors as `D = D̄ ∘ 𝒬_F` for a unique
`D̄ : 𝒞 → actions`, whose image has `K ≤ |𝒞|` distinct actions, the decision classes the policy induces
on the cell tuples. ∎

This is exactly the property the §3.3 conformance suite checks on the frozen corpus: a mapping error
would produce some `x, x'` with `𝒬_F(x) = 𝒬_F(x')` yet `D(x) ≠ D(x')`, flipping a pinned entry.

**Minimal sufficiency.** `𝒬_F` is a sufficient statistic for `D` (the decision factors through it) and
is minimal among per field product statistics that preserve every atom: each `q_f` is the coarsest `~_f`
partition, so merging any two of its cells flips an atom and may flip a decision. A statistic strictly
coarser than `𝒬_F` can exist only if two distinct cell tuples always yield the same action; collapsing
those is a property of `D̄`, and computing it in general is the policy equivalence problem. Figueroa
quantization stops at the per field cells because that layer is exact, field local, and composable
across independently signed policies.

**Corollary (wire cost).** Since `D = D̄ ∘ 𝒬_F`, transmitting `𝒬_F(x)` reproduces every decision, at a
cost bounded by the cell counts alone:

```
bits(x) = ⌈ log₂ |Im 𝒬_F| ⌉  ≤  Σ_f ⌈ log₂ |𝒞_f| ⌉,
```

independent of the sensor's bit depth or sample rate. The map is decision lossless and magnitude lossy:
`D̄` recovers the decision exactly, while only a cell representative, not the original value, is
recoverable. Section 5 measures this bound on the reference corpus.

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

Composing the two halves gives the guarantee the protocol exists to provide.

**Proposition (end to end decision preservation).** Under the codebook agreed from the shared signed
policy, Facet decodes a reading to exactly its Figueroa symbol `𝒬_F(x)`, so by the decision preservation
theorem (§3.5) the decision the receiver computes, `D̄(𝒬_F(x))`, equals `D(x)`, the decision the source's
reading produced. Transport corruption cannot silently change a decision: it is made evident by the per
packet Merkle root, or rejected outright under the optional AEAD.

*Proof.* Codebook agreement makes the decoder's partition identical to the encoder's, and the self
framing symbol coding recovers the symbol tuple without ambiguity, so a decoded reading yields the same
`𝒬_F(x)` that was sent. Theorem 3.5 gives `D = D̄ ∘ 𝒬_F`, hence `D̄(𝒬_F(x)) = D(x)`. A packet whose bytes
were altered fails the per packet Merkle root check (evidence after the fact) or the AEAD tag (rejection
on the hop), so an altered reading is never silently decoded to a different decision. ∎

## 5. Evaluation

### 5.1 Against OTLP (`adapters/fusion/bench/otlp_baseline.py`, `otlp_results.md`)

Over **n = 64,484** representative fused decisions, batched the way OTLP ships:

| wire | bytes/decision | notes |
|---|---:|---|
| OTLP faithful (protobuf) | 101.372 | industry standard telemetry envelope |
| OTLP faithful + zstd level 19 (batched) | 7.162 | |
| **Facet (O1, per field)** | **1.516** | frames itself, shows tampering |

**Facet is 66.9× smaller than OTLP protobuf** and 4.7× smaller than zstd compressed batched OTLP.
O1 counts its integrity apparatus (Merkle epoch roots and the ACK channel, the #84 convention), and
every ratio divides by that exact measured cost. The reduction is *structural*: OTLP ships a
timestamped, typed attribute bag; Facet ships the decision. A
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

### 5.4 Coexistence with full fidelity telemetry

Facet is the decision wire, not the archive, and dropping off policy fields is a per link choice
rather than a system wide one. Where an operator needs raw events for forensics or debugging, Facet
runs beside the existing pipeline, not instead of it: one source fans out to the unchanged raw sink
and to a Facet sink, which is the shipped deployment pattern (`integrations/vector/CANARY.md`, with
`canary_verify.py` proving route parity between the two legs on live traffic). The economics then
sort themselves by link: where bandwidth affords raw, both flow and the raw leg remains the record
of account; where it does not (contested, disconnected, or metered links), the decisions still flow
at about two bytes each and the raw is retained at the source under its own retention policy. The
privacy reading of §1 is the same fact seen from the other side: only what the decision needed ever
leaves the node, unless the operator explicitly ships more.

### 5.5 Cost on constrained hardware

We separate what is measured from what is modeled. Measured: the decision *evaluate* path on
constrained substrates, 5 to 21 cycles per decision in FPGA fabric (a provable 100 to 420 ns bound
at 50 MHz) and byte identical table evaluation on four MCU instruction sets, with wire round trips
dominated by the transport, not the decision (ledger rows #73 to #99). Modeled, and stated as such:
the codec costs on a bare MCU. Zeckendorf coding of a Facet event is bit serial over roughly a
dozen bits with a small addition table (78 entries cover the full 2^53 range, about 0.6 KB of
constant data) and no multiplies or divisions on the hot path; Merkle commitment is one SHA-256 per
block plus a logarithmic combine, and SHA-256 throughput on small cores is well characterized in
the literature. Both are bounded and small by construction, but we have not yet measured them on
bare metal: the hardware shift register codec (Phase C2) is the named, unbuilt artifact that will
turn this paragraph from a cost model into numbers, and until it lands the lightweight claim for
the codec on MCUs is a design argument, not a measurement.

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

Beyond the quantization mechanism, Facet's thesis (transmit only what can change the outcome) is the
organizing idea of *semantic and goal oriented communications*, as old as Weaver's distinction between
Level A, the symbols, and Level B, their meaning [Shannon and Weaver 1949], and resurgent in modern task
oriented coding [Gündüz et al. 2023]. The difference is where relevance comes from. Those systems *learn*
what matters from a task and a dataset, usually with trained neural encoders, so their relevance is
statistical and approximate, with no guarantee that a given transmission preserves the receiver's
decision. Facet's relevance is *derived* from an explicit signed decidable policy and carries a machine
checked proof (§3.5) that no decision is mis-resolved: relevance that is exact and certified, not trained
and estimated.

On the mechanism side, reducing a decision structure to its essential cuts is classical in packet
classification and logic synthesis. TCAM Razor minimizes a packet classifier's rule set for ternary CAM
[Liu et al. 2010], and reduced ordered binary decision diagrams canonicalize and minimize Boolean
functions [Bryant 1986]. Both exploit the property Figueroa quantization rests on, that a field matters
only at the constants it is compared against, and packet classifiers even cut header fields into the same
kind of ranges Level M atoms cut a field's domain into. The distinction is the object being compressed:
TCAM Razor and BDDs compress the *classifier*, the on device matcher that evaluates the rules, while
Figueroa quantization compresses the *reading*, the data on the wire, down to its decision sufficient
cell and preserves the classifier's decisions by a proof rather than by reproducing the classifier. TCAM Razor
and BDDs shrink the rule table, while Figueroa quantization shrinks the telemetry that flows through it.

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
- C. E. Shannon and W. Weaver, "The Mathematical Theory of Communication," University of Illinois Press, 1949.
- D. Gündüz, Z. Qin, I. E. Aguerri, H. S. Dhillon, Z. Yang, A. Yener, K. K. Wong, and C.-B. Chae, "Beyond Transmitting Bits: Context, Semantics, and Task-Oriented Communications," *IEEE J. Sel. Areas Commun.*, 2023.
- A. X. Liu, C. R. Meiners, and E. Torng, "TCAM Razor: A Systematic Approach Towards Minimizing Packet Classifiers in TCAMs," *IEEE/ACM Trans. Netw.*, 2010.
- R. E. Bryant, "Graph-Based Algorithms for Boolean Function Manipulation," *IEEE Trans. Comput.*, 1986.
- OpenTelemetry Protocol (OTLP) specification.
- PrismPath: `PROTOCOL.md` (Facet/1, normative), `SPEC.md` (flow format, Level M).

---

*Draft. Provenance: `adapters/telemetry/{quantizer,wire,zeckendorf,packed}.py`;
`adapters/fusion/bench/{otlp_baseline.py,otlp_results.md,wire.py}`;
`adapters/fusion/tests/{test_fusion_spiral,test_wire_tamper}.py`. Numbers: `otlp_results.md` (n = 64,484).
Deployed implementations, byte identical to the reference over the frozen corpus: `prismpath-rs` and
`prismpath-telemetry-rs` on crates.io, and a Facet codec compiled into Vector (evidence ledger #103;
55/55 fixture readings identical across all three implementations, integer exactness bounded at 2^53
with threshold parity verified either side of it).*
