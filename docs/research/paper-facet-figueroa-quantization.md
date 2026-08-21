# Facet and Figueroa Quantization: ship the decision, not the data

**Draft for review.** A companion to the normative specification in [`../../PROTOCOL.md`](../../PROTOCOL.md)
and the flow format spec in [`../../SPEC.md`](../../SPEC.md). Every number in this paper traces to a
committed artifact, cited inline; the reference implementation is `adapters/telemetry/`.

## Abstract

Telemetry systems ship data: timestamped, typed records that describe themselves, defended at real
cost in bandwidth, storage, and trust. For a system governed by a decidable match action policy,
almost none of that data can change a decision, and the part that can is a small statistic we can
characterize exactly. We define **Figueroa quantization**, the map from a reading to the minimum
sufficient statistic for a policy's decisions: which cell of each field's domain the reading
occupies, derived from the policy itself and provably preserving every decision it can make. We then
define **Facet**, a wire protocol that carries those symbols with a codebook agreed from the shared
signed policy rather than transmitted, a symbol coding that frames itself, and tamper evidence
anchored to an audit chain. On 64,484 representative fused decisions, the Facet wire costs 1.516
bytes per decision with its integrity apparatus counted: 66.9 times smaller than OpenTelemetry
(OTLP) protobuf and 4.7 times smaller than zstd compressed batched OTLP, while it still frames
itself, streams, and shows tampering, none of which a compressed record format provides. The
reduction is structural, not a compression trick: we transmit the decision, not a timestamped
attribute bag. Decision preservation is machine checked three ways against a frozen corpus.

## 1. The problem: telemetry ships the wrong thing

A general telemetry envelope such as OTLP carries, per record, a timestamp, typed attributes, and
repeated string keys. For a fused decision payload this is about 100 bytes per record, and it is
larger than even a minimal JSON of the same fields (measured: 1.49 times). That is not a defect of
OTLP; it is a general observability envelope doing its job. But when the consumer of the telemetry
is a policy, a control plane that will route each record to a decision, the envelope carries
enormous redundancy: any two readings that route identically are, to the policy, the same event.

The setting that makes this exact is the Level M fragment. A PrismPath policy is an inert,
inspectable document whose routing over a field changes truth only at the constants that field is
compared against (`field OP const`; see `SPEC.md`). Because the policy's sensitivity to a field is
confined to a finite set of published cuts, the question this paper answers has a precise form:
what is the smallest thing a node can send that preserves every decision, and can it be sent
without giving up framing, streaming, or tamper evidence?

## 2. Figueroa quantization

### 2.1 The definition

Fix a Level M policy. Its deterministic, non semantic edges decompose into a finite set of atoms,
each testing one field against one literal constant:

```
Atoms(𝒫) = { α₁, …, α_A },    αⱼ(x) = [ field fⱼ of x  ▷ⱼ  cⱼ ],    ▷ⱼ ∈ { <, ≤, >, ≥, =, ≠, ∈, ∉, truthy }.
```

Comparisons of field against field, or against a non literal, carry no cut and lie outside the
fragment. The decision is a function of the atom truth vector alone, `D(x) = Δ(α₁(x), …, α_A(x))`,
where `Δ` is the flow's first match edge logic over the realizable truth vectors (threshold atoms
over one field are not independent, so much of `{0,1}^A` is unreachable and `Δ` is unconstrained
there).

The constants compared against a field cut its domain into cells. Two values in one cell make every
atom of that field agree, so they route identically through the entire policy. Formally, for each
decision relevant field `f`, let `u ~_f u'` when every atom over `f` agrees on `u` and `u'`, and let
`q_f` send a value to its equivalence class: the coarsest partition of the field's domain on which
every atom is constant. For a numeric field, `q_f` is a monotone step function that increments at
each published cut, with adjacent intervals of identical atom truth merged. Three field kinds are
detected automatically: numeric (integer intervals), boolean (two cells), and categorical (one cell
per constant plus a trailing other). The **Figueroa quantization** is the product map over the
decision relevant fields, fields the policy never tests being dropped because they cannot change a
decision:

```
𝒬_F : 𝒳 → 𝒞 = 𝒞₁ × … × 𝒞_N,      𝒬_F(x) = ( q₁(x₁), …, q_N(x_N) ).
```

The result is the minimum sufficient statistic for the policy's decisions: Fisher's classical
notion, specialized to decision equivalence, and, crucially, derived mechanically from the policy
rather than estimated from data. Reference: `adapters/telemetry/quantizer.py`.

### 2.2 The guarantee

**Theorem (decision preservation).** For all readings `x, x'`: if `𝒬_F(x) = 𝒬_F(x')` then
`D(x) = D(x')`.

*Proof.* Equal quantizations give `q_f(x_f) = q_f(x_f')` for every field, so by the definition of
`~_f` every atom agrees on `x` and `x'`. The atom truth vectors coincide, hence
`D(x) = Δ(atoms(x)) = Δ(atoms(x')) = D(x')`. Equivalently, `D` factors as `D = D̄ ∘ 𝒬_F` for a
unique `D̄ : 𝒞 → actions`. ∎

In words: reconstructing any representative of each cell and routing it through the policy
reproduces every decision the original reading produced. This is the property everything else in
the paper rests on, and it is machine checked three ways on a frozen corpus
(`adapters/fusion/tests/test_fusion_spiral.py`): direct evaluation, the full quantize, wire round
trip, reconstruct, evaluate path, and cell index to route, all pinned to a `flow_sha256`. A mapping
error anywhere would produce two readings with equal symbols and different decisions, flipping a
pinned entry and turning the suite red.

**Corollary (wire cost).** Transmitting `𝒬_F(x)` reproduces every decision at a cost bounded by the
cell counts alone, `bits(x) = ⌈log₂ |Im 𝒬_F|⌉ ≤ Σ_f ⌈log₂ |𝒞_f|⌉`, independent of the sensor's bit
depth or sample rate. The map is decision lossless and magnitude lossy: the decision is recovered
exactly, while only a cell representative of the original value is recoverable. Section 4 measures
this bound.

### 2.3 Why the quantization stops at the atoms

`𝒬_F` is sufficient for `D`, and it is the minimal *atom preserving* statistic: each `q_f` is the
coarsest partition on which every atom is constant, so merging any two cells flips some atom and may
flip a decision. It is deliberately not the absolute minimal sufficient statistic. A strictly
coarser statistic exists whenever two distinct cell tuples always yield the same action, but
collapsing them is a property of the specific decision function, not of the fields: computing it in
general is the policy equivalence problem, and the result is brittle under change. Merge two same
action cells today, hot swap the policy so they route differently tomorrow, and the coarser wire can
no longer tell them apart, breaking decision preservation across the swap. Atom preservation is the
invariant that survives policy evolution over a fixed atom set. That is why Figueroa quantization
stops at the per field cells: that layer is exact, field local, robust to hot swap, and composable
across independently signed policies.

### 2.4 Boundary mechanics and precision

Open versus closed never survives to the wire, because the comparison domain is discretized first.
Non integer numerics are truncated toward zero before quantization (the reference and both deployed
implementations share this conversion), so every comparison happens over the integers, where each
strict cut converts exactly to a closed bound (`x < c` is `x <= c - 1`): cells are closed integer
intervals, unbounded only at the extremes. The exactness window is that of double precision
integers: values are exact through 2^53, and beyond it both endpoints round identically through f64,
so decisions stay consistent while absolute integer exactness is out of scope. None of this is
asserted from design alone. A frozen boundary corpus
(`adapters/telemetry/conformance/boundary.json`) probes every threshold edge at t - 1, t, and t + 1
across cuts from 10^2 to 10^12, plus 2^53 - 1, 2^53, 2^53 + 2, and 10^15, and twin tests replay it
in the Python reference and the Rust crates; a symbol drift on either side of any boundary in either
implementation turns the suite red.

### 2.5 What is and is not claimed

Sufficient statistics and quotienting a state space by decision equivalence are classical. Unlike
standard vector quantization, Figueroa quantization does not place its boundaries to minimize
geometric distortion or mean squared error; it places them exactly where the policy's logic already
cuts. The contribution is specific and mechanical: deriving the partition directly and provably from
a Level M match action policy, the same atoms the model checker and compiler read, so the minimal
decidable state code falls out of the policy itself with a machine checked guarantee that it never
mis-resolves a decision. Section 6 situates this against the neighboring literature in detail.

## 3. The Facet protocol

Facet carries Figueroa quantized symbols. Four design choices define the core, specified
normatively in `PROTOCOL.md`; a fifth mechanism is an option of the reference implementation.

**Codebook agreement, not codebook transmission (§2.1).** Both endpoints derive the identical
codebook by running the partitioner over the same signed policy. The only shared state is the
policy, already versioned and integrity bound by the pack machinery. A decode is valid only under
the exact policy that produced the encode; a mismatch is rejected. This signed, versioned codebook,
agreed out of band, is what makes Facet a protocol rather than a mere encoding.

**A symbol coding that frames itself (§2.2).** Each symbol is sent as `symbol + 1` under Zeckendorf
(Fibonacci) coding, a standard code that delimits itself: consecutive 1s cannot occur inside a
codeword, so the trailing `11` is the only place the pattern appears. With canonical field order, a
reading carries no length header and no field tags. Self delimiting also bounds how far damage
travels: a decoder realigns at the next terminator past a corrupted region, so corruption is local.
It touches the symbols it lands on, cannot desynchronize the remainder of a stream, and what it
touches is caught rather than trusted: the recovered symbol count must match or the stream is
rejected, the packet's Merkle root makes damage evident, and the optional keyed layer rejects it
outright. Zeckendorf coding is prior art, used, not claimed.

**Lossless batching over any transport (§2.3).** Because the stream frames itself at the reading
level, concatenation is lossless, so the `stream`, `batch:N`, and `mtu-fill` strategies trade only
latency for bandwidth, never fidelity. Facet rides over TCP/TLS, UDP/DTLS, Thread, LoRa, ESP-NOW,
or a bare MCU link. It is not a transport.

**Tamper evidence and optional confidentiality (§2.4, §2.5).** A 32 byte Merkle root per packet
binds readings into an audit chain that spans sessions. An optional layer composes X25519 ECDHE and
ChaCha20-Poly1305 (TLS 1.3 primitives, rekeyed per epoch) for transports without their own TLS.

**The decision first spiral (Tier 6, optional; §4.6).** When one node routes on several correlated
fields, the reference implementation packs the joint cell space onto a Fermat spiral index `n`,
bands laid out center outward in route severity order: the baseline route at the dense center, the
most specific branches outward. Because the Fermat spiral has `r²` proportional to `n`, membership
in a radial band is a pair of integer compares on `n`, itself a Level M atom; and the golden angle
placement is a deterministic function of `n` (one u32 multiply add on the edge, no trigonometry),
so the wire still carries a single ordered integer. The band ID alone routes correctly; a Gray
ordered refinement recovers the exact cell when the link affords it, so a collapsing link costs
fidelity, never the decision. The spiral is an option for correlated multi field nodes, not part of
the normative Facet/1 core.

Composing the quantization and the wire gives the guarantee the protocol exists to provide.

**Proposition (end to end decision preservation).** Under the codebook agreed from the shared
signed policy, Facet decodes a reading to exactly its Figueroa symbol, so by the theorem of §2.2
the decision the receiver computes equals the decision the source's reading produced. Transport
corruption cannot silently change a decision: it is made evident by the per packet Merkle root, or
rejected outright under the optional keyed layer.

*Proof.* Codebook agreement makes the decoder's partition identical to the encoder's, and the self
framing coding recovers the symbol tuple without ambiguity, so decoding yields the same `𝒬_F(x)`
that was sent; the theorem gives `D̄(𝒬_F(x)) = D(x)`. A packet whose bytes were altered fails the
Merkle root check (evidence after the fact) or the AEAD tag (rejection on the hop), so an altered
reading is never silently decoded to a different decision. ∎

## 4. Measurements

### 4.1 Against OTLP

Over 64,484 representative fused decisions, batched the way OTLP ships
(`adapters/fusion/bench/otlp_baseline.py`, `otlp_results.md`):

| wire | bytes per decision | notes |
|---|---:|---|
| OTLP faithful (protobuf) | 101.372 | industry standard telemetry envelope |
| OTLP faithful + zstd level 19, batched | 7.162 | |
| **Facet (O1, per field)** | **1.516** | frames itself, shows tampering |

Facet is 66.9 times smaller than OTLP protobuf and 4.7 times smaller than zstd compressed batched
OTLP. The Facet figure counts its integrity apparatus (Merkle epoch roots and the ACK channel), and
every ratio divides by that exact measured cost. The reduction is structural: OTLP ships a
timestamped, typed attribute bag; Facet ships the decision. A general compressor on a verbose
format narrows the raw byte gap but gives up framing, streaming, and tamper evidence; the
differentiator is those properties, not the byte count alone.

### 4.2 Framing, batching, and the unit of loss

Because Facet frames itself, the transport header per packet amortizes toward zero as a packet
fills, so the header tax is a latency choice, not a codec limit; batched against batched, Facet
keeps its advantage over plain JSON because JSON keeps paying per record keys inside the batch
(`adapters/fusion/bench/wire.py`). The optional keyed layer adds less than a byte per decision when
batched: a flat 16 byte tag amortized over a full packet, plus a 64 byte handshake amortized over a
4,096 reading epoch.

Framing also sets the unit of loss under corruption, the operational half of the story on
constrained or intermittent links. A length prefixed envelope that takes a hit in a header forfeits
the remainder of its payload, so recovery means retransmitting the whole batch. A Facet decoder
cannot desynchronize past the next `11` terminator, so a hit costs the packet it lands in, and
recovery has only that packet to cover. The localization is structural, from the coding; the
detection half is machine checked (`adapters/fusion/tests/test_wire_tamper.py`): at the bare codec,
at least 90 percent of single bit flips are rejected or leave the decision statistic unchanged, the
residual that decodes cleanly to a different verdict is exactly why the keyed layer exists, and
under the keyed layer every single byte tamper tried is rejected. The retransmission reduction is
stated qualitatively: retry rates under injected loss on a degraded link are not yet benchmarked,
and quantifying them is future work.

### 4.3 Decision preservation

Proven three ways against the frozen corpus (§2.2). Decision fidelity is invariant under batching,
compression, and encryption; only temporal fidelity, freshness, varies with strategy.

### 4.4 Coexistence with full fidelity telemetry

Facet is the decision wire, not the archive, and dropping off policy fields is a per link choice
rather than a system wide one. Where an operator needs raw events for forensics or debugging, Facet
runs beside the existing pipeline, not instead of it: one source fans out to the unchanged raw sink
and to a Facet sink, which is the shipped deployment pattern (`integrations/vector/CANARY.md`, with
`canary_verify.py` proving route parity between the two legs on live traffic). The economics then
sort themselves by link. Where bandwidth affords raw, both flow, and the raw leg remains the record
of account; where it does not (contested, disconnected, or metered links), the decisions still flow
at about 1.5 bytes each and the raw is retained at the source under its own retention policy. The
privacy reading of §1 is the same fact seen from the other side: only what the decision needed ever
leaves the node, unless the operator explicitly ships more.

### 4.5 Cost on constrained hardware

Both halves of the constrained hardware story are measured. The decision evaluate path costs 5 to
21 cycles per decision in FPGA fabric (a provable 100 to 420 ns bound at 50 MHz) and byte identical
table evaluation on four MCU instruction sets, with wire round trips dominated by the transport,
not the decision (ledger rows #73 to #99). The codec is a portable C implementation of the encoder:
a 78 entry Fibonacci table covering the full 2^53 range, 624 bytes of constant data, no multiplies
or divisions on the hot path, verified byte for byte on device against reference generated wire
bytes before any timing (ledger row #104). Per event encode times:

| core | typical 4 field event (2.281 B) | 1,000 cell stress codebook (7.062 B) |
|---|---:|---:|
| ATmega328P, 16 MHz | 463 us | 1.76 ms |
| Xtensa LX6, 240 MHz | 9.3 us | 27.9 us |
| Cortex-M33, 150 MHz | 5.3 us | 14.9 us |
| Hazard3 RISC-V, 150 MHz | 4.6 us | 13.7 us |

Even the 8 bit floor tier encodes a worst case event faster than any telemetry cadence it would
serve, and the 32 bit cores spend roughly 700 to 2,200 cycles per typical event. Two items remain
modeled rather than measured, stated as such: Merkle commitment (one SHA-256 per block plus a
logarithmic combine, well characterized on small cores in the literature) and the FPGA shift
register codec, the remaining unbuilt half of Phase C2.

### 4.6 The spiral, measured

On 20,000 readings per scenario of correlated multi dimensional telemetry
(`adapters/telemetry/bench/spiral_bench.py`, `spiral_results.md`):

| k (fields) | cells | route win vs per field wire | progressive fidelity ratio |
|---:|---:|---:|---:|
| 1 | 4 | 1.0x (none, by design) | 1.72 |
| 2 | 16 | 1.9x | 1.07 |
| 3 | 64 | 2.8x | 0.88 |
| 4 | 256 | 3.6x | 0.79 |

The route win (bits to route correctly, both sides at 100 percent routing accuracy) grows with
dimensionality and is absent at k = 1 by design: the tier exists for correlated multi field state.
Fidelity parity near 1x means the win is progressiveness, not dropped data: the refinement stream
still delivers the full quantized magnitude. Correlation is the resource: the same k = 3 scenario
routes at 3.01 bits correlated versus 3.9 uniform. Under Gilbert Elliott burst loss the spiral
keeps routing where the per field wire cannot (96.4 versus 92.9 percent routed under light burst,
80.0 versus 68.1 under heavy), because the decision needs one band frame to survive where the per
field wire needs all k field frames. Hysteresis at band edges is deliberately the sampling edge's
concern, not the codec's; the layout is pinned by a frozen tessellation corpus the same way the
quantizer is.

### 4.7 The profile on the air

The spiral's two materializations were validated on hardware in two steps
(`prismpath-hw/spiral-node/`, `prismpath-hw/spiral-mesh/`). First, the baked path alone: an ESP32
consuming the signed sidecar (a roughly 150 line table lookup consumer, no routing, no
trigonometry, no floating point) quantized boundary probing readings and emitted band tier and
refinement Zeckendorf frames bit identical to a host independently deriving the layout from the
same flow, 20 of 20 vectors on the first flash. Then the wire itself: three ESP32 nodes braided
their decision streams over ESP-NOW broadcast, stream identity riding the sender MAC (zero stream
identity tax on a transport that authenticates senders at layer 2), payloads of 3 to 5 bytes
carrying `[class, tick, value]` as a self framing Zeckendorf stream. In a 30 second observed
window: 1,891 frames received with zero corruption and zero wrong symbols; every one of 444 band
symbols on the air equal to the host re deriving the quantization from the signed flow, which
closes an honest gap in the earlier mesh work, whose per channel bands were hand coded convention
rather than derived artifacts; per link delivery 92 to 98 percent, a lost frame costing freshness,
never a wrong decision. Each node also gossiped its fused posture, the k = 3 joint spiral cell, as
a two byte coherence beacon: 80.8 percent of fully reported ticks showed three way agreement, and
the remainder were the one tick band edge skew such a beacon exists to expose. Two scope notes
carry over unchanged: the airborne frames in this run are unauthenticated (the pack is signed; per
frame authentication on the mesh is the named follow on), and no airtime saving is claimed for
single small frames, where fixed layer 2 overhead dominates; the airtime story belongs to batching
and to duty cycle limited links, and will be measured, not asserted.

## 5. Trust boundary

Facet's guarantees are precise, and the boundary is deliberate.

1. **Source authenticity: out of scope.** Whether a sensor read true or an upstream lied is the
   data provider's responsibility. Facet is a control plane wire, not a sensor.
2. **Integrity after a value enters: tamper evident, not tamper proof.** A Merkle root anchored to
   the audit chain makes alteration evident against a commitment no attacker can forge; the
   optional keyed layer rejects a tampered packet on the hop; codebook binding rejects any stream
   that does not decode under the exact signed policy. Without the keyed layer, integrity is
   evidence after the fact, not rejection in real time. Measured in
   `adapters/fusion/tests/test_wire_tamper.py`.
3. **Execution faithfulness: guaranteed.** For the input processed, the action provably matches the
   quantization of that value (§2.2), checked for conformance across every substrate.

## 6. Related work

The neighboring literature falls into three families: work this idea is a special case of, work it
structurally resembles but differs from in objective, and work the protocol inherits from. One
sentence pattern applies throughout: we name what is shared, then where the difference lies.

**The idea's family: decision sufficient compression.** Sufficient statistics (Fisher) and decision
theoretic quotients are the conceptual root. The information bottleneck [Tishby, Pereira, and
Bialek 1999] generalizes sufficiency to a soft, learned tradeoff between compression and task
relevance; Figueroa quantization is its hard, exact, policy derived special case, where the
tradeoff collapses because the policy fixes the partition and admits no distortion. Concurrent and
independent work [Walsh 2026] formalizes the coarsest exactly decision sufficient compression as
the quotient of a state space by policy equivalence and studies its approximate form as a rate
distortion problem: the same conceptual core as §2, reached from information theory rather than
from a policy compiler; it derives no partition from an explicit signed policy, carries no machine
checked guarantee, and defines no wire. The classical antecedent on the communication side is
quantization for decentralized detection [Longo, Lookabaugh, and Gray 1990], which designs
quantizers to minimize a hypothesis test's error probability under a rate budget; Figueroa
quantization admits no error, placing boundaries exactly at the policy's own comparison constants.

**Same shape, different objective.** Product quantization [Jégou et al. 2011] also decomposes a
high dimensional space into per field subspaces quantized independently into a compact tuple, but
learns its codebooks by clustering to minimize reconstruction distortion; here the codebook falls
out of the governing policy, and the objective is preservation of the decision, not of the signal.
Supervised discretization [Fayyad and Irani 1993] also cuts continuous axes at class boundaries,
but estimates its bins from labeled data to reduce empirical entropy; Figueroa quantization
extracts them deterministically from an explicit signed policy, with no statistical fitting and an
exactness proof. On the mechanism side, TCAM Razor [Liu et al. 2010] and reduced ordered binary
decision diagrams [Bryant 1986] exploit the same underlying property, that a field matters only at
the constants it is compared against, but compress the classifier, the on device matcher; Figueroa
quantization compresses the reading, the data on the wire, and preserves the classifier's decisions
by a proof rather than by reproducing the classifier.

**The protocol's lineage.** Facet's thesis, transmit only what can change the outcome, is the
organizing idea of semantic and goal oriented communications, as old as Weaver's distinction
between the symbols and their meaning [Shannon and Weaver 1949] and resurgent in task oriented
coding [Gündüz et al. 2023]; those systems learn relevance from a task and a dataset, so their
relevance is statistical and approximate, while Facet's is derived from an explicit signed policy
and certified by the theorem of §2.2. Transmitting on threshold crossings is the send on delta and
event triggered sampling tradition [Miskowicz 2006; Heemels et al. 2012]; Facet's stream, batch,
and fill strategies sit in that lineage, the distinction being that what crosses is a decided cell
boundary, not a raw signal delta. Zeckendorf coding [Zeckendorf 1972] supplies the self framing
symbol code, used as prior art. And where the spiral tier maps a multi dimensional key to one
index, the standard tools are Morton and Hilbert curves, chosen for locality; the spiral uses
Vogel's phyllotaxis construction [Vogel 1979] instead, because route membership, not locality, is
the property the wire needs: on the Fermat spiral a radial region is exactly an index interval, so
the decision is two integer compares, a Level M atom, while a Hilbert or Morton range carries no
such semantic meaning. The placement constant is the golden ratio in fixed point (0x9E3779B9, the
multiplicative constant of Fibonacci hashing), which the implementation shares with its Zeckendorf
coding as a small economy: the protocol's geometry and its framing both lean on the golden ratio's
equidistribution.

We are not aware of a prior or concurrent system that derives a quantization provably preserving
decisions directly from a decidable match action policy and carries it over a codebook agreed from
the signed policy. The conceptual core is classical and independently under active study; the
individual ingredients are all standard. We claim only the composition and the machine checked
quantization derived from the policy.

## 7. Origin and priority

The applied thesis behind this work, reducing an observation to a threshold decided verdict and
transmitting only a signed, receipted decision over a resilient link, was filed as a US provisional
patent application (Crystal Warden Supply Chain Labs LLC, 15 February 2026) in the context of an
out of band supply chain verification device; the quantization method itself was held back and is
not disclosed there. Figueroa quantization as formalized here was developed in mid 2026 and is
contemporaneous with independent academic work on action sufficient compression [Walsh 2026]. We
make no claim of priority over the general notion of quotienting a state space by decision
equivalence, which is classical and actively studied. What we claim is the specific machine checked
derivation of a decision preserving quantization from a signed decidable policy, and its
realization as a byte identical wire across substrates.

## 8. Conclusion

For a system governed by a decidable policy, the decision sufficient statistic is small, exact, and
derivable from the policy itself. Figueroa quantization computes it with a machine checked
guarantee that it preserves decisions; Facet carries it over a wire that frames itself and shows
tampering, whose codebook is agreed rather than transmitted. The result is a bandwidth reduction of
more than an order of magnitude that is structural rather than a compression trick, with framing,
streaming, and audit properties a compressed record format cannot offer.

## References

- É. Zeckendorf, "Représentation des nombres naturels par une somme de nombres de Fibonacci ou de nombres
  de Lucas," *Bull. Soc. Roy. Sci. Liège*, 1972.
- R. A. Fisher, "On the mathematical foundations of theoretical statistics," 1922 (sufficient statistics).
- N. Tishby, F. C. Pereira, and W. Bialek, "The Information Bottleneck Method," *Proc. 37th Allerton Conf.*, 1999.
- M. Walsh, "Support sufficiency as action-sufficient compression: a single-cycle rate-regret formulation," arXiv:2606.09858, 2026.
- R. M. Gray, "Vector Quantization," *IEEE ASSP Magazine*, 1984.
- G. Longo, T. D. Lookabaugh, and R. M. Gray, "Quantization for Decentralized Hypothesis Testing Under Communication Constraints," *IEEE Trans. Inf. Theory*, 36(2):241-255, 1990.
- H. Jégou, M. Douze, and C. Schmid, "Product Quantization for Nearest Neighbor Search," *IEEE Trans. Pattern Anal. Mach. Intell.*, 2011.
- U. M. Fayyad and K. B. Irani, "Multi-Interval Discretization of Continuous-Valued Attributes for Classification Learning," *Proc. IJCAI*, 1993.
- C. E. Shannon and W. Weaver, "The Mathematical Theory of Communication," University of Illinois Press, 1949.
- D. Gündüz, Z. Qin, I. E. Aguerri, H. S. Dhillon, Z. Yang, A. Yener, K. K. Wong, and C.-B. Chae, "Beyond Transmitting Bits: Context, Semantics, and Task-Oriented Communications," *IEEE J. Sel. Areas Commun.*, 2023.
- M. Miskowicz, "Send-On-Delta Concept: An Event-Based Data Reporting Strategy," *Sensors*, 6(1):49-63, 2006.
- W. P. M. H. Heemels, K. H. Johansson, and P. Tabuada, "An Introduction to Event-Triggered and Self-Triggered Control," *Proc. IEEE CDC*, 2012.
- A. X. Liu, C. R. Meiners, and E. Torng, "TCAM Razor: A Systematic Approach Towards Minimizing Packet Classifiers in TCAMs," *IEEE/ACM Trans. Netw.*, 2010.
- R. E. Bryant, "Graph-Based Algorithms for Boolean Function Manipulation," *IEEE Trans. Comput.*, 1986.
- H. Vogel, "A better way to construct the sunflower head," *Mathematical Biosciences*, 1979 (the
  Fermat spiral with golden angle placement).
- G. M. Morton, IBM technical report, 1966, and D. Hilbert, 1891 (space filling curves, the locality
  preserving alternative).

*Draft. Provenance: `adapters/telemetry/{quantizer,wire,zeckendorf,packed}.py`;
`adapters/fusion/bench/{otlp_baseline.py,otlp_results.md,wire.py}`;
`adapters/fusion/tests/{test_fusion_spiral,test_wire_tamper}.py`. Numbers: `otlp_results.md` (n = 64,484).
Deployed implementations, byte identical to the reference over the frozen corpus: `prismpath-rs` and
`prismpath-telemetry-rs` on crates.io, and a Facet codec compiled into Vector (evidence ledger #103;
55/55 fixture readings identical across all three implementations, integer exactness bounded at 2^53
with threshold parity verified either side of it).*
