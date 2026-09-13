# The Decision Dictionary

One thing, one name, at one layer. This is the vocabulary of PrismPath and of Crystal Warden Labs: the
words the code, the documents, the receipts, the proposals and the website use, each defined from the
point of view of a single decision as it moves through the system. It was drafted from a review of the
whole repository on 2026-09-12 (the code review folder in the strategy repository (`code-review-2026-09-12/reports/vocabulary.md`) holds the evidence: every
collision and every synonym with file and line). Entries are a draft until the owner has read them; the
rules at the end are the part to apply first.

## Why this dictionary exists, and how it settles a naming argument

**This dictionary exists so that one thing has one name, and so that the name a person reads on a receipt is
the name a person reads in the source.** Every term in it is defined from the point of view of a single
decision, followed through its whole life: a person authors it, a tool proves it, a compiler turns it into an
image, a wire carries what it needs, a substrate evaluates it, a receipt records it, an auditor reads it. A
word earns a place in this dictionary only if it names something that happens to a decision or something a
decision is made out of. If you cannot say which moment in that life a word belongs to, the word is not a
term, it is a habit, and it goes.

That point of view gives four rules that settle naming conflicts without argument. **First, one term names
one thing at one layer.** The seven layers are flow authoring, kernel evaluation, wire and transport,
substrate execution, evidence and receipts, control plane, and GRC. A word may be reused across layers only
when it is the *same* thing seen from a different side, never when it is a different thing that happens to
rhyme. `image` is the same signed bytes in the compiler, on the wire and in the fabric, so it travels; `frame`
is a picture to the camera, a radio packet to the relay and a codeword boundary to the codec, so it does not
travel and two of those three must be renamed. **Second, when two domains offer a word, the word a reader of
the receipt would understand wins.** The receipt is the narrowest and most public artifact the system
produces, and it is read by people who know neither our compiler nor our radios: an auditor, an assessor, an
operator at three in the morning. If the choice is between a word a networking engineer would use and a word
that would make sense on a receipt, the receipt wins, because the receipt is the only place where all seven
layers have to speak at once. That is exactly why the cause registry is the model this dictionary should
follow: `prismpath/kernel/causes.py` already forces one byte, one name, for every refusal in the stack, and
it is the only vocabulary in the repository that is append only, hashed, and frozen by test.

**Third, a borrowed word keeps its borrowed meaning or is not borrowed.** We borrow heavily and on purpose:
match action from networking, image from compilers and firmware, normal from anomaly detection, control from
compliance, kernel from operating systems, port from hexagonal architecture, verdict from law. Borrowing buys
instant recognition from a specialist, and it buys it only if the specialist's meaning survives. A networking
person who reads "match action table" and finds a match action table is served; a compliance person who reads
"control" and finds a requirement with assessment objectives is served; a lawyer, an assessor or a juror who
reads "verdict" and finds a `uint16` node index is not, and neither is anyone else. Where the borrowed
meaning cannot be honoured, we do not borrow a different word from the same field, we use a plain English
word from the decision's point of view. **Fourth, a word with two meanings is never resolved by context; one
of the two is renamed.** Context resolution works for the author and fails for everyone else, and it fails
worst in exactly the situation the system is built for, which is a person reading an unfamiliar layer under
time pressure. The corollary is that the dictionary must say what happens to the loser: deprecated outright,
kept as a layer specific alias with a stated layer, or kept as the domain's own word inside that domain only
and banned in core. That third disposition already has enforcement machinery, `tools/arch_guard.py` Signal 1,
which fails the build when a domain noun appears in core (`docs/decoder-ring.md:254`,
`adapters/compliance/ADAPTER_CONTRACT.md:11`). The dictionary should feed that guard its word list rather
than the guard keeping a private one.

One more thing the purpose statement should say out loud, because the repository's own history shows it is
needed. **This dictionary governs the company as well as the codebase, and it governs documents before it
governs identifiers.** Terms are fixed in prose first, in `docs/POSITION.md` and here; identifiers are then
brought into line at a pace the certification gates allow. Some identifiers cannot move: the C evaluator core,
the RTL and the eBPF programs are certified byte for byte, and renaming a field in `prismpath-hw/interp.c`
means a silicon re-certification (`prismpath-hw/README.md:33`, `make cert`). For those, the dictionary entry
records the frozen name as a deprecated alias and points at the walkthrough document, instead of pretending
the rename happened.

## The layers

Every entry names one of seven layers, the moments in the life of a decision: **flow authoring** (a
person writes the flow), **kernel evaluation** (the engine or a compiled table decides), **wire and
transport** (a reading crosses a link), **substrate execution** (a port, a fabric, a kernel program or a
microcontroller runs the same table), **evidence and receipts** (the decision is recorded, sealed and
anchored), **control plane** (operators, orchestration, the console), **GRC** (controls, adjudication,
assessment).

## Entries

One hundred and twenty entries, alphabetical. Each is written from the decision's point of view. `Layer` is one of
flow authoring, kernel evaluation, wire and transport, substrate execution, evidence and receipts,
control plane, GRC. A term with no `Also called (deprecated)` line has no losing synonym today.

**abstain**: the decision to make no decision because the information required is absent. Distinct from a denial, which is a decision. Layer: kernel evaluation. Not to be confused with: deny, refusal with cause, escalate. Also called (deprecated): defer (in the kernel sense only; `defer` keeps its GRC and port meaning).

**adapter**: an implementation of one or more ports that carries all of one domain's knowledge, so the core carries none. Layer: control plane. Not to be confused with: connector (the SDK base class an adapter subclasses), port (the interface the adapter implements).

**adjudicate**: to turn one unit of work into one structured result through the Adjudicator port, by a model, a comparator, or a circuit. Layer: control plane. Not to be confused with: route (choosing an edge), decide (the whole act). Also called (deprecated): `adjudicate` in `prismpath/evals/kappa.py:100`, which reconciles two human label sets and should be `reconcile`.

**air gap**: a deliberate absence of network connectivity, and the ledger tier built for it. Layer: evidence and receipts. Not to be confused with: over the air, which means the opposite and is spelled out in full, never abbreviated to `air`.

**anchor**: to bind a Merkle root to a timestamp a third party can verify without trusting the emitter, by OpenTimestamps into Bitcoin or by an RFC 3161 authority. Layer: evidence and receipts. Not to be confused with: seal (closing an epoch, which happens first), attest (binding a claim to a key), the LSP sense of attaching a diagnostic to a line (`prismpath/tests/test_lsp.py:101`), and the identity sense at `prismpath/ledgers/ledger.py:21`.

**annotation**: a line inside a node of the form `@name(args)` that declares something the toolchain acts on, such as `@emits`, `@field_only`, `@spawn`, `@state_bound`, `@checkpoint`, `@worker`. The engine parses annotations and never interprets the instruction prose. Layer: flow authoring. Not to be confused with: `prismpath annotate`, the blind relabelling command for agreement measurement.

**assessor**: the person who anchors, verifies and audits receipts; the fourth persona. Layer: control plane. Not to be confused with: evaluator (the certified routine). Also called (deprecated): evaluator (the persona sense, until September 2026).

**atom**: the irreducible unit of a predicate, a `(field, operator, constant)` triple or a bare field truthiness test. Every atom is total: it is satisfied or unsatisfied, never an error. Layer: kernel evaluation. Not to be confused with: atomic, which means indivisible in time (a pointer flip, a file write) and shares no root sense. Also called (deprecated): row (`ROADMAP.md:89`), comparator (keep only as the fabric materialization).

**attest**: to bind a claim to a key and a content address, so a later reader can check the claim without trusting whoever made it. Layer: evidence and receipts. Not to be confused with: anchor (adding a timestamp), certify (running a corpus), verify (checking someone else's attestation).

**audit event**: a durable record of an administrative action, principally a policy swap, written whether the action succeeded or was refused. Layer: control plane. Not to be confused with: receipt, which records a *decision* rather than an administrative action.

**authority**: what a system is permitted to do, as authored by a person and held in the flow document. One of the three concerns POSITION keeps separate, the other two being computation and evidence. Layer: flow authoring.

**band**: a contiguous range of the joint spiral index whose members all route the same way, so one band identifier is a decision sufficient wire symbol. Layer: wire and transport. Not to be confused with: a cause code numeric range (`prismpath/kernel/causes.py:12`), a gray level in the vision encoder, a cell (one field's bucket rather than a joint range). Also called (deprecated): level, quartile, `q0` to `q3`.

**bound**: see WCET bound. Used bare, `bound` in this project means a worst case execution bound unless qualified; every other kind of bound is named (version floor, replay window, staleness bound, step bound).

**catalog**: an ordered set of controls with their assessment objectives, content addressed and bound into every attestation made against it. Layer: GRC. Not to be confused with: an OSCAL catalog (an external document format this repository imports and exports), the SDK's generic "catalog criteria" (any retrievable knowledge base).

**cause**: the registered reason a decision refused, parked or escalated, carried as one byte with a frozen canonical name and a class, identical in the engine, the pack verifier, the fabric register, the kernel loader and on the wire. Layer: evidence and receipts (defined in kernel evaluation). Not to be confused with: reason (human prose), diagnostic code (authoring time static analysis), error code (an implementation return value), stop state. Also called (deprecated): the unregistered `class:detail` strings in `prismpath/hotswap/policy_pack.py`, which are registry rows now. The identifier is `cause_code` wherever a registry byte and a decoder status string are both in scope; the canonical wire field stays `cause` and carries the byte.

**cell**: a maximal set of values of one field on which every atom of the policy has constant truth, so any two values in the same cell route identically. The unit Figueroa quantization derives and the wire transmits. Layer: wire and transport. Not to be confused with: a vision grid cell (a region of a picture), a register cell (one field's typed slot in the register file), a band.

**certify**: to run a frozen corpus on one substrate and record the score against a declared subset, byte for byte. Layer: substrate execution. Not to be confused with: verify (checking a signature or a proof), validate (static analysis before anything runs), the statistical certificate that risk controlled calibration produces, an X.509 certificate.

**codebook**: the whole set of cells a policy induces, every field with its cut points and the symbol each range maps to, derived from the policy text and printed by the adoption gate before anything encodes. The quantizer's output considered as a table rather than as an act. Layer: wire and transport. Not to be confused with: the image (the decision table, not the partition), a compression dictionary, the field dictionary in a pack manifest (which names and orders fields and holds no cut points).

**codeword**: one self delimiting Zeckendorf code on the wire, ending in the unique `11` that closes it. Layer: wire and transport. Not to be confused with: symbol (the integer the codeword encodes), packet, record. Also called (deprecated): frame, in `prismpath/telemetry/zeckendorf.py` and `packed.py`.

**concentrator**: a bridge that concatenates records from many streams into one datagram so a fleet amortises the transport envelope. Layer: wire and transport. Not to be confused with: relay (which forwards without aggregating).

**condition**: the raw text after the colon on an edge, before any tier classification. Broader than a predicate: a condition may be deterministic, an error condition, an event condition, or natural language. Layer: flow authoring. Not to be confused with: predicate (only the deterministic subset of conditions).

**conformance**: the property an implementation has when it reproduces every committed vector of the frozen corpus exactly. Layer: kernel evaluation. Not to be confused with: certification (one run of a corpus on one substrate), a CycloneDX conformance score (a graded GRC field about an organization).

**connector**: the SDK base class an adapter subclasses, carrying the six ports. Layer: control plane. Not to be confused with: adapter, port.

**contract**: the interface between a flow and its workers, the fields each node must emit and their types, derived by `prismpath contract` and enforceable by the type gate. Layer: flow authoring. Not to be confused with: the adapter contract document, the cadence contract of the refresh profile, the normative spec.

**control**: a requirement from a governing framework, with assessment objectives beneath it and evidence attached to each. Layer: GRC, and nowhere else. Not to be confused with: control plane, control flow, a user interface control, a statistical control, an experimental control. This word is never used bare outside the GRC layer.

**control plane**: the category of system that decides what an autonomous system is permitted to do, as against the components that produce candidate actions. PrismPath is one of many; it is never "the" control plane and never a distinct layer. Layer: control plane. Not to be confused with: the build orchestration layer (the sprint and swarm machinery, which is `orchestration`, never "the control plane"), the FPGA's AXI control path, the data plane.

**corpus**: the frozen set of vectors an implementation is judged by. Always qualified when more than one is in scope: the conformance corpus, the decisions corpus, the safety corpus, the comparison corpus, the pcap corpus. Layer: kernel evaluation. Not to be confused with: a single vector, a fixture table.

**crosswalk**: a table mapping the controls of one framework onto another so one assessment reaches several frameworks. Layer: GRC.

**ctx**: the evaluation environment a predicate sees: the outcome's fields plus the engine owned counters `visits` and `error_count`. Layer: kernel evaluation. Not to be confused with: the register file (the substrate's materialization of the same thing), the reading (the wire's).

**datagram**: the delivery unit of the transport a Facet stream is bound to, and the boundary at which a concentrated stream fails closed. Layer: wire and transport. Not to be confused with: codeword, record, reading. Also called (deprecated): packet, when the Facet sense is meant.

**decision**: the act of determining where a run goes next and whether an action is permitted, and the record of that act. The centre of this dictionary: every other term is defined by its position relative to one of these. Layer: all. Not to be confused with: outcome (the worker's return, which is an *input* to a decision). Also called (deprecated): verdict, in all its senses.

**deny**: the decision that an action is not authorized. A decision, not an absence of one. Layer: kernel evaluation. Not to be confused with: abstain (information absent), refusal with cause (nothing matched), park (holding on the fail safe).

**determination**: the GRC layer's word for a decision about one control, met, partially met, or not met. Kept because assessors use it and it survives into OSCAL. Layer: GRC, and nowhere else. Not to be confused with: decision (the kernel's act), finding, an SSP implementation status. Also called (deprecated): verdict; status as the headline noun, which survives only as a JSON key that assessors, fixtures and OSCAL read; "the determination doc", an off repository design document referenced at `prismpath/telemetry/README.md:8`.

**deterministic edge**: an edge whose condition begins with `when` or is one of the keyword catch alls, resolved by evaluating a predicate against the outcome fields, free and exact. Layer: flow authoring. Not to be confused with: semantic, error and event edges, which are the other three tiers.

**device_id**: the identifier of one physical board or host on a link, carried in a record so a receiver can say which device a reading came from. Layer: wire and transport. Not to be confused with: node (a step of a flow, never a device), a node index inside an image, a MAC address (which is one way to derive a `device_id`, not the term for it). Also called (deprecated): `nid`, and `node_id` where a device rather than a flow node was meant; rule 14 allows an abbreviation only for a term whose full form is in this dictionary, and `node` is not that term.

**edge**: a line of the form `-> target: condition` inside a node, the authored transition. Document order is significant: the first true deterministic edge wins. Layer: flow authoring. Not to be confused with: a clock edge in RTL (`posedge`, `negedge`), an edge device, a graph edge in a rendering library.

**engine**: the full run loop: parse, dispatch to a worker, route, count visits, suspend, checkpoint, receipt. The Python engine is the reference for the flow language. Layer: kernel evaluation. Not to be confused with: interpreter (a table image executor with no run loop), evaluator (one evaluate call), kernel (any conformant implementation of the language), core.

**envelope**: the declared bounds a signed artifact must fit inside, checked at admission and refused rather than clamped. Layer: control plane. Not to be confused with: the camera's capture envelope, the transport envelope the concentrator amortises, the pack (which the envelope constrains).

**epoch**: a sealed window of the Facet stream whose Merkle root chains to the previous one, giving total ordering and tamper evidence across time. Layer: wire and transport. Not to be confused with: a boot nonce (`prismpath-hw/esp-vision-node/WIRE.md:9`), a swap generation counter (`prismpath-hw/mesh/main/ppt_mesh.c:189`), Unix epoch seconds. Those three should be named `boot_nonce`, `swap_generation` and `unix_time`.

**escalate**: to hand a decision to something more expensive because confidence is insufficient: to a model from the embedding router, or to a person from either. Not a refusal. Layer: kernel evaluation. Not to be confused with: abstain (the act of declining, which escalation is one response to), the firmware's `escalates(node)` bitmask, which marks target nodes that trigger evidence capture and should be renamed `captures_evidence`.

**evaluator**: one call that takes a node index and a register file and returns the index of the first matching edge. The smallest unit of decision in the system. Layer: substrate execution. Not to be confused with: **assessor**, the person who anchors and verifies receipts (the persona was called the evaluator until September 2026 and was renamed because this routine is certified and cannot move).

**evidence**: in this project's own operations, the committed artifact that backs a claim (hashes, stamps, reproduction scripts). In GRC, the material that supports a determination about a control. Always qualified. Layer: evidence and receipts, and GRC. Not to be confused with: the evidence ledger (a document), an `EVD1` record (a picture behind an escalating decision, which should be named `capture`), the payload in `pending` on a suspended run (which should be named `handoff`).

**evidence ledger**: the Markdown document in which every public claim is a numbered row with its method, result, honest scope and provenance, linted by `tools/ledger_lint.py` and anchored. Layer: evidence and receipts. Not to be confused with: the Flow Ledger, the context ledger, the guard ledger, which are cryptographic structures and not documents. Never called just "the ledger".

**Facet**: the decision sufficient telemetry wire: self framing Fibonacci codes carrying quantized symbols, with per packet Merkle roots, a staleness bound, replay refusal with a named cause, and a concentrator for fleets. Layer: wire and transport. Not to be confused with: the unrelated Rust `facet` reflection crate, which is why the crates are named `prismpath-*`.

**fail safe**: the signed, most restrictive node a substrate parks on when it cannot decide: state gone stale, a swap in flight, a normal it does not hold. Layer: substrate execution. Not to be confused with: a default edge (an authored catch all), an abstention.

**field**: a named value a predicate can test. The one term that survives every layer unchanged: authored, evaluated, partitioned, compiled to a register, ordered on the wire. Layer: all. Not to be confused with: a C struct field, "in the field" meaning a deployment.

**Figueroa quantization**: the map from a policy's text to the cells of each field that can change a decision, so a reading can be sent as one symbol per cell and still route identically. Proven decision preserving in Lean 4 within a declared domain. Layer: wire and transport. Not to be confused with: Facet, which is the wire that carries the result.

**finding**: a diagnostic PrismPath emits about an authored flow, with a stable code and a severity. Layer: flow authoring. Not to be confused with: a scanner finding, which is an *input fact* PrismPath ingests in the GRC layer and must be called a scan result.

**floor**: a bound below which a decision is refused rather than degraded. Always qualified: version floor, confidence floor, suite class floor, statutory floor, power floor. Layer: varies with the qualifier. Not to be confused with: any use of bare "floor", which is banned.

**flow**: the authored Markdown document that holds a decision structure. The source artifact of everything else. Layer: flow authoring. Not to be confused with: graph, image, pack, policy, which are the same artifact at later stages; control flow.

**fragment**: see match action fragment for the language sense. As a wire term, a fragment is a piece of an oversized payload on the first hop, reassembled by the receiver. Layer: wire and transport. Not to be confused with: the match action fragment, sub frame (the same operation on the second hop). One of these two senses must go; see section 6.

**gate**: a machine check that decides whether work may proceed, in CI or at admission. Layer: control plane. Not to be confused with: `gate_id`, which names a *governed decision point* in an attestation and should be renamed; the type gate; a logic gate; the `gate=` annotation argument.

**graph**: the parsed, in memory form of a flow: nodes, edges, annotations, start. Layer: kernel evaluation. Not to be confused with: flow (the source text), the rendered Mermaid picture, a rendering library's graph model.

**guard**: the deterministic safety floor whose policy grammar has no verb for permitting, so layering can only ever restrict. Layer: control plane. Not to be confused with: `arch_guard` (a CI architecture check), "guard rails" used loosely for deterministic edges, a runtime bound check.

**hop**: one link in the bench topology, named for the specific segment it is. Always qualified when more than one exists. Layer: wire and transport. Not to be confused with: a routing hop count, a Wi-Fi SSID that happens to be called `prismpath-hop`, a relay device.

**host**: the application or daemon that owns a governed decision boundary, principally the PolicyHost that verifies and admits a pack. Layer: control plane. Not to be confused with: the development workstation, a network address, the host relay. Those three are spelled workstation, address and host relay.

**hot swap**: replacing the live policy without rebuilding the system, after its signature, envelope and version floor are checked, flipping atomically and writing one audit event either way. Layer: control plane. Not to be confused with: compare and swap, a pointer swap (the mechanism), a button driven table selection in a demo.

**image**: the compiled Level M table: header, atoms, nodes, edges, programs, optional colors. A few hundred bytes, identical on every substrate. Layer: substrate execution. Not to be confused with: a camera image, a register file, an FPGA bitstream, a container image. Also called (deprecated): table, used alone.

**instruction**: the prose inside a node, handed to the worker verbatim. The engine never interprets it. Layer: flow authoring.

**interpreter**: a table image executor: given a node and a register file, walk the edges and return the target. Layer: substrate execution. Not to be confused with: engine, evaluator, kernel, a third party WebAssembly interpreter used as a comparator.

**kernel**: a conformant implementation of the flow language, judged by the frozen corpus. Four exist: Python, JavaScript, Rust, Go. Layer: kernel evaluation. Not to be confused with: the Linux kernel (always spelled in full), the Lean proof kernel, the decision kernel's C interpreter.

**keyframe**: under the refresh profile, an ordinary Facet frame sent on a cadence so staleness is bounded; byte identical to any other frame. Layer: wire and transport. Not to be confused with: the vision bench's `KEY3` record, which carries a full JPEG and is the most expensive object on the link. One of these two must be renamed; see section 6.

**Level M**: the match action fragment, the decidable subset of the predicate language that every substrate can execute. Layer: kernel evaluation. Not to be confused with: P0, P1 and P2, which describe how much of a flow runs without a model. The two are different axes and POSITION section 6 insists on keeping them apart.

**lockfile**: the committed embeddings and embedder identity for every semantic condition of a flow, making semantic routing reproducible bit for bit and promoting P2 to P1. Layer: flow authoring. Not to be confused with: a dependency lockfile, a mutex, a corpus freeze hash. Never called just "the lock".

**manifest**: the signed metadata of a pack: image hash, field dictionary, version, envelope identity, WCET bound, key identity. Layer: control plane. Not to be confused with: a provenance manifest (evidence and receipts), a packaging manifest. Both of those are always qualified.

**margin**: the gap between the best and second best similarity score from the embedding router. The confidence signal escalation is keyed to, not the raw score. Layer: kernel evaluation.

**match action fragment**: the decidable subset of the predicate language, boolean combinations of field against constant comparisons, membership in literal lists, and bare truthiness. Compiles exactly to a match action table. Layer: kernel evaluation. Not to be confused with: a link layer fragment. Also called: Level M. Never called just "the fragment" in a document that also discusses the wire.

**Mission Control**: the operator's single user, loopback console for observing runs, driving them and reading proofs. Layer: control plane. Not to be confused with: the orchestration layer it can drive.

**node**: one step of a flow: a heading, its instruction, and its ordered edges. Layer: flow authoring. Not to be confused with: a hardware node (always "device" or "board"), a predicate AST node, a code node (which is a flow node with a code worker), a log host field.

**normal**: the anchored baseline a camera's readings are measured against, identified on the wire by a sixteen bit identifier and replaceable only under its own policy. Layer: substrate execution. Not to be confused with: the adjective "ordinary", which must be spelled differently in any document that uses this noun. Also called (deprecated): background, reference, baseline.

**obligation**: a contractual or regulatory duty that resolves to a set of controls. The "why you must" above the "what you do". Layer: GRC. Not to be confused with: control, requirement.

**operator**: the person who runs a deployment day to day: monitors, swaps and attests policy, authors short lived changes, reads the trail. One of the four personas. Layer: control plane.

**orchestration**: the build loop that decides which unit of work runs next and collects what came back: the sprint and swarm machinery in `prismpath/orchestration/`. A fallback for an organisation with no orchestrator of its own, never required by the format. Layer: control plane. Not to be confused with: the control plane (the category PrismPath belongs to, which is about what a system is permitted to do rather than what runs next), Mission Control (the console that can drive orchestration), the engine's run loop over one flow. Also called (deprecated): "the control plane", for this machinery.

**outcome**: what a worker returns for one node: a text and a set of fields. The *input* to a routing decision, never its result. Layer: kernel evaluation. Not to be confused with: decision, stop state, the actuator's answer on the wire (which is an action result).

**overlay**: a short lived policy pack that names the policy of record it temporarily overrides, so `attest` can show both. Layer: control plane. Not to be confused with: an FPGA overlay (a bitstream), which is always spelled bitstream.

**P0, P1, P2**: portability levels describing how much of a flow the general engine runs without a model. P0 needs none; P1 has semantic edges all pinned in a lockfile; P2 needs the full engine. Layer: flow authoring. Not to be confused with: Level M, which is a fragment inside P0 and a different axis.

**pack**: the signed distribution unit: the byte identical image, a detached signed manifest, and the signature. Layer: control plane. Not to be confused with: bit packing into words, the `packing` profile, a C struct packing attribute, a content pack. The bit packing verb must be renamed; see section 6.

**packet**: the transport unit a Facet stream is carried in, over which a Merkle root commits. Layer: wire and transport. Not to be confused with: a network packet that is itself the subject of a decision, as in the eBPF classifier. That one is "the classified packet", spelled in full.

**park**: to hold on the signed fail safe rather than decide, because the state the policy needs is stale, absent or in flight. Always leaves a cause in the `state` class. Layer: substrate execution. Not to be confused with: abstain, refuse, deny. Also called (deprecated): hold.

**persona**: one of the four people a deployment is organised around: process owner, engineer, operator, assessor. The CLI groups its commands by them and the docs are indexed by them. Layer: control plane.

**policy of record**: the authored decision structure a deployment is actually governed by, as against an overlay or a test pack. Layer: flow authoring. Not to be confused with: "policy" used loosely for the compiled image, for a competitor's rule file, or for a severity setting.

**port**: an interface the core owns and the outside world implements, written in the core's own vocabulary. Six exist: Ingestion, Retrieval, Adjudicator, Action/Sink, Attestation, Deferral. Layer: control plane. Not to be confused with: a network or serial port, an RTL port, or "port" as a verb meaning reimplement. The verb is fine; the noun is reserved.

**posture**: the assessed state of a boundary: a set of facts with their provenance. Layer: GRC, and nowhere else. Not to be confused with: the resident node of a stateful selector, which has its own entry; the eBPF selector says `resident_node` now, and the RTL and the frozen selector corpus keep the old spelling because they are certified and do not move for a rename.

**predicate**: the restricted, side effect free expression after `when`, evaluated against the ctx. Total by construction: an impossible comparison is unsatisfied, never an error. Layer: kernel evaluation. Not to be confused with: condition (the broader raw string), guard.

**process owner**: the person who authors and tests the policy of record. One of the four personas. Layer: flow authoring.

**profile**: an optional Facet capability that becomes normative when declared: spiral packing, refresh, concentrator, receipt streams. Layer: wire and transport. Not to be confused with: a sandbox profile, an organization profile, the predicate profile returned on escalation (which should be named `atom_truth`).

**program**: the per edge sequence of stack machine words that folds atom results into a boolean. A part of an image, never the whole. Layer: substrate execution. Not to be confused with: the flow, the image, a running process.

**provenance**: the cryptographic binding of an artifact to what produced it. Layer: evidence and receipts. Not to be confused with: the static dataflow check that a `when` edge reads a field some node declares emitting, which is a lint and should be named `field_declaration`.

**quantizer**: the component that derives each field's cells from the policy text and maps a reading to its symbols. Layer: wire and transport. Not to be confused with: the codec, which turns symbols into codewords.

**reading**: one measurement of the world as a map of field names to values; the unit Figueroa quantization consumes. Layer: wire and transport. Not to be confused with: record (the framed bytes that carry a reading), event, sample, frame.

**receipt**: the durable per decision record: what decided, what it decided, under which policy version, at what time, with the cause byte if it refused, parked or escalated. The artifact the whole dictionary is written to serve. Layer: evidence and receipts. Not to be confused with: audit event (an administrative action), row (an evidence ledger entry), record.

**record**: a magic tagged, fixed layout struct on a link. Layer: wire and transport. Not to be confused with: reading (its payload), receipt, a compliance record, a route log entry.

**refusal cause**: why a decoder rejected a frame outright, as a status string of its own: `receipt-truncated`, `receipt-field-mismatch`, `receipt-invalid-cause`, and `ok` when it did not. Never one of the registry's names: a registered cause explains a decision, a refusal cause explains why there was no decision to read. The identifier is `refusal_cause`, and a decode returns it as the named half of its result beside the receipt. Layer: wire and transport. Not to be confused with: cause (the registered byte, which the same decode returns under `cause_code`), reason (prose for a person), the `wire:` class of the registry, whose codes are decisions a receiving substrate made and did receipt.

**refuse**: to decline to act and say why with a registered cause. In this system a refusal is a decision and carries a receipt; it is never silence. Layer: kernel evaluation. Not to be confused with: abstain, deny, park. Also called (deprecated): reject.

**register**: one field's typed slot in the substrate's register file, `(type, i32)`. The compiled materialization of a field. Layer: substrate execution. Not to be confused with: the cause registry, a plugin registry, a pre registered study, an FPGA shift register. Also called (deprecated): "register image" (`prismpath-hw/TABLE_FORMAT.md:103`), which should be "register file".

**relay**: a device that forwards records between links without aggregating them. Always qualified when more than one exists: the air relay, the host relay. Layer: wire and transport. Not to be confused with: the concentrator (which aggregates), the air gap courier (which should be named courier).

**resident node**: the node a selector is currently sitting on, persisted across evaluations so the next decision starts from where the system already is. The identifier is `resident_node`, and the state that holds it is the resident state. Layer: substrate execution. Not to be confused with: posture (the GRC term, which is an assessed state of a boundary and never this), a start node (what an image declares), the fail safe (where a selector parks when it cannot decide). Also called (deprecated): posture, which the eBPF selector no longer says; the RTL and the certified corpora still carry it and do not move for a rename.

**route**: the outcome of routing, the one target node a decision picked for one reading. Layer: kernel evaluation. Not to be confused with: target (the destination an edge declares, which is the same node named as a part of the flow rather than as the result of deciding), band (the spiral range whose members all take one route), path (the sequence of routes a run walks). A struct field that stores an edge's declared destination is `target`; a value that holds what routing produced is `route`. Also called (deprecated): band verdict, next_node, verdict, chosen.

**row**: one numbered claim in the evidence ledger, with its method, result, scope and provenance. Layer: evidence and receipts. Not to be confused with: a conformance case (a vector), a sensor line (a reading), a ledger entry, an atom.

**run**: one traversal of a flow from its start node to a terminal, a refusal, a suspension or the step bound. Layer: kernel evaluation.

**seal**: to close an epoch and commit its blocks to a Merkle root. Layer: wire and transport. Not to be confused with: anchor (which timestamps a root), receipt sealing in kernel (which should be named `emit_receipt`).

**selector**: a policy whose resident state persists across evaluations, so the decision depends on where the system already is. Layer: substrate execution. Not to be confused with: a CSS or DOM selector. Also called: resident FSM, stateful policy; pick one.

**sensor**: a physical transducer producing field values. Layer: substrate execution. Not to be confused with: a policy named `sensor_interlock` in the comparison corpus.

**spawn**: fan out from one node to child runs, with a declared join policy and deterministic child identity. Layer: flow authoring. Not to be confused with: `spawn` the process primitive.

**spiral**: the layout that packs a multi field reading onto one index whose contiguous ranges are the routes, so the wire carries one band identifier. Proven a bijection over the cell space in Lean. Layer: wire and transport.

**stop state**: what ended a run: `terminal`, `stuck`, `max_steps`, `needs_human`, `waiting`, `contract_violation`. The `stopped` field. Layer: kernel evaluation. Not to be confused with: cause (finer, and registered), outcome. Also called (deprecated): stop reason, outcome (in `prismpath-hw/TABLE_FORMAT.md:23`).

**substrate**: an independent execution environment that must produce byte identical decisions from the same image: Python, JavaScript, Rust, Go, the C target, eBPF, four MCU instruction sets, the fabric. Layer: substrate execution. Not to be confused with: target, kernel, twin, port, engine, runtime, leg, all of which have been used for this and should not be.

**symbol**: the index of the cell a field's value falls into, the atomic unit of the Facet wire, transmitted as `symbol + 1` under Zeckendorf coding. Layer: wire and transport. Not to be confused with: codeword (the bits), a document symbol in the language server, a cause byte (which rides the same slot under the receipt profile).

**table image**: see image. Use the full phrase on first mention in any document; `image` thereafter.

**target**: the destination node of an edge. Layer: flow authoring, and carried unchanged into kernel evaluation and substrate execution. Not to be confused with: a substrate, a build target, a risk target, the Rust build directory. Also called (deprecated): chosen, and `route` where the name holds an edge's declared destination rather than the outcome of a decision.

**terminal node**: a node with no edges. Reaching one ends the run cleanly, with no cause code. Layer: flow authoring.

**tier**: which mechanism resolves an edge: deterministic, semantic, error, or event. Selected by the syntactic shape of the condition, never chosen by the author. Layer: flow authoring. Not to be confused with: ledger anchoring tiers, portability levels.

**trail**: the Merkle rooted sequence of receipts over a window, and the operator's read side of it. Layer: evidence and receipts. Not to be confused with: a git commit trailer, the audit log.

**vector**: one case in a frozen corpus: a condition and a ctx with a recorded result, or a scripted run with a recorded path. Layer: kernel evaluation. Not to be confused with: an embedding vector, which is always "embedding".

**visits**: the per node counter the engine increments before a worker runs and exposes to that node's predicates. An engine owned register, not a worker emitted field. Layer: kernel evaluation.

**WCET bound**: the signed worst case execution bound that travels with an image, derived from the table counts alone and recomputed at verify. Layer: substrate execution. Not to be confused with: a timeout, a step bound, a staleness bound.

**wire**: the Facet encoding, a transport agnostic bitstream format. Layer: wire and transport. Not to be confused with: a link or a transport (Facet is explicitly not one), the vision bench's whole record catalogue (which is "the bench links"), the `wire[]` byte array inside a record.

**witness**: something that makes a claim checkable by observation: a concrete path for reachability, a pin measurement for a timing bound, a second sensor for a fused reading. Always qualified. Layer: varies.

**worker**: whatever produces a candidate outcome for a node: a hosted model, a local model, a shell process, a function, another orchestration system, or a deterministic program. PrismPath does not own it. Layer: control plane. Not to be confused with: an LLM agent (one kind of worker), a server process. `WorkerFn` is the type. Also called (deprecated): agent, in every surface that still answers to it and warns or hides it, `run(agent=)`, `cli_agent`, `worker_agent` and `prismpath run --agent`; executor.

**Zeckendorf coding**: the self delimiting Fibonacci integer code the wire uses, where every code ends in a unique `11` so a stream needs no header and no length field. Prior art, used here and not claimed. Layer: wire and transport.

---

## Naming rules

Fourteen rules a contributor can apply without consulting anyone.

1. **One thing, one word, at one layer.** If a word already names something else in the dictionary, do not reuse it, even in a different directory and even when your field's usage is the standard one. Context resolution works for the author and fails for the reader.

2. **Name from the decision's point of view.** Before you name anything, answer: which moment in the life of a decision is this, authoring, proving, compiling, carrying, evaluating, receipting, or auditing? If you cannot answer, the name is wrong, not the question.

3. **A borrowed word keeps its borrowed meaning or is not borrowed.** If a networking engineer, an auditor or a video engineer would be misled by your use of their word, use a plain English word instead. Do not borrow a *different* word from the same field to escape the problem.

4. **When two domains offer a word, the receipt reader wins.** The receipt is the one artifact where all seven layers speak at once, to a person who knows none of them.

5. **No bare word that has two senses in this repository.** Banned unqualified, in prose and in identifiers: `core`, `floor`, `host`, `lock`, `gate`, `spec`, `air`, `reference`, `band`, `frame`, `image` (outside the substrate layer), `the ledger`, `the evaluator`, `the target`, `the control plane`, `the relay`, `the fragment`. Qualify or rename.

6. **Wire record fields carry the dictionary's term, not the layer's habit.** A field that holds a target node index is named `target`, not `route`, in the struct, in `WIRE.md`, and in the receiver that mirrors it by hand. A record's identity is its whole four byte magic; never compare the version digit alone (`prismpath-hw/esp-vision-node/WIRE.md:12` already warns about this and it is still worth a rule).

7. **Every machine readable refusal is a registered cause.** Named `class:detail`, lowercase, hyphenated after the colon, appended to `prismpath/kernel/causes.py` and never renumbered or renamed. A string that *looks* like a cause name and is not in the registry is a bug, not a convenience.

8. **`cause` is the machine value, `reason` is prose for a human.** Never both for one thing, never one in place of the other. A function that returns refusal codes returns causes; a field that holds a sentence is named `explanation` or `note`, not `reason`.

9. **Return codes that are not causes get their own named enum and a distinct numeric base**, and the call site that maps them into causes states the mapping in a comment. Two small integer namespaces sharing a range on one board is how a wrong cause reaches a receipt.

10. **The checking verbs are pinned and not interchangeable.** `validate` is static analysis of an authored artifact before anything runs. `verify` checks a signature or a proof someone else produced. `certify` runs a frozen corpus on one substrate and records the score. `check` is an internal predicate. `gate` blocks a merge. `guard` restricts at runtime. Pick the verb that matches the job, never the one that sounds strongest.

11. **The proof words are earned.** `proven` means a machine checked proof or an exhaustive model check, and nothing else. A green gate is "gate green"; a unit with a ledger commit is "attested"; neither is "proven". `machine checked` means a proof assistant or exhaustive search, never coverage.

12. **Documents change first, identifiers follow, certified bytes do not move.** Fix the term in `docs/POSITION.md` and the dictionary, then in prose, then in code. Where a rename would touch bytes that are certified (`prismpath-hw/interp.c`, the RTL, the eBPF programs, the frozen corpora, the append only cause registry), do not rename: record the frozen name in the dictionary as a deprecated alias and write the companion walkthrough instead.

13. **A new domain word enters the dictionary in the same commit that introduces it**, and is added to `tools/arch_guard.py`'s word list if it is a domain noun, so the hexagonal boundary is enforced rather than intended. A pull request that introduces a domain noun with no dictionary entry is incomplete.

14. **Abbreviations inherit their term's rules.** `nid` is legal only where `node` means a device, which it no longer does; a device identifier is `device_id`. Abbreviate only terms whose full form is in the dictionary, and abbreviate the same way everywhere (`pver` for policy version, `ctx` for the evaluation environment, `seq` for the sequence counter).

---

## Keeping it current

A term enters here in the same commit that introduces it. A term leaves only by being marked deprecated
with its replacement; entries are never silently deleted, so an old receipt or an old paper can still be
read against this document. Certified bytes do not move for a rename: where a frozen identifier disagrees
with this dictionary, the entry records the frozen name as a deprecated alias and points at the
walkthrough document that explains it.
