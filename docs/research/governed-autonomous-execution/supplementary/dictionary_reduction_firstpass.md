# Dictionary reduction, first pass classification

Supplementary artifact for "Governed Autonomous Execution: Authority Separation and Semantic Invariance Across
Execution Boundaries", the per-term classification behind its Appendix A.

A first pass over every entry in the Decision Dictionary (`docs/DICTIONARY.md` in the PrismPath repository at
commit d4b13bf, the Entries section). Each term is assigned exactly one class
from the rubric, plus a strict primitive_candidate flag and, where it applies, the distinction the
term exists to protect. It is raw material for the reduction the paper reports. It does not name the
theory's primitive set and it does not attempt the final reduction. Rows are in dictionary order.

Class rubric applied here. PRIMITIVE is an irreducible role or object any governed execution system
would need, definable without reference to PrismPath, held very strict. DERIVED is a theory level
concept definable in terms of primitives. MECHANISM is a general technique that realizes a concept but
is not itself required by the theory. IMPLEMENTATION is PrismPath specific machinery a general theory
would strip. EVIDENCE names a record or artifact of what happened, preferred over DERIVED when the
term's primary role is to be a record.

| term | layer | class | one_line_definition | primitive_candidate | distinction_guarded |
|---|---|---|---|---|---|
| abstain | kernel evaluation | DERIVED | The decision to make no decision because the information required is absent. | no | abstain vs deny (missing information vs a decision) |
| adapter | control plane | MECHANISM | An implementation of ports that carries one domain's knowledge so the core carries none. | no | adapter vs port vs connector (implementation vs interface vs base class) |
| adjudicate | control plane | DERIVED | To turn one unit of work into one structured result through the Adjudicator port. | no | adjudicate vs decide vs route (producing a result vs the whole act vs choosing an edge) |
| air gap | evidence and receipts | MECHANISM | A deliberate absence of network connectivity, and the ledger tier built for it. | no | air gap vs over the air (no connectivity vs across a link) |
| anchor | evidence and receipts | MECHANISM | To bind a Merkle root to a timestamp a third party can verify without trusting the emitter. | no | anchor vs seal vs attest (timestamp vs closing an epoch vs binding a claim to a key) |
| annotation | flow authoring | IMPLEMENTATION | A line inside a node of the form @name(args) declaring something the toolchain acts on. | no |  |
| assessor | control plane | DERIVED | The person who anchors, verifies and audits receipts, the fourth persona. | no | assessor vs evaluator (a person vs a certified routine) |
| atom | kernel evaluation | IMPLEMENTATION | The irreducible unit of a predicate, a field operator constant triple or a bare truthiness test. | no |  |
| attest | evidence and receipts | MECHANISM | To bind a claim to a key and a content address so a later reader can check it without trust. | no | attest vs anchor vs certify vs verify (binding a claim vs timestamp vs running a corpus vs checking) |
| audit event | control plane | EVIDENCE | A durable record of an administrative action, principally a policy swap, written either way. | no | audit event vs receipt (an administrative action vs a decision) |
| authority | flow authoring | PRIMITIVE | What a system is permitted to do, as authored by a person and held in the flow document. | yes | authority vs computation vs evidence (what is permitted vs what is computed vs what is recorded) |
| band | wire and transport | IMPLEMENTATION | A contiguous range of the joint spiral index whose members all route the same way. | no | band vs cell (a joint spiral range vs one field bucket) |
| bound | substrate execution | MECHANISM | Used bare, a worst case execution bound unless qualified; every other bound is named. | no | worst case execution bound vs other bounds |
| catalog | GRC | DERIVED | An ordered set of controls with their assessment objectives, content addressed and bound in. | no | catalog vs OSCAL catalog (an internal set of controls vs an external format) |
| cause | evidence and receipts | MECHANISM | The registered reason a decision refused, parked or escalated, carried as one frozen byte. | no | cause vs reason (machine value vs human prose) |
| cell | wire and transport | IMPLEMENTATION | A maximal set of values of one field on which every atom of the policy has constant truth. | no | cell vs band (one field bucket vs a joint range) |
| certify | substrate execution | MECHANISM | To run a frozen corpus on one substrate and record the score against a declared subset. | no | certify vs verify vs validate (running a corpus vs checking a signature vs static analysis) |
| codebook | wire and transport | IMPLEMENTATION | The whole set of cells a policy induces, every field with its cut points and symbol map. | no | codebook vs image (the partition vs the decision table) |
| codeword | wire and transport | IMPLEMENTATION | One self delimiting Zeckendorf code on the wire, ending in the unique closing pair. | no | codeword vs symbol (the bits vs the integer encoded) |
| concentrator | wire and transport | MECHANISM | A bridge that concatenates records from many streams into one datagram so a fleet amortises. | no | concentrator vs relay (aggregates vs forwards) |
| condition | flow authoring | IMPLEMENTATION | The raw text after the colon on an edge, before any tier classification. | no | condition vs predicate (a raw string vs the deterministic subset) |
| conformance | kernel evaluation | DERIVED | The property of reproducing every committed vector of the frozen corpus exactly. | no | conformance vs certification (a property vs one run on a substrate) |
| connector | control plane | IMPLEMENTATION | The SDK base class an adapter subclasses, carrying the six ports. | no | connector vs adapter vs port |
| contract | flow authoring | DERIVED | The interface between a flow and its workers, the fields each node must emit and their types. | no |  |
| control | GRC | DERIVED | A requirement from a governing framework, with assessment objectives and evidence beneath it. | no | control vs control plane (a requirement vs the governing category) |
| control plane | control plane | DERIVED | The category of system that decides what an autonomous system is permitted to do. | no | deciding what is permitted vs producing candidate actions |
| corpus | kernel evaluation | MECHANISM | The frozen set of vectors an implementation is judged by. | no | corpus vs vector (the set vs a single case) |
| crosswalk | GRC | MECHANISM | A table mapping the controls of one framework onto another so one assessment reaches several. | no |  |
| ctx | kernel evaluation | IMPLEMENTATION | The evaluation environment a predicate sees, the outcome fields plus engine owned counters. | no | ctx vs register file vs reading (the same environment seen across layers) |
| datagram | wire and transport | IMPLEMENTATION | The delivery unit of the transport a Facet stream is bound to. | no |  |
| decision | all | DERIVED | The act of determining where a run goes next and whether an action is permitted, and its record. | no | decision vs outcome (the act vs the worker's return, an input) |
| deny | kernel evaluation | DERIVED | The decision that an action is not authorized, a decision and not an absence of one. | no | deny vs abstain (a decision made vs no decision for missing information) |
| determination | GRC | DERIVED | The GRC word for a decision about one control, met, partially met, or not met. | no | determination vs decision (a GRC control determination vs the kernel act) |
| deterministic edge | flow authoring | IMPLEMENTATION | An edge resolved by evaluating a predicate against the outcome fields, free and exact. | no | deterministic vs semantic resolution (an exact predicate vs an inferred edge) |
| device_id | wire and transport | IMPLEMENTATION | The identifier of one physical board or host on a link, carried in a record. | no | device_id vs node (a device vs a flow step) |
| edge | flow authoring | IMPLEMENTATION | A line of the form target colon condition inside a node, the authored transition. | no |  |
| engine | kernel evaluation | IMPLEMENTATION | The full run loop: parse, dispatch to a worker, route, count visits, suspend, checkpoint, receipt. | no | engine vs interpreter vs evaluator vs kernel |
| envelope | control plane | MECHANISM | The declared bounds a signed artifact must fit inside, checked at admission and refused not clamped. | no | checked and refused, never clamped (fail closed) |
| epoch | wire and transport | IMPLEMENTATION | A sealed window of the Facet stream whose Merkle root chains to the previous one. | no |  |
| escalate | kernel evaluation | MECHANISM | To hand a decision to something more expensive because confidence is insufficient. | no | escalate vs abstain (routing to a costlier decider vs declining) |
| evaluator | substrate execution | IMPLEMENTATION | One call that takes a node index and a register file and returns the first matching edge. | no | evaluator vs assessor (a certified routine vs a person) |
| evidence | evidence and receipts, GRC | PRIMITIVE | The committed artifact that backs a claim, or the material that supports a determination. | yes | evidence vs the claim it backs (supporting material vs what is asserted) |
| evidence ledger | evidence and receipts | EVIDENCE | The Markdown document in which every public claim is a numbered row with method and provenance. | no | evidence ledger vs the cryptographic ledgers (a document vs cryptographic structures) |
| Facet | wire and transport | IMPLEMENTATION | The decision sufficient telemetry wire carrying quantized symbols in self framing codes. | no |  |
| fail safe | substrate execution | MECHANISM | The signed, most restrictive node a substrate parks on when it cannot decide. | no | a fail closed default vs an authored catch all |
| field | all | DERIVED | A named value a predicate can test, surviving every layer unchanged. | no |  |
| Figueroa quantization | wire and transport | IMPLEMENTATION | The map from a policy's text to the cells of each field that can change a decision. | no | Figueroa quantization vs Facet (the map vs the wire carrying results) |
| finding | flow authoring | EVIDENCE | A diagnostic PrismPath emits about an authored flow, with a stable code and a severity. | no | finding vs scan result (an emitted diagnostic vs an ingested input fact) |
| floor | varies | MECHANISM | A bound below which a decision is refused rather than degraded, always qualified. | no | refused rather than degraded (fail closed) |
| flow | flow authoring | IMPLEMENTATION | The authored Markdown document that holds a decision structure, the source of everything else. | no | representation vs semantics (the source document vs its parsed and compiled forms) |
| fragment | wire and transport | IMPLEMENTATION | A piece of an oversized payload on the first hop, reassembled by the receiver. | no |  |
| gate | control plane | MECHANISM | A machine check that decides whether work may proceed, in CI or at admission. | no | gate vs guard (blocks at merge or admission vs restricts at runtime) |
| graph | kernel evaluation | IMPLEMENTATION | The parsed, in memory form of a flow: nodes, edges, annotations, start. | no | a parsed form vs source text |
| guard | control plane | MECHANISM | The deterministic safety floor whose grammar has no verb for permitting, so it can only restrict. | no | restricts at runtime, can only restrict never permit (default deny) |
| hop | wire and transport | IMPLEMENTATION | One link in the bench topology, named for the specific segment it is. | no |  |
| host | control plane | IMPLEMENTATION | The application or daemon that owns a governed decision boundary, principally the PolicyHost. | no |  |
| hot swap | control plane | MECHANISM | Replacing the live policy without rebuilding, after checks, flipping atomically with an audit event. | no |  |
| image | substrate execution | IMPLEMENTATION | The compiled Level M table, a few hundred bytes identical on every substrate. | no |  |
| instruction | flow authoring | IMPLEMENTATION | The prose inside a node, handed to the worker verbatim and never interpreted by the engine. | no | uninterpreted worker prose vs interpreted annotation |
| interpreter | substrate execution | IMPLEMENTATION | A table image executor: given a node and a register file, walk the edges and return the target. | no |  |
| kernel | kernel evaluation | IMPLEMENTATION | A conformant implementation of the flow language, judged by the frozen corpus. | no |  |
| keyframe | wire and transport | IMPLEMENTATION | Under the refresh profile, an ordinary Facet frame sent on a cadence so staleness is bounded. | no |  |
| Level M | kernel evaluation | IMPLEMENTATION | The match action fragment, the decidable subset of the predicate language every substrate runs. | no | a decidable fragment vs a portability level (different axes) |
| lockfile | flow authoring | MECHANISM | The committed embeddings and embedder identity that make semantic routing reproducible. | no |  |
| manifest | control plane | EVIDENCE | The signed metadata of a pack: image hash, field dictionary, version, envelope, WCET bound, key. | no |  |
| margin | kernel evaluation | IMPLEMENTATION | The gap between the best and second best similarity score, the confidence signal for escalation. | no | margin vs raw score (the confidence signal vs the raw score) |
| match action fragment | kernel evaluation | IMPLEMENTATION | The decidable subset of the predicate language, compiling exactly to a match action table. | no |  |
| Mission Control | control plane | IMPLEMENTATION | The operator's single user loopback console for observing runs, driving them and reading proofs. | no | Mission Control vs orchestration (the console vs the layer it drives) |
| node | flow authoring | IMPLEMENTATION | One step of a flow: a heading, its instruction, and its ordered edges. | no | a flow step vs a hardware device |
| normal | substrate execution | IMPLEMENTATION | The anchored baseline a camera's readings are measured against, replaceable only under its policy. | no | normal the noun vs ordinary the adjective |
| obligation | GRC | DERIVED | A contractual or regulatory duty that resolves to a set of controls, the why above the what. | no | obligation vs control (the duty vs the requirement) |
| operator | control plane | DERIVED | The person who runs a deployment day to day, monitoring, swapping and attesting policy. | no |  |
| orchestration | control plane | MECHANISM | The build loop that decides which unit of work runs next, a fallback never required by the format. | no | what runs next vs what is permitted (orchestration vs control plane) |
| outcome | kernel evaluation | PRIMITIVE | What a worker returns for one node, a text and a set of fields, the input to a routing decision. | yes | proposal vs decision (the candidate input vs the authorized result) |
| overlay | control plane | MECHANISM | A short lived policy pack that names the policy of record it temporarily overrides. | no |  |
| P0, P1, P2 | flow authoring | IMPLEMENTATION | Portability levels describing how much of a flow the general engine runs without a model. | no | a portability level vs Level M (different axes) |
| pack | control plane | IMPLEMENTATION | The signed distribution unit: the byte identical image, a detached signed manifest, the signature. | no |  |
| packet | wire and transport | IMPLEMENTATION | The transport unit a Facet stream is carried in, over which a Merkle root commits. | no |  |
| park | substrate execution | DERIVED | To hold on the signed fail safe rather than decide, because the needed state is stale or absent. | no | park vs abstain (holding on the fail safe for stale state vs declining for missing information) |
| persona | control plane | DERIVED | One of the four people a deployment is organised around: process owner, engineer, operator, assessor. | no |  |
| policy of record | flow authoring | DERIVED | The authored decision structure a deployment is actually governed by. | no | policy of record vs overlay (the governing authority vs a temporary override) |
| port | control plane | MECHANISM | An interface the core owns and the outside world implements, written in the core's vocabulary. | no | port vs adapter vs connector (interface vs implementation vs base class) |
| posture | GRC | DERIVED | The assessed state of a boundary, a set of facts with their provenance. | no | posture vs resident node (an assessed boundary state vs a selector's current node) |
| predicate | kernel evaluation | IMPLEMENTATION | The restricted side effect free expression after when, total by construction and never an error. | no | predicate vs condition (the deterministic subset vs the raw string) |
| process owner | flow authoring | DERIVED | The person who authors and tests the policy of record, one of the four personas. | no |  |
| profile | wire and transport | IMPLEMENTATION | An optional Facet capability that becomes normative when declared. | no |  |
| program | substrate execution | IMPLEMENTATION | The per edge sequence of stack machine words that folds atom results into a boolean. | no |  |
| provenance | evidence and receipts | DERIVED | The cryptographic binding of an artifact to what produced it. | no | provenance vs truth (who or what produced it vs whether the claim is true) |
| quantizer | wire and transport | IMPLEMENTATION | The component that derives each field's cells from the policy and maps a reading to its symbols. | no | quantizer vs codec (deriving cells and mapping vs turning symbols into codewords) |
| reading | wire and transport | PRIMITIVE | One measurement of the world as a map of field names to values. | yes | reading vs record (the measurement vs the framed bytes that carry it) |
| receipt | evidence and receipts | EVIDENCE | The durable per decision record: what decided, what it decided, under which policy, when, with cause. | no | receipt vs audit event (a decision vs an administrative action) |
| record | wire and transport | IMPLEMENTATION | A magic tagged, fixed layout struct on a link. | no | record vs reading (the framed bytes vs the payload) |
| refusal cause | wire and transport | MECHANISM | Why a decoder rejected a frame outright, a status string of its own and never a registry name. | no | refusal cause vs cause (a decode failure with no decision vs a registered decision reason) |
| refuse | kernel evaluation | DERIVED | To decline to act and say why with a registered cause, a decision that carries a receipt not silence. | no | refuse vs abstain (a decision with a cause vs no decision for missing information) |
| register | substrate execution | IMPLEMENTATION | One field's typed slot in the substrate's register file, the compiled materialization of a field. | no | the compiled materialization of a field vs the field itself |
| relay | wire and transport | MECHANISM | A device that forwards records between links without aggregating them. | no | relay vs concentrator (forwards vs aggregates) |
| resident node | substrate execution | IMPLEMENTATION | The node a selector is currently sitting on, persisted across evaluations. | no | resident node vs posture (a selector's current node vs an assessed boundary state) |
| route | kernel evaluation | DERIVED | The outcome of routing, the one target node a decision picked for one reading. | no | route vs target (the outcome of deciding vs an edge's declared destination) |
| row | evidence and receipts | EVIDENCE | One numbered claim in the evidence ledger, with its method, result, scope and provenance. | no |  |
| run | kernel evaluation | DERIVED | One traversal of a flow from its start node to a terminal, a refusal, a suspension or the step bound. | no |  |
| seal | wire and transport | MECHANISM | To close an epoch and commit its blocks to a Merkle root. | no | seal vs anchor (closing an epoch vs timestamping a root) |
| selector | substrate execution | MECHANISM | A policy whose resident state persists across evaluations so the decision depends on where it is. | no |  |
| sensor | substrate execution | DERIVED | A physical transducer producing field values. | no |  |
| spawn | flow authoring | MECHANISM | To fan out from one node to child runs, with a declared join policy and deterministic identity. | no |  |
| spiral | wire and transport | IMPLEMENTATION | The layout that packs a multi field reading onto one index whose contiguous ranges are the routes. | no |  |
| stop state | kernel evaluation | DERIVED | What ended a run: terminal, stuck, max steps, needs human, waiting, contract violation. | no | stop state vs cause (what ended a run vs the finer registered reason) |
| substrate | substrate execution | DERIVED | An independent execution environment that must produce byte identical decisions from one image. | no |  |
| symbol | wire and transport | IMPLEMENTATION | The index of the cell a field's value falls into, the atomic unit of the Facet wire. | no | symbol vs codeword (the integer vs the bits) |
| table image | substrate execution | IMPLEMENTATION | The full phrase for image, used on first mention then image thereafter. | no |  |
| target | flow authoring | IMPLEMENTATION | The destination node of an edge, carried unchanged into kernel and substrate layers. | no | target vs route (an edge's declared destination vs the outcome of deciding) |
| terminal node | flow authoring | IMPLEMENTATION | A node with no edges, whose reaching ends the run cleanly with no cause code. | no |  |
| tier | flow authoring | IMPLEMENTATION | Which mechanism resolves an edge: deterministic, semantic, error, or event. | no |  |
| trail | evidence and receipts | EVIDENCE | The Merkle rooted sequence of receipts over a window, and the operator's read side of it. | no |  |
| vector | kernel evaluation | MECHANISM | One case in a frozen corpus: a condition and a ctx with a recorded result, or a scripted run. | no | vector vs embedding (a corpus case vs an embedding) |
| visits | kernel evaluation | IMPLEMENTATION | The per node counter the engine increments before a worker runs and exposes to its predicates. | no | an engine owned counter vs a worker emitted field |
| WCET bound | substrate execution | MECHANISM | The signed worst case execution bound that travels with an image, recomputed at verify. | no |  |
| wire | wire and transport | IMPLEMENTATION | The Facet encoding, a transport agnostic bitstream format. | no | an encoding vs a transport (Facet is not a transport) |
| witness | varies | EVIDENCE | Something that makes a claim checkable by observation, a path, a pin measurement, a second sensor. | no |  |
| worker | control plane | DERIVED | Whatever produces a candidate outcome for a node, which PrismPath does not own. | no | what a worker reports vs what the gate decides (a candidate vs the authorized result) |
| Zeckendorf coding | wire and transport | IMPLEMENTATION | The self delimiting Fibonacci integer code the wire uses, prior art used and not claimed. | no |  |

## Tally

Counts per class, over 120 entries.

| class | count |
|---|---|
| PRIMITIVE | 4 |
| DERIVED | 27 |
| MECHANISM | 28 |
| IMPLEMENTATION | 53 |
| EVIDENCE | 8 |

### primitive_candidate = yes

- authority (the authority relation, what a system is permitted to do)
- outcome (the proposal, a candidate consequential transition, the input to a decision)
- evidence (a unit of evidence, the committed artifact that backs a claim)
- reading (a state at a boundary, one measurement of the world)

### distinct distinction_guarded values used

- authority vs computation vs evidence (what is permitted vs what is computed vs what is recorded)
- proposal vs decision (the candidate input vs the authorized result)
- deciding what is permitted vs producing candidate actions
- what runs next vs what is permitted (orchestration vs control plane)
- provenance vs truth (who or what produced it vs whether the claim is true)
- evidence vs the claim it backs (supporting material vs what is asserted)
- cause vs reason (machine value vs human prose)
- refusal cause vs cause (a decode failure with no decision vs a registered decision reason)
- abstain vs deny (missing information vs a decision)
- deny vs abstain (a decision made vs no decision for missing information)
- park vs abstain (holding on the fail safe for stale state vs declining for missing information)
- refuse vs abstain (a decision with a cause vs no decision for missing information)
- escalate vs abstain (routing to a costlier decider vs declining)
- decision vs outcome (the act vs the worker's return, an input)
- route vs target (the outcome of deciding vs an edge's declared destination)
- target vs route (an edge's declared destination vs the outcome of deciding)
- what a worker reports vs what the gate decides (a candidate vs the authorized result)
- reading vs record (the measurement vs the framed bytes that carry it)
- record vs reading (the framed bytes vs the payload)
- representation vs semantics (the source document vs its parsed and compiled forms)
- a parsed form vs source text
- ctx vs register file vs reading (the same environment seen across layers)
- the compiled materialization of a field vs the field itself
- deterministic vs semantic resolution (an exact predicate vs an inferred edge)
- uninterpreted worker prose vs interpreted annotation
- condition vs predicate (a raw string vs the deterministic subset)
- predicate vs condition (the deterministic subset vs the raw string)
- determination vs decision (a GRC control determination vs the kernel act)
- control vs control plane (a requirement vs the governing category)
- obligation vs control (the duty vs the requirement)
- catalog vs OSCAL catalog (an internal set of controls vs an external format)
- posture vs resident node (an assessed boundary state vs a selector's current node)
- resident node vs posture (a selector's current node vs an assessed boundary state)
- policy of record vs overlay (the governing authority vs a temporary override)
- assessor vs evaluator (a person vs a certified routine)
- evaluator vs assessor (a certified routine vs a person)
- Mission Control vs orchestration (the console vs the layer it drives)
- adapter vs port vs connector (implementation vs interface vs base class)
- port vs adapter vs connector (interface vs implementation vs base class)
- connector vs adapter vs port
- adjudicate vs decide vs route (producing a result vs the whole act vs choosing an edge)
- engine vs interpreter vs evaluator vs kernel
- band vs cell (a joint spiral range vs one field bucket)
- cell vs band (one field bucket vs a joint range)
- codebook vs image (the partition vs the decision table)
- codeword vs symbol (the bits vs the integer encoded)
- symbol vs codeword (the integer vs the bits)
- concentrator vs relay (aggregates vs forwards)
- relay vs concentrator (forwards vs aggregates)
- quantizer vs codec (deriving cells and mapping vs turning symbols into codewords)
- Figueroa quantization vs Facet (the map vs the wire carrying results)
- an encoding vs a transport (Facet is not a transport)
- anchor vs seal vs attest (timestamp vs closing an epoch vs binding a claim to a key)
- seal vs anchor (closing an epoch vs timestamping a root)
- attest vs anchor vs certify vs verify (binding a claim vs timestamp vs running a corpus vs checking)
- certify vs verify vs validate (running a corpus vs checking a signature vs static analysis)
- air gap vs over the air (no connectivity vs across a link)
- audit event vs receipt (an administrative action vs a decision)
- receipt vs audit event (a decision vs an administrative action)
- evidence ledger vs the cryptographic ledgers (a document vs cryptographic structures)
- finding vs scan result (an emitted diagnostic vs an ingested input fact)
- conformance vs certification (a property vs one run on a substrate)
- corpus vs vector (the set vs a single case)
- vector vs embedding (a corpus case vs an embedding)
- stop state vs cause (what ended a run vs the finer registered reason)
- device_id vs node (a device vs a flow step)
- a flow step vs a hardware device
- gate vs guard (blocks at merge or admission vs restricts at runtime)
- restricts at runtime, can only restrict never permit (default deny)
- a fail closed default vs an authored catch all
- checked and refused, never clamped (fail closed)
- refused rather than degraded (fail closed)
- margin vs raw score (the confidence signal vs the raw score)
- normal the noun vs ordinary the adjective
- an engine owned counter vs a worker emitted field
- a decidable fragment vs a portability level (different axes)
- a portability level vs Level M (different axes)
- worst case execution bound vs other bounds
