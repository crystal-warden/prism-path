# Verdict: where PrismPath stands against OPA, Cedar, Cerbos, OpenFGA and Openlane

*Phase 6 of the pre registered comparison (PREREGISTRATION.md, freeze 54f05739). Written after every
result file existed. Every grade, count, and per dimension verdict below is read from the matrix
`matrix.py` builds from the 638 result files under `results/` and from nothing else (`MATRIX.md` is
its rendering; `matrix.json` is regenerated, not stored);
`tests/test_comparisons_verdict.py` fails if this document and the matrix disagree. September 2026.*

## 1. What was asked, and what came back

PrismPath is a control plane for autonomous systems, one of many. This comparison was built to find
out, with executed tests rather than argument, how its capabilities stand against the established
policy decision engines, where it can operate that they cannot without work, where they are better,
and where the two integrate. Eight properties PrismPath builds in (Group A) and five where it was
expected to lose (Group B) were fixed before any comparator was installed, each with a neutral test
corpus, a three step grade (native, with work, not), a glue budget for "with work" (300 lines, 8 hours,
no new trust anchor), and a written prediction for every cell.

The pre registration also fixed a strict pass or fail bar on top of the map: a Group A property counts
as a "distinct layer" only if PrismPath is native and every comparator, glue included, is not. That bar
was frozen, so it is answered here, and the answer is no on every property. It is one finding in the
map, reported in section 3, and it is not the question the comparison was built to answer.

The map, from the result files:

| dim | what it tests | PrismPath | OPA | Cedar | Cerbos | OpenFGA | Openlane | OPA plus glue | predicted | computed |
|---|---|---|---|---|---|---|---|---|---|---|
| A1 | abstain as a first class outcome | native | native | with work | with work | not | not | native | NOT-DISTINCT | NOT-DISTINCT |
| A2 | human routing as a routed outcome | native | native | with work | with work | not | not | native | NOT-DISTINCT | NOT-DISTINCT |
| A3 | one policy image, identical decisions across substrates | native | not | not | not | not | not | with work | DISTINCT | NOT-DISTINCT |
| A4 | signed, tamper evident, per decision receipts with cause | native | with work | not | not | not | not | with work | NOT-DISTINCT | NOT-DISTINCT |
| A5 | compact decision sufficient wire | native | not | not | with work | not | not | with work | NOT-DISTINCT | NOT-DISTINCT |
| A6 | anti rollback at the enforcement point | native | with work | not | not | not | not | with work | NOT-DISTINCT | NOT-DISTINCT |
| A7 | bounded decision time | native | with work | with work | with work | not | not | with work | DISTINCT | NOT-DISTINCT |
| A8 | the AI worker governance loop | native | with work | not | not | not | not | with work | NOT-DISTINCT | NOT-DISTINCT |
| B1 | policy expressiveness | not | native | native | native | with work | not | n/a | LOSES | LOSES |
| B2 | formal verification of the engine | not | not | native | not | not | not | n/a | LOSES | LOSES |
| B3 | relationship modeling | not | native | native | with work | native | not | n/a | LOSES | LOSES |
| B4 | ecosystem and integrations | with work | native | native | native | native | native | n/a | LOSES | LOSES |
| B5 | maturity, adoption, community | not | native | native | native | native | with work | n/a | LOSES | LOSES |

The last two columns are the pre registered layer verdict and the computed one. The "OPA plus glue"
column is the combination built in Phase 5: OPA with the three glue pieces that bring it to
PrismPath's row, run for real and measured. It covers Group A only, by design.

Read as a capability map, the table says three things. PrismPath is native on all eight properties it
builds in, and no comparator is native on more than two. OPA, the direct comparator, can be brought to
the same eight with 391 lines of glue in three pieces; Cedar, Cerbos, and OpenFGA cannot be brought to
the receipts row at all under the budget, because a signature needs a trust anchor they do not have.
And PrismPath loses every Group B property as predicted. Thirteen of seventy eight cell predictions
were wrong; every one is in section 4.

## 2. Where PrismPath operates, where the others are better, where they integrate

**Where PrismPath operates that the others need work or cannot reach.** Small devices and chips: the
same 224 B or 160 B image decided the 23 corpus readings identically on host Python, the C reference,
in kernel on aarch64 and x86_64, on both ISAs of an RP2350, and on the Zynq-7020 fabric (seven legs,
`results/prismpath/A3__*`, ledger rows #145 and #146). Radio links where bytes are scarce: a reading
crosses the wire in 4 to 6 B including the receipt, against 117 B for OPA over HTTP, 237 B for Cedar,
512 B for Cerbos. Paths that need a time guarantee: a per policy worst case bound travels signed with
the image, is recomputed at verify, and was honored on the fabric pins for both comparison images (34
of 35 and 23 of 24 cycles, `results/prismpath/evidence/A7/pins_*.json`). The AI worker gate: the six
proposal loop returns allow, deny, abstain, and escalate to a human, tells a policy selected
escalation from a worker requested one by cause code (34), and leaves a signed receipt per decision,
in one run with nothing added.

**Where the others are better, and PrismPath should not compete.** Rich permission policies: Rego,
Cedar, and Cerbos express the RBAC plus ABAC corpus policy in full, PrismPath drops two of its six
rules because field against field comparison and set intersection are outside its predicate language.
Sharing graphs: OpenFGA answers the document sharing question natively, OPA and Cedar answer it with
graph reachability and an entity hierarchy, PrismPath cannot ask it. Proven engines: Cedar's
authorizer and validator are machine checked in Lean, PrismPath's evaluator is certified by
conformance, not proven (the Lean development on Figueroa quantization is a component proof and is
credited in the B2 note, not counted). Cloud tooling and years of adoption: every comparator has a
Kubernetes, Envoy, or SDK surface and a foundation or an operator behind it; PrismPath has a narrow,
substrate shaped integration surface and two months of public history.

**Where they integrate, shown by the glue that was built.** Facet, PrismPath's wire format, carried
OPA's input as a 2 or 3 B frame in place of 70 to 75 B of JSON and OPA decided identically on the
reconstructed reading for all 23 corpus cases (`glue/facet_opa_input.py`, 35 lines). A receipt sink
took OPA's decision log uploads, Merkle rooted them, signed the root with the bundle signing key OPA
already trusts, and issued per decision receipts a third party verifies with OPA's own verification
key; 6 of 6 verified, an altered record and a foreign key were rejected (`glue/opa_receipts.py`, 131
lines). A revision floor in front of OPA's bundle load refused the stale signed bundle, and OPA's own
verification refused the tampered and unsigned ones (`glue/opa_revision_floor.py`, 54 lines). The
shape that follows: a cloud engine decides in the data center, PrismPath decides at the edge and on
devices, and PrismPath's wire and receipt machinery can serve both. Above both sits a governance
system of record such as Openlane, which holds the program and wants exactly the decisions and
evidence PrismPath produces; it is graded not on every Group A row because it is not a decision
engine, and that is a boundary, not a defect.

## 3. The layer bar, and why the two expected survivors fell

The pre registration expected A3 and A7 to clear the bar. Neither did, and in both cases the rubric as
written decided it.

**A3.** Every comparator's own cell is not: none reaches an MCU class target out of the box, and the
attempts are recorded (Cedar's Rust core stops at a `std` dependency in `memchr`; Cerbos and OpenFGA
are servers). But the rubric's own example of "with work" is OPA compiled to WebAssembly on a second
substrate class with identical decisions, and Phase 5 did that rather than estimating it. `opa build -t
wasm` emits a module per policy; the wasm3 interpreter (third party, MIT, about 60 KB of code on the
target, pinned in `toolchain/install.sh`) runs it on a Pico 2 W with 171 lines of glue supplying the
module's six imports and driving OPA's documented `opa_eval` ABI over USB-CDC
(`groupa/opa_wasm_mcu/`). All 23 readings decided identically, outcome and rule. The pre registration
predicted the attempt would fail on memory; it was wrong about the board class. The differences that
remain are in the cells and they are differences of degree:

| on the same RP2350 | OPA module under wasm3 | PrismPath image under the PPT interpreter |
|---|---|---|
| RAM in use | 311,636 B heap high water plus 24 KB interpreter stack | interpreter class 1.7 KB (ledger #92); the table image is the policy |
| policy artifact | 135,831 B and 135,954 B modules | 224 B and 160 B images |
| runtime on the target | wasm3, about 60 KB of code, lazy compiling | 1.7 KB class interpreter |
| USB round trip | 3.8 to 5.5 ms, 54 to 57 ms on the first evaluation after a load | about 0.37 ms (ARM) and 0.55 ms (RISC-V) medians |
| worst case bound | none stated | signed `wcet_cycles` recomputed at verify, witnessed on the fabric pins |
| second ISA on the chip | RISC-V build hung, attempted and not achieved | RISC-V 23/23 |

Both systems on that board are a portable artifact plus a per substrate runtime. The reason one
runtime is 1.7 KB and the other 60 KB, and one has a bound and the other does not, is that PrismPath's
decision structure is restricted to a decidable, tabular fragment. That restriction is also why B1 is
a loss. The fragment is the trade, and the table shows both sides of it.

**A7.** No comparator states a bound, and the prediction gave them all "not". The rubric grades "with
work" for a measured tail with a documented way to cap work, and a request timeout is such a way, so
OPA, Cedar, and Cerbos grade with work at zero lines. The tails are in the cells (network_admission
medians: PrismPath Python 78 us in process, Cedar 38 us in process, OPA 320 us over loopback HTTP,
Cerbos 872 us over loopback HTTP; PrismPath's signed bound is 700 ns at the 50 MHz fabric clock). The
pre registration's own reading applies: for cloud request paths the tail is what matters, for
embedded and real time paths the bound is decisive. The rubric did not split the two, and the verdict
follows the rubric.

## 4. Predictions that were wrong

Thirteen cells and two verdicts, against the section 8 table of the pre registration. None was
adjusted after the fact.

| dim | system | predicted | computed | why |
|---|---|---|---|---|
| A1 | cedar | NOT | WITH-WORK | the outcome rides an `@outcome` annotation read from `authorize -v` diagnostics, and `context has f` guards give unsatisfied semantics on absence; a 40 line client wrapper |
| A2 | cedar | NOT | WITH-WORK | the same annotation carrier |
| A4 | cedar | WITH-WORK | NOT | the cell is the minimum over four sub properties; `signed` is NOT because Cedar has no key or anchor anywhere and a signature would introduce one (section 4 budget rule) |
| A4 | cerbos | WITH-WORK | NOT | same rule: open source Cerbos has no signing key (policy signing is a Cerbos Hub feature) |
| A4 | openfga | WITH-WORK | NOT | the A4 policies are not expressible in OpenFGA, so no sub property can be met |
| A5 | cerbos | NOT | WITH-WORK | Cerbos ships a gRPC protobuf API, a documented compact encoding to switch to (still every attribute, not decision sufficient) |
| A7 | opa | NOT | WITH-WORK | a request timeout is a documented way to cap work |
| A7 | cedar | NOT | WITH-WORK | evaluation is bounded by construction and a timeout caps the rest |
| A7 | cerbos | NOT | WITH-WORK | request timeouts |
| A8 | cerbos | WITH-WORK | NOT | the loop needs a verifiable receipt, and a signed one would introduce a trust anchor Cerbos does not have |
| B4 | cedar | WITH-WORK | NATIVE | Rust, Java, Go, and WebAssembly implementations, Kubernetes authorization and admission, a local agent, an Express.js integration, a managed AWS service |
| A3 | verdict | DISTINCT | NOT-DISTINCT | section 3 |
| A7 | verdict | DISTINCT | NOT-DISTINCT | section 3 |

The pattern: the predictions under rated Cedar's tooling twice, over rated Cerbos's and OpenFGA's
ability to sign anything, and forgot that the rubric counts a timeout as a way to cap work. The trust
anchor rule was fixed before any install, decided A4 and A8, and stands.

## 5. Where PrismPath loses

All five Group B properties compute LOSES from result files (`results/<system>/B*.json`, ledger row
#147), each as predicted. B1 and B3 were graded from the same conformance rows as Group A: PrismPath's
translator dropped the two rules it could not express and declared the sharing policy not expressible,
while OPA, Cedar, and Cerbos matched 8 of 8 and OPA, Cedar, and OpenFGA matched 6 of 6. B2, B4, and B5
are documentation rows with the grade bars written before the rows and the sources beside each result.
The one wrong cell here, Cedar's ecosystem, was under rated.

## 6. What PrismPath is, on this evidence

In the order a reader needs it:

1. **What it is.** A control plane for autonomous systems, one of many, with receipts.
2. **What it does.** It takes the decision structure a human authored from governing policy, the
   predicates and routes of a flow document, compiles that structure into a table image, and decides
   from it what a system may do, leaving a signed receipt with the cause on every decision. It does not
   compile policy from prose; the step from prose to predicates is authored.
3. **What is unusual about the approach.** The decision structure is restricted to a decidable,
   tabular fragment (Level M). That is why one image decides identically from a Python process down to
   a 1.7 KB interpreter on an 8 bit part or a fabric, why a worst case bound can be computed and signed,
   and why readings quantize without changing decisions. The semantic tier, where a model decides, stays
   on the host and is best effort; the cross substrate claim is a claim about the fragment.
4. **What is its own.** Facet, the wire format on top: 2 to 3 B per reading, decision sufficient by the
   proven quantization, and shown in Phase 5 to compose with OPA as well as with PrismPath.
5. **What is built in rather than glued.** Abstain (insufficient information, distinct from deny and
   from the cause 36 refusal when nothing matches and there is no catch all), human routing as a routed
   outcome, receipts with cause, and anti rollback at the point. The comparators reach these with work
   or not at all. That is a statement about integration, measured at 391 lines for OPA, not a moat.

## 7. Method, in one paragraph

Protocol, corpus (6 policies, 61 scenarios, 5 lifecycle entries), rubric, budget, and predictions were
frozen before any comparator was installed (`PREREGISTRATION.lock`, one recorded amendment for tuple
direction, made before any comparator result existed). Comparators were pinned (OPA 1.20.2, Cedar
4.12.0, cedarpy 4.8.7, Cerbos 0.55.0, OpenFGA 1.19.0, Openlane from documentation) and translated
idiomatically with the official construct cited per rule; every translation was re run against the
corpus before any result file was written. Group A ran on host, kernel (two architectures), an RP2350
(two ISAs), and a Zynq-7020 with a logic analyzer on the pins. Group B was graded from the same
conformance rows and from documentation with the grade bars written before the rows. Phase 5 built
every combination and ran it. Work drafted by agy was accepted only after its gate was re run here. A
third party regenerates the matrix with `python -m prismpath.comparisons.matrix`, and this document's
verdicts are tested against it.

## 8. Limits

- One MCU family reached for the OPA combination (RP2350 ARM); the RISC-V build hung and the 8 bit and
  FPGA targets were not attempted for OPA. Those attempts could widen the degree, not change the map.
- A7 compares a signed bound against measured tails under a rubric that treats a timeout as a cap; the
  embedded reading of the same evidence is stated beside it, not substituted for it.
- The receipts glue was built for OPA only; Cedar and Cerbos wrappers were costed in their own cells and
  not built, because their cells are not on the trust anchor rule regardless.
- B4 and B5 are documentation rows with published bars, not measurements.
- The corpus is small and neutral by design; it exercises the pre registered properties, not the full
  range of any engine.
- Everything ran on one bench (the GX10 dev station, a Protectli, a Pico 2 W, an Arty Z7-20).

## 9. Publication and what remains

Publication is the owner's decision. The evidence and the honesty rules point one way: publish the
whole comparison, this verdict included, or none of it. The map with the losses and the thirteen
wrong predictions is what makes the native column believable. Outward material keeps "control plane"
as what PrismPath is, describes it in the order of section 6, and does not describe it as a layer the
existing engines cannot reach, because section 3 shows they can, with work. Nothing in this branch is
pushed, and the staged ledger rows #144 to #149 wait for the fold.
