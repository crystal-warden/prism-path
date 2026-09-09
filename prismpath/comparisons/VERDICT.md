# Verdict: is PrismPath a distinct layer?

*Phase 6 of the pre registered comparison (PREREGISTRATION.md, freeze 54f05739). Written after every
result file existed. The grades, cell counts, and per dimension verdicts below are read from
`matrix.json`, which `matrix.py` generates from the 638 result files under `results/` and from nothing
else; `tests/test_comparisons_verdict.py` fails if this document and the matrix disagree on a verdict.
September 2026.*

## 1. The answer

**No, not under the definition this comparison fixed in advance.** Section 9 of the pre registration
says PrismPath is a distinct layer only if at least one Group A dimension is DISTINCT: the PrismPath
cell NATIVE and every other tested column NOT, practical combinations included. After Phase 5 no
dimension meets that bar.

| dim | what it tests | predicted | computed |
|---|---|---|---|
| A1 | abstain as a first class outcome | NOT-DISTINCT | NOT-DISTINCT |
| A2 | human routing as a routed outcome | NOT-DISTINCT | NOT-DISTINCT |
| A3 | cross substrate byte exact decisions | DISTINCT | NOT-DISTINCT |
| A4 | signed, tamper evident, per decision receipts with cause | NOT-DISTINCT | NOT-DISTINCT |
| A5 | compact decision sufficient wire | NOT-DISTINCT | NOT-DISTINCT |
| A6 | policy anti rollback at the enforcement point | NOT-DISTINCT | NOT-DISTINCT |
| A7 | bounded decision time | DISTINCT | NOT-DISTINCT |
| A8 | the AI worker governance loop | NOT-DISTINCT | NOT-DISTINCT |
| B1 | policy expressiveness | LOSES | LOSES |
| B2 | formal verification of the decision engine | LOSES | LOSES |
| B3 | relationship modeling | LOSES | LOSES |
| B4 | ecosystem and integrations | LOSES | LOSES |
| B5 | maturity, adoption, community | LOSES | LOSES |

Two of the thirteen verdict predictions were wrong, both in the comparators' favor: A3 and A7, the two
dimensions the pre registration named as the expected survivors. Thirteen of seventy eight cell
predictions were wrong; every one is listed in section 4.

The pre registration also said, in its own words, that a "not distinct here" result is valid and that
investor "control plane" language is only as strong as this table. This document takes that at face
value. What PrismPath is, on the evidence, is stated in section 3, and it is a narrower and more
defensible claim than "distinct layer".

## 2. Why the two expected survivors fell

### A3, cross substrate byte exact decisions

PrismPath's cell is NATIVE on the strongest evidence in the study: one compiled image per policy
decides the 23 corpus readings identically on host Python, the C reference, in kernel on aarch64 and
x86_64, on both ISAs of an RP2350, and on the Zynq-7020 fabric (seven legs, `results/prismpath/A3__*`,
ledger rows #145 and #146). Every comparator's own cell is NOT: OPA, Cedar, Cerbos, OpenFGA, and
Openlane reach no MCU class target out of the box, and the attempts are recorded, not dismissed (Cedar's
Rust core stops at a `std` dependency in `memchr`; Cerbos and OpenFGA are servers).

The dimension still computes NOT-DISTINCT because the pre registered rubric says WITH-WORK is "a
comparator reaches a second substrate class through a documented compiler or runtime (for example OPA
to WebAssembly) with the decisions identical", and Phase 5 did exactly that rather than estimating it.
`opa build -t wasm` produces a WebAssembly module per policy; the wasm3 interpreter (third party, MIT,
about 60 KB of code on the target, pinned in `toolchain/install.sh`) runs it on a Pico 2 W with 171
lines of glue that supply the module's six imports and drive OPA's documented `opa_eval` ABI over
USB-CDC (`groupa/opa_wasm_mcu/`). All 23 readings decided identically, outcome and rule
(`results/opa+glue/evidence/A3/opa_wasm3_rp2350-arm.json`). The glue is within the section 4 budget
and adds no trust anchor, so the combination column is WITH-WORK and the verdict follows.

The pre registration predicted this attempt would fail on memory. It was wrong about the board class:
the RP2350 has 520 KB of SRAM and the run peaked at 311,636 B of heap. The differences that remain are
real and are in the cells, and they are differences of degree:

| on the same RP2350 | OPA module under wasm3 | PrismPath image under the PPT interpreter |
|---|---|---|
| RAM in use | 311,636 B heap high water plus 24 KB interpreter stack | interpreter class 1.7 KB (ledger #92); table image is the policy |
| policy artifact | 135,831 B and 135,954 B modules | 224 B and 160 B images |
| runtime on the target | wasm3, about 60 KB of code, lazy compiling | 1.7 KB class interpreter |
| USB round trip | 3.8 to 5.5 ms, 54 to 57 ms on the first evaluation after a load | about 0.37 ms (ARM) and 0.55 ms (RISC-V) medians |
| worst case bound | none stated | signed `wcet_cycles` recomputed at verify, witnessed on the fabric pins |
| second ISA on the chip | RISC-V build hung, attempted and not achieved | RISC-V 23/23 |

An 8 bit AVR with 2 KB of RAM (ledger #92) and the FPGA fabric were not attempted for OPA. They would
widen the degree without changing the verdict, because the rubric asks for one second substrate
class, not for every one PrismPath reaches.

### A7, bounded decision time

PrismPath is NATIVE: a per policy worst case bound travels signed with the policy, is recomputed at
verify from the image bytes, and was honored by measurement on the fabric pins for both comparison
images (34 of 35 cycles and 23 of 24 cycles, `results/prismpath/evidence/A7/pins_*.json`, ledger
#146). No comparator states a bound. The pre registration predicted NOT for all of them and forgot its
own rubric, which grades WITH-WORK for "a measured tail with no bound but a documented way to cap
work". A request timeout is a documented way to cap wall time, so OPA, Cedar, and Cerbos grade
WITH-WORK with zero lines of glue, and the dimension is NOT-DISTINCT. The measured tails are in the
cells (network_admission medians: PrismPath Python 78 us in process, Cedar 38 us in process, OPA 320 us
over loopback HTTP, Cerbos 872 us over loopback HTTP; PrismPath's signed bound is 700 ns at the 50 MHz
fabric clock). The pre registration's own reading applies: for cloud request paths the tail is what
matters and a bound is irrelevant; for embedded and real time paths the bound is decisive. The rubric
did not make that distinction and the verdict follows the rubric.

## 3. What the table does support

The honesty rules said to report combinations that grade WITH-WORK as integration conveniences, real
and sellable, not moats. That is the finding for A4, A5, A6, and A8, and after Phase 5 it is a
measured one: a receipt sink of 131 lines gives OPA per decision, signed, tamper evident receipts
using the bundle key it already trusts; a revision floor of 54 lines gives it anti rollback at the
point; 35 lines of Facet encoding carry its input in 2 or 3 bytes instead of 70 to 75 and OPA decides
identically on the reconstruction for all 23 readings. Facet is a transport that composes with anyone,
exactly as pre registered.

What survives as a factual statement about PrismPath, from the cells:

1. **It is NATIVE on every Group A dimension.** No comparator is NATIVE on more than two of the eight
   (OPA on A1 and A2). Everything the comparators reach on A3 through A8 they reach WITH-WORK, and
   only OPA reaches all of them; Cedar, Cerbos, and OpenFGA are NOT on A3, A6, and A8, and NOT on the
   `signed` sub property of A4 because a signature would need a trust anchor they do not have.
2. **The composition is what is uncommon, not any single property.** OPA plus 391 lines of glue in
   three pieces matches PrismPath's Group A row cell by cell. Nobody ships that composition, and the
   glue has to be designed, kept, and trusted by whoever adopts it. That is a product statement, not a
   layer statement, and it is the one the evidence supports.
3. **On the embedded and real time side the differences are large.** A 1.7 KB interpreter class and
   224 B images against 60 KB of interpreter and 136 KB of module in 312 KB of RAM; sub millisecond
   against millisecond round trips; a signed, pin witnessed bound against none. These are the numbers
   to put in front of anyone building for constrained hardware, and they do not need the word layer.
4. **Where PrismPath loses, it loses as predicted.** B1 to B5 are LOSES. The predicate language cannot
   express field against field comparison or set intersection; there is no relationship graph; the
   decision engine has no machine checked proof (the Lean development on Figueroa quantization is a
   component proof and is credited in the B2 note, not counted); the ecosystem is narrow and
   substrate shaped; the project is two months old from one organization.

The recommended framing for anything public, derived from the above: PrismPath is a policy decision
engine whose one compiled image decides identically from a Python process down to a 1.7 KB
interpreter on an 8 bit part or a fabric, carries a signed worst case bound, and composes abstain,
human routing, signed receipts with cause, and a byte sized wire as built in properties rather than
as glue. It is not a layer the existing engines cannot reach; it is the engine that arrives there
without the glue, and on constrained hardware with two orders of magnitude less memory.

## 4. Predictions that were wrong

Thirteen cells, listed against the section 8 table. None was adjusted after the fact.

| dim | system | predicted | computed | why |
|---|---|---|---|---|
| A1 | cedar | NOT | WITH-WORK | the outcome rides an `@outcome` annotation read from `authorize -v` diagnostics, and `context has f` guards give unsatisfied semantics on absence; a 40 line client wrapper, not NOT |
| A2 | cedar | NOT | WITH-WORK | the same annotation carrier |
| A4 | cedar | WITH-WORK | NOT | the cell is the minimum over four sub properties; `signed` is NOT because Cedar has no key or anchor anywhere and a signature would introduce one (section 4 rule) |
| A4 | cerbos | WITH-WORK | NOT | same rule: open source Cerbos has no signing key (policy signing is a Cerbos Hub feature) |
| A4 | openfga | WITH-WORK | NOT | the A4 policies are not expressible in OpenFGA, so no sub property can be met |
| A5 | cerbos | NOT | WITH-WORK | Cerbos ships a gRPC protobuf API, a documented compact encoding to switch to (still every attribute, not decision sufficient) |
| A7 | opa | NOT | WITH-WORK | a request timeout is a documented way to cap work; the rubric grades that WITH-WORK |
| A7 | cedar | NOT | WITH-WORK | evaluation is bounded by construction and a timeout caps the rest |
| A7 | cerbos | NOT | WITH-WORK | request timeouts |
| A8 | cerbos | WITH-WORK | NOT | the loop needs a verifiable receipt, and a signed one would introduce a trust anchor Cerbos does not have |
| B4 | cedar | WITH-WORK | NATIVE | Rust, Java, Go, and WebAssembly implementations, Kubernetes authorization and admission, a local agent, an Express.js integration, a managed AWS service |
| A3 | verdict | DISTINCT | NOT-DISTINCT | section 2 |
| A7 | verdict | DISTINCT | NOT-DISTINCT | section 2 |

A pattern in the misses: the predictions under rated Cedar's tooling twice, over rated Cerbos's and
OpenFGA's ability to sign anything, and forgot that the rubric counts a timeout as a way to cap work.
The section 4 trust anchor rule turned out to be the decisive line on A4 and A8, and it cut in
PrismPath's favor; it was fixed before any install, and it stands.

## 5. Group B, where PrismPath loses

All five compute LOSES from result files (`results/<system>/B*.json`, ledger row #147). The one
sentence versions: Rego, Cedar, and Cerbos express the RBAC plus ABAC policy in full and PrismPath
drops two of its six rules; OpenFGA answers the document sharing question natively and PrismPath
cannot ask it; Cedar's authorizer and validator are machine checked in Lean and PrismPath's
evaluator is certified, not proven; every comparator has an ecosystem and PrismPath has a narrow,
substrate shaped one; every comparator has years, contributors, and a foundation or an operator, and
PrismPath has two months. The B2 note records PrismPath's Lean development on Figueroa quantization
(13 theorems, zero sorry, standard axioms, the same Lean 4.33.1 toolchain as cedar-spec) without
counting it, because the dimension is verification of the decision engine.

## 6. Method, in one paragraph

Protocol, corpus (6 policies, 61 scenarios, 5 lifecycle entries), rubric, budget, and predictions were
frozen before any comparator was installed (`PREREGISTRATION.lock`, one recorded amendment for tuple
direction, made before any comparator result existed). Comparators were pinned (OPA 1.20.2, Cedar
4.12.0, cedarpy 4.8.7, Cerbos 0.55.0, OpenFGA 1.19.0, Openlane from documentation) and translated
idiomatically with the official construct cited per rule; every translation was re run against the
corpus before any result file was written. Group A ran on host, kernel (two architectures), an
RP2350 (two ISAs), and a Zynq-7020 with a logic analyzer on the pins. Group B was graded from the
same conformance rows and from documentation with the grade bars written before the rows. Phase 5
built every combination and ran it. Work drafted by agy was accepted only after its gate was re run
here. A third party regenerates the matrix with `python -m prismpath.comparisons.matrix` and this
document's verdicts are tested against it.

## 7. Limits of this study

- One MCU family reached for the OPA combination (RP2350 ARM); the RISC-V build hung and the 8 bit
  and FPGA targets were not attempted for OPA. Those attempts could widen the degree, not flip A3.
- A7 compares a signed bound against measured tails; the rubric treats a timeout as a cap, and the
  verdict follows the rubric, not the embedded reading of the same evidence.
- The A4 and A8 comparator receipts glue was built for OPA only; Cedar and Cerbos wrappers were costed
  in their own cells and not built, because their cells are NOT on the trust anchor rule regardless.
- B4 and B5 are documentation rows with published bars, not measurements.
- The corpus is small and neutral by design; it exercises the pre registered properties, not the full
  range of any engine.
- Everything ran on one bench (the GX10 dev station, a Protectli, a Pico 2 W, an Arty Z7-20).

## 8. Public readiness

This is the owner's decision. The evidence and the honesty rules point one way: publish the whole
comparison, verdict included, or none of it. Publishing the matrix without this verdict would be the
inflation the pre registration was written to prevent; publishing the verdict is the strongest
credibility signal the project can give, because it shows the claims are tested against a bar the
project set for itself and reports the miss. The recommendation is to publish, with the section 3
framing replacing "distinct layer" and "control plane" wherever those words appear in outward facing
material, and with the A3 degree table as the embedded story. Held back until decided: nothing in
this branch is pushed (owner gated), and the staged ledger rows #144 to #149 wait for the fold.
