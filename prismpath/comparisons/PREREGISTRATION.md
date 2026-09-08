# Pre registration: is PrismPath a distinct layer?

*Frozen September 2026, before any comparator was installed. The freeze hash over this file, the
result contract, the corpus format, and every corpus policy is pinned in `PREREGISTRATION.lock`
and checked by `prismpath/tests/test_comparisons_prereg.py`. Edits after the freeze are
amendments (section 12), recorded, never silent.*

## 1. The one question

On the properties PrismPath claims, does any existing system, or a practical combination of one
with glue, already deliver them? And on the properties those systems are built for, where does
PrismPath lose? The output is a capability matrix generated from executed results only
(`matrix.py`), a written verdict per dimension (`VERDICT.md`, Phase 6), and a decision on public
readiness taken at the end. "Not distinct here" is a valid, useful result. The point is to find
out.

## 2. Honesty rules (fixed now)

1. Dimensions, scenarios, rubric, and predictions are committed before any comparator is
   installed. No dimension is added or dropped after results exist.
2. Every comparator gets an idiomatic translation using its official documentation and examples.
   No strawmen. Uncertainty about idiom is recorded in the result file (`idiomatic: false`).
3. The matrix is generated from result files only. No cell is typed by hand.
4. Every dimension where PrismPath alone grades NATIVE gets a combination test: comparator plus
   glue, with the glue described, counted, and costed in the result file.
5. Group B, where PrismPath is expected to lose, is mandatory and defined here.
6. Everything runs in repo. A third party regenerates the matrix from `results/`.
7. Delegated work is verified by re running its gate here before it counts.

## 3. Comparator field

| id | role | why it is here |
|---|---|---|
| `opa` | decide layer, the direct comparator | the dominant policy decision point (Kubernetes admission, Envoy); Rego rules return arbitrary documents |
| `cedar` | decide layer | formally verified authorization language, deterministic, Rust core |
| `cerbos` | decide layer | application authorization PDP with an audit log |
| `openfga` | adjacent, relationship authorization | Zanzibar style; a different question, included to show the boundary |
| `openlane` | governance system of record | reference layer only, graded from its documentation and API surface, never benchmarked as a decision engine |

Exact versions are pinned at install (Phase 1) and recorded in every result file's
`system_version`. The field is deliberately tight; Casbin, Oso, and the rest add noise.

## 4. Rubric

Per (system, dimension, scenario), one result file per `results/SCHEMA.md`:

- **NATIVE**: does it out of the box, idiomatically.
- **WITH-WORK**: achievable with glue. The glue is recorded with a component list, a line count,
  and an hour estimate. **Budget**: glue of at most 300 lines and 8 hours that introduces no new
  cryptographic trust anchor (no new signing key, no new anchoring service) grades WITH-WORK. Glue
  above either budget, or glue that has to introduce a trust anchor, grades **NOT** with the glue
  still documented. This is the pre registered meaning of "the glue is itself the hard part".
- **NOT**: no practical path.

Cells aggregate by minimum grade over scenarios; the verdict per dimension is computed, both
exactly as `results/SCHEMA.md` states.

## 5. Group A: where PrismPath claims to be distinct

Each dimension names the corpus policies that exercise it, the procedure, and what earns each
grade. The neutral outcome vocabulary and semantics are in `corpus/README.md`.

**A1. Abstain, or insufficient, as a first class outcome.** Policies `expense_approval`,
`ai_action_gate`, `sensor_interlock`. Scenarios of kind `insufficient` and `undeclared_missing`.
Procedure: run every scenario; record the returned value verbatim and map it to the neutral
vocabulary. NATIVE: the policy can name an `abstain` outcome distinct from `deny` and the system
returns it as a first class result, AND an input lacking a field a rule needs yields an
unsatisfied rule (not an error, not a silent default) so the `undeclared_missing` scenarios land
where the neutral semantics say. WITH-WORK: one of the two holds and the other needs a wrapper.
NOT: outcomes are a fixed allow/deny and absence is an error or a silent default. The
`sensor_interlock` no catch all scenarios probe what a system returns when nothing matches
(undefined, error, default deny, or a named refusal); the observed value is recorded for every
system, PrismPath included (predicted `route:stuck`, cause 36).

**A2. Human routing as a routed outcome.** Policies `expense_approval`, `ai_action_gate`.
Scenarios of kind `escalation`. NATIVE: `escalate_human` is a first class returned outcome the
policy selects, and the system can distinguish a policy selected escalation from a worker
requested one (`escalate_human_requested_1`, predicted cause 34 for PrismPath). WITH-WORK: the
outcome is carried in an annotation or output field on a deny. NOT: only allow/deny exists.

**A3. Cross substrate byte exact decisions.** Policies `network_admission`, `sensor_interlock`
(integer and boolean fields only, so every substrate is reachable). Procedure: the same policy
and the same scenario inputs decide on host Python, the C target, in kernel eBPF on the Protectli
(x86_64) and the GX10 (aarch64) via `BPF_PROG_TEST_RUN`, the ESP32 (Xtensa), the RP2350 (ARM and
RISC-V), and the Zynq-7020 fabric via the Protectli jump; the decision (the selected rule id and
outcome) must be identical on all of them for every scenario. NATIVE: identical decisions on at
least a host, a kernel, and an MCU class target with no per target policy rewrite. WITH-WORK: a
comparator reaches a second substrate class through a documented compiler or runtime (for
example OPA to WebAssembly) with the decisions identical. NOT: a server only architecture, or a
runtime that does not fit the target. Comparators get real attempts, not dismissals: OPA compiled
to WebAssembly on an MCU class runtime (document runtime size and memory precisely if it does not
fit), Cedar's Rust core built without the standard library (document the dependency that blocks),
Cerbos and OpenFGA as servers (document). This dimension carries the claim, so its evidence must
include the raw per substrate decision logs.

**A4. Signed, tamper evident, per decision receipts carrying cause.** Policies `ai_action_gate`,
`expense_approval`. Four sub properties graded as four scenarios: `per_decision` (one record per
decision, not sampled, not best effort), `signed` (the record or the root of the records is bound
to a key or an anchor a third party verifies without trusting the emitter), `tamper_evident`
(altering one past record is detectable from the trail alone), `carries_cause` (a machine readable
reason distinct from the outcome). Each sub property is NATIVE, WITH-WORK, or NOT on its own; the
cell is the minimum. Comparators: OPA decision logs, the Cerbos audit log, Cedar (none built in),
OpenFGA (none built in), Openlane evidence records. Combination test: OPA plus a signed decision
log sink plus a Merkle sidecar, costed under the section 4 budget.

**A5. Compact decision sufficient wire.** Policies `network_admission`, `sensor_interlock`.
Procedure: for every scenario, count the bytes needed to convey the request and the result over
the system's documented network interface: HTTP request and response bodies for JSON APIs, the
serialized protobuf message for gRPC APIs, the Facet frame plus the receipt for PrismPath. Bytes
are counted at the application payload layer; a second line adds a fixed 28 byte IPv4 plus UDP
envelope for every system so the framing tax is visible, and the concentrator profile is reported
separately at fleet sizes 1, 10, and 50. NATIVE: a self framing decision sufficient encoding
exists in the system. WITH-WORK: a compact encoding can be layered on. NOT: verbose text only.
Combination test: Facet encode an OPA input. If that composes cleanly the finding is reported as
"Facet is a transport that composes with anyone", which is a real but different claim from a moat.

**A6. Policy anti rollback at the enforcement point.** Policy `network_admission`, lifecycle
entries `stale_policy_1`, `tampered_policy_1`, `unsigned_policy_1`. Procedure: present the
enforcement point (not a management server) with an older signed version, a tampered image with a
valid signature over the original, and an unsigned image; record the response. NATIVE: the point
itself refuses all three with a named reason and no server in the loop. WITH-WORK: refusal is
available at a server or through a configured bundle verification that a wrapper can extend with
a monotonic floor. NOT: no signing or versioning at the point.

**A7. Bounded decision time.** Policies `network_admission`, `sensor_interlock`. Procedure: for
each system, decide every scenario 100,000 times in the fastest documented embedding of that
system on this host (in process library where one exists, otherwise a local server over
loopback), recording min, median, p95, and max in nanoseconds with the transport named. For
PrismPath the same is recorded for Python in process, the C target, the kernel target via
`BPF_PROG_TEST_RUN`, and the fabric, where the signed `wcet_cycles` bound is checked against the
measured cycles on the pins. NATIVE: a stated worst case bound that travels with the policy and is
honored by measurement. WITH-WORK: a measured tail with no bound but a documented way to cap work.
NOT: unbounded evaluation with no bound. Both readings are reported in the verdict: for cloud
request paths the tail is what matters and a bound is irrelevant; for embedded and real time paths
the bound is decisive.

**A8. The AI worker governance loop.** Policy `ai_action_gate`, scenario `ai_worker_loop_1`.
Procedure: a stub worker emits the six proposals in order; the system under test gates each; the
run must return allow, deny, abstain, and escalate_human across the six, distinguish the worker
requested escalation from the policy selected one, and produce one verifiable receipt per
decision carrying the cause, as one governed loop. NATIVE: all of that without building missing
pieces. WITH-WORK: the gate exists and abstain, human routing, or the receipt is added with glue
under budget. NOT: the loop cannot be closed without building a component that is itself the
subject of A1, A2, or A4. This composes A1, A2, and A4 and is the headline because it is what a
business adopting AI actually needs.

## 6. Group B: where PrismPath is expected to lose

**B1. Policy expressiveness.** Policy `access_control_rbac_abac`: role hierarchy, ownership
(field against field), group intersection, and a time window in one policy. PrismPath's
predicate language is deliberately minimal; the corpus file pre registers exactly which constructs
it cannot express and the predicted grade NOT. Rego and Cedar are expected to grade NATIVE and
the table must show it.

**B2. Formal verification.** Matrix row with evidence pointers. Cedar's authorizer and validator
are machine checked (Lean). PrismPath has conformance certification, a base case proven WCET
invariant with the induction step open (ledger #111), and no proof of the evaluator. Recorded
plainly.

**B3. Relationship modeling at scale.** Policy `document_sharing_rebac`. PrismPath predicted NOT;
OpenFGA is the native home.

**B4. Ecosystem and integrations.** Matrix row with evidence pointers (Kubernetes, Envoy,
Terraform, SDKs, language bindings).

**B5. Maturity, adoption, community.** Matrix row with evidence pointers (release history,
contributors, production references).

## 7. Corpus summary

Six policies, 61 scenarios (one a six step loop), five lifecycle entries, all self consistent
under the neutral semantics (`corpus_check.py`, run in CI). Four policies are pre registered as
Level M expressible; two are pre registered as outside PrismPath's language with the exact
constructs named.

| policy | dimensions | Level M claim | scenarios |
|---|---|---|---|
| `expense_approval` | A1 A2 A4 | yes | 11 |
| `network_admission` | A3 A5 A6 A7 | yes | 14 plus 4 lifecycle |
| `sensor_interlock` | A1 A3 A5 A7 | yes | 12 plus 1 lifecycle, no catch all by design |
| `ai_action_gate` | A1 A2 A4 A8 | yes | 10 including the loop |
| `access_control_rbac_abac` | B1 | no, predicted NOT | 8 |
| `document_sharing_rebac` | B3 | no, predicted NOT | 6 |

## 8. Pre registered predictions

Written before installation. The matrix will be compared against this table in `VERDICT.md`, and
a wrong prediction is reported as such.

| dim | prismpath | opa | cedar | cerbos | openfga | openlane | predicted verdict |
|---|---|---|---|---|---|---|---|
| A1 | NATIVE | NATIVE (Rego returns any document) | NOT | WITH-WORK (outputs) | NOT | NOT | NOT-DISTINCT |
| A2 | NATIVE | NATIVE | NOT | WITH-WORK | NOT | NOT | NOT-DISTINCT |
| A3 | NATIVE | NOT (wasm runtime does not fit an MCU) | NOT (std dependency) | NOT (server) | NOT (server) | NOT | DISTINCT |
| A4 | NATIVE | WITH-WORK (unsigned logs; sidecar) | WITH-WORK | WITH-WORK | WITH-WORK | NOT | NOT-DISTINCT |
| A5 | NATIVE | NOT, WITH-WORK as opa+glue | NOT | NOT | NOT | NOT | NOT-DISTINCT (Facet composes) |
| A6 | NATIVE | WITH-WORK (signed bundles, no floor at the agent) | NOT | NOT | NOT | NOT | NOT-DISTINCT |
| A7 | NATIVE | NOT | NOT | NOT | NOT | NOT | DISTINCT |
| A8 | NATIVE | WITH-WORK | NOT | WITH-WORK | NOT | NOT | NOT-DISTINCT |
| B1 | NOT | NATIVE | NATIVE | NATIVE | WITH-WORK | NOT | LOSES |
| B2 | NOT | NOT | NATIVE | NOT | NOT | NOT | LOSES |
| B3 | NOT | NATIVE | NATIVE | WITH-WORK | NATIVE | NOT | LOSES |
| B4 | WITH-WORK | NATIVE | WITH-WORK | NATIVE | NATIVE | NATIVE | LOSES |
| B5 | NOT | NATIVE | NATIVE | NATIVE | NATIVE | WITH-WORK | LOSES |

If A1 and A2 come out NOT-DISTINCT because Rego can return any value, that is the correct
reading and the abstain story is then carried by the calibrated floor plus the cause code plus the
receipt, which is A8's composition, not A1 alone. If A4, A5, or A6 come out WITH-WORK for OPA plus
glue they are integration conveniences, real and sellable, not moats, and are reported that way.

## 9. What "distinct layer" means

PrismPath is a distinct layer only if at least one Group A dimension is `DISTINCT` under
`results/SCHEMA.md`: the `prismpath` cell NATIVE and every other tested column NOT, combinations
included. Expected candidates: A3 and A7, with A8 as the composed whole if the glue for
comparators exceeds the section 4 budget.

## 10. Execution phases

- **Phase 0, pre register (this commit).** Protocol, corpus, result contract, matrix generator,
  predictions, freeze.
- **Phase 1, install.** OPA, Cedar CLI, Cerbos, OpenFGA server; versions pinned. Openlane: docs
  and API surface only.
- **Phase 2, translators.** One per comparator under `comparisons/<system>/`, idiomatic, with the
  official construct cited per rule; each translation is re run here against the corpus expected
  outcomes before any result file is written. A translator that cannot reproduce the neutral
  semantics records exactly where.
- **Phase 3, Group A.** A8 first as the end to end headline; A3 last, it needs the hardware.
- **Phase 4, Group B.**
- **Phase 5, combination tests** for every A dimension where PrismPath alone is NATIVE.
- **Phase 6, generate the matrix, write VERDICT.md, decide public readiness.**

## 11. Guardrails

The comparison gates pre specified actions; it never compiles intent. The prose to predicate step
is human authored everywhere (the neutral corpus is the artifact), and no result may imply that
PrismPath turns a policy document into rules. The LoRa action wire is out of scope until it
exists. The routing accuracy harness (`run_comparison.py`, LangGraph and CrewAI) is a separate,
already published measurement and is not re graded here.

## 12. Amendments

An amendment is any edit to a frozen file after this commit. It is made by editing the file, adding
a dated entry below stating what changed and why, and regenerating the lock with
`python -m prismpath.comparisons.corpus_check --freeze`. Amendments may fix a defect in a
scenario or a translator facing ambiguity; they never add or drop a dimension or change a
prediction after a result for that dimension exists.

- **Amendment 1 (September 2026, Phase 2, before any comparator result file existed).** The two `parent`
  tuples in `corpus/document_sharing_rebac.json` were written child first while every other tuple was
  subject first; OpenFGA's model rejected the translation and the ambiguity would have forced every
  translator to special case one relation. All tuples are now `[subject, relation, object]`, the
  reference evaluator's `parent` rule reads that order, and `corpus/README.md` states it. No scenario
  expectation, dimension, or prediction changed.
