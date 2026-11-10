# The verified policy core: what is proven, tested, assumed and out of scope

*A summary for a technical reviewer of the narrow slice of PrismPath that is proven once and that every
implementation is held to. Research line, November 2026, branch `verified-core-4`. The normative text is
`docs/design/spec-verified-core.md` (cited below as the specification, with its section numbers); the
proofs are in `formal/Core`; the differential harness and the evidence tools are in `formal/diff`.*

## 1. The object

The verified policy core is one decision: a policy is an ordered list of rules, each a Level M condition
(comparisons of a field with a constant, membership in a list of constants, truthiness, `not`, `and`,
`or`) and a target, together with signed field definitions that say what each integer field means (`int`,
or `fixed` with a scale and a rounding mode, `bool`, `category`, with ranges and whether absence is
allowed). A reading, a map of field names to values, is routed to the target of the first rule whose
condition holds. Both the policy image and the reading are canon/2 documents: JSON with no floats, no
duplicate keys, integers within plus or minus 2^53 minus 1, and a fixed canonical spelling (specification
section 3). Every input that is not routed is refused, and every refusal carries a registered cause from
the append only registry `prismpath/kernel/causes.py` (section 5).

The meaning of the core is one Lean 4 function, `Core.verdict` (`formal/Core/Eval.lean`), from the bytes of
a policy image and of a reading to a decision, a route or a refusal. The oracle, `core-oracle`, is that
function compiled; it is the reference the other implementations are tested against.

## 2. What is proven

Every statement below is a theorem of `formal/Core` checked by Lean 4 (v4.33.1, with Mathlib v4.33.1). The
development contains no `sorry`, and the axiom audit that runs at every build (`formal/FQ/Axioms.lean`)
shows each theorem depends on at most Lean's three standard axioms (`propext`, `Classical.choice`,
`Quot.sound`). The decision function itself, `Core.verdict`, depends only on `propext`, and so does the
check that decides which cases a differential run excludes (`Core.counterRefusal`): nothing the oracle
computes goes through `Classical.choice`. The theorems are about the function the oracle runs, not about a
separate model of it.

| group | theorems | statement in words |
|---|---|---|
| termination | `verdict_total`, `matchSteps_le` | every policy image and reading has a decision, by structural recursion only; routing evaluates at most as many atoms as the policy has |
| no fail open, policy | `policy_refusal_refuses_all`, `unreadable_image_refused` | a policy image that does not read, decode or pass its checks refuses every reading, with its own cause |
| no fail open, reading | `unreadable_reading_refused`, `boundary_refusal` | under an accepted policy, a reading that does not read, or that a field definition refuses, is refused |
| no fail open, the route | `route_sound`, `route_is_a_target` | a route is produced only when the policy image read and passed its checks, the reading read as an object and every definition accepted its value, and it is the target of the first rule whose condition holds |
| refusal completeness | `verdict_cases`, `policy_refusal_iff`, `verdict_route_or_refuse` | every pair of inputs falls in exactly one of six stages, each a route or one refusal of a closed type |
| determinism | `verdict_perm`, `decideReading_perm`, `verdict_text_perm`, `readChars_wf`, `evalC_congr` | the decision depends on a reading's members and not on their order; a condition's truth depends only on the canonical values of its fields |
| registered causes | `refusal_registered`, `refusal_code_ne_zero`, `registry_codes_distinct`, `refusal_name_of_code`, `verdict_refusal_registered` | every refusal's code and name is a row of the registry, the code is never 0, and the code alone names the cause |
| one cause per refused policy | `loadPolicy_first_problem`, `policy_cause_is_first`, `policy_accepted_iff_no_problem`, `verdict_policy_cause`, `lowerCond_first_atom` | a policy image with several problems is refused for the first in the order of specification section 4, and is accepted exactly when it has none |
| the two checks of a reading | `policyCheck_of_systemBoundary`, `systemBoundary_of_policyCheck`, `policyCheck_refuses_routed`, `policyCheck_eq_systemBoundary`, `route_depends_on_routed` | the system boundary (every defined field) is at least as strict as the policy check (the fields the rules read); they are equal when every defined field is read; only the fields the rules read can change a route |
| the bridge to Figueroa quantization | `evalC_toX`, `firstMatch_eq_routeX`, `boundary_canonical`, `accepted_quantization_preserves`, `core_reconstruct_route`, `scaled_correct`, `lowered_threshold_preserves` | the core's evaluation is the FQ development's on the translated policy, so two accepted readings with the same quantization get the same decision, and a decimal threshold lowered on a `fixed` field decides on the canonical integer as the authored decimal decides on the source value |
| the engine counter exclusion | `counterRefusal_iff`, `counter_excluded_refused` | the check a differential run uses to exclude a case holds exactly when the oracle refuses the policy image for reading an engine counter, and then every reading is refused with `policy:engine-counter`, so the exclusion leaves out no route and no other refusal |
| evidence and the semantics | `verified_receipt_is_verdict`, `receipt_is_verdict_of_hashes`, `verified_run_complete`, `verified_refusal_registered`, `verified_excluded_counter`, `evidence_sound` | over a model of a differential run and of its verifier with every receipt replayed (`verifyRun`), every receipt the verifier accepts records `Core.verdict` on the image and the reading whose hashes it carries; every reading of every case not excluded has a receipt; a recorded refusal is the decision's registered nonzero code; a case excluded as reading an engine counter refuses every reading for it; and, under the cryptographic hypotheses of section 4, the root statement binds exactly these receipts |

The evidence theorems take the cryptography as parameters (a hash, the canonical bytes of a receipt, a
Merkle root, signature verification) and its security as explicit hypotheses of the theorems that need
them, each stated for the objects at hand: `Unforgeable` (a signature that verifies under the pinned
instance key was made by its holder), `NoTreeCollision` (a list of receipts under the run's Merkle root
exhibits no collision in the tree or a leaf) and `NoCollision` (a byte string exhibits no collision with a
document of the run). None is stated for all inputs, which no hash onto a finite set satisfies, so none of
the theorems is vacuous for SHA-256. `Unforgeable` relates signature verification to an abstract predicate
"signed by the key's holder"; it is the modelling step from a verifying signature to a person, and the
theorem says no more about the signer than that predicate does.

## 3. What is tested

Tested here means held to the oracle by differential testing or by frozen vectors. It is evidence of
conformance on the inputs run, not a proof about the implementations' source text.

**The differential harness** (`formal/diff/core_diff.py`, specification section 8) generates policy images
and readings, well formed and malformed, biased toward boundaries (ranges at plus or minus 2^53 minus 1 and
at 2^31, scales from 1 to 10^9, decimals at the digit and exponent bounds, conditions at depth 49 to 53,
absence, wrong types, whitespace variants, escapes and astral characters, floats, `-0`, wide integers,
duplicate keys, deep nesting, invalid UTF-8, truncated images), runs every case through the oracle and
through seven legs, and classifies every difference. On the run of 100,000 cases (seed 1, 419,651
readings) no leg shows a finding of any kind:

| leg | implementation | agree | outside the slice, by declared reason | findings |
|---|---|---|---|---|
| `python` | the Python reference implementation | 163,379 | 10,265 inferred path, 372 engine counter; 3,181 images with no flow rendering | 0 |
| `rust` | the Rust port | 163,379 | the same | 0 |
| `js` | the JavaScript kernel, a refusing kernel for field definitions | 60,492 | 10,265 inferred path; 12,902 excluded; 22,035 refused as defining fields; 666 reader gaps of a JSON reader that is not canon/2 | 0 |
| `go` | the Go kernel, a refusing kernel | 60,511 | as `js`, with 647 reader gaps | 0 |
| `c-interp` | the table interpreter `prismpath-hw/interp.c` | 146,673 | 10,265, 372, 3,181; 5,597 refusals of the 32 bit target | 0 |
| `c-hdr` | the embedded evaluator `prismpath-hw/ppt_eval.h` | 146,673 | the same | 0 |
| `ebpf` | the eBPF evaluator `prismpath-ebpf/ppt_eval_bpf.h`, on its userspace path | 146,587 | the same, and 86 readings of tables outside the loader's declared subset | 0 |

The counts are policy rows and reading rows together. "Agree" means the same route, or the same refusal
with the same cause, code, field and reason. On every policy a leg accepts and the oracle accepts, every
reading's decision is the oracle's, and the policy check of the Python and Rust legs equals the oracle's on
every reading. The seeded CI run (`prismpath/tests/test_core_diff.py`, 5,000 cases) fails on any finding.

**Frozen vectors.** canon/2: 73 byte strings covering every reader rule, replayed by Python, Rust and the
oracle (`prismpath/portable/conformance/canon2.json`). Field definitions: the conformance vectors replayed by
Python and Rust, including the depth, whitespace and cause order regressions of D1 to D3 and D7
(`prismpath/portable/conformance/field_definitions.json`).

**A differential run as evidence** (`formal/diff/core_evidence.py`, `prismpath-hotswap-rs/examples/core_evidence.rs`,
specification section 11). On the same 100,000 cases:

- the oracle's check of a policy image, ported to Python (`formal/diff/core_policy.py`) and to Rust (the
  example's `oracle_policy`), names the oracle's result on every one of the 100,000 images in both
  languages (accepted for 24,041; otherwise the same cause, code, field and reason; 1,310 refused for an
  engine counter);
- each language produces a run: 100,000 image attestations under a test authority key, 361,984 receipts,
  13,818 cases excluded with their reasons (1,310 engine counter, 9,327 inferred path, 3,181 with no flow
  rendering), and one canon/2 root statement under a test instance key; every document of the run is
  canon/2;
- the Python verifier verifies the Rust run and the Rust verifier the Python run, with both keys pinned
  and every receipt replayed through the oracle: 361,984 of 361,984 agree, none differs, in both
  directions; the two runs' receipts are the same bytes but for the name of the implementation that
  decided.

The CI sized round trip (`prismpath/tests/test_core_evidence.py`, 400 cases) also alters each part of a
run (a decision, a dropped receipt, a reading, an image signature, the manifest, a key, the root
statement's signature, its clock written as a float, a later clock, a respelled statement, a second
statement), resigns a false receipt with the right key, substitutes the audit log's statement format, and
pins a foreign key; both verifiers refuse every one. It also holds both ported checks to the oracle on
every image of the run and on edge images, and checks that a case is excluded for an engine counter
exactly when the oracle refuses it for one.

## 4. What is assumed

- **Cryptography.** Ed25519 signatures are unforgeable under the pinned keys, and SHA-256 has no collision
  or second preimage against the documents of a run, in the Merkle tree or over the canonical bytes of a
  receipt. These are the hypotheses `Unforgeable`, `NoTreeCollision` and `NoCollision` of section 2; the
  canon/2 writer writing distinct receipts as distinct bytes is part of `NoTreeCollision`. The keys used in
  every run here are test keys generated per run.
- **The proof checker.** The theorems are as trustworthy as Lean's kernel and the three standard axioms.
  Every module of `formal/Core` was also replayed by `leanchecker`, Lean's independent re-check of the
  stored proofs, without error; both rest on the same kernel rules.
- **The oracle binary.** The replay trusts that `core-oracle` computes `Core.verdict`: the Lean compiler,
  its runtime, the C compiler that builds it, the operating system and the hardware. Nothing here proves
  the compiled program equal to the function the theorems are about.
- **The verifiers and the ported checks.** That `core_evidence.verify` and its Rust twin compute
  `verifyRun`, and that the two ported checks of a policy image compute `loadPolicy`, are held by the
  tamper tests and by agreement with the oracle on every image of the large run, not by proof.
- **The implementations.** The Python reference implementation, the Rust port, the JavaScript and Go
  kernels and the three table targets are conformant to the oracle on the inputs generated, not proven:
  differential testing shows no disagreement on 100,000 cases and does not show that none exists. The
  canon/2 readers of Python and Rust are held to the Lean reader by the frozen vectors and the
  differential.
- **Time.** A root statement's `time_us` is the signer's clock. Nothing here anchors it.

## 5. What is out of scope

- **The flow engine:** several nodes, the engine counters `visits` and `error_count`, the error and event
  tiers, suspension, step limits and workers. A policy that reads an engine counter is refused by the core.
- **Semantic edges and every router,** including calibrated floors and escalation to a person.
- **The inferred path:** a flow that defines no fields, whose kinds are inferred from its constants.
- **The surface syntax:** the Markdown flow text and the Python flavoured `when` expressions are a front
  end that lowers to the core's abstract syntax; the front end is tested through the differential's
  renderer, not proven.
- **Floats** of any kind, in documents, readings or arithmetic.
- **Field definitions in the JavaScript and Go kernels,** which refuse every flow that defines its fields,
  as SPEC.md section 4.5 requires of a kernel that does not implement them.
- **The table targets' 32 bit range,** a declared limit of the compiler and the register encoder that shows
  only as a refusal, and the eBPF verifier and JIT in the Linux kernel, which the userspace leg does not
  exercise.
- **Everything already signed under canon/1:** policy packs and envelopes, audit logs, their root
  statements and anchored roots read and verify as before; only the differential run's own root statement
  moved to canon/2 (specification section 3.1).
- **Anchoring a run.** `ledger anchor` is not taught the run's root statement format, so a run carries no
  third party time.
- **A sampled replay** shows only the receipts it replayed; the counts above replay every receipt.

## 6. Reproducing it

```bash
cd formal && lake build                       # the proofs, the axiom audit, and core-oracle
grep -rn -w sorry FQ FQ.lean Core Core.lean   # expect no output
cd .. && python formal/diff/core_diff.py --cases 100000 --seed 1 --report diff.json
python formal/diff/core_evidence.py cases --cases 100000 --seed 1 --out cases.jsonl
python formal/diff/core_evidence.py scope-check --from cases.jsonl --rust <(core_evidence policy --from cases.jsonl)
python formal/diff/core_evidence.py produce --from cases.jsonl --out run-py --keys keys-py
core_evidence produce --from cases.jsonl --out run-rs --keys keys-rs
python formal/diff/core_evidence.py verify run-rs --sample all --pin-authority keys-rs/authority.pub --pin-instance keys-rs/instance.pub
core_evidence verify run-py --sample all --pin-authority keys-py/authority.pub --pin-instance keys-py/instance.pub
```

`core_evidence` is `cargo run -p prismpath-hotswap-rs --example core_evidence --`.
