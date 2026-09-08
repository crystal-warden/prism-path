# Supporting Evidence · STAGING (pending rows)

*Append boundary for ledger overhauls (see `LEDGER_STANDARDS.md` §6). While a docs session overhauls
`supporting-evidence.md`, the **dev session appends new evidence rows here**, starting at the next
free number, instead of editing the main ledger. On merge, the docs session folds these into the
ledger with correct formatting and clears this file.*

*Format each row exactly per `LEDGER_STANDARDS.md` §1 (Claim / Method / Result + Honest scope /
Provenance) with a month granularity date. Next free number: **#142**.*

---

<!-- new rows go below this line -->

#### #129: Fabric cause register, certified on silicon (August 2026)

**Claim.** The interpreter fabric now stamps the refusal cause registry byte per evaluate: a
CAUSE register (0x34, wrapper latched with RESULT) reads 0 on a clean match, 0 on a terminal
stop, and 36 (route:stuck, registry byte verbatim) when a non terminal node has no viable
edge, splitting the two no match surfaces the match bit alone conflates.

**Method.** RTL: one output on ppt_interp stamped in the S_DONE convergence from signals the
FSM already holds (edge count of the evaluated node), one latched read register on ppt_axi;
0x30 left reserved for the stateful CUR_NODE register. Sim: the frozen conformance corpus in
the cocotb gate with cause expectations folded into every predicate vector (true is clean 0,
false is stuck 36), a dedicated terminal stop check, and stuck stop assertions in the engine
walk; the AXI wrapper testbench alongside. Silicon: dp_corpus_cert_cause.py on the Arty Z7 20
datapath overlay, same frozen bundle as the standing corpus cert, plus per vector cause reads
and a terminal leg discovered from each image's own node records; the stateful finale overlay
(cause patch applied on top of its superset wrapper) re certified by the full hysteresis
harness.

**Result.** Sim gate 114 predicate plus 6 engine vectors green with causes. Silicon: 124/124
corpus vectors, zero cause mismatches (68 clean, 56 stuck, the exact expected split), 116/116
terminal stops clean; finale leg 1 replay 4568/4568 events against the frozen trail, leg 2
live operator sweep with band transitions on the signed thresholds. Evidence:
prismpath-hw/evidence-cause-recert/ (causecert.out sha256 23c9a453..., hystcert3.out
1072376f..., finale_load.out 857b77d7...).

**Honest scope.** The LA2016 WCET on pins third witness was NOT taken this session: the tap
signal clips would not seat on the driven JB pins (the analyzer, its ground, and the bitstream
driving W14/Y14/T11/T10 were each proven good; a physical pin identification problem on a board
that browned out repeatedly at PL config time). The RTL landed anyway on an owner decision,
because the bound is established unchanged three other ways: the cause output sits at the
existing done convergence not on the timing path, N_MAX is literally unchanged at 408, the sim
WCET calibration passed on the edited RTL, and the formal proof's basecase passed. The on pins
re witness is deferred to a calmer bench session. The fabric emits one nonzero cause today
(route:stuck); state band causes (stale park, swap park) arrive with the paths that produce
them. The finale wrapper carries the cause patch on top of the not yet landed stateful register
work; only the datapath/base cause register is committed.

**Provenance.** prismpath-hw main 8cca067 (rtl/ppt_interp.sv, rtl/ppt_axi.sv,
tb/test_ppt_interp.py, pynq/dp_corpus_cert_cause.py, evidence-cause-recert/); overlays rebuilt
Vivado 2023.2 batch, timing met, bitstreams hash verified across every transfer hop.

#### #130: Receipt streams, the cause code wire leg (August 2026)

**Claim.** PROTOCOL 2.10 defines the receipt bearing Facet stream: the kernel receipt's
proven fields (prev_node, event, next_node, seq, cause) in canonical order, the cause code
riding as an ordinary symbol under the standard symbol plus one mapping, so a clean decision
is the densest code on the wire; declaration rides the section 2.1 codebook agreement with no
new mechanism.

**Method.** Reference implementation adapters/telemetry/receipts.py in the replay and
concentrator house pattern; frozen conformance vectors
(adapters/telemetry/conformance/receipts.json) covering cause 0, 36, a wire band cause, and
the u8 maximum, with byte identical round trips; referees
adapters/telemetry/tests/test_receipts.py and adapters/fusion/tests/test_receipts_profile.py
(composition with the replay window and concentrator). First vector hand verified against the
Zeckendorf coding by inspection.

**Result.** Full suite 1018 passed, 1 skipped, including the new referees; merged to local
main (push owner gated).

**Honest scope.** Drafted by a governed agent run and review corrected before merge: the
declaration mechanism, the symbol mapping description, and the referee paths were fixed in
review. The dissector does not yet name receipt stream causes (no clean declared profile seam
in facet.lua); noted for a follow on. No live system speaks this profile yet; it is a spec
plus referee pair.

**Provenance.** prism-path main, merge 053e13b (wire/receipts-profile), review fix 213a222.

#### #131: Loader attests the hot-swap migration cause, both arches (August 2026)

**Claim.** The first nonzero cause EMISSION in the kernel/loader plane (which until now only carried
the byte, always clean). On a policy hot-swap the loader attests the migration cause: 0 when the
resident posture is preserved by name, 66 (state:migration-reset) when a reset-to strategy or a
vanished name parks it on the new fail-safe.

**Method.** migrate_node gains a nullable out_cause; selector_hotswap emits a structured loader
migration receipt line carrying it; PPT_CAUSE_MIGRATION_RESET (66) added to ppt_common.h from the
registry; migrate_selector.c asserts both causes. Built and run on both certified arches.

**Result.** migrate_selector PASS on aarch64 (gx10) and x86_64 (the Protectli), each printing
cause=0 (clean) for by-name and cause=66 (state:migration-reset) for reset-to, the resident posture
landing on the signed fail-safe. The eBPF program (ppt_select.bpf.c) is byte-unchanged, so its prior
2-arch receipt cert stands.

**Honest scope.** This is the loader-migration-receipt half of the kernel cause-emission follow-on:
the loader now knows and attests the cause via a structured line; wiring migration receipts into the
SIGNED audit trail alongside the kernel ringbuf stream is completed in #132. Per-packet no-match refusals
are deliberately NOT emitted as receipts (that would flood the stream; a no-match stays a silent drop
with the result-plane counters). Separately noted: gen_migrate_fixtures.py regenerates a
migrate_Breset fixture that behaves differently from the committed one (a generator reproducibility
gap, pre-existing, tracked for a follow-up); the committed fixtures are the certified inputs.

**Provenance.** prism-path main, merge 2f9bd8c (kernel/migration-cause: prismpath-ebpf/loader.c,
migrate_selector.c, ppt_common.h). No push (owner-gated).

#### #132: Migration receipts join the one signed audit trail, both arches (August 2026)

**Claim.** A hot-swap migration now produces a first-class ppt_receipt that folds into the SAME
Merkle-rooted, policy-bound trail as kernel transition receipts, not merely a stderr line. The
migration receipt reuses the anchored ppt_receipt struct unchanged, marks itself with an event
sentinel (PPT_EVENT_MIGRATION), and carries the migration cause (0 preserved by name, 66 reset park).

**Method.** merkle.h extracts the receipt-trail Merkle root verbatim from receipts_selector.c into a
shared header, so kernel and migration receipts anchor with one implementation (no drift);
receipts_selector.c includes it. selector_hotswap gains a nullable out_migr ppt_receipt* (the trail
seam) filled with seq, monotonic t_ns, the new policy hash, pre/post posture, the sentinel, and the
cause. migrate_selector.c became a unified-trail proof: it drains the kernel data receipts, captures
both migration receipts, folds all into one batch, Merkle-roots them, and asserts the migration
receipts are well-formed, policy-bound (distinct non-zero hashes for by-name vs reset-to), and
covered by the root (flip a cause, the root moves).

**Result.** migrate_selector PASS on aarch64 (gx10) and x86_64 (the Protectli): 4 kernel + 2 migration
receipts = 6 leaves, one root, tamper-evident. The Merkle refactor is non-regressive: receipts_selector
still 624/624 with zero mismatches on both arches (same policy_hash 207748442a7915c8; roots differ only
by per-session t_ns, as designed). The eBPF program is byte-unchanged; its 2-arch cert stands.

**Honest scope.** The one-shot swap CLI passes NULL for the receipt (the harness and, in production,
the forwarder that owns the trail capture it via the same out-param). The live-forwarder sink is
completed in #133. Per-packet no-match refusals are still deliberately not emitted (they would flood
the stream).

**Provenance.** prism-path main, merge 1d65dc8 (trail/migration-receipts: prismpath-ebpf/merkle.h new,
ppt_common.h, loader.c, receipts_selector.c, migrate_selector.c). No push (owner-gated).

#### #133: Live forwarder folds migration receipts into its signed trail, both arches (August 2026)

**Claim.** The decision-delta delivery forwarder, a live UDP-driven node, now performs a policy
hot-swap in-process and folds the loader migration receipt into the SAME per-session trail and
Merkle root as the kernel data receipts it drains. Migration receipts are first-class leaves of the
live signed trail, not a side channel.

**Method.** sel_forward_receipts.c gains a UDP control command, SWAP <new_policy.ppt>, that runs an
in-process selector_hotswap capturing the migration receipt via the out-param; the receipt is
appended to the session batch (a Merkle leaf), written to the trail log with its cause and the
PPT_EVENT_MIGRATION discriminator, and send-on-delta'd downstream as the posture change it is. The
new policy is adopted (config_map restamps policy_hash). The forwarder's local merkle_root copy was
removed in favour of the shared merkle.h, so every trail anchors with one implementation.

**Result.** Live on BOTH arches (aarch64 gx10 + x86_64 Protectli): driving the forwarder over UDP
with two events, a SWAP, and a follow-up event yields a trail carrying the migrate-reset receipt
(prev=2, event=PPT_EVENT_MIGRATION, next=1, cause=66) between the data receipts, receipts=4 swaps=1,
one Merkle root over all four leaves, policy_hash restamped across the swap (f24d59.. to 48f24b..).
Roots differ across arches only by per-session t_ns, as designed. The eBPF program is byte-unchanged.

**Honest scope.** The swap is driven over the forwarder's UDP control channel (a live delivery node
owns its swaps); the standalone selector_swap_cmd CLI for one-shot admin swaps is wired to a sealable
journal in #134. Per-packet no-match refusals are still not emitted (flood).

**Provenance.** prism-path main, merge 84ff3b9 (trail/forwarder-sink:
prismpath-ebpf/decision-delta-demo/sel_forward_receipts.c). No push (owner-gated).

#### #134: One-shot swap CLI writes migration receipts to a sealable journal, both arches (August 2026)

**Claim.** An out-of-band admin swap (loader <new> swapselector <old>) now persists its migration
receipt to an append-only receipt journal, so it joins the signed trail lineage instead of vanishing
to stderr. A companion sealer Merkle-roots the journal with the same leaf format and canonical helper
as every other PrismPath trail.

**Method.** selector_swap_cmd captures the migration receipt via the same out-param seam the forwarder
uses and, when PPT_RECEIPT_JOURNAL is set, appends the raw ppt_receipt to that journal and prints its
Merkle leaf (unset leaves behavior unchanged). seal_receipts.c reads a journal of raw ppt_receipt
records, decodes each, Merkle-roots them via the shared merkle.h, and flags a torn trailing partial
record.

**Result.** Both arches (aarch64 gx10 + x86_64 Protectli): two admin swaps (A to Breset reset-to,
then Breset to Bname by-name) accumulate in one journal; seal_receipts reads 2 migration receipts
(cause 66 then cause 0, event PPT_EVENT_MIGRATION, distinct policy hashes 48f24b8314e6e9a9 /
aae3da26c64a29ec) and Merkle-roots both leaves; the CLI-printed leaf hashes match the sealed records.
Decision content identical across arches; roots differ only by per-run t_ns. eBPF program unchanged.

**Honest scope.** The journal is a persistent producer-side sink; pointing the live forwarder at the
same journal for one cross-process trail is realized in #135. Per-packet no-match refusals are still
not emitted (flood).

**Provenance.** prism-path main, merge ab92397 (trail/oneshot-journal: prismpath-ebpf/loader.c,
seal_receipts.c new). No push (owner-gated).

#### #135: One unified cross-process trail, both arches (August 2026)

**Claim.** Pointing the live forwarder at the same PPT_RECEIPT_JOURNAL the one-shot swap CLI writes to
makes ONE append-only journal the single trail across every producer: out-of-band admin swaps,
forwarder decisions, and forwarder in-process migrations. seal_receipts over that one journal is a
single cross-process Merkle root.

**Method.** sel_forward_receipts.c reads PPT_RECEIPT_JOURNAL; rb_cb appends each drained kernel receipt
and the SWAP handler appends the in-process migration receipt, both via the shared
append_receipt_journal helper. The per-session in-memory Merkle root is unchanged (a session view); the
journal is the persistent unified trail.

**Result.** Both arches (aarch64 gx10 + x86_64 Protectli): an out-of-band admin swap (A to Breset) then
a live forwarder session (two data events, a SWAP, a follow-up event) deposit into one journal;
seal_receipts reads 5 leaves from three producers - admin migration (cause 66, policy Breset), two
forwarder data receipts (policy migrate_A), the forwarder in-process migration (cause 66, policy
Breset), a post-swap data receipt (policy Breset) - 2 migration receipts among 5, one Merkle root.
Decision content byte-identical across arches; roots differ only by per-run t_ns. eBPF unchanged.

**Honest scope.** This closes the migration-receipt / kernel cause-emission arc (#131 to #135). The
remaining named follow-ons are unchanged: per-packet no-match refusals stay unemitted (flood), and the
two hardware-blocked edges (finale wrapper + stateful landing, WCET on-pins re-witness) await a stable
board.

**Provenance.** prism-path main, merge 426f088 (trail/unified-journal:
prismpath-ebpf/decision-delta-demo/sel_forward_receipts.c). No push (owner-gated).

#### #136: Field walk of the governed ESP-NOW mesh on real radios (August 2026)

**Claim.** On real ESP-NOW radios, walked apart outdoors, a three node governed mesh commits a signed
fusion-rule swap only on a live quorum and refuses otherwise, treats a partitioned node as a first-class
STALE input that escalates the fused verdict while the surviving quorum keeps deciding, re-absorbs the
node automatically on return, and degrades gracefully under injected packet loss.

**Method.** Three ESP32 nodes ran one unmodified signed fusion table (ppt_fusion_mesh.c); one tethered
node recorded the fused verdict to a single timestamped trail via field_walk.py while the third node was
carried out to increasing range on battery. The two-phase rule swap was fired at in-range, edge, and
partitioned positions; the receiver drop knob was swept 0/50/90/99 percent. 9069 fused verdicts over
about 30 minutes on one continuous, replayable trail.

**Result.** Swap matrix, only a quorum flips the fleet: 2/2 ACKs COMMIT (flip A to B, decisions
unbroken), 1/2 ABORT at the range edge, 0/2 ABORT under partition, no split brain. Partition: present
(band 0, OK) to STALE (band 8, DEGRADED) with the two fixed nodes' quorum held throughout, longest
partition 589 verdicts (about 118 s). Rejoin: automatic within the 1.5 s freshness window, zero
intervention. Interference: 50 percent loss fully tolerated (OK), 90 percent onset, 99 percent blackout a
steady DEGRADED (the recorded node keeps its own reading and refuses a false healthy collective),
auto-recover on clear.

**Honest scope.** This is the on-device signed-table fusion plus two-phase quorum swap, a sibling of, not
identical to, the host-side quorum-or-abstain prototype (flow-studio/pipeline/quorum.py). Single recorded
vantage (no spatial-diversity observer); distances are owner estimates; no RSSI (connectivity measured by
delivery and STALE transitions); the mobile node's sensor slot was unwired (radio and governance
measured, not sensing); interference was injected at the receiver, not a real RF jammer.

**Provenance.** prism-path, branch demo/field-walk-mesh, commit 3852c2c (prismpath-hw/mesh-fusion/:
ppt_fusion_mesh.c, field_walk.py, RESULTS-field-walk-2026-08-30.md, sanitized trail
trail-2026-08-30-field-walk.jsonl). Position marks sanitized for the public record; the raw trail with
real location marks is kept private. No push (owner-gated).

#### #137: The deterministic GRC engine spans many frameworks, breadth measured (September 2026)

**Claim.** The compliance adapter is a multi-framework deterministic GRC engine, not a single-checklist
tool: it assesses NIST 800-171 R2/R3, 800-172 (CMMC Level 3), SOC 2, and an AI-governance catalog from
one honest-hybrid core (config = deterministic checks, documented = LLM adjudication, operational =
recorded task completions), with crosswalks to 800-53 and the NIST AI RMF, plus governance,
three-lines-of-defense, obligations, SOP-generation, remediation/POA&M, and SSP-generation layers.

**Method.** The layered adapter under adapters/compliance/ built out over a committed arc (18dd560
multi-framework .. 5f648c5 SSP generator); breadth verified by its own pytest suite and arch_guard.

**Result.** 314 compliance tests pass, arch_guard clean; 50 machine-checkable 800-171 controls decidable
from posture facts alone (up from 26), the remainder adjudicated by the documented/operational
mechanisms; multi-framework assess-once-report-to-many with authoritative-table crosswalks (800-53 from
the NIST CPRT, AI RMF).

**Honest scope.** Breadth is the claim here, not a clean-room external audit; the LLM-adjudicated path
depends on the configured model (gemma), and the machine-checkable verdicts' trust rests on the evidence
class of each fact (see #139). No customer C3PAO assessment has been run against this engine.

**Provenance.** prism-path, branch feat/grc-compliance-adapter (adapters/compliance/: the layered
modules + tests); commit range 18dd560..5f648c5. No push (owner-gated).

#### #138: The GRC engine dogfooded on a real CUI enclave: an honest CMMC L2 self-assessment from -119 to +63 (September 2026)

**Claim.** The engine assessed a purpose-built CUI enclave against all 110 NIST 800-171 R2 controls and
raised the SPRS score from the -119 floor to +63/110 through real remediation and recorded evidence, with
no gaming: every credited control is backed by verified configuration, a deployed control, an operational
record, or a documented attestation, and INSUFFICIENT is scored as not-met.

**Method.** A hardened Ubuntu 24.04 VM (LUKS + clevis-TPM2 auto-unlock, MFA, auditd/AIDE/ClamAV, ufw)
was built on the org's virtualization host, isolated on its own default-deny network segment, and
monitored by the org SIEM with a dedicated network boundary sensor. PrismPath ran the honest-hybrid
assessment; gaps were remediated (least functionality, device access, account lifecycle) and operational
evidence recorded (training attestation, IR tabletop, maintenance, reviews).

**Result.** SPRS -119 -> +63/110; 72 controls met, 15 documented Not Applicable; every weight-5 control
met except the physical family (locking cabinet pending hardware). Network boundary monitoring proven
live (boundary-flow alerts observed in the SIEM from real enclave traffic); network admin path removed
(SSH masked, console-only) closing device authentication; signed security-awareness training on file.

**Honest scope.** A self-assessment, not a C3PAO assessment; the org handles no CUI yet (a readiness
posture); several verdicts rest on documented attestation rather than a live scan (now disclosed per
#139); the physical controls and the operational cadence accrue over time.

**Provenance.** cmmc-self-assessment/ (posture-cui-enclave.json, assessment-cui-enclave-full.json,
document-package/crystal-warden/, enclave-build-assets/); the dedicated CUI enclave VM;
prism-path adapters/compliance. No push (owner-gated).

#### #139: Evidence-typed compliance verdicts: the receipt cause-code pattern ported to GRC (September 2026)

**Claim.** Every deterministic compliance verdict discloses HOW each fact was evidenced, tool-scanned vs
documentation-attested, so an attested True is never silently equated with an independently verifiable
one, the receipt-cause discipline of the fabric (#129/#130) applied to the GRC decision.

**Method.** deterministic_checks.py gained an evidence class per fact (scanned | attested), an evidence
rollup on each determination receipt (scanned/attested/mixed + per-class objective lists), and a typed
per-objective view; all 124 registered facts were classified. Verified by a new provenance test.

**Result.** 50 machine-checkable controls each carry an evidence rollup; the classification surfaced and
fixed a real mis-mapping (3.8.8 unowned-portable-storage had been overwritten with 3.8.7's
removable-media fact); full compliance suite green (314) including test_evidence_provenance.

**Honest scope.** The class marks provenance, not correctness: an attested True still requires an
assessor to verify the backing document; the engine only guarantees the verdict is deterministic given
the posture and that its provenance is disclosed.

**Provenance.** prism-path, branch feat/grc-compliance-adapter, commit 474d069
(adapters/compliance/deterministic_checks.py: evidence_class, _evidence_rollup, check_objectives_typed;
tests/test_evidence_provenance.py). No push (owner-gated).

#### #140: Theorem I1 proven in Lean 4, and stating it found three decision preservation defects in the reference quantizer (September 2026)

**Claim.** Figueroa quantization's decision preservation (PROTOCOL.md invariant I1, the paper's
Theorem 2.2) is now a machine checked theorem over a Lean 4 model of the Level M fragment, for
policies with integer, boolean, and string fields and well typed total readings; and the act of
stating that theorem against the reference implementation exposed three atom forms on which the
reference violated I1, each now fixed in the Python reference and the Rust mirror and pinned by the
frozen corpus.

**Method.** Lean 4.33.1 with Mathlib v4.33.1 (formal/TOOLCHAIN.md). formal/FQ models conditions,
first match routing, and the per field partitions derived from the policy; the numeric partition is
given both as the reference algorithm (fine grid of point and gap cells, adjacent merge by atom truth
vector) and as a canonical count of retained boundaries, and FQ/Bridge.lean checks by evaluation
that the two agree on integer ranges. FQ/I1.lean proves decision_preservation: equal quantization
implies equal route. The argument is that an atom's truth changes between k and k+1 only when k+1
is a constant or a constant's successor, such a boundary is retained exactly when the truth vector
changes across it, and the symbol counts retained boundaries at or below the value, so equal
symbols leave no retained boundary between two values. Booleans are two cells; two strings with
one symbol are either equal or both unnamed, and every string constant is named. While writing the
partition definitions the reference's constant collection was compared with the model and tested
directly by routing readings and their reconstructed representatives through the engine.

**Result.** decision_preservation compiles with zero sorry; #print axioms lists propext,
Classical.choice, Quot.sound only. The three reference defects, each demonstrated on a one line
policy before the fix: numeric `x in (3, 5)` (readings 3 and 4 shared a symbol and routed
differently), numeric `x not in (7,)` (7 and 8), and bare truthiness `x` alongside `x >= 5`
(0 and 1); a fourth, string truthiness `name` alongside `name == 'root'` ("" and an unnamed
string), was found from the model. Cause: `_numeric_partition` used only ordering and equality
constants as cut points, and `_categorical_partition` had no "" constant; the Rust mirror carried
the same omission and additionally evaluated `in` and `not in` as false in its merge. Fixed in
adapters/telemetry/quantizer.py and prismpath-telemetry-rs/src/quantizer.rs; regression test
adapters/telemetry/tests/test_quantizer_cut_points.py (6 tests); decisions.json frozen corpus v2
adds three flows (numin, truthynum, strtruthy: 17 readings) with the four original flows byte
identical in readings, routes, and Python wire bits (a new gen_wire_parity.py freezes the latter for
the Rust cross implementation test); boundary and spiral corpora regenerate byte identically.
Suites: prismpath/tests 723 passed, telemetry 154, fusion 153, Rust workspace 110, arch_guard clean.

**Honest scope.** No shipped or measured flow uses the affected forms (every bare truthiness edge in
the repo is on a boolean field, no numeric in list exists), so no ledger number moves; the defect
was latent in exactly the atom forms the frozen corpus never exercised, which is the point of the
row: implementations agreeing across substrates showed they agreed with each other, not with the
definition. The theorem is stated over the canonical boundary count form and over well typed total
readings; the reference algorithm's equality with that form is checked by evaluation on ranges, not
yet proven; the generated vector bridge to the frozen corpus (milestone 2), the coarsest partition
claim (I1b), and the reconstruct corollary (route of the representative equals route of the reading,
which needs the retained boundaries proven sorted and duplicate free) remain open and named. The
README and paper keep the wording "machine checked" until the vector bridge lands. Lean is not in
the CI matrix; lake build is a documented local gate.

**Provenance.** Branch formal/lean-fq, commit d3701ca (formal/FQ/{Syntax,Partition,Bridge,I1,Axioms}.lean,
formal/TOOLCHAIN.md, formal/HANDOFF.md section 0); branch fix/quantizer-cut-points (the reference
fix, corpus v2, regression tests, gen_wire_parity.py). No push (owner gated).

#### #141: The FQ formalization completes its bridge and its wire: reconstruct corollary, coarsest interval, Fibonacci code round trip and self framing proven; 623 generated checks tie the model to the frozen corpora and the corrected reference (September 2026)

**Claim.** Beyond #140's Theorem I1, the Lean model now proves the paper's statement of I1 in words
(routing the reconstructed representative reproduces the decision), the coarsest interval property
(I1b), and PROTOCOL.md invariant I2 for the Fibonacci wire (round trip and self framing, including a
whole stream); and the model is tied to the code by generated, build time evaluated checks against
the frozen predicate, decisions, and spiral corpora and the corrected reference quantizer and codec.

**Method.** formal/FQ/Reconstruct.lean: the retained boundaries are strictly increasing
(pairwise_mergeSort, dedup_sublist, nodup_dedup), a count lemma on strictly increasing lists, the
representative of a symbol quantizes to that symbol for all three kinds, a policy's partition fields
are distinct, then decision_preservation applied to a reading and its representative.
formal/FQ/I1.lean: coarsest_interval from the retained filter. formal/FQ/Zeckendorf.lean on Mathlib's
Nat.zeckendorf: body bit i stands for fib (i + 2), a terminating 1; round trip by reindexing the
position sum to the index list and Nat.sum_zeckendorf_fib; self framing from the gap of two between
indices (no adjacent set bits) and the greatest index always being used (the body ends in 1); the
stream theorem by induction with fuel. formal/gen_vectors.py emits FQ/Vectors.lean, one #guard per
check, from predicates.json v2, decisions.json v2, spiral_fusion.json, and the reference codec.

**Result.** Zero sorry; every theorem depends only on propext, Classical.choice, Quot.sound
(FQ/Axioms.lean lists decision_preservation, symbolCount_eq_truthVec, reconstruct_route,
coarsest_interval, Zeck.decode_encode, Zeck.takeCode_encode, Zeck.decodeStream_flatMap). Generated
checks all pass at build: 35 Level M well typed predicate cases equal the frozen expectation, 90
frozen routes and 164 canonical symbols equal the corrected reference quantizer's on every
decisions.json reading, 34 spiral probes, 300 Fibonacci codes byte identical to the reference's
strings; plus the hand written Bridge checks that the reference partition algorithm and the canonical
form agree on integer ranges.

**Honest scope.** I1b is coarsest among INTERVAL partitions: with x == 5 the values 4 and 6 share a
truth vector but not a cell, and neither the implementation nor the paper's monotone step function
merges non adjacent cells, so the paper's phrase "coarsest partition on which every atom is
constant" should carry the interval qualifier. The predicate bridge covers 35 of the 136 Level M
vectors: 72 are missing field cases (the model has total readings), 13 cross kind comparisons, 15
non scalar or float constants, 1 shape not carried; each excluded class is a stated decision, not a
gap in the theorem. Two items stay open, both day scale: the reference list algorithm equal to the
canonical count as a theorem (today evaluated on ranges and on the corpus), and the spiral band
bijection. README and paper keep "machine checked" wording until the owner decides how to cite the
theorems; Lean stays a documented local gate, not in the CI matrix.

**Provenance.** Branch formal/lean-fq, commits b026a24 (bridge), a44df0a (reconstruct, I1b, dedup),
3b06578 (Zeckendorf); formal/TOOLCHAIN.md (Lean 4.33.1, Mathlib v4.33.1 at 0df444a). No push (owner
gated).
