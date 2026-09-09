# Supporting Evidence · STAGING (pending rows)

*Append boundary for ledger overhauls (see `LEDGER_STANDARDS.md` §6). While a docs session overhauls
`supporting-evidence.md`, the **dev session appends new evidence rows here**, starting at the next
free number, instead of editing the main ledger. On merge, the docs session folds these into the
ledger with correct formatting and clears this file.*

*Format each row exactly per `LEDGER_STANDARDS.md` §1 (Claim / Method / Result + Honest scope /
Provenance) with a month granularity date. Next free number: **#144** (#140 and #141 are staged on branch formal/lean-fq).*

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

#### #142: The pre registered comparison against OPA, Cedar, Cerbos, OpenFGA, and Openlane, all six phases: PrismPath is native on every property it builds in, no comparator on more than two, and it is not a distinct layer under the bar the protocol set (September 2026)

**Claim.** A capability comparison fixed before any comparator was installed, run to the end on real
systems and real hardware, and reported against its own predictions. On the eight properties PrismPath
builds in, PrismPath grades native on all eight and no comparator grades native on more than two; OPA,
the direct comparator, reaches the same eight only with 391 lines of glue in three pieces, built and
run here rather than costed; Cedar, Cerbos, and OpenFGA cannot reach the receipts row at all under the
budget. On the five properties where PrismPath was expected to lose, it loses as predicted. Under the
protocol's strict bar, a property counts as a distinct layer only if every comparator including glue is
NOT, and no property meets it: A3 falls because OPA's compiled WebAssembly runs on an RP2350 under a
third party interpreter with identical decisions, A7 because the rubric grades a request timeout as a
documented way to cap work. Thirteen of seventy eight cell predictions were wrong, every one listed
with its reason, none adjusted.

**Method.** prismpath/comparisons/. Phase 0 froze the protocol (PREREGISTRATION.md, lock 54f05739,
one recorded amendment before any comparator result existed): six neutral policies with 61 scenarios
and 5 lifecycle entries, the grade vocabulary native, with work, not, a glue budget of 300 lines and
8 hours with no new trust anchor, a prediction for every cell, and matrix.py generating MATRIX.md and
matrix.json from result files only. Phase 1 pinned and checksum verified OPA 1.20.2, Cedar CLI 4.12.0
with cedarpy 4.8.7 for in process timing, Cerbos 0.55.0, OpenFGA 1.19.0; Openlane from documentation.
Phase 2 translated every policy into each system's idiom with the official construct cited per rule
and re ran every translation against the corpus before any result file was written (PrismPath 52
match, 3 dropped, 6 unexpressible; OPA and Cedar 61; Cerbos 55 with the role hierarchy flattened in
CEL; OpenFGA 6). Phase 3 ran Group A: the six proposal AI worker loop with receipts, abstain and human
routing from the conformance rows, wire bytes from live servers, lifecycle refusals at the agent with
RS256 signed bundles, 100,000 timed decisions per scenario per system, and the substrate legs of #143.
Phase 4 graded Group B from the same conformance rows and, for verification, ecosystem, and maturity,
from documentation with the grade bars written before the rows. Phase 5 built the combination column:
OPA's module under wasm3 on a Pico 2 W (171 lines of glue), a decision log receipt sink signing with
the bundle key OPA already trusts (131 lines), a Facet encoding of OPA's input (35 lines), a revision
floor before bundle load (54 lines). Phase 6 wrote VERDICT.md from the generated matrix, with a test that fails
if the two disagree on any verdict or if the wrong prediction table drifts from the cells. Two glue
modules were drafted by agy and their gates re run here before they counted.

**Result.** Verdicts computed by matrix.py from 638 result files: A1 to A8 NOT-DISTINCT, B1 to B5
LOSES. The map, PrismPath / OPA / Cedar / Cerbos / OpenFGA / OPA plus glue: abstain native / native /
with work / with work / not / native; human routing the same; substrates native / not / not / not /
not / with work; receipts native / with work / not / not / not / with work; compact wire native / not /
not / with work / not / with work; anti rollback native / with work / not / not / not / with work;
bounded time native / with work / with work / with work / not / with work; the AI worker loop native /
with work / not / not / not / with work; Openlane not on all eight by boundary. Measured: wire bytes per
reading 4 to 6 (PrismPath) against 117 (OPA), 237 (Cedar), 512 (Cerbos); decision medians over 100,000,
PrismPath Python 12 to 96 us in process, Cedar 31 to 39 us in process, OPA 302 to 333 us over
loopback HTTP, Cerbos 710 to 872 us; anti rollback, PrismPath refused stale, tampered, and unsigned
at the point, OPA refused tampered and unsigned and accepted an older signed revision until the 54
line floor; OPA's WebAssembly on the RP2350, 23 of 23 identical decisions at 311,636 B heap high
water of 520 KB, 136 KB module per policy, 3.8 to 5.5 ms USB round trip (54 ms on first evaluation),
against PrismPath's 1.7 KB interpreter class, 224 B and 160 B images, sub millisecond, with a signed
bound; Facet over OPA, 2 to 3 B frames in place of 70 to 75 B JSON, 23 of 23 identical; receipts over
OPA, 6 of 6 verified, an altered record and a foreign key rejected. Group B: PrismPath drops two of six
rules of the RBAC plus ABAC policy (field against field, set intersection) where Rego, Cedar, and
Cerbos match 8 of 8; cannot ask the sharing question OpenFGA, OPA, and Cedar answer 6 of 6; has no
machine checked proof of its evaluator where Cedar's authorizer and validator are in Lean; a narrow,
substrate shaped ecosystem; two months of public history. Wrong predictions: Cedar under rated on A1,
A2, and B4; Cerbos and OpenFGA over rated on A4 and A8 because a signature needs a trust anchor they
lack; Cerbos's gRPC on A5; timeouts on A7 for OPA, Cedar, and Cerbos; the A3 and A7 verdicts.

**Honest scope.** The layer bar was the protocol's construct, and its failure retires one claim,
that PrismPath is a layer the existing engines cannot reach; it does not touch what PrismPath is, a
control plane with receipts, one of many control planes, with an unusual approach and its own wire.
Both PrismPath and OPA on the Pico are a portable artifact plus a per substrate runtime; the fragment
PrismPath restricts decisions to is why its runtime is 1.7 KB where wasm3 is 60 KB, why a bound can be
signed, and why B1 is a loss. The cross substrate claim is a claim about the Level M fragment; the
semantic tier stays on the host. One MCU family was reached for OPA (RP2350 ARM; the RISC-V build
hung, recorded as attempted); the 8 bit and FPGA targets were not attempted for OPA and would widen
the degree, not change the map. A7's verdict follows a rubric that treats a timeout as a cap; the
embedded reading of the same evidence is stated beside it. The receipts glue was built for OPA only.
B4 and B5 are documentation rows against published bars. The corpus is small and neutral by design.
The B2 note credits the FQ Lean development (#140) without counting it, because the dimension is
verification of the decision engine. Two caveats on the glue are in its rows: the receipt sink must
run where the bundle private key lives, and the revision floor persists a revision before OPA's
signature check. Publication is the owner's decision; the recommendation is the whole comparison,
verdict included, or none of it.

**Provenance.** Branch comparisons/phase0-prereg, commits fc01f13 (Phase 0) through 7da9ed2 (the
verdict): prismpath/comparisons/{PREREGISTRATION.md, PREREGISTRATION.lock, VERDICT.md, MATRIX.md, matrix.py, harness.py, corpus_check.py, check_translators.py}, corpus/, systems/<id>/
(translators, generated translations, conformance.json), groupa/, groupb/, glue/, toolchain/
(install.sh with every pin including wasm3 40e42cc, TOOLCHAIN.md), results/<system>/ with evidence
(OPA's WebAssembly modules are rebuilt from policy.rego by groupa/opa_wasm_mcu/gen_wasm.py against the
recorded sha256, not stored),
prismpath/tests/test_comparisons_{prereg,matrix,toolchain,translators,groupb,verdict}.py and
test_glue_*.py. Bench: the GX10 (aarch64), the Protectli (x86_64), a Raspberry Pi Pico 2 W, the Arty
Z7-20. No push (owner gated).

#### #143: The comparison corpus decided identically on seven substrates, and the signed worst case bound held on the fabric pins for both comparison images (September 2026)

**Claim.** The A3 and A7 legs of #142 on hardware: one compiled image per comparison policy decides
the 23 corpus readings identically, outcome and rule, on host Python, the C reference, in kernel on
aarch64 and x86_64, on both ISAs of an RP2350, and on the Zynq-7020 fabric; and the per policy
worst case bound that travels signed with each image, recomputed at verify, was honored by every
evaluation the logic analyzer saw on the fabric pins.

**Method.** groupa/a3_corpus.py compiles network_admission (224 B) and sensor_interlock (160 B) once
through the untouched table compiler and frames the 23 complete scenario readings as table per vector
records with the host Python route as the expected target, cross checked against the C reference.
Kernel legs: loader certify via BPF_PROG_TEST_RUN on the GX10 (Linux 6.17.0, clang 18) and on the
Protectli (Linux 6.17.2, program object rebuilt there with clang 19 from the identical source). MCU
legs: groupa/a3_mcu.py replays the records over the unchanged RP2350 certification firmware's
USB-CDC contract, one Pico 2 W flashed with the Cortex-M33 build and then, after a 1200 baud reset
into the bootloader, with the Hazard3 RISC-V build, both rebuilt this session (Pico SDK 2.1.1,
gcc-arm-none-eabi 13.2, riscv32-unknown-elf gcc). Fabric legs: groupa/a3_fabric_attach.py attached to
the finale overlay the board's boot demo service had already loaded (pynq Overlay without download,
address from the running design's own hwh, auto mode off to the certified PS evaluate path of #117
and #123), loaded both images through the AXI load port, and evaluated the 23 readings; then, after
quiescing, groupa/a3_fabric_run.py loaded the tapped ppt_datapath.bit once from a single process and
repeated the 23. Pins witness: groupa/a7_sweep_only.py swept each policy's readings continuously
through the PS path for 400 s while groupa/a7_pins.py on the GX10 took 30 free run LA2016 captures per
policy on Pmod JB at 200 MSa/s (threshold 1.4 V, passed to sigrok as the range literal 1.4-1.4) and
measured every busy window with the #122 bench code (la_wcet_check.measure, edge count and width
methods). groupa/a3.py and groupa/a7.py write PrismPath's result files from the leg records; a7.py
grades from the witness record (native on PASS, with work when absent, not on FAIL).

**Result.** 23 of 23 on every leg: python, C, kernel aarch64 (ALL PASS), kernel x86_64 (ALL PASS),
rp2350-arm (USB-CDC round trip median 370 us), rp2350-riscv (median 551 us), Zynq-7020 fabric on the
resident finale overlay (PS path round trip about 88 us, cause byte 0 on every match) and again on the
tapped datapath overlay. Pins: network_admission longest busy window 34 cycles against the signed 35
over 224 measured evaluations; sensor_interlock 23 against the signed 24 over 216; 0 disagreements
between the two measurement methods; both PASS. PrismPath's A3 result files carry seven legs and its
A7 result files carry the witness.

**Honest scope.** One MCU family this run (RP2350, two ISAs); the ESP32 Xtensa leg was not rerun (row
#98 certifies the same interpreter on it against the frozen predicate corpus, not this policy corpus).
The fabric legs use the PS evaluate path, not the auto mode datapath, because the corpus is fed from
registers. The bounds are tight by one cycle on both images, as the cycle exact formula of #109
predicts; the witness counts are hundreds of evaluations per image sampled free run from a continuous
sweep, not the sixteen thousand of #123 and not an exhaustive per reading pass. Board handling learned
and recorded in groupa/HARDWARE_LEGS.md: the board's boot demo service configures the PL at boot and
spends the one configuration budgeted per power cycle, so it was disabled for this work and is left
disabled; one warm reconfiguration succeeded after quiescing, one observation that does not lift the
rule; one process drives the fabric at a time, and a 37 s overlap caused by a process name match was
ended by killing by PID with the board intact. The Pico was returned to nothing in particular.

**Provenance.** Branch comparisons/phase0-prereg, commits 54cd707 (MCU legs), a568419 (fabric attach),
da41b7c (pins witness): groupa/{a3_corpus,a3,a3_mcu,a3_fabric_attach,a3_fabric_run,a7_sweep_only,
a7_pins,a7}.py, groupa/HARDWARE_LEGS.md, results/prismpath/evidence/A3/ (a3.packets.bin,
a3_vectors.json, the two .ppt images, kernel_aarch64_gx10.log, kernel_x86_64_protectli.log,
mcu_ppt-rp2350_*.json, fabric_finale_attach.log, fabric_datapath_run.log, a3_fabric_bundle.json),
results/prismpath/evidence/A7/ (pins_network_admission.json, pins_sensor_interlock.json,
sweep_*.log), results/prismpath/A3__*.json and A7__*.json (23 each). Boards: Raspberry Pi Pico 2 W,
Arty Z7-20 (PYNQ) via the Protectli jump, Kingst LA2016 on the GX10. No push (owner gated).
