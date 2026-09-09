# Supporting Evidence · STAGING (pending rows)

*Append boundary for ledger overhauls (see `LEDGER_STANDARDS.md` §6). While a docs session overhauls
`supporting-evidence.md`, the **dev session appends new evidence rows here**, starting at the next
free number, instead of editing the main ledger. On merge, the docs session folds these into the
ledger with correct formatting and clears this file.*

*Format each row exactly per `LEDGER_STANDARDS.md` §1 (Claim / Method / Result + Honest scope /
Provenance) with a month granularity date. Next free number: **#140**.*

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

#### #144: The layer comparison, Group A software results: seven of eight pre registered dimensions run against OPA, Cedar, Cerbos, OpenFGA, and Openlane, six computed NOT-DISTINCT as predicted, one computed NOT-DISTINCT against the prediction, one open on hardware (September 2026)

**Claim.** Under the pre registered protocol (prismpath/comparisons/PREREGISTRATION.md, freeze 54f05739)
the Group A matrix is generated from result files produced by the real systems at pinned versions
(OPA 1.20.2, Cedar CLI 4.12.0 with cedarpy 4.8.7 for timing, Cerbos 0.55.0, OpenFGA 1.19.0, Openlane
from documentation), and the computed verdicts are: A1, A2, A4, A5, A6, A8 NOT-DISTINCT as predicted;
A7 NOT-DISTINCT where DISTINCT was predicted; A3 OPEN pending an MCU class leg.

**Method.** prismpath/comparisons/groupa/: a8 (six proposal loop with receipts), a1a2a4 (graded from
the Phase 2 conformance rows and the A8 receipt evidence against declared outcome carriers), a5 (bytes
at the application payload layer from live servers), a6 (real PolicyHost swaps and real RS256 signed
OPA bundles at the agent), a7 (100,000 decisions per scenario in each system's fastest embedding on
this host), a3_corpus and a3 (23 vectors compiled once, host Python, C reference, in kernel on aarch64
and x86_64; OPA to WebAssembly measured; Cedar no_std build attempted), openlane (documentation). The
grading criteria and the glue budget (300 lines, 8 hours, no new trust anchor) were fixed before
installation; matrix.py aggregates by minimum grade and computes the verdicts.

**Result.** PrismPath NATIVE on every Group A cell run. A8: OPA WITH-WORK (first class outcomes, six
unsigned console decision log records; a 150 line sidecar reusing the bundle signing key estimated),
Cedar and Cerbos NOT (a signed receipt trail would be a new trust anchor), OpenFGA not expressible.
A1/A2: OPA NATIVE (Rego returns any document), Cedar and Cerbos WITH-WORK (annotation and output
block carriers, guards for absence), OpenFGA NOT. A4: OPA WITH-WORK, Cedar and Cerbos NOT on signed.
A5, 23 readings: PrismPath 4 to 6 B request plus receipt (30 B with a 28 B IP+UDP envelope at fleet
1, 3.24 B per reading at fleet 50 concentrated), OPA 113 to 125 B, Cedar 233 to 238 B, Cerbos 506 to
516 B; Cerbos WITH-WORK (native gRPC), others NOT. A6: PrismPath refused stale
(version:not-monotonic:1<=2), tampered (image:sha256-mismatch), unsigned (sig:missing) at the point;
OPA refused tampered and unsigned bundles at the agent and accepted an older signed revision
(WITH-WORK); Cedar, Cerbos, OpenFGA NOT. A7, medians over 100,000: PrismPath Python 11.6 to 96.4 us
(signed fabric bounds 35 and 24 cycles, 700 and 480 ns at 50 MHz), Cedar in process 31.1 to 38.6 us,
OPA loopback HTTP 302 to 333 us (max 20.5 ms), Cerbos loopback HTTP 710 to 872 us (max 15.0 ms);
comparators WITH-WORK under the rubric's "documented way to cap work" (timeouts; Cedar's bounded
evaluation). A3: host, C, kernel aarch64, kernel x86_64 agree 23/23; OPA's wasm module 135,831 B with
128 KB minimum memory, not run on an MCU; Cedar's core fails to build for Cortex-M at memchr requiring
std; Cerbos and OpenFGA server only.

**Honest scope.** A7's prediction was wrong on the rubric, not the measurement: a request timeout caps
wall time rather than bounding work, but the pre registered WITH-WORK text counts "a documented way
to cap work", so the verdict is NOT-DISTINCT and the distinction between cap and bound is for the
verdict prose. PrismPath's A7 NATIVE rests on the signed bound honored on the pins for other signed
policies (#122, #123); the pins witness for these two images is the hardware session, and the cell
drops to WITH-WORK without it. A3 needs an MCU class leg (RP2350 or ESP32 boards) before PrismPath's
rows are written. The WITH-WORK glue estimates are estimates until Phase 5 builds them. Openlane is
graded from documentation as a boundary. Group B and the verdict document are not yet written.

**Provenance.** Branch comparisons/phase0-prereg: prismpath/comparisons/groupa/*.py, results/<system>/
(one JSON per scenario, evidence under results/<system>/evidence/), MATRIX.md and matrix.json
regenerated, groupa/HARDWARE_LEGS.md. No push (owner gated).

#### #145: A3 closes DISTINCT: one compiled policy image decides 23 scenario readings identically on host Python, the C reference, in kernel on aarch64 and x86_64, and on both ISAs of an RP2350, while every comparator's MCU path fails or does not exist (September 2026)

**Claim.** The pre registered "cross substrate byte exact decisions" dimension of the layer comparison
is the one Group A dimension where PrismPath grades NATIVE and every comparator and Openlane grades
NOT, so under the frozen criterion (PREREGISTRATION.md section 9) PrismPath is a distinct layer on this
dimension, with the comparator attempts made and recorded rather than dismissed.

**Method.** groupa/a3_corpus.py compiles network_admission and sensor_interlock once (168 B and a second
image, sha256 prefixes recorded) and frames the 23 complete scenario readings as table per vector records
with the host Python route as the expected target, cross checked against the C reference. Kernel legs:
loader certify via BPF_PROG_TEST_RUN on this host (aarch64, Linux 6.17.0, clang 18) and on the Protectli
(x86_64, Linux 6.17.2, program object rebuilt there with clang 19 from the identical source). MCU legs:
groupa/a3_mcu.py replays the corpus over the unchanged RP2350 certification firmware's USB-CDC contract
(I, L, V), one Pico 2 W flashed first with the Cortex-M33 build then, after a 1200 baud reset into the
bootloader, with the Hazard3 RISC-V build, both from the one source rebuilt this session (Pico SDK 2.1.1,
gcc-arm-none-eabi 13.2, riscv32-unknown-elf gcc). groupa/a3.py --write-prismpath writes the 23 result
files from every leg. Comparator attempts (groupa/a3.py): OPA compiled to WebAssembly and the module
measured; the Cedar core built for thumbv8m.main-none-eabi in a no_std crate; Cerbos and OpenFGA
documented as servers.

**Result.** 23/23 agree on all six legs: python, C, kernel aarch64 (ALL PASS), kernel x86_64 (ALL PASS),
rp2350-arm (USB-CDC round trip median 370 us), rp2350-riscv (median 551 us). PrismPath A3 NATIVE 23/23.
OPA NOT: the wasm module is 135,831 B (75,456 B code, 7 host imports, 128 KB minimum imported memory grown
at runtime), a host class runtime form; not run on an MCU. Cedar NOT: cargo fails at memchr requiring std,
cedar-policy 4.12.0 has no no_std feature. Cerbos, OpenFGA, Openlane NOT: server or cloud only. matrix.py
verdict A3 DISTINCT; the full Group A matrix: A3 DISTINCT, A1 A2 A4 A5 A6 A7 A8 NOT-DISTINCT.

**Honest scope.** One MCU family this run (RP2350, two ISAs); the ESP32 Xtensa and the Zynq fabric legs
were not rerun here (prior rows #98 and #108 certify the same interpreter on them against the frozen
predicate corpus, not this policy corpus). The OPA on MCU attempt stops at module facts and inference
about the ESP-WROOM-32's memory; running WAMR on an ESP32-S3 with PSRAM is named for the LoRa board
session and could move OPA's cell only if it runs identically there. The Pico was returned to nothing
in particular (it carried nothing to preserve). The pins witness for these images (A7) is still pending;
A7's PrismPath grade is unaffected by this row.

**Provenance.** Branch comparisons/phase0-prereg: groupa/a3_corpus.py, groupa/a3_mcu.py, groupa/a3.py,
results/prismpath/evidence/A3/ (a3.packets.bin, a3_vectors.json, *.ppt, kernel_aarch64_gx10.log,
kernel_x86_64_protectli.log, mcu_ppt-rp2350_1_rp2350-arm_PPTM-v1.json, mcu_ppt-rp2350_1_rp2350-riscv_PPTM-v1.json),
results/prismpath/A3__*.json (23), MATRIX.md. Board: Raspberry Pi Pico 2 W. No push (owner gated).

#### #146: The Zynq-7020 fabric joins A3 as a seventh substrate (23/23 twice) and the A7 bound is honored on the pins for both comparison images, 34 of 35 and 23 of 24 cycles (September 2026)

**Claim.** The two hardware items left open by #145 are closed on the real board: the compiled comparison
images decide the 23 corpus readings identically in the fabric interpreter, and the signed per policy
worst case bound carried by each image is met by every evaluation the logic analyzer saw on the fabric
pins, so PrismPath's A7 grade rests on a measurement of these images rather than on the earlier images of
#122 and #123. Neither result moves a dimension verdict: A3 was already DISTINCT and A7 stays NOT-DISTINCT
because the comparators hold WITH-WORK through request timeouts under the pre registered rubric.

**Method.** Arty Z7-20 (PYNQ) reached through the Protectli jump after the CMMC hardening. The board's
boot demo service had already spent the one PL configuration budgeted per power cycle on ppt_finale.bit,
so the first leg attached to that resident overlay without reconfiguring (groupa/a3_fabric_attach.py:
pynq Overlay with download off, base address from the running design's own hwh, auto mode off to the
certified PS evaluate path of #117 and #123, service stopped), loaded both images through the AXI load
port and evaluated the 23 readings. The board was then quiesced (auto off, soft reset) and the tapped
ppt_datapath.bit loaded once from a single process (groupa/a3_fabric_run.py), which repeated the 23
readings on that overlay and swept them continuously; groupa/a7_sweep_only.py continued the sweeps per
policy for 400 s each while groupa/a7_pins.py on the gx10 took 30 free run LA2016 captures per policy on
Pmod JB (200 MSa/s, 1.4 V threshold) and measured every busy window with the #122 bench code
(la_wcet_check.measure, edge count and width methods). One process drove the fabric at a time except for
a 37 s overlap caused by a process matching mistake, killed by PID; the board stayed up.

**Result.** A3 fabric: 23/23 on the resident finale overlay (PS path round trip about 88 us, cause byte 0
on every match) and 23/23 again on the tapped datapath overlay. A7 pins: network_admission longest busy
window 34 cycles against the signed 35 over 224 measured evaluations (30 captures), sensor_interlock 23
against the signed 24 over 216 evaluations, 0 disagreements between the two measurement methods, both
PASS. groupa/a7.py now grades PrismPath from the witness record (NATIVE on PASS, WITH-WORK when absent,
NOT on FAIL); the 23 PrismPath A7 rows carry the witness. PrismPath A3 now spans python, C, kernel
aarch64, kernel x86_64, RP2350 ARM, RP2350 RISC-V and the Zynq-7020 fabric.

**Honest scope.** The bounds are tight by one cycle on both images, which is what the cycle exact formula
of #109 predicts, and the witness counts are hundreds of evaluations per image, not the sixteen thousand
of #123; the captures are free run samples of a continuous sweep, so they are a random sample of the
readings, not an exhaustive per reading pass. The fabric legs use the PS evaluate path, not the auto
mode datapath, because the corpus is fed from registers. One warm reconfiguration succeeded this
session after quiescing; that is one observation and does not lift the one configuration per power cycle
rule. The boot demo service on the board is left disabled. The ESP32 Xtensa leg remains not rerun.

**Provenance.** Branch comparisons/phase0-prereg, commits a568419 and da41b7c: groupa/a3_fabric_attach.py,
groupa/a3_fabric_run.py, groupa/a7_sweep_only.py, groupa/a7_pins.py, groupa/a7.py, groupa/HARDWARE_LEGS.md,
results/prismpath/evidence/A3/ (fabric_finale_attach.log, fabric_datapath_run.log, a3_fabric_bundle.json),
results/prismpath/evidence/A7/ (pins_network_admission.json, pins_sensor_interlock.json, sweep_*.log),
results/prismpath/A3__*.json and A7__*.json (23 each), MATRIX.md. Instruments: Kingst LA2016 on the gx10,
sigrok-cli with the kingst-la2016 driver. No push (owner gated).

#### #147: Group B of the layer comparison, where PrismPath loses, graded and computed LOSES on all five pre registered dimensions (September 2026)

**Claim.** The mandatory "where we lose" half of the pre registered comparison is on the record with the
same rubric, result contract, and matrix generator as the Group A claims: PrismPath loses on policy
expressiveness, formal verification of the decision engine, relationship modeling, ecosystem, and
maturity, exactly as predicted in PREREGISTRATION.md section 8, with one comparator prediction wrong in
the comparators' favor (Cedar's ecosystem is NATIVE, not WITH-WORK).

**Method.** groupb/b.py. B1 and B3 are graded per scenario from the Phase 2 conformance rows of every
translator (systems/<id>/generated/conformance.json), so the grades come from the runs already made
against the corpus: a MATCH with idiomatic constructs is NATIVE, a construct the translator had to
flatten or a path documented and costed under the glue budget is WITH-WORK, a rule the translator dropped
or a policy it declared not expressible with no evaluation left for the engine is NOT. B2, B4, and B5 are
documentation rows; the grade bars were written into the module before any row (B2: machine checked
semantics of the decision engine tied to the shipped implementation; B4: three of four integration
classes or three implementations; B5: three years, thirty contributors, a foundation home or a named
production operator) and the sources sit beside each result (sources.txt, facts.json from the GitHub API
on 2026-09-09).

**Result.** B1 LOSES: PrismPath NOT (owner_write_1, group_read_1, contractor_group_read_1 need field
against field comparison or set intersection, both outside the predicate language and dropped;
manager_hours_write_1 WITH-WORK through the hierarchy flattened at authoring; four NATIVE), OPA, Cedar,
Cerbos NATIVE 8/8 (Cerbos idiomatic=false, derived roles cannot join the negation chain), OpenFGA
WITH-WORK (conditions plus tuples plus a caller side rule ordering shim, 120 lines, 6 hours, costed not
built), Openlane NOT. B2 LOSES: Cedar NATIVE (cedar-spec, definitional authorizer, validator, and symbolic
compiler in Lean 4.33.1 with proven forbid overrides, explicit permit, default deny, order independence,
sound slicing and typing, tied to Rust by differential testing); PrismPath NOT, with the record stated
exactly: 13 machine checked theorems about Figueroa quantization, the spiral index, and the Zeckendorf
wire (rows #140 to #143), the WCET base case (#111), conformance certification on every substrate, and
no proof of the evaluator's semantics; OPA, Cerbos, OpenFGA, Openlane NOT. B3 LOSES: PrismPath NOT (not
expressible, the caller would make the decision), OPA NATIVE (graph.reachable), Cedar NATIVE (entity
hierarchy), OpenFGA NATIVE (its native question), Cerbos WITH-WORK (caller supplies the relationship data
as a list, CEL tests membership, 40 lines, 2 hours), Openlane NOT. B4 LOSES: PrismPath WITH-WORK (Zarf,
UDS, Vector codec, Wireshark dissector, kernel, MCU, FPGA, Rust and C libraries, GRC scanner adapters;
no Kubernetes admission path, Envoy filter, Terraform provider, or package index release; a webhook or
ext_authz shim costed at 200 lines, 8 hours), every comparator NATIVE. B5 LOSES: PrismPath NOT (public
since 2026-07-19, 381 commits, one organization, one tag), OPA, Cedar, Cerbos, OpenFGA NATIVE, Openlane
WITH-WORK (two years, about twenty contributors). matrix.py computes LOSES on all five.

**Honest scope.** OpenFGA's B1 and Cerbos's B3 WITH-WORK cells rest on costed, documented paths, not
executed glue, the same standard Group A applied to comparator glue; executing them could only raise
those cells, never change LOSES. B4 and B5 are documentation rows with published bars, not measurements.
The B2 note credits the quantization proofs without counting them, because the dimension is
verification of the decision engine and the formal development itself states it is not a proof about the
evaluator or the source text. The one wrong prediction (Cedar B4) is reported, not adjusted away.

**Provenance.** Branch comparisons/phase0-prereg, commit d1ba764: groupb/b.py, results/<system>/B*.json
(90 files), results/<system>/evidence/B{2,4,5}/, MATRIX.md, matrix.json, tests/test_comparisons_groupb.py.
No push (owner gated).
