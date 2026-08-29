# Supporting Evidence · STAGING (pending rows)

*Append boundary for ledger overhauls (see `LEDGER_STANDARDS.md` §6). While a docs session overhauls
`supporting-evidence.md`, the **dev session appends new evidence rows here**, starting at the next
free number, instead of editing the main ledger. On merge, the docs session folds these into the
ledger with correct formatting and clears this file.*

*Format each row exactly per `LEDGER_STANDARDS.md` §1 (Claim / Method / Result + Honest scope /
Provenance) with a month granularity date. Next free number: **#129**.*

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
SIGNED audit trail alongside the kernel ringbuf stream is the next step. Per-packet no-match refusals
are deliberately NOT emitted as receipts (that would flood the stream; a no-match stays a silent drop
with the result-plane counters). Separately noted: gen_migrate_fixtures.py regenerates a
migrate_Breset fixture that behaves differently from the committed one (a generator reproducibility
gap, pre-existing, tracked for a follow-up); the committed fixtures are the certified inputs.

**Provenance.** prism-path main, merge 2f9bd8c (kernel/migration-cause: prismpath-ebpf/loader.c,
migrate_selector.c, ppt_common.h). No push (owner-gated).
