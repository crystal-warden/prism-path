# Supporting Evidence · STAGING (pending rows)

*Append boundary for ledger overhauls (see `LEDGER_STANDARDS.md` §6). While a docs session overhauls
`supporting-evidence.md`, the **dev session appends new evidence rows here**, starting at the next
free number, instead of editing the main ledger. On merge, the docs session folds these into the
ledger with correct formatting and clears this file.*

*Format each row exactly per `LEDGER_STANDARDS.md` §1 (Claim / Method / Result + Honest scope /
Provenance) with a month granularity date. Next free number: **#118**.*

---

<!-- new rows go below this line -->

### #117 — a signed policy drives a resident finite-state machine in the kernel: the stateful selector, conformance certified in-kernel 624/624 (August 2026)

**Claim:** the fixed in-kernel interpreter, unchanged, becomes a RESIDENT finite-state machine by holding its current node in a BPF map — so a signed policy is the *transition function* of a stateful kernel control plane, not just a per-packet decider. Each control packet is one discrete event; the resident posture persists across packets; no userspace is in the loop. This is the fabric switch-navigation pattern (a resident FSM whose transitions route on the policy) carried down to the eBPF decode plane.

**Method:** `ppt_select.bpf.c` is the certified `ppt_xdp` interpreter with its evaluator (`eval_atom`/`eval_prog`/`evaluate`) **byte identical** — so the frozen predicate conformance carries — plus ONE `sel_state_map` (a BPF array holding `cur_node`): the start node comes from the map (the policy's `start_node` on the first packet), it evaluates, and writes the decided target back. The transition policy `posture_selector` (a normal → elevated → lockdown ladder, escalate/de-escalate clamping at both ends) is signed Ed25519 (key `d519348f`). `gen_selector_corpus.py` freezes **49 event streams / 624 events** — boundary walks that clamp at each end, every (posture, event) transition, hold events (out of range values that route to `else`), 30 seeded random streams, and a 200 event stress stream — recording the posture the resident interpreter reaches after each event as the reference, cross checked step by step against the C target (`interp.c`), the same two referee discipline the predicate corpus uses. `cert_selector.c` replays each stream through the loaded eBPF program via `BPF_PROG_TEST_RUN`, resetting the resident state per stream, and diffs the kernel's posture trail against the frozen reference.

**Result:** in kernel, **624/624 events match and 49/49 streams are clean** — the kernel reproduces the frozen posture trail exactly (Linux 6.17, `BPF_PROG_TEST_RUN`, no NIC). The C target agrees with Python at every one of the 624 reference steps, so three independent evaluators (kernel, C, Python) concur. The resident FSM pattern is substrate independent: the identical signed selector runs as a resident walk on the C interpreter, and (from the hardware work) on the fabric `ppt_nav` overlay in simulation; only the driver differs — a BPF map here, a register in fabric, a variable in a userspace loop. **Honest scope:** a prototype, certified in kernel on the GX10 dev station via `BPF_PROG_TEST_RUN`, NOT yet live attached on a NIC nor on the Protectli deployment; one selector policy (the posture ladder), not a family; the corpus is decidable transition coverage, not an adversarial fuzz; this is a NEW capability (resident state in the kernel) distinct from the stateless net admission target, and its priority date OTS anchor over the corpus is stamped at publish, not yet.

**Provenance:** `prismpath-ebpf/ppt_select.bpf.c`, `prismpath-ebpf/posture_selector.md`, `prismpath-ebpf/gen_selector_corpus.py`, `prismpath-ebpf/cert_selector.c`, `prismpath-ebpf/selector_corpus.json` + `.bin`, `prismpath-ebpf/STATEFUL_SELECTOR.md`; box Linux 6.17 / clang 18 / BTF; transition policy signed with the Ed25519 authority key_id `d519348f`.
