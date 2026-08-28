# Supporting Evidence · STAGING (pending rows)

*Append boundary for ledger overhauls (see `LEDGER_STANDARDS.md` §6). While a docs session overhauls
`supporting-evidence.md`, the **dev session appends new evidence rows here**, starting at the next
free number, instead of editing the main ledger. On merge, the docs session folds these into the
ledger with correct formatting and clears this file.*

*Format each row exactly per `LEDGER_STANDARDS.md` §1 (Claim / Method / Result + Honest scope /
Provenance) with a month granularity date. Next free number: **#128**.*

---

<!-- new rows go below this line -->

### #128 — the kernel receipt carries its cause, and the receipt root is anchored — the #119 audit-trail caveat closes (August 2026)

**Claim:** two things, one certified session. First, the stateful selector's in-kernel audit receipt now carries the **cause code** field from the registry (`docs/design/spec-cause-codes.md`): the former pad slot (explicitly written zero since introduction) becomes `cause`, so size, layout, and every historical receipt byte are unchanged and old receipts retroactively read as cause 0; ordinary committed transitions stamp `PPT_CAUSE_NONE`, and the receipts harness now **checks** the field on every receipt rather than merely carrying it. Second, the receipt-root anchor that #119's honest scope left "pending (owner-gated)" is done: a fresh certified session's Merkle root over decisions plus signed time is OTS-stamped.

**Method:** rename `_pad` to `cause` in `ppt_receipt` plus an explicit `PPT_CAUSE_NONE` stamp at the kernel emission site, then full in-kernel re-certification via `BPF_PROG_TEST_RUN` against the frozen 624-event / 49-stream selector corpus: the posture-trail conformance run with its fail-safe check, then the receipts harness (extended with the cause check) replaying the same corpus and verifying completeness, decision fidelity, time monotonicity, policy binding, and cause 0 on every clean commit. Session outputs logged; SHA256SUMS over the session log, the frozen corpus, and the certified BPF object; OTS stamp on the sums.

**Result:** **624/624 events, 49/49 streams clean, fail-safe PASS** (uninitialized state plus one event lands on lockdown, not normal); **624/624 receipts complete, 0 decision mismatches, 0 non-monotonic timestamps, 0 nonzero causes on clean commits**, policy_hash `207748442a7915c8`; session Merkle root `58c025ba364c0c7427cb8aa0374bf2c8f45b9780a0c315469fb9c98d2479fa56`, anchored (pending Bitcoin at stamp time). **Honest scope:** receipt roots are per-session by design (the signed time axis), so this anchors THIS certified session, the like-for-like closure of #119's caveat under that row's own convention that transient captures freeze a verdict record; certified on aarch64 (the GX10), matching #119's certified scope, with the x86_64 re-verify riding the next Protectli session per the per-arch discipline; the cause byte on kernel receipts is the FORMAT plus the clean-commit stamp — nonzero kernel causes arrive with the paths that produce them (loader migration receipts, refusal emissions), a named follow-on. At fold time, annotate #119's receipt-root caveat *(Closed by #128.)* per LEDGER_STANDARDS §3.

**Provenance:** `prismpath-ebpf/` (`ppt_common.h`, `ppt_select.bpf.c`, `receipts_selector.c` with the cause check, `evidence/receipts_session_2026-08-28.{log,SHA256SUMS,SHA256SUMS.ots}`); run: `clang -target bpf` build, then `sudo ./cert_selector selector_corpus.bin ppt_select.bpf.o` and `sudo ./receipts_selector selector_corpus.bin ppt_select.bpf.o`.
