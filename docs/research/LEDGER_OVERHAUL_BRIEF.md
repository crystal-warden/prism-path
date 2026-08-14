# WORK ORDER — Evidence-Ledger Overhaul  *(delete this file before merge)*

You are a **docs-only** session. Your job: bring `docs/research/supporting-evidence.md` (and spot-check
the two papers) up to `docs/research/LEDGER_STANDARDS.md`. **Read `LEDGER_STANDARDS.md` first.**

## Environment (already set up for you)

- You are in the worktree **`/home/cwadmin/cwprojects/prismpath-docs`** on branch **`docs/ledger-overhaul`**.
- The dev session works on `main` in `/home/cwadmin/cwprojects/prismpath`. **Do not touch code,
  conformance fixtures, or `main`.** You edit only `docs/research/` (and `docs/design/` if needed).
- New evidence rows the dev session produces land in `docs/research/supporting-evidence.pending.md`
  (#97+). Leave that file alone until the fold-in step.

## The two defects to fix

**A. Dates → month-granularity, whole doc.** Every `### #N —` prose row header (and any body date)
must be `Month YYYY`, not `YYYY-MM-DD`. The precise date already lives in the OTS anchor, so this loses
nothing (LEDGER_STANDARDS §2). The lint lists all 28 (`#65`–`#92`).

**B. Honest-scope reconciliation on the review caveats.** Several older caveats read as un-done work
that was actually finished later. Classify each per LEDGER_STANDARDS §3 — **annotate, never rewrite
history.** Specific guidance (verify against the rows before applying):

| Row | Caveat | Disposition |
|---|---|---|
| #84 | "protobuf/OTLP baseline not yet built" | **Closed by #95** — annotate. |
| #88 | "built but not live-recertified", "still element-wise (not double-buffered)", "staged, not committed" | loader hardenings **Closed by #90**; the element-wise swap **Closed by #93** — annotate both. |
| #89 | "eBPF re-cert pending a privileged run" | **Closed by #90** — annotate. |
| #90 | "RTL re-sweep pending a hardware retest" **and** "swap remains element-wise" | **Split:** the RTL re-sweep is *genuinely still open* (RTL stands at 114) — leave, confirm. The element-wise line is **Closed by #93** — annotate. |
| #93 | "still element-wise / not double-buffered" | **False positive** — this row *quotes* the caveat it closes. No open item; rephrase only if it reads as open. |
| #95 | "not yet built" | **False positive** — #95 *is* the row that closes #84's follow-on. Reference, not an open caveat. |
| #78, #85 | "not yet earned" | **Verify** — read each; classify closed / rephrase / confirm-open. |

Also fix the **11 schema gaps** the lint flags (rows missing a labelled `Provenance:` — #65–#71, #76–#78 — or `Result:` — #86): add the missing labelled section from the row's existing content.

## Additional scope (added 2026-08-13 by the dev session)

The dev session's work landed on `main` (2026-08-13; commits `64a76e7` hardware, `98f2807` Facet
protocol; OTS-anchored via `prismpath/evidence/facet_mcu_2026-08-13.SHA256SUMS`). These items are now
unblocked.

1. **Adopt the final Facet / Figueroa-quantization vocabulary across `docs/research/`.** The dev session
   added `PROTOCOL.md` (main) as the normative source of truth: **Figueroa quantization** (the primitive),
   **the Facet protocol** (`Facet/1`), with Zeckendorf cited as the coding component. Papers cite
   `PROTOCOL.md` rather than re-defining the terms.
2. **Finalize the new paper** `docs/research/paper-facet-figueroa-quantization.md` (dev-session draft):
   verify every cited number against its artifact, tighten, and cross-link from the engineering paper.
3. **Substrate + demonstrator update to the engineering paper** — *only after the hardware work is
   committed* (rows #97–#100 in `supporting-evidence.pending.md`): four MCU ISAs now decide identically
   (AVR / ARM Cortex-M33 / RISC-V Hazard3 / Xtensa) on top of the language kernels, eBPF, and the FPGA
   fabric — this strengthens the portability claim and belongs in the portability/substrate section. The
   ToF (physical input → on-device decision) and the ESP-NOW coordinated fleet swap are *demonstrators*:
   a sentence or a figure, not a section.
4. **Style sweep, house rule (from the dev session, 2026-08-13): no em/en-dashes AND minimize hyphens.**
   Sweep the whole committed doc corpus (the ledger rows `#1-#100`, `CHANGELOG.md`, the hardware READMEs,
   and any other `docs/`): remove every em-dash and en-dash; open or reword hyphenated compound modifiers.
   **Keep** a hyphen only where it is part of a proper name (`ChaCha20-Poly1305`, `ESP-NOW`, `SHA-256`,
   `FNV-1a`), a code identifier, or math (subtraction). `PROTOCOL.md` and
   `paper-facet-figueroa-quantization.md` are the finished style exemplars; match them. (The dev session
   already applied this to those two files and the mesh README; the rest of the corpus is yours.)
5. **Fix the 1.49 vs 1.5 rounding.** `adapters/fusion/bench/otlp_results.md` rounds the OTLP-over-JSON
   ratio to "1.5x"; the true value (and the Facet paper) is **1.49x**. Correct the results doc.
   (The fold-in of rows #97-#100 from `supporting-evidence.pending.md` is already covered under
   Merge-back below; de-dash and de-hyphenate them as you fold them in.)

## Versioning deliverables (LEDGER_STANDARDS §5)

1. Add a version header near the top: `**Ledger v2 · rows #1–#96 · <Month YYYY>**`.
2. Add a short **Revision history** footer: v1 (original consolidation) and v2 (this overhaul), each
   naming its OTS anchor file.
3. Re-anchor: write a `prismpath/evidence/ledger_v2_<YYYY-MM-DD>.SHA256SUMS` over the finalized
   `supporting-evidence.md`, `ots stamp` it, and cite it in the footer. *(This is the one place an
   exact date is allowed — the anchor filename.)*

## Definition of done

- `python tools/ledger_lint.py docs/research/supporting-evidence.md --strict` exits **0** (hard = 0).
- All 8 review caveats classified (annotated / rephrased / confirmed-open) — re-run without `--strict`
  and confirm every remaining CAVEAT line is a deliberate, confirmed-open item.
- `python tools/docs_health.py` clean.
- Version header + revision footer + OTS anchor added.
- Papers spot-checked: no `YYYY-MM-DD` reintroduced; cross-references to reconciled rows still read true.

## Merge-back

- Fold any rows from `supporting-evidence.pending.md` into the ledger (correct formatting, next
  numbers), then clear that file.
- Delete this brief. Merge `docs/ledger-overhaul` → `main` as one reviewed commit.
- Once merged and green, wire `ledger_lint --strict` into CI as a blocking gate (LEDGER_STANDARDS §7).
