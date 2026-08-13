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
