# Evidence-Ledger Standards

*The rules `supporting-evidence.md` (and the research papers that cite it) are held to. Enforced by
`tools/ledger_lint.py`. Crystal Warden Labs.*

The evidence ledger is a defensive-publication record and the merge source for the papers. It must
survive a hostile read and read cleanly top-to-bottom. These standards make "rigorous" concrete.

## 1. Row schema (`### #N —` prose rows)

Every numbered prose row is:

```
### #N — <one-line title> (<Month YYYY>)

**Claim:** <the falsifiable assertion>
**Method:** <how it was measured / proven, with the commands or files>
**Result:** <the measured outcome> ... **Honest scope:** <what is NOT claimed / still open>
**Provenance:** <the files, scripts, or hosts that reproduce it>
```

- **Claim / Method / Result / Provenance are mandatory.** `Honest scope` is mandatory wherever the
  result has a real limitation (almost always).
- Numbers are first-party and reproducible from the cited provenance, or the row states plainly that
  they are not (e.g. off-repo lab artifacts).

## 2. Dates — month-granularity in prose; the anchor is the timestamp

- **All prose dates (row headers and body) use month granularity: `Month YYYY`** (e.g. `August 2026`).
  No `YYYY-MM-DD` in the ledger prose.
- **Rationale:** the precise, tamper-evident date already lives in the OpenTimestamps anchor
  (`prismpath*/evidence/*.SHA256SUMS.ots`, verifiable with `ots info`). The anchor is the
  cryptographic proof of priority date; the prose does not need to — and should not — restate it to
  the day. Generalizing the prose loses nothing and reads as a research record, not a git log.
- The **only** place an exact date belongs is inside a `.SHA256SUMS` filename or an `ots info` output.

## 3. Honest-scope reconciliation — classify, never rewrite

The ledger is **append-only**: a row that said "X is pending" was a true snapshot when written. Do
**not** delete or falsify a past caveat. When later work changes its status, reconcile by
annotation:

- **Since-closed** → append `*(Closed by #N.)*` (or `*(Closed in #N.)*`) to the caveat, naming the
  row that closed it. The original snapshot stays; the reader learns it was resolved.
- **Never-a-gap / misread** → rephrase so it no longer reads as un-done work or a missed
  opportunity, while keeping the factual content. (A point that was addressed in the same row, or was
  a deliberate non-goal, should not read as an open gap.)
- **Still-open** → leave as is, after confirming it is genuinely still open.

A caveat containing `pending`, `not yet`, `still <X>`, `built but not`, `follow-on`, or `not yet
earned` that is **not** annotated `Closed by #N` is a lint review item — resolve each explicitly.

## 4. Numbering

- `### #N` rows are **contiguous and unique**. No gaps, no duplicates.
- New rows are appended at the tail with the next number. During a ledger overhaul, new rows go to
  the **staging file** (see §6), not the main ledger.

## 5. Versioning

- The ledger carries a version header: `**Ledger vN · rows #1–#M · <Month YYYY>**`, bumped on each
  substantive overhaul.
- A short **Revision history** footer records each version with its OTS anchor filename — the anchor
  is the version's authoritative timestamp.
- Each finalized revision is OTS-anchored (a `SHA256SUMS` over the ledger + any changed papers,
  `ots stamp`'d, upgraded to a Bitcoin attestation on the usual cadence).

## 6. Parallel-work boundary (docs session vs dev session)

To let a dedicated docs session overhaul the ledger while development continues:

- The **docs session** owns `docs/research/` prose. It works on a branch/worktree and does not touch
  code or conformance fixtures.
- The **dev session** does not edit `supporting-evidence.md` prose during an overhaul. New evidence
  rows it produces are appended to **`docs/research/supporting-evidence.pending.md`** (the staging
  file), starting at the next free number.
- On merge, the docs session folds the staged rows into the ledger with correct formatting and
  clears the staging file. Because the two sessions never edit the same region, conflicts are ~zero.

## 7. The gate

`python tools/ledger_lint.py docs/research/supporting-evidence.md` checks: month-granularity dates,
contiguous/unique numbering, the mandatory row sections, and the unreconciled-caveat review list. It
runs in report mode (exit 0) by default and `--strict` (non-zero on hard violations) for a
definition-of-done target. It is wired into CI as a blocking gate **only once the current overhaul
brings it to zero** — until then it is the worklist, not a red build.
