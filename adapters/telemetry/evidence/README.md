# Content anchor — telemetry adapter

An OpenTimestamps content anchor over the telemetry adapter (Phase A/B + Phase C C1/C3) and its off-repo
design of record. It stamps a **priority date** on the design and implementation: git-independent, so it
survives a squash-merge and any later rebase. (A separate *commit* anchor on the merged `main` commit can
be added later — the two stack.)

## Files
- `SHA256SUMS` — sha256 of every tracked adapter artifact (repo-relative paths) plus one line for the
  off-repo determination doc (`prismpath-idea-fibonacci-telemetry.md`), whose **content hash** is recorded
  here while the file itself stays off-repo by policy.
- `SHA256SUMS.ots` — the OpenTimestamps proof for `SHA256SUMS`. Currently **pending** (submitted to the
  calendar servers); upgrade it to a Bitcoin block attestation once confirmed.

## Verify
```
# repo artifacts (from the repo root) — the '#' comment lines and the off-repo doc line are skipped/absent
sha256sum -c adapters/telemetry/evidence/SHA256SUMS

# the off-repo doc: hash your local copy and compare to its line in SHA256SUMS
sha256sum ~/Desktop/prismpath-idea-fibonacci-telemetry.md

# the timestamp itself
ots verify adapters/telemetry/evidence/SHA256SUMS.ots
```
`sha256sum -c` reports the single off-repo doc line as "No such file" from the repo root — expected: that
file is intentionally not in the repo; verify it manually against your local copy (line above).

## Upgrade (after the Bitcoin attestation confirms, ~a few hours)
```
ots upgrade adapters/telemetry/evidence/SHA256SUMS.ots
```
This replaces the pending calendar attestations with a Bitcoin block attestation. Commit the upgraded
`.ots` when done.
