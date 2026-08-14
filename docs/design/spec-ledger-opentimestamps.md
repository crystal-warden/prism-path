# SPEC: OpenTimestamps Anchoring for the Flow Ledger

*Formal design spec. Upgrades the commit as state Flow Ledger (`ledger.py`, research paper §3.4)
from **accident tamper evident** to **adversarial temporal integrity**: proofs that cannot be
backdated or silently rewritten even by an adversary with filesystem access. Companion to
`ledger.py` / `ledger_runner.py`. Crystal Warden Labs, 2026-07-19.*

---

## 1. Goal & current gap
The ledger already makes each gate green unit a content addressed git proof commit with an
order independent `PrismPath-Output-Hash` trailer. Per §3.4 this is scoped to **accident**: "an adversary with
filesystem access can rewrite the whole chain, so we do not claim adversarial integrity; anchoring the
ref heads with OpenTimestamps is the honest adversarial upgrade (future work)." This spec is that
upgrade.

## 2. What OpenTimestamps (OTS) provides
OTS commits a hash into the Bitcoin blockchain via free, redundant aggregation **calendar servers**
(no node, no account, no fee). A proof attests *"this exact hash existed at or before block time T,"*
verifiable by anyone against Bitcoin. It is **integrity of record + trustless time**, nothing more
(see §6). Stamping is two phase: a **pending** calendar attestation returns immediately; an
**upgrade** promotes it to a full Bitcoin proof after the aggregating tx confirms (~1 to 6 h).

## 3. Design
### 3.1 Batched Merkle anchoring (not per proof)
On an **anchor tick**, build a Merkle tree over every new `PrismPath-Output-Hash` since the last anchor;
stamp the single **root**. Each unit stores its Merkle **inclusion path** to that root. One OTS call
covers thousands of proofs. Roots are the only value that leaves the enclave (high entropy; see §6).
### 3.2 Engine stays pure: anchoring is out of band
OTS is network I/O, so it lives in the **harness**, never the pure engine (same discipline as the
event tier `scheduler.py`). Two timers:
- `cw-ledger-anchor`: build root → `ots stamp` → store `<root>.ots` (pending) + per unit Merkle paths.
- `cw-ledger-upgrade`: periodically `ots upgrade` pending proofs to confirmed Bitcoin proofs.

Both ship as staged user units in `prismpath/deploy/systemd/` (see its README).
Both are strictly off the critical path: any failure degrades to the existing accident evident ledger.
### 3.3 Verification
`prismpath ledger verify --ots <unit>`: recompute the Output-Hash from stored content → verify the Merkle
path to the anchored root → `ots verify` the root against Bitcoin → report *"existed unaltered at/before
block T."* A tamper test (mutate any proof → verification MUST fail) is a release gate.
### 3.4 Storage
`.ots` proofs + Merkle paths are small and git tracked inside the bare ledger repo
(`$XDG_STATE_HOME/prismpath/<flow>.git`), so `SPRINT_FRESH` cannot delete them (they live outside the
project tree, per §3.4).

## 4. Air gapped deployments (DIB / OT / healthcare: the core vertical)
OTS needs internet; our buyers are air gapped. Ship a **tiered attestation**, strongest available:
1. **Anchor at the egress boundary**: the one way telemetry export point the out of band design
   already has. Only a *hash* crosses (non sensitive), which a one way review process can pass.
2. **Batch and forward**: accumulate roots in enclave; carry hashes out through the diode or maintenance
   window; stamp from a connected relay; carry `.ots` proofs back.
3. **Internal RFC-3161 TSA** for fully disconnected sites: a standard trusted timestamp appliance:
   trusts a party (weaker than Bitcoin) but compliance recognized and works offline.
Offer **OTS when connected + RFC-3161 when air gapped** as one policy. The tiering is a sellable design
(and likely the patent defensible core), not a compromise.

## 5. Claim upgrade gate
Only after stamp to upgrade to verify round trips AND the air gap tier ships may the pitch say
"cryptographically provable, non backdateable, third party verifiable evidence timeline." Until then:
**"attested, content addressed audit chain."** Never skip this gate: it is the exact overclaim a
regulator/insurer dismantles.

## 6. HONEST CAVEATS & how we compensate  *(read this section twice)*

### C1: It proves integrity of RECORD, not integrity of SOURCE.
OTS proves *when* a hash existed and *that it hasn't changed since**, **not that the recorded content is
true.** An attacker who compromises the pipeline *before* a proof is written gets a valid timestamp on
bad data. Timestamping is not a truth oracle.
**Compensate:**
- **Anchor at ingestion, not just at verdict.** Hash raw evidence at the sensor/export boundary and
  anchor it too, so the provable chain of custody starts at *ingestion*; the only unprovable window is
  sensor to first anchor latency, which §3.1's fast tick minimizes.
- **Bind the logic, not just the output.** Anchor the flow definition hash (`POLICY_HASH`) + gate
  identity, so *what code/logic produced the verdict* is provable: you can't later claim a different
  policy ran.
- **Multi sensor corroboration.** Independent sensors (Wazuh, Zeek, ET-BERT) each anchor; a single
  compromised source cannot rewrite the cross sensor record without detectable divergence.
- **Harden the ingestion boundary** (FIM on the flow dir, signed agents, append only/WORM staging). OTS
  *composes with* source security; it never replaces it.
- **Frame it honestly:** sell "tamper evident chain of custody of what the system recorded and when,"
  NOT "proof the verdict was correct." That framing is both true and sufficient for audit/forensics.

### C2: Strong (Bitcoin) proof lags the event by hours.
Between stamp and Bitcoin confirmation (~1 to 6 h) you hold only the pending calendar attestation.
**Compensate:**
- **The pending proof is not "unprotected"**: it is immediately, cryptographically binding on the
  **multiple independent calendar operators** (federation strength). It's "trusted federation until
  Bitcoin," not "nothing."
- **Dual anchor for instant strength:** an RFC-3161 TSA gives an *immediate* trusted timestamp
  alongside the *eventual* trustless OTS proof; no window lacks at least a strong trusted anchor.
- **The lag rarely matters:** audit, forensics, insurance, and compliance operate on hours to days old
  records; a few hours of anchoring latency is irrelevant to those use cases.

### C3: Verification needs the original data (not just the proof).
A proof over a hash is useless without the content to rehash.
**Compensate:** the ledger is already content addressed and retains the content trees; store `.ots` +
Merkle paths beside them. Verification is self contained from the ledger repo.

### C4: Hash leak privacy (a subtle one).
Only hashes leave the enclave (good), but a hash of *low entropy, guessable* content can be confirmed
by brute force by whoever sees the hash.
**Compensate:** anchor only the **high entropy Merkle roots** (already random looking), and/or
**HMAC/salt** unit hashes with a secret retained in enclave. Never anchor a bare hash of a short,
guessable record.

### C5: Long term durability assumes Bitcoin persists; calendars can be transiently down.
**Compensate:** use OTS's multiple default calendars (redundancy) + a stamp retry queue (stamps are
idempotent/replayable); keep the RFC-3161 anchor as an independent second root of trust; optionally
**restamp** long lived proofs periodically so trust doesn't rest on a single chain of custody.

## 7. Steps & effort
1. Merkle root builder over new `Output-Hash` set + per unit inclusion paths.  *(~1 day)*
2. OTS stamp/upgrade integration (`opentimestamps-client`) + the two out of band timers.  *(~2 days)*
3. `prismpath ledger verify --ots` + tamper test release gate.  *(~1 to 2 days)*
4. **Air gap tier** (egress stamp / batch forward / RFC-3161 fallback): the hard, high value piece.  *(~1 to 2 wk)*
5. Ingestion boundary anchoring + `POLICY_HASH` binding (the C1 compensations).  *(~2 to 3 days)*
Connected v1 (1 to 3) is ~a week; the defensible IP is item 4.

## 8. What NOT to claim (ever)
- Not "proof the AI's verdict was correct" (C1).
- Not "instant tamper proof" before the confirmation window closes (C2): say pending vs confirmed.
- Not "cryptographically provable" until §5's gate passes.

---
## CONNECTED V1: DELIVERED + VALIDATED (2026-07-21, #36)
`ledger_ots.py` implements the connected anchoring engine, validated end to end (`ots` CLI v0.7.2 + opentimestamps 0.4.5):
- **`from_ledger()`** enumerates `PrismPath-Output-Hash` trailers from a live Flow Ledger via git-log; tested: read 3 hashes from a real bare repo mini ledger.
- **Merkle batching**: every leaf reconstructs the root (verified); one `ots stamp` covers the whole batch.
- **OTS stamp**: real submission to 4 Bitcoin calendar servers (opentimestamps / eternitywall / catallaxy), `stamped=true`; `upgrade()` promotes pending→confirmed (async ~1 to 6h).
- **Verify**: output hash → Merkle path → root → `ots verify` (honest "Pending confirmation in Bitcoin blockchain" in session, upgrades later).
- **Tamper evident**: corrupted Merkle sibling → False; absent hash → rejected.

**REMAINING (task #53, the ~1 to 2wk defensible IP):** out of band `cw-ledger-anchor`/`cw-ledger-upgrade` timers (deploy when a ledger produces data); `prismpath ledger verify --ots` CLI; the **AIR GAP TIER** (egress stamp / batch forward / RFC-3161 fallback); the C1 compensations (ingestion boundary + POLICY_HASH binding). The connected v1 upgrades the ledger's attestation from *accident*-tamper evident to *adversarial* temporal integrity for internet connected deployments; air gap tier extends it to DIB/OT/healthcare.


## AIR GAP TIER: DELIVERED + VALIDATED (2026-07-21, #53)
`ledger_airgap.py` implements the disconnected deployment tiers from §4 and the §6 compensations;
validated end to end with **zero internet** (the exact air gapped condition):
- **T1 batch and forward** (§4.2): `export_stamp_request` packages ONLY high entropy roots + a
  provenance manifest into a tiny tar the one way boundary can pass; `relay_stamp` `ots stamp`s on a
  connected relay; `import_proofs` places `.ots` beside the roots. Full round trip proven for real
  (export → real calendar stamp → import; proof file lands).
- **T2 RFC-3161 offline TSA** (§4.3): `rfc3161_query`/`rfc3161_verify` + a throwaway local test TSA
  (`make_test_tsa`) prove query → sign → **`Verification: OK`** → tampered root **rejected**, entirely
  offline. This is the fully disconnected fallback (internal appliance) and the patent defensible core.
- **C1 compensations** (§6): `provenance_manifest` binds `POLICY_HASH` + gate identity + ingestion
  hashes to the anchored root, so chain of custody starts at ingestion and *what logic ran* is provable.
- **C4**: `salt_leaf` HMACs low entropy unit hashes with an in enclave secret before anchoring.
- **CLI**: `prismpath ledger {anchor,upgrade,verify --ots,export-request,relay-stamp,import-proofs,rfc3161}`.
- **Timers**: `deploy/systemd/cw-ledger-{anchor,upgrade}.{service,timer}` + `cw-ledger-run.sh` wrapper,
  STAGED (not enabled; no live ledger yet; deploy when a ledger produces data).

**Claim gate status (§5):** the air gap tier has now shipped AND connected v1 round trips, so the
stronger claim language is unlocked for connected deployments; air gapped sites use "RFC-3161
trusted timestamp (immediate) + OTS when a window opens (trustless)"; state the tier actually in use,
never imply Bitcoin strength on a site that only has the internal TSA.
