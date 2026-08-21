# SPEC: Secure Policy Hot Swap

*Formal design spec. Upgrades the live policy swap (eBPF `netupdate`, the FPGA table reload, and a
new software reference host) from "replace the table" to an enforced runtime guarantee: every swap
is **Authorized**, **Envelope bounded**, **Attested**, and **Audited + atomic**. Companion to
`policy_pack.py` / `policy_host.py`, `spec-ledger-opentimestamps.md`, and SPEC.md §4.3/§7 (the
Level M fragment). Crystal Warden Labs, 2026-08-12.*

*This document is published deliberately as **prior art**. The composition it describes: a policy
swap that is cryptographically authorized AND formally proven in envelope AND attested AND audited,
on constrained substrates, with qualified envelope conformance as an enforced runtime gate, is
disclosed here in full so that it remains free for anyone to implement. No patent is sought or
intended; this publication is the defensive record of that choice.*

---

## 1. Goal & current gap

The pitch the repo already makes (qualify the envelope once, swap the policy within it, prove
each swap stays in bounds) is today a claim about process, not a property the runtime enforces.
The existing swap mechanisms load any structurally valid table: the eBPF loader checks magic,
version, and length; the FPGA path watches a file and reloads whatever appears. Nothing verifies
*who authorized* the new policy, *whether it stays inside* the qualified envelope, or *which policy
was actually live* at a given time, and no swap is atomic against a torn read.

This spec closes that gap with four properties, each independently testable, composed from
primitives the repo already ships.

## 2. Threat model & trust boundary

Defend against:

1. **Unauthorized load**: an attacker with file or API access loads a tampered or self made policy.
2. **Rollback / replay**: an old, validly signed but since revoked policy is replayed.
3. **Envelope escape**: a signed policy *outside* the qualified envelope (new fields, larger
   tables, non decidable constructs) is loaded to escape proven behavior.
4. **History forgery**: "which policy ran when" is falsified after the fact, even with
   filesystem access.
5. **Torn state**: a partially applied swap leaves the runtime evaluating a mixed table.

Trusted: the signing **authority** (its private key) and the verification path in the runtime.
Authorization attaches to the **policy artifact** (a signature over its manifest), not to a user
session, consistent with the control plane's posture that session auth is a non goal
(`SECURITY.md`). Out of scope: a compromised authority key (key management is a named follow on),
a fully compromised runtime (attestation detects, it does not prevent), and worker content safety
(the guard onion's job, not the swap's).

## 3. The four properties

### 3.1 Authorized

Every policy ships as a **pack**: the byte identical `.ppt` image plus a detached, signed manifest.
The image itself is never modified: byte identity with the already certified toolchain artifacts
is preserved, and existing loaders keep reading the same file.

`flow.manifest.json` (canonical JSON: `sort_keys=True`, separators `(",", ":")`, UTF-8):

```json
{
  "format": "ppt-pack/1",
  "image_sha256": "<hex sha256 of the .ppt bytes>",
  "fields": {"<field name>": "<kind>"},
  "counts": {"atoms": 0, "nodes": 0, "edges": 0, "prog_words": 0,
              "max_steps": 0, "max_stack": 0},
  "wcet_cycles": 0,
  "version": 1,
  "envelope_id": "<id of the envelope this pack targets>",
  "key_id": "<hex sha256 of the authority public key>",
  "created": "<ISO-8601 UTC>"
}
```

`flow.manifest.sig` is an Ed25519 signature over the canonical manifest bytes. The runtime holds
the authority public key(s) plus a revocation list (a JSON set of `key_id`s) and verifies before
any load. The manifest binds the **field schema** as well as the image hash: a valid signature
over a schema mismatched image is impossible by construction, closing the pin the wrong schema
routing hazard.

`wcet_cycles` is this policy's worst case evaluate bound on the hardware tier: the maximum over
nodes of the sum, across the node's edges, of `2 + max(prog_words, 1)` cycles, plus 2. For
compiler emitted policies (every edge's program is at least one word) this equals `2E + P + 2`,
where E is the node's edge count and P its total program words; the `max(., 1)` term keeps the
bound exact for hand crafted images with zero word edges, which still cost one cycle each
(formula calibrated cycle exact against the RTL; see the hardware repo's WCET record).
The signer computes it from the image bytes and `verify_pack` recomputes it at load time, so the
timing claim travels signed with the policy and a wrong claim fails verification even under a
valid signature. Packs signed before this field exist without it; verification treats the field
as optional and checks it only when present.

`packing` (optional) declares a wire packing profile whose baked artifact rides the pack:
`{"profile": "spiral", "sidecar_sha256": "<hex sha256 of the sidecar bytes>"}`. The sidecar file
sits beside the image as `<name>.ppt.spiral` and carries the layout a small target cannot derive
(see PROTOCOL.md section 2.6); the builder derives it from the signed flow and refuses convention
violating flows at the lint gate. `verify_pack` re hashes the sidecar against the manifest, so a
missing or tampered sidecar fails verification (`spiral:sidecar-missing`,
`spiral:sidecar-hash-mismatch`) even under a valid signature, and an unknown profile name is
rejected. The field is optional and checked only when present.

**Anti rollback:** `version` is a monotonic integer. The runtime persists the active version
(software tier: an fsync'd state file; hardware tiers: eFUSE / secure element counter) and refuses
any pack whose `version` is ≤ the stored value: a revoked but signed policy cannot be replayed.
The software tier's file backed counter is honest best effort: an attacker with filesystem write
access can reset it, which is exactly why the hardware counter is the qualified deployment story.

### 3.2 Envelope bounded

At qualification time the deployer records and signs the **envelope**: the "qualified once"
baseline:

```json
{
  "envelope_id": "<id>",
  "fields": {"<field name>": "<kind>"},
  "caps": {"atoms": 1024, "nodes": 256, "edges": 1024, "prog_words": 4096,
            "max_steps": 25, "max_stack": 16},
  "require_level_m": true,
  "key_id": "<authority key id>"
}
```

Before a verified pack goes active, the runtime checks it against the envelope, **image native**
(no source flow needed at swap time):

- header magic + format version;
- every count in the 28 byte `.ppt` header ≤ the envelope cap (the default caps are the eBPF
  loader's `MAX_*` constants, closing a real gap: nothing bounded these at build time before);
- manifest fields ⊆ envelope fields;
- an **opcode whitelist walk** over the image's atom section, the decidable fragment membership
  recheck. The compiler already guarantees fragment membership at build time (it rejects
  non Level M constructs with stable `SubsetError` reasons); the walk reverifies the shipped
  artifact at load time so the guarantee does not depend on trusting the build host.

Any miss → reject, before anything is staged. Constrained substrates that cannot afford the check
use the **trusted pre loader** pattern (§5).

### 3.3 Attested

The runtime exposes the `sha256` + `version` + `since` of the currently active policy (API call in
software; a register on hardware). Every swap and every periodic attestation appends to the
Merkle rooted audit log (`audit_log.py`), whose roots are OpenTimestamps anchorable to Bitcoin
(`spec-ledger-opentimestamps.md`). "Policy X was live from T1 to T2" becomes a provable statement:
an auditor holding the policy document recomputes its image hash and verifies the ledger chain
against the anchored root.

### 3.4 Audited + atomic

Every swap **attempt** (accepted or rejected) appends
`{ts, actor, from_hash, to_hash, version, key_id, envelope_id, result, reason}` to the audit log.
Rejected attempts are first class events: attack visibility, not just success history.

Atomicity: the new policy is staged and *fully* validated (signature → envelope → version → parse)
into a shadow slot; the switch to active is a single reference flip under a lock. Any failure at
any stage leaves the previous policy active with no partial state, and the last known good pack is
retained for explicit rollback.

## 4. What this composes (nothing new is invented)

| Property | Existing primitive |
|---|---|
| canonical image + metadata | `.ppt` compiler (`ppt_compile.py`, read only consumer) |
| fragment membership | Level M checker (`model_check.flow_level_m`) + compiler `SubsetError` |
| audit trail | `audit_log.py` (Merkle rooted, provable inclusion) |
| temporal anchoring | `ledger_ots.py` (OpenTimestamps → Bitcoin) |
| signature | Ed25519 (the `cryptography` library; optional extra `signing`) |
| the swap itself | eBPF `netupdate` map swap; FPGA table reload; software host (new) |

The signature layer is composed from a vetted library, never hand rolled, and is an **optional
dependency with loud absence**: if verification is unavailable the swap refuses with an actionable
message: it never falls through silently. A demo only unsigned path exists behind an explicit
flag and stamps `unsigned: true` into the audit event.

## 5. Per substrate layering

- **Software kernels (Python reference; the pattern ports to JS/Rust/Go):** all four properties
  in process (`policy_host.py`).
- **eBPF:** the loader's `netupdate` is fronted by a **trusted pre loader** on the host
  (`net_swap.py`): verify pack + envelope first, only then touch maps. Loader side hardening:
  capacity bounds enforced at parse, map update return values checked, and the enforcement mask
  carried forward across swaps. **True double buffered atomicity is now delivered** (evidence #93):
  the table maps hold two banks and a packet reads a single `__u32` bank selector once (aligned
  load, atomic against the loader's aligned store); `netupdate` writes the inactive bank in full,
  then flips the selector in one update, so no packet ever sees a torn table. Reverified and
  recertified on both aarch64 and x86_64 (124/124 unchanged); proven torn free under a concurrent
  swap storm.
- **FPGA:** the pre loader verifies and signs an envelope conformance attestation; the device
  verifies that signature and a version register (eFUSE backed monotonic counter for
  anti rollback). Gated on the hardware retest rule: no FPGA change lands without rerunning the
  conformance suite on the physical fabric.
- **MCU / bare metal:** same pre loader pattern as FPGA; static table in flash, staged bank +
  pointer flip.

## 6. Build phasing

1. Signed pack + verify on load + anti rollback (software). *(this change)*
2. Envelope + pre load conformance gate. *(this change)*
3. Attestation + audit ledger + OTS anchoring. *(this change)*
4. Atomic shadow swap + rollback, failure injection tested. *(this change)*
5. eBPF pre loader + loader hardening. *(this change)*
5b. eBPF double buffered atomic swap + concurrent swap storm proof. *(delivered, #93)*
6. FPGA signed attestation path + version register. *(follow on: hardware retest)*
7. MCU pre loader. *(follow on: hardware availability)*
8. Key management hardening: rotation, revocation distribution, secure element storage.
   *(follow on)*

## 7. Honest caveats

- The software anti rollback counter is file backed: tamper evident via the ledger, not
  tamper proof. The hardware monotonic counter is the qualified answer.
- The eBPF swap is double buffered (#93): the torn read window is closed, proven torn free under a
  concurrent swap storm on both architectures. The atomicity rests on aligned word load/store
  atomicity (x86_64 and aarch64 both provide it).
- Attestation detects a compromised runtime after the fact; it does not prevent one.
- Key compromise is out of scope here and named as its own workstream.
