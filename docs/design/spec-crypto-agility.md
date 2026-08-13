# SPEC — Provable Crypto-Agility Control Plane

*Status: phases 1–5 implemented (software tier) and gated — see evidence #94. Phase 6 (image-native
eBPF/FPGA/MCU tiers) and the Rust/JS mirrors of the proofs are named follow-ons.*

*Formal design spec. Instantiates the four secure-hot-swap properties (Authorized, Envelope-bounded,
Attested, Audited + atomic) for a new artifact class: the **crypto-suite-selection policy** — the
decision of *which* approved cryptographic suite a channel, flow, or fleet node is authorized to use,
and how that decision is swapped forward without a flag day. Companion to `spec-secure-hotswap.md`,
`policy_pack.py` / `policy_host.py`, `spec-ledger-opentimestamps.md`, and SPEC.md §4.3/§7 (the Level M
fragment). Crystal Warden Labs, August 2026.*

*Published deliberately as **prior art**. The composition it describes — crypto-agility governed by a
decidable control plane, where the set of approved suites is an enforced envelope, the algorithm (not
just the key) has monotone anti-rollback, and "which suite was live when" is an attested statement, on
substrates down to an 8-bit MCU — is disclosed here in full so it remains free for anyone to
implement. No patent is sought or intended.*

---

## 0. The boundary, stated first

**PrismPath is a control plane, not a cipher. It never encrypts a byte.** It governs *which* crypto
policy is authorized to be live, proves properties about that policy, and attests what actually ran —
nothing more. Every cryptographic operation (KEM, signature, AEAD) is delegated to a vetted provider
(`cryptography` / libsodium / a platform HSM), pinned by a signed registry, and invoked through an
**optional dependency with loud absence** — if the provider is missing the runtime refuses, it never
falls through to a weaker path. Saying otherwise would be exactly the overclaim this repo keeps its
failures in the ledger to avoid. Read every "the runtime selects suite S" below as "the runtime
authorizes the vetted provider to use suite S," never as "the runtime implements S."

## 1. Goal & the actual gap

Crypto-agility as a raw capability — *change the algorithm on the fly* — is largely solved, or is
being finished right now under the post-quantum migration. What is **not** solved is *governing* the
swap on the substrates and at the assurance level that matter:

- a swap to a **weaker or deprecated suite** (a downgrade) that is a *rejected, audited* event rather
  than a silent success — enforced at load time, without trusting the box performing the swap;
- a **tamper-evident record** of which suite was live on which node from T1 to T2, that an auditor can
  verify against an anchored root;
- the algorithm's **monotone forward migration** — a proof that no reachable path falls back to a
  classical-only suite once a node is past a migration phase (anti-rollback of the *algorithm*, not
  just the key material);
- all of it **on constrained and fleet substrates** — an MCU or FPGA that cannot run a negotiation
  stack and whose field configuration cannot be trusted.

This spec closes that gap by treating the suite-selection decision as a first-class PrismPath policy
artifact and applying the machinery the repo already ships.

## 2. What already exists (honest prior-art ledger)

| Capability | State of the art | What it does *not* give you |
|---|---|---|
| Suite negotiation | TLS 1.3, IKEv2 pick a suite at handshake | agility only at connection birth; no fleet-wide invariant, no proof |
| Key rotation | KMS / HSM / Vault, Signal double-ratchet | rotates *key material*, not the *algorithm*; algorithm stays fixed |
| Agile crypto APIs | PQC-driven (ML-KEM/ML-DSA), TLS hybrid X25519+ML-KEM | the *ability* to swap; not an enforced envelope, attestation, or proof |
| Config-push swap | ship a new cipher config to a fleet | inherits the deploy pipeline's trust; no in-envelope proof; unknown live state |

The sliver left — *provable, envelope-bounded, attested* agility with algorithm-level anti-rollback,
on substrates where no negotiation stack can run — is what §3–§6 specify. Nothing here re-invents a
primitive; the contribution is the **decidable governance layer** over selection.

## 3. The model — a crypto-suite-selection policy is a Level M table

A crypto-agility policy is an ordinary PrismPath match-action flow in the decidable Level M fragment.
Its **fields** are the routing context, its **action** is a symbolic approved-suite identifier:

- **Context fields** (examples; deployment-defined): `peer_class` (e.g. internal/partner/public),
  `data_class` (e.g. cui/secret/public), `channel_role` (control/bulk), `migration_phase` (a monotone
  integer the fleet advances through), `hw_floor` (the peer's minimum capability).
- **Action**: `suite_id` — a symbolic name (e.g. `cnsa2-hybrid-1`, `legacy-tls13-aesgcm`), **never** a
  concrete algorithm. The symbol resolves through the signed **suite registry** (§7).

Because the policy is Level M — finite fields, bounded predicates, no unbounded computation — every
property in §5 is *decidable*: it is proven over the policy graph, not sampled by testing. This is the
capability nobody else in the prior-art ledger has, and it is the whole reason to model selection as a
PrismPath table rather than a config file.

Example (illustrative flow, compiles to the same `.ppt` image class the other substrates certify):

```
when data_class == "cui" and migration_phase >= 2   -> suite "cnsa2-hybrid-1"
when data_class == "cui"                             -> suite "cnsa2-hybrid-1"   # never weaker for CUI
when peer_class == "public" and hw_floor >= 1        -> suite "tls13-hybrid-x25519mlkem"
when peer_class == "public"                          -> suite "tls13-aesgcm"
otherwise                                            -> deny                      # explicit, audited
```

## 4. The four properties, instantiated for crypto

The properties, mechanisms, and trust boundary are exactly `spec-secure-hotswap.md` §3, specialized:

### 4.1 Authorized
The suite-selection policy ships as a signed **pack** (`policy_pack.py`, unchanged): the byte-identical
`.ppt` image plus a detached Ed25519-signed manifest binding the image hash *and* the field schema.
The runtime verifies against the authority key set and revocation list before any load. Authorization
attaches to the policy artifact, not a session (consistent with `SECURITY.md`).

### 4.2 Envelope-bounded — *the anti-downgrade property*
The qualification envelope for a crypto-agility policy carries one extra bound beyond the standard caps:
an **approved suite set**.

```json
{
  "envelope_id": "cnsa2-2026",
  "fields": {"peer_class": "str", "data_class": "str", "migration_phase": "int", "hw_floor": "int"},
  "caps": { "...standard .ppt caps..." : 0 },
  "require_level_m": true,
  "approved_suites": ["cnsa2-hybrid-1", "tls13-hybrid-x25519mlkem", "tls13-aesgcm"],
  "min_suite_by_class": {"cui": "cnsa2-hybrid-1"},
  "registry_hash": "<sha256 of the signed suite registry>",
  "key_id": "<authority key id>"
}
```

Before a verified pack goes active, the pre-load gate (`policy_host.py` envelope check, extended)
verifies **image-native**, no source flow required at swap time:
- every action `suite_id` reachable in the image ∈ `approved_suites` (the opcode/action-whitelist walk
  already re-checks fragment membership; here it also re-checks the action alphabet);
- the policy's `registry_hash` matches the envelope's — a pack cannot smuggle a re-pointed suite table;
- (optional, class-strength) no context in `min_suite_by_class` can route to a suite ranked below its
  floor — a static check against a signed suite-strength partial order.

Any miss → **reject before staging**, logged as an attempted downgrade. This is the guarantee negotiation
stacks do not give: not "resist downgrade within one handshake," but "this fleet may **never** activate
a suite outside the approved set," enforced at load, without trusting the box.

### 4.3 Attested
The runtime exposes the `sha256` + `version` + `since` + active `envelope_id` of the live policy (an API
call in software; a register on hardware). Every swap and periodic attestation appends to the
Merkle-rooted audit log (`audit_log.py`), OTS-anchorable to Bitcoin (`spec-ledger-opentimestamps.md`).
"Node N ran a policy selecting `cnsa2-hybrid-1` for CUI traffic from T1 to T2" becomes a *provable*
statement: an auditor holding the policy document recomputes its image hash and verifies the ledger
chain against the anchored root.

### 4.4 Audited + atomic
Every swap **attempt** — accepted or rejected — appends
`{ts, actor, from_hash, to_hash, version, key_id, envelope_id, from_suite_set, to_suite_set, result,
reason}`. **Attempted downgrades are first-class events** — attack visibility, not just success history.
The active flip is a single reference flip under lock (software), or the double-buffered `__u32` bank
selector already proven torn-free (eBPF, evidence #93); any failure leaves the prior policy active with
no partial state, last-known-good retained for rollback.

## 5. The proof obligations — what only a decidable control plane can offer

The differentiator. Each is a machine-checked property over the policy graph, composing primitives the
repo already ships (`model_check.check_reach`, `capability_report`, `flow_level_m`) — **not** a test.

| # | Property | Composed from | The claim it earns |
|---|---|---|---|
| P1 | **Envelope closure** — no reachable state selects a suite ∉ approved set | `check_reach` over the action alphabet | "this policy can never activate an unapproved suite" |
| P2 | **Totality** — every context in the field domain routes to a defined suite or an explicit `deny` | `capability_report` | "no context silently falls to a default cipher" |
| P3 | **Class floor** — no reachable path routes a `data_class` below its `min_suite` rank | `check_reach` + signed suite-strength order | "CUI is never carried under a below-floor suite" |
| P4 | **Monotone migration** — once `migration_phase ≥ k`, no reachable path selects a classical-only suite | `check_reach` on the phase-guarded subgraph | anti-rollback of the *algorithm*, not just the key |
| P5 | **Decidability** — the policy is Level M | `flow_level_m` | the four above are decidable, not sampled |

P4 is the sharp one: it is the algorithm-level analogue of the anti-rollback counter in
`spec-secure-hotswap.md` §3.1, but proven *statically* over the policy rather than enforced only by a
runtime version floor. The two compose — P4 proves the policy *cannot* express a downgrade past phase
k; the version counter prevents replaying an *older* signed policy that could.

## 6. Per-substrate layering

Mirrors `spec-secure-hotswap.md` §5; the selection action is small (a suite tag), so it reaches the
constrained tiers.

- **Software kernels** (Python reference; ports to JS/Rust/Go): all four properties + all five proofs
  in-process. The provider binding calls the vetted library.
- **eBPF / XDP**: the policy selects a `suite_id` tag per flow; the data path hands the tag to the
  kernel crypto (or to a userspace AEAD for the demonstrator). Double-buffered swap (evidence #93) gives
  atomic suite-policy flips torn-free.
- **FPGA**: pre-loader verifies + signs an envelope-conformance attestation (including `approved_suites`
  and `registry_hash`); the device verifies the signature and a version register. Gated on the
  hardware-retest rule — no FPGA change lands without re-certifying on the physical fabric.
- **MCU / bare-metal** — *the differentiated tier*. The device holds a static suite-selection table in
  flash and a staged bank + pointer flip; a trusted host pre-loader verifies the signed crypto-policy
  envelope and ships the device a bounded attestation. Result: **crypto-agility governance that can
  *prove* it only ever authorized approved suites, on an 8-bit part** — a capability the prior-art ledger
  cannot offer because no negotiation stack runs there.

## 7. The suite registry — where symbol meets primitive (and where crypto stays delegated)

The one genuinely new object. A **signed registry** maps each symbolic `suite_id` to a concrete,
vetted implementation; the control plane governs *selection over symbols*, the registry pins
*implementations*, the provider performs *operations*.

```json
{
  "format": "ppt-suite-registry/1",
  "suites": {
    "cnsa2-hybrid-1":               {"kem": "x25519+ml-kem-1024", "sig": "ml-dsa-87", "aead": "aes-256-gcm", "provider": "cryptography>=44", "strength_rank": 3},
    "tls13-hybrid-x25519mlkem":     {"kem": "x25519+ml-kem-768",  "sig": "ed25519",   "aead": "chacha20poly1305", "provider": "cryptography", "strength_rank": 2},
    "tls13-aesgcm":                 {"kem": "x25519",             "sig": "ed25519",   "aead": "aes-256-gcm",  "provider": "cryptography", "strength_rank": 1}
  },
  "key_id": "<authority key id>"
}
```

- `registry_hash` is bound into both the envelope and the pack manifest, so a swap cannot silently
  re-point a symbol at a weaker primitive.
- `strength_rank` is the signed partial order P3/P4 check against. It is a *declared* ordering, honest
  about being a policy input, not a cryptographic proof of relative strength.
- `provider` is resolved with **loud absence**: if the named provider (or a required algorithm within
  it, e.g. ML-KEM before it lands in the platform lib) is unavailable, the runtime refuses to activate
  a policy that can reach that suite, stamps the reason into the audit log, and never substitutes a
  weaker suite. Today's demonstrator resolves X25519 + ChaCha20-Poly1305/AES-GCM through the
  `cryptography` library (the same one `wire.py`'s `measure_crypto_cost` already exercises); ML-KEM/ML-DSA
  bind the moment a vetted provider is present — measured then, never claimed before.

## 8. Threat model & trust boundary

Defends against (specializing `spec-secure-hotswap.md` §2):

1. **Algorithm downgrade / rollback** — a signed-but-weaker policy, or a re-pointed registry symbol,
   activated to escape approved strength. → §4.2 envelope + §5 P3/P4 + registry_hash binding.
2. **Envelope escape** — a policy selecting an unapproved suite. → §4.2 action-whitelist walk + P1.
3. **Silent default** — a context with no matching rule falling to an implicit cipher. → P2 totality.
4. **History forgery** — "which suite ran when" falsified. → §4.3 Merkle + OTS.
5. **Torn state** — a partially applied swap mixing suites. → §4.4 atomic flip / double-buffer.
6. **Unauthorized load** — a tampered or self-made crypto policy. → §4.1 signature + revocation.

**Explicitly out of scope** (and named as such): breaking the primitives themselves; the strength of a
suite the deployer *chooses to put in the envelope* (garbage-in — the control plane enforces the
envelope, it does not vet the cryptography inside it); side-channels in the provider; key management and
key compromise (a compromised authority key defeats §4.1 — its own workstream); a fully compromised
runtime (attestation detects, it does not prevent).

## 9. What this composes (nothing new invented but the registry)

| Property | Existing primitive |
|---|---|
| signed pack + verify-on-load + anti-rollback | `policy_pack.py` / `policy_host.py` (unchanged) |
| envelope + pre-load conformance gate | the §4.2 gate, extended with `approved_suites` / `registry_hash` |
| fragment membership + proofs P1–P5 | `model_check.{flow_level_m, check_reach, capability_report}` |
| audit trail + temporal anchoring | `audit_log.py` + `ledger_ots.py` |
| signature | Ed25519 via `cryptography` (optional extra, loud absence) |
| the crypto operations | delegated to the vetted provider named in the registry |
| **the suite registry + strength order + provider binding** | **new (§7) — the only new object** |

## 10. Build phasing (small, commit-ready, in the repo's discipline)

1. **Suite registry + signing** — `crypto_registry.py`: canonical-JSON registry, Ed25519 sign/verify,
   `registry_hash`, declared strength order + PQC marker; tamper tests. **(done, #94)**
2. **Envelope + proofs gate** — for the software tier the Envelope-bounded property *is* the proofs
   (`crypto_agility.py`): `approved_suites` / `min_suite_by_class` / `registry_hash` drive P1–P5;
   deliberate-fail cases keep them falsifiable. **(done, #94)**
3. **The proofs + conformance** — P1–P5 in `crypto_agility.py` composing `model_check`; frozen
   `portable/conformance/crypto_agility.json` generated by the Python reference. Rust/JS mirrors for
   cross-runtime byte parity: **named follow-on**. **(done, #94 — Python reference + fixture)**
4. **Provider binding + governor** — `crypto_host.py` resolves suites through `cryptography` with loud
   absence (refuses, never downgrades), swaps a policy, enforces the version floor + registry binding,
   emits the Merkle audit trail, and reports *measured* per-suite classical cost. **(done, #94)**
5. **Fleet-migration replay** — the monotone-migration property characterized as a policy-gate ×
   envelope-floor matrix (`portable/conformance/crypto_migration.json`: P4 holds ⇔ floor ≥ gate);
   version-rollback refusal + audit demonstrated in `crypto_host`. **(done, #94)**
6. **eBPF / FPGA / MCU tiers** — image-native suite-alphabet walk; suite-tag selection on the
   double-buffered path; MCU pre-loader attestation. *(follow-on: hardware-retest rule)*
7. **Evidence + CHANGELOG + gates + defensive-publication cross-link.** **(done, #94)**

## 11. Honest caveats

- **Control plane, not cipher** (restating §0 because it is the load-bearing honesty): this governs
  *selection*, *proof*, and *attestation*. It does not encrypt, does not replace TLS, and cannot make a
  weak suite strong — it can only prove a weak suite is *outside the approved envelope* if the deployer
  put a stronger floor there.
- **`strength_rank` is a declared policy input**, not a theorem about relative cryptographic strength.
  The proofs are sound *with respect to that declared order*; a deployer who mis-ranks suites gets a
  provably-enforced wrong answer.
- **Provider timings are measured, not guaranteed** — reported per host (as `wire.py` already does),
  meaningless on a noisy shared runner, honest on a real device.
- **The software version counter is file-backed** (tamper-evident via the ledger, not tamper-proof); the
  hardware monotonic counter is the qualified answer, same as the parent spec.
- **Attestation detects a compromised runtime after the fact; it does not prevent one.**
- **Post-quantum suites bind when a vetted provider is present.** Until then the demonstrator proves the
  *governance* over classical + hybrid-classical suites end-to-end and leaves the ML-KEM/ML-DSA rows in
  the registry inert-until-available — disclosed as prior art now, measured when the primitive lands.

## 12. Evidence plan (every claim maps to an artifact — house rule)

- **P1–P5**: the frozen `conformance/crypto_agility.json` proof verdicts, re-verified green in Python
  and Rust (byte-equal), cited in the evidence ledger.
- **Anti-downgrade**: an audit-log excerpt showing an unapproved-suite / below-floor pack **rejected**
  before staging, with the reason.
- **Monotone migration**: the phase-advance replay corpus (§10.5) with every rollback attempt audited.
- **Cost**: a measured per-suite selection+crypto overhead table from `measure_crypto_cost`, framed
  exactly as the wire bench is — measured on a named host, not projected.
- **Attestation**: a Merkle root over a swap sequence, OTS-anchored, with a worked verification.

---

*Status: DRAFT for owner review. On approval, phase 1–5 are prismpath-core + adapter work (no hardware
needed); phase 6 is gated on the hardware-retest rule. This document is the defensive-publication
record; it lands in the repo before code, as `spec-secure-hotswap.md` did.*
