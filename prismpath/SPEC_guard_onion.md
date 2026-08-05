# SPEC — the Guard: the security half of the onion

*Formal design spec for `prismpath/guard.py`. Companion to `SPEC_ledger_opentimestamps.md`, which
covers the observability half. Crystal Warden Labs, 2026-07-29.*

---

## 1. Goal & current gap

The onion is **security + observability** wrapped around the engine. The observability half exists —
`audit_log.py`, `ledger*.py`, attestation. The security half did not, so every consumer hand-rolled
its own filter — a deterministic blocklist applied to model input and output inside the calling
component. Good discipline, wrong location: per-app, per-language, unversioned, untestable in
isolation, and it protects exactly one caller.

This spec makes the safety boundary a **layer**: authored once, inherited by every adapter, bypassable
by none.

## 2. The two-author model

Two people with two different jobs write policy, and the design exists to let both do so safely:

- **The safety owner** writes the **floor** — statutory controls that hold everywhere, authored once
  by whoever actually tracks the regulatory landscape rather than re-derived (and forgotten) by each
  flow author.
- **The flow author** writes **augmentations** — runtime guardrails they think of while authoring
  content, plus any extra strictness their domain warrants. An author who happens to know the
  regulatory landscape can always go further; they can never go less far.

## 3. Design

### 3.1 Monotonicity is enforced by the grammar, not by a check
The obvious risk in letting flow authors touch safety is that one of them weakens it. So **the policy
language has no verb for permitting.** There is `deny:` and nothing else; composition is a union of
denials. Weakening the floor is not "disallowed and validated against" — it is *unsayable*.

This is deliberately stronger than a validation pass. A check can be bypassed, mis-implemented, or
have a case its author did not consider; a missing verb has no expression for a reviewer to overlook
and no code path to get wrong. Writing `allow:` is a **parse error** with an explanation, so an author
attempting an exception is told plainly rather than silently ignored.

### 3.2 Deterministic by construction (P0)
Evaluation is literal and regex matching only — no model, no embeddings. The weakest device runs the
weakest model, so the guarantee must be strongest exactly where the model is least trustworthy. A
guard that asked a small local model whether something was safe would be weakest precisely when it
matters most. This also means the layer runs unchanged on the 8 GB floor tier.

### 3.3 Fail closed
- A malformed policy **raises**; it is never skipped. A skipped rule is a silent hole in something
  trusted.
- A rule with no `deny:` pattern is an error — a rule that denies nothing is a mistake.
- `compose()` **refuses** a guard with no floor policy. Running with only augmentations would mean the
  statutory baseline is absent; refusing beats silently applying a weaker boundary.

### 3.4 The shim sits between, and the safe path is the only convenient one
`guarded_exchange(guard, text, call)` checks inbound **before** `call` happens — denied input never
reaches the model — and checks the response before returning it. The guard is a **required positional
argument**; there is no overload that quietly skips the boundary, so an adapter wanting a model
response has nothing simpler to reach for. Denials `raise Blocked` rather than returning a sentinel,
so a caller that forgets to check cannot mistake a refusal for an answer.

### 3.5 Composes with the observability half
`on_verdict` receives every verdict, allowed or not — wire it to `audit_log` / attestation. Binding
`guard.policy_hash` into the provenance manifest (alongside `policy_hash` for the flow, per
`ADAPTER_GUIDE` invariant 4) makes **which safety policy ran** provable after the fact, not merely
asserted. That is the same C1 compensation the ledger spec calls "bind the logic, not just the output."

### 3.6 Separate authorship, separate signing
Floor and augmentation are separate documents with separate `authority:` fields and separate source
hashes. They are reviewed on different cadences by different people and should be signed by different
keys. The `Policy.source_hash` is the hook for that; signing itself is future work (§5).

## 4. What this does NOT do *(read before claiming anything)*

- **It is not a jailbreak-proof filter.** Deterministic pattern matching is defeatable by obfuscation,
  encoding, translation, and roleplay framing. It is a *floor*, not a *ceiling*: it makes the common
  and careless cases fail safely and gives a provable, auditable record of what policy was applied.
  Anything stronger needs a model, which the P0 tier deliberately forbids.
- **It does not make the content safe.** It gates a boundary; it does not evaluate truthfulness,
  quality, or pedagogy.
- **It is not legal advice, and the shipped floor is a scaffold.** Rules cite the obligation they are
  *aimed at*; none has been reviewed by counsel. No compliance claim may rest on it until that happens.
- **Narrowness is a feature.** A floor that over-blocks gets disabled by whoever it frustrates, and a
  disabled floor protects nobody. Breadth belongs in domain augmentations that know their context.

## 5. Steps & effort

1. Core guard: parse → compose → evaluate, with the shim. *(done)*
2. Shipped statutory floor + 37 tests, weighted toward attempts to weaken it. *(done)*
3. Adapter wiring: route consumer mentors/adjudicators through `guarded_exchange`; retire the
   hand-rolled in-component blocklists. *(done — the Connector SDK's Adjudicator port takes an
   optional `guard` and routes the exchange through `guarded_exchange`)*
4. **Frozen safety-conformance corpus** — `(policies, text, direction) → verdict` vectors in the shape
   of `prismpath/portable/conformance/predicates.json`, so the boundary is provably unchanged after any
   edit and a second implementation is measurable against it. *(done — 136 vectors in
   `prismpath/portable/conformance/safety.json`; a second, independent TypeScript guard passes them)*
5. Policy signing + `arch_guard` signal that flags a model call not routed through a guard. *(open)*

## 6. Claim-upgrade gate

The gate was: *until step 4 ships and a second implementation passes the corpus*, the wording stays
**"a deterministic, auditable safety floor with attested policy provenance."**

**Status: the gate's conditions are met** — the frozen corpus ships (136 vectors) and an independent
TypeScript implementation passes it, so the boundary is provably reproducible across two languages.
What the gate unlocked is *cross-implementation reproducibility*, and **nothing more**: the wording
above still stands, because §4's limits are unchanged and measured — `BYPASS_MEASUREMENT.md` publishes
the per-stratum bypass rates (`roleplay` 1.00 at every threshold that holds the benign bound;
`translation` 0.98). Still not "verified safe", not "jailbreak-resistant", not "compliant with X".
Same discipline as `SPEC_ledger_opentimestamps.md` §5 — the overclaim is what a regulator dismantles.
