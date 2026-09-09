# Cause codes: the refusal/deviation registry

*Design spec, v1. Reference: `prismpath/kernel/causes.py`; referee: `prismpath/tests/test_causes.py`.*

## 1. Why this layer exists

Three independent 2026 actors converged on the same observation from three directions: identical
surface refusals with different structural causes are different situations, and a governed system
should say which one occurred (the convergence review's failure signatures and reason codes; our
own channels, scattered). The wire work added four more named causes in one day. This spec
unifies them: **one byte on the receipt answers "why did the system refuse, park, or escalate,"**
with a stable registry mapping every runtime refusal site in the stack to a numeric code.

The second consumer is the attentional-depth collaboration. In that architecture, the NATURE of a
discrepancy routes a query upstream through the provenance chain (which branch, which support
dimension) while its magnitude sets how far the query travels. The cause code **is** the nature
signal, machine readable: a query policy — itself a signed Level M document — routes on it like
any other field. Building the registry first means every receipt in the stack is already speaking
the vocabulary the query layer will consume.

## 2. The field

- **One byte.** `0` is reserved: a clean decision carries no cause. All codes fit `u8`, so the
  field costs one byte in a packed receipt struct and, when carried on the Facet wire, rides as an
  ordinary symbol (`code + 1` under Zeckendorf, densest on the smallest and most common codes).
- **Placement per materialization:** a `cause` field on the receipt record (kernel struct, fabric
  render, Python audit events, wire receipts). This spec defines the registry; each substrate
  adopts the field under its own re-certification discipline (§6).

## 3. The registry

Canonical names are the strings the code **already emits**, verbatim — the registry describes
reality, it renames nothing. That is why two naming styles coexist (the verifier's `sig:missing`
colon style and the wire layer's `replay-duplicate` hyphen style); unifying the styles would break
the emitted-string contract for zero semantic gain. New names introduced by this registry (the
routing and state bands) use the colon style.

Bands group codes by class for legibility; the **class** column is the semantic axis, the band
arithmetic is not. See `prismpath/kernel/causes.py` for the full table: `authority` (1-15, the signature
chain and signed manifest), `envelope` (16-31, admission caps and profile artifacts), `routing`
(32-47, the decision itself: no matching edge, below the calibrated floor, needs-human, max steps,
stuck, contract violation), `wire` (48-63, strict decode, codebook binding, replay, concentrator),
and `state` (64-79, resident-state transitions that are not ordinary matches: stale park,
recovery, migration reset, swap-in-flight park).

## 4. Stability rules

Append only, exactly like the evidence ledger: codes are never renumbered or reused, names and
classes never change once shipped. The referee pins a hash over every `(code, name, class)`
triple; descriptions may be edited for clarity, nothing else may move without the hash changing in
the same commit that appends rows. A future registry that must break these rules is a new
registry, versioned as such.

## 5. Mapping to the attentional-depth trigger classes

The collaboration's trigger taxonomy distinguishes support-conditioned reopening (the evidence
structure is suspect), content-conditioned reopening (the content class merits a closer look), and
their interaction. The registry classes project onto it cleanly, and the projection is itself the
kind of decidable mapping a signed query policy can carry:

- **Support-conditioned:** `authority`, `envelope`, and `wire` causes. Nothing about the content
  was weighed; the pipe, the provenance, or the signature chain degraded. A query routed on these
  goes to the support dimension: fetch the fuller predicate profile, the retained window, the
  provenance trace.
- **Content-conditioned:** `routing` causes. The content reached the decision layer and the layer
  abstained, escalated, or found no edge. A query routed on these goes to the content dimension:
  what did the reading look like, which cells did it land in, what would the next tier have said.
- **Interaction:** `state` causes. A stale park or a migration reset says something about BOTH the
  link and the decision context; these are the cases where the joint trigger policy earns its
  keep.

Magnitude is deliberately NOT in this registry. The registry answers *which kind*; how far a query
travels is a separate, per-cause quantity (staleness duration, confidence distance from the floor,
replay depth) that belongs beside the cause on the receipt, not inside the code space.

## 6. Rollout, gated

1. **Now (this change):** the registry, the reference module, and the referee. Pure data; no
   behavior anywhere changes.
2. **Python receipts:** `audit_log` events and engine stop records adopt the `cause` field
   (`ENGINE_STOP_TO_CAUSE` is the mapping); additive, next Python-focused session.
3. **Kernel: DONE (August 2026).** The selector receipt carries the `cause` byte in the former
   pad slot (size, layout, and historical receipt bytes unchanged), stamped `PPT_CAUSE_NONE` on
   clean commits and CHECKED by the receipts harness; re-certified 624/624 in-kernel in the same
   session that anchored the #119 receipt root (staging row #128). Nonzero kernel causes arrive
   with the paths that produce them (loader migration receipts, refusal emissions), named
   follow-on.
4. **Fabric:** the receipt render gains the byte; held for a hardware re-cert session per the
   standing rule.
5. **Wire carriage:** a receipt-bearing Facet stream carries the code as a symbol; enters as an
   optional declared profile like every wire addition.

## 7. Non-goals

Authoring-time lint findings stay out (they refuse documents, not decisions; `validate` already
names them). Success states stay out (`terminal`, `waiting`; `0` means clean). No renaming of any
emitted string, no substrate changes in this change, no claim that the registry is complete — it
is complete with respect to the refusal sites inventoried in the referee, and append-only for
everything the stack grows next.
