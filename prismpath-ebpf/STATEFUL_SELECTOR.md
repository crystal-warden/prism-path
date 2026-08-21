# Stateful selector — a signed policy driving resident state in the kernel

A resident finite-state machine in the kernel, whose transitions are a **signed PrismPath policy**.
The existing `ppt_xdp` interpreter is stateless (the start node rides in each packet). `ppt_select`
adds one BPF map holding `cur_node`: the start node comes from the map, not the packet, and the
decided target is written back. Each packet is one discrete control event; the resident posture
persists across packets — no userspace in the loop.

This is the switch-nav pattern (resident FSM + edge routing) carried down to the decode plane. It
came out of the fully-in-fabric switch navigation: once the interpreter is a resident FSM on one
substrate, it is one on all of them, because every target's evaluate takes an arbitrary start node.

## Verified (in-kernel, this box: kernel 6.17, clang 18, BTF)

`ppt_select.bpf.c` builds clean and loads past the verifier; driven with the signed
`posture_selector` policy (normal -> elevated -> lockdown, escalate/de-escalate clamping at the
ends), a stream of control-event packets walks the resident posture **identically to the C and
Python interpreters** (BPF_PROG_TEST_RUN):

```
start=normal
ev=1 -> elevated   ev=1 -> lockdown   ev=1 -> lockdown(clamp)   ev=0 -> lockdown(hold)
ev=2 -> elevated   ev=2 -> normal     ev=2 -> normal(clamp)     ev=1 -> elevated
```

The `cur_node` in the state map persisted across every packet — the resident state is the whole
mechanism, and the signed table is the transition function.

## The design (minimal diff to the certified interpreter)

- `ppt_select.bpf.c` = `ppt_xdp.bpf.c` + one `sel_state_map` (ARRAY, `{cur_node, inited}`) and, in the
  program: read `cur` from the map, `evaluate(cur, …)`, write the target back. The evaluator
  (`eval_atom`/`eval_prog`/`evaluate`) is byte-identical, so the 114/114 conformance carries.
- **Fail-safe reset (fail closed, not open).** A deliberate clean start is the loader writing
  `{start_node, inited=1}`, so a fresh load begins at the baseline. But `inited==0` — a crash, a fresh
  or torn state map, any state the loader did not set — falls to the **most restrictive** posture (the
  last, highest-severity node), never the baseline. A forced reload must buy `lockdown`, not `normal`:
  the resident FSM fails closed. The fail-safe posture is a **signed `safe_node`** carried in the image
  (the high byte of the header flags word at offset 26, so it rides the manifest signature — tampering
  it fails `verify_pack` with an image-hash mismatch). A policy declares it with `safe: <node>` in its
  frontmatter; an undeclared policy falls back to the last-node convention (nodes ordered
  least-to-most restrictive, the severity order the spiral lint enforces).
- **Discrete events simplify it.** The fabric switch-nav needed edge-detection + debounce because its
  input was a continuous *level* sampled fast. Packets are already discrete events, so the selector
  needs neither — just the resident `cur_node`. That contrast is the useful half of the "atomic
  snapshot" discipline: it is only required when the input is a level, not an event.

## Concurrency — measured shut, not argued shut

On a multi-queue NIC the program runs on several CPUs at once against the one shared `sel_state_map`.
`evaluate()` calls map helpers, so it cannot run inside a `bpf_spin_lock` critical section; the
read-modify-write is instead a **generation-counter CAS with bounded retry** — snapshot `{cur_node,
gen}` under the lock, evaluate unlocked, then commit under the lock only if `gen` is unchanged. On a
lost commit it re-snapshots from the *new* state and re-evaluates, up to `SEL_MAX_RETRY` (4) times, so
a contender turns a drop into a commit against fresh state rather than losing the event. Every
re-evaluation is from the actual current posture, so a committed transition is **never applied from a
stale snapshot** — the resident posture only ever steps along a real edge of its actual current value,
never a phantom. Only pathological contention (all retries lose) drops. The bounded loop with a
spinlock and `evaluate()` inside verifies clean on kernel 6.17.

`smoke_selector.c` measures it: 8 threads run the loaded program via `BPF_PROG_TEST_RUN` on separate
CPUs, all against the same map, 20 000 events each. Result on this box (kernel 6.17):

- **160 000 concurrent events, the resident posture stayed a valid in-range state throughout, never
  torn** — 96 437 committed advances, 63 563 CAS drops with 4 retries (a single-shot CAS drops
  118 701). The residual drops are the adversarial worst case (8 CPUs, one shared cell, zero
  inter-event gap, no steering) and prove the safety invariant holds under maximum contention. It is
  not a deployment throughput figure.

The **serialization point for a real deployment** is single-RX-queue steering (RSS/ntuple) — the
kernel analog of the fabric clock — which lands control events on one CPU and drives drops to zero;
selector control events are naturally rare, so contention is near zero in practice. The in-program
lock plus bounded retry is the safety net that guarantees no corruption and no stale-misapply even
when steering is absent.

## Hot-swap migration (a signed strategy, lint-gated)

A resident selector's `cur_node` survives across a signed hot-swap of the policy — but a raw node
*index* carried into a new policy silently reinterprets the posture (node 2 may be a different posture
in the new table). So a stateful pack must declare how its state migrates, and the choice is signed:

- `migration: by-name` — re-resolve the current node by NAME in the new policy (posture continuity; a
  name that is gone falls back to the fail-safe). Rides flags bit 1 (`FLAG_MIGRATE_BY_NAME`) in the
  image, so `verify_pack` covers it (same image-hash coverage as `safe_node`).
- `migration: reset-to` — reset the resident state to the fail-safe node on swap (maximally safe).

The **lint** (`analysis` code `stateful-migration-undeclared`) refuses a pack that declares a
fail-safe (`safe:`) but no migration strategy — the author must decide, exactly as `packing: spiral`
forces the baseline-last decision. `posture_selector` declares `migration: by-name`.

**The loader enforces it at swap time.** by-name needs node identities, so a stateful pack also carries
a signed **per-node name-hash section** (FNV-1a-32 of each node name, appended under `FLAG_NODE_NAMES`,
covered by the image hash). On a swap the loader's `migrate_node` re-resolves the resident node's name
hash in the new policy (by-name) or resets to the new fail-safe (reset-to). `migrate_selector.c`
advances the resident posture to `lockdown` in-kernel under policy A (`normal=0, elevated=1,
lockdown=2`), then swaps to a **reindexed** B (`normal=0, lockdown=1, elevated=2` — same names):
by-name lands on B's `lockdown` (idx 1) and the migrated state drives B's FSM live in-kernel, where a
raw index carry (idx 2) would have misread it as `elevated`; reset-to instead sends an in-flight
`elevated` to B's fail-safe. Remaining: wiring `migrate_node` into the loader's production attach/swap
path (the harness exercises the enforcement logic against the live kernel state).

## Receipts + Merkle anchor (the stateful history, tamper-evident)

The `result_map` holds only the current posture — a flat snapshot that loses the transition history.
So each committed transition also emits a **receipt** to a ringbuf: `{seq, policy_hash, prev_node,
event, next_node}`. It carries the PRE-state, so the whole stateful history is reconstructable from the
log alone, and the `policy_hash` (low 64 bits of the loaded image's sha256 — the same bytes the signed
manifest hashes) binds each receipt to the exact signed policy that produced it.

`receipts_selector.c` drains the ringbuf while replaying the frozen corpus and checks the log against
the certified reference:

- **624 receipts for 624 committed transitions** (one per event — a complete log), **0 mismatches**:
  every receipt's `next_node` reproduces the certified posture trail, its `prev_node` is the posture
  before the event (chain continuity), its `event` is the driving field, and its `policy_hash` binds to
  the loaded image.
- A **Merkle root** over the receipt batch is deterministic across runs (`0858c133…`); that root is
  what an OTS stamp anchors — the same held-for-publish step as the corpus manifest, via the
  `ledger_ots` machinery. One stamp makes the whole batch tamper-evident; a single altered receipt
  changes the root.

This is the review's "receipts carrying pre-state": it restores the statefulness a current-state-only
map flattens, and keeps the audit trail linear-to-write but tamper-evident in `O(log n)` via the tree.
Honest scope: `policy_hash` is a 64-bit prefix of the image sha256 (the full hash is in the signed
manifest); the **loader stamps it at load** — `populate_maps` computes `sha256(image)`, and it matches
`policy_pack`'s manifest `image_sha256` (verified), so a receipt cross-references the signed pack. The
OTS anchor of the Merkle root is the remaining step.

## Cross-substrate (the same signed policy, everywhere)

The transition policy is Level M, so the *same* `.ppt` routes identically on fabric (`ppt_nav`), C
(proven, resident walk), the kernel (here), and Rust/JS/the MCUs (conformance corpus). What each
substrate adds is a thin driver: hold `cur_node`, feed it as the start. Fabric holds it in a
register; the kernel in a BPF map; a userspace loop in a variable.

## Portable disciplines (from the nav work)

1. **Edge-as-predicate** `(x==1 and p==0) or (x==0 and p==1)` keeps change-detection in Level M — a
   substrate-independent policy idiom, given a current + previous field.
2. **Resident FSM** = feed the decided target back as the next start. Every evaluate interface already
   takes an arbitrary start node, so it is a driver pattern, not an interpreter change.
3. **Atomic input snapshot** is required for *continuous-level* inputs (read once per evaluate, use for
   both the field and the prev-compare) and *not* for *discrete events* (packets) — know which you have.
4. **Field-write lockstep** (RTL only): when a fabric FSM writes multiple fields via a counter, the
   index/value must be registered in lockstep with the write strobe. No software analog (sequential
   writes), but the forward-looking rule for the fusion fabric datapath.

## Conformance corpus — BUILT + PASSING (in-kernel)

A stateful-selector corpus, the same discipline as the 124-vector frozen predicate corpus but for
SEQUENCES: `gen_selector_corpus.py` freezes event streams with the posture trail the resident
interpreter reaches, the Python reference cross-checked step-by-step against the C target (interp.c);
`cert_selector.c` replays each stream through `ppt_select` via BPF_PROG_TEST_RUN, resetting the
resident state per stream, and diffs the kernel's trail against the frozen reference.

- Corpus: **49 streams, 624 events** (boundary walks that clamp at both ends, every (posture, event)
  transition, hold events, 30 seeded-random streams, and a 200-event stress stream). Reference:
  `selector_corpus.json` (readable) / `selector_corpus.bin` (frozen). C target agrees with Python at
  every one of the 624 steps.
- **In-kernel cert: 624/624 events match, 49/49 streams clean, PASS** — the kernel reproduces the
  frozen posture trail exactly (kernel 6.17, BPF_PROG_TEST_RUN). Each stream is reset with a
  *deliberate* clean start (`{start_node, inited=1}`), and a separate fail-safe check confirms an
  uninitialized state plus one event lands on the most-restrictive posture (`lockdown`), not the
  baseline — the reset fails closed.

Novelty vs SLSA/sigstore: those prove provenance *to* delivery; this drives runtime *state* with a
signed policy in-kernel, conformance-certified — a governed, stateful control plane.

*Prototype set (uncommitted, pending owner review + a ledger row + OTS anchor): `ppt_select.bpf.c`,
`posture_selector.md` (signed, key d519348f), `gen_selector_corpus.py`, `cert_selector.c`,
`selector_corpus.{json,bin}`.*
