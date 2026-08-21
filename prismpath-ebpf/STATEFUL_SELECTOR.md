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
  program: read `cur` from the map (`config.start_node` the first packet), `evaluate(cur, …)`, write
  the target back. The evaluator (`eval_atom`/`eval_prog`/`evaluate`) is byte-identical, so the
  114/114 conformance carries.
- **Discrete events simplify it.** The fabric switch-nav needed edge-detection + debounce because its
  input was a continuous *level* sampled fast. Packets are already discrete events, so the selector
  needs neither — just the resident `cur_node`. That contrast is the useful half of the "atomic
  snapshot" discipline: it is only required when the input is a level, not an event.

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
  frozen posture trail exactly (kernel 6.17, BPF_PROG_TEST_RUN).

Novelty vs SLSA/sigstore: those prove provenance *to* delivery; this drives runtime *state* with a
signed policy in-kernel, conformance-certified — a governed, stateful control plane.

*Prototype set (uncommitted, pending owner review + a ledger row + OTS anchor): `ppt_select.bpf.c`,
`posture_selector.md` (signed, key d519348f), `gen_selector_corpus.py`, `cert_selector.c`,
`selector_corpus.{json,bin}`.*
