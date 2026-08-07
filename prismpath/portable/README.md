# The portable kernel — the auditable subset runs anywhere

**Try it: [`playground.html`](playground.html)** — the kernel running client-side (paste a flow,
watch it parse, tier-classify, graph, and route live; nothing leaves the page):

```
cd prismpath/portable && python3 -m http.server 8321   # ES modules need HTTP, not file://
open http://localhost:8321/playground.html
```

`prismpath.mjs` is the PrismPath kernel for the **ML-free portable subset**, in one dependency-free ES
module: the Markdown flow parser, the safe predicate evaluator (a hand-rolled recursive-descent
parser — no `eval`, same sandbox as Python's `predicates.py`), and the engine loop
(deterministic + error + event tiers, `needs_human` / `wait` / `spawn` suspension, `visits`,
re-entry via `start`/`state`). No build step, no packages: it runs as-is in Node, a browser
`<script type="module">`, an edge function, or a network appliance.

**Which flows? Portability is a TIER, not a bit** — `prismpath portable <flow>` computes it for the
whole composition tree (`@spawn` children included):

- **P0** — every reachable edge is decidable (`when` / `on error` / `on event`). Zero ML; runs on
  this module anywhere JavaScript runs. `run()` here refuses anything else rather than guess.
- **P1** — semantic edges exist but ALL are pinned in the flow's routing lockfile: the condition
  side is committed vectors, so routing needs only an *outcome-side* embedder at runtime (an
  ONNX-able ~35MB dependency) — appliance/edge-deployable as *one flow + one lock + one encoder*.
  Locks record their `(model, provider, precision)` identity: the same weights under a different
  runtime or quantization are a different numeric contract, and `verify_lock` says so.
- **P2** — semantic edges not fully locked: needs the full Python engine (live embedding and/or
  LLM escalation). `prismpath lock` promotes to P1; rewriting edges as `when` predicates promotes
  to P0.

Notably, the production SOC triage flow (`prismpath/flows/wazuh_triage.md`) is **P0**: its *routing* is
fully decidable — the LLM lives in the workers, which the host supplies in any language.

```js
import { parse, run } from "./prismpath.mjs";

const graph = parse(await (await fetch("triage.md")).text());
const result = run(graph, (node, instruction, state) => myWorker(node, state));
// result: {path, steps, stopped, state, pending} — the same RunResult the Python engine returns
```

**Fidelity is verified, not claimed.** The cross-language conformance suite
(`prismpath/tests/test_portable_conformance.py` + `run_conformance.mjs`) replays the same flows and scripted
worker outcomes through both engines and requires identical paths, stop reasons, and pending
nodes. The Python-exact predicate semantics are preserved deliberately, including the sharp edges:
`True/False/None` are constants while lowercase `true`/`false` are *field names*; booleans compare
numerically (`flag == 1` matches `flag: true`); a comparison against a missing field or
type-mismatched pair is *unsatisfied*, never a crash — except `not in`, whose failure is
*satisfied*; chained comparisons; substring `in` on strings; Python truthiness (`[]` and `{}` are
falsy). Unit tests: `node --test prismpath/portable/prismpath.test.mjs`.

On top of the suite, a **differential fuzzer** (~61,700 comparisons: 45k grammar-fuzzed
predicate/context pairs, 15k realistic flow predicates, plus classifier/parser/engine probes) drove
both evaluators side by side. The realistic corpus was 15,000/15,000 identical; the divergences it
found in the exotic corners — Python hard keywords as field names, `str()`-vs-`String()` outcome
text, paren depth accounting, `0x`/`_` numeric spellings, Python escape tables, list ordering past
equal-but-unorderable elements, `splitlines()` boundaries — were **fixed and pinned as conformance
fixtures**, and Python's `eval_condition` now enforces the sandbox statically (a lazily
short-circuited chain can no longer smuggle a disallowed call past the runtime on either engine).

The spec itself now ships as **data**: [`conformance/`](conformance/README.md) holds 1,067
predicate vectors + 27 engine fixtures, generated deterministically from the Python reference
(`gen_conformance.py`) and enforced in both directions on every test run — the committed files
must match a fresh regeneration (no silent reference drift), and this port must pass them
(`node prismpath/portable/run_vectors.mjs` → CONFORMANT). And no longer only this port: **Rust
(`prismpath-rs/`) and Go (`prismpath-go/`) kernels implement the frozen subset and pass every
vector** — three independent implementations, provably interchangeable. (The Level M fragment
additionally has a hardware target certified on a *declared subset* of these vectors —
[prism-path-hw](https://github.com/crystal-warden/prism-path-hw) — deliberately not counted as a
fourth kernel.)

**Known non-portable corner:** `error_type` in error-edge predicates is language-specific
(`RuntimeError` vs `Error`) — route on `error_count` or `error_message` content, which are
portable, not on exception class names. JSON integer context values beyond 2^53 lose precision in
any JavaScript host (an ecosystem constraint, not a port bug).

**In the portable subset since P1 landed:** locked semantic routing — pass a parsed `.lock` and a
caller-supplied `embed(text)` callback to `run()` and pinned-vector cosine routing (with
`humanFloor` escalation) runs right here, model-free on the condition side
(`run_p1_conformance.mjs` certifies it). **Not in the portable subset (by design):** live/unlocked
semantic routing (embedder/LLM), the risk-controlled
calibration, `type_gate` (needs `contract.py`), and the fan-out *harness* (`composer.py` spawns
processes; the port still *suspends* correctly on `spawn` and exposes the spec — a JS host can
implement its own composer against `eventTarget()`).
