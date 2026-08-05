# Contributing

Thanks for looking. This project has an unusual property that shapes how contributions work:
**the control flow is data**, so the highest-value contributions are often *checks on the data*
(lint rules), *examples of the data* (gallery flows), or *implementations of the data's spec*
(conformance-certified runtimes) — not features on the engine, which stays deliberately small
and pure (see the invariants in [docs/guides/authoring.md](docs/guides/authoring.md) §9 and the boundary rules in
[SPEC.md](SPEC.md)).

## Setup

```bash
git clone https://github.com/crystal-warden/prism-path.git && cd prism-path
pip install -e .            # numpy only; add ".[embeddings]" for semantic-routing work
pip install pytest
pytest -q                   # the Python suite
node --test prismpath/portable/prismpath.test.mjs          # the portable-kernel unit tests (Node ≥ 18)
node prismpath/portable/run_vectors.mjs                 # the frozen conformance vectors -> CONFORMANT
python -m prismpath.fuzz_predicates -n 20000     # the sandbox gate: 0 exec / 0 crash, always
```

All four must pass before and after your change. If your change intentionally alters predicate
or engine *semantics*, the conformance test will fail by design — regenerate the vectors
(`python prismpath/portable/gen_conformance.py`), commit the diff, and say so prominently in the PR: that
diff **is** the spec-change review, and it bumps the spec version (SPEC.md §8).

## Sign-off (DCO, not CLA)

We use the [Developer Certificate of Origin](https://developercertificate.org/). Sign your
commits (`git commit -s`) to certify you have the right to contribute under the project's
Apache-2.0 license. There is no CLA and no copyright assignment — your contribution stays
yours, licensed to the project and everyone else under Apache-2.0.

## The perfect first contribution: a lint rule

A lint rule is self-contained, decidable, corpus-driven, and immediately useful to every user.
The recipe (every existing check followed it):

1. Pick a mistake a flow author actually makes.
2. Write the check in `prismpath/analysis.py` — a function `Graph -> List[Finding]`, wired into
   `analyze()`. Stay inside the decidable fragment: **no false positives** is the bar, and
   "unknown → no finding" is the rule (see the module docstring).
3. Add a broken flow demonstrating it to `prismpath/tests/fixtures/broken/` and a test asserting the
   finding (and asserting it does NOT fire on the shipping flows — they're the false-positive
   corpus).
4. Add one row to the README's check table.

### Ten lint rules looking for an author

Each of these is a self-contained afternoon. Claim one by opening an issue with its name.

1. **`unconditional-self-loop`** — `-> X: always` where the target is the node itself: a
   guaranteed `max_steps` spin. (Stricter special case of `unbounded-cycle`.)
2. **`event-name-collision`** — two `on event <name>` edges with the same name on one node;
   the first silently shadows the second at resume time.
3. **`error-context-unknown-field`** — an `on error when <expr>` predicate referencing fields
   outside the error context (`error`, `error_type`, `error_message`, `error_count`,
   `visits`): always-unsatisfied, the handler never fires.
4. **`annotation-near-miss`** — an unknown annotation one edit away from a known one
   (`@emit` vs `@emits`, `@fieldonly` vs `@field_only`): silently inert today.
5. **`field-name-near-miss`** — two predicates in one flow reading fields one edit apart
   (`tests_pass` / `test_pass`): almost always a typo, currently a silent fall-through.
6. **`literal-type-mismatch`** — a comparison whose two literal-typed sides can never satisfy
   (`when score > "5"` with numeric emissions elsewhere): extends `always-false-edge` beyond
   intervals.
7. **`empty-instruction`** — a non-terminal node with edges but no prose: the worker receives
   an empty instruction.
8. **`visits-cap-exceeds-max-steps`** — `when visits > N` where N ≥ the default `max_steps`:
   the guard can never fire under default configuration (warn, since `max_steps` is settable).
9. **`duplicate-fixture-row`** — same (node, fields) asserted twice in a `.tests.md` file,
   possibly with different expectations (lives in `prismpath/flow_test.py`).
10. **`fixture-expect-not-an-edge`** — a `.tests.md` row whose `expect` is not an edge target
    of its node: fails confusingly at run time, should fail clearly at parse time.

## Other welcome shapes

- **Gallery flows** — a real workflow from your domain, no code required: see
  [gallery/README.md](prismpath/gallery/README.md). This is the contribution path for analysts, PMs, and
  ops people.
- **A runtime in your language** — implement SPEC.md, read two JSON files
  (`prismpath/portable/conformance/`), and `run_vectors`-equivalence makes it official. Open an issue
  first so efforts don't collide.
- **Bug reports as fixture rows** — the best routing bug report is a failing
  `| node | outcome | fields | expect |` row (the issue template asks for one). It becomes the
  regression test verbatim.

## What we will (politely) decline

Engine impurity (I/O, clocks, or concurrency inside `engine.py` — harness territory), a
connector ecosystem, features that operate on the *runtime* rather than the *document*, and
new heavyweight dependencies in the kernel path. When in doubt, the test is in the README of
this repo's design docs: *is this an operation on the document, or on the runtime?*
