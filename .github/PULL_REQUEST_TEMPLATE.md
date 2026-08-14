**What & why.**

**Checklist:**
- [ ] `pytest -q` green
- [ ] `node --test prismpath/portable/prismpath.test.mjs` green (if the kernel/port changed)
- [ ] `node prismpath/portable/run_vectors.mjs` → CONFORMANT (+ `run_p1_conformance.mjs` for P1)
- [ ] `cd prismpath-go && go test ./...` and `cd prismpath-rs && cargo test` (if the portable kernels changed)
- [ ] `python -m prismpath.fuzz_predicates -n 20000` clean (if predicates changed)
- [ ] Commits signed off (`git commit -s`; DCO, see CONTRIBUTING.md)

**Semantics change?** If this alters predicate or engine behavior, the conformance vectors will
change. Regenerate (`python prismpath/portable/gen_conformance.py`), commit the diff, and describe it here
;  that diff is the spec-change review and bumps the spec version.
