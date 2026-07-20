**What & why.**

**Checklist:**
- [ ] `pytest -q` green
- [ ] `node --test portable/prismpath.test.mjs` green (if the kernel/port changed)
- [ ] `node portable/run_vectors.mjs` → CONFORMANT
- [ ] `python -m prismpath.fuzz_predicates -n 20000` clean (if predicates changed)
- [ ] Commits signed off (`git commit -s` — DCO, see CONTRIBUTING.md)

**Semantics change?** If this alters predicate or engine behavior, the conformance vectors will
change. Regenerate (`python portable/gen_conformance.py`), commit the diff, and describe it here
— that diff is the spec-change review and bumps the spec version.
