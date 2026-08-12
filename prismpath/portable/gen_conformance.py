"""gen_conformance.py — freeze the portable-kernel spec as LANGUAGE-NEUTRAL conformance vectors.

The cross-language conformance suite and the differential fuzzer proved the JS port routes
identically to the Python engine — but those live inside a pytest run. This script exports the
spec as committed DATA (`portable/conformance/*.json`), generated from the PYTHON reference
implementation, so that ANY implementation (the shipping .mjs port, a future Go or Rust/WASM
kernel) can be validated bit-for-bit with nothing but a JSON reader:

    python -m prismpath.portable.gen_conformance     # regenerate (deterministic: fixed seed)
    node portable/run_vectors.mjs                 # verify the JS port against the vectors

Two files:
  * predicates.json — (condition, context) -> True | False | "ERROR" for the predicate
    evaluator: ~100 curated torture cases (one per divergence class the differential fuzzer
    found) + a seeded grammar-fuzz sample. "ERROR" means PredicateError — the edge is
    non-matching at run time, and check/eval agree it's outside the sandbox.
  * flows.json — full engine fixtures: a flow document + scripted worker outcomes ->
    {path, stopped, pending_node, spawn}. Same script protocol as run_conformance.mjs
    ({"__raise__": msg} throws, exercising the error tier).

Determinism: fixed RNG seed, sorted iteration — regenerating on the same Python produces
byte-identical files, so `git diff` over this directory IS the spec-change review. The pytest
bridge (tests/test_conformance_vectors.py) regenerates and diffs on every run: an accidental
Python-semantics change shows up as vector drift, not silently.
"""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path

from prismpath import predicates
from prismpath.engine import run
from prismpath.parser import parse

OUT_DIR = Path(__file__).parent / "conformance"
VERSION = 2   # v2: signed integer literals fold to constants (predicates.fold_unary_signs)
SEED = 42
N_FUZZ = 1000

# ---------------------------------------------------------------------- curated predicates
# One representative per semantic sharp-edge / fuzz-found divergence class. Each is (cond, ctx).
CURATED = [
    # constants vs field names
    ("when x == True", {"x": True}),
    ("when x == True", {"x": 1}),
    ("when x == true", {"x": True}),                      # `true` is a NAME -> ctx['true'] (None)
    ("when x == true", {"x": 7, "true": 7}),
    ("when x == None", {}),
    ("when x == None", {"x": None}),
    ("when x == False", {"x": 0}),
    # bool/number mixing
    ("when flag == 1", {"flag": True}),
    ("when flag == 0", {"flag": False}),
    ("when flag < 2", {"flag": True}),
    ("when n == 1.0", {"n": 1}),
    # signed integer literals: `-5` folds to a single constant, so it is an ordinary Level M atom
    # (predicates.fold_unary_signs). `-field` and `-<float>` do NOT fold and stay outside the
    # sandbox, and the sign folds in every orientation and inside membership lists.
    ("when x >= -5", {"x": -5}),
    ("when x >= -5", {"x": -6}),
    ("when x < -1282", {"x": -2000}),
    ("when -1 < x", {"x": 5}),                            # constant-OP-field, flipped orientation
    ("when x == -3", {"x": -3}),
    ("when x != -3", {"x": 0}),
    ("when +7 == x", {"x": 7}),                           # unary plus folds too
    ("when x in [-3, -1, 2]", {"x": -1}),
    ("when x in [-3, -1, 2]", {"x": 0}),
    ("when x >= -0.0", {"x": 1}),                         # negative FLOAT: still disallowed (ERROR)
    ("when -y < x", {"x": 1, "y": 2}),                    # negation of a FIELD: still disallowed
    ("when x >= -foo", {"x": 1}),                         # negation of a field name: disallowed
    # missing fields / type mismatch: unsatisfied, never a crash; not-in satisfied
    ("when nope > 3", {}),
    ("when x > 3", {"x": "high"}),
    ("when x in y", {"x": 1, "y": 42}),
    ("when x not in y", {"x": 1, "y": 42}),
    ("when not nope", {}),
    # chained comparisons
    ("when 1 < x < 5", {"x": 3}),
    ("when 1 < x < 5", {"x": 7}),
    ("when 1 < x < 5", {}),
    ("when a <= b <= c", {"a": 1, "b": 1, "c": 2}),
    # membership: substring / list / tuple / dict-keys
    ('when "error" in text', {"text": "an error happened"}),
    ('when "xyz" in text', {"text": "an error happened"}),
    ('when a in ["contain", "watch"]', {"a": "watch"}),
    ('when a in ("contain", "watch")', {"a": "contain"}),
    ("when k in obj", {"k": "a", "obj": {"a": 1}}),
    ("when 1 in xs", {"xs": [1.0, 2]}),
    ("when x in ()", {"x": 1}),                            # empty tuple
    # truthiness: [] {} "" falsy; non-empty truthy
    ("when items", {"items": []}),
    ("when items", {"items": [0]}),
    ("when d", {"d": {}}),
    ("when d", {"d": {"k": 0}}),
    ("when s", {"s": ""}),
    ("when s and ok", {"s": "x", "ok": True}),
    # keywords: hard keywords are ERROR; soft keywords are names
    ('when class == "phish"', {"class": "phish"}),         # ERROR (both engines)
    ("when import > 1", {"import": 2}),                    # ERROR
    ("when match == 1", {"match": 1}),                     # soft keyword -> Name -> True
    ("when type == 'a'", {"type": "a"}),
    # depth / grouping / bare tuples
    ("when ((((((((((x))))))))))", {"x": 1}),
    ("when (a or b) and c", {"a": 0, "b": 1, "c": 1}),
    ("when x, y", {}),                                     # bare tuple -> ALWAYS truthy (trap)
    ("when not x < ()", {}),
    # numeric spellings + strings
    ("when n == 0x10", {"n": 16}),
    ("when n == 0o17", {"n": 15}),
    ("when n == 0b101", {"n": 5}),
    ("when n == 1_000", {"n": 1000}),
    ("when n == 1e3", {"n": 1000}),
    ('when x == "\\x41"', {"x": "A"}),
    ('when x == "\\u0041"', {"x": "A"}),
    ("when x == r'\\n'", {"x": "\\n"}),
    ('when x == "a\\qb"', {"x": "a\\qb"}),                 # unknown escape keeps the backslash
    # list ordering incl. equal-but-unorderable elements
    ("when [None, 1] > [None]", {}),
    ("when [1, 2] < [1, 3]", {}),
    ("when xs < ys", {"xs": [1, "a"], "ys": [2]}),
    # ellipsis, keywords-as-ops errors, disallowed syntax
    ("when ...", {}),
    ("when f(x)", {}),                                     # ERROR: call
    ("when x.y", {}),                                      # ERROR: attribute
    ("when x + 1 > 2", {}),                                # ERROR: arithmetic
    ("when -1 < x", {"x": 5}),                             # ERROR: unary minus
    ("when 2 < 1 < f(x)", {}),                             # ERROR: strict eval walk (both sides)
    ("when x is None", {}),                                # ERROR: `is`
    # keyword catch-alls
    ("always", {}),
    ("else", {}),
    ("never", {}),
    ("false", {}),
    # strings compare by code point; unicode
    ('when a < b', {"a": "apple", "b": "banana"}),
    ('when a == b', {"a": "café", "b": "café"}),
    ('when "é" in s', {"s": "café"}),
]


# ------------------------------------------------------------------- seeded grammar fuzz
def _gen_fuzz(rng: random.Random, n: int):
    """A compact generator over the ALLOWED grammar, biased toward the tricky classes. Purely
    seeded — same seed, same corpus."""
    names = ["x", "y", "n", "flag", "items", "text", "action", "score", "ok", "true", "visits"]
    strings = ["fix", "watch", "contain", "", "error happened", "café"]
    nums = [0, 1, 2, 3, -0.0, 0.5, 1.0, 10, 1000]

    def value(depth=0):
        r = rng.random()
        if r < 0.25:
            return rng.choice(names)
        if r < 0.45:
            return repr(rng.choice(strings))
        if r < 0.6:
            return repr(rng.choice(nums)) if rng.random() < 0.9 else rng.choice(["True", "False", "None"])
        if r < 0.75 and depth < 2:
            elts = ", ".join(value(depth + 1) for _ in range(rng.randint(0, 3)))
            return f"[{elts}]"
        return rng.choice(names)

    def comparison(depth=0):
        ops = ["==", "!=", "<", "<=", ">", ">=", "in", "not in"]
        left = value(depth)
        parts = [left]
        for _ in range(1 if rng.random() < 0.8 else 2):    # some chained
            parts.append(rng.choice(ops))
            parts.append(value(depth))
        return " ".join(parts)

    def expr(depth=0):
        r = rng.random()
        if r < 0.15 and depth < 3:
            return f"not {expr(depth + 1)}"
        if r < 0.4 and depth < 3:
            joiner = rng.choice([" and ", " or "])
            return joiner.join(expr(depth + 1) for _ in range(2))
        if r < 0.5 and depth < 3:
            return f"({expr(depth + 1)})"
        return comparison(depth)

    def ctx():
        c = {}
        for name in rng.sample(names, rng.randint(0, 6)):
            r = rng.random()
            if r < 0.3:
                c[name] = rng.choice(nums)
            elif r < 0.5:
                c[name] = rng.choice(strings)
            elif r < 0.65:
                c[name] = rng.choice([True, False, None])
            elif r < 0.85:
                c[name] = [rng.choice(nums + strings) for _ in range(rng.randint(0, 3))]
            else:
                c[name] = {"k": rng.choice(nums)}
        return c

    return [(f"when {expr()}", ctx()) for _ in range(n)]


def _expect(cond: str, ctx: dict):
    try:
        return predicates.eval_condition(cond, ctx)
    except predicates.PredicateError:
        return "ERROR"


# ---------------------------------------------------------------------- engine fixtures
def _flow_fixtures():
    """The engine-level fixtures — imported from the conformance test so there is ONE fixture
    source; their expected results are computed here from the Python engine."""
    from prismpath.tests.test_portable_conformance import FIXTURES, scripted_agent
    out = []
    for fx in FIXTURES:
        graph = parse(fx["flow"])
        state = json.loads(json.dumps(fx["state"])) if "state" in fx else None
        res = run(graph, scripted_agent(fx["script"]), max_steps=fx.get("maxSteps", 25),
                  start=fx.get("start"), state=state)
        out.append({
            "name": fx["name"], "flow": fx["flow"], "script": fx["script"],
            **({"maxSteps": fx["maxSteps"]} if "maxSteps" in fx else {}),
            **({"start": fx["start"]} if "start" in fx else {}),
            **({"state": fx["state"]} if "state" in fx else {}),
            "expect": {"path": res.path, "stopped": res.stopped,
                       "pending_node": (res.pending or {}).get("node"),
                       "spawn": (res.pending or {}).get("spawn")},
        })
    return out


def generate() -> dict:
    rng = random.Random(SEED)
    cases = list(CURATED) + _gen_fuzz(rng, N_FUZZ)
    predicates_doc = {
        "version": VERSION, "seed": SEED,
        "note": "expect: true|false = eval_condition result; 'ERROR' = PredicateError "
                "(edge non-matching at run time). Any implementation must match every case.",
        "cases": [{"cond": c, "ctx": ctx, "expect": _expect(c, ctx)} for c, ctx in cases],
    }
    flows_doc = {
        "version": VERSION,
        "note": "script maps node -> outcomes consumed in visit order (last repeats); "
                "{'__raise__': msg} throws. expect is the Python reference engine's result.",
        "cases": _flow_fixtures(),
    }
    return {"predicates.json": predicates_doc, "flows.json": flows_doc}


def main() -> int:
    import warnings
    warnings.filterwarnings("ignore", category=SyntaxWarning)   # the unknown-escape curated case
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    docs = generate()
    for name, doc in docs.items():
        path = OUT_DIR / name
        path.write_text(json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False) + "\n",
                        encoding="utf-8")
        n = len(doc["cases"])
        print(f"wrote {path}  ({n} cases)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
