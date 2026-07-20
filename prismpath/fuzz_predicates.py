"""fuzz_predicates.py — adversarial + random fuzzing of the `when` predicate sandbox.

The sandbox's security claim (whitepaper §3.3): a flow is a Markdown file that may come from an
untrusted author, and a `when` predicate "cannot execute code." This harness stress-tests that
claim and, separately, the engine's robustness (a predicate must never crash a running flow).

Three outcome classes per input:
  OK        eval_condition returned a bool                       (fine)
  REJECTED  raised the sandbox's own PredicateError / ValueError (intended: unsafe/malformed input)
  CRASH     raised any OTHER exception type                      (robustness bug — uncaught)
and a hard invariant checked out-of-band:
  EXEC      a payload produced a side effect (code ran)          (SECURITY FAILURE — must be 0)

Run:  python -m prismpath.fuzz_predicates            # summary + any findings
      python -m prismpath.fuzz_predicates -n 20000   # more random cases
"""
from __future__ import annotations

import argparse
import random
import sys

from prismpath import predicates

# A module-level canary: if any sandboxed expression manages to call into Python, the payloads
# below try to flip this. It must remain False for the whole run.
CANARY = {"tripped": False}


def _trip():
    CANARY["tripped"] = True
    return True


# Adversarial payloads — every one MUST be rejected, and NONE may execute. These are the exact
# shapes a hostile "I broke your sandbox" issue would try: calls, attribute walks to builtins,
# subscript/dunder traversal, comprehensions, lambdas, f-strings, walrus, imports.
ATTACKS = [
    "when __import__('os').system('touch /tmp/prismpath_pwned')",
    "when open('/etc/passwd').read()",
    "when ().__class__.__bases__[0].__subclasses__()",
    "when [].__class__",
    "when trip()",                                  # ctx supplies trip -> _trip; must NOT be called
    "when (trip)()",
    "when foo.bar",
    "when foo.bar.baz",
    "when foo[0]",
    "when foo['k']",
    "when x[1:2]",
    "when {'a': 1}",
    "when {1, 2, 3}",
    "when [trip() for _ in range(3)]",
    "when (lambda: trip())()",
    "when f'{trip()}'",
    "when (n := trip())",
    "when x if trip() else y",
    "when 1 + 1",                                   # arithmetic not in the allowlist
    "when 2 ** 999999999",                          # would be costly IF evaluated (it must not be)
    "when x @ y",
    "when -x",
    "when ~x",
    "when x | y",
    "when not foo()",
    "when yield x",
    "when await x",
    "when x.__class__.__mro__",
    "when globals()",
    "when locals()",
    "when getattr(x, 'y')",
    "when x is y",                                  # `is` is not in the comparator allowlist
    "when x is not y",
]

# Random expression generation over the *intended* grammar plus deliberately-nasty operands
# (missing names, type-mismatched comparisons, deep nesting) — this is where robustness (CRASH)
# bugs live, not security ones.
_NAMES = ["x", "y", "visits", "tests_pass", "score", "missing", "blocked", "status"]
_LITS = ["0", "1", "3", "0.9", "-1", '"done"', '"contain"', "true", "false",
         "None", "[1, 2, 3]", '["a", "b"]', "[]"]
_CMP = ["==", "!=", "<", "<=", ">", ">=", "in", "not in"]
_BOOL = ["and", "or"]


def _atom(r):
    return r.choice(_NAMES + _LITS)


def _expr(r, depth=0):
    if depth > 4 or r.random() < 0.4:
        a, b = _atom(r), _atom(r)
        return f"{a} {r.choice(_CMP)} {b}"
    kind = r.random()
    if kind < 0.4:
        return f"({_expr(r, depth+1)}) {r.choice(_BOOL)} ({_expr(r, depth+1)})"
    if kind < 0.7:
        return f"not ({_expr(r, depth+1)})"
    return f"{_atom(r)} {r.choice(_CMP)} {_atom(r)}"


def _random_ctx(r):
    # Deliberately partial + type-mixed: missing fields, strings where numbers may be compared, etc.
    ctx = {}
    for name in _NAMES:
        if r.random() < 0.5:
            continue  # leave it missing -> exercises the None path
        ctx[name] = r.choice([0, 1, 3, 42, 0.9, True, False, "done", "contain", [1, 2, 3], None])
    return ctx


def classify(cond, ctx):
    """Run one input; return ('OK'|'REJECTED'|'CRASH', detail)."""
    try:
        predicates.eval_condition(cond, ctx)
        return "OK", None
    except getattr(predicates, "PredicateError", ()) or ():
        return "REJECTED", None
    except ValueError:
        return "REJECTED", None
    except RecursionError:
        return "CRASH", "RecursionError"
    except Exception as e:  # noqa: BLE001 - the whole point is to catch the unexpected
        return "CRASH", f"{type(e).__name__}: {e}"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", type=int, default=8000, help="random cases")
    ap.add_argument("--seed", type=int, default=1234)
    args = ap.parse_args(argv)
    r = random.Random(args.seed)

    counts = {"OK": 0, "REJECTED": 0, "CRASH": 0}
    crash_examples = {}   # detail-signature -> example condition
    exec_failures = []

    # 1) adversarial payloads — must be REJECTED and must never trip the canary
    attack_ctx = {"trip": _trip, "x": 1, "y": 2, "foo": {"bar": 1}, "n": 0}
    attack_bad = []
    for cond in ATTACKS:
        before = CANARY["tripped"]
        klass, detail = classify(cond, attack_ctx)
        if CANARY["tripped"] and not before:
            exec_failures.append(cond)
        if klass != "REJECTED":
            attack_bad.append((cond, klass, detail))
        counts[klass] += 1

    # 2) deep-nesting stress (parser + evaluator recursion)
    for depth in (50, 200, 1000, 5000):
        cond = "when " + "(" * depth + "x" + ")" * depth
        klass, detail = classify(cond, {"x": 1})
        counts[klass] += 1
        if klass == "CRASH":
            crash_examples.setdefault(f"deep-paren/{detail}", f"depth={depth}")
    for depth in (50, 500, 5000):
        cond = "when " + " and ".join(["x"] * depth)
        klass, detail = classify(cond, {"x": True})
        counts[klass] += 1
        if klass == "CRASH":
            crash_examples.setdefault(f"deep-and/{detail}", f"terms={depth}")

    # 3) random valid-grammar expressions with hostile operands/contexts
    for _ in range(args.n):
        cond = "when " + _expr(r)
        ctx = _random_ctx(r)
        klass, detail = classify(cond, ctx)
        counts[klass] += 1
        if klass == "CRASH":
            crash_examples.setdefault(detail, cond + f"    ctx={ctx}")

    total = sum(counts.values())
    print(f"=== predicate fuzz: {total} inputs "
          f"(seed={args.seed}, n={args.n}, +{len(ATTACKS)} attacks + nesting) ===")
    for k in ("OK", "REJECTED", "CRASH"):
        print(f"  {k:9s} {counts[k]:6d}  ({100*counts[k]/total:.1f}%)")

    print(f"\n--- security: canary tripped? {'YES — FAIL' if exec_failures else 'no (good)'}")
    for c in exec_failures:
        print(f"    EXECUTED: {c}")
    if attack_bad:
        print(f"\n--- {len(attack_bad)} adversarial payload(s) NOT cleanly rejected:")
        for cond, klass, detail in attack_bad:
            print(f"    [{klass}] {cond}   ({detail})")
    else:
        print("--- all adversarial payloads cleanly rejected (good)")

    if crash_examples:
        print(f"\n--- {len(crash_examples)} distinct CRASH signature(s) (uncaught, would kill a run):")
        for sig, ex in sorted(crash_examples.items()):
            print(f"    {sig}\n        e.g. {ex}")
    else:
        print("\n--- no uncaught crashes (good)")

    # exit nonzero if the security invariant failed or anything crashed
    bad = bool(exec_failures) or counts["CRASH"] > 0 or bool(attack_bad)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
