#!/usr/bin/env python3
"""CI gate worker (Python). Read the build report from the [context] block on stdin, decide pass/coverage,
print ONE JSON object, exit 0. A nonzero exit routes to the flow's error tier.
Wire it in with:  cli_agent(["python", "ci_gate.py"], pass_state=["report"])"""
import json
import re
import sys


def context() -> dict:
    _, _, ctx = sys.stdin.read().partition("[context]")   # PrismPath appends: ...\n\n[context]\n{json}
    return json.loads(ctx.strip() or "{}")


try:
    report = context()["report"]
    failed = int(re.search(r"failed=(\d+)", report).group(1))
    coverage = int(re.search(r"coverage=(\d+)", report).group(1))
except (KeyError, AttributeError, ValueError):
    print("unparseable build report", file=sys.stderr)     # -> the flow's error tier
    sys.exit(1)

print(json.dumps({"passed": failed == 0, "failed": failed, "coverage": coverage}))
