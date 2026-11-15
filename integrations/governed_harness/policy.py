# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The owner's agent rules as a signed core policy, and the one decision per proposed tool call.

The policy is `policy/agent_rules.core.json`, a `prismpath.core/1` image in its canonical canon/2 bytes
(written from `agent_rules.src.json` through `prismpath canonicalize`). It is decided by the repository's
own code, nothing reimplemented here:

  * the image is checked by the port of the Lean oracle's `loadPolicy` (`formal/diff/core_policy.py`),
    which must accept it;
  * it is rendered to its canonical flow text (`prismpath.kernel.core_render.render`, the rendering a core
    run stores and the evidence verifier holds every stored flow to) and
    parsed by the reference kernel (`prismpath.kernel.parser.parse`), which applies the field definitions
    and the six policy rules of SPEC.md section 4.5;
  * a reading is decided by the reference's decision path (`core_diff.python_reading`: the strict canon/2
    reader, the system boundary, the first deterministic rule that holds), and every receipted decision
    is replayed through the Lean oracle when the run is verified (evidence.py).

A rule's target says what the harness does with the call, and names the cause by its registered code, so
the cause is part of the signed image rather than a table beside it:

  allow            the call runs, in the sandbox
  refuse_<code>    the call never runs; the decision is a refusal with that registered cause
  escalate_<code>  the call never runs; it is held for the owner, with that registered cause

A refusal of the core itself (a reading the boundary refuses, `route:contract-violation`; no rule holds,
`route:no-matching-edge`; a reading that does not read) is a refusal too. There is no catch all allow:
what no rule allows is refused by the core, so the policy fails closed by the core's own semantics.
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
for extra in (REPO, REPO / "formal" / "diff"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

import core_diff  # noqa: E402
import core_policy  # noqa: E402
from prismpath.kernel import canon2, causes, core_render  # noqa: E402
from prismpath.kernel.parser import parse  # noqa: E402

POLICY_PATH = HERE / "policy" / "agent_rules.core.json"
SOURCE_PATH = HERE / "policy" / "agent_rules.src.json"
_TARGET = re.compile(r"^(allow|refuse_(\d+)|escalate_(\d+))$")


@dataclass(frozen=True)
class Decision:
    """What the harness does with one call: `allow`, `refuse` or `escalate`, with the registered cause of a
    refusal or an escalation, and the core's own verdict it came from."""
    kind: str
    cause: Optional[str]
    cause_code: Optional[int]
    verdict: Dict[str, Any]

    @property
    def runs(self) -> bool:
        return self.kind == "allow"


def target_decision(target: str):
    """(kind, cause, code) a rule's target names, or None when it names nothing the harness knows."""
    match = _TARGET.match(target)
    if not match:
        return None
    if match.group(1) == "allow":
        return "allow", None, None
    code = int(match.group(2) or match.group(3))
    name = causes.name(code)
    if name is None:
        return None
    return ("refuse" if match.group(2) else "escalate"), name, code


class Policy:
    def __init__(self, image: bytes):
        if image.endswith(b"\n"):
            image = image[:-1]                 # the one line feed a file may end with
        self.image = image
        refusal = core_policy.load_policy(image)
        if refusal is not None:
            raise ValueError(f"the core refuses the agent policy: {refusal}")
        self.doc = canon2.loads(image)
        self.flow = core_render.render(self.doc)
        self.graph = parse(self.flow)
        self.fields = sorted(self.doc["fields"])
        for rule in self.doc["rules"]:
            if target_decision(rule["target"]) is None:
                raise ValueError(f"the policy names a target the harness does not know: {rule['target']}")

    @classmethod
    def load(cls, path: Path = POLICY_PATH) -> "Policy":
        return cls(Path(path).read_bytes())

    def reading_bytes(self, reading: Dict[str, Any]) -> bytes:
        """A reading's canonical canon/2 bytes: the only spelling the core reads."""
        return canon2.dumps(reading)

    def verdict(self, raw: bytes) -> Dict[str, Any]:
        """The core's verdict on one reading's bytes, from the reference decision path."""
        verdict = core_diff.python_reading(self.graph, raw)
        verdict.pop("policy_check", None)
        return verdict

    def decide(self, raw: bytes) -> Decision:
        verdict = self.verdict(raw)
        if verdict.get("verdict") == "route":
            kind, cause, code = target_decision(verdict["target"])
            return Decision(kind, cause, code, verdict)
        cause = verdict.get("cause")
        code = causes.code(cause) if isinstance(cause, str) else None
        # an uncoded refusal (the reference crashed) is still a refusal, never a run; it carries no code, so
        # its receipt fails verification and the run reports it, rather than borrowing another cause
        return Decision("refuse", cause if isinstance(cause, str) else "crash", code, verdict)
