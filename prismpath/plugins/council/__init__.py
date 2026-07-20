"""Council plugin — deliberation as an OPTIONAL expansion (the exception, not the default).

prismpath's default control plane is a flow: one worker per node, edges route on the outcome. The
council pattern — several voices propose, a vote picks, a seeded dice roll steers exploration —
came out of a game-build sprint loop (Roblox-origin) and earns its complexity ONLY where a single
decision benefits from deliberate diversity (design/expand rounds, contested triage). It is not the
recommended starting shape for anything; reach for it after a plain flow has demonstrably plateaued.

What the plugin provides as `@worker` bindings (each deterministic and auditable — that's the point;
LLM-backed propose/vote voices stay in YOUR harness, composed around these):

    council.roll     — the seeded Oblique-Strategies dice: same round + same project files -> the
                       same mandate, always (structured stochasticity you can replay in a review).
                       Reads `state["round_key"]` + `state["files"]`; optional `state["ledger"]`.
    council.tally    — coverage/balance-weighted vote tally over `state["votes"]`
                       ({voter: category}): an over-selected category's votes count for less, so
                       exploration doesn't collapse into a rut. Emits the winner + the weights used.

Flow sketch (the binding is in the document — reviewable, checkable with `prismpath plugins --check`):

    ## steer
    Roll the expansion mandate for this round.
    @worker(council.roll)
    -> propose: always
"""
from . import dice

NAME = "council"
VERSION = "1"
DESCRIPTION = "deliberation expansion: seeded dice + weighted vote tally (optional — not core)"


def _roll(node, instruction, state):
    r = dice.roll(state.get("round_key", 0), state.get("files") or {}, state.get("ledger"))
    return {"text": dice.mandate(r), **{f"roll_{k}": v for k, v in r.items()}}


def _tally(node, instruction, state):
    votes = state.get("votes") or {}
    ledger = state.get("ledger") or {}
    weights = {}
    for voter, category in votes.items():
        w = dice.balance_weight(ledger, category)
        weights[category] = weights.get(category, 0.0) + w
    if not weights:
        return {"text": "no votes", "winner": None}
    winner = max(sorted(weights), key=lambda c: weights[c])   # sorted() = deterministic tie-break
    return {"text": f"council selects {winner}", "winner": winner,
            "weights": {k: round(v, 4) for k, v in sorted(weights.items())}}


WORKERS = {"roll": _roll, "tally": _tally}
