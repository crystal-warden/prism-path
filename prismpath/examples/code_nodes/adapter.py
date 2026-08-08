"""Code-node worker example — a deterministic function as a flow worker, routing on its outcome.

PrismPath governs the routing (the `->` edges in pipeline.md); the code node just returns fields.
`extract` is a pure function, so it runs via `in_process_runner`; untrusted or effectful code should
use `prismpath.sandbox.SandboxRunner` instead — the same agent, governed at runtime by the envelope.

    python prismpath/examples/code_nodes/adapter.py
"""
import os
import re

from prismpath.code_nodes import code_agent, in_process_runner
from prismpath.engine import run
from prismpath.parser import parse_file

HERE = os.path.dirname(os.path.abspath(__file__))
FLOW = os.path.join(HERE, "pipeline.md")


def extract(node: str, instruction: str, state: dict) -> dict:
    """The code node: pull the amount out of the request text. Unparseable -> -1 (routes to `invalid`).
    Note it returns a FIELD; it does not branch — the flow's edges decide where -1 / 100 / 750 go."""
    text = str(state.get("request", ""))
    m = re.search(r"-?\d+(?:\.\d+)?", text)
    amount = float(m.group(0)) if m else -1
    return {"amount": amount, "text": f"parsed amount={amount}"}


HANDLERS = {"extract": extract}


def build_agent(graph):
    return code_agent(graph, HANDLERS, runner=in_process_runner)


def route(request: str):
    graph = parse_file(FLOW)
    return run(graph, build_agent(graph), state={"request": request})


if __name__ == "__main__":
    for req in ["refund $750 please", "refund of 100 dollars", "no number in here"]:
        res = route(req)
        print(f"{req!r:24} -> {' -> '.join(res.path)}  ({res.stopped})")
