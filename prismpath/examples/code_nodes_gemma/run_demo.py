"""Mixed md + code-node flow on LOCAL Gemma — proof that both worker kinds run together, governed.

  parse, decide        -> code nodes, executed in the bwrap SANDBOX (prismpath.sandbox.SandboxRunner),
                          each under its declared @code(net=false, fs=none, ...) envelope.
  triage, page_oncall,
  file_ticket          -> markdown nodes, executed by the local served GEMMA endpoint (chat_agent).

PrismPath governs the routing; Gemma advises (the `urgent` hint); the code node decides (the fixed
page/no-page policy). Nothing leaves the box: Gemma is served locally, code runs sandboxed locally.

    LLM_BASE=http://127.0.0.1:8888/v1 LLM_MODEL=gemma4 \
      PYTHONPATH=prismpath/examples/code_nodes_gemma \
      python prismpath/examples/code_nodes_gemma/run_demo.py
"""
import os

import alert_handlers  # importable module (dotted path) so the sandbox child can load the handlers

from prismpath.chat_agent import chat_agent
from prismpath.code_nodes import code_agent
from prismpath.engine import run
from prismpath.parser import parse_file
from prismpath.sandbox import SandboxRunner

HERE = os.path.dirname(os.path.abspath(__file__))
FLOW = os.path.join(HERE, "alert_router.md")
HANDLERS = {"parse": alert_handlers.parse, "decide": alert_handlers.decide}
SANDBOXED = set(HANDLERS)

BASE = os.environ.get("LLM_BASE", "http://127.0.0.1:8888/v1")
MODEL = os.environ.get("LLM_MODEL", "gemma4")

ALERTS = [
    "service=checkout 87 errors in 5m, latency spiking, customers seeing 500s at pay",
    "service=analytics 3 errors, nightly batch retried and recovered on its own",
    "a totally malformed blob with no fields at all",
]


def main():
    graph = parse_file(FLOW)
    gemma = chat_agent(f"openai:{MODEL}@{BASE}")
    # code nodes -> sandbox; every other node -> Gemma. One composed agent, fail-closed on code.
    agent = code_agent(graph, HANDLERS, runner=SandboxRunner(), base=gemma)

    for alert in ALERTS:
        res = run(graph, agent, state={"alert": alert, "transcript": [], "visits": {}})
        print("=" * 88)
        print("ALERT :", alert)
        print("PATH  :", " -> ".join(res.path), f"   ({res.stopped})")
        for s in res.steps:
            worker = "sandbox" if s.node in SANDBOXED else "gemma"
            line = " ".join(str(s.outcome).split())
            print(f"   [{worker:7}] {s.node} -> {s.target}: {line[:96]}")


if __name__ == "__main__":
    main()
