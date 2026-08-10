# Run any program as a worker

PrismPath governs the **routing**; a node's **worker** does the actual work. That worker can be a program
in any language, doing any job. If you already have a Python script, a Node program, a compiled Go or Rust
binary, or a shell script, you wire it in as a worker without writing any PrismPath-specific glue: the seam
is a subprocess, and the contract is the most stable interface in software.

This is the fastest way to get an existing project driving a flow. (For a trusted or sandboxed **Python
function** specifically, see [code nodes](code-nodes.md); for AI-agent, local-LLM, swarm, and
human-in-the-loop patterns, see [frontier-agent integration](frontier-agent-integration.md).)

## The contract

Your program is a worker if it:

1. reads the request on **stdin**,
2. does its work,
3. prints **one JSON object** on **stdout** (its fields become the outcome the flow's `when` edges read),
4. exits **0** (a nonzero exit, or a timeout, routes to the flow's error tier).

That is the whole interface. No SDK, no import on your side, no return-shape magic. Anything that can read
stdin and print stdout is a worker.

## Wire it in

```python
from prismpath.parser import parse_file
from prismpath.engine import run
from prismpath.cli_worker import cli_agent

agent = cli_agent(["python", "ci_gate.py"], pass_state=["report"])
# agent = cli_agent(["node", "log_alert.js"], pass_state=["line"])   # a JS worker
# agent = cli_agent(["./release_gate"], pass_state=["from", "to"])   # a built Go or Rust binary

run(parse_file("ci_gate.md"), agent, state={"report": "tests=48 failed=0 coverage=91"})
```

`pass_state` lists the run-state fields to hand the worker; they arrive as a JSON `[context]` block
appended to the node's instruction on stdin, e.g. `{"node": "gate", "report": "tests=48 failed=0..."}`.

## Three jobs, four languages, one contract

Different job, different language, same seam. All four workers are live and runnable in
[`prismpath/examples/cli_worker/`](../../prismpath/examples/cli_worker/), each with its own flow. Python
and Rust run the *same* CI gate, to show one job porting across languages with no change to the flow.

| worker | language | job | emits | routes with |
|---|---|---|---|---|
| `ci_gate.py` | Python | CI test / coverage gate | `{passed, coverage}` | `when passed and coverage >= 80` |
| `ci_gate.rs` | Rust | the same CI gate | `{passed, coverage}` | `when passed and coverage >= 80` |
| `log_alert.js` | JavaScript | log severity + latency alert | `{level, latency_ms}` | `when level == "error"` |
| `release_gate.go` | Go | semver release gate | `{bump, breaking}` | `when breaking` |

The Python gate, in full ([`ci_gate.py`](../../prismpath/examples/cli_worker/ci_gate.py)):

```python
import json, re, sys

_, _, ctx = sys.stdin.read().partition("[context]")     # PrismPath appends: ...\n\n[context]\n{json}
try:
    report = json.loads(ctx.strip() or "{}")["report"]
    failed = int(re.search(r"failed=(\d+)", report).group(1))
    coverage = int(re.search(r"coverage=(\d+)", report).group(1))
except (KeyError, AttributeError, ValueError):
    print("unparseable build report", file=sys.stderr); sys.exit(1)   # -> the flow's error tier

print(json.dumps({"passed": failed == 0, "failed": failed, "coverage": coverage}))
```

The [JavaScript alerter](../../prismpath/examples/cli_worker/log_alert.js) reads `process.stdin`, extracts
a log line's `level` and `latency`, and `process.exit(1)` on an unparseable line. The
[Go release gate](../../prismpath/examples/cli_worker/release_gate.go) reads `os.Stdin`, compares two
semver strings, and `os.Exit(1)` on a bad version. The
[Rust gate](../../prismpath/examples/cli_worker/ci_gate.rs) is the same CI gate as the Python one,
compiled. Same four-step contract, four languages, three jobs.

## Routing on what the worker emits

The flow reads the emitted JSON fields on plain deterministic edges (first true wins), with the error tier
last. From [`ci_gate.md`](../../prismpath/examples/cli_worker/ci_gate.md):

```markdown
## gate
Read the build report and decide whether to ship.
-> ship:         when passed and coverage >= 80
-> low_coverage: when passed
-> triage:       else
-> error_hold:   on error
```

A worker that prints `{"passed": true, "coverage": 91}` routes to `ship`; `{"passed": true, "coverage":
71}` routes to `low_coverage`; a failed build routes to `triage`; and a worker that exits nonzero routes to
`error_hold`.

## Failures are edges, not exceptions

A nonzero exit or a timeout becomes a `CliWorkerError` on the **error tier**, so a retry budget and an
escalation path are edges in the document, not wrapper code:

```markdown
-> retry:  on error when error_count < 3
-> giveup: on error
```

## Different engines at different nodes

Map each node to its own command (unmapped nodes fall back to `default`, or route to the error tier if
there is none):

```python
cli_agent({"gate": ["python", "ci_gate.py"], "alert": ["node", "log_alert.js"]}, default=["./release_gate"])
```

A cheap engine's outcome can decide, on a `when` edge, whether its work stands or escalates to an
expensive one: the routing spectrum, one layer up.

## Trust boundary, stated plainly

A CLI worker is **arbitrary code execution by design**: you chose to run that program, exactly as you
choose any dependency. PrismPath's proof is about the **routing** layer (the `when` evaluator runs no
worker-influenced code, ever); it is not, and cannot be, a claim that your worker is safe. For untrusted
or effectful **Python** specifically, a [code node](code-nodes.md) runs the function in a
capability-scoped sandbox derived from its declared envelope.

## Proof

The four workers and their flows are in
[`prismpath/examples/cli_worker/`](../../prismpath/examples/cli_worker/). The contract is gated in
[`prismpath/tests/test_cli_worker_example.py`](../../prismpath/tests/test_cli_worker_example.py): each flow
routes every case (including the nonzero-exit case onto the error tier). The Python gate runs always; the
Rust gate, the Node alerter, and the Go release gate run wherever their toolchain is installed (the Go
worker was recertified on Go 1.26 and the Rust worker on rustc 1.97; CI is Python-only).
