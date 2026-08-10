# cli_worker: run any program as a worker

Four language workers across three jobs, all on the same contract: **read the request on stdin, print ONE
JSON object on stdout, exit 0.** A nonzero exit routes to the flow's error tier. Each worker pairs with a
flow that routes on the fields it emits. Python and Rust run the *same* job (a CI gate) to show one job
porting across languages with no change to the flow; the broader point is that any program, in any
language, doing any job, plugs in the same way.

| worker | language | job | emits | flow |
|---|---|---|---|---|
| [`ci_gate.py`](ci_gate.py) | Python | a CI test / coverage gate | `{passed, failed, coverage}` | [`ci_gate.md`](ci_gate.md) |
| [`ci_gate.rs`](ci_gate.rs) | Rust | the same CI gate, second language | `{passed, failed, coverage}` | [`ci_gate.md`](ci_gate.md) |
| [`log_alert.js`](log_alert.js) | JavaScript | log-line severity + latency alerting | `{level, latency_ms}` | [`log_alert.md`](log_alert.md) |
| [`release_gate.go`](release_gate.go) | Go | a semver release gate | `{bump, breaking}` | [`release_gate.md`](release_gate.md) |

Full walkthrough: [docs/guides/workers.md](../../../docs/guides/workers.md).

## Run one

Python and Node need no build step:

```python
from prismpath.parser import parse_file
from prismpath.engine import run
from prismpath.cli_worker import cli_agent

agent = cli_agent(["python", "ci_gate.py"], pass_state=["report"])
res = run(parse_file("ci_gate.md"), agent, state={"report": "tests=48 failed=0 coverage=91"})
print(res.path)          # ['gate', 'ship']
```

Go and Rust build first, then point `cli_agent` at the binary:

```bash
go build -o release_gate release_gate.go     # Go
rustc -O ci_gate.rs                          # Rust
```
```python
agent = cli_agent(["./release_gate"], pass_state=["from", "to"])
```

The contract is proven in
[`prismpath/tests/test_cli_worker_example.py`](../../tests/test_cli_worker_example.py): Python always, and
Node, Go, and Rust whenever their toolchain is present (the Go worker was recertified on Go 1.26, the Rust
worker on rustc 1.97).
