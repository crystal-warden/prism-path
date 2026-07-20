"""cli_worker.py — ANY command-line program as a flow worker (the generic subprocess contract).

The engine's worker interface is `agent(node, instruction, state) -> str | dict`. This module
adapts the most stable interface in software — a process with stdin/stdout/exit-code — onto it,
so a Claude/Gemini/aider CLI, a task-file runner, or a shell script can be a node's worker with
no Python written by the flow author. The contract:

  * **stdout is the outcome.** If stdout parses as a JSON object, it becomes the DICT outcome —
    its fields feed `when` predicates directly (`{"text": "…", "tests_pass": true}` routes
    `-> done: when tests_pass` deterministically). Anything else is the outcome TEXT.
  * **Nonzero exit RAISES** (`CliWorkerError`, exit code + stderr tail in the message) — which
    lands on the flow's ERROR TIER: `-> retry: on error when error_count < 3` gives any CLI a
    retry budget and a human-escalation path as *edges in the document*, no wrapper code.
  * **Timeout raises** the same way (`on error when "timeout" in error_message` is routable).
  * **The prompt goes to stdin** (default) — the node's instruction plus a JSON context block —
    or into argv/env via templating, for CLIs that take files or flags instead.

Trust boundary, stated bluntly: a CLI worker is **arbitrary code execution by design** — you are
choosing to run that program, exactly as you choose any worker. prismpath's sandbox claim is about
the ROUTING layer (the `when` predicate evaluator executes no worker-influenced code, ever); it
is not, and cannot be, a claim that your workers are safe. Choose your commands like you choose
your dependencies.

    from prismpath.cli_worker import CliWorker, cli_agent

    # every node runs the same CLI, prompt on stdin:
    agent = cli_agent(["claude", "-p"])

    # or per-node commands, with templating ({node}/{instruction} in args; state via stdin JSON):
    agent = cli_agent({
        "implement": ["md", "tasks/implement.claude.md"],
        "review":    ["md", "tasks/review.gemini.md"],
    }, default=["claude", "-p"])

Engine-heterogeneous routing falls out: different nodes run different engines, and a `when`
predicate on the cheap engine's outcome decides whether its work stands or escalates to the
expensive one — the escalation philosophy lifted one layer up.
"""
from __future__ import annotations

import json
import subprocess
from typing import Dict, List, Optional, Sequence, Union

DEFAULT_TIMEOUT = 600.0
_STDERR_TAIL = 800


class CliWorkerError(RuntimeError):
    """A CLI worker failed (nonzero exit, timeout, or unlaunchable command). The message carries
    the exit code / reason and a stderr tail, so error-tier predicates can route on
    `error_message` content — the portable fields (`error_type` is language-specific; see SPEC
    §5.3)."""


def _render(arg: str, node: str, instruction: str) -> str:
    """Template {node} and {instruction} into an argv element. Unknown braces are left alone (a
    JSON literal in an arg must not explode); templating failures are the author's to see."""
    return arg.replace("{node}", node).replace("{instruction}", instruction)


def _outcome_from_stdout(stdout: str):
    """JSON object on stdout -> dict outcome (fields feed predicates); anything else -> text.
    Only a top-level JSON OBJECT is treated as structured — a bare number/string/array on stdout
    is far more likely to be plain program output than an outcome contract."""
    s = stdout.strip()
    if s.startswith("{") and s.endswith("}"):
        try:
            obj = json.loads(s)
            if isinstance(obj, dict):
                obj.setdefault("text", s)
                return obj
        except ValueError:
            pass
    return s


class CliWorker:
    """One command as a worker. `command` is an argv list; `{node}`/`{instruction}` are templated
    into args. Unless `stdin=False`, the process receives the instruction and a JSON context block
    (node name + the state fields listed in `pass_state`) on stdin."""

    def __init__(self, command: Sequence[str], timeout: float = DEFAULT_TIMEOUT,
                 stdin: bool = True, pass_state: Optional[Sequence[str]] = None,
                 cwd: Optional[str] = None, env: Optional[dict] = None):
        self.command = list(command)
        self.timeout = float(timeout)
        self.stdin = stdin
        self.pass_state = list(pass_state or [])
        self.cwd = cwd
        self.env = env

    def _stdin_payload(self, node: str, instruction: str, state: dict) -> str:
        ctx = {k: state.get(k) for k in self.pass_state if k in state}
        block = ""
        if ctx:
            try:
                block = "\n\n[context]\n" + json.dumps({"node": node, **ctx}, default=str)
            except Exception:                             # noqa: BLE001 - context is best-effort
                block = ""
        return instruction + block

    def __call__(self, node: str, instruction: str, state: dict):
        argv = [_render(a, node, instruction) for a in self.command]
        payload = self._stdin_payload(node, instruction, state) if self.stdin else None
        try:
            p = subprocess.run(argv, input=payload, capture_output=True, text=True,
                               timeout=self.timeout, cwd=self.cwd, env=self.env)
        except subprocess.TimeoutExpired as e:
            raise CliWorkerError(
                f"cli worker timeout after {self.timeout:.0f}s: {' '.join(argv[:3])}…") from e
        except OSError as e:                              # command not found / not executable
            raise CliWorkerError(f"cli worker could not start ({argv[0]!r}): {e}") from e
        if p.returncode != 0:
            tail = (p.stderr or p.stdout or "").strip()[-_STDERR_TAIL:]
            raise CliWorkerError(
                f"cli worker exit {p.returncode} ({argv[0]}): {tail or '(no stderr)'}")
        return _outcome_from_stdout(p.stdout)


def cli_agent(commands: Union[Sequence[str], Dict[str, Sequence[str]]],
              default: Optional[Sequence[str]] = None, **kw):
    """Build an engine-ready agent from CLI command(s).

    * a single argv list -> every node runs that command;
    * a {node_name: argv} dict -> per-node commands (engine-heterogeneous routing), with
      `default` for unmapped nodes (no default -> unmapped nodes raise, landing on error edges).
    Extra kwargs (timeout, stdin, pass_state, cwd, env) apply to every constructed worker."""
    if isinstance(commands, dict):
        workers = {n: CliWorker(cmd, **kw) for n, cmd in commands.items()}
        fallback = CliWorker(default, **kw) if default else None

        def agent(node: str, instruction: str, state: dict):
            w = workers.get(node) or fallback
            if w is None:
                raise CliWorkerError(f"no CLI command mapped for node {node!r} and no default")
            return w(node, instruction, state)
        return agent
    return CliWorker(commands, **kw)
