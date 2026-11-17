# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""A stdio MCP proxy that decides every `tools/call` against the signed agent policy before the server sees it.

    python -m prismpath.agent.mcp_proxy [--policy P] [--runs DIR] [--session ID] [--keys DIR] -- SERVER ARGS...

The proxy starts the downstream MCP server command as a child process and relays newline delimited JSON-RPC
between its own standard streams (the client) and the child's. The child's standard error is the proxy's.
Everything is relayed as the same bytes, in order, except a client `tools/call`:

  1. the call's `name` and `arguments` are read into the classifier's call shape (mcp_map.py; a tool it does
     not know is `unknown`), classified against the workspace, and decided by the core against the policy;
  2. the decision is appended as a receipt to the proxy session's run (run.RunStore), durably, before
     anything else happens to the call;
  3. allow: the request's own bytes go to the child and the child's answer comes back as it is.
     refuse: the call is not forwarded; the client gets a result that is an MCP tool error (`isError: true`)
     whose text names the registered cause and the receipt index.
     escalate: the call is not forwarded either; the client gets a tool error saying the call needs the
     person's approval, with the cause and the receipt.

Why escalate answers with an error. A PrismPath escalation means "a person decides this call". MCP gives a
proxy no such answer to return: a `tools/call` result is a result or an error, and the client's own
confirmation prompt (if it has one) has already been passed when the request reaches the proxy. So the proxy
holds the call and says so in a tool error the model and the person can read; the call can be run by the
person outside the agent, or allowed by a changed signed policy. A later version could ask the person through
the protocol for clients that support elicitation: under the 2026-07-28 revision a server answers with an
`InputRequiredResult` carrying an `elicitation/create` input request and the client retries the call with the
person's `inputResponses` (multi round-trip requests). That needs the person's answer bound into the receipt
of the retried call, which is not designed yet, so it is not done here.

Fail closed. A policy that does not load, a run that cannot be opened, a mapping, classifier or decision
failure, or a receipt that is not durably appended refuses the call; no call is forwarded whose receipt
`append` did not return. Such a refusal has no core decision, so it names what failed and says that no
receipt was written. A client line that is not one well formed JSON-RPC message in UTF-8 (not JSON, a JSON
object with a repeated key anywhere, a bare value) is never forwarded either and is answered with a JSON-RPC
error with a null id: a repeated key is how a message could read as `tools/list` here and as `tools/call` to
a server whose parser keeps the first of two keys. A `tools/call` notification (no `id`) is decided and
receipted the same way and forwarded only when allowed; it gets no answer, since a notification has none.

Protocol. Written against the MCP specification revision 2026-07-28 (modelcontextprotocol.io, current on
2026-11-16): stateless requests with `_meta`, `server/discover`, `resultType` on every result, stdio framing of
one message per line with no embedded newline. The proxy keeps no protocol state, so the initialize era
(2025-11-25 and earlier: `initialize`, server to client requests and the client's responses to them) passes
through unchanged too. A proxy answer carries `resultType: "complete"` when the request names its protocol
version in `_meta` (the 2026-07-28 era) and leaves it out otherwise. JSON-RPC batches were allowed only by
the 2025-03-26 revision: a batch without a `tools/call` request is relayed unchanged; one with tools calls has
each call decided as above, the allowed part forwarded as one batch, and the withheld calls answered in a
batch of their own.

Workspace. Paths are classified against `--workspace` (default: the proxy's working directory), with the
classifier's toolchain directories (classifier.Config.for_workspace); the child is started in the proxy's
working directory, which is where a filesystem server's relative path points.

Policy. `--policy` names a `prismpath.core/1` image; by default it is `policy/agent_default.core.json` when
the package ships it (the default policy of the Claude Code adapter, which escalates what the classifier
cannot read) and `policy/agent_rules.core.json` otherwise, which refuses it with cause 104. Runs are kept
under `--runs` (default `$XDG_CONFIG_HOME/prismpath/agent/runs`), one per `--session` (default a fresh id
printed on standard error). With `--keys` the run is sealed when the proxy ends; `Run.verify` seals an open
run in any case.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Dict, List, Optional, Sequence

from . import classifier, mcp_map
from . import policy as policymod
from .run import RunStore

PROTOCOL_VERSION = "2026-07-28"
META_VERSION = "io.modelcontextprotocol/protocolVersion"
PARSE_ERROR, INVALID_REQUEST = -32700, -32600


def default_policy_path() -> Path:
    path = getattr(policymod, "DEFAULT_POLICY_PATH", policymod.HERE / "policy" / "agent_default.core.json")
    return Path(path) if Path(path).exists() else policymod.POLICY_PATH


def default_runs_root() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return Path(base) / "prismpath" / "agent" / "runs"


class _Repeated(ValueError):
    pass


def _pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise _Repeated(key)
        out[key] = value
    return out


def parse_message(line: bytes) -> Any:
    """The JSON value of one line, strict: UTF-8, one value, no repeated key in any object. Raises ValueError."""
    return json.loads(line.decode("utf-8"), object_pairs_hook=_pairs)


@dataclass(frozen=True)
class Outcome:
    kind: str                          # allow | refuse | escalate
    cause: Optional[str] = None
    code: Optional[int] = None
    receipt: Optional[int] = None
    failure: Optional[str] = None      # what failed, for a refusal with no core decision


class Governor:
    """The decision and the receipt of one `tools/call`, against one policy and one run."""

    def __init__(self, policy_path: Path, runs: Path, session: str, workspace: Path, server_cwd: str):
        self.session, self.server_cwd = session, server_cwd
        self.failure: Optional[str] = None
        self.policy = self.run = self.config = None
        try:
            self.config = classifier.Config.for_workspace(workspace)
            self.policy = policymod.Policy.load(policy_path)
        except Exception as exc:   # noqa: BLE001 - a policy that does not load refuses every call
            self.failure = f"the policy could not be loaded ({type(exc).__name__}: {exc})"
            return
        try:
            self.run = RunStore(runs).open(session, self.policy.image)
        except Exception as exc:   # noqa: BLE001
            self.failure = f"the run could not be opened ({type(exc).__name__}: {exc})"

    def decide(self, params: Any) -> Outcome:
        if self.failure:
            return Outcome("refuse", failure=self.failure)
        try:
            call = mcp_map.classifier_call(params, self.server_cwd)
            reading = classifier.classify(call, self.config)
            raw = self.policy.reading_bytes(reading)
            decision = self.policy.decide(raw)
        except Exception as exc:   # noqa: BLE001
            return Outcome("refuse", failure=f"the call could not be decided ({type(exc).__name__}: {exc})")
        try:
            index = self.run.append(raw, decision.verdict)
        except Exception as exc:   # noqa: BLE001 - never forward a call whose receipt is not durable
            return Outcome("refuse", failure=f"its receipt could not be written ({type(exc).__name__}: {exc})")
        return Outcome(decision.kind, decision.cause, decision.cause_code, index)

    def text(self, outcome: Outcome) -> str:
        if outcome.failure:
            return (f"PrismPath refused this call because {outcome.failure}. It was not sent to the server. "
                    f"No receipt was written.")
        cause = f"{outcome.cause} ({outcome.code})" if outcome.code is not None else f"{outcome.cause}"
        receipt = f"Receipt {outcome.receipt} of run {self.session}."
        if outcome.kind == "escalate":
            return (f"PrismPath holds this call for the person's approval: cause {cause}. The proxy cannot ask "
                    f"the person through MCP, so the call was not sent to the server. {receipt}")
        return f"PrismPath refused this call: cause {cause}. It was not sent to the server. {receipt}"


def tool_error(request: Dict[str, Any], text: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {"content": [{"type": "text", "text": text}], "isError": True}
    params = request.get("params")
    meta = params.get("_meta") if isinstance(params, dict) else None
    if isinstance(meta, dict) and META_VERSION in meta:
        result = {"resultType": "complete", **result}
    return {"jsonrpc": "2.0", "id": request.get("id"), "result": result}


def rpc_error(code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": None, "error": {"code": code, "message": message}}


def _encode(message: Any) -> bytes:
    return json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"


def _is_call(message: Any) -> bool:
    return isinstance(message, dict) and message.get("method") == "tools/call"


class Proxy:
    def __init__(self, governor: Governor, child_in: BinaryIO, client_out: BinaryIO):
        self.governor, self.child_in, self.client_out = governor, child_in, client_out
        self.out_lock = threading.Lock()

    def to_client(self, data: bytes) -> None:
        with self.out_lock:
            self.client_out.write(data)
            self.client_out.flush()

    def to_child(self, data: bytes) -> None:
        self.child_in.write(data)
        self.child_in.flush()

    def _withheld(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """None when the call may be forwarded; else the answer to send (or {} for a notification)."""
        outcome = self.governor.decide(message.get("params"))
        if outcome.kind == "allow":
            return None
        if "id" not in message:
            return {}
        return tool_error(message, self.governor.text(outcome))

    def client_line(self, line: bytes) -> None:
        if not line.strip():
            return
        body = line.rstrip(b"\r\n")
        try:
            message = parse_message(body)
        except _Repeated:
            self.to_client(_encode(rpc_error(INVALID_REQUEST, "a message with a repeated key is not forwarded")))
            return
        except ValueError:
            self.to_client(_encode(rpc_error(PARSE_ERROR, "the line is not one JSON value in UTF-8")))
            return
        if isinstance(message, dict):
            if _is_call(message):
                answer = self._withheld(message)
                if answer is not None:
                    if answer:
                        self.to_client(_encode(answer))
                    return
            self.to_child(line if line.endswith(b"\n") else line + b"\n")
            return
        if isinstance(message, list) and message:
            if not any(_is_call(element) for element in message):
                self.to_child(line if line.endswith(b"\n") else line + b"\n")
                return
            forward, answers = [], []
            for element in message:
                answer = self._withheld(element) if _is_call(element) else None
                if answer is None:
                    forward.append(element)
                elif answer:
                    answers.append(answer)
            if len(forward) == len(message):
                self.to_child(line if line.endswith(b"\n") else line + b"\n")
            elif forward:
                self.to_child(_encode(forward))
            if answers:
                self.to_client(_encode(answers))
            return
        self.to_client(_encode(rpc_error(INVALID_REQUEST, "the message is not a JSON-RPC object or batch")))


def _relay(source: BinaryIO, proxy: Proxy, done: threading.Event) -> None:
    try:
        for line in iter(source.readline, b""):
            proxy.to_client(line)
    except (OSError, ValueError):
        pass
    finally:
        done.set()


def _pump(source: BinaryIO, proxy: Proxy, done: threading.Event) -> None:
    try:
        for line in iter(source.readline, b""):
            proxy.client_line(line)
    except (BrokenPipeError, OSError, ValueError):
        pass
    finally:
        done.set()


def serve(command: Sequence[str], governor: Governor, client_in: BinaryIO, client_out: BinaryIO,
          keys: Optional[Path] = None) -> int:
    child = subprocess.Popen(list(command), stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0)
    proxy = Proxy(governor, child.stdin, client_out)
    done = threading.Event()
    relay = threading.Thread(target=_relay, args=(child.stdout, proxy, done), daemon=True)
    pump = threading.Thread(target=_pump, args=(client_in, proxy, done), daemon=True)
    relay.start()
    pump.start()
    done.wait()
    try:
        child.stdin.close()
    except OSError:
        pass
    try:
        code = child.wait(timeout=5)
    except subprocess.TimeoutExpired:
        child.terminate()
        try:
            code = child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            child.kill()
            code = child.wait()
    relay.join(timeout=2)
    if keys is not None and governor.run is not None:
        try:
            governor.run.seal(keys)
        except Exception as exc:   # noqa: BLE001 - the receipts are durable; verify seals them later
            sys.stderr.write(f"prismpath mcp proxy: the run was not sealed ({type(exc).__name__}: {exc})\n")
    return code


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m prismpath.agent.mcp_proxy",
                                     description="Decide every MCP tools/call against the signed agent policy.")
    parser.add_argument("--policy", type=Path, default=None, help="the prismpath.core/1 policy image")
    parser.add_argument("--runs", type=Path, default=None, help="the directory of runs, one per session")
    parser.add_argument("--session", default=None, help="the session id of this proxy's run")
    parser.add_argument("--workspace", type=Path, default=None, help="the workspace paths are classified against")
    parser.add_argument("--keys", type=Path, default=None, help="seal the run with these keys when the proxy ends")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="-- the MCP server command and its arguments")
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("name the MCP server command after --")
    session = args.session or f"mcp-{time.strftime('%Y%m%dT%H%M%S')}-{uuid.uuid4().hex[:8]}"
    if not args.session:
        sys.stderr.write(f"prismpath mcp proxy: session {session}\n")
    governor = Governor(args.policy or default_policy_path(), args.runs or default_runs_root(), session,
                        args.workspace or Path.cwd(), os.getcwd())
    if governor.failure:
        sys.stderr.write(f"prismpath mcp proxy: every tools/call will be refused: {governor.failure}\n")
    return serve(command, governor, sys.stdin.buffer, sys.stdout.buffer, args.keys)


if __name__ == "__main__":
    sys.exit(main())
