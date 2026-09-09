# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""prismpath.code_nodes — code nodes as governed workers.

A **code node** is a node whose worker is plain code (not an LLM, not mdflow). It is the same worker
seam mdflow rides on (`connector.py`), applied to a local function. The thesis is preserved: PrismPath
**governs the routing, provably**; the code node is a *leaf action* that returns outcome fields, and the
branching stays on the flow's edges — never inside the code.

Two properties make a code node governed rather than a hole in the model:

1. **A declared capability envelope.** A code node carries `@code(net=…, fs=…, timeout_s=…, mem_mb=…)`
   on its node. The declaration is flow data — portable, inspectable, and statically checkable by any
   kernel (`check_code_nodes`), exactly like Level M membership.
2. **Fail-closed execution.** `code_agent` refuses to run a handler on a node that is *not* declared
   `@code` (no undeclared code sneaks in), refuses an invalid envelope, and refuses when no runner is
   supplied. The sandboxed runner (`prismpath.sandbox`) enforces the envelope at runtime; an in-process
   runner is available for trusted/pure code (tests, deterministic transforms).

Code nodes are **software-tier (P2)**: substrate-specific, never portable to another kernel or to the
Level M hardware target. Keep them leaf actions with routing on their outcome fields.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

_FS_MODES = {"none": "none", "ro": "ro", "readonly": "ro", "rw": "rw", "readwrite": "rw"}
_TRUE = {"true", "1", "yes", "on"}
_FALSE = {"false", "0", "no", "off"}
_ENVELOPE_KEYS = {"net", "fs", "timeout_s", "mem_mb"}


class CodeNodeError(Exception):
    """Raised when a code node cannot run under its governed contract (fail-closed)."""


@dataclass(frozen=True)
class Envelope:
    """The capability envelope a code node is permitted — the sandbox profile is derived from this."""
    net: bool = False
    fs: str = "none"            # none | ro | rw
    timeout_s: int = 10
    mem_mb: int = 256


def _as_bool(v, key: str, problems: List[str]) -> Optional[bool]:
    s = str(v).strip().lower()
    if s in _TRUE:
        return True
    if s in _FALSE:
        return False
    problems.append(f"{key}={v!r} is not a boolean")
    return None


def _as_pos_int(v, key: str, problems: List[str]) -> Optional[int]:
    try:
        n = int(str(v).strip())
    except (TypeError, ValueError):
        problems.append(f"{key}={v!r} is not an integer")
        return None
    if n <= 0:
        problems.append(f"{key}={v!r} must be positive")
        return None
    return n


def parse_envelope(anno: Optional[dict]) -> Tuple[Optional[Envelope], List[str]]:
    """Parse a node's `@code(...)` annotation dict into an Envelope, or return the reasons it is invalid.

    `anno is None` means the node is not declared `@code` at all — a distinct, reported error."""
    if anno is None:
        return None, ["node is not declared @code (no capability envelope)"]
    problems: List[str] = []
    unknown = set(anno) - _ENVELOPE_KEYS
    if unknown:
        problems.append(f"unknown @code key(s): {', '.join(sorted(unknown))}")
    kw: dict = {}
    if "net" in anno:
        b = _as_bool(anno["net"], "net", problems)
        if b is not None:
            kw["net"] = b
    if "fs" in anno:
        m = str(anno["fs"]).strip().lower()
        if m in _FS_MODES:
            kw["fs"] = _FS_MODES[m]
        else:
            problems.append(f"fs={anno['fs']!r} must be one of none|ro|rw")
    if "timeout_s" in anno:
        n = _as_pos_int(anno["timeout_s"], "timeout_s", problems)
        if n is not None:
            kw["timeout_s"] = n
    if "mem_mb" in anno:
        n = _as_pos_int(anno["mem_mb"], "mem_mb", problems)
        if n is not None:
            kw["mem_mb"] = n
    if problems:
        return None, problems
    return Envelope(**kw), []


def is_code_node(node) -> bool:
    """A node is a code node iff it declares an `@code` annotation."""
    return "code" in getattr(node, "annotations", {})


def check_code_nodes(graph) -> List[str]:
    """Static gate: every `@code` node must declare a valid envelope. [] means the flow is clean.

    A portable, verifiable property (any kernel can check it from the flow alone), like Level M."""
    problems: List[str] = []
    for name in sorted(graph.nodes):
        node = graph.nodes[name]
        anno = node.annotations.get("code")
        if anno is None:
            continue
        _env, probs = parse_envelope(anno)
        problems.extend(f"code node {name!r}: {p}" for p in probs)
    return problems


# A runner executes a code handler under an envelope: (handler, env, node, instruction, state) -> outcome.
Runner = Callable[[Callable, Envelope, str, str, dict], object]


def in_process_runner(handler: Callable, env: Envelope, node: str, instruction: str, state: dict):
    """Trusted, in-process execution — for pure/deterministic code (tests, transforms). Does NOT
    enforce the envelope. Use `prismpath.sandbox.SandboxRunner` for untrusted or effectful code."""
    return handler(node, instruction, state)


def code_agent(graph, handlers: Dict[str, Callable], runner: Optional[Runner] = None,
               base: Optional[Callable] = None) -> Callable[[str, str, dict], object]:
    """Build a flow agent that dispatches code nodes through `runner`, fail-closed.

    - a handler on a node NOT declared `@code`  -> CodeNodeError (no undeclared code)
    - an invalid `@code` envelope               -> CodeNodeError
    - a code node hit with no `runner`          -> CodeNodeError (loud absence, never run silently)
    - a node with no handler                    -> delegated to `base` (or a text passthrough)
    """
    def agent(node: str, instruction: str, state: dict):
        handler = handlers.get(node)
        if handler is None:
            return base(node, instruction, state) if base else {"text": node}
        n = graph.nodes.get(node)
        anno = n.annotations.get("code") if n else None
        env, problems = parse_envelope(anno)
        if env is None:
            raise CodeNodeError(f"code node {node!r}: {'; '.join(problems)}")
        if runner is None:
            raise CodeNodeError(
                f"code node {node!r}: no runner supplied — refusing to execute code un-governed "
                f"(pass prismpath.sandbox.SandboxRunner, or in_process_runner for trusted code)")
        return runner(handler, env, node, instruction, state)

    return agent
