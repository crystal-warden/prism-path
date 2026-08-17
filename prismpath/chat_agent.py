# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""chat_agent.py — any OpenAI-compatible chat endpoint as a flow worker, stdlib only.

The five-minutes-after-clone path for people who already run local models:

    prismpath run flow.md --agent ollama:llama3.2          # Ollama's built-in /v1 endpoint
    prismpath run flow.md --agent openai:MODEL@http://host:8888/v1   # vLLM / LM Studio / llama.cpp / any

Contract (same honesty as cli_worker): the node's instruction is the user message, with the
previous hop's outcome appended as context. If the model replies with JSON (bare or fenced), the
fields feed `when` predicates directly — which is what well-written node instructions ask for;
plain text routes semantically. Connection failures, non-200s, and timeouts RAISE — landing on the
flow's `on error` edges, so retry budgets stay readable in the document instead of hidden here.

No API key is required for local endpoints; OPENAI_API_KEY is sent if set. OLLAMA_HOST overrides
the Ollama default (http://localhost:11434).
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request

DEFAULT_TIMEOUT = 120.0


class ChatAgentError(RuntimeError):
    """A worker-tier failure (endpoint down, non-200, timeout) — rides the flow's error edges."""


def parse_spec(spec: str):
    """'ollama:MODEL' | 'openai:MODEL@BASE' -> (base_url, model). Loud on malformed specs."""
    kind, _, rest = spec.partition(":")
    if kind == "ollama":
        if not rest:
            raise ValueError("--agent ollama needs a model: e.g. --agent ollama:llama3.2 "
                             "(`ollama list` shows what you have)")
        base = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
        return f"{base}/v1", rest
    if kind == "openai":
        model, _, base = rest.partition("@")
        if not model or not base:
            raise ValueError("--agent openai needs MODEL@BASE: e.g. "
                             "--agent openai:gemma4@http://localhost:8888/v1")
        return base.rstrip("/"), model
    raise ValueError(f"unknown agent spec {spec!r} (use ollama:MODEL or openai:MODEL@BASE)")


def _extract_json(text: str):
    """A JSON object in the reply (bare, or inside a ``` fence) -> dict, else None."""
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S) or re.search(r"(\{.*\})", text, re.S)
    if not m:
        return None
    try:
        obj = json.loads(m.group(1))
        return obj if isinstance(obj, dict) else None
    except ValueError:
        return None


def chat_agent(spec: str, timeout: float = DEFAULT_TIMEOUT, temperature: float = 0.0):
    """An engine-compatible agent(node, instruction, state) backed by an OpenAI-compatible endpoint."""
    base, model = parse_spec(spec)
    url = f"{base}/chat/completions"

    def agent(node, instruction, state):
        prior = (state.get("transcript") or [])
        context = f"\n\nPrevious step's outcome: {prior[-1]['outcome']}" if prior else ""
        body = json.dumps({
            "model": model,
            "temperature": temperature,
            "messages": [
                {"role": "system",
                 "content": "You are a worker executing one node of a workflow. Follow the node's "
                            "instruction exactly. If it asks for JSON, reply with ONLY that JSON."},
                {"role": "user", "content": f"{instruction}{context}"},
            ],
        }).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if os.environ.get("OPENAI_API_KEY"):
            headers["Authorization"] = f"Bearer {os.environ['OPENAI_API_KEY']}"
        req = urllib.request.Request(url, data=body, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                reply = json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as e:
            raise ChatAgentError(f"[{node}] {model} at {base}: {e.reason if hasattr(e, 'reason') else e}") from e
        except TimeoutError as e:
            raise ChatAgentError(f"[{node}] {model} at {base}: timeout after {timeout}s") from e
        try:
            text = reply["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as e:
            raise ChatAgentError(f"[{node}] malformed response from {base}: {e}") from e
        fields = _extract_json(text)
        if fields is not None:
            fields.setdefault("text", text.strip())
            return fields
        return text.strip()

    return agent
