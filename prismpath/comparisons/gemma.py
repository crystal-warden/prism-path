# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Shared LLM client for the Area-5 head-to-head, instrumented for the measured table.

Every baseline that consults a model routes through the SAME local endpoint, the SAME model, and
the SAME routing prompt (`routing_prompt` below) — so the measured differences are attributable to
the *routing strategy* (embed-first vs LLM-every-hop) and the *framework machinery*, not to prompt
engineering or a stronger model on one side.

Endpoint defaults to the local gemma4 server (OpenAI-compatible). Override with env:
    GEMMA_BASE   (default http://localhost:8888/v1)
    GEMMA_MODEL  (default gemma4)
    GEMMA_KEY    (default "x" — local servers ignore it)
"""
from __future__ import annotations

import os
import time

BASE = os.environ.get("GEMMA_BASE", "http://localhost:8888/v1")
MODEL = os.environ.get("GEMMA_MODEL", "gemma4")
KEY = os.environ.get("GEMMA_KEY", "x")


def routing_prompt(instruction: str, outcome: str, edges) -> str:
    """The one routing prompt every LLM-consulting baseline uses — identical to
    prismpath.router.LLMRouter's, so LLM-router / LangGraph / CrewAI / prismpath-on-doubt all ask the
    model the exact same question and only the *strategy* around it differs."""
    opts = "\n".join(f"{i + 1}. {cond}" for i, (_, cond) in enumerate(edges))
    return (
        "You route a workflow. Given the current step and the outcome of the work, pick "
        "the ONE option that best matches what should happen next.\n\n"
        f"Current step: {instruction}\n"
        f"Outcome of the work: {outcome}\n\n"
        f"Options:\n{opts}\n\n"
        "Reply with ONLY the number of the best option.")


class Gemma:
    """OpenAI-compatible chat wrapper that counts calls and records per-call latency."""

    def __init__(self, temperature: float = 0.0, base: str = BASE, model: str = MODEL):
        import openai
        self._c = openai.OpenAI(base_url=base, api_key=KEY)
        self.model = model
        self.temperature = temperature
        self.calls = 0
        self.latencies: list[float] = []

    def generate(self, prompt: str) -> str:
        t = time.perf_counter()
        r = self._c.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=self.temperature,
            max_tokens=16)
        self.latencies.append(time.perf_counter() - t)
        self.calls += 1
        return (r.choices[0].message.content or "").strip()

    def reset(self):
        self.calls = 0
        self.latencies = []
