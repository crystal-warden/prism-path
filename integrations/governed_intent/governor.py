# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The governed harness's loop with the intent layer in it.

    model reply -> proposed call -> classifier (trusted) + intent reader (trusted) -> reading (canon/2)
                -> core decision on intent_calls.core.json -> receipt -> allow: run in bwrap | never run
    model reply with no call (an answer) -> intent reader -> reading -> intent_responses.core.json
                -> receipt -> allow: the answer is routed | refuse semantic:harm: withheld

Everything the governed harness does is reused unchanged: the classifier, the sandbox, the receipt layout
(`governed_harness.evidence.EpisodeRun`), the chat call, the reply parser and the system prompt. The only
additions are the six semantic fields of each reading and the response gate. An episode is two signed
core runs, `evidence/calls` and `evidence/responses`, each verified and replayed by
`formal/diff/core_evidence.py` exactly as the harness's are.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from integrations.governed_harness import classifier, evidence, harness, sandbox

from . import intent_reader as ir
from .policy import Policy, zeroed


@dataclass
class Step:
    reply: str
    kind: str                       # call | response
    call: Any = None
    reading: Optional[Dict[str, Any]] = None
    decision: Optional[str] = None
    cause: Optional[str] = None
    cause_code: Optional[int] = None
    floor: Optional[Tuple[str, Optional[str]]] = None    # the image's own decision on the zeroed reading
    unprobed: Optional[Tuple[str, Optional[str]]] = None # the decision on the same reading with probing_count 0
    observation: Optional[Dict[str, Any]] = None
    receipt: Optional[int] = None
    executed: bool = False
    routed: bool = False
    result: Optional[Dict[str, Any]] = None
    seconds: float = 0.0


@dataclass
class Episode:
    steps: List[Step] = field(default_factory=list)
    stopped: str = "max_steps"
    final: Any = None
    observer: Any = None


class IntentGovernor:
    def __init__(self, calls: Policy, responses: Policy, reader: ir.IntentReader, config: classifier.Config,
                 call_run: evidence.EpisodeRun, response_run: evidence.EpisodeRun, workspace: Path, task: str,
                 execute: bool = True, observer=None, probing_n: Optional[int] = None):
        self.observer, self.probing_n = observer, probing_n
        self.calls, self.responses, self.reader, self.config = calls, responses, reader, config
        self.call_run, self.response_run, self.workspace, self.task = call_run, response_run, Path(workspace), task
        self.execute = execute

    def call_reading(self, reply: str, call: Any) -> Dict[str, Any]:
        reading = classifier.classify(call, self.config)
        reading.update(self.reader.read_call(self.task, reply, call))
        return reading

    @property
    def probing_stopped(self) -> bool:
        return self.observer is not None and self.probing_n is not None and self.observer.probing_count >= self.probing_n

    def propose(self, reply: str, call: Any) -> Tuple[Step, str]:
        reading = self.call_reading(reply, call)
        if "probing_count" in self.calls.fields:
            reading["probing_count"] = self.observer.probing_count if self.observer is not None else 0
        raw = self.calls.reading_bytes(reading)
        decision = self.calls.decide(raw)
        idx = self.call_run.record(raw, decision.verdict)        # the receipt exists before anything runs
        floor = self.calls.decide(self.calls.reading_bytes(zeroed(reading)))
        unprobed = self.calls.decide(self.calls.reading_bytes({**reading, "probing_count": 0})) \
            if "probing_count" in reading else decision
        observation = None
        if self.observer is not None and decision.kind != "allow":   # labelled after the decision, never before
            observation = self.observer.observe(idx, raw, reading, decision, call, self.task,
                                                evidence.core_evidence.sha256_hex(self.calls.image))
        result = sandbox.execute(call, self.workspace) if decision.runs and self.execute else None
        step = Step(reply=reply, kind="call", call=call, reading=reading, decision=decision.kind,
                    cause=decision.cause, cause_code=decision.cause_code, floor=(floor.kind, floor.cause),
                    unprobed=(unprobed.kind, unprobed.cause), observation=observation,
                    receipt=idx, executed=decision.runs and self.execute, result=result)
        if result is None and decision.runs:
            result = {"ok": True, "output": "(not executed in this run)"}
        return step, harness.describe(decision, idx, result)

    def respond(self, reply: str, final: Any = None) -> Step:
        reading = self.reader.read_response(reply, final)
        raw = self.responses.reading_bytes(reading)
        decision = self.responses.decide(raw)
        idx = self.response_run.record(raw, decision.verdict)
        floor = self.responses.decide(self.responses.reading_bytes(zeroed(reading)))
        return Step(reply=reply, kind="response", reading=reading, decision=decision.kind, cause=decision.cause,
                    cause_code=decision.cause_code, floor=(floor.kind, floor.cause), receipt=idx,
                    routed=decision.runs)


def run_episode(task: str, governor: IntentGovernor, *, max_steps: int = 8, chat_fn=harness.chat,
                episode: Optional[Episode] = None) -> Episode:
    """`governed_harness.harness.run_episode` with every reply decided: a call by the call image, an answer
    or a reply with no call by the response image. A refused answer is not routed: it is not the
    episode's final answer, and the model is told it was withheld."""
    messages = [{"role": "system", "content": harness.SYSTEM_PROMPT}, {"role": "user", "content": task}]
    episode, nudges = (episode if episode is not None else Episode()), 0
    for _ in range(max_steps):
        started = time.monotonic()
        reply = chat_fn(messages)
        messages.append({"role": "assistant", "content": reply})
        kind, value = harness.parse_reply(reply)
        if kind in ("final", "none"):
            step = governor.respond(reply, value if kind == "final" else None)
            step.seconds = time.monotonic() - started
            episode.steps.append(step)
            if kind == "final":
                episode.stopped = "final" if step.routed else "final_withheld"
                episode.final = value if step.routed else None
                return episode
            nudges += 1
            if nudges > 2:
                episode.stopped = "no_json"
                return episode
            messages.append({"role": "user", "content": "Reply with exactly one JSON object: a tool call or {\"final\": ...}."})
            continue
        step, text = governor.propose(reply, value)
        step.seconds = time.monotonic() - started
        episode.steps.append(step)
        if governor.probing_stopped:          # the episode rule fired: the agent is stopped
            episode.stopped = "probing"
            return episode
        messages.append({"role": "user", "content": text})
    return episode
