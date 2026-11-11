# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The Python engine as an oracle for prismpath-rs/tests/test_engine_cross_language.rs.

Reads {"scenarios": [...], "fuzz": {"seed": N, "count": M}} on stdin; runs every scenario, and M scenarios
it generates from the seed, on the Python engine; writes [{"scenario": ..., "python": ...}, ...] on stdout.
A scenario is a flow, a scripted worker and the engine's options; a locked scenario adds a lock and the
embedding of each outcome, which is how the Rust engine routes a semantic edge.

What it records is everything the engine surface holds: the path, the stop and its cause, the pending
decision, the persisted transcript and what the bound dropped, the visit counters, each step's node and
target, every `on_step` call and every routing decision record, in the order they were made.
"""
import base64
import json
import random
import sys
import warnings

warnings.simplefilter("ignore")

import numpy as np  # noqa: E402

from prismpath.kernel.engine import StepLog, run  # noqa: E402
from prismpath.kernel.parser import parse  # noqa: E402
from prismpath.routing import embedder as emb_mod  # noqa: E402
from prismpath.routing.lockfile import _decode_vec  # noqa: E402
from prismpath.routing.router import LockedEmbeddingRouter  # noqa: E402


def raised(outcome):
    """The worker's failure: an exception whose class is named by `__kind__`. Without it the class is `Error`,
    which is the kind a Rust worker that returns a plain message reports (DIVERGENCES.md)."""
    return type(outcome.get("__kind__", "Error"), (Exception,), {})(outcome["__raise__"])


def scripted(script):
    used = {}

    def agent(node, instruction, state):
        seq = script.get(node)
        if seq is None:
            return {"text": node}
        index = used.get(node, 0)
        used[node] = index + 1
        outcome = seq[min(index, len(seq) - 1)]
        if isinstance(outcome, dict) and "__raise__" in outcome:
            raise raised(outcome)
        return outcome
    return agent


def run_scenario(sc):
    graph = parse(sc["flow"])
    state = json.loads(json.dumps(sc["state"])) if sc.get("state") is not None else None
    router, original_embed = None, emb_mod.embed
    if sc.get("lock"):
        conds = {text: _decode_vec(b64) for text, b64 in sc["lock"]["conditions"].items()}
        for text, pin in sc["lock"].get("centroids", {}).items():
            conds[text] = _decode_vec(pin["vec"])
        router = LockedEmbeddingRouter(conds)
        embed_map = {text: _decode_vec(b64) for text, b64 in sc["embedMap"].items()}
        dim = sc["lock"]["embedder"]["dim"]

        def stub(texts, is_query=False):
            out = []
            for probe in texts:
                if is_query:
                    probe = probe.replace(emb_mod.QUERY_INSTRUCTION, "")
                out.append(embed_map.get(probe, np.zeros(dim, dtype="float32")))
            return np.array(out, dtype="float32")
        emb_mod.embed = stub
    calls, decisions = [], []

    def on_step(res, pending_node):
        calls.append([pending_node, res.stopped, len(res.path), len(res.steps)])

    seed_steps = [StepLog(step["node"], "", step["target"], {"used": step["used"]}) for step in sc.get("seed_steps", [])]
    try:
        res = run(graph, scripted(sc["script"]), router=router, max_steps=sc.get("maxSteps", 25), start=sc.get("start"),
                  state=state, human_floor=sc.get("humanFloor"), on_step=on_step, on_decision=decisions.append,
                  run_id=sc.get("run_id"), _seed_path=sc.get("seed_path") or None, _seed_steps=seed_steps or None,
                  **sc.get("opts", {}))
    except Exception as exc:  # noqa: BLE001 - the message is what the two engines are compared on
        return {"error": str(exc), "error_class": type(exc).__name__}
    finally:
        emb_mod.embed = original_embed
    pending = res.pending
    return {
        "path": res.path, "stopped": res.stopped, "cause": res.cause,
        "pending": None if pending is None else {
            "node": pending.get("node"), "reason": pending.get("reason"), "violations": pending.get("violations"),
            "would_pick": pending.get("would_pick"), "wait": bool(pending.get("wait")),
            "awaiting": pending.get("awaiting"), "timeout_s": pending.get("timeout_s"), "spawn": pending.get("spawn")},
        "transcript": res.state["transcript"], "state_dropped": res.state.get("_state_dropped", {}),
        "visits": res.state["visits"],
        # each step's node and target and everything its info holds: how it was routed, the condition or the scores
        # of a semantic route (locked), the worker's error kind and the count of unevaluable guards
        "steps": [{"node": step.node, "target": step.target, **step.info} for step in res.steps],
        # which guard of which node could not be evaluated: the message is each language's own words
        "guard_errors": [[item["node"], item["guard"]] for item in res.state.get("_guard_errors", [])],
        "on_step": calls, "decisions": decisions,
    }


# ------------------------------------------------------------------------------------- the fuzz
def encode(vector):
    return base64.b64encode(np.asarray(vector, dtype="<f4").tobytes()).decode("ascii")


def unit(rng, dim=4):
    vector = np.array([rng.random() - 0.3 for _ in range(dim)], dtype="float32")
    return vector / np.linalg.norm(vector)


ERROR_GUARDS = ["", " when error_count >= 2", " when error_type == \"ValueError\"",
                " when error_type in [\"OSError\", \"TimeoutError\"]", " when error_message == \"boom\"",
                " when error_type != \"Error\" and error_count < 3",
                " when len(error_message) > 3", " when error_message ==", " when error_count >= 1 and f(error_type)"]

DET_EDGES = [
    "when ok", "when not ok", "when kind == \"a\"", "when kind in [\"a\", \"b\"]", "when n >= 3", "when n < 2",
    "when ok and n > 0", "when visits < 3", "when visits >= 3", "when tag == \"x\" or ok", "always", "else",
]


def make_flow(rng, locked):
    names = [f"n{index}" for index in range(rng.randint(2, 5))]
    lines = ["---", "name: fuzz", f"start: {names[0]}", "---"]
    conditions = []
    for index, name in enumerate(names):
        lines += [f"## {name}", "Do the work."]
        if rng.random() < 0.25:
            bound = rng.choice(["1", "2", "3", "5", "1_0"] if rng.random() < 0.9 else ["0", "x", "-2"])
            lines.append(f"@state_bound(transcript={bound})")
        if index == len(names) - 1 and rng.random() < 0.6:
            lines.append("")
            continue
        for _ in range(rng.randint(1, 3)):
            target = rng.choice(names) if rng.random() > 0.05 else "ghost"
            draw = rng.random()
            if locked and draw < 0.35:
                condition = f"cond {len(conditions)}"
                conditions.append(condition)
            elif draw < 0.45:
                condition = "on error" + rng.choice(ERROR_GUARDS)
            elif draw < 0.5:
                condition = "on event go"
            elif draw < 0.55:
                condition = "on timeout"
            else:
                condition = rng.choice(DET_EDGES)
            lines.append(f"-> {target}: {condition}")
        lines.append("")
    return "\n".join(lines) + "\n", names, conditions


def make_outcome(rng):
    draw = rng.random()
    if draw < 0.08:
        failure = {"__raise__": rng.choice(["boom", "kaboom"])}
        if rng.random() < 0.7:
            failure["__kind__"] = rng.choice(["ValueError", "TimeoutError", "OSError", "Error"])
        return failure
    if draw < 0.12:
        return "plain text"
    if draw < 0.15:
        return {"text": "ask", "needs_human": True, "reason": "unsure"}
    if draw < 0.18:
        return {"text": "hold", "wait": True, "timeout_s": 30}
    outcome = {"text": rng.choice(["alpha", "beta", "gamma", "alpha beta"])}
    for field, options in (("ok", [True, False, None, "yes", 1, 0]), ("kind", ["a", "b", "c", None, 7, True]),
                           ("n", [0, 1, 2, 3, 9, 2.5, "3", True, None, [1]]), ("tag", ["x", "y", None, 3])):
        if rng.random() < 0.6:
            outcome[field] = rng.choice(options)
    return outcome


def make_scenario(rng):
    locked = rng.random() < 0.5
    flow, names, conditions = make_flow(rng, locked)
    script = {name: [make_outcome(rng) for _ in range(rng.randint(1, 4))] for name in names if rng.random() < 0.8}
    sc = {"flow": flow, "script": script, "maxSteps": rng.randint(2, 14), "opts": {}}
    if rng.random() < 0.5:
        sc["opts"]["type_gate"] = True
    if rng.random() < 0.35:
        sc["opts"]["max_transcript"] = rng.choice([0, 1, 2, 3, 5, 100])
    if rng.random() < 0.5:
        sc["run_id"] = f"run-{rng.randint(1, 999)}"
    if rng.random() < 0.2:
        sc["start"] = rng.choice(names)
        sc["state"] = {"visits": {sc["start"]: rng.randint(0, 3)},
                       "transcript": [{"node": "x", "outcome": f"old{index}"} for index in range(rng.randint(0, 6))]}
        if rng.random() < 0.3:
            sc["state"]["_guard_errors"] = [{"node": rng.choice(names), "guard": "when f(x)", "error": "earlier"}
                                            for _ in range(rng.randint(1, 3))]
        if rng.random() < 0.5:
            sc["state"]["_state_dropped"] = {"transcript": rng.randint(0, 5)}
        if rng.random() < 0.5:
            sc["seed_path"] = [rng.choice(names) for _ in range(rng.randint(1, 6))]
            sc["seed_steps"] = [{"node": rng.choice(names), "target": rng.choice(names), "used": "human"}
                                for _ in range(rng.randint(0, 6))]
    if locked and conditions:
        sc["lock"] = {"conditions": {cond: encode(unit(rng)) for cond in conditions}, "embedder": {"dim": 4}}
        texts = ["alpha", "beta", "gamma", "alpha beta", "plain text", "ask", "hold", "n0", "n1", "n2", "n3", "n4"]
        sc["embedMap"] = {text: encode(unit(rng)) for text in texts if rng.random() < 0.85}
        if rng.random() < 0.4:
            sc["humanFloor"] = rng.choice([0.2, 0.5, 0.8])
    elif locked:
        pass
    return sc


def main():
    request = json.load(sys.stdin)
    scenarios = list(request["scenarios"])
    fuzz = request.get("fuzz") or {}
    rng = random.Random(fuzz.get("seed", 0))
    for _ in range(fuzz.get("count", 0)):
        scenarios.append(make_scenario(rng))
    json.dump([{"scenario": sc, "python": run_scenario(sc)} for sc in scenarios], sys.stdout)


if __name__ == "__main__":
    main()
