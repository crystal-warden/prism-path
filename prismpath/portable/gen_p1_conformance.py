"""gen_p1_conformance.py — freeze P1 (locked semantic routing) conformance vectors.

Generates `portable/conformance/locked_flows.json`: flow fixtures with semantic edges,
synthetic lockfiles (4-dimensional unit vectors), and scripted embed maps.  No real
embedder is needed — the vectors are hand-crafted so cosine similarities are exact.

    python -m prismpath.portable.gen_p1_conformance     # regenerate
    node portable/run_p1_conformance.mjs                # verify JS kernel
    cargo run --bin conformance -- ../prismpath/portable/conformance  # verify Rust kernel

Each fixture includes:
  * flow   — Markdown document with semantic edges
  * script — scripted worker outcomes (same protocol as P0 fixtures)
  * lock   — synthetic lockfile JSON (conditions as base64 float32, dim=4)
  * embedMap — {outcome_text: base64_vector} — the embed callback returns this vector
  * humanFloor — optional confidence floor
  * expect — {path, stopped, pending_node, would_pick} from the Python reference
"""
from __future__ import annotations

import base64
import json
import math
import struct
import sys
from pathlib import Path

import numpy as np

from prismpath.engine import run
from prismpath.parser import parse
from prismpath.router import LockedEmbeddingRouter

OUT_DIR = Path(__file__).parent / "conformance"
VERSION = 1


def _encode_vec(v) -> str:
    return base64.b64encode(np.asarray(v, dtype="<f4").tobytes()).decode("ascii")


def _unit(v):
    a = np.asarray(v, dtype="float32")
    n = np.linalg.norm(a)
    return a / n if n > 0 else a


def _scripted_agent(script: dict):
    used = {}
    def agent(node, instruction, state):
        seq = script.get(node)
        if seq is None:
            return {"text": node}
        i = used.get(node, 0)
        used[node] = i + 1
        outcome = seq[min(i, len(seq) - 1)]
        if isinstance(outcome, dict) and "__raise__" in outcome:
            raise RuntimeError(outcome["__raise__"])
        return outcome
    return agent


FIXTURES = []

# --- 1. Basic semantic routing: outcome close to one condition ----------------------------
FIXTURES.append({
    "name": "basic_semantic_routing",
    "flow": (
        "---\nname: sentiment\nstart: classify\n---\n"
        "## classify\nClassify the sentiment.\n\n"
        "-> positive: sentiment is positive\n"
        "-> negative: sentiment is negative\n\n"
        "## positive\nPositive result.\n\n"
        "## negative\nNegative result.\n"
    ),
    "script": {"classify": [{"text": "great job"}]},
    "lock": {
        "conditions": {
            "sentiment is positive": _encode_vec(_unit([1, 0, 0, 0])),
            "sentiment is negative": _encode_vec(_unit([0, 1, 0, 0])),
        },
        "embedder": {"dim": 4},
    },
    "embedMap": {"great job": _encode_vec(_unit([0.95, 0.1, 0, 0]))},
})

# --- 2. Mixed deterministic + semantic: deterministic wins --------------------------------
FIXTURES.append({
    "name": "deterministic_takes_priority",
    "flow": (
        "---\nname: mixed\nstart: a\n---\n"
        "## a\nRoute.\n\n"
        "-> b: when x == 1\n"
        "-> c: semantic fallback\n\n"
        "## b\nDeterministic.\n\n"
        "## c\nSemantic.\n"
    ),
    "script": {"a": [{"text": "go", "x": 1}]},
    "lock": {
        "conditions": {"semantic fallback": _encode_vec(_unit([0, 0, 1, 0]))},
        "embedder": {"dim": 4},
    },
    "embedMap": {"go": _encode_vec(_unit([0, 0, 0.9, 0.1]))},
})

# --- 3. Deterministic fails, semantic succeeds -------------------------------------------
FIXTURES.append({
    "name": "deterministic_fails_semantic_succeeds",
    "flow": (
        "---\nname: fallback\nstart: a\n---\n"
        "## a\nRoute.\n\n"
        "-> b: when x == 99\n"
        "-> c: the answer is correct\n"
        "-> d: the answer is wrong\n\n"
        "## b\nB.\n\n## c\nC.\n\n## d\nD.\n"
    ),
    "script": {"a": [{"text": "looks right", "x": 5}]},
    "lock": {
        "conditions": {
            "the answer is correct": _encode_vec(_unit([1, 0, 0, 0])),
            "the answer is wrong": _encode_vec(_unit([0, 1, 0, 0])),
        },
        "embedder": {"dim": 4},
    },
    "embedMap": {"looks right": _encode_vec(_unit([0.9, 0.2, 0, 0]))},
})

# --- 4. human_floor triggers needs_human ------------------------------------------------
FIXTURES.append({
    "name": "human_floor_triggers",
    "flow": (
        "---\nname: hfloor\nstart: a\n---\n"
        "## a\nClassify.\n\n"
        "-> b: option one\n"
        "-> c: option two\n\n"
        "## b\nB.\n\n## c\nC.\n"
    ),
    "script": {"a": [{"text": "ambiguous"}]},
    "lock": {
        "conditions": {
            "option one": _encode_vec(_unit([1, 0, 0, 0])),
            "option two": _encode_vec(_unit([0, 1, 0, 0])),
        },
        "embedder": {"dim": 4},
    },
    "embedMap": {"ambiguous": _encode_vec(_unit([0.6, 0.5, 0, 0]))},
    "humanFloor": 0.9,
})

# --- 5. human_floor passes (score above threshold) --------------------------------------
FIXTURES.append({
    "name": "human_floor_passes",
    "flow": (
        "---\nname: hfloor_pass\nstart: a\n---\n"
        "## a\nClassify.\n\n"
        "-> b: option one\n"
        "-> c: option two\n\n"
        "## b\nB.\n\n## c\nC.\n"
    ),
    "script": {"a": [{"text": "clear signal"}]},
    "lock": {
        "conditions": {
            "option one": _encode_vec(_unit([1, 0, 0, 0])),
            "option two": _encode_vec(_unit([0, 1, 0, 0])),
        },
        "embedder": {"dim": 4},
    },
    "embedMap": {"clear signal": _encode_vec(_unit([0.99, 0.01, 0, 0]))},
    "humanFloor": 0.5,
})

# --- 6. Single semantic edge (margin = 1.0) ----------------------------------------------
FIXTURES.append({
    "name": "single_semantic_edge",
    "flow": (
        "---\nname: single\nstart: a\n---\n"
        "## a\nDo.\n\n"
        "-> b: the only option\n\n"
        "## b\nDone.\n"
    ),
    "script": {"a": [{"text": "anything"}]},
    "lock": {
        "conditions": {"the only option": _encode_vec(_unit([1, 0, 0, 0]))},
        "embedder": {"dim": 4},
    },
    "embedMap": {"anything": _encode_vec(_unit([0.8, 0.2, 0.1, 0]))},
})

# --- 7. Centroid overrides condition vector -----------------------------------------------
FIXTURES.append({
    "name": "centroid_override",
    "flow": (
        "---\nname: centroid\nstart: a\n---\n"
        "## a\nClassify.\n\n"
        "-> b: alpha\n"
        "-> c: beta\n\n"
        "## b\nB.\n\n## c\nC.\n"
    ),
    "script": {"a": [{"text": "test input"}]},
    "lock": {
        "conditions": {
            "alpha": _encode_vec(_unit([1, 0, 0, 0])),
            "beta": _encode_vec(_unit([0, 1, 0, 0])),
        },
        "centroids": {
            "alpha": {"vec": _encode_vec(_unit([0, 1, 0, 0])), "n": 5},
        },
        "embedder": {"dim": 4},
    },
    # outcome close to [0,1,0,0] — matches "beta" AND "alpha" (via centroid), but
    # alpha's centroid now IS [0,1,0,0], same as beta.  alpha is first in doc order.
    "embedMap": {"test input": _encode_vec(_unit([0.05, 0.99, 0, 0]))},
})

# --- 8. Multi-step semantic flow --------------------------------------------------------
FIXTURES.append({
    "name": "multi_step_semantic",
    "flow": (
        "---\nname: pipeline\nstart: intake\n---\n"
        "## intake\nRead the input.\n\n"
        "-> analyze: needs analysis\n"
        "-> done: already resolved\n\n"
        "## analyze\nAnalyze it.\n\n"
        "-> done: analysis complete\n\n"
        "## done\nFinished.\n"
    ),
    "script": {
        "intake": [{"text": "complex case"}],
        "analyze": [{"text": "finished analyzing"}],
    },
    "lock": {
        "conditions": {
            "needs analysis": _encode_vec(_unit([1, 0, 0, 0])),
            "already resolved": _encode_vec(_unit([0, 1, 0, 0])),
            "analysis complete": _encode_vec(_unit([0, 0, 1, 0])),
        },
        "embedder": {"dim": 4},
    },
    "embedMap": {
        "complex case": _encode_vec(_unit([0.9, 0.1, 0, 0])),
        "finished analyzing": _encode_vec(_unit([0.05, 0.05, 0.95, 0])),
    },
})


def _run_fixture(fx):
    from prismpath.lockfile import _decode_vec

    conds = {}
    for text, b64 in fx["lock"]["conditions"].items():
        conds[text] = _decode_vec(b64)
    if "centroids" in fx["lock"]:
        for text, pin in fx["lock"]["centroids"].items():
            conds[text] = _decode_vec(pin["vec"])
    router = LockedEmbeddingRouter(conds)

    embed_map = {text: _decode_vec(b64) for text, b64 in fx["embedMap"].items()}

    import prismpath.embedder as emb_mod
    _orig_embed = emb_mod.embed
    def _stub_embed(texts, is_query=False):
        vecs = []
        for t in texts:
            if is_query:
                t = t.replace(emb_mod.QUERY_INSTRUCTION, "")
            v = embed_map.get(t)
            if v is None:
                v = np.zeros(fx["lock"]["embedder"]["dim"], dtype="float32")
            vecs.append(v)
        return np.array(vecs, dtype="float32")
    emb_mod.embed = _stub_embed

    try:
        graph = parse(fx["flow"])
        res = run(
            graph,
            _scripted_agent(fx["script"]),
            router=router,
            max_steps=fx.get("maxSteps", 25),
            human_floor=fx.get("humanFloor"),
        )
        pending = res.pending or {}
        expect = {
            "path": res.path,
            "stopped": res.stopped,
            "pending_node": pending.get("node"),
            "would_pick": pending.get("would_pick"),
        }
        return expect
    finally:
        emb_mod.embed = _orig_embed


def generate():
    cases = []
    for fx in FIXTURES:
        expect = _run_fixture(fx)
        case = {
            "name": fx["name"],
            "flow": fx["flow"],
            "script": fx["script"],
            "lock": fx["lock"],
            "embedMap": fx["embedMap"],
            "expect": expect,
        }
        if "humanFloor" in fx:
            case["humanFloor"] = fx["humanFloor"]
        if "maxSteps" in fx:
            case["maxSteps"] = fx["maxSteps"]
        cases.append(case)
    return {
        "version": VERSION,
        "note": "P1 locked-routing conformance: synthetic 4D vectors, no real embedder needed. "
                "embedMap maps outcome text -> base64 float32 vector for the scripted embed callback.",
        "cases": cases,
    }


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    doc = generate()
    path = OUT_DIR / "locked_flows.json"
    path.write_text(
        json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {path}  ({len(doc['cases'])} cases)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
