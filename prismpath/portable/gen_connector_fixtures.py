"""Freeze cross-language CONNECTOR-SDK + COMPOSITION fixtures — hashes, the flattened prompt
surface, the attestation manifest, and a spawn/join fan-out run through the reference
`checkpoint.resume(event=...)` path — so the Rust port is measured, not asserted.

    python prismpath/portable/gen_connector_fixtures.py  ->  conformance/connector.json
"""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))

from prismpath.connector import BaseConnector, PayloadFlattener   # noqa: E402
from prismpath.checkpoint import run_durable, resume, load_checkpoint  # noqa: E402

OUT = HERE / "conformance" / "connector.json"


class _Echo(BaseConnector):
    def __init__(self):
        super().__init__("echo")


_PAYLOADS = [
    {"alert": {"id": 7, "severity": "high"}, "agent": "web-01"},
    {"roles": ["admin", "dev"], "active": True, "score": 1.5},
    {"nested": {"deep": {"leaf": None}}, "note": "café"},
]

_FLOW_PARENT = """---
name: fx_parent
start: plan
---
## plan
Plan the fan-out.
-> gather: always
## gather
Fan out one child per item.
-> merge: on event all_done
## merge
Combine child results.
-> end: always
## end
Done.
"""

_FLOW_CHILD = """---
name: fx_child
start: work
---
## work
Process one item.
-> finish: always
## finish
Done.
"""


def _scripted(script):
    used = {}

    def agent(node, _instruction, _state):
        seq = script.get(node)
        if seq is None:
            return {"text": node}
        i = used.get(node, 0)
        used[node] = i + 1
        return seq[min(i, len(seq) - 1)]

    return agent


def main() -> int:
    conn = _Echo()

    hashes = [{"data": p,
               "ingestion": conn.compute_ingestion_hash(p),
               "knowledge": conn.compute_knowledge_hash(p)} for p in _PAYLOADS]

    prompts = [
        {"payload": _PAYLOADS[0], "criteria": None, "schema": None,
         "prompt": conn.adjudication_prompt(_PAYLOADS[0])},
        {"payload": _PAYLOADS[1], "criteria": "rule 12 governs", "schema": None,
         "prompt": conn.adjudication_prompt(_PAYLOADS[1], criteria="rule 12 governs")},
        {"payload": _PAYLOADS[2], "criteria": None,
         "schema": {"properties": {"verdict": {}, "reason": {}}},
         "prompt": conn.adjudication_prompt(
             _PAYLOADS[2], schema={"properties": {"verdict": {}, "reason": {}}})},
    ]

    flat_cases = [{"data": p, "flat": PayloadFlattener().flatten(p)} for p in _PAYLOADS]

    outcome = {"verdict": "contain", "score": 0.93}
    att = conn.attest_decision(outcome, "sha256:deadbeef", "wazuh_triage@v3",
                               ["sha256:aa"], "sha256:kb")
    att["created"] = "2026-08-12T00:00:00Z"
    body = json.dumps({k: att[k] for k in att if k != "manifest_hash"}, sort_keys=True).encode()
    att["manifest_hash"] = hashlib.sha256(body).hexdigest()

    # ---- join-policy grid: the composer's REAL threshold/event functions, frozen ----
    from prismpath.composer import _join_event, _quorum_threshold
    join_grid = []
    for join in ["all_done", "any", "quorum:2", "quorum:0.6", "quorum:5", "quorum:oops"]:
        for done in ([True, True, True], [True, True, False], [True, False, False],
                     [False, False, False], [True], [False]):
            join_grid.append({
                "join": join, "done": done,
                "threshold": _quorum_threshold(join, len(done)) if join.startswith("quorum") else None,
                "event": _join_event({"join": join}, list(done)),
            })

    # ---- spawn/join fan-out through the reference resume(event=...) path ----
    with tempfile.TemporaryDirectory(prefix="cw_conn_fx_") as td:
        td = Path(td)
        parent = td / "fx_parent.md"; parent.write_text(_FLOW_PARENT)
        ckpt = td / "fx_parent.ckpt.json"
        items = [{"id": 1}, {"id": 2}, {"id": 3}]
        parent_script = {"plan": [{"text": "planned"}],
                         "gather": [{"spawn": {"flow": "fx_child", "items": items,
                                               "join": "all_done"}}],
                         "merge": [{"text": "merged"}]}
        r1 = run_durable(str(parent), _scripted(parent_script), str(ckpt))
        suspended = {"path": r1.path, "stopped": r1.stopped,
                     "spawn": (r1.pending or {}).get("spawn")}

        # children: run each in-process with state={'_item': item} (the minimal driver protocol)
        from prismpath.engine import run as engine_run
        from prismpath.parser import parse
        child_graph = parse(_FLOW_CHILD)
        child_script = {"work": [{"text": "worked"}], "finish": [{"text": "done"}]}
        children = []
        for item in items:
            res = engine_run(child_graph, _scripted(child_script), state={"_item": item})
            children.append({"item": item, "path": res.path, "stopped": res.stopped})

        # aggregate into the parent's checkpoint state, then deliver the join event
        cp = load_checkpoint(str(ckpt))
        cp["state"]["_children"] = children
        (td / "fx_parent.ckpt.json").write_text(json.dumps(cp, indent=2))
        r2 = resume(str(ckpt), _scripted(parent_script), event="all_done")
        final = {"path": r2.path, "stopped": r2.stopped,
                 "children_in_state": r2.state.get("_children")}

    doc = {
        "version": 2,
        "note": "Connector-SDK + composition fixtures from the Python reference. Rust must "
                "reproduce hashes and prompt strings byte-for-byte, the attestation manifest "
                "exactly, the fan-out final path/stopped with _children aggregated, and the "
                "join-policy grid (composer._quorum_threshold/_join_event) value-for-value.",
        "hashes": hashes,
        "prompts": prompts,
        "flatten": flat_cases,
        "attestation": {"outcome": outcome, "policy_hash": "sha256:deadbeef",
                        "gate_id": "wazuh_triage@v3", "ingestion_hashes": ["sha256:aa"],
                        "kb_hash": "sha256:kb", "manifest": att},
        "joins": join_grid,
        "fanout": {"parent_flow": _FLOW_PARENT, "child_flow": _FLOW_CHILD,
                   "parent_script": parent_script, "child_script": child_script,
                   "items": items, "suspended": suspended, "children": children,
                   "final": final},
    }
    OUT.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
    print(f"wrote {OUT}  ({len(hashes)} hash, {len(prompts)} prompt, 1 fan-out)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
