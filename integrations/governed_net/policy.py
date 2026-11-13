# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The network policy: one signed core image decided two ways, by the Python kernel and by the XDP table.

`policy/net_rules.core.json` is a `prismpath.core/1` image over the protocol's seven header fields, all
integers. The Python decision is the governed harness's own (`governed_harness.policy.Policy`: the image
checked by the port of the Lean `loadPolicy`, rendered, parsed and decided by the reference kernel).

The table for the kernel is compiled from the same image the way the core differential's table leg does
(`formal/diff/core_diff.table_leg`): the image is rendered and parsed by the reference, each rule of the
start node gets a node of its own so the matched edge index names the rule, and the condition programs are
compiled by `prismpath-hw/ppt_compile.py`, with the field map pinned to the protocol's register order
(`protocol.SCHEMA`), as `prismpath-ebpf/net_compile.py` pins the packet schema for `ppt_net.bpf.c`. The
table is then admitted by `ebpf_table_limits.require_within_limits`, the loader's own checks.

The XDP program needs one more thing per rule: whether its target lets the packet through. That is the
action table, one byte per rule (1 = pass to the tool server, 0 = drop), derived from the targets of the
same signed image, plus the rule's cause code for the receipt logger. A packet no rule matches is dropped
(the core refuses it with `route:no-matching-edge`), and so is any packet when the tables are empty.
"""
from __future__ import annotations

import hashlib
import importlib.util
import struct
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
for extra in (REPO, REPO / "formal" / "diff", REPO / "prismpath-hw", REPO / "prismpath-ebpf"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

from integrations.governed_harness.policy import Decision, Policy, target_decision  # noqa: E402,F401
from prismpath.kernel import causes  # noqa: E402
from prismpath.kernel.parser import Node, parse  # noqa: E402

from . import protocol  # noqa: E402

POLICY_PATH = HERE / "policy" / "net_rules.core.json"
SOURCE_PATH = HERE / "policy" / "net_rules.src.json"
ACTIONS_MAGIC = 0x474E4143            # "GNAC"
NO_MATCH_CODE = causes.code("route:no-matching-edge")


def _ppt_compile():
    spec = importlib.util.spec_from_file_location("ppt_compile", REPO / "prismpath-hw" / "ppt_compile.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class NetPolicy(Policy):
    """The signed image, its Python decision, and its compiled table for the XDP program."""

    def __init__(self, image: bytes):
        super().__init__(image)
        if tuple(sorted(self.fields)) != tuple(sorted(protocol.SCHEMA)):
            raise ValueError(f"the policy's fields {self.fields} are not the protocol's {protocol.SCHEMA}")
        self.sha256 = hashlib.sha256(self.image).hexdigest()
        self.labels: List[str] = [target for target, _cond in self.graph.nodes[self.graph.start].edges]
        self.ppt = self._compile()

    @classmethod
    def load(cls, path: Path = POLICY_PATH) -> "NetPolicy":
        return cls(Path(path).read_bytes())

    def _compile(self) -> bytes:
        ppt = _ppt_compile()
        from ebpf_table_limits import require_within_limits
        graph = parse(self.flow)
        start = graph.nodes[graph.start]
        start.edges = [(f"rule{index}", cond) for index, (_target, cond) in enumerate(start.edges)]
        for index in range(len(self.labels)):
            graph.nodes[f"rule{index}"] = Node(name=f"rule{index}")
        image = ppt.TableImage()
        for slot, name in enumerate(protocol.SCHEMA):
            image.fields[name] = slot
        names = list(graph.nodes)
        idx = {name: index for index, name in enumerate(names)}
        for name in names:
            edges = [(idx[target], cond, image.compile_condition(cond)) for target, cond in graph.nodes[name].edges]
            image.nodes.append((name, edges))
        image.start = idx[graph.start]
        if tuple(image.fields) != protocol.SCHEMA:
            raise ValueError(f"the compiled table reads fields outside the protocol: {list(image.fields)}")
        if len(image.intern) != 1:
            raise ValueError("the compiled table interns strings; the protocol's fields are integers only")
        blob = image.serialize()
        require_within_limits(blob)
        return blob

    def rule_decision(self, edge: int) -> Tuple[str, Optional[str], Optional[int]]:
        return target_decision(self.labels[edge])

    def actions(self) -> bytes:
        """The action table the XDP program and the receipt logger read: magic, rule count, the image's
        sha256, then per rule (pass byte, kind byte, cause code u16). Kind: 0 allow, 1 refuse, 2 escalate."""
        out = struct.pack("<II", ACTIONS_MAGIC, len(self.labels)) + bytes.fromhex(self.sha256)
        for label in self.labels:
            kind, _cause, code = target_decision(label)
            out += struct.pack("<BBH", 1 if kind == "allow" else 0, {"allow": 0, "refuse": 1, "escalate": 2}[kind],
                               code or 0)
        return out

    def reading_raw(self, reading: Dict[str, int]) -> bytes:
        return self.reading_bytes(reading)

    def verdict_of_edge(self, edge: int) -> Dict:
        """The core verdict an XDP match names: a route to the rule's target, or the core's no match refusal."""
        if edge < 0:
            return {"verdict": "refuse", "cause": "route:no-matching-edge", "code": NO_MATCH_CODE}
        return {"verdict": "route", "target": self.labels[edge]}


def write_build(out: Path, policy: NetPolicy = None) -> Dict[str, str]:
    """The kernel's inputs, written beside each other: the table (`net_rules.ppt`), the action table
    (`net_rules.actions`) and the signed image they came from (`net_rules.core.json`)."""
    policy = policy or NetPolicy.load()
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "net_rules.ppt").write_bytes(policy.ppt)
    (out / "net_rules.actions").write_bytes(policy.actions())
    (out / "net_rules.core.json").write_bytes(policy.image + b"\n")
    return {"ppt": str(out / "net_rules.ppt"), "actions": str(out / "net_rules.actions"), "image_sha256": policy.sha256}


if __name__ == "__main__":
    import json
    print(json.dumps(write_build(Path(sys.argv[1])), indent=1))
