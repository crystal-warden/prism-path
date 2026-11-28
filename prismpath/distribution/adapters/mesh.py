# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The `mesh` adapter: a model of one ESP32 node (`prismpath-hw/mesh/main/ppt_mesh.c`) as a distribution target
(spec-policy-distribution.md, section 3), so the Python reference runs the same machine, hold included, as the
C core the firmware carries.

A node holds one `.ppt` table of at most 640 bytes and decides with the embedded PPT evaluator
(`prismpath-hw/ppt_eval.h`), `evaluate`, which is that evaluator in Python (`prismpath.hotswap.ppt_eval`). A
node ignores `meta` and runs its own table parser, so its check of a `policy.ppt` is the image check alone
(`kinds.check_mesh_table`).
"""
from __future__ import annotations

from typing import Optional

from prismpath.distribution.adapters import Adapter
from prismpath.hotswap import policy_pack
from prismpath.hotswap.ppt_eval import (EvalError, OP_EQ, OP_GE, OP_GT, OP_LE, OP_LT, OP_NE,  # noqa: F401
                                        OP_TRUTHY, OPC_AND, OPC_FALSE, OPC_NOT, OPC_OR, OPC_TRUE, STACK_MAX, TY_BOOL,
                                        TY_INT, TY_NONE, TY_STR, evaluate)


class MeshAdapter(Adapter):
    """One modelled mesh node. `activate` holds the committed table and `deactivate` drops it, so the node
    decides nothing. `decide(regs)` is the next node from the table's start node, None when no edge holds."""
    kind = "mesh"

    def __init__(self):
        self.table: Optional[bytes] = None

    def activate(self, release) -> None:
        self.table = release.bodies["policy.ppt"]

    def deactivate(self, cause: str) -> None:
        self.table = None

    def decide(self, regs: bytes) -> Optional[int]:
        if self.table is None:
            raise RuntimeError("a node with no table decides nothing")
        start = policy_pack.read_ppt_header(self.table)["start"]
        step = evaluate(self.table, regs, start)
        return None if step is None else step[1]
