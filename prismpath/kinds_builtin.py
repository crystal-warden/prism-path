# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Every built in target kind, loaded once by each surface that starts a process.

A target kind registers itself when its module is imported (`prismpath.distribution.kinds.register`), and the trust
path imports no kind. So a process knows the kinds its surface loaded and no other: a PEP of a kind that was never
loaded is refused with "no enforcement point of kind", and an artifact whose reader was never registered does not
read. `load` imports the `agent` and `gateway` kinds, and registers the reader of `net.dests` that finds the XDP
edge's own reader (`prismpath-ebpf/net_dist.py`) beside the package when a destination table is first read. That
module registers its reader and its comparator itself when it is imported. A tree that does not carry it refuses the
artifact rather than guessing at it.

`prismpath.cli.main`, `python -m prismpath.mission_control`, the agent's hook (through `prismpath.agent.commands`)
and the gateway (through `prismpath.gateway.proxy`) load what they use. A tool that verifies or compares envelopes
of every kind calls `load` first.
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

EDGE_DIR = Path(__file__).resolve().parents[1] / "prismpath-ebpf"


def edge_reader():
    """`net_dist`, the XDP edge's reader of `net.dests` and its loader adapter, from `prismpath-ebpf/` beside the
    package. `Refused` with `dist:bad-format` in a tree that does not carry it, so a destination table is never
    taken unread."""
    from prismpath.distribution import kinds
    if "net_dist" in sys.modules:
        return sys.modules["net_dist"]
    if not (EDGE_DIR / "net_dist.py").is_file():
        raise kinds.Refused(kinds.BAD_FORMAT, "this tree has no reader of the XDP edge's destination table")
    if str(EDGE_DIR) not in sys.path:
        sys.path.insert(0, str(EDGE_DIR))
    return importlib.import_module("net_dist")


def read_dests(body: bytes):
    """`net.dests`, read by the edge's own reader (`net_dist.read_dests`)."""
    return edge_reader().read_dests(body)


def load() -> None:
    """Register every built in kind. Loading again changes nothing."""
    from prismpath.agent import dist_kind as _agent  # noqa: F401 - registers the agent kind
    from prismpath.distribution import kinds
    from prismpath.gateway import dist_kind as _gateway  # noqa: F401 - registers the gateway kind
    if "net.dests" not in kinds.READERS:
        kinds.register_reader("net.dests", read_dests)
