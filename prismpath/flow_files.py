# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""flow_files.py: the file reads behind the kernel's cross flow analysis.

`prismpath.kernel.analysis` reasons about a whole `@spawn` tree, which means resolving a child path, asking whether
the file is there, parsing it, and reading the routing lockfile that pins a flow's semantic conditions. The kernel does
no I/O, so those reads live here, in a surface module, and the kernel asks `FILES` for them. The functions at the end
are the kernel's own with `FILES` already passed, so a caller that wants the old behaviour calls them from here.
"""
from __future__ import annotations

import os
from typing import List

from prismpath.kernel import analysis


class FlowFiles:
    """Resolves, tests and parses the flow files of a composition tree, and reads a flow's lockfile."""

    def text(self, flow_path) -> str:
        return os.fspath(flow_path)

    def abspath(self, flow_path) -> str:
        """The absolute path of a flow file, which is how a tree walk recognises a flow it has already visited."""
        return os.path.abspath(os.fspath(flow_path))

    def child_path(self, parent_abspath: str, child: str) -> str:
        """The path a `@spawn(child=...)` names, relative to the directory of the parent flow."""
        if os.path.isabs(child):
            return child
        return os.path.normpath(os.path.join(os.path.dirname(parent_abspath), child))

    def exists(self, path) -> bool:
        return os.path.exists(path)

    def parse(self, path):
        from prismpath.kernel.parser import parse_file
        return parse_file(path)

    def lock_conditions(self, flow_path):
        """(the conditions the lockfile pins, the lock's path when it was read, the reason when it is present but
        unreadable). No lockfile at all gives an empty set and two Nones."""
        from prismpath.routing import lockfile
        lock_file = lockfile.lock_path(flow_path)
        if not os.path.exists(lock_file):
            return set(), None, None
        try:
            return set(lockfile.load_lock(lock_file).get("conditions", {})), lock_file, None
        except Exception as exc:                      # noqa: BLE001 - an unreadable lock is reported, not raised
            return set(), None, f"{lock_file}: {exc}"


FILES = FlowFiles()


def analyze_composition(graph, flow_path) -> List[analysis.Finding]:
    return analysis.analyze_composition(graph, flow_path, FILES)


def portability_tree(graph, flow_path) -> List[analysis.Finding]:
    return analysis.portability_tree(graph, flow_path, None, FILES)


def portability_tier(graph, flow_path) -> dict:
    return analysis.portability_tier(graph, flow_path, FILES)


def portability_tier_tree(graph, flow_path) -> dict:
    return analysis.portability_tier_tree(graph, flow_path, None, FILES)
