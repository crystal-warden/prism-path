# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Mission Control: the facade the routers import.

The reference deployment's control plane, re-scoped to **proving + observability over flows** for one
local operator on loopback. Everything here is transport-agnostic: pure functions over a single followed
sprint's on-disk artifacts (`status.json` heartbeat, `interactions.jsonl` glass lens, checkpoints,
the audit log, read through prismpath.ledgers). The FastAPI routers in this package are thin adapters
over these functions.

The work is split by job into one module each, and this module re-exports them under the names the
routers already use:

    config      every path, port and cap, with the shipped values as defaults
    state       the one operator's live state and the locks that serialize writes
    audit       the append-only, Merkle committed log of control actions
    files       containment against the followed project, and the editable file listing
    discovery   finding sprints by their heartbeat, and following the live one
    launch      starting, stopping and detecting a sprint
    status      the status summary every view polls
    lens        the glass lens over interactions.jsonl (dialogue and retrievals)
    balance     the category-balance view
    stage       where the loop is, inferred from the run's status file and log
    graph       the flow topology the command center draws

Two of those hold process-wide mutable objects, `SETTINGS` and `audit.LOG`. Read them through the
object (`SETTINGS.max_file_bytes`, `audit.LOG`), never by binding the value into a local name at
import, so that changing one is seen everywhere.

No multi-user identity, no chat, no model inference: PrismPath routes and proves; it does not serve
models. See docs/design/orchestration.md.
"""
from . import audit
from .balance import balance_state
from .config import SETTINGS, Settings
from .discovery import discover_sprints, follow_active_sprint
from .files import file_tree, is_contained, safe_path
from .graph import serialize_flow_graph
from .launch import sprint_running, start_sprint, touch_marker
from .lens import interactions, retrievals
from .stage import flow_state
from .state import FILE_LOCK, LAUNCH_LOCK, STATE
from .status import status

__all__ = [
    "SETTINGS", "Settings", "STATE", "FILE_LOCK", "LAUNCH_LOCK", "audit",
    "balance_state", "discover_sprints", "file_tree", "flow_state", "follow_active_sprint",
    "interactions", "is_contained", "retrievals", "safe_path", "serialize_flow_graph",
    "sprint_running", "start_sprint", "status", "touch_marker",
]
