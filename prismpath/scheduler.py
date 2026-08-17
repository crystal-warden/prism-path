# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""scheduler.py — a reference timer for `on timeout` edges (the piece that makes them fire).

The engine is deliberately pure and does no I/O. When a worker returns `{"wait": True, "timeout_s": N}`
the run suspends as `waiting` and the checkpoint records `saved_at`; the engine never fires the timer
itself. This module is the trivial out-of-band scanner a deployment runs on a tick (a cron entry, a
loop, a systemd timer): for every `waiting` checkpoint whose `timeout_s` has elapsed since `saved_at`,
it delivers the `__timeout__` event via `checkpoint.resume(..., event="__timeout__")`, taking the
node's `on timeout` edge.

Without a scanner like this, `on timeout` edges are documented but inert. This is the reference
implementation — dependency-free, no daemon — not a production scheduler (which would add jitter,
leasing, and at-least-once delivery). See `on event`/`on timeout` in the engine and
`checkpoint.resume(event=...)`.

    from prismpath import scheduler
    fired = scheduler.fire_due_timeouts(agent)     # scan the default queue dir once; resume the due ones
"""
from __future__ import annotations

import glob
import os
import time
from typing import List, Optional

from prismpath import checkpoint


def seconds_until_due(cp: dict, now: Optional[float] = None) -> Optional[float]:
    """Seconds until this checkpoint's timeout fires (<=0 means due now); None if it has no timer."""
    if cp.get("stopped") != "waiting":
        return None
    pending = cp.get("pending_decision") or {}
    timeout_s = pending.get("timeout_s")
    saved_at = cp.get("saved_at")
    if timeout_s is None or saved_at is None:
        return None
    now = time.time() if now is None else now
    return (saved_at + float(timeout_s)) - now


def is_due(cp: dict, now: Optional[float] = None) -> bool:
    d = seconds_until_due(cp, now)
    return d is not None and d <= 0


def fire_due_timeouts(agent, qdir: Optional[str] = None, now: Optional[float] = None,
                      router=None, human_floor: Optional[float] = None) -> List[dict]:
    """Scan a queue dir of checkpoints once and resume every `waiting` run whose timer has elapsed by
    delivering `__timeout__`. Returns one record per fired timeout: {path, result}. Runs that are not
    waiting, have no timer, or are not yet due are left untouched."""
    qdir = qdir or checkpoint.queue_dir()
    fired: List[dict] = []
    for path in sorted(glob.glob(os.path.join(qdir, "*"))):
        if not os.path.isfile(path):
            continue
        try:
            cp = checkpoint.load_checkpoint(path)
        except Exception:
            continue                                 # not a checkpoint / unreadable — skip
        if not is_due(cp, now):
            continue
        res = checkpoint.resume(path, agent, router=router, event="__timeout__",
                                human_floor=human_floor)
        fired.append({"path": path, "result": res})
    return fired
