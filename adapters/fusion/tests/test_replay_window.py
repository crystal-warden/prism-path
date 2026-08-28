# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The replay window referee (PROTOCOL.md section 2.8).

Deterministic tick sequences, no clock. Covers: strict in-order mode (duplicates and stale
ticks rejected with their distinct causes), reorder-tolerant mode (late-but-unseen accepted
inside the window, duplicate-inside-window rejected, beyond-window rejected as stale), the
check/observe split (check never mutates), and the interaction that motivated the window: a
replayed old keyframe must not regress a refresh-profile consumer's state.
"""
import sys
from pathlib import Path

import pytest

ADAPTER = Path(__file__).resolve().parent.parent
REPO = ADAPTER.parent.parent
sys.path.insert(0, str(REPO / "adapters" / "telemetry"))

from refresh import StalenessTracker                          # noqa: E402
from replay import (ACCEPT, REPLAY_DUPLICATE, REPLAY_STALE,   # noqa: E402
                    TickWindow)


def run(win, ticks):
    return [win.observe(t) for t in ticks]


# ------------------------------------------------------------------------- strict in-order
def test_strict_monotonic_accepts():
    assert run(TickWindow(), [1, 2, 3, 10, 11]) == [(True, ACCEPT)] * 5


def test_strict_duplicate_rejected_with_cause():
    win = TickWindow()
    assert win.observe(5) == (True, ACCEPT)
    assert win.observe(5) == (False, REPLAY_DUPLICATE)


def test_strict_old_replay_rejected_with_cause():
    win = TickWindow()
    run(win, [1, 2, 3])
    assert win.observe(1) == (False, REPLAY_STALE)


# ---------------------------------------------------------------------- reorder tolerance
def test_reorder_late_but_unseen_accepted():
    win = TickWindow(reorder=4)
    run(win, [1, 2, 4])                      # 3 is late but inside the window and unseen
    assert win.observe(3) == (True, ACCEPT)
    assert win.observe(3) == (False, REPLAY_DUPLICATE)


def test_reorder_beyond_window_is_stale():
    win = TickWindow(reorder=4)
    run(win, list(range(1, 9)) + [10])       # 9 never arrived; top = 10, window covers 7..10
    assert win.observe(6) == (False, REPLAY_STALE)      # beyond the window
    assert win.observe(7) == (False, REPLAY_DUPLICATE)  # inside the window, already seen
    assert win.observe(9) == (True, ACCEPT)             # inside the window, unseen: reorder


def test_reorder_duplicate_inside_window():
    win = TickWindow(reorder=4)
    run(win, [1, 2, 3, 4])
    assert win.observe(3) == (False, REPLAY_DUPLICATE)


def test_window_slides_correctly_over_gaps():
    win = TickWindow(reorder=4)
    run(win, [1, 100])                       # a large jump must flush the old mask
    assert win.observe(99) == (True, ACCEPT)
    assert win.observe(96) == (False, REPLAY_STALE)
    assert win.observe(1) == (False, REPLAY_STALE)


def test_check_does_not_mutate():
    win = TickWindow(reorder=4)
    run(win, [1, 2, 3])
    assert win.check(4) == (True, ACCEPT)
    assert win.check(4) == (True, ACCEPT)    # still unseen: check must not admit
    assert win.observe(4) == (True, ACCEPT)
    assert win.observe(4) == (False, REPLAY_DUPLICATE)


def test_reorder_bounds():
    with pytest.raises(ValueError):
        TickWindow(reorder=-1)
    with pytest.raises(ValueError):
        TickWindow(reorder=65)


# ------------------------------------- the motivating interaction with the refresh profile
def test_replayed_keyframe_cannot_regress_state():
    """An attacker replays a captured LOW keyframe after the stream moved to HIGH. With the
    window in front of the tracker, the consumer's acting state never regresses."""
    win = TickWindow()
    tracker = StalenessTracker(stale_ms=1500, safe_state="SAFE")
    frames = [(1, 0, "LOW"), (2, 500, "LOW"), (3, 1000, "HIGH"),
              (1, 1100, "LOW"),               # the replay
              (4, 1500, "HIGH")]
    for tick, t_ms, state in frames:
        ok, _cause = win.observe(tick)
        if ok:
            tracker.on_frame(t_ms, state)
        acting, _fresh = tracker.acting_state(t_ms)
        if t_ms >= 1000:
            assert acting == "HIGH", f"state regressed at t={t_ms} via replayed tick {tick}"
