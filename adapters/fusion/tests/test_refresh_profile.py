# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The refresh profile referee (PROTOCOL.md section 2.7): invariant I6 under injected loss.

The gap the profile closes, demonstrated first: a send-on-delta stream over a lossy link can
leave a naive consumer holding a WRONG state for unbounded time (one lost change frame, silence
forever after). Then the bound, proven: with a keyframe cadence and a stale bound, at any
instant a declared consumer acts on the sender's current state, a state the sender held within
the last stale_ms, or the signed fail-safe (I6) — under single loss, burst loss, and total
blackout. Loss masks are deterministic; no randomness, no wall clock.
"""
import sys
from pathlib import Path

ADAPTER = Path(__file__).resolve().parent.parent
REPO = ADAPTER.parent.parent
sys.path.insert(0, str(REPO / "adapters" / "telemetry"))

from refresh import KeyframeScheduler, StalenessTracker  # noqa: E402

TICK_MS = 100
KEYFRAME_MS = 500
STALE_MS = 1500
SAFE = "SAFE"

# A band walk with dwell: LOW until t=1000, HIGH until t=3000, MID to the end (t=6000).
TRUTH = (["LOW"] * 10) + (["HIGH"] * 20) + (["MID"] * 31)


def simulate(loss, keyframe_ms=KEYFRAME_MS, stale_ms=STALE_MS):
    """Run the sender/consumer pair over TRUTH with a per-tick loss predicate.

    Returns [(t_ms, truth, acting, fresh)] per tick, plus the tracker (for transitions)."""
    sched = KeyframeScheduler(keyframe_ms)
    tracker = StalenessTracker(stale_ms, SAFE)
    rows = []
    prev = None
    for i, state in enumerate(TRUTH):
        t = i * TICK_MS
        changed = state != prev
        prev = state
        if sched.should_emit(t, changed):
            sched.note_emit(t)
            if not loss(i, t):
                tracker.on_frame(t, state)
        acting, fresh = tracker.acting_state(t)
        rows.append((t, state, acting, fresh))
    return rows, tracker


def held_within(t, acting, stale_ms):
    """True iff the sender held `acting` at some instant in [t - stale_ms, t]."""
    lo = max(0, (t - stale_ms) // TICK_MS)
    hi = t // TICK_MS
    return acting in TRUTH[lo:hi + 1]


def assert_i6(rows, stale_ms=STALE_MS):
    for t, truth, acting, fresh in rows:
        ok = (acting == truth) or (acting == SAFE) or held_within(t, acting, stale_ms)
        assert ok, f"I6 violated at t={t}: acting={acting!r}, truth={truth!r}"
        if not fresh:
            assert acting == SAFE, f"stale consumer acted on {acting!r}, not the fail-safe"


# ------------------------------------------------------------------- the gap, demonstrated
def test_delta_only_wrong_state_is_unbounded():
    """No keyframes, naive last-value consumer: lose the one HIGH->MID change frame and the
    consumer is wrong from t=3000 to the end of time. This is the undeclared behavior."""
    sched = KeyframeScheduler(None)                    # send-on-delta only
    last_received = None
    wrong_ticks = 0
    prev = None
    for i, state in enumerate(TRUTH):
        changed = state != prev
        prev = state
        if sched.should_emit(i * TICK_MS, changed):
            sched.note_emit(i * TICK_MS)
            if i != 30:                                # lose exactly the HIGH->MID change frame
                last_received = state
        if i >= 30 and last_received != state:
            wrong_ticks += 1
    assert wrong_ticks == len(TRUTH) - 30              # wrong every tick to the end, unbounded


# ---------------------------------------------------------------------- I6 under loss shapes
def test_i6_lossless():
    rows, tracker = simulate(lambda i, t: False)
    assert_i6(rows)
    assert all(fresh for _t, _s, _a, fresh in rows)    # a healthy link never goes stale
    assert tracker.transitions == [(0, "recovered")]


def test_i6_single_lost_change_frame():
    rows, _ = simulate(lambda i, t: i == 30)           # the HIGH->MID change frame again
    assert_i6(rows)
    # wrong-state exposure is bounded by the next delivered keyframe, well inside stale_ms
    wrong = [t for t, truth, acting, _f in rows if acting not in (truth, SAFE)]
    assert wrong and max(wrong) - min(wrong) < KEYFRAME_MS
    assert not any(acting == SAFE for _t, _s, acting, _f in rows)   # never had to park


def test_i6_burst_loss():
    rows, _ = simulate(lambda i, t: 28 <= i <= 37)     # 1s burst swallowing the change + keyframes
    assert_i6(rows)


def test_i6_blackout_parks_safe_within_bound():
    blackout_start = 20                                 # t=2000, mid-HIGH dwell, link dies for good
    rows, tracker = simulate(lambda i, t: i >= blackout_start)
    assert_i6(rows)
    stale_rows = [(t, acting) for t, _s, acting, fresh in rows if not fresh]
    assert stale_rows, "blackout must eventually trip stale"
    first_stale_t = stale_rows[0][0]
    last_delivery_t = (blackout_start - 1) * TICK_MS
    # parks on the fail-safe no later than one tick past last delivery + stale_ms
    assert first_stale_t <= last_delivery_t + STALE_MS + TICK_MS
    assert all(acting == SAFE for _t, acting in stale_rows)
    assert tracker.transitions[-1][1] == "stale"


def test_recovery_after_blackout():
    rows, tracker = simulate(lambda i, t: 20 <= i <= 44)   # blackout, then the link returns
    assert_i6(rows)
    # after the link returns, the next delivered emission restores fresh, correct state
    post = [r for r in rows if r[0] >= 45 * TICK_MS + KEYFRAME_MS]
    assert post and all(fresh and acting == truth for _t, truth, acting, fresh in post)
    kinds = [k for _t, k in tracker.transitions]
    assert kinds == ["recovered", "stale", "recovered"]    # one clean stale episode, receipted


# ----------------------------------------------------------------------------- sender cadence
def test_keyframe_cadence_bounds_emission_gap():
    sched = KeyframeScheduler(KEYFRAME_MS)
    emits = []
    prev = None
    for i, state in enumerate(TRUTH):
        t = i * TICK_MS
        changed = state != prev
        prev = state
        if sched.should_emit(t, changed):
            sched.note_emit(t)
            emits.append(t)
    gaps = [b - a for a, b in zip(emits, emits[1:])]
    assert max(gaps) <= KEYFRAME_MS                    # the conforming-sender contract
    assert 1000 in emits and 3000 in emits             # both changes still emit immediately
