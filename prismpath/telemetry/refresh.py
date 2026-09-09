# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The refresh profile (PROTOCOL.md section 2.7): bounded staleness under loss for send-on-delta
and resident-state streams.

The profile changes CADENCE, never bytes: a keyframe is byte-identical to any other frame, so a
Facet/1 stream under this profile is a valid Facet/1 stream without it. The sender emits the
current full state at least every ``keyframe_ms`` even when unchanged; a consumer treats state
older than ``stale_ms`` as stale and acts on the policy's signed fail-safe instead, exactly the
fail-safe the migration path already uses. Invariant I6 (bounded staleness) is what this buys:
at any instant a declared consumer acts on the sender's current state, a state the sender held
within the last ``stale_ms``, or the signed fail-safe. Proven under injected loss in
``adapters/fusion/tests/test_refresh_profile.py``.

Everything here is pure and clockless: callers pass monotonic milliseconds, nothing reads a wall
clock, so behavior is deterministic and testable tick by tick.
"""
from __future__ import annotations

from typing import Any, List, Optional, Tuple


class KeyframeScheduler:
    """Sender half: emit on change, and at least every ``keyframe_ms`` regardless.

    ``keyframe_ms=None`` disables the cadence (send-on-delta only) — that is the undeclared
    behavior the profile exists to bound, kept available so benches can demonstrate the gap.
    """

    def __init__(self, keyframe_ms: Optional[int]):
        if keyframe_ms is not None and keyframe_ms <= 0:
            raise ValueError(f"keyframe_ms must be a positive integer or None; got {keyframe_ms}")
        self.keyframe_ms = keyframe_ms
        self._last_emit_ms: Optional[int] = None

    def should_emit(self, now_ms: int, changed: bool) -> bool:
        if changed or self._last_emit_ms is None:
            return True
        if self.keyframe_ms is None:
            return False
        return now_ms - self._last_emit_ms >= self.keyframe_ms

    def note_emit(self, now_ms: int) -> None:
        self._last_emit_ms = now_ms


class StalenessTracker:
    """Consumer half: hold the last received state while fresh; past ``stale_ms``, act on the
    signed fail-safe. Transitions are recorded for receipting (fresh -> stale, stale -> fresh)."""

    def __init__(self, stale_ms: int, safe_state: Any):
        if stale_ms <= 0:
            raise ValueError(f"stale_ms must be a positive integer; got {stale_ms}")
        self.stale_ms = stale_ms
        self.safe_state = safe_state
        self._state: Any = None
        self._last_frame_ms: Optional[int] = None
        self._stale = True                      # no frame yet: born stale, acts on the fail-safe
        self.transitions: List[Tuple[int, str]] = []

    def on_frame(self, now_ms: int, state: Any) -> None:
        self._state = state
        self._last_frame_ms = now_ms
        if self._stale:
            self._stale = False
            self.transitions.append((now_ms, "recovered"))

    def acting_state(self, now_ms: int) -> Tuple[Any, bool]:
        """The state a consumer may act on right now: ``(state, fresh)``. Stale consumers get
        ``(safe_state, False)`` — never the last received value."""
        if self._last_frame_ms is None or now_ms - self._last_frame_ms >= self.stale_ms:
            if not self._stale:
                self._stale = True
                self.transitions.append((now_ms, "stale"))
            return self.safe_state, False
        return self._state, True
