# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The replay window (PROTOCOL.md section 2.8): a tick far ahead of the highest accepted one must not cost
memory in proportion to the jump, and the bit mask the window keeps must be what the plain shift gave."""
import time

from prismpath.telemetry import replay


def test_a_hostile_tick_jump_does_not_allocate_a_mask_as_long_as_the_jump():
    """`observe` once shifted the mask by the jump itself, so a tick of 2**40 asked for a 128 GB integer."""
    for reorder in (0, 1, 8, 64):
        window = replay.TickWindow(reorder)
        started = time.monotonic()
        assert window.observe(1) == (True, replay.ACCEPT)
        assert window.observe(2**62) == (True, replay.ACCEPT)
        assert window.observe(2**62) == (False, replay.REPLAY_DUPLICATE)
        assert window.observe(2**200) == (True, replay.ACCEPT)
        assert time.monotonic() - started < 1.0
        assert window._mask == 1


def test_the_mask_after_a_short_jump_is_unchanged_by_the_fix():
    reference = replay.TickWindow(8)
    mask, top = 0, -1
    for tick in (10, 12, 11, 17, 18, 3, 40):
        ok, _cause = reference.observe(tick)
        if ok and tick > top:
            mask = ((mask << (tick - top)) | 1) & ((1 << 8) - 1)
            top = tick
        elif ok:
            mask |= 1 << (top - tick)
        assert (reference._top, reference._mask) == (top, mask)
