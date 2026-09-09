# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The replay window (PROTOCOL.md section 2.8): tick-based replay rejection for bare-profile
streams whose transport binding carries a per-frame tick (e.g. the ESP-NOW spiral binding).

Scope, stated honestly: this rejects REPLAYED and DUPLICATED frames on bindings that carry a
tick. It is not authentication (a forger who can construct valid frames can construct fresh
ticks; origin trust is the keyed layer's or the transport's job), and the bare datagram profile
without a tick-carrying binding has NO replay protection at all — the keyed layer (2.5) is the
answer there, where the epoch+index nonce kills replay outright.

Rejections carry a distinct cause string ("replay-duplicate", "replay-stale") so receipts can
say WHICH check refused a frame. Clockless and deterministic: state advances only on observed
ticks.
"""
from __future__ import annotations

from typing import Tuple


ACCEPT = "accept"
REPLAY_DUPLICATE = "replay-duplicate"
REPLAY_STALE = "replay-stale"


class TickWindow:
    """Per-stream replay window over a monotonically increasing frame tick.

    Default is strict in-order (``reorder=0``): accept only ticks strictly greater than the
    highest seen, which is exact for single-hop datagram links that cannot reorder. A transport
    that can reorder declares a small ``reorder`` tolerance: a tick at or below the highest seen
    is then accepted iff it lies within the last ``reorder`` ticks AND has not been seen before
    (a bitmask sliding window, the IPsec/DTLS shape).
    """

    def __init__(self, reorder: int = 0):
        if reorder < 0 or reorder > 64:
            raise ValueError(f"reorder must be in 0..64; got {reorder}")
        self.reorder = reorder
        self._top: int = -1        # highest tick accepted so far
        self._mask: int = 0        # bit k set = tick (_top - k) seen, k in 0..reorder-1

    def check(self, tick: int) -> Tuple[bool, str]:
        """Would this tick be accepted right now? ``(ok, cause)`` without mutating state."""
        if tick > self._top:
            return True, ACCEPT
        if self.reorder == 0:
            return False, REPLAY_DUPLICATE if tick == self._top else REPLAY_STALE
        back = self._top - tick
        if back >= self.reorder:
            return False, REPLAY_STALE
        if (self._mask >> back) & 1:
            return False, REPLAY_DUPLICATE
        return True, ACCEPT

    def observe(self, tick: int) -> Tuple[bool, str]:
        """Check and, on acceptance, admit the tick into the window. ``(ok, cause)``."""
        ok, cause = self.check(tick)
        if not ok:
            return ok, cause
        if tick > self._top:
            ahead = tick - self._top
            self._mask = ((self._mask << ahead) | 1) & ((1 << max(self.reorder, 1)) - 1)
            self._top = tick
        else:
            self._mask |= 1 << (self._top - tick)
        return True, ACCEPT
