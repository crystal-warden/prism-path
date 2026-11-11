// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The replay window (PROTOCOL.md section 2.8): tick based replay rejection for bare profile streams whose
//! transport binding carries a per frame tick. A faithful port of `prismpath/telemetry/replay.py`.
//!
//! Scope, as in the reference: this rejects REPLAYED and DUPLICATED frames on bindings that carry a tick.
//! It is not authentication, and a bare datagram stream with no tick has no replay protection at all.
//! Rejections carry a distinct cause string so a receipt can say WHICH check refused a frame. Clockless and
//! deterministic: state advances only on observed ticks.
//!
//! Ticks are `i64` (Python's are unbounded integers); the arithmetic is done wider, so no tick overflows.

pub const ACCEPT: &str = "accept";
pub const REPLAY_DUPLICATE: &str = "replay-duplicate";
pub const REPLAY_STALE: &str = "replay-stale";

/// Per stream replay window over a monotonically increasing frame tick.
///
/// The default is strict in order (`reorder` 0): accept only ticks strictly greater than the highest seen.
/// A transport that can reorder declares a small `reorder` tolerance: a tick at or below the highest seen is
/// then accepted iff it lies within the last `reorder` ticks AND has not been seen before (a bitmask sliding
/// window, the IPsec/DTLS shape).
#[derive(Debug, Clone)]
pub struct TickWindow {
    reorder: u32,
    top: i128,  // the highest tick accepted so far
    mask: u128, // bit k set = tick (top - k) seen, k in 0..reorder-1
}

impl TickWindow {
    /// `Err` unless `reorder` is in 0..=64.
    pub fn new(reorder: i64) -> Result<TickWindow, String> {
        if !(0..=64).contains(&reorder) {
            return Err(format!("reorder must be in 0..64; got {reorder}"));
        }
        Ok(TickWindow { reorder: reorder as u32, top: -1, mask: 0 })
    }

    pub fn reorder(&self) -> u32 {
        self.reorder
    }

    /// The highest tick accepted so far (-1 before any).
    pub fn top(&self) -> i64 {
        self.top as i64 // only ticks that came in as i64 are ever stored, and -1
    }

    /// Bit k set means tick `top - k` has been seen.
    pub fn mask(&self) -> u64 {
        self.mask as u64 // never wider than 64 bits: the window is at most 64
    }

    /// Would this tick be accepted right now? `(ok, cause)` without mutating state.
    pub fn check(&self, tick: i64) -> (bool, &'static str) {
        let tick = i128::from(tick);
        if tick > self.top {
            return (true, ACCEPT);
        }
        if self.reorder == 0 {
            return (false, if tick == self.top { REPLAY_DUPLICATE } else { REPLAY_STALE });
        }
        let back = self.top - tick;
        if back >= i128::from(self.reorder) {
            return (false, REPLAY_STALE);
        }
        if (self.mask >> back) & 1 == 1 {
            return (false, REPLAY_DUPLICATE);
        }
        (true, ACCEPT)
    }

    /// Check and, on acceptance, admit the tick into the window. `(ok, cause)`.
    pub fn observe(&mut self, tick: i64) -> (bool, &'static str) {
        let (ok, cause) = self.check(tick);
        if !ok {
            return (ok, cause);
        }
        let tick = i128::from(tick);
        if tick > self.top {
            let ahead = tick - self.top;
            let width = i128::from(self.reorder.max(1));
            // A jump of the window's width or more leaves no earlier tick inside it, so the mask is just
            // this tick (and the shift never gets a count it cannot take).
            self.mask = if ahead >= width { 1 } else { ((self.mask << ahead) | 1) & ((1u128 << width) - 1) };
            self.top = tick;
        } else {
            self.mask |= 1u128 << (self.top - tick);
        }
        (true, ACCEPT)
    }
}
