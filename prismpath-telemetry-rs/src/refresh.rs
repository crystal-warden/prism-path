// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The refresh profile (PROTOCOL.md section 2.7): bounded staleness under loss for send-on-delta and
//! resident state streams. A faithful port of `prismpath/telemetry/refresh.py`.
//!
//! The profile changes CADENCE, never bytes: a keyframe is byte identical to any other frame. The sender
//! emits the current full state at least every `keyframe_ms` even when unchanged; a consumer treats state
//! older than `stale_ms` as stale and acts on the policy's signed fail safe instead (invariant I6, bounded
//! staleness). Everything here is pure and clockless: callers pass monotonic milliseconds (`i64`; the
//! differences are taken wider, so no pair of times overflows).

/// Sender half: emit on change, and at least every `keyframe_ms` regardless. `None` disables the cadence
/// (send on delta only), the undeclared behavior the profile exists to bound.
#[derive(Debug, Clone)]
pub struct KeyframeScheduler {
    keyframe_ms: Option<i64>,
    last_emit_ms: Option<i64>,
}

impl KeyframeScheduler {
    /// `Err` unless `keyframe_ms` is `None` or a positive integer.
    pub fn new(keyframe_ms: Option<i64>) -> Result<KeyframeScheduler, String> {
        if let Some(value) = keyframe_ms {
            if value <= 0 {
                return Err(format!("keyframe_ms must be a positive integer or None; got {value}"));
            }
        }
        Ok(KeyframeScheduler { keyframe_ms, last_emit_ms: None })
    }

    pub fn keyframe_ms(&self) -> Option<i64> {
        self.keyframe_ms
    }

    pub fn should_emit(&self, now_ms: i64, changed: bool) -> bool {
        let last = match self.last_emit_ms {
            Some(last) if !changed => last,
            _ => return true,
        };
        match self.keyframe_ms {
            None => false,
            Some(keyframe_ms) => i128::from(now_ms) - i128::from(last) >= i128::from(keyframe_ms),
        }
    }

    pub fn note_emit(&mut self, now_ms: i64) {
        self.last_emit_ms = Some(now_ms);
    }
}

/// Consumer half: hold the last received state while fresh; past `stale_ms`, act on the signed fail safe.
/// Transitions (fresh to stale, stale to fresh) are recorded for receipting.
#[derive(Debug, Clone)]
pub struct StalenessTracker<T: Clone> {
    stale_ms: i64,
    safe_state: T,
    state: Option<T>,
    last_frame_ms: Option<i64>,
    stale: bool,
    transitions: Vec<(i64, &'static str)>,
}

impl<T: Clone> StalenessTracker<T> {
    /// `Err` unless `stale_ms` is a positive integer. A new tracker is born stale: no frame yet, so it acts
    /// on the fail safe.
    pub fn new(stale_ms: i64, safe_state: T) -> Result<StalenessTracker<T>, String> {
        if stale_ms <= 0 {
            return Err(format!("stale_ms must be a positive integer; got {stale_ms}"));
        }
        Ok(StalenessTracker { stale_ms, safe_state, state: None, last_frame_ms: None, stale: true, transitions: Vec::new() })
    }

    pub fn on_frame(&mut self, now_ms: i64, state: T) {
        self.state = Some(state);
        self.last_frame_ms = Some(now_ms);
        if self.stale {
            self.stale = false;
            self.transitions.push((now_ms, "recovered"));
        }
    }

    /// The state a consumer may act on right now: `(state, fresh)`. A stale consumer gets the fail safe and
    /// `false`, never the last received value.
    pub fn acting_state(&mut self, now_ms: i64) -> (T, bool) {
        let fresh_state = match (self.last_frame_ms, &self.state) {
            (Some(last), Some(state)) if i128::from(now_ms) - i128::from(last) < i128::from(self.stale_ms) => Some(state.clone()),
            _ => None,
        };
        match fresh_state {
            Some(state) => (state, true),
            None => {
                if !self.stale {
                    self.stale = true;
                    self.transitions.push((now_ms, "stale"));
                }
                (self.safe_state.clone(), false)
            }
        }
    }

    pub fn transitions(&self) -> &[(i64, &'static str)] {
        &self.transitions
    }
}
