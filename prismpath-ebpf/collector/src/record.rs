// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The feed's framing: one canon/2 record per line, length bounded, and the one request a client may send.

use prismpath_rs::canon2::{self, Doc};
use serde_json::Value;

/// The feed's protocol name, in the subscription and in `hello`.
pub const PROTOCOL: &str = "prismpath.collector/1";
/// The longest record line, newline included. A seal at the largest count the collector seals to
/// (2^53 - 1 leaves, 53 peaks) fits with room to spare; every other record is far shorter.
pub const MAX_RECORD: usize = 8192;
/// The longest subscription line, newline included.
pub const MAX_SUBSCRIPTION: usize = 256;

/// A record that could not be framed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    NotCanon2(&'static str),
    TooLong(usize),
}

/// The canon/2 bytes of `value` and a newline, refused when the value is not canon/2 (a float, an integer
/// beyond plus or minus 2^53 - 1) or the line would be longer than [`MAX_RECORD`].
pub fn frame(value: &Value) -> Result<Vec<u8>, FrameError> {
    let mut bytes = canon2::write_json(value).map_err(|error| FrameError::NotCanon2(error.rule()))?;
    bytes.push(b'\n');
    if bytes.len() > MAX_RECORD {
        return Err(FrameError::TooLong(bytes.len()));
    }
    Ok(bytes)
}

/// The exact bytes of the one request the feed accepts, without its newline.
pub fn subscription_bytes() -> Vec<u8> {
    canon2::write(&Doc::Obj(vec![("op".into(), Doc::Str("subscribe".into())), ("protocol".into(), Doc::Str(PROTOCOL.into()))]))
        .expect("the subscription is canon/2")
}

/// Why a client's request was refused, as the `refused` record names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// No newline within [`MAX_SUBSCRIPTION`] bytes.
    Oversized,
    /// Bytes after the subscription's newline.
    Extra,
    /// Not canon/2, or not its canonical spelling.
    NotCanon2,
    /// canon/2, but not the subscription.
    NotSubscription,
    /// Nothing complete before the timeout.
    Timeout,
    /// The peer's credentials are not on the allow list.
    Peer,
    /// The feed already serves as many clients as it is configured to.
    Busy,
}

impl Refusal {
    pub fn as_str(self) -> &'static str {
        match self {
            Refusal::Oversized => "oversized",
            Refusal::Extra => "extra-input",
            Refusal::NotCanon2 => "not-canon2",
            Refusal::NotSubscription => "not-a-subscription",
            Refusal::Timeout => "timeout",
            Refusal::Peer => "peer-not-allowed",
            Refusal::Busy => "busy",
        }
    }
}

/// Check what a client sent before its subscription was accepted: exactly the subscription's canon/2
/// bytes and one newline, nothing before and nothing after. `received` is every byte read so far.
/// None means more bytes are needed.
pub fn check_subscription(received: &[u8]) -> Option<Result<(), Refusal>> {
    let Some(newline) = received.iter().position(|byte| *byte == b'\n') else {
        return if received.len() >= MAX_SUBSCRIPTION { Some(Err(Refusal::Oversized)) } else { None };
    };
    if newline + 1 > MAX_SUBSCRIPTION {
        return Some(Err(Refusal::Oversized));
    }
    if newline + 1 != received.len() {
        return Some(Err(Refusal::Extra));
    }
    let line = &received[..newline];
    if canon2::read(line).is_err() {
        return Some(Err(Refusal::NotCanon2));
    }
    Some(if line == subscription_bytes().as_slice() { Ok(()) } else { Err(Refusal::NotSubscription) })
}
