// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The feed's framing: one canon/2 record per line, length bounded, and the one request a client may send:
//! a subscription, or a subscription that resumes a session from the count the client last verified.

use prismpath_rs::canon2::{self, Doc};
use serde_json::Value;

/// The feed's protocol name, in the subscription and in `hello`.
pub const PROTOCOL: &str = "prismpath.collector/2";
/// The longest record line, newline included. A seal at the largest count the collector seals to
/// (2^53 - 1 leaves, 53 peaks) with the longest consistency proof there can be (54 hashes) fits, and
/// `tests/consistency.rs` measures it; every other record is far shorter.
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

/// The exact bytes of a subscription that resumes `session` from `count` leaves, without its newline:
/// `{"count":N,"op":"subscribe","protocol":P,"session":S}`.
pub fn resume_bytes(session: &str, count: u64) -> Vec<u8> {
    canon2::write(&Doc::Obj(vec![
        ("count".into(), Doc::Int(count as i64)),
        ("op".into(), Doc::Str("subscribe".into())),
        ("protocol".into(), Doc::Str(PROTOCOL.into())),
        ("session".into(), Doc::Str(session.into())),
    ]))
    .expect("a resume is canon/2")
}

/// An accepted request: from the start, or resuming a session (its id, and the count of the last seal the
/// client verified in it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscription {
    pub resume: Option<(String, u64)>,
}

fn session_id(text: &str) -> bool {
    text.len() == 32 && text.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// The resume a canonical line asks for, or None when it is not exactly a resume.
fn as_resume(doc: &Doc) -> Option<(String, u64)> {
    let Doc::Obj(members) = doc else { return None };
    match members.as_slice() {
        [(count_key, Doc::Int(count)), (op_key, Doc::Str(op)), (protocol_key, Doc::Str(protocol)), (session_key, Doc::Str(session))]
            if count_key == "count" && op_key == "op" && protocol_key == "protocol" && session_key == "session"
                && op == "subscribe" && protocol == PROTOCOL && *count >= 0 && session_id(session) =>
        {
            Some((session.clone(), *count as u64))
        }
        _ => None,
    }
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

/// Check what a client sent before its subscription was accepted: exactly the canon/2 bytes of a
/// subscription or of a resume, and one newline, nothing before and nothing after. `received` is every
/// byte read so far. None means more bytes are needed.
pub fn check_subscription(received: &[u8]) -> Option<Result<Subscription, Refusal>> {
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
    let Ok(doc) = canon2::read(line) else {
        return Some(Err(Refusal::NotCanon2));
    };
    if canon2::write(&doc).ok().as_deref() != Some(line) {
        return Some(Err(Refusal::NotCanon2));
    }
    if line == subscription_bytes().as_slice() {
        return Some(Ok(Subscription { resume: None }));
    }
    Some(as_resume(&doc).map(|resume| Subscription { resume: Some(resume) }).ok_or(Refusal::NotSubscription))
}
