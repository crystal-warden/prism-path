// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The concentrator profile (PROTOCOL.md section 2.9): many streams, one datagram. A faithful port of
//! `prismpath/telemetry/concentrator.py`.
//!
//! A record is `[stream_id][reading]`: the stream id is Zeckendorf coded (ids from 1) and the reading
//! carries no length, because the stream's codebook fixes its field count (I3 does the framing). Records
//! pack bit contiguously; only the datagram is padded to the byte.
//!
//! The demultiplexer is strict and fail closed over the whole datagram: an unknown stream id, a record
//! truncated mid reading, or a trailing partial that is not zero pad rejects the datagram with a distinct
//! cause and returns no records, never a partial delivery.
//!
//! Python carries integers of any width; here a wire integer is `u64`. A reading integer beyond 64 bits is
//! `ConcentratorError::Overflow`; a stream id beyond 64 bits cannot be in a `u64` registry, so it is an
//! unknown stream, as it is in Python for any registry that does not list it (DIVERGENCES.md).

use crate::{packed, zeckendorf};
use std::collections::HashMap;

pub const CONCENTRATOR_UNKNOWN_STREAM: &str = "concentrator-unknown-stream";
pub const CONCENTRATOR_TRUNCATED: &str = "concentrator-truncated";
pub const OK: &str = "ok";

/// A record: the stream id and the stream's wire integers (symbols plus one).
pub type Record = (u64, Vec<u64>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConcentratorError {
    /// Stream ids are positive.
    StreamIdNotPositive,
    /// A record carries no reading.
    EmptyReading(u64),
    /// A wire integer is below 1.
    WireIntNotPositive(u64),
    /// A reading integer is beyond 64 bits.
    Overflow,
}

impl std::fmt::Display for ConcentratorError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConcentratorError::StreamIdNotPositive => write!(formatter, "stream ids are positive (Zeckendorf-coded); got 0"),
            ConcentratorError::EmptyReading(stream_id) => write!(formatter, "stream {stream_id}: empty reading"),
            ConcentratorError::WireIntNotPositive(stream_id) => write!(formatter, "stream {stream_id}: a wire integer below 1"),
            ConcentratorError::Overflow => write!(formatter, "a reading integer is beyond 64 bits"),
        }
    }
}
impl std::error::Error for ConcentratorError {}

fn to_usize(value: u64) -> Result<usize, ConcentratorError> {
    usize::try_from(value).map_err(|_| ConcentratorError::Overflow)
}

/// `[(stream_id, wire_ints)]` -> one byte aligned concentrated frame. The wire integers are the streams'
/// already encoded symbols plus one; this layer composes the existing encoders and never re-encodes.
pub fn concentrate(records: &[Record]) -> Result<Vec<u8>, ConcentratorError> {
    let mut bits = String::new();
    for (stream_id, wire_ints) in records {
        if *stream_id < 1 {
            return Err(ConcentratorError::StreamIdNotPositive);
        }
        if wire_ints.is_empty() {
            return Err(ConcentratorError::EmptyReading(*stream_id));
        }
        bits.push_str(&zeckendorf::encode(to_usize(*stream_id)?).map_err(|_| ConcentratorError::StreamIdNotPositive)?);
        for wire_int in wire_ints {
            bits.push_str(&zeckendorf::encode(to_usize(*wire_int)?).map_err(|_| ConcentratorError::WireIntNotPositive(*stream_id))?);
        }
    }
    Ok(packed::pack(&bits, 8))
}

/// One Fibonacci code starting at `pos`: the first `11` at or after it ends the code. `None` when no
/// complete code exists there; `Some((value, next_pos))` otherwise, the value `None` when it is beyond 64 bits.
fn take_one(bits: &str, pos: usize) -> Option<(Option<usize>, usize)> {
    let bytes = bits.as_bytes();
    let mut index = pos;
    while index + 1 < bytes.len() {
        if bytes[index] == b'1' && bytes[index + 1] == b'1' {
            // the slice ends at the first `11`, so it holds no other and is a code
            return Some((zeckendorf::decode(&bits[pos..index + 2]).ok(), index + 2));
        }
        index += 1;
    }
    None
}

/// One concentrated frame -> `(records, cause)`. `registry` maps stream id to field count (from the
/// stream's signed policy). On any structural failure the WHOLE datagram is rejected: `([], cause)`.
/// `Err` only for a reading integer beyond 64 bits.
pub fn demux(frame: &[u8], registry: &HashMap<u64, usize>) -> Result<(Vec<Record>, &'static str), ConcentratorError> {
    let bits = packed::unpack(frame);
    let mut out: Vec<Record> = Vec::new();
    let mut pos = 0;
    while pos < bits.len() {
        if !bits[pos..].contains('1') {
            break; // trailing zero pad: the only legal tail
        }
        let (stream_value, next) = match take_one(&bits, pos) {
            Some(found) => found,
            None => return Ok((Vec::new(), CONCENTRATOR_TRUNCATED)), // a 1 bit tail with no terminator
        };
        let stream_id = match stream_value.and_then(|value| u64::try_from(value).ok()).filter(|id| registry.contains_key(id)) {
            Some(id) => id,
            None => return Ok((Vec::new(), CONCENTRATOR_UNKNOWN_STREAM)),
        };
        let mut wire_ints = Vec::new();
        pos = next;
        for _ in 0..registry[&stream_id] {
            match take_one(&bits, pos) {
                None => return Ok((Vec::new(), CONCENTRATOR_TRUNCATED)), // record cut mid reading
                Some((value, after)) => {
                    wire_ints.push(value.and_then(|number| u64::try_from(number).ok()).ok_or(ConcentratorError::Overflow)?);
                    pos = after;
                }
            }
        }
        out.push((stream_id, wire_ints));
    }
    Ok((out, OK))
}
