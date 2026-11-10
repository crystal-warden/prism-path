// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The receipt stream profile (PROTOCOL.md section 2.10): cause code carriage on the wire. A faithful port
//! of `prismpath/telemetry/receipts.py`.
//!
//! A receipt reading carries `cause`, `event`, `next_node`, `prev_node` and `seq`, in that alphabetical
//! order. The cause code IS the symbol, carried under the standard symbol plus one mapping, so cause 0 (a
//! clean decision) rides as wire integer 1 (`"11"`), the densest code, and the whole `u8` registry space is
//! representable. A decode returns two things apart: the registry code the frame carried
//! (`Receipt::cause`) and the status string saying why a decode was refused (`DecodedReceipt::refusal_cause`).
//!
//! Python carries integers of any width; the fields here are `u64`. A field beyond 2^64 - 2 is refused with
//! `ReceiptError::Overflow` on both the encode and the decode side instead of wrapping (DIVERGENCES.md).

use crate::{packed, zeckendorf};
use prismpath_rs::causes;

pub const RECEIPT_FIELDS: [&str; 5] = ["cause", "event", "next_node", "prev_node", "seq"];

pub const OK: &str = "ok";
pub const RECEIPT_TRUNCATED: &str = "receipt-truncated";
pub const RECEIPT_INVALID_CAUSE: &str = "receipt-invalid-cause";
pub const RECEIPT_FIELD_MISMATCH: &str = "receipt-field-mismatch";

/// A cause given as its registry code or its registry name, as Python's `cause_code` accepts either.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CauseRef<'a> {
    Code(i128),
    Name(&'a str),
}

impl From<u8> for CauseRef<'_> {
    fn from(code: u8) -> Self {
        CauseRef::Code(i128::from(code))
    }
}
impl From<i64> for CauseRef<'_> {
    fn from(code: i64) -> Self {
        CauseRef::Code(i128::from(code))
    }
}
impl From<i32> for CauseRef<'_> {
    fn from(code: i32) -> Self {
        CauseRef::Code(i128::from(code))
    }
}
impl<'a> From<&'a str> for CauseRef<'a> {
    fn from(name: &'a str) -> Self {
        CauseRef::Name(name)
    }
}

/// Why an encode or decode could not complete (Python's `ValueError`s, and the width Python does not have).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptError {
    UnknownCauseName(String),
    CauseOutOfRange(i128),
    /// A field needs a wire integer beyond 64 bits.
    Overflow(&'static str),
}

impl std::fmt::Display for ReceiptError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReceiptError::UnknownCauseName(name) => write!(formatter, "unknown cause name: {name:?}"),
            ReceiptError::CauseOutOfRange(code) => write!(formatter, "cause code out of range 0..255: {code}"),
            ReceiptError::Overflow(field) => write!(formatter, "receipt field {field} is beyond 64 bits"),
        }
    }
}
impl std::error::Error for ReceiptError {}

/// A decoded receipt: the fields as the wire carried them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub cause: u8,
    /// The registry name of `cause`; `None` for 0 and for an unregistered code.
    pub cause_name: Option<&'static str>,
    pub event: u64,
    pub next_node: u64,
    pub prev_node: u64,
    pub seq: u64,
}

/// The result of a decode with its two halves named apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedReceipt {
    pub receipt: Option<Receipt>,
    /// Why the decode was refused (`OK` when it was not): a decoder status string, never a registry name.
    pub refusal_cause: &'static str,
}

fn refused(refusal_cause: &'static str) -> DecodedReceipt {
    DecodedReceipt { receipt: None, refusal_cause }
}

fn resolve_cause(cause: &CauseRef<'_>) -> Result<u8, ReceiptError> {
    match cause {
        CauseRef::Name(name) => causes::code(name).ok_or_else(|| ReceiptError::UnknownCauseName((*name).to_string())),
        CauseRef::Code(code) => u8::try_from(*code).map_err(|_| ReceiptError::CauseOutOfRange(*code)),
    }
}

/// The receipt fields as symbols (0 based cell indices) in canonical field order
/// `[cause, event, next_node, prev_node, seq]`. A cause given by name must be registered; a cause given
/// by code must be 0..=255.
pub fn encode_receipt_symbols(seq: u64, prev_node: u64, event: u64, next_node: u64, cause: CauseRef<'_>) -> Result<[u64; 5], ReceiptError> {
    let code = resolve_cause(&cause)?;
    Ok([u64::from(code), event, next_node, prev_node, seq])
}

/// The wire integers, each symbol plus one. A symbol of 2^64 - 1 has no 64 bit wire integer.
pub fn encode_receipt_wire_ints(seq: u64, prev_node: u64, event: u64, next_node: u64, cause: CauseRef<'_>) -> Result<[u64; 5], ReceiptError> {
    let symbols = encode_receipt_symbols(seq, prev_node, event, next_node, cause)?;
    let mut wire_ints = [0u64; 5];
    for (index, symbol) in symbols.iter().enumerate() {
        wire_ints[index] = symbol.checked_add(1).ok_or(ReceiptError::Overflow(RECEIPT_FIELDS[index]))?;
    }
    Ok(wire_ints)
}

/// A self framing Zeckendorf bitstream of the receipt.
pub fn encode_receipt_bits(seq: u64, prev_node: u64, event: u64, next_node: u64, cause: CauseRef<'_>) -> Result<String, ReceiptError> {
    let wire_ints = encode_receipt_wire_ints(seq, prev_node, event, next_node, cause)?;
    let mut values = Vec::with_capacity(5);
    for (index, wire_int) in wire_ints.iter().enumerate() {
        values.push(usize::try_from(*wire_int).map_err(|_| ReceiptError::Overflow(RECEIPT_FIELDS[index]))?);
    }
    // Every wire integer is at least 1, so the codec has no positivity refusal to raise.
    Ok(zeckendorf::encode_stream(&values).expect("wire integers are positive"))
}

/// A word packed Facet wire frame of the receipt.
pub fn encode_receipt(seq: u64, prev_node: u64, event: u64, next_node: u64, cause: CauseRef<'_>) -> Result<Vec<u8>, ReceiptError> {
    Ok(packed::pack(&encode_receipt_bits(seq, prev_node, event, next_node, cause)?, 8))
}

/// The wire frame of a decoded receipt, by its code.
pub fn encode_receipt_struct(receipt: &Receipt) -> Result<Vec<u8>, ReceiptError> {
    encode_receipt(receipt.seq, receipt.prev_node, receipt.event, receipt.next_node, CauseRef::from(receipt.cause))
}

/// Decode a Zeckendorf bitstream into a receipt, or the reason it was refused. A frame with no complete
/// codeword, or fewer than five, is `RECEIPT_TRUNCATED`; more than five is `RECEIPT_FIELD_MISMATCH`; a
/// cause beyond the byte is `RECEIPT_INVALID_CAUSE`. A trailing partial codeword (bit padding) is dropped.
/// `Err` only when a field other than the cause is an integer beyond 64 bits, which Python carries.
pub fn decode_receipt_bits(bits: &str) -> Result<DecodedReceipt, ReceiptError> {
    if bits.is_empty() {
        return Ok(refused(RECEIPT_TRUNCATED));
    }
    let wire_ints = zeckendorf::decode_stream_wide(bits);
    if wire_ints.is_empty() {
        return Ok(refused(RECEIPT_TRUNCATED));
    }
    if wire_ints.len() != RECEIPT_FIELDS.len() {
        return Ok(refused(if wire_ints.len() < RECEIPT_FIELDS.len() { RECEIPT_TRUNCATED } else { RECEIPT_FIELD_MISMATCH }));
    }
    // symbol = wire integer - 1; a wire integer is at least 1, and a cause beyond 64 bits is beyond the byte
    let cause_code = match wire_ints[0].map(|wire_int| wire_int - 1) {
        Some(symbol) if symbol <= 255 => symbol as u8,
        _ => return Ok(refused(RECEIPT_INVALID_CAUSE)),
    };
    let mut fields = [0u64; 4];
    for (index, wire_int) in wire_ints[1..].iter().enumerate() {
        fields[index] = match wire_int {
            Some(value) => *value as u64 - 1,
            None => return Err(ReceiptError::Overflow(RECEIPT_FIELDS[index + 1])),
        };
    }
    Ok(DecodedReceipt {
        receipt: Some(Receipt {
            cause: cause_code,
            cause_name: causes::name(cause_code),
            event: fields[0],
            next_node: fields[1],
            prev_node: fields[2],
            seq: fields[3],
        }),
        refusal_cause: OK,
    })
}

/// Decode a packed byte frame into a receipt, or the reason it was refused.
pub fn decode_receipt(frame: &[u8]) -> Result<DecodedReceipt, ReceiptError> {
    if frame.is_empty() {
        return Ok(refused(RECEIPT_TRUNCATED));
    }
    decode_receipt_bits(&packed::unpack(frame))
}
