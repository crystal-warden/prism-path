//! Word-packed wire — the real byte format.

use crate::zeckendorf;
use serde::{Deserialize, Serialize};

pub const WORD_BITS: usize = 64;

/// Bit-string -> bytes, MSB-first, flushing per `word_bits`-bit word; final word zero-padded right.
pub fn pack(bits: &str, word_bits: usize) -> Vec<u8> {
    let bytes_per_word = word_bits / 8;
    let mut out = Vec::new();
    let mut acc: u128 = 0;
    let mut n = 0;
    for ch in bits.chars() {
        let bit = if ch == '1' { 1 } else { 0 };
        acc = (acc << 1) | bit;
        n += 1;
        if n == word_bits {
            let be_bytes = acc.to_be_bytes();
            out.extend_from_slice(&be_bytes[16 - bytes_per_word..]);
            acc = 0;
            n = 0;
        }
    }
    if n > 0 {
        acc <<= word_bits - n;
        let be_bytes = acc.to_be_bytes();
        out.extend_from_slice(&be_bytes[16 - bytes_per_word..]);
    }
    out
}

/// Bytes -> bit-string, MSB-first (includes any trailing zero pad).
pub fn unpack(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:08b}", b)).collect()
}

/// Positive ints -> Fibonacci-coded, word-packed bytes. `Err` if any int is `< 1`.
pub fn encode(ints: &[usize], word_bits: usize) -> Result<Vec<u8>, String> {
    Ok(pack(&zeckendorf::encode_stream(ints)?, word_bits))
}

/// Word-packed bytes -> ints (trailing zero pad is a partial frame and is dropped).
pub fn decode(data: &[u8]) -> Vec<usize> {
    zeckendorf::decode_stream(&unpack(data))
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PaddingOverhead {
    pub n: usize,
    pub actual_bits: usize,
    pub wire_bytes: usize,
    pub pad_bits: usize,
    pub pad_pct: f64,
}

pub fn padding_overhead(ints: &[usize], word_bits: usize) -> Result<PaddingOverhead, String> {
    let actual_bits = zeckendorf::encode_stream(ints)?.len();
    let wire = encode(ints, word_bits)?;
    let padded_bits = wire.len() * 8;
    let pad_bits = padded_bits - actual_bits;
    let pad_pct = if actual_bits > 0 {
        (100.0 * pad_bits as f64) / actual_bits as f64
    } else {
        0.0
    };
    Ok(PaddingOverhead {
        n: ints.len(),
        actual_bits,
        wire_bytes: wire.len(),
        pad_bits,
        pad_pct,
    })
}
