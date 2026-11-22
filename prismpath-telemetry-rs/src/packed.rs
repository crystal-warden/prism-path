// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! Word-packed wire — the real byte format.

use crate::zeckendorf;
use serde::{Deserialize, Serialize};

pub const WORD_BITS: usize = 64;

/// Packs bits MSB-first into `word_bits`-bit words written big endian, the last word zero-padded on the
/// right: the bytes `pack` makes from the same bits, written as they come with no bit-string between.
pub struct BitWriter {
    out: Vec<u8>,
    acc: u128,
    filled: u32,
    word_bits: u32,
}

impl BitWriter {
    /// A writer for `word_bits`-bit words (a multiple of 8, at most 64).
    pub fn new(word_bits: usize) -> Self {
        Self::appending(Vec::new(), word_bits)
    }

    /// A writer that appends its words to `out`, after the bytes already there.
    pub fn appending(out: Vec<u8>, word_bits: usize) -> Self {
        assert!(word_bits % 8 == 0 && (8..=64).contains(&word_bits), "word_bits must be 8 to 64 in steps of 8");
        BitWriter { out, acc: 0, filled: 0, word_bits: word_bits as u32 }
    }

    /// The buffer as it stands, without the word in progress.
    pub fn into_inner(self) -> Vec<u8> {
        self.out
    }

    /// The low `len` bits of `bits`, the highest of them first.
    pub fn put(&mut self, bits: u128, mut len: u32) {
        while len > 0 {
            let room = self.word_bits - self.filled;
            let take = room.min(len);
            let chunk = (bits >> (len - take)) & ((1u128 << take) - 1);
            self.acc = (self.acc << take) | chunk;
            self.filled += take;
            len -= take;
            if self.filled == self.word_bits {
                self.flush_word();
            }
        }
    }

    fn flush_word(&mut self) {
        let be = self.acc.to_be_bytes();
        self.out.extend_from_slice(&be[16 - (self.word_bits / 8) as usize..]);
        self.acc = 0;
        self.filled = 0;
    }

    /// The bytes, the last word zero-padded on the right.
    pub fn finish(mut self) -> Vec<u8> {
        if self.filled > 0 {
            self.acc <<= self.word_bits - self.filled;
            self.flush_word();
        }
        self.out
    }

    /// `finish`, appended to `dest`.
    pub fn finish_into(self, dest: &mut Vec<u8>) {
        dest.extend_from_slice(&self.finish());
    }

    /// Runs `write` with a writer appending to `dest`, then pads the last word. When `write` refuses, `dest` is
    /// cut back to the length it had, so a refused reading leaves no bytes behind.
    pub fn write_into<E>(dest: &mut Vec<u8>, word_bits: usize, write: impl FnOnce(&mut BitWriter) -> Result<(), E>) -> Result<(), E> {
        let start = dest.len();
        let mut writer = BitWriter::appending(std::mem::take(dest), word_bits);
        match write(&mut writer) {
            Ok(()) => {
                *dest = writer.finish();
                Ok(())
            }
            Err(error) => {
                let mut out = writer.into_inner();
                out.truncate(start);
                *dest = out;
                Err(error)
            }
        }
    }
}

/// Whether `BitWriter` takes this word size: a multiple of 8 from 8 to 64.
pub fn writer_word_bits(word_bits: usize) -> bool {
    word_bits % 8 == 0 && (8..=64).contains(&word_bits)
}

/// Bit-string -> bytes, MSB-first, flushing per `word_bits`-bit word; final word zero-padded right.
pub fn pack(bits: &str, word_bits: usize) -> Vec<u8> {
    if !writer_word_bits(word_bits) {
        return pack_any(bits, word_bits);
    }
    let mut writer = BitWriter::new(word_bits);
    for &byte in bits.as_bytes() {
        writer.put(u128::from(byte == b'1'), 1);
    }
    writer.finish()
}

/// `pack` for a word size the writer does not take, bit by bit as it always was.
fn pack_any(bits: &str, word_bits: usize) -> Vec<u8> {
    let bytes_per_word = word_bits / 8;
    let mut out = Vec::new();
    let mut acc: u128 = 0;
    let mut bits_in_word = 0;
    for ch in bits.chars() {
        let bit = if ch == '1' { 1 } else { 0 };
        acc = (acc << 1) | bit;
        bits_in_word += 1;
        if bits_in_word == word_bits {
            let be_bytes = acc.to_be_bytes();
            out.extend_from_slice(&be_bytes[16 - bytes_per_word..]);
            acc = 0;
            bits_in_word = 0;
        }
    }
    if bits_in_word > 0 {
        acc <<= word_bits - bits_in_word;
        let be_bytes = acc.to_be_bytes();
        out.extend_from_slice(&be_bytes[16 - bytes_per_word..]);
    }
    out
}

/// Bytes -> bit-string, MSB-first (includes any trailing zero pad).
pub fn unpack(data: &[u8]) -> String {
    data.iter().map(|byte| format!("{:08b}", byte)).collect()
}

/// Positive ints -> Fibonacci-coded, word-packed bytes. `Err` if any int is `< 1`.
pub fn encode(ints: &[usize], word_bits: usize) -> Result<Vec<u8>, String> {
    if !writer_word_bits(word_bits) {
        return Ok(pack_any(&zeckendorf::encode_stream(ints)?, word_bits));
    }
    let mut writer = BitWriter::new(word_bits);
    for &value in ints {
        let (code, len) = zeckendorf::code_bits(value)
            .ok_or_else(|| format!("Fibonacci coding is for positive integers; got {value}"))?;
        writer.put(code, len);
    }
    Ok(writer.finish())
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
