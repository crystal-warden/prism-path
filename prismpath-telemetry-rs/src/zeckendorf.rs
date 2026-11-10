// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! Zeckendorf / Fibonacci codec — the self-framing wire for the decision-preserving telemetry stream.

use prismpath_rs::causes;

fn fibs_upto(upper_bound: usize) -> Vec<usize> {
    // `fibs` is seeded with [1, 2] and only ever grows, so `.last()` is always Some. A term the usize cannot
    // hold is beyond any bound, so the growth stops there.
    let mut fibs = vec![1, 2];
    while *fibs.last().expect("fibs seeded non-empty") <= upper_bound {
        match fibs[fibs.len() - 1].checked_add(fibs[fibs.len() - 2]) {
            Some(next) => fibs.push(next),
            None => return fibs,
        }
    }
    if *fibs.last().expect("fibs seeded non-empty") > upper_bound {
        fibs.pop();
    }
    fibs
}

/// Fibonacci code of a positive integer `n` (>= 1) as a bit-string ending in `"11"`.
pub fn encode(value: usize) -> Result<String, String> {
    if value < 1 {
        return Err(format!("Fibonacci coding is for positive integers; got {value}"));
    }
    let fibs = fibs_upto(value);
    let mut bits = vec!['0'; fibs.len()];
    let mut rem = value;
    for index in (0..fibs.len()).rev() {
        if fibs[index] <= rem {
            bits[index] = '1';
            rem -= fibs[index];
        }
    }
    assert_eq!(rem, 0, "Zeckendorf decomposition failed for {value}");
    let mut out: String = bits.into_iter().collect();
    out.push('1'); // append terminator -> unique trailing '11'
    Ok(out)
}

/// One Fibonacci code to its value: `Ok(None)` when the value is beyond the `usize` range (Python decodes
/// any width), `Err` when the string is not a code at all.
fn decode_code(code: &str) -> Result<Option<usize>, String> {
    if code.len() < 2 || !code.ends_with("11") {
        return Err(format!("not a Fibonacci code (must end in '11'): {code:?}"));
    }
    let zeck = &code[..code.len() - 1]; // strip terminator '1'
    if zeck.contains("11") {
        // Zeckendorf digits are never consecutive, so an internal "11" is a bit string `encode` can never emit.
        return Err(format!("not a Fibonacci code (consecutive 1s before the terminator): {code:?}"));
    }
    let mut sum: usize = 0;
    // The weights are 1, 2, 3, 5, ...; once the next one passes the usize range only a 0 digit may follow.
    let (mut weight, mut next_weight): (Option<usize>, Option<usize>) = (Some(1), Some(2));
    for ch in zeck.chars() {
        if ch == '1' {
            match weight.and_then(|digit_weight| sum.checked_add(digit_weight)) {
                Some(total) => sum = total,
                None => return Ok(None),
            }
        }
        let after = match (weight, next_weight) {
            (Some(low), Some(high)) => low.checked_add(high),
            _ => None,
        };
        weight = next_weight;
        next_weight = after;
    }
    Ok(Some(sum))
}

/// Inverse of `encode`: one Fibonacci code (bit-string ending in `"11"`) -> the integer.
///
/// `Err` for a string that is not a code (no `11` ending, or consecutive 1s before the terminator) and
/// for a value beyond the `usize` range: Python decodes any width, and this refuses what it cannot hold
/// instead of wrapping or panicking on a hostile frame.
pub fn decode(code: &str) -> Result<usize, String> {
    decode_code(code)?.ok_or_else(|| format!("Fibonacci code beyond the usize range: {} bits", code.len()))
}

/// Concatenate the codes; each code's trailing `"11"` frames the next — zero header, self-delimiting.
/// `Err` if any value is `< 1` (Fibonacci coding is for positive integers; the wire sends symbol+1).
pub fn encode_stream(values: &[usize]) -> Result<String, String> {
    let mut out = String::new();
    for &value in values {
        out.push_str(&encode(value)?);
    }
    Ok(out)
}

/// Split a concatenated stream at each self-framing `"11"` and decode each code.
/// A trailing run of bits with no terminator is an incomplete final frame and is dropped.
pub fn decode_stream(bits: &str) -> Vec<usize> {
    let mut out = Vec::new();
    let chars: Vec<char> = bits.chars().collect();
    let bit_count = chars.len();
    let mut start = 0;
    let mut cursor = 0;
    while cursor < bit_count {
        if chars[cursor] == '1' && cursor + 1 < bit_count && chars[cursor + 1] == '1' {
            let slice: String = chars[start..=cursor + 1].iter().collect();
            if let Ok(val) = decode(&slice) {
                out.push(val);
            }
            cursor += 2;
            start = cursor;
        } else {
            cursor += 1;
        }
    }
    out
}

/// `decode_stream` that keeps the place of a code beyond the `usize` range as `None` instead of dropping it
/// (the lenient `decode_stream` shifts every later symbol), and still drops an incomplete final frame as
/// Python's `decode_stream` does. Python decodes any width; a decoder that must count the integers on a
/// hostile frame the way Python does, and then refuse the wide ones, uses this one.
pub fn decode_stream_wide(bits: &str) -> Vec<Option<usize>> {
    decode_stream_wide_tail(bits).0
}

/// `decode_stream_wide` and the bits it left over, as Python's `decode_stream_tail` gives them: the run
/// after the last complete code. A tail with a `1` in it is a partial codeword with data bits, an all zero
/// tail is byte alignment padding.
pub fn decode_stream_wide_tail(bits: &str) -> (Vec<Option<usize>>, String) {
    let mut out = Vec::new();
    let chars: Vec<char> = bits.chars().collect();
    let bit_count = chars.len();
    let mut start = 0;
    let mut cursor = 0;
    while cursor < bit_count {
        if chars[cursor] == '1' && cursor + 1 < bit_count && chars[cursor + 1] == '1' {
            let slice: String = chars[start..=cursor + 1].iter().collect();
            // The slice holds no internal "11" (the scan splits at the first one), so it is a code.
            out.push(decode_code(&slice).unwrap_or(None));
            cursor += 2;
            start = cursor;
        } else {
            cursor += 1;
        }
    }
    (out, chars[start..].iter().collect())
}

/// Why `decode_stream_strict` refused: its own message and, where the refusal is exactly one of the strict
/// decode causes, the registry code beside it (`wire:no-terminator` 48 when the stream holds no complete
/// codeword at all, `wire:dangling-codeword` 49 when it ends in a partial codeword with data bits after a
/// complete one). A code that is not a Fibonacci code carries none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrictDecodeError {
    pub message: String,
    pub cause: Option<u8>,
}

impl std::fmt::Display for StrictDecodeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.message)
    }
}
impl std::error::Error for StrictDecodeError {}

/// Strict variant for a receiving codec: the lenient `decode_stream` silently drops an incomplete
/// final frame, which is right for the self-heal/inspect paths but hides truncation from a decoder
/// that must surface corruption. Here any leftover bits after the last complete code are an error
/// unless they are all `'0'` — a run of zero bits is legitimate byte-alignment padding
/// (`packed::pack`), while a leftover `'1'` means a truncated or corrupted final code.
pub fn decode_stream_strict(bits: &str) -> Result<Vec<usize>, StrictDecodeError> {
    let mut out = Vec::new();
    let chars: Vec<char> = bits.chars().collect();
    let bit_count = chars.len();
    let mut start = 0;
    let mut cursor = 0;
    while cursor < bit_count {
        if chars[cursor] == '1' && cursor + 1 < bit_count && chars[cursor + 1] == '1' {
            let slice: String = chars[start..=cursor + 1].iter().collect();
            out.push(decode(&slice).map_err(|message| StrictDecodeError { message, cause: None })?);
            cursor += 2;
            start = cursor;
        } else {
            cursor += 1;
        }
    }
    if chars[start..].contains(&'1') {
        return Err(StrictDecodeError {
            message: format!("truncated Fibonacci stream: {} trailing bits contain a '1' with no terminator", bit_count - start),
            cause: Some(if out.is_empty() { causes::WIRE_NO_TERMINATOR } else { causes::WIRE_DANGLING_CODEWORD }),
        });
    }
    Ok(out)
}
