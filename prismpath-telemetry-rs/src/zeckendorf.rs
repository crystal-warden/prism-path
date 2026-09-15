// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! Zeckendorf / Fibonacci codec — the self-framing wire for the decision-preserving telemetry stream.

fn fibs_upto(upper_bound: usize) -> Vec<usize> {
    // `fibs` is seeded with [1, 2] and only ever grows, so `.last()` is always Some.
    let mut fibs = vec![1, 2];
    while *fibs.last().expect("fibs seeded non-empty") <= upper_bound {
        let next = fibs[fibs.len() - 1] + fibs[fibs.len() - 2];
        fibs.push(next);
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

/// Inverse of `encode`: one Fibonacci code (bit-string ending in `"11"`) -> the integer.
pub fn decode(code: &str) -> Result<usize, String> {
    if code.len() < 2 || !code.ends_with("11") {
        return Err(format!("not a Fibonacci code (must end in '11'): {code:?}"));
    }
    let zeck = &code[..code.len() - 1]; // strip terminator '1'
    let mut fibs = vec![1, 2];
    while fibs.len() < zeck.len() {
        let next = fibs[fibs.len() - 1] + fibs[fibs.len() - 2];
        fibs.push(next);
    }
    let mut sum = 0;
    for (index, ch) in zeck.chars().enumerate() {
        if ch == '1' {
            sum += fibs[index];
        }
    }
    Ok(sum)
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

/// Strict variant for a receiving codec: the lenient `decode_stream` silently drops an incomplete
/// final frame, which is right for the self-heal/inspect paths but hides truncation from a decoder
/// that must surface corruption. Here any leftover bits after the last complete code are an error
/// unless they are all `'0'` — a run of zero bits is legitimate byte-alignment padding
/// (`packed::pack`), while a leftover `'1'` means a truncated or corrupted final code.
pub fn decode_stream_strict(bits: &str) -> Result<Vec<usize>, String> {
    let mut out = Vec::new();
    let chars: Vec<char> = bits.chars().collect();
    let bit_count = chars.len();
    let mut start = 0;
    let mut cursor = 0;
    while cursor < bit_count {
        if chars[cursor] == '1' && cursor + 1 < bit_count && chars[cursor + 1] == '1' {
            let slice: String = chars[start..=cursor + 1].iter().collect();
            out.push(decode(&slice)?);
            cursor += 2;
            start = cursor;
        } else {
            cursor += 1;
        }
    }
    if chars[start..].contains(&'1') {
        return Err(format!(
            "truncated Fibonacci stream: {} trailing bits contain a '1' with no terminator",
            bit_count - start
        ));
    }
    Ok(out)
}
