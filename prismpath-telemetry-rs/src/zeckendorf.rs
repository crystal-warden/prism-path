//! Zeckendorf / Fibonacci codec — the self-framing wire for the decision-preserving telemetry stream.

fn fibs_upto(n: usize) -> Vec<usize> {
    // `fibs` is seeded with [1, 2] and only ever grows, so `.last()` is always Some.
    let mut fibs = vec![1, 2];
    while *fibs.last().expect("fibs seeded non-empty") <= n {
        let next = fibs[fibs.len() - 1] + fibs[fibs.len() - 2];
        fibs.push(next);
    }
    if *fibs.last().expect("fibs seeded non-empty") > n {
        fibs.pop();
    }
    fibs
}

/// Fibonacci code of a positive integer `n` (>= 1) as a bit-string ending in `"11"`.
pub fn encode(n: usize) -> Result<String, String> {
    if n < 1 {
        return Err(format!("Fibonacci coding is for positive integers; got {n}"));
    }
    let fibs = fibs_upto(n);
    let mut bits = vec!['0'; fibs.len()];
    let mut rem = n;
    for i in (0..fibs.len()).rev() {
        if fibs[i] <= rem {
            bits[i] = '1';
            rem -= fibs[i];
        }
    }
    assert_eq!(rem, 0, "Zeckendorf decomposition failed for {n}");
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
    for (i, ch) in zeck.chars().enumerate() {
        if ch == '1' {
            sum += fibs[i];
        }
    }
    Ok(sum)
}

/// Concatenate the codes; each code's trailing `"11"` frames the next — zero header, self-delimiting.
/// `Err` if any value is `< 1` (Fibonacci coding is for positive integers; the wire sends symbol+1).
pub fn encode_stream(values: &[usize]) -> Result<String, String> {
    let mut out = String::new();
    for &v in values {
        out.push_str(&encode(v)?);
    }
    Ok(out)
}

/// Split a concatenated stream at each self-framing `"11"` and decode each code.
/// A trailing run of bits with no terminator is an incomplete final frame and is dropped.
pub fn decode_stream(bits: &str) -> Vec<usize> {
    let mut out = Vec::new();
    let chars: Vec<char> = bits.chars().collect();
    let n = chars.len();
    let mut start = 0;
    let mut i = 0;
    while i < n {
        if chars[i] == '1' && i + 1 < n && chars[i + 1] == '1' {
            let slice: String = chars[start..=i + 1].iter().collect();
            if let Ok(val) = decode(&slice) {
                out.push(val);
            }
            i += 2;
            start = i;
        } else {
            i += 1;
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
    let n = chars.len();
    let mut start = 0;
    let mut i = 0;
    while i < n {
        if chars[i] == '1' && i + 1 < n && chars[i + 1] == '1' {
            let slice: String = chars[start..=i + 1].iter().collect();
            out.push(decode(&slice)?);
            i += 2;
            start = i;
        } else {
            i += 1;
        }
    }
    if chars[start..].contains(&'1') {
        return Err(format!(
            "truncated Fibonacci stream: {} trailing bits contain a '1' with no terminator",
            n - start
        ));
    }
    Ok(out)
}
