// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC

//! The Rust leg of the canon/2 differential (formal/diff/canon2_diff.py). An adapter, not part of the
//! crate: it reads framed documents on stdin, each `<byte length>\n<bytes>\n`, and prints one line per
//! document, `<strict> ; <canonicalize>`: `canon2::read`'s answer (`ok <hex>` with `canon2::write` of the
//! value, or `refuse <rule>`) and `canon2::canonicalize`'s (`canon <hex>` or `refuse <rule>`), or `panic`.
use prismpath_rs::canon2;
use std::io::{Read, Write};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn line(doc: &[u8]) -> String {
    let strict = match canon2::read(doc).and_then(|value| canon2::write(&value)) {
        Err(e) => format!("refuse {}", e.rule()),
        Ok(out) => format!("ok {}", hex(&out)),
    };
    let canon = match canon2::canonicalize(doc) {
        Err(e) => format!("refuse {}", e.rule()),
        Ok(out) => format!("canon {}", hex(&out)),
    };
    format!("{strict} ; {canon}")
}

fn main() {
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input).expect("stdin");
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    std::panic::set_hook(Box::new(|_| {}));
    let mut pos = 0usize;
    while pos < input.len() {
        let nl = match input[pos..].iter().position(|&b| b == b'\n') {
            Some(i) => pos + i,
            None => std::process::exit(2),
        };
        let n: usize = std::str::from_utf8(&input[pos..nl]).ok().and_then(|s| s.parse().ok()).unwrap_or_else(|| std::process::exit(2));
        let start = nl + 1;
        if start + n + 1 > input.len() {
            std::process::exit(2);
        }
        let doc = &input[start..start + n];
        let text = std::panic::catch_unwind(|| line(doc)).unwrap_or_else(|_| "panic".to_string());
        writeln!(out, "{}", text).expect("stdout");
        pos = start + n + 1;
    }
}
