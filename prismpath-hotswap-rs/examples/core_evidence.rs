// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! A differential run as evidence, the Rust twin of `formal/diff/core_evidence.py`
//! (docs/design/spec-verified-core.md, section 11). The run format is that module's, byte for byte:
//! `run.json` (the manifest), `cases.jsonl` (the inputs), `images.jsonl` (an image attestation per case,
//! Ed25519 with the authority key over `prismpath.core-image/1\0` and the image's canon/2 bytes),
//! `receipts.jsonl` (a canon/2 receipt per decision; a receipt is not signed by itself) and
//! `receipts.roots.jsonl` (one canon/2 root statement, `prismpath.core-run-root/2`, signed with the
//! instance key over its own domain prefix, over the receipts' RFC 6962 Merkle root, binding the manifest, its time
//! an integer count of microseconds), with the two public keys beside them.
//!
//!     core_evidence produce --from CASES.jsonl --out RUN --keys KEYS   # the Rust port decides
//!     core_evidence policy --from CASES.jsonl   # the ported oracle check of every image, one line each
//!     core_evidence render --from CASES.jsonl   # every image's canonical rendering, one line each
//!     core_evidence verify RUN [--sample N|all] [--seed S] [--pin-authority PUB --pin-instance PUB] [--oracle BIN]
//!
//! `produce` decides every case with the Rust port, composed as the differential harness's Rust leg
//! composes it (`prismpath-rs/examples/core_diff.rs`), and signs with test keys it generates in `--keys`
//! when none are there (`keygen`, the pack signing code); a case outside the core is excluded with its
//! reason (`outside_core`). `verify` re-checks the root statement, every
//! receipt, every image attestation and that every stored flow is its image's canonical rendering
//! (`render`, the port of `prismpath.kernel.core_render`), and replays a sample of the decisions through the Lean oracle;
//! it verifies a run the Python module produced, and the Python module verifies one produced here.

use ed25519_dalek::Signer;
use prismpath_hotswap_rs::merkle::merkle_root;
use prismpath_hotswap_rs::{keygen, load_private, sha256_hex, verify_ed25519};
use prismpath_rs::canon2::{self, Doc};
use prismpath_rs::field_definitions::system_boundary;
use prismpath_rs::{causes, first_deterministic, parse, Value};
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

const RUN_FORMAT: &str = "prismpath.core-run/1";
const IMAGE_FORMAT: &str = "prismpath.core-image/1";
const RECEIPT_FORMAT: &str = "prismpath.core-receipt/1";
const IMAGE_DOMAIN: &[u8] = b"prismpath.core-image/1\x00";
const LOG_CORE_RUN: &str = "core-run";
/// The run's root statement: canon/2, its own format and domain prefix (`core_evidence.ROOT_FORMAT`).
/// `/2` states a root of the RFC 6962 tree; `/1` stated one of the retired tree and is refused by name.
const ROOT_FORMAT: &str = "prismpath.core-run-root/2";
const ROOT_DOMAIN: &[u8] = b"prismpath.core-run-root/2\x00";
const OLD_ROOT_FORMATS: [&str; 1] = ["prismpath.core-run-root/1"];
const ROOT_MEMBERS: [&str; 10] = ["format", "log", "root", "leaves", "time_us", "trigger", "key_id", "public_key", "policy", "sig"];
const FILES: [&str; 7] = ["run.json", "cases.jsonl", "images.jsonl", "receipts.jsonl", "receipts.roots.jsonl", "authority.pub", "instance.pub"];

struct Case {
    id: String,
    image: Vec<u8>,
    flow: Option<String>,
    readings: Vec<Vec<u8>>,
}

fn obj(members: Vec<(&str, Doc)>) -> Doc {
    Doc::Obj(members.into_iter().map(|(key, value)| (key.to_string(), value)).collect())
}

fn text(value: &str) -> Doc {
    Doc::Str(value.to_string())
}

fn member<'a>(doc: &'a Doc, key: &str) -> Option<&'a Doc> {
    match doc {
        Doc::Obj(members) => members.iter().find(|(name, _)| name == key).map(|(_, value)| value),
        _ => None,
    }
}

fn str_of<'a>(doc: &'a Doc, key: &str) -> Result<&'a str, String> {
    match member(doc, key) {
        Some(Doc::Str(value)) => Ok(value),
        _ => Err(format!("no string member {key:?}")),
    }
}

fn int_of(doc: &Doc, key: &str) -> Result<i64, String> {
    match member(doc, key) {
        Some(Doc::Int(value)) => Ok(*value),
        _ => Err(format!("no integer member {key:?}")),
    }
}

fn lines(bytes: &[u8]) -> Vec<&[u8]> {
    let mut out: Vec<&[u8]> = bytes.split(|byte| *byte == b'\n').collect();
    if out.last().is_some_and(|line| line.is_empty()) {
        out.pop();
    }
    out
}

fn unhex(value: &str) -> Result<Vec<u8>, String> {
    hex::decode(value).map_err(|error| error.to_string())
}

fn read_cases(bytes: &[u8]) -> Result<Vec<Case>, String> {
    let mut cases = Vec::new();
    for line in lines(bytes) {
        let row = canon2::read(line).map_err(|error| format!("cases.jsonl: {error}"))?;
        let readings = match member(&row, "readings") {
            Some(Doc::Arr(items)) => items
                .iter()
                .map(|item| match item {
                    Doc::Str(value) => unhex(value),
                    _ => Err("a reading is hex".to_string()),
                })
                .collect::<Result<Vec<_>, _>>()?,
            _ => return Err("cases.jsonl: no readings".to_string()),
        };
        let flow = match member(&row, "flow") {
            Some(Doc::Str(flow)) => Some(flow.clone()),
            Some(Doc::Null) => None,
            _ => return Err("cases.jsonl: the flow is text or null".to_string()),
        };
        cases.push(Case { id: str_of(&row, "case")?.to_string(), image: unhex(str_of(&row, "image")?)?, flow, readings });
    }
    Ok(cases)
}

// ----------------------------------------------------------------- the canonical rendering
/// An image's canonical rendering as the flow text the kernels parse, the port of
/// `prismpath.kernel.core_render.render` with no random source (every choice takes its plainest spelling),
/// or None for an image with no faithful rendering. A run stores this text beside each image, and `verify`
/// refuses a run whose stored flow is not it: the decisions come from the flow, so a flow edited away from
/// the signed image would decide a policy the authority never signed. `core_evidence render` prints it for
/// every case, so the Python suite holds the two renderings equal.
mod render {
    use prismpath_rs::canon2::{self, Doc};

    const FORMAT: &str = "prismpath.core/1";
    const START: &str = "core_decision";
    const ALWAYS: [&str; 6] = ["always", "true", "else", "otherwise", "default", "_"];
    const NEVER: [&str; 2] = ["false", "never"];
    const OPERATORS: [&str; 6] = ["<", "<=", ">", ">=", "==", "!="];
    const BREAKS: [char; 10] = ['\n', '\r', '\x0b', '\x0c', '\x1c', '\x1d', '\x1e', '\u{85}', '\u{2028}', '\u{2029}'];

    type R = Result<String, ()>;

    fn ident(name: &str) -> bool {
        let mut chars = name.chars();
        matches!(chars.next(), Some(first) if first.is_ascii_alphabetic() || first == '_')
            && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    }

    fn name_of(doc: &Doc) -> R {
        match doc {
            Doc::Str(name) if ident(name) => Ok(name.clone()),
            _ => Err(()),
        }
    }

    fn py_string(value: &str) -> String {
        let mut out = String::from("\"");
        for ch in value.chars() {
            let code = ch as u32;
            match ch {
                '\\' => out.push_str("\\\\"),
                '"' => out.push_str("\\\""),
                _ if code < 0x20 || code == 0x7f || code == 0x85 || code == 0x2028 || code == 0x2029 => {
                    out.push_str(&if code < 0x100 { format!("\\x{code:02x}") } else { format!("\\u{code:04x}") })
                }
                _ => out.push(ch),
            }
        }
        out.push('"');
        out
    }

    fn digits(text: &str) -> bool {
        !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
    }

    /// `-?[1-9][0-9]*`
    fn plain_integer(text: &str) -> bool {
        let body = text.strip_prefix('-').unwrap_or(text);
        body.as_bytes().first().is_some_and(|first| (b'1'..=b'9').contains(first)) && digits(body) 
    }

    /// `[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?`
    fn decimal(text: &str) -> bool {
        let body = text.strip_prefix(['+', '-']).unwrap_or(text);
        let (mantissa, exponent) = match body.find(['e', 'E']) {
            Some(at) => (&body[..at], Some(&body[at + 1..])),
            None => (body, None),
        };
        let mantissa_ok = match mantissa.split_once('.') {
            Some((whole, fraction)) => (digits(whole) && (fraction.is_empty() || digits(fraction))) || (whole.is_empty() && digits(fraction)),
            None => digits(mantissa),
        };
        let exponent_ok = exponent.is_none_or(|exp| digits(exp.strip_prefix(['+', '-']).unwrap_or(exp)));
        mantissa_ok && exponent_ok
    }

    fn constant(k: &Doc) -> R {
        let Doc::Arr(items) = k else { return Err(()) };
        let Some(Doc::Str(tag)) = items.first() else { return Err(()) };
        match (tag.as_str(), &items[1..]) {
            ("num", [Doc::Int(value)]) => Ok(value.to_string()),
            ("num", [Doc::Str(value)]) if plain_integer(value) || (decimal(value) && value.contains(['.', 'e', 'E'])) => Ok(value.clone()),
            ("bool", [Doc::Bool(value)]) => Ok(if *value { "True" } else { "False" }.to_string()),
            ("str", [Doc::Str(value)]) => Ok(py_string(value)),
            ("none", []) => Ok("None".to_string()),
            ("field", [Doc::Str(name)]) if ident(name) => Ok(name.clone()),
            _ => Err(()),
        }
    }

    fn is_junction(doc: &Doc) -> bool {
        matches!(doc, Doc::Arr(items) if matches!(items.first(), Some(Doc::Str(tag)) if tag == "and" || tag == "or"))
    }

    fn condition(c: &Doc, top: bool) -> R {
        let Doc::Arr(items) = c else { return Err(()) };
        let Some(Doc::Str(tag)) = items.first() else { return Err(()) };
        match tag.as_str() {
            "truthy" if items.len() == 2 => {
                let name = name_of(&items[1])?;
                let lower = name.to_lowercase();
                Ok(if top && (ALWAYS.contains(&lower.as_str()) || NEVER.contains(&lower.as_str())) { format!("({name})") } else { name })
            }
            "cmp" if items.len() == 4 && matches!(items[2], Doc::Str(_)) => {
                let Doc::Str(op) = &items[2] else { unreachable!() };
                if !OPERATORS.contains(&op.as_str()) {
                    return Err(());
                }
                let name = name_of(&items[1])?;
                Ok(format!("{name} {op} {}", constant(&items[3])?))
            }
            "in" | "not in" if items.len() == 3 && matches!(items[2], Doc::Arr(_)) => {
                let name = name_of(&items[1])?;
                let Doc::Arr(set) = &items[2] else { unreachable!() };
                let members = set.iter().map(constant).collect::<Result<Vec<_>, _>>()?;
                Ok(format!("{name} {tag} [{}]", members.join(", ")))
            }
            "not" if items.len() == 2 => {
                let inner = condition(&items[1], false)?;
                Ok(if is_junction(&items[1]) { format!("not ({inner})") } else { format!("not {inner}") })
            }
            "and" | "or" if items.len() >= 3 => {
                let parts = items[1..]
                    .iter()
                    .map(|operand| condition(operand, false).map(|text| if is_junction(operand) { format!("({text})") } else { text }))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(parts.join(&format!(" {tag} ")))
            }
            _ => Err(()),
        }
    }

    fn member<'a>(members: &'a [(String, Doc)], key: &str) -> Option<&'a Doc> {
        members.iter().find(|(name, _)| name == key).map(|(_, value)| value)
    }

    fn python_space(ch: char) -> bool {
        ch.is_whitespace() || ('\x1c'..='\x1f').contains(&ch)
    }

    /// The canonical rendering of a canon/2 document in the core's abstract syntax, or Err.
    pub fn render(doc: &Doc) -> R {
        let Doc::Obj(members) = doc else { return Err(()) };
        let mut keys: Vec<&str> = members.iter().map(|(key, _)| key.as_str()).collect();
        keys.sort_unstable();
        if keys != ["fields", "format", "rules"] || member(members, "format") != Some(&Doc::Str(FORMAT.to_string())) {
            return Err(());
        }
        let (Some(Doc::Obj(fields)), Some(Doc::Arr(rules))) = (member(members, "fields"), member(members, "rules")) else { return Err(()) };
        let mut lines = vec!["---".to_string(), "name: core".to_string(), format!("start: {START}")];
        for (name, definition) in fields {
            let Doc::Str(definition) = definition else { return Err(()) };
            if name.is_empty() || name.contains(':') || name.chars().chain(definition.chars()).any(|ch| BREAKS.contains(&ch))
                || name.trim_matches(python_space) != name || name.starts_with('-')
            {
                return Err(());
            }
            lines.push(format!("field.{name}: {definition}"));
        }
        lines.push("---".to_string());
        lines.push(format!("## {START}"));
        let mut targets: Vec<String> = Vec::new();
        for rule in rules {
            let Doc::Obj(parts) = rule else { return Err(()) };
            let mut keys: Vec<&str> = parts.iter().map(|(key, _)| key.as_str()).collect();
            keys.sort_unstable();
            let (Some(Doc::Str(target)), Some(when)) = (member(parts, "target"), member(parts, "when")) else { return Err(()) };
            if keys != ["target", "when"] || target.is_empty() || !target.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-') {
                return Err(());
            }
            let single = |word: &str| matches!(when, Doc::Arr(items) if items.len() == 1 && items[0] == Doc::Str(word.to_string()));
            let cond = if single("always") {
                "always".to_string()
            } else if single("never") {
                "never".to_string()
            } else {
                format!("when {}", condition(when, true)?)
            };
            lines.push(format!("-> {target}: {cond}"));
            let lower = target.to_lowercase();
            if lower != START && !targets.contains(&lower) {
                targets.push(lower);
            }
        }
        for target in targets {
            lines.push(format!("## {target}"));
        }
        Ok(lines.join("\n") + "\n")
    }

    /// The canonical flow of an image's bytes, or None when it has none (unreadable or unrenderable).
    pub fn flow_of(image: &[u8]) -> Option<String> {
        render(&canon2::read(image).ok()?).ok()
    }
}

/// Why a case's stored flow is not the canonical rendering of its signed image (`core_evidence.flow_problem`).
fn flow_problem(case: &Case) -> Option<String> {
    let flow = render::flow_of(&case.image);
    if case.flow == flow {
        return None;
    }
    Some(match flow {
        None => format!("case {}: the stored flow renders no image: the signed image has no rendering", case.id),
        Some(_) => format!("case {}: the stored flow is not the rendering of the signed image", case.id),
    })
}

/// The canonical rendering of every case's image, one canon/2 line each (`{"case", "flow"}`), for the
/// Python suite to hold to `core_render.flow_of`.
fn render_lines(source: &Path) -> Result<String, String> {
    let cases = read_cases(&std::fs::read(source).map_err(|error| error.to_string())?)?;
    let mut out = Vec::new();
    for case in &cases {
        let flow = render::flow_of(&case.image).map_or(Doc::Null, Doc::Str);
        let line = canon2::write(&obj(vec![("case", text(&case.id)), ("flow", flow)])).map_err(|error| error.to_string())?;
        out.push(String::from_utf8(line).map_err(|error| error.to_string())?);
    }
    Ok(out.join("\n"))
}

// ----------------------------------------------------------------- the core's scope
/// Why a case is not a decision of the core, or None, as `core_evidence.outside_core` decides it from the
/// image alone: `engine-counter` when the oracle refuses the image for reading an engine counter (the
/// oracle's own check, ported in `oracle_policy`), `unrenderable` or `inferred-path`.
fn outside_core(image: &[u8], flow: Option<&str>) -> Option<&'static str> {
    let doc = canon2::read(image).ok()?;
    if oracle_policy::refuses_for_counter(image) {
        return Some("engine-counter");
    }
    if flow.is_none() {
        return Some("unrenderable");
    }
    let whens: Vec<&Doc> = match member(&doc, "rules") {
        Some(Doc::Arr(rules)) => rules.iter().filter_map(|rule| if let Doc::Obj(_) = rule { member(rule, "when") } else { None }).collect(),
        _ => Vec::new(),
    };
    let catch_all = |when: &Doc| matches!(when, Doc::Arr(items) if items.len() == 1 && (items[0] == text("always") || items[0] == text("never")));
    if matches!(member(&doc, "fields"), Some(Doc::Obj(fields)) if fields.is_empty()) && whens.iter().any(|when| !catch_all(when)) {
        return Some("inferred-path");
    }
    None
}

/// The ported check's result on every case, one canon/2 line each, for `core_evidence.py scope-check
/// --rust`, which holds it to the Python port and so to the oracle.
fn policy_lines(source: &Path) -> Result<String, String> {
    let cases = read_cases(&std::fs::read(source).map_err(|error| error.to_string())?)?;
    let mut out = Vec::new();
    for case in &cases {
        let mut members = vec![("case", text(&case.id))];
        match oracle_policy::load_policy(&case.image) {
            None => members.push(("policy", text("accepted"))),
            Some(refused) => {
                members.extend([("policy", text("refused")), ("cause", text(refused.cause)), ("code", Doc::Int(refused.code()))]);
                if let Some(field) = &refused.field {
                    members.push(("field", text(field)));
                }
                if let Some(reason) = &refused.reason {
                    members.push(("reason", text(reason)));
                }
            }
        }
        out.extend(canon2::write(&obj(members)).map_err(|error| error.to_string())?);
        out.push(b'\n');
    }
    String::from_utf8(out).map(|text| text.trim_end().to_string()).map_err(|error| error.to_string())
}

// ----------------------------------------------------------------- the oracle's check of an image
/// The oracle's check of a policy image, ported from the Lean semantics (`loadPolicy`,
/// formal/Core/Policy.lean) as `formal/diff/core_policy.py` ports it, so the producer decides what the
/// oracle decides about an image without running the oracle. Each function names the Lean definition it
/// ports and checks in Lean's order (spec section 4). Integers past the bounds the checks compare with
/// (plus or minus 2^53 times a scale of at most 10^9, an exponent of at most 30) are held as values of the
/// same sign past those bounds, which changes no comparison.
mod oracle_policy {
    use prismpath_rs::canon2::{self, Doc};

    const EXACT_LIMIT: i128 = 9_007_199_254_740_991;
    const FORMAT_TAG: &str = "prismpath.core/1";
    const MAX_COND_DEPTH: usize = 50;
    const MAX_SCALE: i128 = 1_000_000_000;
    /// A value this wide is past every bound a check compares with, and times a scale still fits in i128.
    const WIDE: i128 = 100_000_000_000_000_000_000;
    const ENGINE_COUNTERS: [&str; 2] = ["visits", "error_count"];
    const HARD_KEYWORDS: [&str; 35] = [
        "False", "None", "True", "and", "as", "assert", "async", "await", "break", "class", "continue", "def", "del", "elif", "else", "except", "finally", "for", "from",
        "global", "if", "import", "in", "is", "lambda", "nonlocal", "not", "or", "pass", "raise", "return", "try", "while", "with", "yield",
    ];
    const OPS: [&str; 6] = ["<", "<=", ">", ">=", "==", "!="];
    const ORDER_OPS: [&str; 4] = ["<", "<=", ">", ">="];

    /// One `PolicyErr`, as `spellPolicy` spells it: its registered cause, and the field and reason.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Refused {
        pub cause: &'static str,
        pub field: Option<String>,
        pub reason: Option<String>,
    }

    impl Refused {
        /// `PolicyErr.code`.
        pub fn code(&self) -> i64 {
            match self.cause {
                "policy:unreadable" => 89,
                "policy:shape" => 90,
                "image:unknown-op" => 74,
                "image:unknown-type" => 75,
                "policy:not-level-m" => 91,
                "policy:definition" => 92,
                "image:field-index-oob" => 76,
                "policy:engine-counter" => 93,
                "policy:kind-mismatch" => 94,
                "policy:rounding" => 95,
                "policy:threshold" => 96,
                "policy:none" => 97,
                "policy:not-canonical" => 101,
                _ => 98,
            }
        }
    }

    type Pe<T> = Result<T, Refused>;

    fn refuse<T>(cause: &'static str, field: Option<&str>, reason: Option<&str>) -> Pe<T> {
        Err(Refused { cause, field: field.map(str::to_string), reason: reason.map(str::to_string) })
    }

    fn shape<T>(what: &str) -> Pe<T> {
        refuse("policy:shape", None, Some(what))
    }

    #[derive(Clone)]
    struct Dec {
        neg: bool,
        digits: i128,
        frac_len: i64,
        exp: i64,
        sig: usize,
    }

    #[derive(Clone)]
    enum Const {
        Int(i128),
        Dec(Dec),
        Bool,
        Str,
        Null,
    }

    enum Cond {
        Always,
        Never,
        Truthy(String),
        Cmp(String, &'static str, Const),
        Mem(String, Vec<Const>),
        Not(Box<Cond>),
        All(Vec<Cond>),
    }

    struct Def {
        name: String,
        kind: &'static str,
        scale: i128,
        rounding: &'static str,
        lo: i128,
        hi: i128,
        absent_ok: bool,
    }

    fn is_alpha(c: char) -> bool {
        c.is_ascii_alphabetic()
    }

    /// `isIdent`.
    fn is_ident(text: &str) -> bool {
        let mut chars = text.chars();
        matches!(chars.next(), Some(c) if is_alpha(c) || c == '_') && chars.all(|c| is_alpha(c) || c.is_ascii_digit() || c == '_')
    }

    /// `isTarget`.
    fn is_target(text: &str) -> bool {
        !text.is_empty() && text.chars().all(|c| is_alpha(c) || c.is_ascii_digit() || c == '_' || c == '-')
    }

    /// `digitsValue`, exact below `WIDE`.
    fn digits_value(digits: &str) -> i128 {
        let body = digits.trim_start_matches('0');
        if body.len() > 20 {
            WIDE
        } else {
            body.bytes().fold(0i128, |acc, byte| acc * 10 + i128::from(byte - b'0')).min(WIDE)
        }
    }

    fn span_digits(text: &str) -> (&str, &str) {
        let at = text.find(|c: char| !c.is_ascii_digit()).unwrap_or(text.len());
        text.split_at(at)
    }

    /// `parseDecimal`.
    fn parse_decimal(text: &str) -> Option<Dec> {
        let (neg, rest) = match text.as_bytes().first() {
            Some(b'-') => (true, &text[1..]),
            Some(b'+') => (false, &text[1..]),
            _ => (false, text),
        };
        let (int_part, rest) = span_digits(rest);
        let (frac_part, rest) = match rest.strip_prefix('.') {
            Some(after) => span_digits(after),
            None => ("", rest),
        };
        if int_part.is_empty() && frac_part.is_empty() {
            return None;
        }
        let (exp, rest) = match rest.strip_prefix(['e', 'E']) {
            Some(after) => {
                let (eneg, after) = match after.as_bytes().first() {
                    Some(b'-') => (true, &after[1..]),
                    Some(b'+') => (false, &after[1..]),
                    _ => (false, after),
                };
                let (exp_digits, after) = span_digits(after);
                if exp_digits.is_empty() {
                    return None;
                }
                let body = exp_digits.trim_start_matches('0');
                let value = if body.len() > 6 { 1_000_000 } else { body.parse::<i64>().unwrap_or(0) };
                (if eneg { -value } else { value }, after)
            }
            None => (0, rest),
        };
        if !rest.is_empty() {
            return None;
        }
        let every = format!("{int_part}{frac_part}");
        let sig = every.trim_start_matches('0').len();
        // the digits' value is read only when the literal is in bounds, at most 28 significant digits
        let digits = if sig <= 28 { digits_value(&every) } else { 0 };
        Some(Dec { neg, digits, frac_len: frac_part.len() as i64, exp, sig })
    }

    /// `decInBounds`.
    fn dec_in_bounds(dec: &Dec) -> bool {
        dec.sig <= 28 && dec.exp.abs() <= 30
    }

    /// `Dec.scaled`.
    fn dec_scaled(dec: &Dec, scale: i128) -> Option<i128> {
        let m = dec.digits * scale;
        let t = dec.exp - dec.frac_len;
        let value = if t >= 0 {
            // t is at most 30 in bounds; past i128 the value is past every range a field has
            10i128.checked_pow(t as u32).and_then(|power| m.checked_mul(power)).unwrap_or(if m == 0 { 0 } else { i128::MAX })
        } else if -t > 38 {
            // m is below 10^37, so it is a multiple of 10^-t only when it is 0
            if m == 0 {
                0
            } else {
                return None;
            }
        } else {
            let power = 10i128.pow((-t) as u32);
            if m % power != 0 {
                return None;
            }
            m / power
        };
        Some(if dec.neg { -value } else { value })
    }

    /// `isCanonicalIntText`.
    fn is_canonical_int_text(text: &str) -> bool {
        if text == "0" {
            return true;
        }
        let body = text.strip_prefix('-').unwrap_or(text);
        !body.is_empty() && !body.starts_with('0') && body.bytes().all(|byte| byte.is_ascii_digit())
    }

    fn member<'a>(members: &'a [(String, Doc)], key: &str) -> Option<&'a Doc> {
        members.iter().find(|(name, _)| name == key).map(|(_, value)| value)
    }

    /// `decodeConst`.
    fn decode_const(j: &Doc) -> Pe<Const> {
        if let Doc::Arr(items) = j {
            match items.as_slice() {
                [Doc::Str(tag), Doc::Int(n)] if tag == "num" => return Ok(Const::Int(i128::from(*n))),
                [Doc::Str(tag), Doc::Str(text)] if tag == "num" => {
                    if is_canonical_int_text(text) {
                        let n = match text.strip_prefix('-') {
                            Some(body) => -digits_value(body),
                            None => digits_value(text),
                        };
                        if !(-EXACT_LIMIT..=EXACT_LIMIT).contains(&n) {
                            return Ok(Const::Int(n));
                        }
                        return shape("integer-as-string");
                    }
                    return match parse_decimal(text) {
                        Some(dec) if text.contains(['.', 'e', 'E']) => {
                            if dec_in_bounds(&dec) {
                                Ok(Const::Dec(dec))
                            } else {
                                refuse("policy:threshold", Some(""), Some("digits"))
                            }
                        }
                        Some(_) => shape("number-spelling"),
                        None => shape("number-text"),
                    };
                }
                [Doc::Str(tag), Doc::Bool(_)] if tag == "bool" => return Ok(Const::Bool),
                [Doc::Str(tag), Doc::Str(_)] if tag == "str" => return Ok(Const::Str),
                [Doc::Str(tag)] if tag == "none" => return Ok(Const::Null),
                [Doc::Str(tag), Doc::Str(_)] if tag == "field" => return refuse("image:unknown-type", None, Some("field-vs-field")),
                [Doc::Str(tag), ..] if tag == "list" => return refuse("image:unknown-type", None, Some("nested-container")),
                _ => {}
            }
        }
        refuse("image:unknown-type", None, Some("constant"))
    }

    /// `checkName`.
    fn check_name(name: &str) -> Pe<()> {
        if !is_ident(name) || HARD_KEYWORDS.contains(&name) {
            return refuse("policy:not-level-m", None, Some("name"));
        }
        Ok(())
    }

    /// `decodeCond`, arm by arm in Lean's order.
    fn decode_cond(j: &Doc) -> Pe<Cond> {
        if let Doc::Arr(items) = j {
            match items.as_slice() {
                [Doc::Str(tag)] if tag == "always" => return Ok(Cond::Always),
                [Doc::Str(tag)] if tag == "never" => return Ok(Cond::Never),
                [Doc::Str(tag), Doc::Str(f)] if tag == "truthy" => {
                    check_name(f)?;
                    return Ok(Cond::Truthy(f.clone()));
                }
                [Doc::Str(tag), Doc::Str(f), Doc::Str(op), k] if tag == "cmp" => {
                    check_name(f)?;
                    let Some(op) = OPS.iter().copied().find(|known| known == op) else {
                        return refuse("image:unknown-op", None, Some("operator"));
                    };
                    let constant = decode_const(k)?;
                    if ORDER_OPS.contains(&op) && matches!(constant, Const::Str) {
                        return refuse("image:unknown-op", None, Some("string-ordering"));
                    }
                    return Ok(Cond::Cmp(f.clone(), op, constant));
                }
                [Doc::Str(tag), Doc::Str(f), list] if tag == "in" || tag == "not in" => {
                    let Doc::Arr(ks) = list else {
                        return refuse("image:unknown-op", None, Some("membership-not-in-a-list"));
                    };
                    check_name(f)?;
                    let consts = ks.iter().map(decode_const).collect::<Pe<Vec<_>>>()?;
                    return Ok(Cond::Mem(f.clone(), consts));
                }
                [Doc::Str(tag), c] if tag == "not" => return Ok(Cond::Not(Box::new(decode_cond(c)?))),
                [Doc::Str(tag), _, _, ..] if tag == "and" || tag == "or" => {
                    return Ok(Cond::All(items[1..].iter().map(decode_cond).collect::<Pe<Vec<_>>>()?));
                }
                _ => {}
            }
        }
        shape("condition")
    }

    /// `Cond.depth`.
    fn depth(cond: &Cond) -> usize {
        match cond {
            Cond::Always | Cond::Never => 0,
            Cond::Truthy(_) => 1,
            Cond::Cmp(..) | Cond::Mem(..) => 2,
            Cond::Not(inner) => depth(inner) + 1,
            Cond::All(operands) => operands.iter().map(depth).max().unwrap_or(0) + 1,
        }
    }

    /// `decodeRule`.
    fn decode_rule(j: &Doc) -> Pe<Cond> {
        let Doc::Obj(members) = j else { return shape("rule") };
        if !members.iter().all(|(key, _)| key == "target" || key == "when") {
            return shape("rule-key");
        }
        let (Some(Doc::Str(target)), Some(when)) = (member(members, "target"), member(members, "when")) else {
            return shape("rule");
        };
        if !is_target(target) {
            return shape("target");
        }
        let cond = decode_cond(when)?;
        if depth(&cond) > MAX_COND_DEPTH {
            return refuse("policy:not-level-m", None, Some("depth"));
        }
        Ok(cond)
    }

    /// `decodeImage`: the definitions as text, in document order, and the rules' conditions.
    /// A decoded image: its definitions as (name, text) in document order, and its rules' conditions.
    type Decoded = (Vec<(String, String)>, Vec<Cond>);

    fn decode_image(j: &Doc) -> Pe<Decoded> {
        let Doc::Obj(members) = j else { return shape("image") };
        if !members.iter().all(|(key, _)| key == "format" || key == "fields" || key == "rules") {
            return shape("image-key");
        }
        let (Some(Doc::Str(tag)), Some(Doc::Obj(fields)), Some(Doc::Arr(rules))) = (member(members, "format"), member(members, "fields"), member(members, "rules")) else {
            return shape("image");
        };
        if tag != FORMAT_TAG {
            return shape("format");
        }
        let mut texts = Vec::new();
        for (name, text) in fields {
            let Doc::Str(text) = text else { return shape("definition-not-text") };
            texts.push((name.clone(), text.clone()));
        }
        Ok((texts, rules.iter().map(decode_rule).collect::<Pe<Vec<_>>>()?))
    }

    /// `isPyWs`: Python's `str.isspace`.
    fn is_py_ws(c: char) -> bool {
        let n = c as u32;
        (0x09..=0x0D).contains(&n)
            || (0x1C..=0x20).contains(&n)
            || [0x85, 0xA0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000].contains(&n)
            || (0x2000..=0x200A).contains(&n)
    }

    /// `intOption`: `[+-]?[0-9]+`.
    fn int_option(text: &str) -> Option<i128> {
        let (neg, body) = match text.as_bytes().first() {
            Some(b'-') => (true, &text[1..]),
            Some(b'+') => (false, &text[1..]),
            _ => (false, text),
        };
        if body.is_empty() || !body.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        Some(if neg { -digits_value(body) } else { digits_value(body) })
    }

    fn options_of(kind: &str) -> &'static [&'static str] {
        match kind {
            "int" => &["min", "max", "absent"],
            "fixed" => &["scale", "rounding", "unit", "min", "max", "absent"],
            _ => &["absent"],
        }
    }

    /// `parseDef`.
    fn parse_def(name: &str, text: &str) -> Pe<Def> {
        let bad = |reason: &str| refuse("policy:definition", Some(name), Some(reason));
        if !is_ident(name) {
            return bad("name");
        }
        if ENGINE_COUNTERS.contains(&name) {
            return bad("engine-counter");
        }
        let words: Vec<&str> = text.split(is_py_ws).filter(|word| !word.is_empty()).collect();
        let Some((kind_word, rest)) = words.split_first() else { return bad("empty") };
        let Some(kind) = ["int", "fixed", "bool", "category"].into_iter().find(|kind| kind == kind_word) else {
            return bad("unknown-kind");
        };
        let mut options: Vec<(&str, &str)> = Vec::new();
        for word in rest {
            let Some((option, value)) = word.split_once('=') else { return bad("not-option") };
            if value.is_empty() {
                return bad("not-option");
            }
            if !options_of(kind).contains(&option) {
                return bad("option-not-taken");
            }
            if options.iter().any(|(seen, _)| *seen == option) {
                return bad("option-repeated");
            }
            options.push((option, value));
        }
        let lookup = |key: &str| options.iter().find(|(option, _)| *option == key).map(|(_, value)| *value);
        let absent = lookup("absent").unwrap_or("refused");
        if absent != "refused" && absent != "allowed" {
            return bad("absent");
        }
        let (mut scale, mut rounding) = (1, "exact");
        if kind == "fixed" {
            let (Some(scale_text), Some(rounding_text)) = (lookup("scale"), lookup("rounding")) else {
                return bad("fixed-needs-scale-and-rounding");
            };
            let Some(parsed) = int_option(scale_text) else { return bad("not-integer") };
            if !(1..=MAX_SCALE).contains(&parsed) {
                return bad("scale");
            }
            let Some(mode) = ["floor", "ceiling", "exact"].into_iter().find(|mode| *mode == rounding_text) else {
                return bad("rounding");
            };
            (scale, rounding) = (parsed, mode);
        }
        let lo = match lookup("min") {
            None => -EXACT_LIMIT,
            Some(text) => match int_option(text) {
                Some(value) => value,
                None => return bad("not-integer"),
            },
        };
        let hi = match lookup("max") {
            None => EXACT_LIMIT,
            Some(text) => match int_option(text) {
                Some(value) => value,
                None => return bad("not-integer"),
            },
        };
        if !(-EXACT_LIMIT <= lo && lo <= hi && hi <= EXACT_LIMIT) {
            return bad("range");
        }
        Ok(Def { name: name.to_string(), kind, scale, rounding, lo, hi, absent_ok: absent == "allowed" })
    }

    /// `carries`; None stands for truthiness and membership.
    fn carries(rounding: &str, op: Option<&str>) -> bool {
        match rounding {
            "exact" => true,
            "floor" => matches!(op, Some(">=") | Some("<")),
            _ => matches!(op, Some(">") | Some("<=")),
        }
    }

    /// `lowerNum`.
    fn lower_num(d: &Def, constant: &Const) -> Pe<()> {
        let fixed = d.kind == "fixed";
        match constant {
            Const::Int(n) => {
                let value = if fixed { n * d.scale } else { *n };
                if value < d.lo || value > d.hi {
                    return refuse("policy:threshold", Some(&d.name), Some(if fixed { "out-of-range" } else { "constant-range" }));
                }
                Ok(())
            }
            Const::Dec(dec) => {
                if !fixed {
                    return refuse("image:unknown-type", None, Some("float"));
                }
                match dec_scaled(dec, d.scale) {
                    None => refuse("policy:threshold", Some(&d.name), Some("off-grid")),
                    Some(value) if value < d.lo || value > d.hi => refuse("policy:threshold", Some(&d.name), Some("out-of-range")),
                    Some(_) => Ok(()),
                }
            }
            _ => refuse("policy:kind-mismatch", Some(&d.name), None),
        }
    }

    /// `checkCmp`.
    fn check_cmp(d: &Def, op: &str, constant: &Const) -> Pe<()> {
        if let Const::Null = constant {
            if op != "==" && op != "!=" {
                return refuse("policy:none", Some(&d.name), Some("ordered"));
            }
            if !d.absent_ok {
                return refuse("policy:none", Some(&d.name), Some("absence-refused"));
            }
            return Ok(());
        }
        match d.kind {
            "bool" | "category" => {
                let own = matches!((d.kind, constant), ("bool", Const::Bool) | ("category", Const::Str));
                if own {
                    if op == "==" || op == "!=" {
                        return Ok(());
                    }
                    return refuse("policy:kind-mismatch", Some(&d.name), None);
                }
                if let Const::Dec(_) = constant {
                    return refuse("image:unknown-type", None, Some("float"));
                }
                refuse("policy:kind-mismatch", Some(&d.name), None)
            }
            _ => {
                let fixed = d.kind == "fixed";
                if fixed && !carries(d.rounding, Some(op)) && matches!(constant, Const::Int(_) | Const::Dec(_)) {
                    return refuse("policy:rounding", Some(&d.name), None);
                }
                lower_num(d, constant)?;
                if fixed && !carries(d.rounding, Some(op)) {
                    return refuse("policy:rounding", Some(&d.name), None);
                }
                Ok(())
            }
        }
    }

    /// `checkMem` with `lowerMembers`.
    fn check_mem(d: &Def, consts: &[Const]) -> Pe<()> {
        if consts.iter().any(|constant| matches!(constant, Const::Null)) {
            return refuse("policy:none", Some(&d.name), Some("in-list"));
        }
        for constant in consts {
            match (d.kind, constant) {
                (_, Const::Null) => return refuse("policy:none", Some(&d.name), Some("in-list")),
                ("category", Const::Str) => {}
                ("int", _) | ("fixed", _) => lower_num(d, constant)?,
                (_, Const::Dec(_)) => return refuse("image:unknown-type", None, Some("float")),
                _ => return refuse("policy:kind-mismatch", Some(&d.name), None),
            }
        }
        if d.kind == "fixed" && !carries(d.rounding, None) {
            return refuse("policy:rounding", Some(&d.name), None);
        }
        Ok(())
    }

    /// `defined`: an engine counter first, then the definition.
    fn defined<'a>(defs: &'a [Def], name: &str) -> Pe<&'a Def> {
        if ENGINE_COUNTERS.contains(&name) {
            return refuse("policy:engine-counter", Some(name), None);
        }
        match defs.iter().find(|d| d.name == name) {
            Some(d) => Ok(d),
            None => refuse("image:field-index-oob", Some(name), None),
        }
    }

    /// `lowerCond`, depth first and left to right, gathering `LCond.noneTested`.
    fn lower_cond(defs: &[Def], cond: &Cond, tested: &mut Vec<String>) -> Pe<()> {
        match cond {
            Cond::Always | Cond::Never => Ok(()),
            Cond::Truthy(f) => {
                let d = defined(defs, f)?;
                if d.kind == "fixed" && !carries(d.rounding, None) {
                    return refuse("policy:rounding", Some(&d.name), None);
                }
                Ok(())
            }
            Cond::Cmp(f, op, constant) => {
                check_cmp(defined(defs, f)?, op, constant)?;
                if let Const::Null = constant {
                    tested.push(f.clone());
                }
                Ok(())
            }
            Cond::Mem(f, consts) => check_mem(defined(defs, f)?, consts),
            Cond::Not(inner) => lower_cond(defs, inner, tested),
            Cond::All(operands) => operands.iter().try_for_each(|operand| lower_cond(defs, operand, tested)),
        }
    }

    /// The cause of an image the strict reader refuses: its own for a document that is not its canonical
    /// spelling (`PolicyErr.code` 101), `policy:unreadable` for a reader rule.
    pub fn unreadable_image_cause(error: canon2::Canon2Error) -> &'static str {
        if error == canon2::Canon2Error::NotCanonical {
            "policy:not-canonical"
        } else {
            "policy:unreadable"
        }
    }

    /// `loadPolicy` on the image's bytes: None when the oracle accepts it, else its refusal.
    pub fn load_policy(image: &[u8]) -> Option<Refused> {
        let doc = match canon2::read(image) {
            Ok(doc) => doc,
            Err(error) => return Some(Refused { cause: unreadable_image_cause(error), field: None, reason: Some(error.rule().to_string()) }),
        };
        check_image(&doc).err()
    }

    /// `decodeImage` then `checkImage`: the definitions, every rule lowered in order, then rule 6.
    fn check_image(doc: &Doc) -> Pe<()> {
        {
            let (mut texts, rules) = decode_image(doc)?;
            // `parseDefs`: code point order of the names, which is the order of their UTF-8 bytes
            texts.sort_by(|a, b| a.0.cmp(&b.0));
            let defs = texts.iter().map(|(name, text)| parse_def(name, text)).collect::<Pe<Vec<_>>>()?;
            let mut tested = Vec::new();
            for cond in &rules {
                lower_cond(&defs, cond, &mut tested)?;
            }
            // `checkAbsence`, rule 6, in code point order
            match defs.iter().find(|d| d.absent_ok && !tested.contains(&d.name)) {
                Some(d) => refuse("policy:absence-untested", Some(&d.name), None),
                None => Ok(()),
            }
        }
    }

    /// Lean's `counterRefusal`: the oracle refuses the image for reading an engine counter.
    pub fn refuses_for_counter(image: &[u8]) -> bool {
        load_policy(image).is_some_and(|refused| refused.cause == "policy:engine-counter")
    }
}

// ----------------------------------------------------------------- the decisions
/// A receipt's decision members, in the order they are written (canon/2 sorts them).
type Decision = Vec<(&'static str, Doc)>;

/// A refusal's decision members: its registered cause, code, and the field and reason where it has them.
fn refusal(cause: &str, field: Option<&str>, reason: Option<&str>) -> Result<Decision, String> {
    let code = causes::code(cause).ok_or_else(|| format!("{cause} is not a registered cause"))?;
    let mut out = vec![("decision", text("refuse")), ("cause", text(cause)), ("cause_code", Doc::Int(i64::from(code)))];
    if let Some(field) = field.filter(|field| !field.is_empty()) {
        out.push(("field", text(field)));
    }
    if let Some(reason) = reason.filter(|reason| !reason.is_empty()) {
        out.push(("reason", text(reason)));
    }
    Ok(out)
}

/// One reading under a checked policy, composed as `core_diff.rs` composes it.
fn reading_decision(graph: &prismpath_rs::Graph, bytes: &[u8]) -> Result<Decision, String> {
    let document = match canon2::read(bytes) {
        Ok(document) => document,
        Err(error) => {
            let cause = if error == canon2::Canon2Error::NotCanonical { "reading:not-canonical" } else { "reading:unreadable" };
            return refusal(cause, None, Some(error.rule()));
        }
    };
    let Doc::Obj(members) = document else {
        return refusal("reading:not-object", None, None);
    };
    let values: HashMap<String, Value> = members.iter().map(|(key, value)| (key.clone(), value.to_value())).collect();
    if let Some((field, reason)) = system_boundary(graph, &values) {
        return refusal("route:contract-violation", Some(&field), Some(reason));
    }
    match first_deterministic(&graph.nodes[&graph.start].edges, &values) {
        Some((target, _)) => Ok(vec![("decision", text("route")), ("target", text(target))]),
        None => refusal("route:no-matching-edge", None, None),
    }
}

/// Every reading's decision, or None for a case the port has no decision on (an image with no flow).
fn case_decisions(case: &Case) -> Result<Option<Vec<Decision>>, String> {
    if let Err(error) = canon2::read(&case.image) {
        let refused = refusal(oracle_policy::unreadable_image_cause(error), None, Some(error.rule()))?;
        return Ok(Some(case.readings.iter().map(|_| refused.clone()).collect()));
    }
    let Some(flow) = &case.flow else { return Ok(None) };
    let graph = parse(flow);
    if graph.refusal().is_some() {
        let cause = graph.field_error_cause.ok_or_else(|| format!("case {}: an uncoded refusal", case.id))?;
        let refused = refusal(cause, graph.field_error_field.as_deref(), graph.field_error_reason)?;
        return Ok(Some(case.readings.iter().map(|_| refused.clone()).collect()));
    }
    case.readings.iter().map(|bytes| reading_decision(&graph, bytes)).collect::<Result<Vec<_>, _>>().map(Some)
}

// ----------------------------------------------------------------- producing a run
/// The signer's clock as the run's root statement holds it: microseconds since the epoch, an integer.
fn now_us() -> i64 {
    let since = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("a clock after 1970");
    i64::try_from(since.as_micros()).expect("a clock before the year 294,000")
}

/// What the root statement's signature covers: its domain prefix, then the canon/2 bytes of every member
/// but `sig`.
fn root_signed_bytes(statement: &Doc) -> Result<Vec<u8>, String> {
    let Doc::Obj(members) = statement else { return Err("the root statement is an object".to_string()) };
    let body = Doc::Obj(members.iter().filter(|(key, _)| key != "sig").cloned().collect());
    let mut out = ROOT_DOMAIN.to_vec();
    out.extend(canon2::write(&body).map_err(|error| error.to_string())?);
    Ok(out)
}

fn is_hex_of(value: &str, size: usize) -> bool {
    value.len() == 2 * size && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The run's root statement checked in full, as `core_evidence.verify_root_statement` checks it.
fn verify_root_statement(data: &[u8], leaves: &[String], manifest_bytes: &[u8], instance_raw: &[u8]) -> Result<Doc, String> {
    let Some(line) = data.strip_suffix(b"\n").filter(|line| !line.contains(&b'\n')) else {
        return Err("the root statement is not one line".to_string());
    };
    let statement = canon2::read(line).map_err(|error| format!("the root statement is not a canon/2 document ({})", error.rule()))?;
    if canon2::write(&statement).ok().as_deref() != Some(line) {
        return Err("the root statement is not in its canonical canon/2 spelling".to_string());
    }
    let Doc::Obj(members) = &statement else { return Err("the root statement is not in its canonical canon/2 spelling".to_string()) };
    let keys: BTreeSet<&str> = members.iter().map(|(key, _)| key.as_str()).collect();
    let shaped = keys == ROOT_MEMBERS.iter().copied().collect()
        && member(&statement, "format") == Some(&text(ROOT_FORMAT))
        && member(&statement, "log") == Some(&text(LOG_CORE_RUN))
        && member(&statement, "trigger") == Some(&text(LOG_CORE_RUN));
    if let Some(Doc::Str(old)) = member(&statement, "format").filter(|format| matches!(format, Doc::Str(f) if OLD_ROOT_FORMATS.contains(&f.as_str()))) {
        return Err(format!("the root statement is {old}, whose root is of the retired Merkle tree (no domain prefixes, \
                            the last node of an odd layer duplicated); this verifier reads only {ROOT_FORMAT} ({}), so produce \
                            the run again", prismpath_rs::merkle::MERKLE_SCHEME));
    }
    if !shaped {
        return Err(format!("the root statement is not a {ROOT_FORMAT} statement"));
    }
    for key in ["leaves", "time_us"] {
        if !matches!(member(&statement, key), Some(Doc::Int(value)) if *value >= 0) {
            return Err(format!("the root statement's {key} is not a nonnegative integer"));
        }
    }
    let (root, key_id, public_key, sig) = match (member(&statement, "root"), member(&statement, "key_id"), member(&statement, "public_key"), member(&statement, "sig")) {
        (Some(Doc::Str(root)), Some(Doc::Str(key_id)), Some(Doc::Str(public_key)), Some(Doc::Str(sig))) if is_hex_of(key_id, 32) && is_hex_of(public_key, 32) && is_hex_of(sig, 64) => (root, key_id, public_key, sig),
        _ => return Err("the root statement's root, key or signature is malformed".to_string()),
    };
    if *public_key != hex::encode(instance_raw) || *key_id != sha256_hex(instance_raw) {
        return Err("the root statement is not signed with the run's instance key".to_string());
    }
    if !verify_ed25519(instance_raw, &root_signed_bytes(&statement)?, &unhex(sig)?) {
        return Err("the root statement's signature does not verify".to_string());
    }
    if int_of(&statement, "leaves")? != leaves.len() as i64 || *root != merkle_root(leaves)? {
        return Err("the root statement does not verify: its root is not the receipts' Merkle root".to_string());
    }
    if member(&statement, "policy") != Some(&obj(vec![("core_run_sha256", text(&sha256_hex(manifest_bytes)))])) {
        return Err("the root statement does not bind this run.json".to_string());
    }
    Ok(statement)
}

fn produce(source: &Path, out: &Path, keys: &Path) -> Result<String, String> {
    let keys_dir = keys.to_str().ok_or("a key directory path that is UTF-8")?;
    if !keys.join("authority.key").exists() {
        keygen(keys_dir, "authority")?;
    }
    if !keys.join("instance.key").exists() {
        keygen(keys_dir, "instance")?;
    }
    let authority = load_private(keys.join("authority.key").to_str().ok_or("UTF-8 path")?)?;
    let instance = load_private(keys.join("instance.key").to_str().ok_or("UTF-8 path")?)?;
    let authority_raw = authority.verifying_key().to_bytes();
    let instance_raw = instance.verifying_key().to_bytes();
    let (authority_id, instance_id) = (sha256_hex(&authority_raw), sha256_hex(&instance_raw));
    if authority_id == instance_id {
        return Err("the instance key is also the authority key".to_string());
    }
    std::fs::create_dir_all(out).map_err(|error| error.to_string())?;
    let cases_bytes = std::fs::read(source).map_err(|error| error.to_string())?;
    std::fs::write(out.join("cases.jsonl"), &cases_bytes).map_err(|error| error.to_string())?;
    let cases = read_cases(&cases_bytes)?;
    if let Some(problem) = cases.iter().find_map(flow_problem) {
        return Err(format!("{problem}; write the cases with `core_evidence.write_cases`"));
    }

    let mut images = Vec::new();
    for case in &cases {
        let mut signed = IMAGE_DOMAIN.to_vec();
        signed.extend(&case.image);
        let attestation = obj(vec![
            ("format", text(IMAGE_FORMAT)),
            ("case", text(&case.id)),
            ("image_sha256", text(&sha256_hex(&case.image))),
            ("key_id", text(&authority_id)),
            ("sig", text(&hex::encode(authority.sign(&signed).to_bytes()))),
        ]);
        images.extend(canon2::write(&attestation).map_err(|error| error.to_string())?);
        images.push(b'\n');
    }
    std::fs::write(out.join("images.jsonl"), &images).map_err(|error| error.to_string())?;

    let (mut receipts, mut leaves, mut excluded) = (Vec::new(), Vec::new(), Vec::new());
    for case in &cases {
        if let Some(why) = outside_core(&case.image, case.flow.as_deref()) {
            excluded.push(obj(vec![("case", text(&case.id)), ("why", text(why))]));
            continue;
        }
        let Some(decisions) = case_decisions(case)? else {
            return Err(format!("case {}: no decision on a case inside the core", case.id));
        };
        for (index, (raw, decision)) in case.readings.iter().zip(decisions).enumerate() {
            let mut members = vec![
                ("format", text(RECEIPT_FORMAT)),
                ("idx", Doc::Int(leaves.len() as i64)),
                ("case", text(&case.id)),
                ("reading", Doc::Int(index as i64)),
                ("image_sha256", text(&sha256_hex(&case.image))),
                ("reading_sha256", text(&sha256_hex(raw))),
                ("decider", text("rust")),
            ];
            members.extend(decision);
            let line = canon2::write(&obj(members)).map_err(|error| error.to_string())?;
            leaves.push(sha256_hex(&line));
            receipts.extend(line);
            receipts.push(b'\n');
        }
    }
    std::fs::write(out.join("receipts.jsonl"), &receipts).map_err(|error| error.to_string())?;

    let excluded_count = excluded.len();
    let manifest = obj(vec![
        ("format", text(RUN_FORMAT)),
        ("decider", text("rust")),
        ("cases", Doc::Int(cases.len() as i64)),
        ("receipts", Doc::Int(leaves.len() as i64)),
        ("excluded", Doc::Arr(excluded)),
        ("cases_sha256", text(&sha256_hex(&cases_bytes))),
        ("images_sha256", text(&sha256_hex(&images))),
        ("authority_key_id", text(&authority_id)),
        ("instance_key_id", text(&instance_id)),
    ]);
    let manifest_bytes = canon2::write(&manifest).map_err(|error| error.to_string())?;
    let mut manifest_line = manifest_bytes.clone();
    manifest_line.push(b'\n');
    std::fs::write(out.join("run.json"), manifest_line).map_err(|error| error.to_string())?;
    std::fs::write(out.join("authority.pub"), authority_raw).map_err(|error| error.to_string())?;
    std::fs::write(out.join("instance.pub"), instance_raw).map_err(|error| error.to_string())?;

    // one canon/2 root statement over every receipt, as `core_evidence.make_root_statement` writes one
    let mut statement = obj(vec![
        ("format", text(ROOT_FORMAT)),
        ("log", text(LOG_CORE_RUN)),
        ("root", text(&merkle_root(&leaves)?)),
        ("leaves", Doc::Int(leaves.len() as i64)),
        ("time_us", Doc::Int(now_us())),
        ("trigger", text(LOG_CORE_RUN)),
        ("key_id", text(&instance_id)),
        ("public_key", text(&hex::encode(instance_raw))),
        ("policy", obj(vec![("core_run_sha256", text(&sha256_hex(&manifest_bytes)))])),
    ]);
    let sig = hex::encode(instance.sign(&root_signed_bytes(&statement)?).to_bytes());
    if let Doc::Obj(members) = &mut statement {
        members.push(("sig".to_string(), text(&sig)));
    }
    let mut line = canon2::write(&statement).map_err(|error| error.to_string())?;
    line.push(b'\n');
    std::fs::write(out.join("receipts.roots.jsonl"), line).map_err(|error| error.to_string())?;
    Ok(format!(
        "core_evidence: produced {}: decider rust, {} cases, {} receipts, {} excluded",
        out.display(),
        cases.len(),
        leaves.len(),
        excluded_count
    ))
}

// ----------------------------------------------------------------- verifying a run
struct Options {
    sample: Option<usize>,
    seed: u64,
    pin_authority: Option<PathBuf>,
    pin_instance: Option<PathBuf>,
    oracle: PathBuf,
}

/// A decision as comparable members: route and target, or refuse with cause, code, field and reason (an
/// empty field, the oracle's spelling of a threshold on no field, is no field).
fn normal(decision: &serde_json::Value) -> Vec<String> {
    let get = |key: &str| decision.get(key).map(|value| match value {
        serde_json::Value::String(text) => text.clone(),
        other => other.to_string(),
    });
    let verdict = get("decision").or_else(|| get("verdict")).unwrap_or_default();
    if verdict == "route" {
        return vec![verdict, get("target").unwrap_or_default()];
    }
    let code = get("cause_code").or_else(|| get("code")).unwrap_or_default();
    vec![verdict, get("cause").unwrap_or_default(), code, get("field").unwrap_or_default(), get("reason").unwrap_or_default()]
}

fn verify(run: &Path, options: &Options) -> Result<String, String> {
    for name in FILES {
        if !run.join(name).exists() {
            return Err(format!("the run has no {name}"));
        }
    }
    let read = |name: &str| std::fs::read(run.join(name)).map_err(|error| format!("{name}: {error}"));
    let manifest_file = read("run.json")?;
    let manifest_bytes = manifest_file.strip_suffix(b"\n").unwrap_or(&manifest_file).to_vec();
    let manifest = canon2::read(&manifest_bytes).map_err(|error| format!("run.json: {error}"))?;
    if member(&manifest, "format") != Some(&text(RUN_FORMAT)) || canon2::write(&manifest).ok().as_deref() != Some(&manifest_bytes[..]) {
        return Err("run.json is not a canonical prismpath.core-run/1 manifest".to_string());
    }
    let decider = str_of(&manifest, "decider")?.to_string();

    // the keys: pinned when the reader names them, else the ones the run carries
    let (authority_raw, instance_raw) = (read("authority.pub")?, read("instance.pub")?);
    for (pin, raw, role) in [(&options.pin_authority, &authority_raw, "authority"), (&options.pin_instance, &instance_raw, "instance")] {
        if let Some(pin) = pin {
            if &std::fs::read(pin).map_err(|error| error.to_string())? != raw {
                return Err(format!("the run's {role} key is not the pinned {role} key"));
            }
        }
    }
    let pinned = options.pin_authority.is_some() && options.pin_instance.is_some();
    let (authority_id, instance_id) = (sha256_hex(&authority_raw), sha256_hex(&instance_raw));
    if str_of(&manifest, "authority_key_id")? != authority_id || str_of(&manifest, "instance_key_id")? != instance_id {
        return Err("run.json names other keys than the run carries".to_string());
    }
    if authority_id == instance_id {
        return Err("the instance key is also the authority key".to_string());
    }

    // the root statement over the receipts, and the manifest it binds
    let receipts_bytes = read("receipts.jsonl")?;
    let receipt_lines = lines(&receipts_bytes);
    let leaves: Vec<String> = receipt_lines.iter().map(|line| sha256_hex(line)).collect();
    verify_root_statement(&read("receipts.roots.jsonl")?, &leaves, &manifest_bytes, &instance_raw)?;
    if int_of(&manifest, "receipts")? != leaves.len() as i64 {
        return Err("run.json counts other receipts than the run holds".to_string());
    }

    // the cases and the image attestations
    let (cases_bytes, images_bytes) = (read("cases.jsonl")?, read("images.jsonl")?);
    if sha256_hex(&cases_bytes) != str_of(&manifest, "cases_sha256")? || sha256_hex(&images_bytes) != str_of(&manifest, "images_sha256")? {
        return Err("cases.jsonl or images.jsonl is not the file run.json names".to_string());
    }
    let cases = read_cases(&cases_bytes)?;
    let image_lines = lines(&images_bytes);
    if cases.len() as i64 != int_of(&manifest, "cases")? || image_lines.len() != cases.len() {
        return Err("run.json, cases.jsonl and images.jsonl count other cases".to_string());
    }
    if let Some(problem) = cases.iter().find_map(flow_problem) {
        return Err(problem);
    }
    for (case, line) in cases.iter().zip(&image_lines) {
        let attestation = canon2::read(line).map_err(|error| format!("images.jsonl: {error}"))?;
        let mut signed = IMAGE_DOMAIN.to_vec();
        signed.extend(&case.image);
        let sound = canon2::write(&attestation).ok().as_deref() == Some(*line)
            && str_of(&attestation, "format")? == IMAGE_FORMAT
            && str_of(&attestation, "case")? == case.id
            && str_of(&attestation, "key_id")? == authority_id
            && str_of(&attestation, "image_sha256")? == sha256_hex(&case.image);
        if !sound {
            return Err(format!("case {}: the image attestation does not match the image", case.id));
        }
        if !verify_ed25519(&authority_raw, &signed, &unhex(str_of(&attestation, "sig")?)?) {
            return Err(format!("case {}: the image signature does not verify", case.id));
        }
    }

    // every receipt, in order: every reading of every case the run did not exclude, once
    let mut excluded: HashMap<String, String> = HashMap::new();
    let Some(Doc::Arr(rows)) = member(&manifest, "excluded") else { return Err("run.json lists no excluded cases".to_string()) };
    for row in rows {
        match row {
            Doc::Obj(members) if members.len() == 2 => {
                excluded.insert(str_of(row, "case")?.to_string(), str_of(row, "why")?.to_string());
            }
            _ => return Err("run.json lists an excluded case without its reason".to_string()),
        }
    }
    for case in &cases {
        let why = outside_core(&case.image, case.flow.as_deref());
        if excluded.get(&case.id).map(String::as_str) != why {
            return Err(format!("case {}: excluded as {:?}, but the image says {why:?}", case.id, excluded.get(&case.id)));
        }
    }
    let expected: Vec<(&Case, usize)> = cases.iter().filter(|case| !excluded.contains_key(&case.id)).flat_map(|case| (0..case.readings.len()).map(move |index| (case, index))).collect();
    if expected.len() != receipt_lines.len() {
        return Err(format!("{} receipts for {} decisions", receipt_lines.len(), expected.len()));
    }
    let mut receipts = Vec::new();
    for (idx, ((case, index), line)) in expected.iter().zip(&receipt_lines).enumerate() {
        let receipt = canon2::read(line).map_err(|error| format!("receipt {idx}: {error}"))?;
        if canon2::write(&receipt).ok().as_deref() != Some(*line) {
            return Err(format!("receipt {idx} is not in its canonical canon/2 spelling"));
        }
        let binds = str_of(&receipt, "format")? == RECEIPT_FORMAT
            && int_of(&receipt, "idx")? == idx as i64
            && str_of(&receipt, "case")? == case.id
            && int_of(&receipt, "reading")? == *index as i64
            && str_of(&receipt, "image_sha256")? == sha256_hex(&case.image)
            && str_of(&receipt, "reading_sha256")? == sha256_hex(&case.readings[*index])
            && str_of(&receipt, "decider")? == decider;
        if !binds {
            return Err(format!("receipt {idx} does not bind case {} reading {index}", case.id));
        }
        let Doc::Obj(members) = &receipt else { unreachable!("a receipt read as an object") };
        let keys: BTreeSet<&str> = members.iter().map(|(key, _)| key.as_str()).collect();
        let base = ["format", "idx", "case", "reading", "image_sha256", "reading_sha256", "decider", "decision"];
        match str_of(&receipt, "decision")? {
            "route" => {
                if keys != base.iter().copied().chain(["target"]).collect() {
                    return Err(format!("receipt {idx}: a route names a target and nothing else"));
                }
            }
            "refuse" => {
                let cause = str_of(&receipt, "cause")?;
                let code = int_of(&receipt, "cause_code")?;
                let allowed: BTreeSet<&str> = base.iter().copied().chain(["cause", "cause_code", "field", "reason"]).collect();
                if causes::code(cause).map(i64::from) != Some(code) || code == 0 || !keys.is_subset(&allowed) {
                    return Err(format!("receipt {idx}: a refusal carries a registered nonzero cause code"));
                }
            }
            _ => return Err(format!("receipt {idx}: the decision is a route or a refusal")),
        }
        receipts.push((*case, *index, receipt.to_json()));
    }

    // a sample of the decisions, replayed through the oracle
    let chosen: Vec<usize> = match options.sample {
        Some(count) if count < receipts.len() => {
            // a seeded partial Fisher Yates shuffle (xorshift64*), so a run replays the same sample
            let mut state = options.seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
            let mut order: Vec<usize> = (0..receipts.len()).collect();
            for slot in 0..count {
                state ^= state >> 12;
                state ^= state << 25;
                state ^= state >> 27;
                let pick = slot + (state.wrapping_mul(0x2545_F491_4F6C_DD1D) % (receipts.len() - slot) as u64) as usize;
                order.swap(slot, pick);
            }
            order.truncate(count);
            order
        }
        _ => (0..receipts.len()).collect(),
    };
    let mut frames = Vec::new();
    for (number, which) in chosen.iter().enumerate() {
        let (case, index, _) = &receipts[*which];
        let reading = &case.readings[*index];
        frames.extend(format!("case r{number} 1\n{}\n", case.image.len()).into_bytes());
        frames.extend(&case.image);
        frames.extend(format!("\n{}\n", reading.len()).into_bytes());
        frames.extend(reading);
        frames.push(b'\n');
    }
    let mut child = Command::new(&options.oracle)
        .arg("--batch")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|error| format!("the oracle {}: {error}", options.oracle.display()))?;
    {
        use std::io::Write;
        let mut stdin = child.stdin.take().expect("piped stdin");
        let writer = std::thread::spawn(move || stdin.write_all(&frames));
        let output = child.wait_with_output().map_err(|error| error.to_string())?;
        writer.join().expect("the writer thread").map_err(|error| error.to_string())?;
        if !output.status.success() {
            return Err("the oracle failed".to_string());
        }
        let rows: HashMap<String, serde_json::Value> = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .map(|row| (row["id"].as_str().unwrap_or_default().to_string(), row))
            .collect();
        let mut agree = 0usize;
        for (number, which) in chosen.iter().enumerate() {
            let (case, _index, receipt) = &receipts[*which];
            let row = rows.get(&format!("r{number}")).ok_or("the oracle skipped a case")?;
            let oracle = &row["readings"][0];
            // every receipted case is inside the core, so every decision must be the oracle's
            if normal(oracle) != normal(receipt) {
                return Err(format!("a replayed decision differs from the oracle: case {} receipt {receipt} oracle {oracle}", case.id));
            }
            agree += 1;
        }
        Ok(format!(
            "core_evidence: verified {}: decider {decider}, {} receipts, {} image attestations, root statement {}, {} replayed: {agree} agree, 0 disagree",
            run.display(),
            receipts.len(),
            cases.len(),
            if pinned { "signed" } else { "signed-unpinned" },
            chosen.len()
        ))
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flag = |name: &str| args.iter().position(|arg| arg == name).and_then(|at| args.get(at + 1)).cloned();
    let outcome = match args.first().map(String::as_str) {
        Some("produce") => match (flag("--from"), flag("--out"), flag("--keys")) {
            (Some(source), Some(out), Some(keys)) => produce(Path::new(&source), Path::new(&out), Path::new(&keys)),
            _ => Err("produce --from CASES --out RUN --keys KEYS".to_string()),
        },
        Some("policy") => match flag("--from") {
            Some(source) => policy_lines(Path::new(&source)),
            None => Err("policy --from CASES".to_string()),
        },
        Some("render") => match flag("--from") {
            Some(source) => render_lines(Path::new(&source)),
            None => Err("render --from CASES".to_string()),
        },
        Some("verify") if args.len() > 1 => {
            let sample = match flag("--sample").as_deref() {
                Some("all") => None,
                Some(count) => Some(count.parse().unwrap_or(200)),
                None => Some(200),
            };
            let oracle = flag("--oracle").map(PathBuf::from).or_else(|| std::env::var_os("PRISMPATH_CORE_ORACLE").map(PathBuf::from)).unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../formal/.lake/build/bin/core-oracle"));
            let options = Options {
                sample,
                seed: flag("--seed").and_then(|seed| seed.parse().ok()).unwrap_or(0),
                pin_authority: flag("--pin-authority").map(PathBuf::from),
                pin_instance: flag("--pin-instance").map(PathBuf::from),
                oracle,
            };
            verify(Path::new(&args[1]), &options).map_err(|why| format!("core_evidence: REFUSED {}: {why}", args[1]))
        }
        _ => Err("usage: core_evidence produce --from CASES --out RUN --keys KEYS | policy --from CASES | render --from CASES | verify RUN [--sample N|all] [--seed S] [--pin-authority PUB --pin-instance PUB] [--oracle BIN]".to_string()),
    };
    match outcome {
        Ok(line) => {
            println!("{line}");
            ExitCode::SUCCESS
        }
        Err(why) => {
            println!("{why}");
            ExitCode::FAILURE
        }
    }
}
