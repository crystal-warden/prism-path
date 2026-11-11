//! Every refusal name the pack verifier emits is a registered cause, as `prismpath/tests/test_causes.py`
//! holds the Python verifier to. The names are read out of the verifier's own source, so a refusal
//! added without a registry row fails here.

use prismpath_rs::causes;

/// Every `"class:detail"` string literal in `src`, with a parameter suffix (`:atom3`) cut off.
fn refusal_names(src: &str) -> Vec<String> {
    let mut found = Vec::new();
    for line in src.lines() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        let mut rest = line;
        while let Some(open) = rest.find('"') {
            let after = &rest[open + 1..];
            let close = match after.find('"') {
                Some(position) => position,
                None => break,
            };
            let literal = &after[..close];
            let mut parts = literal.splitn(3, ':');
            let (class, detail) = (parts.next().unwrap_or(""), parts.next());
            let class_ok = !class.is_empty() && class.chars().all(|ch| ch.is_ascii_lowercase());
            if let (true, Some(detail)) = (class_ok, detail) {
                if !detail.is_empty() && detail.chars().all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-') {
                    found.push(format!("{class}:{detail}"));
                }
            }
            rest = &after[close + 1..];
        }
    }
    found.sort();
    found.dedup();
    found
}

#[test]
fn every_verifier_refusal_name_is_a_registry_row() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs")).unwrap();
    let names = refusal_names(&src);
    assert!(names.len() >= 30, "expected the whole verifier set, found {names:?}");
    for name in &names {
        assert!(causes::code(name).is_some(), "the verifier emits {name:?}, which the registry does not list");
    }
}

#[test]
fn the_names_the_parity_review_found_missing_are_present_and_registered() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs")).unwrap();
    let names = refusal_names(&src);
    for wanted in ["image:safe-node-oob", "image:node-attr-oob", "manifest:wcet-mismatch", "packing:unknown-profile",
                   "spiral:sidecar-missing", "spiral:sidecar-hash-mismatch"] {
        assert!(names.iter().any(|name| name == wanted), "{wanted}");
        assert!(causes::code(wanted).is_some(), "{wanted}");
    }
}
