// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The places the receipt verifiers are deliberately not the Python reference, and the shapes the
//! frozen vectors cannot carry. Each is fail closed: Rust refuses what Python would let through, never
//! the reverse. (The vectors in `test_receipt_verify.rs` hold every other verdict to Python's.)

use ed25519_dalek::{Signer, SigningKey};
use prismpath_hotswap_rs::flow_authority::{verify_flow, VersionFloor, FLOW_MANIFEST_FORMAT};
use prismpath_hotswap_rs::root_statement::{
    key_id_of, read_statements_text, signed_bytes, statement_hash, statements_path_for, verify_trail, INVALID, SIGNED,
};
use prismpath_hotswap_rs::{canonical_bytes, sha256_hex, verify_ed25519};
use serde_json::{json, Value};

fn key(label: u8) -> SigningKey {
    SigningKey::from_bytes(&[label; 32])
}

/// A statement signed in the test, to exercise shapes the Python generator does not emit.
fn statement(signer: &SigningKey, seq: i64, leaves: i64, root: &str, prev: &str) -> Value {
    let public = signer.verifying_key().to_bytes();
    let mut statement = json!({
        "format": "prismpath-root-statement/1", "log": "audit-log", "seq": seq, "root": root, "leaves": leaves,
        "prev": prev, "time": "2026-11-04T12:00:00.250Z", "trigger": "run-end", "key_id": key_id_of(&public),
        "public_key": hex::encode(public), "policy": null,
    });
    let signature = signer.sign(&signed_bytes(&statement).unwrap());
    statement["sig"] = json!(hex::encode(signature.to_bytes()));
    statement
}

#[test]
fn a_small_order_key_is_refused_where_python_accepts_its_signature() {
    let identity = [&[1u8][..], &[0u8; 31]].concat();
    let forged = [identity.clone(), vec![0u8; 32]].concat();
    assert!(!verify_ed25519(&identity, b"any message at all", &forged));
}

#[test]
fn keys_and_signatures_of_the_wrong_length_verify_nothing() {
    let signer = key(7);
    let signature = signer.sign(b"m").to_bytes();
    let public = signer.verifying_key().to_bytes();
    assert!(verify_ed25519(&public, b"m", &signature));
    assert!(!verify_ed25519(&public[..31], b"m", &signature));
    assert!(!verify_ed25519(&public, b"m", &signature[..63]));
    assert!(!verify_ed25519(&public, b"m", &[signature.as_slice(), &[0u8]].concat()));
    assert!(!verify_ed25519(&public, b"other", &signature));
}

#[test]
fn a_boolean_is_not_an_integer_in_a_statement() {
    let signer = key(7);
    let log = "";
    let mut stmt = statement(&signer, 0, 0, "", "");
    stmt["seq"] = json!(false);
    let report = verify_trail(log, Some(&format!("{stmt}\n")), &[signer.verifying_key().to_bytes().to_vec()]);
    assert_eq!(report.status, INVALID);
    assert_eq!(report.finding_names(), ["bad_format"]);
}

#[test]
fn a_chain_signed_in_rust_test_code_verifies_like_one_signed_by_python() {
    let signer = key(7);
    let pinned = vec![signer.verifying_key().to_bytes().to_vec()];
    let events = [json!({"idx": 0, "id": "0", "ts": 1730800000.5, "actor": "a", "action": "decision", "data": {}})];
    let leaf = sha256_hex(&canonical_bytes(&events[0]));
    let first = statement(&signer, 0, 1, &leaf, "");
    let log = format!("{}\n", serde_json::to_string(&events[0]).unwrap());
    let report = verify_trail(&log, Some(&format!("{first}\n")), &pinned);
    assert_eq!((report.status, report.findings.len()), (SIGNED, 0));
    assert_eq!(report.last_statement_sha256.as_deref(), Some(statement_hash(&first).as_str()));
    // A second statement that names the first.
    let second = statement(&signer, 1, 1, &leaf, &statement_hash(&first));
    assert_eq!(verify_trail(&log, Some(&format!("{first}\n{second}\n")), &pinned).status, SIGNED);
    // The same chain read without its newline at the end, and with Windows line endings.
    assert_eq!(verify_trail(&log, Some(&format!("{first}\r\n{second}")), &pinned).status, SIGNED);
}

#[test]
fn a_statement_hash_covers_the_signature() {
    let signer = key(7);
    let one = statement(&signer, 0, 0, "", "");
    let mut other = one.clone();
    other["sig"] = json!("00".repeat(64));
    assert_ne!(statement_hash(&one), statement_hash(&other));
}

#[test]
fn reading_statements_names_the_line() {
    let (statements, findings) = read_statements_text("{\"a\": 1}\nnot json\n{\"b\": 2}\n{\"c\"");
    assert_eq!(statements.len(), 3);
    assert_eq!(findings, vec![json!({"finding": "bad_format", "line": 2}), json!({"finding": "interrupted_statement", "line": 4})]);
    assert_eq!(read_statements_text("").0.len(), 0);
}

#[test]
fn statements_sit_beside_the_log() {
    assert_eq!(statements_path_for("run.audit.jsonl"), "run.audit.roots.jsonl");
    assert_eq!(statements_path_for("state/swaps.log"), "state/swaps.log.roots.jsonl");
}

#[test]
fn a_flow_manifest_with_a_boolean_version_is_bad_format() {
    let authority = key(9);
    let flow = b"---\nname: t\n---\n";
    let manifest = json!({"format": FLOW_MANIFEST_FORMAT, "flow": "t", "flow_sha256": sha256_hex(flow), "version": true,
                          "key_id": key_id_of(&authority.verifying_key().to_bytes()), "created": "2026-11-04T12:00:00+00:00"});
    let signature = authority.sign(&canonical_bytes(&manifest)).to_bytes();
    let verdict = verify_flow(flow, Some(&manifest.to_string()), Some(&signature), &[authority.verifying_key().to_bytes().to_vec()], &[], None);
    assert_eq!(verdict.causes, ["manifest:bad-format"]);
}

#[test]
fn a_flow_that_is_not_utf8_does_not_match_its_hash() {
    let authority = key(9);
    let flow = [0xffu8, 0xfe, b'\n'];
    let manifest = json!({"format": FLOW_MANIFEST_FORMAT, "flow": "t", "flow_sha256": sha256_hex(&flow), "version": 1,
                          "key_id": key_id_of(&authority.verifying_key().to_bytes()), "created": "x"});
    let signature = authority.sign(&canonical_bytes(&manifest)).to_bytes();
    let verdict = verify_flow(&flow, Some(&manifest.to_string()), Some(&signature), &[authority.verifying_key().to_bytes().to_vec()], &[], None);
    assert_eq!(verdict.causes, ["flow:sha256-mismatch"]);
}

#[test]
fn the_version_floor_reads_and_writes_the_file_python_keeps() {
    let text = "{\n \"b\": {\n  \"flow_sha256\": \"x\",\n  \"manifest_sha256\": \"y\",\n  \"version\": 1\n },\n \"triage\": {\n  \"flow_sha256\": \"ab\",\n  \"manifest_sha256\": \"cd\",\n  \"version\": 3\n }\n}\n";
    let floor = VersionFloor::from_json_str(text).unwrap();
    assert_eq!(floor.to_json_string(), text);
    assert!(VersionFloor::from_json_str("[]").is_err());
    assert!(VersionFloor::from_json_str("nope").is_err());
}

#[test]
fn a_damaged_floor_entry_admits_nothing() {
    let floor = VersionFloor::from_json_str(r#"{"triage": {"version": "three"}}"#).unwrap();
    assert!(!floor.admits(&json!({"flow": "triage", "version": 4, "flow_sha256": "ab"})));
    assert!(floor.admits(&json!({"flow": "another", "version": 1, "flow_sha256": "ab"})));
}

#[test]
fn the_rust_audit_log_writes_leaves_the_verifier_reads_the_same() {
    use prismpath_hotswap_rs::host::AuditLog;
    use prismpath_hotswap_rs::root_statement::{AuditLogView, UNSIGNED};
    let dir = std::env::temp_dir().join(format!("pp_receipt_edges_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.join("swaps.log");
    let mut log = AuditLog::open(path.to_str().unwrap());
    log.append("policy_host", "swap", json!({"to_hash": "ab", "version": 1, "note": "caf\u{e9} \u{1d11e}", "ratio": 1e-7, "result": "accepted"}));
    log.append("policy_host", "attest", json!({"ok": true}));
    let text = std::fs::read_to_string(&path).unwrap();
    let view = AuditLogView::from_text(&text);
    assert_eq!(view.leaves, log.leaves);
    assert_eq!(view.root_at(2), log.current_root());
    let report = verify_trail(&text, None, &[]);
    assert_eq!((report.status, report.log_leaves, report.unsigned_tail), (UNSIGNED, 2, 2));
    let _ = std::fs::remove_dir_all(&dir);
}
