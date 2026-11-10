// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! What the host trace corpus leaves out: the four corners where the Rust host fails closed or words
//! an error its own way (DIVERGENCES.md), the forms a floor file can take, the system clock, and the
//! lock (a host shared between threads keeps every file and the log consistent).

mod common;

use common::{corpus, fresh_dir, pack_path, stage};
use prismpath_hotswap_rs::host::{AuditLog, HostError, PolicyHost};
use prismpath_hotswap_rs::*;
use serde_json::{json, Value};
use std::sync::Arc;

struct Setup {
    doc: Value,
    dir: common::Scratch,
    pubs: Vec<String>,
}

impl Setup {
    fn new(tag: &str) -> Setup {
        let doc = corpus();
        let dir = fresh_dir(tag);
        let pubs = stage(&doc, &dir);
        Setup { doc, dir, pubs }
    }

    fn state(&self) -> String {
        self.dir.join("state").to_str().unwrap().to_string()
    }

    fn host(&self) -> Result<PolicyHost, HostError> {
        PolicyHost::new(&self.state(), self.pubs.clone(), self.doc["envelopes"]["default"].clone(), Vec::new())
    }

    fn put(&self, name: &str, text: &str) {
        std::fs::create_dir_all(self.state()).unwrap();
        std::fs::write(format!("{}/{name}", self.state()), text).unwrap();
    }
}

#[test]
fn an_unreadable_active_record_is_not_restored_and_the_event_says_so() {
    let setup = Setup::new("corner_record");
    setup.put("active_policy.json", "{not json");
    let host = setup.host().unwrap();
    assert_eq!(host.active_info(), json!({"active": null}));
    let event = host.history().pop().unwrap();
    assert_eq!(event["action"], "active_unreadable");
    assert_eq!(event["data"]["result"], "not_restored");
    assert!(event["data"]["reason"].as_str().unwrap().starts_with("record:unreadable:"), "{event}");
    assert!(host.audit.verify_persisted().unwrap());
    // a record that is not UTF-8 gets the same answer
    let setup = Setup::new("corner_record_bytes");
    std::fs::create_dir_all(setup.state()).unwrap();
    std::fs::write(format!("{}/active_policy.json", setup.state()), [0xff, 0xfe, 0x00]).unwrap();
    assert!(setup.host().unwrap().history().pop().unwrap()["data"]["reason"].as_str().unwrap().starts_with("record:unreadable:"));
}

/// Python skips the same lines (`prismpath/tests/test_canon_nonfinite.py`): NaN, Infinity, a number beyond
/// the double range and a lone surrogate have no canonical JSON form, so neither language reads them as events.
#[test]
fn a_log_line_with_no_canonical_form_is_a_skipped_line() {
    let setup = Setup::new("corner_nan");
    let host = setup.host().unwrap();
    assert_eq!(host.swap(&pack_path(&setup.dir, "v1"), false).unwrap()["ok"], true);
    drop(host);
    let log = format!("{}/swaps.log", setup.state());
    for (line, offender) in [("NaN", 2usize), ("[Infinity]", 2), ("{\"x\": \"\\ud800\"}", 2), ("{\"x\": 1e400}", 2), ("{\"x\": -Infinity}", 2)] {
        let intact = std::fs::read_to_string(&log).unwrap().lines().next().unwrap().to_string() + "\n";
        std::fs::write(&log, format!("{intact}{line}\n")).unwrap();
        let reopened = AuditLog::open(&log).unwrap();
        assert_eq!(reopened.skipped(), vec![offender], "{line}");
        assert!(!reopened.verify_log(), "{line}: a log with a line that is not an event does not verify");
        assert!(!reopened.verify_persisted().unwrap(), "{line}");
    }
}

/// An event holding a number beyond the double range is refused with the log unchanged, as
/// `AuditLog.append` refuses a NaN or a lone surrogate in Python (`AuditWriteError`).
#[test]
fn an_event_with_no_canonical_form_is_refused_and_the_log_is_unchanged() {
    let setup = Setup::new("corner_event");
    let log_path = format!("{}/events.log", setup.state());
    std::fs::create_dir_all(setup.state()).unwrap();
    let log = AuditLog::open(&log_path).unwrap();
    log.append("t", "ok", vec![("n", json!(1))]).unwrap();
    let overflow: Value = serde_json::from_str("1e400").unwrap();
    let refused = log.append("t", "bad", vec![("v", overflow)]).unwrap_err();
    assert!(refused.to_string().contains("no canonical JSON form"), "{refused}");
    assert_eq!(log.leaves().len(), 1);
    assert_eq!(std::fs::read_to_string(&log_path).unwrap().lines().count(), 1);
    assert!(log.verify_persisted().unwrap());
}

#[test]
fn an_intent_record_that_is_not_an_object_fails_closed() {
    let setup = Setup::new("corner_intent");
    setup.put("pending_swap", "[1]");
    assert!(matches!(setup.host(), Err(HostError::IntentUnreadable(_))));
    setup.put("pending_swap", "\"text\"");
    assert!(matches!(setup.host(), Err(HostError::IntentUnreadable(_))));
}

#[test]
fn a_verified_manifest_whose_version_is_not_an_integer_changes_nothing() {
    let setup = Setup::new("corner_version");
    let image_b64 = setup.doc["packs"]["v1"]["image_b64"].as_str().unwrap();
    use base64::Engine;
    let image = base64::engine::general_purpose::STANDARD.decode(image_b64).unwrap();
    let (private, public, _key_id) = keygen(setup.dir.join("rust_keys").to_str().unwrap(), "rust").unwrap();
    let ppt = setup.dir.join("packs/halfway.ppt");
    std::fs::write(&ppt, &image).unwrap();
    let fields = [("temp".to_string(), "int".to_string())].into_iter().collect();
    build_pack(ppt.to_str().unwrap(), &fields, 7, "env1", &private, &public, "2026-01-01T00:00:00+00:00").unwrap();
    // the same manifest with a version of 7.5, signed again by the same key: a canon/2 manifest cannot
    // hold the float at all, so it is refused as unreadable before its signature is looked at
    let manifest_path = format!("{}.manifest.json", ppt.display());
    let mut manifest: Value = serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest["version"] = json!(7.5);
    std::fs::write(&manifest_path, serde_json::to_string(&manifest).unwrap()).unwrap();
    let probe = PolicyHost::new(&setup.state(), vec![public.clone()], setup.doc["envelopes"]["default"].clone(), Vec::new()).unwrap();
    assert_eq!(probe.swap(ppt.to_str().unwrap(), false).unwrap()["reasons"], json!(["manifest:bad-format"]));
    drop(probe);
    // a canon/2 manifest with a version that is a string reads, and its signature verifies, so the version check decides
    manifest["version"] = json!("7");
    std::fs::write(&manifest_path, serde_json::to_string(&manifest).unwrap()).unwrap();
    use ed25519_dalek::Signer;
    let signature = load_private(&private).unwrap().sign(&signed_bytes(&manifest).unwrap());
    std::fs::write(format!("{}.manifest.sig", ppt.display()), signature.to_bytes()).unwrap();

    let host = PolicyHost::new(&setup.state(), vec![public], setup.doc["envelopes"]["default"].clone(), Vec::new()).unwrap();
    let result = host.swap(ppt.to_str().unwrap(), false);
    assert!(matches!(result, Err(HostError::BadManifest(_))), "{result:?}");
    assert_eq!(host.active_info(), json!({"active": null}));
    assert!(std::fs::read_to_string(format!("{}/pending_swap", setup.state())).is_err(), "nothing was committed");
    assert!(std::fs::read_to_string(format!("{}/active_version", setup.state())).is_err());
}

/// The forms an `active_version` file can take, as `int(text.strip() or "0")` reads them, and what the
/// host does with each: the floor it names binds the next swap.
#[test]
fn the_floor_file_is_read_the_way_python_reads_an_integer() {
    let forms: [(&str, Option<i64>); 11] = [
        ("3", Some(3)), ("+3", Some(3)), ("  3\n", Some(3)), ("1_0", Some(10)), ("0003", Some(3)),
        ("", Some(0)), ("  \n", Some(0)), ("1__0", None), ("_1", None), ("3.0", None), ("three", None),
    ];
    for (text, floor) in forms {
        let setup = Setup::new("corner_floor");
        setup.put("active_version", text);
        let host = setup.host().unwrap();
        // v2 is admitted by a floor below 2 and refused by a floor of 2 or more
        let result = host.swap(&pack_path(&setup.dir, "v2"), false).unwrap();
        let admitted = floor.unwrap_or(0) < 2;
        assert_eq!(result["ok"] == true, admitted, "{text:?}: {result}");
    }
    // a floor too large for any integer type still refuses everything
    let setup = Setup::new("corner_floor_huge");
    setup.put("active_version", &"9".repeat(60));
    let result = setup.host().unwrap().swap(&pack_path(&setup.dir, "v6"), false).unwrap();
    assert_eq!(result["ok"], false);
    // a negative floor is read as written and admits version 1
    let setup = Setup::new("corner_floor_negative");
    setup.put("active_version", "-5");
    assert_eq!(setup.host().unwrap().swap(&pack_path(&setup.dir, "v1"), false).unwrap()["ok"], true);
}

#[test]
fn the_system_clock_stamps_events_and_policies() {
    let setup = Setup::new("corner_clock");
    let host = setup.host().unwrap();
    let swapped = host.swap(&pack_path(&setup.dir, "v1"), false).unwrap();
    let since = swapped["since"].as_str().unwrap();
    assert_eq!(since.len(), 25, "{since}");
    assert!(since.starts_with("20") && since.ends_with("+00:00") && since.as_bytes()[10] == b'T', "{since}");
    let ts_us = host.history()[0]["ts_us"].as_i64().unwrap();
    assert!(ts_us > 1_700_000_000_000_000 && ts_us < 4_000_000_000_000_000, "{ts_us}");
    assert_eq!(iso_from_epoch_for_test(0), "1970-01-01T00:00:00+00:00");
    assert_eq!(iso_from_epoch_for_test(1_767_225_600), "2026-01-01T00:00:00+00:00");
    assert_eq!(iso_from_epoch_for_test(951_782_400), "2000-02-29T00:00:00+00:00", "a leap day");
}

fn iso_from_epoch_for_test(secs: u64) -> String {
    prismpath_hotswap_rs::host::iso_from_epoch(secs)
}

/// The lock: threads swapping through one host never interleave a commit. Every accepted swap's files
/// and event are whole, the floor equals the active version, and the log verifies against its file.
#[test]
fn a_host_shared_between_threads_commits_one_swap_at_a_time() {
    let setup = Setup::new("corner_threads");
    let host = Arc::new(setup.host().unwrap());
    let packs = ["v1", "v2", "v3", "v5", "v6", "v2b", "v4_overlay", "v1", "v2"];
    let mut handles = Vec::new();
    for pack in packs {
        let host = Arc::clone(&host);
        let path = pack_path(&setup.dir, pack);
        handles.push(std::thread::spawn(move || host.swap(&path, false).unwrap()));
    }
    let results: Vec<Value> = handles.into_iter().map(|handle| handle.join().unwrap()).collect();
    let accepted: Vec<i64> = {
        let mut versions: Vec<(String, i64)> = host
            .history()
            .iter()
            .filter(|event| event["action"] == "swap")
            .map(|event| (event["data"]["to_hash"].as_str().unwrap().to_string(), event["data"]["version"].as_i64().unwrap()))
            .collect();
        versions.dedup();
        versions.into_iter().map(|(_, version)| version).collect()
    };
    assert!(accepted.windows(2).all(|pair| pair[0] < pair[1]), "accepted versions only ever rise: {accepted:?}");
    assert_eq!(results.iter().filter(|result| result["ok"] == true).count(), accepted.len());
    let last = *accepted.last().unwrap();
    assert_eq!(host.active_info()["version"], last);
    assert_eq!(std::fs::read_to_string(format!("{}/active_version", setup.state())).unwrap(), last.to_string());
    assert!(!std::path::Path::new(&format!("{}/pending_swap", setup.state())).exists());
    assert_eq!(host.history().len(), packs.len(), "one audit event per attempt");
    assert!(host.audit.verify_log() && host.audit.verify_persisted().unwrap());
    let fresh = setup.host().unwrap();
    assert_eq!(fresh.active_info()["active"], host.active_info()["active"]);
}

/// The bytes a signature covers are refused, not panicked on, for a number beyond the double range, a float
/// and a document that does not name canon/2.
#[test]
fn canonical_bytes_refuse_a_number_beyond_the_double_range() {
    let overflow: Value = serde_json::from_str("1e400").unwrap();
    assert!(canonical_bytes(&tagged_doc(json!({"wcet_cycles": overflow}))).is_err());
    assert!(canonical_bytes(&tagged_doc(json!({"wcet_cycles": 1.5}))).is_err());
    assert!(canonical_bytes(&json!({"b": 1, "a": 2})).is_err(), "canon/1 is retired: an untagged document has no bytes");
    assert_eq!(canonical_bytes(&tagged_doc(json!({"b": 1, "a": 2}))).unwrap(), br#"{"a":2,"b":1,"encoding":"canon/2"}"#.to_vec());
}

fn tagged_doc(mut doc: Value) -> Value {
    doc["encoding"] = json!("canon/2");
    doc
}

/// Python's `PolicyHost` answers these the same way (`prismpath/tests/test_policy_host.py`); the reason text
/// after `record:unreadable:` is the part each language words for itself, so it is not in the trace corpus.
#[test]
fn an_active_record_holding_a_non_finite_number_is_not_restored() {
    for (tag, number) in [("nan", "NaN"), ("overflow", "1e400"), ("minus_infinity", "-Infinity")] {
        let setup = Setup::new(&format!("corner_record_{tag}"));
        let host = setup.host().unwrap();
        assert_eq!(host.swap(&pack_path(&setup.dir, "v1"), false).unwrap()["ok"], true);
        drop(host);
        let path = format!("{}/active_policy.json", setup.state());
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"version\":1"));
        std::fs::write(&path, text.replacen("\"version\":1", &format!("\"version\":{number}"), 1)).unwrap();
        let reopened = setup.host().unwrap();
        assert_eq!(reopened.active_info(), json!({"active": null}), "{number}");
        let event = reopened.history().pop().unwrap();
        assert_eq!(event["action"], "active_unreadable");
        assert!(event["data"]["reason"].as_str().unwrap().starts_with("record:unreadable:"), "{event}");
    }
}

/// An intent record with a number canonical JSON cannot carry is unreadable, at open and at the next swap.
#[test]
fn an_intent_record_holding_a_non_finite_number_is_unreadable() {
    for (tag, record) in [
        ("nan", r#"{"to_hash": null, "version": NaN}"#),
        ("overflow", r#"{"to_hash": null, "version": 1e400}"#),
        ("op", r#"{"to_hash": "x", "version": 2, "op": "rollback", "extra": Infinity}"#),
    ] {
        let setup = Setup::new(&format!("corner_pending_{tag}"));
        let host = setup.host().unwrap();
        assert_eq!(host.swap(&pack_path(&setup.dir, "v1"), false).unwrap()["ok"], true);
        setup.put("pending_swap", record);
        assert!(matches!(setup.host(), Err(HostError::IntentUnreadable(_))), "{tag}");
        assert!(matches!(host.swap(&pack_path(&setup.dir, "v2"), false), Err(HostError::IntentUnreadable(_))), "{tag}");
        assert_eq!(host.active_info()["version"], 1);
    }
}

/// A manifest holding NaN or a number beyond the double range is `manifest:bad-format`, audited as a rejection,
/// in both languages (`verify_pack` in Python used to raise `CanonicalReadError` from the reading); the active
/// policy is unchanged and the pack is not activated.
#[test]
fn a_pack_whose_manifest_holds_a_non_finite_number_is_rejected_and_not_activated() {
    let setup = Setup::new("corner_manifest");
    let host = setup.host().unwrap();
    assert_eq!(host.swap(&pack_path(&setup.dir, "v1"), false).unwrap()["ok"], true);
    for (tag, number) in [("nan", "NaN"), ("overflow", "1e400")] {
        let manifest_path = format!("{}.manifest.json", pack_path(&setup.dir, "v2"));
        let text = std::fs::read_to_string(&manifest_path).unwrap();
        assert!(text.contains("\"version\": 2"));
        std::fs::write(&manifest_path, text.replacen("\"version\": 2", &format!("\"version\": {number}"), 1)).unwrap();
        let result = host.swap(&pack_path(&setup.dir, "v2"), false).unwrap();
        assert_eq!(result, json!({"ok": false, "reasons": ["manifest:bad-format"]}), "{tag}");
        assert_eq!(host.history().pop().unwrap()["action"], "swap_rejected", "{tag}: audited");
        assert_eq!(host.active_info()["version"], 1);
        std::fs::write(&manifest_path, text).unwrap();
    }
}
