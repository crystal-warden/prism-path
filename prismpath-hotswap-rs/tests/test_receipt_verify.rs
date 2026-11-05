// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! Receipt verification cross-language gate: replay `conformance/receipts.json`, the frozen vectors
//! the Python reference produced for canonical JSON, the Merkle tree, audit logs with their root
//! statements, receipt bundles, flow manifests, the version floor and the instance key separation,
//! and require every verdict to match Python's exactly (status, counts, finding names and fields,
//! check results, refusal causes). Every case runs; the test fails with the names of all that differ.

use prismpath_hotswap_rs::flow_authority::{verify_flow, VersionFloor};
use prismpath_hotswap_rs::merkle::{merkle_root, path_from_json, verify_leaf};
use prismpath_hotswap_rs::root_statement::{check_separation, verify_receipt_bundle, verify_trail};
use prismpath_rs::durable::py_canonical_string;
use serde_json::{json, Value};

fn vectors() -> Value {
    let path = format!("{}/../prismpath/portable/conformance/receipts.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).expect("read receipts.json")).expect("parse receipts.json")
}

fn keys(case: &Value, field: &str) -> Vec<Vec<u8>> {
    case[field].as_array().unwrap().iter().map(|key| hex::decode(key.as_str().unwrap()).unwrap()).collect()
}

fn strings(case: &Value, field: &str) -> Vec<String> {
    case[field].as_array().unwrap().iter().map(|text| text.as_str().unwrap().to_string()).collect()
}

fn run_case(case: &Value) -> Result<(), String> {
    let expect = &case["expect"];
    let compare = |got: Value| {
        if &got == expect {
            Ok(())
        } else {
            Err(format!("expected {expect}\n     got {got}"))
        }
    };
    match case["kind"].as_str().unwrap() {
        "canon" => {
            let parsed: Value = serde_json::from_str(case["json"].as_str().unwrap()).map_err(|error| error.to_string())?;
            compare(json!(py_canonical_string(&parsed, false)))
        }
        "merkle" => {
            let leaves = strings(case, "leaves");
            if merkle_root(&leaves)? != case["root"].as_str().unwrap() {
                return Err("root differs".to_string());
            }
            let root = case["root"].as_str().unwrap();
            for (leaf, path) in leaves.iter().zip(case["paths"].as_array().unwrap()) {
                let steps = path_from_json(path)?;
                if !verify_leaf(leaf, &steps, root)? {
                    return Err(format!("inclusion path for {leaf} does not verify"));
                }
                if verify_leaf(&hex::encode([0u8; 32]), &steps, root)? && !steps.is_empty() {
                    return Err("a leaf that is not in the tree verified".to_string());
                }
            }
            Ok(())
        }
        "trail" => {
            let statements = case["statements_text"].as_str();
            compare(verify_trail(case["log_text"].as_str().unwrap(), statements, &keys(case, "pinned")).to_json())
        }
        "bundle" => compare(match verify_receipt_bundle(&case["bundle"], &keys(case, "pinned")) {
            Ok(verdict) => verdict.to_json(),
            Err(_) => json!({"error": true}),
        }),
        "flow" => {
            let signature = case["sig_hex"].as_str().map(|text| hex::decode(text).unwrap());
            let floor = case["floor"].as_object().map(|entries| VersionFloor { entries: entries.clone() });
            let verdict = verify_flow(
                case["flow_text"].as_str().unwrap().as_bytes(),
                case["manifest_text"].as_str(),
                signature.as_deref(),
                &keys(case, "pubs"),
                &strings(case, "revoked"),
                floor.as_ref(),
            );
            compare(verdict.to_json())
        }
        "floor" => {
            let mut floor = VersionFloor::default();
            let mut admits = Vec::new();
            for step in case["steps"].as_array().unwrap() {
                admits.push(floor.admits(&step["manifest"]));
                floor.accept(&step["manifest"])?;
            }
            compare(json!({"admits": admits, "entries": floor.entries}))
        }
        "separation" => {
            let authorities = strings(case, "authority_key_ids");
            compare(json!({"ok": check_separation(case["instance_key_id"].as_str(), &authorities).is_ok()}))
        }
        other => Err(format!("unknown case kind {other}")),
    }
}

#[test]
fn rust_gives_every_verdict_the_python_reference_gave() {
    let doc = vectors();
    let cases = doc["cases"].as_array().unwrap();
    let mut failures = Vec::new();
    let mut by_kind = std::collections::BTreeMap::new();
    for case in cases {
        *by_kind.entry(case["kind"].as_str().unwrap().to_string()).or_insert(0usize) += 1;
        if let Err(why) = run_case(case) {
            failures.push(format!("{} {}: {why}", case["kind"], case["name"]));
        }
    }
    eprintln!("receipts: {}/{} cases agree with Python {:?}", cases.len() - failures.len(), cases.len(), by_kind);
    assert!(cases.len() >= 250, "the vector set is missing cases");
    assert!(failures.is_empty(), "{} case(s) differ from the Python reference:\n{}", failures.len(), failures.join("\n"));
}

#[test]
fn the_vector_set_has_every_kind() {
    let doc = vectors();
    let kinds: std::collections::BTreeSet<&str> = doc["cases"].as_array().unwrap().iter().map(|case| case["kind"].as_str().unwrap()).collect();
    let expected = ["bundle", "canon", "floor", "flow", "merkle", "separation", "trail"];
    assert_eq!(kinds.into_iter().collect::<Vec<_>>(), expected);
}
