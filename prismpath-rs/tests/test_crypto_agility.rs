//! Conformance gate for the Rust crypto-agility proof layer (§4.2, §5).
//!
//! Gates byte-for-byte against BOTH frozen conformance fixtures:
//!   - `prismpath/portable/conformance/crypto_agility.json`
//!   - `prismpath/portable/conformance/crypto_migration.json`
//!
//! Parity is proven, not asserted.

use prismpath_rs::crypto_agility::{
    prove_all, prove_monotone_migration, registry_hash,
};
use prismpath_rs::parse;
use serde_json::Value;
use std::fs;

fn load_fixture(filename: &str) -> Value {
    let path = format!(
        "{}/../prismpath/portable/conformance/{}",
        env!("CARGO_MANIFEST_DIR"),
        filename
    );
    let doc: Value = serde_json::from_str(&fs::read_to_string(&path).expect("read fixture"))
        .expect("parse fixture");
    doc
}

fn phase_policy(k: i64) -> String {
    format!(
        r#"---
name: ca_phase_{k}
start: classify
---
## classify
-> cui-path: when data_class == "cui"
-> legacy-path: when migration_phase < {k}
-> hybrid-path: else
## cui-path
-> suite-cnsa2-hybrid-1: when always
## legacy-path
-> suite-tls13-aesgcm: when always
## hybrid-path
-> suite-tls13-hybrid-x25519mlkem: when always
## suite-cnsa2-hybrid-1
-> end: when always
## suite-tls13-aesgcm
-> end: when always
## suite-tls13-hybrid-x25519mlkem
-> end: when always
## end
done
"#
    )
}

fn migration_envelope(rh: &str, floor: i64) -> Value {
    let suites = vec![
        "cnsa2-hybrid-1",
        "tls13-aesgcm",
        "tls13-hybrid-x25519mlkem",
    ];
    serde_json::json!({
        "envelope_id": format!("floor-{floor}"),
        "approved_suites": suites,
        "class_field": "data_class",
        "migration_phase_field": "migration_phase",
        "migration_phase_floor": floor,
        "registry_hash": rh,
        "key_id": "0".repeat(64),
    })
}

#[test]
fn crypto_agility_conformance() {
    let agility_fx = load_fixture("crypto_agility.json");
    let registry = &agility_fx["registry"];
    let expected_hash = agility_fx["registry_hash"].as_str().expect("hash str");
    let computed_hash = registry_hash(registry);

    assert_eq!(computed_hash, expected_hash, "registry_hash mismatch");

    let cases = agility_fx["cases"].as_array().expect("cases array");
    for c in cases {
        let name = c["name"].as_str().expect("case name");
        let flow_text = c["flow_text"].as_str().expect("flow text");
        let g = parse(flow_text);
        let got = prove_all(&g, &agility_fx["envelope"], registry);
        assert_eq!(got, c["expected"], "crypto_agility case {name} mismatch");
    }

    eprintln!("crypto_agility: {}/{} cases CONFORMANT", cases.len(), cases.len());
}

#[test]
fn crypto_migration_conformance() {
    let agility_fx = load_fixture("crypto_agility.json");
    let registry = &agility_fx["registry"];
    let migration_fx = load_fixture("crypto_migration.json");

    let expected_hash = migration_fx["registry_hash"].as_str().expect("hash str");
    let computed_hash = registry_hash(registry);
    assert_eq!(computed_hash, expected_hash, "migration registry_hash mismatch");

    let cells = migration_fx["cells"].as_array().expect("cells array");
    for cell in cells {
        let k = cell["policy_gate"].as_i64().expect("gate");
        let f = cell["envelope_floor"].as_i64().expect("floor");
        let g = parse(&phase_policy(k));
        let env = migration_envelope(&computed_hash, f);

        let p4 = prove_monotone_migration(&g, &env, registry);

        assert_eq!(p4, cell["p4"], "migration cell k={k}, f={f} p4 mismatch");

        let p4_ok = p4["ok"].as_bool().unwrap_or(false);
        let inv = cell["invariant_holds"].as_bool().unwrap_or(false);
        assert_eq!(p4_ok == (f >= k), inv, "migration cell k={k}, f={f} invariant mismatch");
    }

    eprintln!("crypto_migration: {}/{} cells CONFORMANT", cells.len(), cells.len());
}
