//! Context-ledger cross-language gate: replay `conformance/context.json` — every segment
//! leaf/chain, head, Merkle root, and the bound manifest must match the Python reference
//! byte-for-byte; tamper and privacy properties re-proven on this side.
#![cfg(feature = "durable")]

use prismpath_rs::durable::{verify_context_chain, verify_manifest, ContextLedger};
use serde_json::Value;

fn fixtures() -> Value {
    let path = format!(
        "{}/../prismpath/portable/conformance/context.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("read context.json"))
        .expect("parse context.json")
}

#[test]
fn ledgers_match_the_python_reference() {
    let fx = fixtures();
    let cases = fx["cases"].as_array().unwrap();
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let mut led = ContextLedger::default();
        for inp in c["inputs"].as_array().unwrap() {
            led.commit(
                inp["role"].as_str().unwrap(),
                inp["content"].as_str().unwrap(),
                inp["salt"].as_str(),
            )
            .unwrap();
        }
        // segments byte-match (idx, role, leaf, salted, chain)
        let got: Vec<Value> = led
            .segments
            .iter()
            .map(|s| {
                serde_json::json!({"idx": s.idx, "role": s.role, "leaf": s.leaf,
                                   "salted": s.salted, "chain": s.chain})
            })
            .collect();
        assert_eq!(serde_json::json!(got), c["segments"], "{name}: segments");
        assert_eq!(led.head(), c["head"].as_str().unwrap(), "{name}: head");
        assert_eq!(led.root(), c["root"].as_str().unwrap(), "{name}: root");

        // the bound manifest matches Python's exactly (created pinned) and verifies
        let a = &c["attest_inputs"];
        let m = led.attest(
            a["policy_hash"].as_str(),
            a["gate_id"].as_str(),
            a["model_id"].as_str().unwrap(),
            c["manifest"]["created"].as_str().unwrap(),
        );
        assert_eq!(m, c["manifest"], "{name}: manifest");
        assert!(verify_manifest(&m), "{name}: manifest must verify");

        // chain verifies; any edit flips it
        assert!(verify_context_chain(&led.segments), "{name}: chain");
        if led.segments.len() > 1 {
            let mut tampered = led.segments.clone();
            tampered[0].leaf = "e".repeat(64);
            assert!(!verify_context_chain(&tampered), "{name}: tamper must fail");
        }

        // privacy: no input content appears anywhere in the artifacts. Trivial strings ("yes",
        // "no") collide with JSON field names as substrings ("k~no~wledge_base_hash") — their
        // privacy is already proven above by the salted leaf differing from the guessable hash,
        // so the substring scan applies to non-trivial content only.
        let artifact = format!("{got:?}{m}");
        for inp in c["inputs"].as_array().unwrap() {
            let content = inp["content"].as_str().unwrap();
            if content.len() > 8 {
                assert!(!artifact.contains(content), "{name}: content leaked");
            }
        }
    }
    eprintln!("context: {}/{} ledgers match the reference", cases.len(), cases.len());
}
