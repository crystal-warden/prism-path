//! Conformance gate for the Rust proof layer — Level M classification + capability report.
//! Gates byte-for-byte against the SAME frozen corpora the Python reference and the JS twin pass
//! (`prismpath/portable/conformance/{level_m,capability}.json`). Parity is proven, not asserted.

use prismpath_rs::{capability_report, check_reach, flow_level_m, parse};
use serde_json::Value;
use std::fs;

fn cases(name: &str) -> Vec<Value> {
    let path = format!(
        "{}/../prismpath/portable/conformance/{}",
        env!("CARGO_MANIFEST_DIR"),
        name
    );
    let doc: Value = serde_json::from_str(&fs::read_to_string(&path).expect("read corpus"))
        .expect("parse corpus");
    doc.get("cases")
        .and_then(|c| c.as_array())
        .cloned()
        .or_else(|| doc.as_array().cloned())
        .expect("corpus is a list or {cases:[...]}")
}

#[test]
fn level_m_conformance() {
    let cs = cases("level_m.json");
    for c in &cs {
        let flow = c["flow"].as_str().expect("flow");
        let g = parse(flow);
        let (lm, non_member) = flow_level_m(&g);
        // Mirror run_level_m.mjs's normalizer: the level_m corpus drops the `level_m` flag from
        // each non-member edge (capability.json keeps it — the two runners differ deliberately).
        let nm: Vec<Value> = non_member
            .iter()
            .map(|e| {
                serde_json::json!({
                    "node": e.node, "target": e.target, "condition": e.condition, "reason": e.reason,
                })
            })
            .collect();
        let got = serde_json::json!({ "level_m": lm, "non_member_edges": nm });
        assert_eq!(got, c["expected"], "level_m case {}", c["key"]);
    }
    assert!(!cs.is_empty());
    eprintln!("level_m: {}/{} CONFORMANT", cs.len(), cs.len());
}

#[test]
fn capability_conformance() {
    let cs = cases("capability.json");
    for c in &cs {
        let flow = c["flow"].as_str().expect("flow");
        let g = parse(flow);
        let got = capability_report(&g);
        assert_eq!(got, c["expected"], "capability case {}", c["key"]);
    }
    assert!(!cs.is_empty());
    eprintln!("capability: {}/{} CONFORMANT", cs.len(), cs.len());
}

#[test]
fn reach_conformance() {
    let cs = cases("reach.json");
    for c in &cs {
        let flow = c["flow"].as_str().expect("flow");
        let g = parse(flow);
        let targets: Vec<String> = c["targets"]
            .as_array()
            .expect("targets")
            .iter()
            .map(|t| t.as_str().expect("target str").to_string())
            .collect();
        let assume = c["assume"].as_str(); // null -> None
        let bound = c["bound"].as_u64().unwrap_or(25) as usize;
        let inc_err = c["include_errors"].as_bool().unwrap_or(true);
        let inc_evt = c["include_events"].as_bool().unwrap_or(true);
        let got = check_reach(&g, &targets, assume, bound, inc_err, inc_evt);
        assert_eq!(got, c["expected"], "reach case {}", c["key"]);
    }
    assert!(!cs.is_empty());
    eprintln!("reach: {}/{} CONFORMANT", cs.len(), cs.len());
}
