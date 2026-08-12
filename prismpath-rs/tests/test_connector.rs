//! Connector-SDK + composition gate: replay `conformance/connector.json` — hashes and prompt
//! strings byte-for-byte, the attestation manifest exactly, and the spawn/join fan-out ending in
//! the same final path/stopped with `_children` aggregated — against the Python reference.
#![cfg(feature = "durable")]

use prismpath_rs::compose::run_fanout;
use prismpath_rs::connector::{flatten, Connector, DeferralStore, EchoConnector, MemDeferralStore};
use prismpath_rs::{RunState, V};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};

fn fixtures() -> Value {
    let path = format!(
        "{}/../prismpath/portable/conformance/connector.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("read connector.json"))
        .expect("parse connector.json")
}

#[test]
fn hashes_and_flatten_match_python() {
    let fx = fixtures();
    let conn = EchoConnector { name: "echo".to_string() };
    for c in fx["hashes"].as_array().unwrap() {
        assert_eq!(conn.ingestion_hash(&c["data"]), c["ingestion"].as_str().unwrap());
        assert_eq!(conn.knowledge_hash(&c["data"]), c["knowledge"].as_str().unwrap());
    }
    for c in fx["flatten"].as_array().unwrap() {
        let mut flat = BTreeMap::new();
        flatten(&c["data"], "", ".", &mut flat);
        let expected = c["flat"].as_object().unwrap();
        assert_eq!(flat.len(), expected.len(), "flatten arity for {}", c["data"]);
        for (k, v) in expected {
            // Python stores raw values; the prompt renders them str() — compare rendered.
            let rendered = prismpath_rs::py_str(&V::from_json(v));
            assert_eq!(flat.get(k), Some(&rendered), "flatten[{k}] for {}", c["data"]);
        }
    }
}

#[test]
fn prompt_surface_matches_python_byte_for_byte() {
    let fx = fixtures();
    let conn = EchoConnector { name: "echo".to_string() };
    for c in fx["prompts"].as_array().unwrap() {
        let criteria = c["criteria"].as_str();
        let schema = c.get("schema").filter(|s| !s.is_null());
        let got = conn.adjudication_prompt(&c["payload"], criteria, schema);
        assert_eq!(got, c["prompt"].as_str().unwrap(), "prompt for {}", c["payload"]);
    }
}

#[test]
fn attestation_manifest_matches_python() {
    let fx = fixtures();
    let a = &fx["attestation"];
    let conn = EchoConnector { name: "echo".to_string() };
    let ing: Vec<&str> =
        a["ingestion_hashes"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect();
    let got = conn.attest_decision(
        &a["outcome"],
        a["policy_hash"].as_str().unwrap(),
        a["gate_id"].as_str().unwrap(),
        &ing,
        a["kb_hash"].as_str().unwrap(),
        None,
        a["manifest"]["created"].as_str().unwrap(),
    );
    assert_eq!(got, a["manifest"], "attestation manifest");
}

#[test]
fn adjudicate_extracts_json_and_degrades_gracefully() {
    let conn = EchoConnector { name: "echo".to_string() };
    let mut model = |_prompt: &str| r#"verdict follows {"verdict": "contain"} end"#.to_string();
    let out = conn.adjudicate(&json!({"x": 1}), &mut model, None, None);
    assert_eq!(out["verdict"], "contain");
    let mut plain = |_p: &str| "no json here".to_string();
    let out2 = conn.adjudicate(&json!({"x": 1}), &mut plain, None, None);
    assert_eq!(out2, json!({"text": "no json here"}));
}

#[test]
fn deferral_port_round_trip() {
    let mut store = MemDeferralStore::default();
    store.defer("u1", "needs evidence", json!({"k": 1}), None);
    assert_eq!(store.pending().len(), 1);
    assert!(store.resume("u1", json!({"approved": true}), "auditor:js"));
    assert_eq!(store.pending().len(), 0);
    assert!(!store.resume("u1", json!({}), "again")); // already resolved
}

#[test]
fn emit_record_is_idempotent() {
    let conn = EchoConnector { name: "echo".to_string() };
    let dir = std::env::temp_dir().join(format!("pp_conn_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let dest = dir.join("out.jsonl");
    let dest_s = dest.to_str().unwrap();
    let _ = std::fs::remove_file(&dest);
    conn.emit_record(&json!({"id": "a", "v": 1}), dest_s, "id").unwrap();
    conn.emit_record(&json!({"id": "a", "v": 2}), dest_s, "id").unwrap(); // replayed -> replaces
    conn.emit_record(&json!({"id": "b", "v": 3}), dest_s, "id").unwrap();
    let lines: Vec<Value> = std::fs::read_to_string(&dest)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 2, "replayed key must not double-write");
    assert_eq!(lines[0]["v"], 2);
    let _ = std::fs::remove_dir_all(&dir);
}

// ------------------------------------------------------------------ spawn/join fan-out

fn scripted(script: Value) -> Box<dyn FnMut(&str, &str, &RunState) -> Result<V, String>> {
    let mut used: HashMap<String, usize> = HashMap::new();
    Box::new(move |node: &str, _i: &str, _s: &RunState| {
        let Some(seq) = script.get(node).and_then(|s| s.as_array()) else {
            return Ok(V::Obj(vec![("text".to_string(), V::Str(node.to_string()))]));
        };
        let i = *used.get(node).unwrap_or(&0);
        used.insert(node.to_string(), i + 1);
        Ok(V::from_json(&seq[i.min(seq.len() - 1)]))
    })
}

#[test]
fn fanout_matches_the_python_reference() {
    let fx = fixtures();
    let f = &fx["fanout"];
    let dir = std::env::temp_dir().join(format!("pp_fanout_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let parent = dir.join("fx_parent.md");
    std::fs::write(&parent, f["parent_flow"].as_str().unwrap()).unwrap();
    let ckpt = dir.join("fx_parent.ckpt.json");

    let parent_script = f["parent_script"].clone();
    let child_script = f["child_script"].clone();
    let child_flow = f["child_flow"].as_str().unwrap().to_string();

    let (final_res, children) = run_fanout(
        parent.to_str().unwrap(),
        ckpt.to_str().unwrap(),
        &mut *scripted(parent_script.clone()),
        move || scripted(child_script.clone()),
        move |name| {
            if name == "fx_child" {
                Ok(child_flow.clone())
            } else {
                Err(format!("unknown child flow {name}"))
            }
        },
    )
    .expect("fanout");

    // children match the reference (item, path, stopped)
    let got_children: Vec<Value> = children
        .iter()
        .map(|c| json!({"item": c.item, "path": c.path, "stopped": c.stopped}))
        .collect();
    assert_eq!(json!(got_children), f["children"], "child results");

    // parent finishes on the same path with the aggregation visible in state
    assert_eq!(json!(final_res.path), f["final"]["path"], "final path");
    assert_eq!(final_res.stopped, f["final"]["stopped"].as_str().unwrap(), "final stopped");
    let children_in_state =
        final_res.state.extra.get("_children").map(V::to_json).unwrap_or(Value::Null);
    assert_eq!(children_in_state, f["final"]["children_in_state"], "_children in state");

    eprintln!("fanout: {} children, final path {:?} — matches Python", children.len(), final_res.path);
    let _ = std::fs::remove_dir_all(&dir);
}
