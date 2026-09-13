// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
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
    for case in fx["hashes"].as_array().unwrap() {
        assert_eq!(conn.ingestion_hash(&case["data"]), case["ingestion"].as_str().unwrap());
        assert_eq!(conn.knowledge_hash(&case["data"]), case["knowledge"].as_str().unwrap());
    }
    for case in fx["flatten"].as_array().unwrap() {
        let mut flat = BTreeMap::new();
        flatten(&case["data"], "", ".", &mut flat);
        let expected = case["flat"].as_object().unwrap();
        assert_eq!(flat.len(), expected.len(), "flatten arity for {}", case["data"]);
        for (key, value) in expected {
            // Python stores raw values; the prompt renders them str() — compare rendered.
            let rendered = prismpath_rs::py_str(&V::from_json(value));
            assert_eq!(flat.get(key), Some(&rendered), "flatten[{key}] for {}", case["data"]);
        }
    }
}

#[test]
fn prompt_surface_matches_python_byte_for_byte() {
    let fx = fixtures();
    let conn = EchoConnector { name: "echo".to_string() };
    for case in fx["prompts"].as_array().unwrap() {
        let criteria = case["criteria"].as_str();
        let schema = case.get("schema").filter(|value| !value.is_null());
        let got = conn.adjudication_prompt(&case["payload"], criteria, schema);
        assert_eq!(got, case["prompt"].as_str().unwrap(), "prompt for {}", case["payload"]);
    }
}

#[test]
fn attestation_manifest_matches_python() {
    let fx = fixtures();
    let attestation = &fx["attestation"];
    let conn = EchoConnector { name: "echo".to_string() };
    let ing: Vec<&str> =
        attestation["ingestion_hashes"].as_array().unwrap().iter().map(|entry| entry.as_str().unwrap()).collect();
    let got = conn.attest_decision(
        &attestation["outcome"],
        attestation["policy_hash"].as_str().unwrap(),
        attestation["gate_id"].as_str().unwrap(),
        &ing,
        attestation["kb_hash"].as_str().unwrap(),
        None,
        attestation["manifest"]["created"].as_str().unwrap(),
    );
    assert_eq!(got, attestation["manifest"], "attestation manifest");
}

#[test]
fn adjudicate_extracts_json_and_degrades_gracefully() {
    let conn = EchoConnector { name: "echo".to_string() };
    let mut model = |_prompt: &str| r#"verdict follows {"verdict": "contain"} end"#.to_string();
    let out = conn.adjudicate(&json!({"x": 1}), &mut model, None, None);
    assert_eq!(out["verdict"], "contain");
    let mut plain = |_prompt: &str| "no json here".to_string();
    let out2 = conn.adjudicate(&json!({"x": 1}), &mut plain, None, None);
    assert_eq!(out2, json!({"text": "no json here"}));
}

#[test]
fn join_policy_grid_matches_the_composer() {
    use prismpath_rs::compose::{join_event, quorum_threshold};
    let fx = fixtures();
    let grid = fx["joins"].as_array().expect("regen connector.json (v2) for the joins grid");
    for case in grid {
        let join = case["join"].as_str().unwrap();
        let done: Vec<bool> = case["done"].as_array().unwrap().iter().map(|entry| entry.as_bool().unwrap()).collect();
        if let Some(thr) = case["threshold"].as_u64() {
            assert_eq!(quorum_threshold(join, done.len()) as u64, thr, "threshold {join} {done:?}");
        }
        let expected = case["event"].as_str();
        assert_eq!(join_event(join, &done), expected, "event for {join} {done:?}");
    }
    eprintln!("joins: {}/{} grid entries match composer", grid.len(), grid.len());
}

/// Bidirectional file-deferral parity: Python defers -> Rust lists + resumes -> Python reads the
/// resolution (and the reverse). Skips cleanly without the venv.
#[test]
fn file_deferral_store_is_cross_runtime() {
    use prismpath_rs::connector::FileDeferralStore;
    let repo = format!("{}/..", env!("CARGO_MANIFEST_DIR"));
    let python = format!("{repo}/.venv/bin/python");
    if !std::path::Path::new(&python).exists() {
        eprintln!("SKIP: no .venv python for the bidirectional leg");
        return;
    }
    let dir = std::env::temp_dir().join(format!("pp_defer_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let store = FileDeferralStore::new(&dir).unwrap();
    let run_python = |code: &str| {
        let out = std::process::Command::new(&python).arg("-c").arg(code).output().unwrap();
        assert!(out.status.success(), "python failed: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };

    // Python defers -> Rust sees it pending and resumes it -> Python reads the resolution
    run_python(&format!(
        "import sys; sys.path.insert(0, {repo:?})\n\
         from prismpath.deferral import FileDeferralStore\n\
         FileDeferralStore({d:?}).defer('wu:py', reason='needs evidence', state={{'n': 1}})",
        repo = repo, d = dir.to_str().unwrap()
    ));
    let pending = store.pending();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0]["unit_id"], "wu:py");
    store.resume("wu:py", json!({"approved": true}), "auditor:rust").unwrap();
    let verdict = run_python(&format!(
        "import sys, json; sys.path.insert(0, {repo:?})\n\
         from prismpath.deferral import FileDeferralStore\n\
         r = FileDeferralStore({d:?}).get('wu:py')\n\
         print(json.dumps([r['status'], r['actor'], len(FileDeferralStore({d:?}).pending())]))",
        repo = repo, d = dir.to_str().unwrap()
    ));
    assert_eq!(verdict, r#"["resolved", "auditor:rust", 0]"#);

    // Rust defers -> Python resumes -> Rust reads the resolution
    store.defer("wu:rs", "human review", json!({"k": 2}), None).unwrap();
    run_python(&format!(
        "import sys; sys.path.insert(0, {repo:?})\n\
         from prismpath.deferral import FileDeferralStore\n\
         FileDeferralStore({d:?}).resume('wu:rs', {{'ok': True}}, 'auditor:py')",
        repo = repo, d = dir.to_str().unwrap()
    ));
    let rec = store.get("wu:rs").unwrap();
    assert_eq!(rec["status"], "resolved");
    assert_eq!(rec["actor"], "auditor:py");
    assert_eq!(store.pending().len(), 0);
    eprintln!("file deferral: cross-runtime round-trips both ways");
    let _ = std::fs::remove_dir_all(&dir);
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
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines.len(), 2, "replayed key must not double-write");
    assert_eq!(lines[0]["v"], 2);
    let _ = std::fs::remove_dir_all(&dir);
}

// ------------------------------------------------------------------ spawn/join fan-out

/// A boxed agent callback (node, input, state) -> result — aliased to stay under clippy's
/// type-complexity bar.
type ScriptedAgent = Box<dyn FnMut(&str, &str, &RunState) -> Result<V, String>>;

fn scripted(script: Value) -> ScriptedAgent {
    let mut used: HashMap<String, usize> = HashMap::new();
    Box::new(move |node: &str, _instr: &str, _state: &RunState| {
        let Some(seq) = script.get(node).and_then(|value| value.as_array()) else {
            return Ok(V::Obj(vec![("text".to_string(), V::Str(node.to_string()))]));
        };
        let call_count = *used.get(node).unwrap_or(&0);
        used.insert(node.to_string(), call_count + 1);
        Ok(V::from_json(&seq[call_count.min(seq.len() - 1)]))
    })
}

#[test]
fn fanout_matches_the_python_reference() {
    let fx = fixtures();
    let fanout = &fx["fanout"];
    let dir = std::env::temp_dir().join(format!("pp_fanout_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let parent = dir.join("fx_parent.md");
    std::fs::write(&parent, fanout["parent_flow"].as_str().unwrap()).unwrap();
    let ckpt = dir.join("fx_parent.ckpt.json");

    let parent_script = fanout["parent_script"].clone();
    let child_script = fanout["child_script"].clone();
    let child_flow = fanout["child_flow"].as_str().unwrap().to_string();

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
        .map(|child| json!({"item": child.item, "path": child.path, "stopped": child.stopped}))
        .collect();
    assert_eq!(json!(got_children), fanout["children"], "child results");

    // parent finishes on the same path with the aggregation visible in state
    assert_eq!(json!(final_res.path), fanout["final"]["path"], "final path");
    assert_eq!(final_res.stopped, fanout["final"]["stopped"].as_str().unwrap(), "final stopped");
    let children_in_state =
        final_res.state.extra.get("_children").map(V::to_json).unwrap_or(Value::Null);
    assert_eq!(children_in_state, fanout["final"]["children_in_state"], "_children in state");

    eprintln!("fanout: {} children, final path {:?} — matches Python", children.len(), final_res.path);
    let _ = std::fs::remove_dir_all(&dir);
}
