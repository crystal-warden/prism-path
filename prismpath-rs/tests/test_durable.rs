// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! Durable-layer conformance gate: replay `conformance/durable.json` — canonical JSON byte-exact,
//! manifests re-addressed + verified (tamper must fail), salt vectors, and the checkpoint/resume
//! scenarios run through the REAL Rust engine with scripted agents, compared against what the
//! Python reference froze (flow_path/saved_at dropped; everything else must match).
#![cfg(feature = "durable")]

use prismpath_rs::durable::*;
use prismpath_rs::{RunState, V};
use serde_json::Value;
use std::collections::HashMap;

fn fixtures() -> Value {
    let path = format!(
        "{}/../prismpath/portable/conformance/durable.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("read durable.json"))
        .expect("parse durable.json")
}

#[test]
fn canonical_json_is_byte_identical_to_python() {
    let fx = fixtures();
    let cases = fx["canonical"].as_array().unwrap();
    for case in cases {
        assert_eq!(
            py_canonical_string(&case["obj"], false),
            case["compact"].as_str().unwrap(),
            "compact bytes for {}",
            case["obj"]
        );
        assert_eq!(
            py_canonical_string(&case["obj"], true),
            case["spaced"].as_str().unwrap(),
            "spaced bytes for {}",
            case["obj"]
        );
    }
    eprintln!("canonical: {}/{} byte-identical", cases.len(), cases.len());
}

#[test]
fn manifests_verify_and_tamper_fails() {
    let fx = fixtures();
    let prov = &fx["manifests"]["provenance"];
    let over = &fx["manifests"]["override"];
    let tampered = &fx["manifests"]["tampered"];

    assert!(verify_manifest(prov), "Python-built provenance manifest must verify in Rust");
    assert!(verify_manifest(over), "Python-built override manifest must verify in Rust");
    assert!(!verify_manifest(tampered), "tampered manifest must fail");

    // Rebuild the SAME manifests in Rust from the frozen inputs — the content addresses must match.
    let ing: Vec<&str> =
        prov["ingestion_hashes"].as_array().unwrap().iter().map(|entry| entry.as_str().unwrap()).collect();
    let rebuilt = provenance_manifest(
        prov["root"].as_str().unwrap(),
        prov["label"].as_str().unwrap(),
        prov["created"].as_str().unwrap(),
        prov["policy_hash"].as_str(),
        prov["gate_id"].as_str(),
        &ing,
        prov["knowledge_base_hash"].as_str(),
    );
    assert_eq!(rebuilt, *prov, "Rust-built provenance manifest != Python's");

    let rebuilt_over = override_manifest(
        prov,
        over["overrider_id"].as_str().unwrap(),
        over["rationale"].as_str().unwrap(),
        over["root"].as_str().unwrap(),
        None,
        over["created"].as_str().unwrap(),
    );
    assert_eq!(rebuilt_over, *over, "Rust-built override manifest != Python's");
}

#[test]
fn salt_vectors_match() {
    let fx = fixtures();
    for case in fx["salt"].as_array().unwrap() {
        let got = salt_leaf(case["leaf"].as_str().unwrap(), case["secret"].as_str().unwrap()).unwrap();
        assert_eq!(got, case["expected"].as_str().unwrap());
    }
}

// ------------------------------------------------------------------ checkpoint scenarios

fn scripted_agent(
    script: &Value,
) -> impl FnMut(&str, &str, &RunState) -> Result<V, String> + '_ {
    let mut used: HashMap<String, usize> = HashMap::new();
    move |node: &str, _instr: &str, _st: &RunState| {
        let Some(seq) = script.get(node).and_then(|value| value.as_array()) else {
            return Ok(V::Obj(vec![("text".to_string(), V::Str(node.to_string()))]));
        };
        let call_count = *used.get(node).unwrap_or(&0);
        used.insert(node.to_string(), call_count + 1);
        let outcome = &seq[call_count.min(seq.len() - 1)];
        if let Some(msg) = outcome.get("__raise__").and_then(|value| value.as_str()) {
            return Err(msg.to_string());
        }
        Ok(V::from_json(outcome))
    }
}

fn normalize(mut cp: Value) -> Value {
    if let Value::Object(object) = &mut cp {
        object.remove("flow_path");
        object.remove("saved_at");
    }
    cp
}

fn tmpdir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("pp_durable_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn checkpoint_scenarios_match_the_python_reference() {
    let fx = fixtures();
    let dir = tmpdir();
    let scenarios = fx["checkpoints"].as_array().unwrap();
    for scenario in scenarios {
        let name = scenario["name"].as_str().unwrap();
        let flow_path = dir.join(format!("{name}.md"));
        std::fs::write(&flow_path, scenario["flow"].as_str().unwrap()).unwrap();
        let ckpt = dir.join(format!("{name}.ckpt.json"));
        let (flow_s, ckpt_s) =
            (flow_path.to_str().unwrap().to_string(), ckpt.to_str().unwrap().to_string());

        let run_res =
            run_durable(&flow_s, scripted_agent(&scenario["script"]), &ckpt_s, false, Default::default());

        match name {
            "crash_resume" => {
                assert!(run_res.is_err(), "{name}: the crash scenario must error");
            }
            _ => {
                let result = run_res.unwrap_or_else(|error| panic!("{name}: run failed: {error}"));
                if let Some(susp) = scenario.get("suspended").filter(|value| !value.is_null()) {
                    assert_eq!(serde_json::json!(result.path), susp["path"], "{name}: suspended path");
                    assert_eq!(result.stopped, susp["stopped"].as_str().unwrap(), "{name}: suspended stop");
                }
            }
        }
        let got = normalize(load_checkpoint(&ckpt_s).unwrap());
        assert_eq!(got, scenario["ckpt"], "{name}: checkpoint after run");

        // Resume leg, if the scenario has one.
        if let Some(resume_spec) = scenario.get("resume").filter(|value| !value.is_null()) {
            let choose = resume_spec.get("choose").and_then(|value| value.as_str());
            let event = resume_spec.get("event").and_then(|value| value.as_str());
            let script = resume_spec.get("script").unwrap_or(&scenario["script"]);
            let resumed = resume(&ckpt_s, scripted_agent(script), choose, event, 25, true)
                .unwrap_or_else(|error| panic!("{name}: resume failed: {error}"));
            assert_eq!(serde_json::json!(resumed.path), scenario["final"]["path"], "{name}: final path");
            assert_eq!(resumed.stopped, scenario["final"]["stopped"].as_str().unwrap(), "{name}: final stop");
            let got2 = normalize(load_checkpoint(&ckpt_s).unwrap());
            assert_eq!(got2, scenario["ckpt_after"], "{name}: checkpoint after resume");
        } else if scenario.get("final").is_some() {
            // terminal scenario: final == the run itself
            let got_final = &scenario["final"];
            let cp = load_checkpoint(&ckpt_s).unwrap();
            assert_eq!(cp["path"], got_final["path"], "{name}: terminal path");
        }
    }
    eprintln!("checkpoints: {}/{} scenarios match", scenarios.len(), scenarios.len());
    let _ = std::fs::remove_dir_all(&dir);
}
