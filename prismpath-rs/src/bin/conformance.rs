// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! Certify `prismpath-rs` against the frozen kernel spec.

use prismpath_rs::{eval_condition, parse, run, run_locked, Lock, RunOpts, RunState, Value};
use std::collections::HashMap;

#[derive(serde::Deserialize)]
struct PredicateCase {
    cond: String,
    ctx: HashMap<String, serde_json::Value>,
    expect: serde_json::Value,
}

#[derive(serde::Deserialize)]
struct PredicateFile {
    cases: Vec<PredicateCase>,
}

#[derive(serde::Deserialize)]
struct FlowCase {
    name: String,
    flow: String,
    #[serde(default)]
    script: HashMap<String, Vec<serde_json::Value>>,
    expect: serde_json::Value,
    #[serde(default)]
    start: Option<String>,
    #[serde(default)]
    state: Option<serde_json::Value>,
    #[serde(default, rename = "maxSteps")]
    max_steps: Option<usize>,
}

#[derive(serde::Deserialize)]
struct FlowFile {
    cases: Vec<FlowCase>,
}

#[derive(serde::Deserialize)]
struct P1FlowCase {
    name: String,
    flow: String,
    #[serde(default)]
    script: HashMap<String, Vec<serde_json::Value>>,
    lock: serde_json::Value,
    #[serde(default, rename = "embedMap")]
    embed_map: HashMap<String, serde_json::Value>,
    expect: serde_json::Value,
    #[serde(default)]
    start: Option<String>,
    #[serde(default)]
    state: Option<serde_json::Value>,
    #[serde(default, rename = "maxSteps")]
    max_steps: Option<usize>,
    #[serde(default, rename = "humanFloor")]
    human_floor: Option<f64>,
}

#[derive(serde::Deserialize)]
struct P1FlowFile {
    cases: Vec<P1FlowCase>,
}

fn classify(cond: &str) -> &'static str {
    let cond_str = cond.trim_start_matches("when ").trim();
    let tokens: Vec<&str> = cond_str.split_whitespace().collect();
    if cond_str.contains(" not in ") {
        "`not in` semantics"
    } else if tokens.len() > 3 && (cond_str.contains('<') || cond_str.contains('>') || cond_str.contains("==")) {
        "chained / multi-term comparison"
    } else if cond_str.contains(" and ") || cond_str.contains(" or ") || cond_str.starts_with("not ") {
        "boolean connective (and/or/not)"
    } else if cond_str.contains('[') || cond_str.contains('(') {
        "collection literal / grouping"
    } else if tokens.len() == 3 {
        "binary comparison semantics"
    } else if tokens.len() == 1 {
        "bare-field truthiness"
    } else {
        "other"
    }
}

fn scripted_agent<'a>(
    script: &'a HashMap<String, Vec<serde_json::Value>>,
) -> impl FnMut(&str, &str, &RunState) -> Result<Value, String> + 'a {
    let mut used: HashMap<String, usize> = HashMap::new();
    move |node: &str, _instruction: &str, _state: &RunState| {
        let Some(seq) = script.get(node) else {
            return Ok(Value::Obj(vec![("text".to_string(), Value::Str(node.to_string()))]));
        };
        let idx = *used.get(node).unwrap_or(&0);
        used.insert(node.to_string(), idx + 1);
        let outcome = &seq[idx.min(seq.len().saturating_sub(1))];
        if let serde_json::Value::Object(obj_val) = outcome {
            if let Some(msg) = obj_val.get("__raise__") {
                return Err(match msg {
                    serde_json::Value::String(str_val) => str_val.clone(),
                    other => other.to_string(),
                });
            }
        }
        Ok(Value::from_json(outcome))
    }
}

fn main() {
    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "../prismpath/portable/conformance".to_string());

    println!("=== prismpath-rs CONFORMANCE CERTIFICATION ===");
    println!("corpus: {dir}\n");

    let mut failures = 0usize;

    // predicates
    let raw = std::fs::read_to_string(format!("{dir}/predicates.json")).unwrap_or_else(|err| {
        eprintln!("cannot read predicates.json: {err}");
        std::process::exit(2);
    });
    let pf: PredicateFile = serde_json::from_str(&raw).expect("predicates.json parse");

    let mut pred_pass = 0usize;
    let mut buckets: HashMap<&'static str, usize> = HashMap::new();
    let mut samples: HashMap<&'static str, Vec<String>> = HashMap::new();

    for case in &pf.cases {
        let ctx: HashMap<String, Value> =
            case.ctx.iter().map(|(key, val)| (key.clone(), Value::from_json(val))).collect();

        let got = match eval_condition(&case.cond, &ctx) {
            Ok(bool_val) => bool_val.to_string(),
            Err(_) => "ERROR".to_string(),
        };
        let want = match &case.expect {
            serde_json::Value::Bool(bool_val) => bool_val.to_string(),
            serde_json::Value::String(str_val) => str_val.clone(),
            other => other.to_string(),
        };

        if got == want {
            pred_pass += 1;
        } else {
            failures += 1;
            let bucket = classify(&case.cond);
            *buckets.entry(bucket).or_insert(0) += 1;
            let entry = samples.entry(bucket).or_default();
            if entry.len() < 3 {
                entry.push(format!(
                    "{:?} ctx={} -> expected {want}, got {got}",
                    case.cond,
                    serde_json::to_string(&case.ctx).unwrap_or_default()
                ));
            }
        }
    }
    println!("PREDICATES: {pred_pass}/{} match the frozen spec", pf.cases.len());
    if pred_pass < pf.cases.len() {
        println!("\n  divergences grouped by cause:");
        let mut rows: Vec<_> = buckets.iter().collect();
        rows.sort_by(|left, right| right.1.cmp(left.1));
        for (bucket, count) in rows {
            println!("    {count:>5}  {bucket}");
            for sample_item in &samples[*bucket] {
                println!("           {sample_item}");
            }
        }
    }

    // flows
    let fraw = std::fs::read_to_string(format!("{dir}/flows.json")).expect("read flows.json");
    let ff: FlowFile = serde_json::from_str(&fraw).expect("flows.json parse");

    let mut flow_pass = 0usize;
    for fx in &ff.cases {
        let graph = parse(&fx.flow);
        let opts = RunOpts {
            max_steps: fx.max_steps.unwrap_or(25),
            start: fx.start.clone(),
            state: fx.state.as_ref().map(Value::from_json),
            ..Default::default()
        };
        let got = match run(&graph, scripted_agent(&fx.script), opts) {
            Ok(res) => serde_json::json!({
                "path": res.path,
                "stopped": res.stopped,
                "pending_node": res.pending.as_ref().map(|pending_val| pending_val.node.clone()),
                "spawn": res.pending.as_ref().and_then(|pending_val| pending_val.spawn.as_ref().map(val_to_json)),
            }),
            Err(err) => serde_json::json!({ "error": err.to_string() }),
        };
        let want = serde_json::json!({
            "path": fx.expect.get("path").cloned().unwrap_or(serde_json::Value::Null),
            "stopped": fx.expect.get("stopped").cloned().unwrap_or(serde_json::Value::Null),
            "pending_node": fx.expect.get("pending_node").cloned().unwrap_or(serde_json::Value::Null),
            "spawn": fx.expect.get("spawn").cloned().unwrap_or(serde_json::Value::Null),
        });
        if got == want {
            flow_pass += 1;
        } else {
            failures += 1;
            println!("\nFLOW MISMATCH  {}", fx.name);
            println!("  expect = {want}");
            println!("  got    = {got}");
        }
    }
    println!("\nFLOWS: {flow_pass}/{} match the frozen spec", ff.cases.len());

    // P1 locked flows
    let p1_path = format!("{dir}/locked_flows.json");
    if let Ok(p1_raw) = std::fs::read_to_string(&p1_path) {
        let p1f: P1FlowFile = serde_json::from_str(&p1_raw).expect("locked_flows.json parse");
        let mut p1_pass = 0usize;
        for fx in &p1f.cases {
            let graph = parse(&fx.flow);
            let lock = Lock::from_json(&fx.lock).unwrap_or_else(|err| {
                panic!("P1 fixture {:?}: lock parse error: {err}", fx.name);
            });

            let embed_map: HashMap<String, Vec<f32>> = fx
                .embed_map
                .iter()
                .map(|(key, val)| {
                    let b64 = val.as_str().expect("embedMap values must be base64 strings");
                    (key.clone(), prismpath_rs::decode_b64_f32(b64).expect("embedMap base64 decode"))
                })
                .collect();
            let dim = lock.dim;

            let opts = RunOpts {
                max_steps: fx.max_steps.unwrap_or(25),
                start: fx.start.clone(),
                state: fx.state.as_ref().map(Value::from_json),
                human_floor: fx.human_floor,
                ..Default::default()
            };

            let got = match run_locked(
                &graph,
                scripted_agent(&fx.script),
                |text: &str| {
                    embed_map
                        .get(text)
                        .cloned()
                        .unwrap_or_else(|| vec![0.0f32; dim])
                },
                &lock,
                opts,
            ) {
                Ok(res) => serde_json::json!({
                    "path": res.path,
                    "stopped": res.stopped,
                    "pending_node": res.pending.as_ref().map(|pending_val| pending_val.node.clone()),
                    "would_pick": res.pending.as_ref().and_then(|pending_val| pending_val.would_pick.clone()),
                }),
                Err(err) => serde_json::json!({ "error": err.to_string() }),
            };
            let want = serde_json::json!({
                "path": fx.expect.get("path").cloned().unwrap_or(serde_json::Value::Null),
                "stopped": fx.expect.get("stopped").cloned().unwrap_or(serde_json::Value::Null),
                "pending_node": fx.expect.get("pending_node").cloned().unwrap_or(serde_json::Value::Null),
                "would_pick": fx.expect.get("would_pick").cloned().unwrap_or(serde_json::Value::Null),
            });
            if got == want {
                p1_pass += 1;
            } else {
                failures += 1;
                println!("\nP1 FLOW MISMATCH  {}", fx.name);
                println!("  expect = {want}");
                println!("  got    = {got}");
            }
        }
        println!("\nP1 LOCKED FLOWS: {p1_pass}/{} match the frozen spec", p1f.cases.len());
    } else {
        println!("\n(no locked_flows.json found - P1 conformance skipped)");
    }

    // verdict
    println!("\n---------------------------------------------------");
    if failures == 0 {
        println!("CONFORMANT - prismpath-rs matches the frozen kernel spec.");
        std::process::exit(0);
    }
    println!("NOT CONFORMANT - {failures} divergence(s) from the frozen kernel spec.");
    std::process::exit(1);
}

fn val_to_json(val: &Value) -> serde_json::Value {
    match val {
        Value::Null => serde_json::Value::Null,
        Value::Bool(bool_val) => serde_json::Value::Bool(*bool_val),
        Value::Num(num_val) if num_val.fract() == 0.0 && num_val.abs() < 9.2e18 => {
            serde_json::Value::Number(serde_json::Number::from(*num_val as i64))
        }
        Value::Num(num_val) => serde_json::Number::from_f64(*num_val)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        Value::Str(str_val) => serde_json::Value::String(str_val.clone()),
        Value::List(arr_val) => serde_json::Value::Array(arr_val.iter().map(val_to_json).collect()),
        Value::Obj(obj_val) => serde_json::Value::Object(
            obj_val.iter().map(|(key, item)| (key.clone(), val_to_json(item))).collect(),
        ),
        Value::Ellipsis => serde_json::Value::Null,
    }
}
