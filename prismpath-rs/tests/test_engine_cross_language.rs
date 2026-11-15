// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The engine surface, run on both engines: the same flows and scripted workers give the same paths, stops,
//! causes, pending decisions, persisted transcripts, dropped counts, `on_step` calls and routing decision
//! records, in the same order.
//!
//! The scenarios are every case of `flows.json` and `locked_flows.json` (the locked ones with a `run_id`, so
//! the decision records carry it), a few written by hand for the seeded resume and the gate on a locked
//! flow, and a seeded random sample the Python oracle (`tests/support/engine_oracle.py`) generates: flows
//! with deterministic, error, event and semantic edges, `@state_bound` annotations (a few malformed), workers
//! that emit values of every type, raise, ask for a human or wait, and every combination of the options.
//! A decision record's scores are compared to 1e-5, since Python scores in float32 and Rust in double.
//!
//! Runs when `PRISMPATH_PYTHON` names an interpreter with the package importable; with
//! `PRISMPATH_REQUIRE_CROSS_LANGUAGE` set a missing interpreter is a failure, not a skip.

use prismpath_rs::engine::{run_locked_decided, run_observed};
use prismpath_rs::{parse, Lock, RunOpts, RunState, Step, Value, WorkerError};
use serde_json::{json, Value as Json};
use std::collections::HashMap;
use std::process::{Command, Stdio};

const ORACLE: &str = include_str!("support/engine_oracle.py");
const FUZZ_SEED: u64 = 20261109;
const FUZZ_COUNT: u64 = 600;

/// The sample size: 600 unless `PRISMPATH_FUZZ_COUNT` asks for more (a longer run, not a gate).
fn fuzz_count() -> u64 {
    std::env::var("PRISMPATH_FUZZ_COUNT").ok().and_then(|text| text.parse().ok()).unwrap_or(FUZZ_COUNT)
}

fn corpus(name: &str) -> Json {
    let text = std::fs::read_to_string(format!("tests/fixtures/{name}.json")).unwrap_or_else(|error| panic!("read {name}.json: {error}"));
    serde_json::from_str(&text).expect("parse corpus")
}

fn flow_scenario(case: &Json) -> Json {
    let mut scenario = json!({"flow": case["flow"], "script": case["script"], "opts": case.get("opts").cloned().unwrap_or(json!({}))});
    for (from, to) in [("maxSteps", "maxSteps"), ("start", "start"), ("state", "state")] {
        if let Some(found) = case.get(from) {
            scenario[to] = found.clone();
        }
    }
    scenario
}

fn locked_scenario(case: &Json) -> Json {
    let mut scenario = flow_scenario(case);
    for key in ["lock", "embedMap", "humanFloor"] {
        if let Some(found) = case.get(key) {
            scenario[key] = found.clone();
        }
    }
    scenario["run_id"] = json!(format!("run-{}", case["name"].as_str().unwrap()));
    scenario
}

fn scenarios() -> Vec<Json> {
    let mut out: Vec<Json> = corpus("flows")["cases"].as_array().unwrap().iter().map(flow_scenario).collect();
    let locked = corpus("locked_flows");
    let locked_cases = locked["cases"].as_array().unwrap();
    out.extend(locked_cases.iter().map(locked_scenario));
    // the gate, the bound and a run id on a flow the semantic tier routes
    let mut gated = locked_scenario(&locked_cases[0]);
    gated["opts"] = json!({"type_gate": true, "max_transcript": 1});
    out.push(gated);
    // a resume seeded with a long history: the bound trims the path and the steps too
    let seeded = json!({
        "flow": "---\nname: seeded\nstart: a\n---\n## a\n@state_bound(transcript=2)\n-> a: when visits < 4\n-> b: else\n## b\nDone.\n",
        "script": {"a": [{"text": "x"}]}, "start": "a",
        "state": {"visits": {"a": 1}, "transcript": [{"node": "a", "outcome": "1"}, {"node": "a", "outcome": "2"}, {"node": "a", "outcome": "3"}]},
        "seed_path": ["a", "a", "a", "a", "a"],
        "seed_steps": [{"node": "a", "target": "a", "used": "human"}, {"node": "a", "target": "a", "used": "human"}, {"node": "a", "target": "a", "used": "human"}],
        "opts": {},
    });
    out.push(seeded);
    let mut seeded_override = out.last().unwrap().clone();
    seeded_override["opts"] = json!({"max_transcript": 4});
    out.push(seeded_override);
    out
}

fn value_to_json(value: &Value) -> Json {
    value.to_json()
}

fn rust_result(scenario: &Json) -> Json {
    let graph = parse(scenario["flow"].as_str().unwrap());
    let script: HashMap<String, Vec<Json>> = scenario["script"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(node, outcomes)| (node.clone(), outcomes.as_array().unwrap().clone()))
        .collect();
    let mut used: HashMap<String, usize> = HashMap::new();
    let agent = move |node: &str, _instruction: &str, _state: &RunState| -> Result<Value, WorkerError> {
        let Some(seq) = script.get(node) else {
            return Ok(Value::Obj(vec![("text".to_string(), Value::Str(node.to_string()))]));
        };
        let index = *used.get(node).unwrap_or(&0);
        used.insert(node.to_string(), index + 1);
        let outcome = &seq[index.min(seq.len() - 1)];
        if let Some(message) = outcome.get("__raise__") {
            let message = message.as_str().unwrap_or("").to_string();
            // a failure with a class is reported with it; one without is the plain message, whose kind is `Error`
            return Err(match outcome.get("__kind__").and_then(Json::as_str) {
                Some(kind) => WorkerError::new(kind, message),
                None => message.into(),
            });
        }
        Ok(Value::try_from_json(outcome).expect("scenario outcome"))
    };
    let opts_json = scenario.get("opts").cloned().unwrap_or(json!({}));
    let opts = RunOpts {
        max_steps: scenario.get("maxSteps").and_then(Json::as_u64).unwrap_or(25) as usize,
        start: scenario.get("start").and_then(Json::as_str).map(str::to_string),
        state: scenario.get("state").map(|state| Value::try_from_json(state).expect("scenario state")),
        human_floor: scenario.get("humanFloor").and_then(Json::as_f64),
        type_gate: opts_json.get("type_gate").and_then(Json::as_bool).unwrap_or(false),
        max_transcript: opts_json.get("max_transcript").and_then(Json::as_i64),
        run_id: scenario.get("run_id").and_then(Json::as_str).map(str::to_string),
        seed_path: scenario
            .get("seed_path")
            .and_then(Json::as_array)
            .map(|path| path.iter().map(|node| node.as_str().unwrap().to_string()).collect())
            .unwrap_or_default(),
        seed_steps: scenario
            .get("seed_steps")
            .and_then(Json::as_array)
            .map(|steps| {
                steps
                    .iter()
                    .map(|step| Step {
                        node: step["node"].as_str().unwrap().to_string(),
                        outcome: String::new(),
                        target: step["target"].as_str().unwrap().to_string(),
                        used: step["used"].as_str().unwrap().to_string(),
                        cond: None,
                        score: None,
                        margin: None,
                        sims: None,
                        locked: None,
                        error_type: None,
                        guard_errors: None,
                    })
                    .collect()
            })
            .unwrap_or_default(),
    };
    let mut calls: Vec<Json> = Vec::new();
    let mut decisions: Vec<Json> = Vec::new();
    let on_step = |res: &prismpath_rs::RunResult, _state: &RunState, pending_node: Option<&str>| {
        calls.push(json!([pending_node, res.stopped, res.path.len(), res.steps.len()]));
    };
    let outcome = if let Some(lock_json) = scenario.get("lock") {
        let lock = Lock::from_json(lock_json).expect("scenario lock");
        let dim = lock.dim;
        let embed_map: HashMap<String, Vec<f32>> = scenario["embedMap"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(text, b64)| (text.clone(), prismpath_rs::decode_b64_f32(b64.as_str().unwrap()).expect("embed vector")))
            .collect();
        run_locked_decided(
            &graph,
            agent,
            |text: &str| embed_map.get(text).cloned().unwrap_or_else(|| vec![0.0f32; dim]),
            &lock,
            opts,
            on_step,
            |decision| decisions.push(decision.to_json()),
        )
    } else {
        run_observed(&graph, agent, opts, on_step)
    };
    match outcome {
        Err(error) => match error.reference_exception() {
            Some((class, message)) => json!({"error": message, "error_class": class}),
            None => json!({"error": error.to_string()}),
        },
        Ok(res) => {
            let pending = res.pending.as_ref().map(|pending| {
                json!({
                    "node": pending.node,
                    "reason": pending.reason,
                    "violations": pending.violations,
                    "would_pick": pending.would_pick,
                    "wait": pending.wait,
                    "awaiting": if pending.wait { json!(pending.awaiting) } else { Json::Null },
                    "timeout_s": pending.timeout_s.as_ref().map(value_to_json),
                    "spawn": pending.spawn.as_ref().map(value_to_json),
                })
            });
            json!({
                "path": res.path,
                "stopped": res.stopped,
                "cause": res.cause,
                "pending": pending,
                "transcript": res.state.transcript.iter().map(value_to_json).collect::<Vec<_>>(),
                "state_dropped": res.state.dropped.iter().map(|(key, count)| (key.clone(), json!(count))).collect::<serde_json::Map<_, _>>(),
                "visits": res.state.visits.iter().map(|(key, count)| (key.clone(), json!(count))).collect::<serde_json::Map<_, _>>(),
                "steps": res.steps.iter().map(step_json).collect::<Vec<_>>(),
                "guard_errors": res.state.guard_errors.iter().map(|entry| {
                    let entry = value_to_json(entry);
                    json!([entry["node"], entry["guard"]])
                }).collect::<Vec<_>>(),
                "on_step": calls,
                "decisions": decisions,
            })
        }
    }
}

/// A step as the Python oracle writes it: its node and target and what its info holds. The info of the reference's
/// step is `used` and `cond` for a deterministic route, `used`, `score`, `margin`, `sims` and `locked` for a
/// semantic one and `used`, `error_type` and `guard_errors` for the error tier.
fn step_json(step: &Step) -> Json {
    let mut item = json!({"node": step.node, "target": step.target, "used": step.used});
    if let Some(cond) = &step.cond {
        item["cond"] = json!(cond);
    }
    if let Some(score) = step.score {
        item["score"] = json!(score);
    }
    if let Some(margin) = step.margin {
        item["margin"] = json!(margin);
    }
    if let Some(sims) = &step.sims {
        item["sims"] = json!(sims);
    }
    if let Some(locked) = step.locked {
        item["locked"] = json!(locked);
    }
    if let Some(kind) = &step.error_type {
        item["error_type"] = json!(kind);
    }
    if let Some(count) = step.guard_errors {
        item["guard_errors"] = json!(count);
    }
    item
}

/// Equal, with numbers compared as doubles to a relative 1e-5.
fn close(left: &Json, right: &Json) -> bool {
    match (left, right) {
        (Json::Number(a), Json::Number(b)) => match (a.to_string().parse::<f64>(), b.to_string().parse::<f64>()) {
            (Ok(x), Ok(y)) => (x - y).abs() <= 1e-5 * x.abs().max(1.0),
            _ => a == b,
        },
        (Json::Array(a), Json::Array(b)) => a.len() == b.len() && a.iter().zip(b).all(|(x, y)| close(x, y)),
        (Json::Object(a), Json::Object(b)) => a.len() == b.len() && a.iter().all(|(key, x)| b.get(key).is_some_and(|y| close(x, y))),
        _ => left == right,
    }
}

fn oracle(scenarios: &[Json]) -> Option<Vec<Json>> {
    let python = match std::env::var("PRISMPATH_PYTHON") {
        Ok(path) => path,
        Err(_) => {
            assert!(
                std::env::var("PRISMPATH_REQUIRE_CROSS_LANGUAGE").is_err(),
                "PRISMPATH_REQUIRE_CROSS_LANGUAGE is set but PRISMPATH_PYTHON is not"
            );
            eprintln!("SKIP: PRISMPATH_PYTHON not set; the corpus checks in test_conformance and the conformance binary still ran");
            return None;
        }
    };
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let request = json!({"scenarios": scenarios, "fuzz": {"seed": FUZZ_SEED, "count": fuzz_count()}});
    let mut child = Command::new(python)
        .args(["-c", ORACLE])
        .env("PYTHONPATH", repo_root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run python");
    {
        use std::io::Write;
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(request.to_string().as_bytes()).unwrap();
    }
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    Some(serde_json::from_slice::<Vec<Json>>(&output.stdout).expect("oracle output"))
}

#[test]
fn both_engines_agree_on_the_corpus_and_on_a_random_sample() {
    let given = scenarios();
    let Some(pairs) = oracle(&given) else { return };
    assert_eq!(pairs.len(), given.len() + fuzz_count() as usize);
    let mut stops: HashMap<String, usize> = HashMap::new();
    let (mut decided, mut gated, mut bounded, mut errors, mut error_steps) = (0usize, 0usize, 0usize, 0usize, 0usize);
    let (mut guarded, mut missing_nodes) = (0usize, 0usize);
    let mut used_counts: HashMap<String, usize> = HashMap::new();
    let mut error_kinds: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut bad = Vec::new();
    for pair in &pairs {
        let scenario = &pair["scenario"];
        let python = &pair["python"];
        let rust = rust_result(scenario);
        if let Some(stop) = python["stopped"].as_str() {
            *stops.entry(stop.to_string()).or_insert(0) += 1;
        }
        decided += python["decisions"].as_array().map_or(0, |list| list.len());
        gated += usize::from(python["stopped"] == "contract_violation");
        bounded += usize::from(python["state_dropped"].as_object().is_some_and(|dropped| !dropped.is_empty()));
        errors += usize::from(python.get("error").is_some());
        missing_nodes += usize::from(python["error_class"] == "KeyError");
        guarded += python["guard_errors"].as_array().map_or(0, |list| list.len());
        for step in python["steps"].as_array().into_iter().flatten() {
            if let Some(kind) = step["error_type"].as_str() {
                error_steps += 1;
                error_kinds.insert(kind.to_string());
            }
            *used_counts.entry(step["used"].as_str().unwrap_or("").to_string()).or_insert(0) += 1;
        }
        if !close(python, &rust) && bad.len() < 6 {
            bad.push(format!("flow:\n{}\nscenario: {}\npython: {python}\nrust:   {rust}", scenario["flow"].as_str().unwrap(), {
                let mut shown = scenario.clone();
                shown.as_object_mut().unwrap().remove("flow");
                shown
            }));
        }
    }
    println!("engine cross language: {} scenarios, stops {stops:?}, {decided} decision records, {gated} gate stops, {bounded} bounded runs, {errors} refusals, {error_steps} error steps of kinds {error_kinds:?}, {guarded} unevaluable error guards recorded, {missing_nodes} routes into an undefined node, steps by tier {used_counts:?}", pairs.len());
    assert!(bad.is_empty(), "{} mismatches, first:\n{}", bad.len(), bad.join("\n\n"));
    // the sample reaches what it is for
    for stop in ["terminal", "stuck", "needs_human", "waiting", "max_steps", "contract_violation"] {
        assert!(stops.contains_key(stop), "no {stop} run among the scenarios");
    }
    assert!(decided > 0 && gated > 0 && bounded > 0 && errors > 0);
    for tier in ["deterministic", "embed", "error"] {
        assert!(used_counts.get(tier).is_some_and(|count| *count > 0), "no {tier} step among the scenarios");
    }
    assert!(error_steps > 0 && error_kinds.len() >= 3 && guarded > 0 && missing_nodes > 0, "the sample routes on the worker's error kind: {error_kinds:?}");
}
