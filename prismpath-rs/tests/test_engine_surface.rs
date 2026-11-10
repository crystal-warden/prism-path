// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The engine options the Python engine has and the frozen corpus did not: the type gate and its stop
//! (`contract_violation`, cause 37), the transcript bound, `run_id` and the routing decision observer. The
//! corpus cases are in `flows.json` (run by the conformance binary) and the two engines are compared in
//! `test_engine_cross_language.rs`; this file holds what neither can: the refusals Rust adds, the
//! checkpoint a gated run writes and a Python resume of it, the decision records of every locked flow,
//! and the hostile inputs.
#![cfg(feature = "durable")]

mod common;

use common::Scratch;
use prismpath_rs::causes;
use prismpath_rs::durable::{load_checkpoint, resume, run_durable};
use prismpath_rs::engine::{run_locked_decided, Decision};
use prismpath_rs::{parse, run, EngineError, Lock, RunOpts, RunState, Value, WorkerError};
use serde_json::{json, Value as Json};
use std::collections::HashMap;
use std::process::Command;

const GATED: &str = "---\nname: gated\nstart: triage\n---\n## triage\nTriage.\n-> done: when confirmed\n-> held: else\n## done\nDone.\n## held\nHeld.\n";

fn worker(outcomes: Json) -> impl FnMut(&str, &str, &RunState) -> Result<Value, String> {
    move |node: &str, _instruction: &str, _state: &RunState| {
        Ok(Value::try_from_json(outcomes.get(node).unwrap_or(&json!({"text": node}))).unwrap())
    }
}

fn gated_opts() -> RunOpts {
    RunOpts { type_gate: true, ..Default::default() }
}

#[test]
fn a_wrong_type_stops_the_run_with_cause_37_and_leaves_the_evidence() {
    let result = run(&parse(GATED), worker(json!({"triage": {"text": "t", "confirmed": "yes"}})), gated_opts()).unwrap();
    assert_eq!(result.stopped, "contract_violation");
    assert_eq!(result.cause, causes::ROUTE_CONTRACT_VIOLATION);
    assert_eq!(result.cause, 37);
    assert_eq!(result.path, ["triage"]);
    let pending = result.pending.unwrap();
    assert_eq!(pending.node, "triage");
    assert_eq!(pending.reason.as_deref(), Some("worker output violates the derived contract"));
    assert_eq!(pending.violations.unwrap(), ["type: 'confirmed' should be boolean but worker emitted str ('yes')"]);
    // the same output routes when the gate is off
    let ungated = run(&parse(GATED), worker(json!({"triage": {"text": "t", "confirmed": "yes"}})), RunOpts::default()).unwrap();
    assert_eq!(ungated.stopped, "terminal");
    assert_eq!(ungated.path, ["triage", "done"]);
}

#[test]
fn a_contract_that_cannot_be_derived_exactly_refuses_the_gated_run_and_not_the_ungated_one() {
    let flow = GATED.replace("when confirmed", "when level == 9007199254740993");
    let refused = run(&parse(&flow), worker(json!({})), gated_opts());
    assert!(matches!(refused, Err(EngineError::Contract(_))), "{refused:?}");
    assert!(refused.unwrap_err().to_string().contains("2^53"));
    assert!(run(&parse(&flow), worker(json!({})), RunOpts::default()).is_ok());
}

#[test]
fn a_malformed_state_bound_refuses_the_run_before_the_worker_is_called() {
    for (text, shown) in [("0", "0"), ("-4", "-4"), ("abc", "'abc'"), ("2.5", "'2.5'")] {
        let flow = GATED.replace("## triage\n", &format!("## triage\n@state_bound(transcript={text})\n"));
        let mut called = false;
        let refused = run(&parse(&flow), |_: &str, _: &str, _: &RunState| { called = true; Ok::<_, String>(Value::Null) }, RunOpts::default());
        assert!(!called, "{text}: the worker ran");
        let message = refused.unwrap_err().to_string();
        assert!(message.starts_with(&format!("@state_bound(transcript={shown}) on node 'triage': ")), "{message}");
    }
}

#[test]
fn a_bound_slides_the_transcript_and_counts_what_it_dropped() {
    let flow = "---\nname: loop\nstart: spin\n---\n## spin\n-> spin: when visits < 6\n-> out: else\n## out\nDone.\n";
    for (keep, kept, dropped) in [(Some(2usize), 2usize, Some(4i64)), (Some(0), 6, None), (None, 6, None), (Some(6), 6, None), (Some(1), 1, Some(5))] {
        let result = run(&parse(flow), worker(json!({})), RunOpts { max_transcript: keep, ..Default::default() }).unwrap();
        assert_eq!(result.state.transcript.len(), kept, "{keep:?}");
        assert_eq!(result.state.dropped.get("transcript").copied(), dropped, "{keep:?}");
        assert_eq!(result.path.len(), 7, "the bound never touches the path of a run that was not seeded");
        assert_eq!(result.state.visits["spin"], 6, "routing reads the visit counter, which the bound leaves alone");
    }
}

#[test]
fn a_bound_larger_than_any_run_is_never_reached() {
    let flow = GATED.replace("## triage\n", "## triage\n@state_bound(transcript=99999999999999999999999999)\n");
    let result = run(&parse(&flow), worker(json!({})), RunOpts::default()).unwrap();
    assert!(result.state.dropped.is_empty());
}

#[test]
fn a_gated_run_checkpoints_the_violation_and_a_resume_keeps_the_gate() {
    let scratch = Scratch::new("surface");
    let (flow, checkpoint) = (scratch.path("gated.md"), scratch.path("gated.ckpt.json"));
    std::fs::write(&flow, GATED).unwrap();
    let result = run_durable(&flow, worker(json!({"triage": {"text": "t", "confirmed": 1}})), &checkpoint, true, RunOpts::default()).unwrap();
    assert_eq!(result.stopped, "contract_violation");
    let saved = load_checkpoint(&checkpoint).unwrap();
    assert_eq!(saved["stopped"], "contract_violation");
    assert_eq!(saved["type_gate"], true);
    assert_eq!(saved["pending_node"], "triage");
    assert_eq!(
        saved["pending_decision"],
        json!({"node": "triage", "reason": "worker output violates the derived contract",
               "violations": ["type: 'confirmed' should be boolean but worker emitted int (1)"]}),
        "the evidence packet is the node, the reason and the problems, with no candidates"
    );
    // a resume re-enters the node under the gate: a worker that is still wrong stops again, a fixed one passes
    let again = resume(&checkpoint, worker(json!({"triage": {"text": "t", "confirmed": "no"}})), None, None, 25, false).unwrap();
    assert_eq!(again.stopped, "contract_violation");
    let fixed = resume(&checkpoint, worker(json!({"triage": {"text": "t", "confirmed": true}})), None, None, 25, true).unwrap();
    assert_eq!(fixed.stopped, "terminal");
    assert_eq!(fixed.path, ["triage", "done"]);
}

#[test]
fn a_checkpoint_holds_what_the_bound_dropped() {
    let scratch = Scratch::new("surface");
    let (flow, checkpoint) = (scratch.path("loop.md"), scratch.path("loop.ckpt.json"));
    std::fs::write(&flow, "---\nname: loop\nstart: spin\n---\n## spin\n@state_bound(transcript=2)\n-> spin: when visits < 5\n-> out: else\n## out\nDone.\n").unwrap();
    run_durable(&flow, worker(json!({})), &checkpoint, false, RunOpts::default()).unwrap();
    let saved = load_checkpoint(&checkpoint).unwrap();
    assert_eq!(saved["state"]["_state_dropped"], json!({"transcript": 3}));
    assert_eq!(saved["state"]["transcript"].as_array().unwrap().len(), 2);
}

fn python() -> Option<String> {
    match std::env::var("PRISMPATH_PYTHON") {
        Ok(path) => Some(path),
        Err(_) => {
            assert!(
                std::env::var("PRISMPATH_REQUIRE_CROSS_LANGUAGE").is_err(),
                "PRISMPATH_REQUIRE_CROSS_LANGUAGE is set but PRISMPATH_PYTHON is not"
            );
            eprintln!("SKIP: PRISMPATH_PYTHON not set; the Rust only checks above still ran");
            None
        }
    }
}

fn run_python(python: &str, script: &str, args: &[&str]) -> Json {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let output = Command::new(python).arg("-c").arg(script).args(args).env("PYTHONPATH", repo_root).output().expect("run python");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    serde_json::from_slice(&output.stdout).expect("python output")
}

#[test]
fn python_resumes_a_rust_gated_checkpoint_and_rust_resumes_a_python_one() {
    let Some(python) = python() else { return };
    let scratch = Scratch::new("surface");
    let (flow, rust_ckpt, py_ckpt) = (scratch.path("gated.md"), scratch.path("rust.ckpt.json"), scratch.path("python.ckpt.json"));
    std::fs::write(&flow, GATED).unwrap();
    run_durable(&flow, worker(json!({"triage": {"text": "t", "confirmed": "yes"}})), &rust_ckpt, true, RunOpts::default()).unwrap();
    let resume_script = "import json, sys\nfrom prismpath.ledgers.checkpoint import resume\n\
        res = resume(sys.argv[1], lambda node, instruction, state: {'text': node, 'confirmed': True}, write_back=False)\n\
        print(json.dumps({'path': res.path, 'stopped': res.stopped, 'cause': res.cause}))";
    assert_eq!(run_python(&python, resume_script, &[&rust_ckpt]), json!({"path": ["triage", "done"], "stopped": "terminal", "cause": 0}));
    // and the reverse: Python writes the checkpoint of a violation, Rust reads it, keeps the gate and finishes
    let write_script = "import json, sys\nfrom prismpath.ledgers.checkpoint import run_durable\n\
        res = run_durable(sys.argv[1], lambda node, instruction, state: {'text': node, 'confirmed': 'yes'}, sys.argv[2], type_gate=True)\n\
        print(json.dumps({'stopped': res.stopped, 'cause': res.cause}))";
    assert_eq!(run_python(&python, write_script, &[&flow, &py_ckpt]), json!({"stopped": "contract_violation", "cause": 37}));
    let saved = load_checkpoint(&py_ckpt).unwrap();
    assert_eq!(saved["pending_decision"]["violations"], json!(["type: 'confirmed' should be boolean but worker emitted str ('yes')"]));
    let still_wrong = resume(&py_ckpt, worker(json!({"triage": {"text": "t", "confirmed": "yes"}})), None, None, 25, false).unwrap();
    assert_eq!(still_wrong.stopped, "contract_violation", "Rust kept the gate the Python checkpoint carried");
    let fixed = resume(&py_ckpt, worker(json!({"triage": {"text": "t", "confirmed": false}})), None, None, 25, false).unwrap();
    assert_eq!(fixed.path, ["triage", "held"]);
    assert_eq!(fixed.stopped, "terminal");
}

fn corpus(name: &str) -> Json {
    serde_json::from_str(&std::fs::read_to_string(format!("../prismpath/portable/conformance/{name}.json")).unwrap()).unwrap()
}

#[test]
fn every_locked_flow_gives_one_decision_record_per_semantic_step_with_the_run_id() {
    let doc = corpus("locked_flows");
    let mut records = 0usize;
    for case in doc["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let graph = parse(case["flow"].as_str().unwrap());
        let lock = Lock::from_json(&case["lock"]).unwrap();
        let embed_map: HashMap<String, Vec<f32>> = case["embedMap"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(text, b64)| (text.clone(), prismpath_rs::decode_b64_f32(b64.as_str().unwrap()).unwrap()))
            .collect();
        let script = case["script"].as_object().unwrap().clone();
        let mut used: HashMap<String, usize> = HashMap::new();
        let agent = move |node: &str, _i: &str, _s: &RunState| -> Result<Value, String> {
            let Some(seq) = script.get(node).and_then(Json::as_array) else {
                return Ok(Value::Obj(vec![("text".to_string(), Value::Str(node.to_string()))]));
            };
            let index = *used.get(node).unwrap_or(&0);
            used.insert(node.to_string(), index + 1);
            Ok(Value::try_from_json(&seq[index.min(seq.len() - 1)]).unwrap())
        };
        let dim = lock.dim;
        let mut decisions: Vec<Decision> = Vec::new();
        let opts = RunOpts {
            human_floor: case.get("humanFloor").and_then(Json::as_f64),
            run_id: Some(format!("run-{name}")),
            max_steps: case.get("maxSteps").and_then(Json::as_u64).unwrap_or(25) as usize,
            ..Default::default()
        };
        let result = run_locked_decided(
            &graph,
            agent,
            |text: &str| embed_map.get(text).cloned().unwrap_or_else(|| vec![0.0; dim]),
            &lock,
            opts,
            |_, _, _| {},
            |decision| decisions.push(decision.clone()),
        )
        .unwrap();
        let semantic_steps: Vec<&prismpath_rs::Step> = result.steps.iter().filter(|step| step.locked == Some(true)).collect();
        assert_eq!(decisions.len(), semantic_steps.len(), "{name}: one record per semantic route");
        for (decision, step) in decisions.iter().zip(&semantic_steps) {
            assert_eq!(decision.node, step.node, "{name}");
            assert_eq!(decision.chosen, step.target, "{name}");
            assert_eq!(decision.run_id.as_deref(), Some(format!("run-{name}").as_str()));
            assert_eq!(decision.flow, graph.name);
            assert_eq!(decision.top1, step.score);
            assert!(decision.top2.is_none_or(|second| second <= decision.top1.unwrap()), "{name}: top2 is the runner up");
            assert_eq!(decision.mechanism, "embed");
            assert!(!decision.escalated && decision.llm_choice.is_none() && decision.label.is_none());
            assert!(decision.outcome_fields.iter().all(|(key, _)| key != "text"));
            assert_eq!(decision.to_json()["run_id"], json!(format!("run-{name}")));
        }
        records += decisions.len();
        // a human floor that stops the run leaves no record: the decision was not made
        if result.stopped == "needs_human" && case.get("humanFloor").is_some() {
            assert!(decisions.len() < 2, "{name}");
        }
    }
    assert!(records >= 5, "{records} decision records over the locked corpus");
}

#[test]
fn the_deterministic_tier_and_every_stop_leave_no_decision_record() {
    let doc = corpus("locked_flows");
    let case = &doc["cases"].as_array().unwrap().iter().find(|case| case["name"] == "deterministic_takes_priority").unwrap().clone();
    let graph = parse(case["flow"].as_str().unwrap());
    let lock = Lock::from_json(&case["lock"]).unwrap();
    let mut count = 0usize;
    let result = run_locked_decided(
        &graph,
        worker(json!({"a": {"text": "go", "x": 1}})),
        |_: &str| vec![0.0f32; 4],
        &lock,
        RunOpts::default(),
        |_, _, _| {},
        |_| count += 1,
    )
    .unwrap();
    assert_eq!(result.path, ["a", "b"]);
    assert_eq!(count, 0);
}

#[test]
fn hostile_options_never_panic() {
    let flow = parse(GATED);
    for keep in [0usize, 1, usize::MAX] {
        let result = run(&flow, worker(json!({"triage": {"text": "t", "confirmed": true}})), RunOpts { max_transcript: Some(keep), type_gate: true, ..Default::default() });
        assert!(result.is_ok(), "{keep}");
    }
    let huge_state = json!({"visits": {"triage": 1e300}, "transcript": [], "_state_dropped": {"transcript": 1e300, "path": "x"}});
    let result = run(
        &flow,
        worker(json!({})),
        RunOpts { state: Some(Value::try_from_json(&huge_state).unwrap()), max_transcript: Some(1), ..Default::default() },
    );
    assert!(result.is_ok());
    // a seeded history longer than the bound, with no steps and no path
    let seeded = run(&flow, worker(json!({})), RunOpts { seed_path: vec!["a".to_string(); 50_000], max_transcript: Some(3), ..Default::default() }).unwrap();
    assert_eq!(seeded.path, ["a", "a", "a", "triage", "held"]);
    assert_eq!(seeded.state.dropped["path"], 49_997);
}

const KINDS: &str = "---\nname: kinds\nstart: work\n---\n## work\nWork.\n-> typed: on error when error_type == \"ValueError\"\n-> plain: on error when error_type == \"Error\"\n-> done: when ok\n## typed\nTyped.\n## plain\nPlain.\n## done\nDone.\n";

#[test]
fn a_worker_reports_its_error_kind_and_a_plain_message_is_kind_error() {
    let typed = run(&parse(KINDS), |_: &str, _: &str, _: &RunState| Err::<Value, _>(WorkerError::new("ValueError", "bad input")), RunOpts::default()).unwrap();
    assert_eq!(typed.path, ["work", "typed"]);
    assert_eq!(typed.steps[0].error_type.as_deref(), Some("ValueError"));
    assert_eq!(typed.steps[0].used, "error");
    assert_eq!(typed.state.transcript[0].to_json()["outcome"], "[error: ValueError: bad input]");
    // the message alone, as a String or a &str, is the kind the reference's port always told the flow
    let plain = run(&parse(KINDS), |_: &str, _: &str, _: &RunState| Err::<Value, String>("oops".to_string()), RunOpts::default()).unwrap();
    assert_eq!(plain.path, ["work", "plain"]);
    assert_eq!(plain.steps[0].error_type.as_deref(), Some("Error"));
    let borrowed = run(&parse(KINDS), |_: &str, _: &str, _: &RunState| Err::<Value, &str>("oops"), RunOpts::default()).unwrap();
    assert_eq!(borrowed.path, ["work", "plain"]);
}

#[test]
fn a_worker_error_no_edge_handles_propagates_with_its_kind_and_message() {
    let flow = "## work\n-> timed_out: on error when error_type == \"TimeoutError\"\n-> done: when ok\n## timed_out\nT.\n## done\nD.\n";
    let refused = run(&parse(flow), |_: &str, _: &str, _: &RunState| Err::<Value, _>(WorkerError::new("ValueError", "bad")), RunOpts::default());
    let Err(EngineError::Worker(error)) = &refused else { panic!("{refused:?}") };
    assert_eq!((error.kind.as_str(), error.message.as_str()), ("ValueError", "bad"));
    assert_eq!(refused.unwrap_err().reference_exception(), Some(("ValueError".to_string(), "bad".to_string())));
    let none = run(&parse("## work\n-> done: when ok\n## done\nD.\n"), |_: &str, _: &str, _: &RunState| Err::<Value, String>("x".into()), RunOpts::default());
    assert!(matches!(none, Err(EngineError::Worker(ref error)) if error.kind == "Error"));
}

#[test]
fn a_route_into_an_undefined_node_is_missing_node_which_the_reference_raises_as_a_key_error() {
    let ghost = "## work\n-> ghost: always\n## done\nDone.\n";
    let refused = run(&parse(ghost), |_: &str, _: &str, _: &RunState| Ok::<_, String>(Value::Null), RunOpts::default()).unwrap_err();
    assert!(matches!(&refused, EngineError::MissingNode(name) if name == "ghost"), "{refused:?}");
    assert_eq!(refused.reference_exception(), Some(("KeyError".to_string(), "'ghost'".to_string())));
    // a name with a quote in it is told as Python's repr tells it
    let quoted = EngineError::MissingNode("it's \"x\"".to_string());
    assert_eq!(quoted.reference_exception().unwrap().1, r#"'it\'s "x"'"#);
    // the start counts too, and a run that spends its last step on the route stops first, with the node in its path
    let start = run(&parse("## a\n-> b: always\n## b\nDone.\n"), |_: &str, _: &str, _: &RunState| Ok::<_, String>(Value::Null), RunOpts { start: Some("nowhere".into()), ..Default::default() });
    assert!(matches!(start, Err(EngineError::MissingNode(ref name)) if name == "nowhere"));
    let last = run(&parse(ghost), |_: &str, _: &str, _: &RunState| Ok::<_, String>(Value::Null), RunOpts { max_steps: 1, ..Default::default() }).unwrap();
    assert_eq!((last.stopped.as_str(), last.path.as_slice()), ("max_steps", &["work".to_string(), "ghost".to_string()][..]));
}

const GUARDED: &str = "---\nname: guarded\nstart: work\n---\n## work\nWork.\n-> handled: on error when len(error_message) > 3\n-> fallback: on error\n-> done: when ok\n## handled\nH.\n## fallback\nF.\n## done\nD.\n";

#[test]
fn an_error_guard_that_cannot_be_evaluated_is_recorded_and_the_step_counts_it() {
    let graph = parse(GUARDED);
    let result = run(&graph, |_: &str, _: &str, _: &RunState| Err::<Value, _>("boom"), RunOpts::default()).unwrap();
    assert_eq!(result.path, ["work", "fallback"]);
    assert_eq!(result.state.guard_errors.len(), 1);
    let entry = result.state.guard_errors[0].to_json();
    assert_eq!((entry["node"].as_str(), entry["guard"].as_str()), (Some("work"), Some("when len(error_message) > 3")));
    assert!(!entry["error"].as_str().unwrap().is_empty());
    assert_eq!(result.steps[0].guard_errors, Some(1));
    // it is in the state a checkpoint persists, and a state that brings records keeps them and counts them
    assert_eq!(prismpath_rs::durable::state_to_json(&result.state)["_guard_errors"][0]["node"], "work");
    let earlier = json!({"visits": {}, "transcript": [], "_guard_errors": [
        {"node": "work", "guard": "g", "error": "e"}, {"node": "other", "guard": "g", "error": "e"}]});
    let resumed = run(
        &graph,
        |_: &str, _: &str, _: &RunState| Err::<Value, _>("boom"),
        RunOpts { state: Some(Value::try_from_json(&earlier).unwrap()), ..Default::default() },
    )
    .unwrap();
    assert_eq!(resumed.state.guard_errors.len(), 3);
    assert_eq!(resumed.steps[0].guard_errors, Some(2));
    // a guard that evaluates leaves nothing, in the state or the step
    let clean = run(&parse(&GUARDED.replace("len(error_message) > 3", "error_count >= 2")), |_: &str, _: &str, _: &RunState| Err::<Value, _>("boom"), RunOpts::default()).unwrap();
    assert!(clean.state.guard_errors.is_empty() && clean.steps[0].guard_errors.is_none());
    assert!(prismpath_rs::durable::state_to_json(&clean.state).get("_guard_errors").is_none());
}
