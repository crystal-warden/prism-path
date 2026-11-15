// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The parser's input bounds against `tests/fixtures/parse_limits.json`, generated from the Python reference
//! (`prismpath/portable/gen_parse_limits_fixtures.py`): a document at each cap and one over it, where the
//! reference counts (characters, distinct names, edge lines under a heading), which cap a document reaches
//! first, documents built to the default caps, and the integers an environment variable may hold.
//! With `PRISMPATH_PYTHON` set a seeded sample of random documents under random caps is also parsed by a live
//! Python and compared.
//!
//! The refusals are what the reference raises as `ParseError`: here the graph comes back empty with
//! `parse_error` set, the engine and the codec refuse it, and `parse_checked` returns the message. A hostile
//! document never panics.

use prismpath_rs::{parse, parse_checked, parse_with_limits, run, EngineError, Limits, RunOpts, RunState, Value};
use serde_json::{json, Value as Json};
use std::process::{Command, Stdio};

fn corpus() -> Json {
    let text = std::fs::read_to_string("tests/fixtures/parse_limits.json").expect("read parse_limits.json");
    serde_json::from_str(&text).expect("parse parse_limits.json")
}

fn limits_of(json: &Json) -> Limits {
    Limits {
        max_flow_bytes: json["max_flow_bytes"].as_i64().unwrap(),
        max_nodes: json["max_nodes"].as_i64().unwrap(),
        max_edges: json["max_edges"].as_i64().unwrap(),
    }
}

/// What a parse gave, in the corpus' words: the nodes in document order with their edge counts, or the message.
fn outcome(text: &str, limits: &Limits) -> Json {
    let graph = parse_with_limits(text, limits);
    match graph.parse_error {
        Some(message) => json!({"error": message, "error_class": "ParseError"}),
        None => {
            let nodes: Vec<Json> = graph.order.iter().map(|name| json!([name, graph.nodes[name].edges.len()])).collect();
            json!({"ok": true, "start": graph.start, "nodes": nodes})
        }
    }
}

/// The document a `defaults` rule stands for (the generator's `build`).
fn build(kind: &str, count: usize) -> String {
    match kind {
        "nodes" => (0..count).map(|index| format!("## n{index}\n")).collect(),
        "edges" => format!("## a\n{}", "-> a: x\n".repeat(count)),
        "characters" => format!("## a\n{}", "x".repeat(count - 5)),
        other => panic!("unknown rule {other}"),
    }
}

#[test]
fn every_case_gives_the_reference_outcome() {
    let corpus = corpus();
    let cases = corpus["cases"].as_array().unwrap();
    assert!(cases.len() >= 45);
    let mut bad = Vec::new();
    for case in cases {
        let got = outcome(case["flow"].as_str().unwrap(), &limits_of(&case["limits"]));
        if got != case["expect"] {
            bad.push(format!("{}: want {} got {got}", case["name"], case["expect"]));
        }
    }
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}

#[test]
fn a_document_at_each_default_cap_parses_and_one_over_is_refused() {
    let corpus = corpus();
    assert_eq!(Limits::default(), limits_of(&corpus["defaults"][0]["limits"]), "the default caps are the reference's");
    let environment_overrides = ["PRISMPATH_MAX_FLOW_BYTES", "PRISMPATH_MAX_NODES", "PRISMPATH_MAX_EDGES"].iter().any(|name| std::env::var(name).is_ok());
    for case in corpus["defaults"].as_array().unwrap() {
        let text = build(case["kind"].as_str().unwrap(), case["count"].as_u64().unwrap() as usize);
        let limits = limits_of(&case["limits"]);
        let graph = parse_with_limits(&text, &limits);
        let want = &case["expect"];
        match want.get("error") {
            Some(message) => assert_eq!(graph.parse_error.as_deref(), message.as_str(), "{}", case["name"]),
            None => {
                assert!(graph.parse_error.is_none(), "{}: {:?}", case["name"], graph.parse_error);
                assert_eq!(graph.nodes.len() as u64, want["node_count"].as_u64().unwrap(), "{}", case["name"]);
                let edges: usize = graph.nodes.values().map(|node| node.edges.len()).sum();
                assert_eq!(edges as u64, want["edge_count"].as_u64().unwrap(), "{}", case["name"]);
            }
        }
        // `parse` itself, which reads the bounds from the environment, agrees when nothing overrides them
        if !environment_overrides {
            assert_eq!(parse(&text).parse_error, graph.parse_error, "{}", case["name"]);
        }
    }
}

#[test]
fn the_environment_is_read_as_python_int_reads_it() {
    for entry in corpus()["env"].as_array().unwrap() {
        let raw = entry["raw"].as_str().unwrap();
        let got = Limits::read_value("PRISMPATH_MAX_NODES", raw);
        match entry.get("value") {
            Some(value) => assert_eq!(got, Ok(value.as_i64().unwrap()), "{raw:?}"),
            None => assert!(got.is_err(), "{raw:?} is not an integer but was read as {got:?}"),
        }
    }
    // what Python reads and this crate refuses, said in the message
    assert!(Limits::read_value("PRISMPATH_MAX_NODES", "\u{663}").unwrap_err().contains("PRISMPATH_MAX_NODES is not an integer"));
    assert!(Limits::read_value("PRISMPATH_MAX_EDGES", "9223372036854775808").unwrap_err().contains("beyond a 64 bit integer"));
    assert!(Limits::read_value("PRISMPATH_MAX_EDGES", "99999999999999999999999999").is_err());
}

#[test]
fn a_document_over_a_cap_is_refused_by_the_engine_and_by_parse_checked_and_never_panics() {
    let limits = Limits { max_flow_bytes: 40, max_nodes: 2, max_edges: 2 };
    for text in ["## a\n## b\n## c\n", "## a\n-> a: x\n-> a: y\n-> a: z\n", &"x".repeat(41)] {
        let graph = parse_with_limits(text, &limits);
        assert!(graph.nodes.is_empty() && graph.order.is_empty() && graph.start.is_empty());
        let reason = graph.refusal().expect("a refused graph says why").to_string();
        assert!(reason.starts_with("flow document exceeds PRISMPATH_MAX_"), "{reason}");
        let refused = run(&graph, |_: &str, _: &str, _: &RunState| Ok::<_, String>(Value::Null), RunOpts::default());
        assert!(matches!(&refused, Err(EngineError::InvalidFlow(message)) if *message == reason), "{refused:?}");
    }
    // a big document is refused before any work
    let huge = "## a\n".repeat(1_000_000);
    assert!(parse(&huge).refusal().is_some_and(|reason| reason.contains("PRISMPATH_MAX_FLOW_BYTES")));
    assert_eq!(parse_checked(&"y".repeat(3 * 1024 * 1024)).unwrap_err(), "flow document exceeds PRISMPATH_MAX_FLOW_BYTES (2097152 bytes)");
    assert!(parse_checked("## a\n-> b: x\n## b\nDone.\n").is_ok());
}

// ------------------------------------------------------------------- the live Python, a seeded sample

const ORACLE: &str = r#"
import json, sys, warnings
warnings.simplefilter("ignore")
from prismpath.kernel import parser
cases = json.load(sys.stdin)
out = []
for case in cases:
    limits = case["limits"]
    parser.MAX_FLOW_BYTES, parser.MAX_NODES, parser.MAX_EDGES = limits["max_flow_bytes"], limits["max_nodes"], limits["max_edges"]
    try:
        graph = parser.parse(case["flow"])
        out.append({"ok": True, "start": graph.start, "nodes": [[name, len(node.edges)] for name, node in graph.nodes.items()]})
    except parser.ParseError as error:
        out.append({"error": str(error), "error_class": "ParseError"})
json.dump(out, sys.stdout)
"#;

const LINES: [&str; 14] = [
    "## a", "## b", "## C D", "## c_d", "-> a: x", "- -> b: y", "  -> c: when ok", "text", "@n(x)", "", "##", "---", "-> b", "##  ",
];

fn sample(count: usize) -> Vec<Json> {
    let mut state: u64 = 0x2026_1109_5a5a_5a5a;
    let mut next = move |bound: u64| {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (state >> 33) % bound
    };
    (0..count)
        .map(|_| {
            let lines: Vec<&str> = (0..next(24)).map(|_| LINES[next(LINES.len() as u64) as usize]).collect();
            let mut flow = lines.join("\n");
            if next(5) == 0 {
                flow = format!("---\nname: f\nstart: a\n---\n{flow}");
            }
            if next(7) == 0 {
                flow.push_str("\u{e9}\u{1f600}");
            }
            let size = if next(3) == 0 { next(flow.chars().count() as u64 + 4) as i64 - 1 } else { 10_000 };
            json!({"flow": flow, "limits": {"max_flow_bytes": size, "max_nodes": next(7) as i64 - 1, "max_edges": next(9) as i64 - 1}})
        })
        .collect()
}

#[test]
fn a_live_python_parses_a_random_sample_under_random_caps_as_this_crate_does() {
    let python = match std::env::var("PRISMPATH_PYTHON") {
        Ok(path) => path,
        Err(_) => {
            assert!(std::env::var("PRISMPATH_REQUIRE_CROSS_LANGUAGE").is_err(), "PRISMPATH_REQUIRE_CROSS_LANGUAGE is set but PRISMPATH_PYTHON is not");
            eprintln!("SKIP: PRISMPATH_PYTHON not set; the corpus checks above still ran");
            return;
        }
    };
    let cases = sample(1500);
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
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
        child.stdin.take().unwrap().write_all(Json::Array(cases.clone()).to_string().as_bytes()).unwrap();
    }
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let theirs: Vec<Json> = serde_json::from_slice(&output.stdout).expect("oracle output");
    assert_eq!(theirs.len(), cases.len());
    let (mut refused, mut parsed) = (0, 0);
    for (case, python) in cases.iter().zip(&theirs) {
        let got = outcome(case["flow"].as_str().unwrap(), &limits_of(&case["limits"]));
        assert_eq!(&got, python, "flow {:?} under {}", case["flow"], case["limits"]);
        if python.get("error").is_some() {
            refused += 1;
        } else {
            parsed += 1;
        }
    }
    println!("parse limits cross language: {} documents, {parsed} parsed, {refused} refused, no mismatch", cases.len());
    assert!(parsed > 100 && refused > 100, "the sample reaches both outcomes");
}
