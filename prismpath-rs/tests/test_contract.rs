// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The worker output contract against `tests/fixtures/contract.json`, generated from the Python reference
//! (`prismpath/portable/gen_contract_fixtures.py`): every flow's derived contract, JSON Schema and text,
//! and every worker output's problems, in order. With `PRISMPATH_PYTHON` set the same flows are also
//! derived by a live Python and compared.
//!
//! The refusals Python does not have are tested here too: an integer past 2^53 minus 1 or a float past
//! the double range that would become a routed value is a `ContractError`, and a hostile predicate is
//! skipped without a panic or a stack overflow.

use prismpath_rs::contract::{derive_contract, describe, node_contract_to_json, to_json_schema, validate_output, MAX_NEST};
use prismpath_rs::{parse, Value};
use serde_json::{json, Value as Json};
use std::process::Command;

fn corpus() -> Json {
    let text = std::fs::read_to_string("tests/fixtures/contract.json").expect("read contract.json");
    serde_json::from_str(&text).expect("parse contract.json")
}

/// Equality where a number is told apart by its written form (an integer from a float) and compared by value.
fn same(left: &Json, right: &Json) -> bool {
    match (left, right) {
        (Json::Number(a), Json::Number(b)) => {
            let is_float = |n: &serde_json::Number| n.to_string().contains(['.', 'e', 'E']);
            is_float(a) == is_float(b) && a.to_string().parse::<f64>().ok() == b.to_string().parse::<f64>().ok()
        }
        (Json::Array(a), Json::Array(b)) => a.len() == b.len() && a.iter().zip(b).all(|(x, y)| same(x, y)),
        (Json::Object(a), Json::Object(b)) => a.len() == b.len() && a.iter().all(|(key, x)| b.get(key).is_some_and(|y| same(x, y))),
        _ => left == right,
    }
}

fn pairs_json(contract: &prismpath_rs::contract::Contract) -> Json {
    let mut out = serde_json::Map::new();
    for (name, node_contract) in contract.nodes() {
        let listed: Vec<Json> = node_contract.iter().map(|(field, spec)| json!([field, spec.to_json()])).collect();
        out.insert(name.clone(), Json::Array(listed));
    }
    Json::Object(out)
}

#[test]
fn every_derived_contract_schema_and_description_is_pythons() {
    let doc = corpus();
    for case in doc["derive"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let graph = parse(case["flow"].as_str().unwrap());
        let contract = derive_contract(&graph).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert!(same(&pairs_json(&contract), &case["contract"]), "{name}: contract\n got {}\nwant {}", pairs_json(&contract), case["contract"]);
        let mut schemas = serde_json::Map::new();
        for (node, node_contract) in contract.nodes() {
            schemas.insert(node.clone(), to_json_schema(node_contract));
        }
        assert!(same(&Json::Object(schemas.clone()), &case["schemas"]), "{name}: schemas\n got {}\nwant {}", Json::Object(schemas), case["schemas"]);
        assert_eq!(describe(&contract), case["describe"].as_str().unwrap(), "{name}: describe");
    }
}

#[test]
fn every_problem_validate_output_finds_is_pythons_in_order() {
    let doc = corpus();
    for case in doc["validate"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let graph = parse(case["flow"].as_str().unwrap());
        let contract = derive_contract(&graph).unwrap();
        let node = case["node"].as_str().unwrap();
        let fields = match Value::try_from_json(&case["fields"]).unwrap() {
            Value::Obj(entries) => entries,
            other => panic!("{name}: fields is {other:?}"),
        };
        let got = validate_output(contract.get(node).map(Vec::as_slice).unwrap_or(&[]), &fields);
        let want: Vec<String> = case["problems"].as_array().unwrap().iter().map(|item| item.as_str().unwrap().to_string()).collect();
        assert_eq!(got, want, "{name}");
    }
}

#[test]
fn the_corpus_covers_what_the_contract_reads() {
    let doc = corpus();
    let names: Vec<&str> = doc["derive"].as_array().unwrap().iter().map(|case| case["name"].as_str().unwrap()).collect();
    assert!(names.len() >= 50, "{} derive cases", names.len());
    let problems: Vec<&str> =
        doc["validate"].as_array().unwrap().iter().flat_map(|case| case["problems"].as_array().unwrap()).map(|item| item.as_str().unwrap()).collect();
    for kind in ["type:", "missing:", "note:"] {
        assert!(problems.iter().any(|problem| problem.starts_with(kind)), "no {kind} problem in the corpus");
    }
}

fn flow_with(edge: &str) -> String {
    format!("---\nname: h\nstart: n\n---\n## n\nGo.\n-> t: {edge}\n## t\nDone.\n")
}

#[test]
fn a_routed_literal_that_cannot_be_held_exactly_is_refused_not_rounded() {
    for edge in [
        "when x == 9007199254740993",
        "when x in [1, 99999999999999999999999999]",
        "when x == 1e999",
        "when x == 0x20000000000001",
    ] {
        let graph = parse(&flow_with(edge));
        assert!(derive_contract(&graph).is_err(), "{edge}");
    }
    // beyond the range but only ordered against, nothing is routed and nothing is refused
    let ordered = derive_contract(&parse(&flow_with("when x > 99999999999999999999999999 or y < 1e999"))).unwrap();
    assert_eq!(ordered.to_json(), json!({"n": {"x": {"type": "number"}, "y": {"type": "number"}}, "t": {}}));
    // 2^53 minus 1 itself is held exactly
    let edge = derive_contract(&parse(&flow_with("when x == 9007199254740991"))).unwrap();
    assert_eq!(edge.to_json()["n"]["x"]["values"], json!([9007199254740991i64]));
}

#[test]
fn hostile_predicates_are_skipped_and_never_panic() {
    let nest = MAX_NEST + 40;
    let hostile = [
        "(".repeat(5000),
        format!("{}x{}", "(".repeat(nest), ")".repeat(nest)),
        format!("{}x", "not ".repeat(nest * 2)),
        format!("{}x", "- ".repeat(nest * 2)),
        format!("x{}", " + 1".repeat(20000)),
        format!("f({})", "a, ".repeat(20000)),
        "'unterminated".to_string(),
        "\"\"\"unterminated triple".to_string(),
        "x == \"\\N{DIGIT ONE}\"".to_string(),
        "x == \"\\ud800\"".to_string(),
        "x == \"\\U00110000\"".to_string(),
        "x[".to_string(),
        "x[]".to_string(),
        "x[1:2:3:4]".to_string(),
        "lambda".to_string(),
        "lambda x".to_string(),
        "1 if".to_string(),
        "x.1".to_string(),
        "x == 0x".to_string(),
        "x == 1_".to_string(),
        "x == 1__0".to_string(),
        "\u{0}".to_string(),
        "x \u{a0}== 1".to_string(),
        "\\".to_string(),
        "$".to_string(),
        "x == [for]".to_string(),
        "x == (for".to_string(),
        "{".to_string(),
        "{1:".to_string(),
        "x := 1".to_string(),
        "".to_string(),
    ];
    for edge in hostile {
        let graph = parse(&flow_with(&format!("when {edge} or ok")));
        let derived = derive_contract(&graph).unwrap_or_else(|error| panic!("{:?}: {error}", &edge[..edge.len().min(40)]));
        // whatever else is skipped, nothing panicked and the derived JSON is well formed
        let _ = node_contract_to_json(derived.get("n").unwrap());
    }
    // within the bound the same shapes are read
    let shallow = derive_contract(&parse(&flow_with(&format!("when {}x{}", "(".repeat(MAX_NEST - 20), ")".repeat(MAX_NEST - 20))))).unwrap();
    assert_eq!(shallow.to_json()["n"], json!({"x": {"type": "boolean"}}));
    let deep = derive_contract(&parse(&flow_with(&format!("when {}x{}", "(".repeat(MAX_NEST + 40), ")".repeat(MAX_NEST + 40))))).unwrap();
    assert_eq!(deep.to_json()["n"], json!({}), "past the nesting bound the predicate is skipped");
}

#[test]
fn derivation_agrees_with_a_live_python_on_every_corpus_flow() {
    let python = match std::env::var("PRISMPATH_PYTHON") {
        Ok(path) => path,
        Err(_) => {
            assert!(
                std::env::var("PRISMPATH_REQUIRE_CROSS_LANGUAGE").is_err(),
                "PRISMPATH_REQUIRE_CROSS_LANGUAGE is set but PRISMPATH_PYTHON is not"
            );
            eprintln!("SKIP: PRISMPATH_PYTHON not set; the frozen corpus checks above still ran");
            return;
        }
    };
    let doc = corpus();
    let flows: Vec<Json> = doc["derive"].as_array().unwrap().iter().map(|case| case["flow"].clone()).collect();
    let script = "import json, sys, warnings\nwarnings.simplefilter('ignore')\nfrom prismpath.kernel import contract\nfrom prismpath.kernel.parser import parse\n\
        out = []\nfor flow in json.load(sys.stdin):\n    derived = contract.derive_contract(parse(flow))\n    out.append({n: [[f, s] for f, s in fields.items()] for n, fields in derived.items()})\nprint(json.dumps(out))";
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut child = Command::new(python)
        .args(["-c", script])
        .env("PYTHONPATH", repo_root)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("run python");
    {
        use std::io::Write;
        child.stdin.take().unwrap().write_all(serde_json::to_string(&flows).unwrap().as_bytes()).unwrap();
    }
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let live: Json = serde_json::from_slice(&output.stdout).unwrap();
    for (flow, python_contract) in flows.iter().zip(live.as_array().unwrap()) {
        let contract = derive_contract(&parse(flow.as_str().unwrap())).unwrap();
        assert!(same(&pairs_json(&contract), python_contract), "flow {flow}\n rust {}\n python {python_contract}", pairs_json(&contract));
    }
}
