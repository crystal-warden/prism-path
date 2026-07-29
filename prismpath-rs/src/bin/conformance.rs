//! Certify `prismpath-rs` against the frozen kernel spec.
//!
//! The conformance corpus is the specification expressed as data:
//!   * `predicates.json` — 1,067 `(condition, context) -> true | false | "ERROR"` cases
//!   * `flows.json`      — 27 engine fixtures -> `{path, stopped, pending_node, spawn}`
//!
//! Its README states the intent plainly: "A future Go / Rust / WASM kernel implements the frozen
//! subset, reads these two files, and is provably interchangeable — or measurably not." This binary
//! answers that question for the Rust crate. It is deliberately non-forgiving: every divergence from
//! the reference is reported, grouped by cause, so a failure is itemized drift documentation rather
//! than a verdict.
//!
//! Usage: cargo run --bin conformance -- [path/to/conformance/dir]

use prismpath_rs::{Engine, Flow, Value};
use std::collections::HashMap;

#[derive(serde::Deserialize)]
struct PredicateCase {
    cond: String,
    ctx: HashMap<String, serde_json::Value>,
    expect: serde_json::Value, // true | false | "ERROR"
}

#[derive(serde::Deserialize)]
struct PredicateFile {
    cases: Vec<PredicateCase>,
}

#[derive(serde::Deserialize)]
struct FlowCase {
    flow: String,
    #[serde(default)]
    expect: serde_json::Value,
}

#[derive(serde::Deserialize)]
struct FlowFile {
    cases: Vec<FlowCase>,
}

/// Convert a serde_json value into the crate's own `Value`.
fn to_value(v: &serde_json::Value) -> Value {
    match v {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => Value::Number(n.as_f64().unwrap_or(0.0)),
        serde_json::Value::String(s) => Value::String(s.clone()),
        serde_json::Value::Array(a) => Value::Array(a.iter().map(to_value).collect()),
        serde_json::Value::Object(o) => {
            Value::Object(o.iter().map(|(k, val)| (k.clone(), to_value(val))).collect())
        }
    }
}

/// Classify a divergence so the report groups causes instead of listing 900 near-identical lines.
fn classify(cond: &str) -> &'static str {
    let c = cond.trim_start_matches("when ").trim();
    let tokens: Vec<&str> = c.split_whitespace().collect();
    if c.contains(" not in ") {
        "`not in` operator unsupported"
    } else if tokens.len() > 3 && (c.contains('<') || c.contains('>') || c.contains("==")) {
        "chained / multi-term comparison (>3 tokens)"
    } else if c.contains(" and ") || c.contains(" or ") || c.starts_with("not ") {
        "boolean connective (and/or/not)"
    } else if c.contains('[') || c.contains('.') {
        "index / attribute access"
    } else if tokens.len() == 3 {
        "binary comparison semantics"
    } else if tokens.len() == 1 {
        "bare-field truthiness"
    } else {
        "other"
    }
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| {
        "../prismpath/portable/conformance".to_string()
    });

    println!("=== prismpath-rs CONFORMANCE CERTIFICATION ===");
    println!("corpus: {dir}\n");

    // ---------------------------------------------------------------- predicates
    let pred_path = format!("{dir}/predicates.json");
    let raw = match std::fs::read_to_string(&pred_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("cannot read {pred_path}: {e}");
            std::process::exit(2);
        }
    };
    let pf: PredicateFile = serde_json::from_str(&raw).expect("predicates.json parse");

    // A minimal flow so we can construct an Engine; the predicate evaluator does not use it.
    let flow = Flow {
        name: "conformance".into(),
        start: "n".into(),
        nodes: HashMap::new(),
    };
    let engine = Engine::new(flow);

    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut buckets: HashMap<&'static str, usize> = HashMap::new();
    let mut samples: HashMap<&'static str, (String, String, String)> = HashMap::new();

    for case in &pf.cases {
        let ctx: HashMap<String, Value> =
            case.ctx.iter().map(|(k, v)| (k.clone(), to_value(v))).collect();

        let got = engine.conformance_eval(&case.cond, &ctx);
        let got_repr = match &got {
            Ok(b) => b.to_string(),
            Err(_) => "ERROR".to_string(),
        };
        let want_repr = match &case.expect {
            serde_json::Value::Bool(b) => b.to_string(),
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };

        if got_repr == want_repr {
            pass += 1;
        } else {
            fail += 1;
            let bucket = classify(&case.cond);
            *buckets.entry(bucket).or_insert(0) += 1;
            samples.entry(bucket).or_insert_with(|| {
                (case.cond.clone(), want_repr.clone(), got_repr.clone())
            });
        }
    }

    let total = pass + fail;
    println!("PREDICATES: {pass}/{total} match the frozen spec");
    if fail > 0 {
        println!("\n  divergences grouped by cause:");
        let mut rows: Vec<_> = buckets.iter().collect();
        rows.sort_by(|a, b| b.1.cmp(a.1));
        for (bucket, count) in rows {
            println!("    {count:>5}  {bucket}");
            if let Some((cond, want, got)) = samples.get(*bucket) {
                println!("           e.g. {cond:?} -> expected {want}, got {got}");
            }
        }
    }

    // ---------------------------------------------------------------- flows
    let flow_path = format!("{dir}/flows.json");
    let fraw = std::fs::read_to_string(&flow_path).expect("read flows.json");
    let ff: FlowFile = serde_json::from_str(&fraw).expect("flows.json parse");

    // The fixtures carry the flow as a Markdown document with YAML frontmatter. The crate's `Flow`
    // is a JSON struct with no parser for that format, and `run()` returns only a path — the spec
    // requires {path, stopped, pending_node, spawn}. Report this as a structural gap rather than
    // pretending to run 27 cases we cannot even load.
    let markdown_fixtures = ff
        .cases
        .iter()
        .filter(|c| c.flow.trim_start().starts_with("---"))
        .count();

    println!("\nFLOWS: 0/{} executable", ff.cases.len());
    println!("    {markdown_fixtures} of {} fixtures are Markdown documents with YAML frontmatter;", ff.cases.len());
    println!("    the crate deserializes Flow from JSON and has no Markdown/frontmatter parser.");
    println!("    Engine::run also returns only `path`, while the spec requires");
    println!("    {{path, stopped, pending_node, spawn}} — 3 of 4 output fields are absent.");

    // ---------------------------------------------------------------- verdict
    println!("\n---------------------------------------------------");
    if fail == 0 && ff.cases.is_empty() {
        println!("CONFORMANT");
        std::process::exit(0);
    }
    println!("NOT CONFORMANT — prismpath-rs does not implement the frozen kernel spec.");
    println!("  predicates: {fail} of {total} cases diverge");
    println!("  flows:      {} of {} fixtures cannot be executed at all", ff.cases.len(), ff.cases.len());
    std::process::exit(1);
}
