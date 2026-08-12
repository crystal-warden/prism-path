//! Certify `prismpath-rs` against the frozen kernel spec.
//!
//! The conformance corpus is the specification expressed as data:
//!   * `predicates.json` — 1,079 `(condition, context) -> true | false | "ERROR"` cases
//!   * `flows.json`      — 27 engine fixtures -> `{path, stopped, pending_node, spawn}`
//!
//! Its README states the intent plainly: "A future Go / Rust / WASM kernel implements the frozen
//! subset, reads these two files, and is provably interchangeable — or measurably not." This binary
//! answers that question for the Rust crate, replaying exactly what `run_vectors.mjs` replays. On
//! failure every divergence is reported, grouped by cause — itemized drift documentation rather
//! than a verdict.
//!
//! Usage: cargo run --bin conformance -- [path/to/conformance/dir]

use prismpath_rs::{eval_condition, parse, run, run_locked, Lock, RunOpts, RunState, V};
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

/// Classify a divergence so the report groups causes instead of listing hundreds of lines.
fn classify(cond: &str) -> &'static str {
    let c = cond.trim_start_matches("when ").trim();
    let tokens: Vec<&str> = c.split_whitespace().collect();
    if c.contains(" not in ") {
        "`not in` semantics"
    } else if tokens.len() > 3 && (c.contains('<') || c.contains('>') || c.contains("==")) {
        "chained / multi-term comparison"
    } else if c.contains(" and ") || c.contains(" or ") || c.starts_with("not ") {
        "boolean connective (and/or/not)"
    } else if c.contains('[') || c.contains('(') {
        "collection literal / grouping"
    } else if tokens.len() == 3 {
        "binary comparison semantics"
    } else if tokens.len() == 1 {
        "bare-field truthiness"
    } else {
        "other"
    }
}

/// The scripted agent from `run_vectors.mjs`: outcomes are consumed in visit order, the last one
/// repeats, an unscripted node answers `{text: node}`, and `{"__raise__": msg}` throws.
fn scripted_agent(
    script: &HashMap<String, Vec<serde_json::Value>>,
) -> impl FnMut(&str, &str, &RunState) -> Result<V, String> + '_ {
    let mut used: HashMap<String, usize> = HashMap::new();
    move |node: &str, _instruction: &str, _state: &RunState| {
        let Some(seq) = script.get(node) else {
            return Ok(V::Obj(vec![("text".to_string(), V::Str(node.to_string()))]));
        };
        let i = *used.get(node).unwrap_or(&0);
        used.insert(node.to_string(), i + 1);
        let outcome = &seq[i.min(seq.len().saturating_sub(1))];
        if let serde_json::Value::Object(o) = outcome {
            if let Some(msg) = o.get("__raise__") {
                return Err(match msg {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                });
            }
        }
        Ok(V::from_json(outcome))
    }
}

fn main() {
    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "../prismpath/portable/conformance".to_string());

    println!("=== prismpath-rs CONFORMANCE CERTIFICATION ===");
    println!("corpus: {dir}\n");

    let mut failures = 0usize;

    // ---------------------------------------------------------------- predicates
    let raw = std::fs::read_to_string(format!("{dir}/predicates.json")).unwrap_or_else(|e| {
        eprintln!("cannot read predicates.json: {e}");
        std::process::exit(2);
    });
    let pf: PredicateFile = serde_json::from_str(&raw).expect("predicates.json parse");

    let mut pred_pass = 0usize;
    let mut buckets: HashMap<&'static str, usize> = HashMap::new();
    let mut samples: HashMap<&'static str, Vec<String>> = HashMap::new();

    for case in &pf.cases {
        let ctx: HashMap<String, V> =
            case.ctx.iter().map(|(k, v)| (k.clone(), V::from_json(v))).collect();

        let got = match eval_condition(&case.cond, &ctx) {
            Ok(b) => b.to_string(),
            Err(_) => "ERROR".to_string(),
        };
        let want = match &case.expect {
            serde_json::Value::Bool(b) => b.to_string(),
            serde_json::Value::String(s) => s.clone(),
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
        rows.sort_by(|a, b| b.1.cmp(a.1));
        for (bucket, count) in rows {
            println!("    {count:>5}  {bucket}");
            for s in &samples[*bucket] {
                println!("           {s}");
            }
        }
    }

    // ---------------------------------------------------------------- flows
    let fraw = std::fs::read_to_string(format!("{dir}/flows.json")).expect("read flows.json");
    let ff: FlowFile = serde_json::from_str(&fraw).expect("flows.json parse");

    let mut flow_pass = 0usize;
    for fx in &ff.cases {
        let graph = parse(&fx.flow);
        let opts = RunOpts {
            max_steps: fx.max_steps.unwrap_or(25),
            start: fx.start.clone(),
            state: fx.state.as_ref().map(V::from_json),
            ..Default::default()
        };
        let got = match run(&graph, scripted_agent(&fx.script), opts) {
            Ok(res) => serde_json::json!({
                "path": res.path,
                "stopped": res.stopped,
                "pending_node": res.pending.as_ref().map(|p| p.node.clone()),
                "spawn": res.pending.as_ref().and_then(|p| p.spawn.as_ref().map(v_to_json)),
            }),
            Err(e) => serde_json::json!({ "error": e.to_string() }),
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

    // ---------------------------------------------------------------- P1 locked flows
    let p1_path = format!("{dir}/locked_flows.json");
    if let Ok(p1_raw) = std::fs::read_to_string(&p1_path) {
        let p1f: P1FlowFile = serde_json::from_str(&p1_raw).expect("locked_flows.json parse");
        let mut p1_pass = 0usize;
        for fx in &p1f.cases {
            let graph = parse(&fx.flow);
            let lock = Lock::from_json(&fx.lock).unwrap_or_else(|e| {
                panic!("P1 fixture {:?}: lock parse error: {e}", fx.name);
            });

            let embed_map: HashMap<String, Vec<f32>> = fx
                .embed_map
                .iter()
                .map(|(k, v)| {
                    let b64 = v.as_str().expect("embedMap values must be base64 strings");
                    (k.clone(), prismpath_rs::decode_b64_f32(b64).expect("embedMap base64 decode"))
                })
                .collect();
            let dim = lock.dim;

            let opts = RunOpts {
                max_steps: fx.max_steps.unwrap_or(25),
                start: fx.start.clone(),
                state: fx.state.as_ref().map(V::from_json),
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
                    "pending_node": res.pending.as_ref().map(|p| p.node.clone()),
                    "would_pick": res.pending.as_ref().and_then(|p| p.would_pick.clone()),
                }),
                Err(e) => serde_json::json!({ "error": e.to_string() }),
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
        println!("\n(no locked_flows.json found — P1 conformance skipped)");
    }

    // ---------------------------------------------------------------- verdict
    println!("\n---------------------------------------------------");
    if failures == 0 {
        println!("CONFORMANT — prismpath-rs matches the frozen kernel spec.");
        std::process::exit(0);
    }
    println!("NOT CONFORMANT — {failures} divergence(s) from the frozen kernel spec.");
    std::process::exit(1);
}

fn v_to_json(v: &V) -> serde_json::Value {
    match v {
        V::Null => serde_json::Value::Null,
        V::Bool(b) => serde_json::Value::Bool(*b),
        // JSON.stringify(1.0) is "1": the contract's numbers are f64 rendered the JS way, so an
        // integral float must serialize as an integer or the comparison fails on notation alone.
        V::Num(n) if n.fract() == 0.0 && n.abs() < 9.2e18 => {
            serde_json::Value::Number(serde_json::Number::from(*n as i64))
        }
        V::Num(n) => serde_json::Number::from_f64(*n)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        V::Str(s) => serde_json::Value::String(s.clone()),
        V::List(a) => serde_json::Value::Array(a.iter().map(v_to_json).collect()),
        V::Obj(o) => serde_json::Value::Object(
            o.iter().map(|(k, x)| (k.clone(), v_to_json(x))).collect(),
        ),
        V::Ellipsis => serde_json::Value::Null,
    }
}
