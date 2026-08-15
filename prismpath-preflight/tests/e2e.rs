//! The same contract the Python reference tool's tests pin, exercised against the compiled
//! binary — plus the one place the Rust value model differs (string-to-0 coercion), which this
//! tool must surface precisely BECAUSE the reference errors there instead.

use std::path::PathBuf;
use std::process::{Command, Output};

const FLOW: &str = "---
name: preflight_guard
start: classify
---
## classify
-> critical: when temp >= 90 and armed
-> warn: when temp >= 50
-> ok: else
## critical
## warn
## ok
";

fn setup(name: &str, events: &[&str]) -> (PathBuf, PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("fpf_{}_{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let flow = dir.join("flow.md");
    std::fs::write(&flow, FLOW).unwrap();
    let sample = dir.join("sample.ndjson");
    std::fs::write(&sample, events.join("\n") + "\n").unwrap();
    (flow, sample, dir.join("report.json"))
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_prismpath-preflight")).args(args).output().unwrap()
}

fn report(path: &PathBuf) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn clean_sample_is_ready() {
    let (flow, sample, out) = setup("clean", &[
        r#"{"temp": 95, "armed": true}"#, r#"{"temp": 60, "armed": false}"#,
        r#"{"temp": 10, "armed": true}"#, r#"{"temp": 89, "armed": true}"#]);
    let r = run(&[flow.to_str().unwrap(), sample.to_str().unwrap(),
                  "--json", out.to_str().unwrap()]);
    assert_eq!(r.status.code(), Some(0), "{}", String::from_utf8_lossy(&r.stdout));
    let rep = report(&out);
    assert_eq!(rep["ready"], true);
    assert_eq!(rep["encoded"], 4);
    assert_eq!(rep["codebook"]["temp"]["cells"], 3);
    assert_eq!(rep["codebook"]["armed"]["kind"], "boolean");
    // one byte-aligned reading per frame, exactly as the Vector codec sends it
    assert_eq!(rep["framed_bytes_per_event"], 1.0);
}

#[test]
fn missing_field_error_vs_skip() {
    let (flow, sample, out) = setup("missing", &[
        r#"{"temp": 95, "armed": true}"#, r#"{"temp": 60}"#]);
    let r = run(&[flow.to_str().unwrap(), sample.to_str().unwrap()]);
    assert_eq!(r.status.code(), Some(1));           // on_missing=error, the codec default
    let r = run(&[flow.to_str().unwrap(), sample.to_str().unwrap(),
                  "--on-missing", "skip", "--json", out.to_str().unwrap()]);
    assert_eq!(r.status.code(), Some(0));           // skip is declared codec behavior
    let rep = report(&out);
    assert_eq!(rep["encoded"], 1);
    assert_eq!(rep["missing_by_field"]["armed"], 1);
}

#[test]
fn map_reaches_nested_fields() {
    let (flow, sample, out) = setup("map", &[
        r#"{"sensor": {"temp": 95}, "armed": true}"#,
        r#"{"sensor": {"temp": 20}, "armed": false}"#]);
    let r = run(&[flow.to_str().unwrap(), sample.to_str().unwrap()]);
    assert_eq!(r.status.code(), Some(1));           // temp never seen without the map
    let r = run(&[flow.to_str().unwrap(), sample.to_str().unwrap(),
                  "--map", "temp=sensor.temp", "--json", out.to_str().unwrap()]);
    assert_eq!(r.status.code(), Some(0));
    let rep = report(&out);
    assert_eq!(rep["encoded"], 2);
    assert_eq!(rep["fields_never_seen"].as_array().unwrap().len(), 0);
    assert_eq!(rep["route_distribution"]["classify"]["critical"], 1);
    assert_eq!(rep["route_distribution"]["classify"]["ok"], 1);
}

#[test]
fn string_coercion_to_zero_is_surfaced_and_blocks_ready() {
    // The Rust crates coerce an unparseable string on a numeric field to 0 (the Python
    // reference errors instead). The Rust preflight must therefore encode the event AND flag it.
    let (flow, sample, out) = setup("coerce", &[
        r#"{"temp": "not-a-number", "armed": true}"#, r#"{"temp": 50, "armed": false}"#]);
    let r = run(&[flow.to_str().unwrap(), sample.to_str().unwrap(),
                  "--json", out.to_str().unwrap()]);
    assert_eq!(r.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&r.stdout).contains("COERCED TO 0"));
    let rep = report(&out);
    assert_eq!(rep["encoded"], 2);                  // both encode: coercion is not an error here
    assert_eq!(rep["coerced_to_zero_by_field"]["temp"], 1);
    assert_eq!(rep["out_of_partition"].as_object().unwrap().len(), 0);
}

#[test]
fn float_truncation_counted_and_null_is_missing() {
    let (flow, sample, out) = setup("trunc", &[
        r#"{"temp": 49.9, "armed": true}"#,          // truncates to 49 -> ok, counted
        r#"{"temp": null, "armed": true}"#]);        // JSON null = missing, as in the codec
    let r = run(&[flow.to_str().unwrap(), sample.to_str().unwrap(),
                  "--on-missing", "skip", "--json", out.to_str().unwrap()]);
    assert_eq!(r.status.code(), Some(0));
    let rep = report(&out);
    assert_eq!(rep["float_truncated_by_field"]["temp"], 1);
    assert_eq!(rep["missing_by_field"]["temp"], 1);
    assert_eq!(rep["route_distribution"]["classify"]["ok"], 1);
}

#[test]
fn no_decision_fields_flow_fails_loud() {
    let dir = std::env::temp_dir().join(format!("fpf_{}_nodec", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let flow = dir.join("flow.md");
    std::fs::write(&flow, "---\nname: f\nstart: a\n---\n## a\n-> b: always\n## b\n").unwrap();
    let sample = dir.join("sample.ndjson");
    std::fs::write(&sample, "{\"x\": 1}\n").unwrap();
    let r = run(&[flow.to_str().unwrap(), sample.to_str().unwrap()]);
    assert_eq!(r.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&r.stdout).contains("no decision-relevant fields"));
}

#[test]
fn bad_usage_exits_two() {
    let r = run(&["only-one-arg"]);
    assert_eq!(r.status.code(), Some(2));
}
