//! The same contract the Python reference tool's tests pin, exercised against the compiled
//! binary, plus acceptance finding a string on a numeric field raises, which this
//! tool must surface precisely BECAUSE the reference errors there instead.

use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

/// A scratch directory removed when it goes out of scope, a failed assertion included, so a test run leaves
/// nothing in the temporary directory.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!("pp_preflight_{name}_{}_{}", std::process::id(), NEXT.fetch_add(1, Ordering::SeqCst)));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl std::ops::Deref for Scratch {
    type Target = std::path::Path;
    fn deref(&self) -> &std::path::Path {
        &self.0
    }
}

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

/// The flow, the sample and where the report goes, in a directory that lives as long as the first value.
fn setup(name: &str, events: &[&str]) -> (Scratch, PathBuf, PathBuf, PathBuf) {
    let dir = Scratch::new(name);
    let flow = dir.join("flow.md");
    std::fs::write(&flow, FLOW).unwrap();
    let sample = dir.join("sample.ndjson");
    std::fs::write(&sample, events.join("\n") + "\n").unwrap();
    let report = dir.join("report.json");
    (dir, flow, sample, report)
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_prismpath-preflight")).args(args).output().unwrap()
}

fn report(path: &PathBuf) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn clean_sample_is_ready() {
    let (_dir, flow, sample, out) = setup("clean", &[
        r#"{"temp": 95, "armed": true}"#, r#"{"temp": 60, "armed": false}"#,
        r#"{"temp": 10, "armed": true}"#, r#"{"temp": 89, "armed": true}"#]);
    let result = run(&[flow.to_str().unwrap(), sample.to_str().unwrap(),
                  "--json", out.to_str().unwrap()]);
    assert_eq!(result.status.code(), Some(0), "{}", String::from_utf8_lossy(&result.stdout));
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
    let (_dir, flow, sample, out) = setup("missing", &[
        r#"{"temp": 95, "armed": true}"#, r#"{"temp": 60}"#]);
    let result = run(&[flow.to_str().unwrap(), sample.to_str().unwrap()]);
    assert_eq!(result.status.code(), Some(1));           // on_missing=error, the codec default
    let result = run(&[flow.to_str().unwrap(), sample.to_str().unwrap(),
                  "--on-missing", "skip", "--json", out.to_str().unwrap()]);
    assert_eq!(result.status.code(), Some(0));           // skip is declared codec behavior
    let rep = report(&out);
    assert_eq!(rep["encoded"], 1);
    assert_eq!(rep["missing_by_field"]["armed"], 1);
}

#[test]
fn map_reaches_nested_fields() {
    let (_dir, flow, sample, out) = setup("map", &[
        r#"{"sensor": {"temp": 95}, "armed": true}"#,
        r#"{"sensor": {"temp": 20}, "armed": false}"#]);
    let result = run(&[flow.to_str().unwrap(), sample.to_str().unwrap()]);
    assert_eq!(result.status.code(), Some(1));           // temp never seen without the map
    let result = run(&[flow.to_str().unwrap(), sample.to_str().unwrap(),
                  "--map", "temp=sensor.temp", "--json", out.to_str().unwrap()]);
    assert_eq!(result.status.code(), Some(0));
    let rep = report(&out);
    assert_eq!(rep["encoded"], 2);
    assert_eq!(rep["fields_never_seen"].as_array().unwrap().len(), 0);
    assert_eq!(rep["route_distribution"]["classify"]["critical"], 1);
    assert_eq!(rep["route_distribution"]["classify"]["ok"], 1);
}

#[test]
fn acceptance_refusal_is_surfaced_and_blocks_ready() {
    // A string that is not an integer literal on a numeric field is refused by acceptance
    // and by the encoder alike, on both sides of the stack: the event is out of partition for the
    // permissive encoder and refused by the contract, and neither lets it become a zero reading.
    let (_dir, flow, sample, out) = setup("contract", &[
        r#"{"temp": 95, "armed": true}"#,
        r#"{"temp": "hot", "armed": true}"#,
    ]);
    let output = run(&[flow.to_str().unwrap(), sample.to_str().unwrap(), "--json", out.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1));
    let rep = report(&out);
    assert_eq!(rep["encoded"], 1);
    assert_eq!(rep["out_of_partition"]["temp"], 1);
    assert_eq!(rep["refused_by_field"]["temp"]["wrong_type"], 1);   // unparseable_string until corpus v2
    assert!(rep.get("coerced_to_zero_by_field").is_none());
    assert_eq!(rep["ready"], false);
}

#[test]
fn a_fraction_is_refused_not_truncated_and_null_is_missing() {
    let (_dir, flow, sample, out) = setup("trunc", &[
        r#"{"temp": 49.9, "armed": true}"#,          // refused as fractional, never truncated to 49
        r#"{"temp": null, "armed": true}"#]);        // JSON null = missing, as in the codec
    let result = run(&[flow.to_str().unwrap(), sample.to_str().unwrap(),
                  "--on-missing", "skip", "--json", out.to_str().unwrap()]);
    assert_eq!(result.status.code(), Some(1), "a fraction is refused by acceptance");
    let rep = report(&out);
    assert!(rep.get("float_truncated_by_field").is_none());
    assert_eq!(rep["refused_by_field"]["temp"]["fractional"], 1);
    assert_eq!(rep["missing_by_field"]["temp"], 1);
    assert_eq!(rep["out_of_partition"]["temp"], 1, "the encoder cannot place it, as for any refused value");
    assert_eq!(rep["encoded"], 0, "the fractional reading is not encoded under a truncated value");
    assert_eq!(rep["ready"], false);
}

#[test]
fn no_decision_fields_flow_fails_loud() {
    let dir = Scratch::new("nodec");
    let flow = dir.join("flow.md");
    std::fs::write(&flow, "---\nname: f\nstart: a\n---\n## a\n-> b: always\n## b\n").unwrap();
    let sample = dir.join("sample.ndjson");
    std::fs::write(&sample, "{\"x\": 1}\n").unwrap();
    let result = run(&[flow.to_str().unwrap(), sample.to_str().unwrap()]);
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stdout).contains("no decision-relevant fields"));
}

#[test]
fn bad_usage_exits_two() {
    let result = run(&["only-one-arg"]);
    assert_eq!(result.status.code(), Some(2));
}

const DEFINED_FLOW: &str = "---
name: defined_guard
start: classify
field.load: fixed scale=100 unit=ratio rounding=floor min=0 max=100
field.zone: category absent=allowed
---
## classify
-> critical: when load >= 0.9
-> unzoned: when zone == None
-> warn: when load >= 0.5 and zone == \"a\"
-> ok: else
## critical
## unzoned
## warn
## ok
";

#[test]
fn a_defined_flow_is_judged_by_its_definitions() {
    // The twin of the Python test of the same name: a numeric string is refused rather than parsed,
    // a fraction is refused, and an absent zone is a routed value, not a missing field.
    let (_dir, flow, sample, out) = setup("defined", &[
        r#"{"load": 95, "zone": "a"}"#, r#"{"load": 60}"#, r#"{"load": 60, "zone": null}"#,
        r#"{"load": 60, "zone": "a"}"#, r#"{"load": "60", "zone": "a"}"#, r#"{"load": 60.5, "zone": "a"}"#]);
    std::fs::write(&flow, DEFINED_FLOW).unwrap();
    let result = run(&[flow.to_str().unwrap(), sample.to_str().unwrap(), "--json", out.to_str().unwrap()]);
    assert_eq!(result.status.code(), Some(1), "{}", String::from_utf8_lossy(&result.stdout));
    let rep = report(&out);
    assert_eq!(rep["refused_by_field"], serde_json::json!({"load": {"wrong_type": 1, "fractional": 1}}));
    assert!(rep.get("missing_by_field").is_none_or(|missing| missing.as_object().is_none_or(|map| map.is_empty())));
    assert_eq!(rep["encoded"], 4);
    assert_eq!(rep["route_mismatches"], serde_json::json!([]));
    assert_eq!(rep["ready"], false);
}

/// The twin of the Python test of the same name: a line that holds a NaN or Infinity token, a number
/// beyond the double range or a lone surrogate is refused as not JSON, never read as a number, so both
/// tools count the same lines as `bad_json` and encode the same events.
#[test]
fn a_line_with_a_non_finite_or_overflowing_number_or_a_lone_surrogate_is_not_an_event() {
    let (_dir, flow, sample, out) = setup("hostile_numbers", &[
        r#"{"temp": 95, "armed": true}"#, r#"{"temp": NaN, "armed": true}"#, r#"{"temp": Infinity, "armed": true}"#,
        r#"{"temp": -Infinity, "armed": true}"#, r#"{"temp": 1e400, "armed": true}"#, r#"{"temp": -1e400, "armed": false}"#,
        r#"{"temp": 60, "armed": true, "note": "\ud800"}"#, r#"{"temp": 60, "armed": false}"#]);
    let result = run(&[flow.to_str().unwrap(), sample.to_str().unwrap(), "--json", out.to_str().unwrap()]);
    assert_eq!(result.status.code(), Some(0), "{}", String::from_utf8_lossy(&result.stdout));
    let rep = report(&out);
    assert_eq!(rep["bad_json"], 6);
    assert_eq!(rep["encoded"], 2);
}

#[test]
fn example_values_are_shown_as_python_writes_them() {
    // The Python report prints an example value with `repr`: 'yes' with its quotes, not the value model's
    // debug text (`Str("yes")`).
    let (_dir, flow, sample, _out) = setup("repr", &[
        r#"{"temp": 95, "armed": true}"#, r#"{"temp": "yes", "armed": true}"#, r#"{"temp": 60, "armed": "x"}"#]);
    let result = run(&[flow.to_str().unwrap(), sample.to_str().unwrap()]);
    let text = String::from_utf8_lossy(&result.stdout).to_string();
    assert!(text.contains("(example value: 'yes')"), "{text}");
    assert!(text.contains("(example value: 'x')"), "{text}");
    assert!(!text.contains("Str("), "{text}");
}
