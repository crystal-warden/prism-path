//! Integration tests for facet-vector-sink binary execution and contract verification.

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

/// Helper directory holder that creates a isolated temporary test directory and cleans up on drop.
struct TestSetup {
    directory_path: PathBuf,
    flow_file_path: PathBuf,
}

impl TestSetup {
    /// Creates a new test directory and writes standard flow markdown for testing.
    fn new(test_name: &str) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let directory_path = env::temp_dir().join(format!(
            "facet_sink_test_{}_{}_{}",
            test_name,
            std::process::id(),
            timestamp
        ));
        fs::create_dir_all(&directory_path).expect("create test temp directory");
        let flow_file_path = directory_path.join("flow.md");
        let flow_content = r#"---
name: t
start: a
---
## a
-> hot: when temp >= 90 and armed
-> warm: when temp >= 50
-> cold: else
## hot
## warm
## cold
"#;
        fs::write(&flow_file_path, flow_content).expect("write flow file");
        Self {
            directory_path,
            flow_file_path,
        }
    }
}

impl Drop for TestSetup {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory_path);
    }
}

/// Executes the facet-vector-sink binary with piped standard input and returns standard output and status.
fn run_sink_with_stdin(
    flow_path: &Path,
    arguments: &[&str],
    input_text: &str,
) -> (String, String, ExitStatus) {
    let binary_path = env!("CARGO_BIN_EXE_facet-vector-sink");
    let mut command = Command::new(binary_path);
    command.arg(flow_path);
    for argument in arguments {
        command.arg(argument);
    }
    command.stdin(Stdio::piped());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());

    let mut child_process = command.spawn().expect("spawn process");
    if let Some(mut stdin) = child_process.stdin.take() {
        stdin.write_all(input_text.as_bytes()).expect("write to stdin");
    }
    let output = child_process.wait_with_output().expect("wait for process output");
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status,
    )
}

#[test]
fn test_batch_reporting_before_summary() {
    let setup = TestSetup::new("batch_reporting");
    let input = r#"{"temp": 95, "armed": true}
{"temp": 60, "armed": false}
{"temp": 20, "armed": false}
{"temp": 91, "armed": true}
{"temp": 55, "armed": true}
"#;
    let (stdout, _stderr, status) = run_sink_with_stdin(&setup.flow_file_path, &["--batch", "2"], input);
    assert!(status.success(), "process failed");

    let output_lines: Vec<&str> = stdout.lines().filter(|line| !line.trim().is_empty()).collect();
    assert!(
        output_lines.len() >= 4,
        "expected at least 4 output lines, got {}",
        output_lines.len()
    );

    for (index, line) in output_lines.iter().take(3).enumerate() {
        let parsed_batch_report: serde_json::Value =
            serde_json::from_str(line).expect("valid json batch report");
        assert!(
            parsed_batch_report.get("batch_index").is_some(),
            "line at index {} should be a batch report",
            index
        );
    }

    let summary_line = output_lines.last().expect("summary line");
    let parsed_summary_report: serde_json::Value =
        serde_json::from_str(summary_line).expect("valid json summary report");
    assert!(
        parsed_summary_report.get("epoch_chain_length").is_some(),
        "last line should be summary report"
    );
}

#[test]
fn test_rejected_input_accounting() {
    let setup = TestSetup::new("rejected_accounting");
    let valid_reading_first = r#"{"temp": 95, "armed": true}"#;
    let unparseable_line = r#"{"temp": 95, "armed": true invalid json"#;
    let unencodable_line = r#"{"temp": 95}"#;
    let valid_reading_second = r#"{"temp": 20, "armed": false}"#;

    let input_payload = format!(
        "{}\n{}\n{}\n{}\n",
        valid_reading_first, unparseable_line, unencodable_line, valid_reading_second
    );

    let (stdout, _stderr, status) =
        run_sink_with_stdin(&setup.flow_file_path, &["--batch", "10"], &input_payload);
    assert!(status.success(), "process failed");

    let output_lines: Vec<&str> = stdout.lines().filter(|line| !line.trim().is_empty()).collect();
    let summary_line = output_lines.last().expect("summary line");
    let parsed_summary_report: serde_json::Value =
        serde_json::from_str(summary_line).expect("valid summary json");

    let readings_encoded = parsed_summary_report["readings_encoded"].as_u64().expect("readings encoded") as usize;
    let lines_rejected_unparseable =
        parsed_summary_report["lines_rejected_unparseable"].as_u64().expect("unparseable count") as usize;
    let lines_rejected_unencodable =
        parsed_summary_report["lines_rejected_unencodable"].as_u64().expect("unencodable count") as usize;
    let accepted_input_bytes =
        parsed_summary_report["accepted_input_bytes"].as_u64().expect("accepted bytes") as usize;
    let rejected_input_bytes =
        parsed_summary_report["rejected_input_bytes"].as_u64().expect("rejected bytes") as usize;
    let compression_ratio = parsed_summary_report["compression_ratio"].as_f64().expect("ratio value");

    assert_eq!(readings_encoded, 2);
    assert_eq!(lines_rejected_unparseable, 1);
    assert_eq!(lines_rejected_unencodable, 1);

    let expected_accepted_bytes = valid_reading_first.len() + valid_reading_second.len();
    let expected_rejected_bytes = unparseable_line.len() + unencodable_line.len();

    assert_eq!(accepted_input_bytes, expected_accepted_bytes);
    assert_eq!(rejected_input_bytes, expected_rejected_bytes);

    let encoded_payload_bytes =
        parsed_summary_report["encoded_payload_bytes"].as_u64().expect("payload bytes") as usize;
    let expected_ratio = accepted_input_bytes as f64 / encoded_payload_bytes as f64;
    assert!((compression_ratio - expected_ratio).abs() < 1e-6);
}

#[test]
fn test_reproducible_interference_seed() {
    let setup = TestSetup::new("reproducible_seed");
    let mut input_payload = String::new();
    for index in 0..20 {
        input_payload.push_str(&format!(
            "{{\"temp\": {}, \"armed\": {}}}\n",
            50 + index,
            index % 2 == 0
        ));
    }

    let (stdout_seed_seven_first, _stderr_first, status_first) = run_sink_with_stdin(
        &setup.flow_file_path,
        &["--interference", "0.3", "--seed", "7"],
        &input_payload,
    );
    assert!(status_first.success());

    let (stdout_seed_seven_second, _stderr_second, status_second) = run_sink_with_stdin(
        &setup.flow_file_path,
        &["--interference", "0.3", "--seed", "7"],
        &input_payload,
    );
    assert!(status_second.success());

    let (stdout_seed_eight, _stderr_third, status_third) = run_sink_with_stdin(
        &setup.flow_file_path,
        &["--interference", "0.3", "--seed", "8"],
        &input_payload,
    );
    assert!(status_third.success());

    assert_eq!(
        stdout_seed_seven_first, stdout_seed_seven_second,
        "two runs with identical seed 7 must produce identical stdout"
    );
    assert_ne!(
        stdout_seed_seven_first, stdout_seed_eight,
        "runs with seed 7 and seed 8 should produce different stdout"
    );
}

#[test]
fn test_bounded_buffering_and_backpressure() {
    let setup = TestSetup::new("bounded_buffering");
    let mut input_payload = String::new();
    for index in 0..30 {
        input_payload.push_str(&format!(
            "{{\"temp\": {}, \"armed\": {}}}\n",
            50 + index,
            index % 2 == 0
        ));
    }

    let (stdout, _stderr, status) = run_sink_with_stdin(
        &setup.flow_file_path,
        &[
            "--max-queued",
            "1",
            "--consumer-delay-ms",
            "200",
            "--interference",
            "0.0",
            "--batch",
            "1",
        ],
        &input_payload,
    );
    assert!(status.success());

    let output_lines: Vec<&str> = stdout.lines().filter(|line| !line.trim().is_empty()).collect();
    let summary_line = output_lines.last().expect("summary line");
    let parsed_summary_report: serde_json::Value =
        serde_json::from_str(summary_line).expect("summary json");

    let batches_dropped = parsed_summary_report["batches_dropped_backpressure"]
        .as_u64()
        .expect("batches dropped backpressure");
    let gaps = parsed_summary_report["gaps"].as_array().expect("gaps array");
    let verify_chain = parsed_summary_report["verify_chain"].as_bool().expect("verify chain bool");

    assert!(
        batches_dropped > 0,
        "expected batches_dropped_backpressure > 0, got {}",
        batches_dropped
    );
    assert!(
        !gaps.is_empty(),
        "expected at least one gap listed in gaps array"
    );
    assert!(verify_chain, "expected verify_chain to be true");
}
