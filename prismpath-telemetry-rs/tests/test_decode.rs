use prismpath_rs::{parse, V};
use prismpath_telemetry_rs::{decode, quantizer, wire};
use std::collections::HashMap;

const CAT: &str = r#"---
name: cat
start: classify
---
## classify
-> urgent: when kind == 'urgent'
-> batch: when kind in ('nightly', 'weekly')
-> blocked: when status != 'ok'
-> normal: else
## urgent
## batch
## blocked
## normal
"#;

#[test]
fn test_decode_reproduces_routes() {
    let graph = parse(CAT);
    let parts = quantizer::build_partitions(&graph).expect("the flow partitions");
    let readings = vec![
        {
            let mut reading = HashMap::new();
            reading.insert("kind".to_string(), V::Str("urgent".to_string()));
            reading.insert("status".to_string(), V::Str("ok".to_string()));
            reading
        },
        {
            let mut reading = HashMap::new();
            reading.insert("kind".to_string(), V::Str("nightly".to_string()));
            reading.insert("status".to_string(), V::Str("ok".to_string()));
            reading
        },
        {
            let mut reading = HashMap::new();
            reading.insert("kind".to_string(), V::Str("adhoc".to_string()));
            reading.insert("status".to_string(), V::Str("bad".to_string()));
            reading
        },
        {
            let mut reading = HashMap::new();
            reading.insert("kind".to_string(), V::Str("weekly".to_string()));
            reading.insert("status".to_string(), V::Str("degraded".to_string()));
            reading
        },
    ];
    let bits = decode::encode_readings(&parts, &readings).unwrap();
    let rep = decode::inspect(&graph, &bits).expect("the flow partitions");
    assert_eq!(rep.n_readings, 4);
    assert_eq!(rep.trailing_ints, 0);

    for (orig, row) in readings.iter().zip(rep.readings.iter()) {
        assert_eq!(
            row.routes.get("classify").cloned().flatten(),
            wire::route_node(&graph, "classify", orig)
        );
    }
}

#[test]
fn test_other_renders_readably() {
    let graph = parse(CAT);
    let parts = quantizer::build_partitions(&graph).expect("the flow partitions");
    let mut reading = HashMap::new();
    reading.insert("kind".to_string(), V::Str("adhoc".to_string()));
    reading.insert("status".to_string(), V::Str("bad".to_string()));
    let bits = decode::encode_readings(&parts, &[reading]).unwrap();
    let rep = decode::inspect(&graph, &bits).expect("the flow partitions");
    assert_eq!(
        rep.readings[0].reading.get("kind").unwrap(),
        &V::Str("<other>".to_string())
    );
}

#[test]
fn test_partial_final_frame_is_reported_not_crashed() {
    let graph = parse(CAT);
    let parts = quantizer::build_partitions(&graph).expect("the flow partitions");
    let mut reading = HashMap::new();
    reading.insert("kind".to_string(), V::Str("urgent".to_string()));
    reading.insert("status".to_string(), V::Str("ok".to_string()));
    let bits = decode::encode_readings(&parts, &[reading]).unwrap();
    let rep = decode::inspect(&graph, &format!("{}0", bits)).expect("the flow partitions");
    assert_eq!(rep.n_readings, 1);
}

/// A reading off the wire that carries a number beyond the double range is refused with an error, not a panic.
#[test]
fn a_reading_row_with_a_number_beyond_the_double_range_is_an_error_not_a_panic() {
    for text in [
        r#"{"symbols": {}, "reading": {"x": 1e400}, "routes": {}}"#,
        r#"{"symbols": {}, "reading": {"x": [1, {"y": -1e999}]}, "routes": {}}"#,
    ] {
        let outcome = std::panic::catch_unwind(|| serde_json::from_str::<decode::ReadingRow>(text));
        let parsed = outcome.unwrap_or_else(|_| panic!("deserializing {text} panicked"));
        let error = parsed.expect_err("a number beyond the double range must be refused");
        assert!(error.to_string().contains("beyond the double range"), "{error}");
    }
    assert!(serde_json::from_str::<decode::ReadingRow>(r#"{"symbols": {}, "reading": {"x": 1.5}, "routes": {}}"#).is_ok());
}
