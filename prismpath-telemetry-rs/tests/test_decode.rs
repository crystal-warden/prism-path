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
    let parts = quantizer::build_partitions(&graph);
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
    let rep = decode::inspect(&graph, &bits);
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
    let parts = quantizer::build_partitions(&graph);
    let mut reading = HashMap::new();
    reading.insert("kind".to_string(), V::Str("adhoc".to_string()));
    reading.insert("status".to_string(), V::Str("bad".to_string()));
    let bits = decode::encode_readings(&parts, &[reading]).unwrap();
    let rep = decode::inspect(&graph, &bits);
    assert_eq!(
        rep.readings[0].reading.get("kind").unwrap(),
        &V::Str("<other>".to_string())
    );
}

#[test]
fn test_partial_final_frame_is_reported_not_crashed() {
    let graph = parse(CAT);
    let parts = quantizer::build_partitions(&graph);
    let mut reading = HashMap::new();
    reading.insert("kind".to_string(), V::Str("urgent".to_string()));
    reading.insert("status".to_string(), V::Str("ok".to_string()));
    let bits = decode::encode_readings(&parts, &[reading]).unwrap();
    let rep = decode::inspect(&graph, &format!("{}0", bits));
    assert_eq!(rep.n_readings, 1);
}
