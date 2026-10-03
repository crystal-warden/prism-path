use prismpath_rs::{parse, V};
use prismpath_telemetry_rs::quantizer;
use std::collections::HashMap;

const INCIDENT: &str = r#"---
name: incident_severity
start: assess
---

## assess
Read the incoming alert and classify it. Emit `user_facing` (bool), `error_rate` (percent of
requests failing, 0–100), and `data_at_risk` (bool).
@emits(user_facing, error_rate, data_at_risk)
-> sev1_page: when data_at_risk
-> sev1_page: when user_facing and error_rate >= 25
-> sev2_oncall: when user_facing and error_rate >= 5
-> sev3_ticket: when error_rate >= 1
-> watch: else

## sev1_page
## sev2_oncall
## sev3_ticket
## watch
"#;

const CATEGORICAL: &str = r#"---
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

const NUMERIC_EQ: &str = r#"---
name: numeq
start: classify
---
## classify
-> exact: when x == 5
-> high: when x >= 10
-> low: else
## exact
## high
## low
"#;

fn route(graph: &prismpath_rs::Graph, node: &str, reading: &HashMap<String, V>) -> Option<String> {
    if let Some(flow_node) = graph.nodes.get(node) {
        for (target, cond) in &flow_node.edges {
            if prismpath_rs::is_deterministic(cond) {
                if let Ok(true) = prismpath_rs::eval_condition(cond, reading) {
                    return Some(target.clone());
                }
            }
        }
    }
    None
}

fn assert_decisions_preserved(graph: &prismpath_rs::Graph, node: &str, readings: &[HashMap<String, V>]) {
    let parts = quantizer::build_partitions(graph);
    for reading in readings {
        let orig = route(graph, node, reading);
        let recon = route(graph, node, &quantizer::reconstruct(&parts, &quantizer::quantize(&parts, reading).unwrap()));
        assert_eq!(orig, recon, "decision changed for {:?}", reading);
    }
}

#[test]
fn test_incident_partition_is_minimal() {
    let graph = parse(INCIDENT);
    let parts = quantizer::build_partitions(&graph);
    assert_eq!(parts["error_rate"].kind, quantizer::FieldKind::Numeric);
    assert_eq!(parts["error_rate"].n, 4);
    assert_eq!(parts["data_at_risk"].kind, quantizer::FieldKind::Boolean);
    assert_eq!(parts["data_at_risk"].n, 2);
    assert_eq!(parts["user_facing"].kind, quantizer::FieldKind::Boolean);
    assert_eq!(parts["user_facing"].n, 2);
}

#[test]
fn test_categorical_partition_shape() {
    let graph = parse(CATEGORICAL);
    let parts = quantizer::build_partitions(&graph);
    assert_eq!(parts["kind"].kind, quantizer::FieldKind::Categorical);
    assert_eq!(parts["kind"].n, 4);
    assert_eq!(parts["status"].kind, quantizer::FieldKind::Categorical);
    assert_eq!(parts["status"].n, 2);
}

#[test]
fn test_numeric_equality_keeps_the_point_cell() {
    let graph = parse(NUMERIC_EQ);
    let parts = quantizer::build_partitions(&graph);
    assert_eq!(parts["x"].kind, quantizer::FieldKind::Numeric);
    assert_eq!(parts["x"].n, 4);
    assert_ne!(parts["x"].symbol(&V::Num(5.0)).unwrap(), parts["x"].symbol(&V::Num(4.0)).unwrap());
    assert_ne!(parts["x"].symbol(&V::Num(7.0)).unwrap(), parts["x"].symbol(&V::Num(5.0)).unwrap());
}

#[test]
fn test_incident_decisions_preserved() {
    let graph = parse(INCIDENT);
    let mut readings = Vec::new();
    for dar in [true, false] {
        for uf in [true, false] {
            for er in [-5, 0, 1, 2, 4, 5, 6, 24, 25, 26, 50, 100] {
                let mut reading = HashMap::new();
                reading.insert("data_at_risk".to_string(), V::Bool(dar));
                reading.insert("user_facing".to_string(), V::Bool(uf));
                reading.insert("error_rate".to_string(), V::Num(er as f64));
                readings.push(reading);
            }
        }
    }
    assert_decisions_preserved(&graph, "assess", &readings);
}

#[test]
fn test_categorical_decisions_preserved() {
    let graph = parse(CATEGORICAL);
    let mut readings = Vec::new();
    for kind in ["urgent", "nightly", "weekly", "adhoc", "xyz"] {
        for status in ["ok", "bad", "degraded"] {
            let mut reading = HashMap::new();
            reading.insert("kind".to_string(), V::Str(kind.to_string()));
            reading.insert("status".to_string(), V::Str(status.to_string()));
            readings.push(reading);
        }
    }
    assert_decisions_preserved(&graph, "classify", &readings);
}

#[test]
fn test_numeric_equality_decisions_preserved() {
    let graph = parse(NUMERIC_EQ);
    let readings: Vec<HashMap<String, V>> = (-3..20)
        .map(|value| {
            let mut reading = HashMap::new();
            reading.insert("x".to_string(), V::Num(value as f64));
            reading
        })
        .collect();
    assert_decisions_preserved(&graph, "classify", &readings);
}

#[test]
fn test_symbols_are_small() {
    let graph = parse(INCIDENT);
    let parts = quantizer::build_partitions(&graph);
    let mut reading = HashMap::new();
    reading.insert("data_at_risk".to_string(), V::Bool(true));
    reading.insert("user_facing".to_string(), V::Bool(false));
    reading.insert("error_rate".to_string(), V::Num(42.0));
    let syms = quantizer::quantize(&parts, &reading).unwrap();
    for symbol in syms.values() {
        assert!(*symbol < 8);
    }
}

#[test]
fn test_out_of_partition_numeric_is_err_not_panic() {
    // build_partitions always leaves open ends, so construct a bounded partition by hand — the
    // case a library consumer (e.g. a Vector codec) could feed; it must be an Err, never a panic.
    let cells = vec![quantizer::Cell { lo: Some(0), hi: Some(9), const_val: None, rep: V::Num(5.0) }];
    let part = quantizer::FieldPartition::new("x".into(), quantizer::FieldKind::Numeric, cells);
    assert!(part.symbol(&V::Num(5.0)).is_ok());
    assert!(part.symbol(&V::Num(99.0)).is_err());
    let mut parts = HashMap::new();
    parts.insert("x".to_string(), part);
    let mut reading = HashMap::new();
    reading.insert("x".to_string(), V::Num(99.0));
    assert!(quantizer::quantize(&parts, &reading).is_err());
}


/// Found in October 2026 by the Lean formalization's float check: the permissive `symbol` truncated a
/// fraction with `as i64`, toward zero, which moved the reading across a cut and changed the decision.
/// A fraction and a non finite number are refused on the permissive path now, as on the checked one.
#[test]
fn a_fraction_is_refused_on_the_permissive_path_never_truncated() {
    const CUTS: &str = r#"---
name: cuts
start: s
---
## s
@emits(x)
-> hit: when x < 0
-> hit: when x == 3
-> hit: when x in [7]
-> miss: else
## hit
## miss
"#;
    let parts = quantizer::build_partitions(&parse(CUTS));
    let x = &parts["x"];
    for value in [-0.5, -0.9, 3.5, 7.5, 0.25, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let error = x.symbol(&V::Num(value)).expect_err("a fraction or non finite number must be refused");
        assert!(error.contains("refused rather than truncated"), "{value}: {error}");
    }
    for value in [-1.0, 0.0, 3.0, 7.0] {
        assert!(x.symbol(&V::Num(value)).is_ok(), "an integral float is still its integer: {value}");
    }
}
