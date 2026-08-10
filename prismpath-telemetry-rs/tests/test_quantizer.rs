use prismpath_rs::{parse, V};
use prismpath_telemetry_rs::quantizer as q;
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
    if let Some(n) = graph.nodes.get(node) {
        for (target, cond) in &n.edges {
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
    let parts = q::build_partitions(graph);
    for r in readings {
        let orig = route(graph, node, r);
        let recon = route(graph, node, &q::reconstruct(&parts, &q::quantize(&parts, r)));
        assert_eq!(orig, recon, "decision changed for {:?}", r);
    }
}

#[test]
fn test_incident_partition_is_minimal() {
    let g = parse(INCIDENT);
    let parts = q::build_partitions(&g);
    assert_eq!(parts["error_rate"].kind, q::FieldKind::Numeric);
    assert_eq!(parts["error_rate"].n, 4);
    assert_eq!(parts["data_at_risk"].kind, q::FieldKind::Boolean);
    assert_eq!(parts["data_at_risk"].n, 2);
    assert_eq!(parts["user_facing"].kind, q::FieldKind::Boolean);
    assert_eq!(parts["user_facing"].n, 2);
}

#[test]
fn test_categorical_partition_shape() {
    let g = parse(CATEGORICAL);
    let parts = q::build_partitions(&g);
    assert_eq!(parts["kind"].kind, q::FieldKind::Categorical);
    assert_eq!(parts["kind"].n, 4);
    assert_eq!(parts["status"].kind, q::FieldKind::Categorical);
    assert_eq!(parts["status"].n, 2);
}

#[test]
fn test_numeric_equality_keeps_the_point_cell() {
    let g = parse(NUMERIC_EQ);
    let parts = q::build_partitions(&g);
    assert_eq!(parts["x"].kind, q::FieldKind::Numeric);
    assert_eq!(parts["x"].n, 4);
    assert_ne!(parts["x"].symbol(&V::Num(5.0)), parts["x"].symbol(&V::Num(4.0)));
    assert_ne!(parts["x"].symbol(&V::Num(7.0)), parts["x"].symbol(&V::Num(5.0)));
}

#[test]
fn test_incident_decisions_preserved() {
    let g = parse(INCIDENT);
    let mut readings = Vec::new();
    for dar in [true, false] {
        for uf in [true, false] {
            for er in [-5, 0, 1, 2, 4, 5, 6, 24, 25, 26, 50, 100] {
                let mut r = HashMap::new();
                r.insert("data_at_risk".to_string(), V::Bool(dar));
                r.insert("user_facing".to_string(), V::Bool(uf));
                r.insert("error_rate".to_string(), V::Num(er as f64));
                readings.push(r);
            }
        }
    }
    assert_decisions_preserved(&g, "assess", &readings);
}

#[test]
fn test_categorical_decisions_preserved() {
    let g = parse(CATEGORICAL);
    let mut readings = Vec::new();
    for k in ["urgent", "nightly", "weekly", "adhoc", "xyz"] {
        for s in ["ok", "bad", "degraded"] {
            let mut r = HashMap::new();
            r.insert("kind".to_string(), V::Str(k.to_string()));
            r.insert("status".to_string(), V::Str(s.to_string()));
            readings.push(r);
        }
    }
    assert_decisions_preserved(&g, "classify", &readings);
}

#[test]
fn test_numeric_equality_decisions_preserved() {
    let g = parse(NUMERIC_EQ);
    let readings: Vec<HashMap<String, V>> = (-3..20)
        .map(|v| {
            let mut r = HashMap::new();
            r.insert("x".to_string(), V::Num(v as f64));
            r
        })
        .collect();
    assert_decisions_preserved(&g, "classify", &readings);
}

#[test]
fn test_symbols_are_small() {
    let g = parse(INCIDENT);
    let parts = q::build_partitions(&g);
    let mut r = HashMap::new();
    r.insert("data_at_risk".to_string(), V::Bool(true));
    r.insert("user_facing".to_string(), V::Bool(false));
    r.insert("error_rate".to_string(), V::Num(42.0));
    let syms = q::quantize(&parts, &r);
    for s in syms.values() {
        assert!(*s < 8);
    }
}
