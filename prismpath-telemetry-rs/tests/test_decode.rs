use prismpath_rs::{parse, V};
use prismpath_telemetry_rs::{decode as dec, quantizer as q, wire as w};
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
    let g = parse(CAT);
    let parts = q::build_partitions(&g);
    let readings = vec![
        {
            let mut r = HashMap::new();
            r.insert("kind".to_string(), V::Str("urgent".to_string()));
            r.insert("status".to_string(), V::Str("ok".to_string()));
            r
        },
        {
            let mut r = HashMap::new();
            r.insert("kind".to_string(), V::Str("nightly".to_string()));
            r.insert("status".to_string(), V::Str("ok".to_string()));
            r
        },
        {
            let mut r = HashMap::new();
            r.insert("kind".to_string(), V::Str("adhoc".to_string()));
            r.insert("status".to_string(), V::Str("bad".to_string()));
            r
        },
        {
            let mut r = HashMap::new();
            r.insert("kind".to_string(), V::Str("weekly".to_string()));
            r.insert("status".to_string(), V::Str("degraded".to_string()));
            r
        },
    ];
    let bits = dec::encode_readings(&parts, &readings).unwrap();
    let rep = dec::inspect(&g, &bits);
    assert_eq!(rep.n_readings, 4);
    assert_eq!(rep.trailing_ints, 0);

    for (orig, row) in readings.iter().zip(rep.readings.iter()) {
        assert_eq!(
            row.routes.get("classify").cloned().flatten(),
            w::route_node(&g, "classify", orig)
        );
    }
}

#[test]
fn test_other_renders_readably() {
    let g = parse(CAT);
    let parts = q::build_partitions(&g);
    let mut r = HashMap::new();
    r.insert("kind".to_string(), V::Str("adhoc".to_string()));
    r.insert("status".to_string(), V::Str("bad".to_string()));
    let bits = dec::encode_readings(&parts, &[r]).unwrap();
    let rep = dec::inspect(&g, &bits);
    assert_eq!(
        rep.readings[0].reading.get("kind").unwrap(),
        &V::Str("<other>".to_string())
    );
}

#[test]
fn test_partial_final_frame_is_reported_not_crashed() {
    let g = parse(CAT);
    let parts = q::build_partitions(&g);
    let mut r = HashMap::new();
    r.insert("kind".to_string(), V::Str("urgent".to_string()));
    r.insert("status".to_string(), V::Str("ok".to_string()));
    let bits = dec::encode_readings(&parts, &[r]).unwrap();
    let rep = dec::inspect(&g, &format!("{}0", bits));
    assert_eq!(rep.n_readings, 1);
}
