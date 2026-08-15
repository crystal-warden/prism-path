//! The Rust twin of the frozen boundary parity corpus: identical symbols at every threshold
//! edge and at the 2^53 f64 exactness edge. Cross implementation drift at a boundary goes red.

use prismpath_rs::{parse, V};
use prismpath_telemetry_rs::quantizer;

#[test]
fn boundary_symbols_match_frozen_corpus() {
    let path = std::path::Path::new("../adapters/telemetry/conformance/boundary.json");
    let corpus: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("read boundary.json"))
            .expect("parse boundary.json");
    let graph = parse(corpus["flow"].as_str().unwrap());
    let parts = quantizer::build_partitions(&graph);
    let p = &parts[corpus["field"].as_str().unwrap()];
    assert_eq!(p.n as u64, corpus["cells"].as_u64().unwrap());
    for probe in corpus["probes"].as_array().unwrap() {
        let v = probe["value"].as_i64().unwrap();
        let expected = probe["symbol"].as_u64().unwrap() as usize;
        let got = p.symbol(&V::Num(v as f64)).unwrap();
        assert_eq!(got, expected, "value {v} quantized to {got}, frozen corpus says {expected}");
    }
}
