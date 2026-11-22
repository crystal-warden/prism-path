use prismpath_rs::{parse, V};
use prismpath_telemetry_rs::{quantizer as q, spiral_groups as sg};
use serde_json::Value;
use std::collections::HashMap;

fn corpus() -> Value {
    let content = std::fs::read_to_string("tests/fixtures/grouped_band.json").expect("read grouped_band.json");
    serde_json::from_str(&content).expect("parse grouped_band.json")
}

fn reading(obj: &serde_json::Map<String, Value>) -> HashMap<String, V> {
    obj.iter().map(|(k, v)| (k.clone(), V::from_json(v))).collect()
}

#[test]
fn band_tier_matches_the_python_reference() {
    let corpus = corpus();
    let cases = corpus["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 3);
    let mut large = 0;
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let graph = parse(case["flow"].as_str().unwrap());
        let parts = q::build_partitions(&graph).unwrap();
        let nodes = sg::profile_nodes(&graph, &parts);
        let want_nodes: Vec<String> = case["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_str().unwrap().to_string())
            .collect();
        assert_eq!(nodes, want_nodes, "{name}: decision nodes");
        for node in &nodes {
            let want_routes: Vec<Option<String>> = case["routes"][node]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r.as_str().filter(|s| !s.is_empty()).map(|s| s.to_string()))
                .collect();
            assert_eq!(sg::route_order(&graph, node), want_routes, "{name}/{node}: band list");
            let cells = case["joint_cells"][node].as_u64().unwrap() as usize;
            assert_eq!(sg::joint_cells(&graph, node, &parts), cells, "{name}/{node}: joint cells");
            if cells > sg::ENUMERATION_LIMIT {
                large += 1;
            }
        }
        for entry in case["readings"].as_array().unwrap() {
            let r = reading(entry["reading"].as_object().unwrap());
            for node in &nodes {
                let want = entry["bands"][node].as_u64().unwrap() as usize;
                assert_eq!(sg::band_id(&graph, node, &r).unwrap(), want, "{name}/{node}: band");
            }
            let bits = sg::encode_decision_band(&graph, &nodes, &r).unwrap();
            assert_eq!(bits, entry["bits"].as_str().unwrap(), "{name}: band bits");
            // the receiver reads the route off the first code
            let first = &nodes[0];
            let want_route = prismpath_telemetry_rs::wire::route_node(&graph, first, &r);
            let code_len = bits.find("11").unwrap() + 2;
            assert_eq!(sg::decode_band(&graph, first, &bits[..code_len]).unwrap(), want_route);
        }
    }
    assert!(large >= 2, "two of the three cases are policies too large to list");
}

#[test]
fn a_band_outside_the_node_is_refused() {
    let graph = parse(
        "---\nname: a\nstart: watch\n---\n## watch\n-> hot: when t >= 5\n-> ok: else\n## hot\n## ok\n",
    );
    assert!(sg::decode_band(&graph, "watch", "0000011").is_err());
}
