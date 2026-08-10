use prismpath_rs::{parse, V};
use prismpath_telemetry_rs::{spiral as sp, wire as w};
use serde_json::Value;
use std::collections::HashMap;

fn load_spiral_corpus() -> Value {
    let path = std::path::Path::new("../adapters/telemetry/conformance/spiral.json");
    let content = std::fs::read_to_string(path).expect("read spiral.json");
    serde_json::from_str(&content).expect("parse spiral.json")
}

#[test]
fn test_conformance_spiral_tessellation_and_3way_routing() {
    let corpus = load_spiral_corpus();
    let flow = corpus["flow"].as_str().unwrap();
    let node = corpus["node"].as_str().unwrap();
    let g = parse(flow);
    let layout = sp::SpiralLayout::new(&g, node).unwrap();

    // Assert exact tessellation match
    let corpus_fields: Vec<String> = corpus["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(layout.fields, corpus_fields);

    let corpus_radices: Vec<usize> = corpus["radices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap() as usize)
        .collect();
    assert_eq!(layout.radices, corpus_radices);
    assert_eq!(layout.size, corpus["size"].as_u64().unwrap() as usize);

    let got_bands: Vec<Value> = layout
        .routes
        .iter()
        .enumerate()
        .map(|(i, r)| {
            serde_json::json!({
                "route": r,
                "base": layout.band_base[i],
                "width": layout.band_width[i]
            })
        })
        .collect();
    assert_eq!(got_bands, corpus["bands"].as_array().unwrap().clone());

    let got_cells: Vec<Value> = (0..layout.size)
        .map(|n| {
            serde_json::json!({
                "cell": layout.cell_of[n],
                "n": n,
                "band": layout.band_index[&layout.route_of(n)],
                "route": layout.route_of(n)
            })
        })
        .collect();
    assert_eq!(got_cells, corpus["cells"].as_array().unwrap().clone());

    // Assert each probe routes three ways identically
    for probe in corpus["probes"].as_array().unwrap() {
        let r_obj = probe["reading"].as_object().unwrap();
        let mut reading = HashMap::new();
        for (k, v) in r_obj {
            reading.insert(k.clone(), V::Num(v.as_f64().unwrap()));
        }
        let expected_route = probe["route"].as_str().map(|s| s.to_string());

        let direct = w::route_node(&g, node, &reading);
        let via_band = w::route_node(&g, node, &layout.reconstruct_band(layout.band_id(&reading)));
        let via_index = layout.route_of(layout.index(&reading));

        assert_eq!(direct, expected_route, "Direct routing mismatch on {:?}", reading);
        assert_eq!(via_band, expected_route, "Via-band routing mismatch on {:?}", reading);
        assert_eq!(via_index, expected_route, "Via-index routing mismatch on {:?}", reading);
    }
}
