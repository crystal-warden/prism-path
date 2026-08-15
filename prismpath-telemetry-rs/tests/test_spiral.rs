use prismpath_rs::{parse, V};
use prismpath_telemetry_rs::{quantizer as q, spiral as sp, wire as w, zeckendorf as z};
use serde_json::Value;
use std::collections::HashMap;

fn load_corpus() -> Value {
    let path = std::path::Path::new("../adapters/telemetry/conformance/spiral.json");
    let content = std::fs::read_to_string(path).expect("read spiral.json");
    serde_json::from_str(&content).expect("parse spiral.json")
}

fn layout_from_corpus(corpus: &Value) -> (prismpath_rs::Graph, sp::SpiralLayout) {
    let flow = corpus["flow"].as_str().unwrap();
    let node = corpus["node"].as_str().unwrap();
    let g = parse(flow);
    let layout = sp::SpiralLayout::new(&g, node).unwrap();
    (g, layout)
}

#[test]
fn test_gray_sequence_is_single_step_and_complete() {
    let test_radices = vec![
        vec![2, 2],
        vec![3, 2],
        vec![3, 3, 3],
        vec![4, 2, 3],
    ];

    for radices in test_radices {
        let seq = sp::mixed_radix_gray(&radices);
        let size: usize = radices.iter().product();
        assert_eq!(seq.len(), size);

        let unique: std::collections::HashSet<_> = seq.iter().cloned().collect();
        assert_eq!(unique.len(), size);

        for pair in seq.windows(2) {
            let a = &pair[0];
            let b = &pair[1];
            let diffs: Vec<usize> = (0..radices.len()).filter(|&i| a[i] != b[i]).collect();
            assert_eq!(diffs.len(), 1);
            let idx = diffs[0];
            let diff = (a[idx] as isize - b[idx] as isize).abs();
            assert_eq!(diff, 1);
        }
    }
}

#[test]
fn test_bands_are_contiguous_and_partition_the_index() {
    let corpus = load_corpus();
    let (_, layout) = layout_from_corpus(&corpus);
    let bounds = layout.band_bounds();
    assert_eq!(bounds[0].0, 0);
    for window in bounds.windows(2) {
        let hi = window[0].1;
        let nlo = window[1].0;
        assert_eq!(hi, nlo);
    }
    assert_eq!(bounds.last().unwrap().1, layout.size);
}

#[test]
fn test_baseline_route_sits_at_the_center() {
    let corpus = load_corpus();
    let (_, layout) = layout_from_corpus(&corpus);
    assert_eq!(layout.route_of(0), layout.routes[0]);
    let baseline_reading: HashMap<String, V> = layout
        .fields
        .iter()
        .map(|f| (f.clone(), layout.parts[f].representative(0)))
        .collect();
    assert_eq!(layout.band_id(&baseline_reading), 0);
}

#[test]
fn test_route_of_is_an_integer_band_compare() {
    let corpus = load_corpus();
    let (_, layout) = layout_from_corpus(&corpus);
    for n in 0..layout.size {
        let mut expect = None;
        for b in 0..layout.routes.len() {
            if n < layout.band_base[b] + layout.band_width[b] {
                expect = layout.routes[b].clone();
                break;
            }
        }
        assert_eq!(layout.route_of(n), expect);
        let _ = sp::radius2(n as u32);
        let _ = sp::theta_u32(n as u32);
    }
}

#[test]
fn test_decisions_preserved_through_the_spiral() {
    let corpus = load_corpus();
    let (g, layout) = layout_from_corpus(&corpus);
    let node = corpus["node"].as_str().unwrap();

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

        assert_eq!(direct, expected_route);
        assert_eq!(via_band, expected_route);
        assert_eq!(via_index, expected_route);
    }
}

#[test]
fn test_progressive_round_trip_recovers_the_cell() {
    let corpus = load_corpus();
    let (g, layout) = layout_from_corpus(&corpus);
    let node = corpus["node"].as_str().unwrap();

    for probe in corpus["probes"].as_array().unwrap() {
        let r_obj = probe["reading"].as_object().unwrap();
        let mut reading = HashMap::new();
        for (k, v) in r_obj {
            reading.insert(k.clone(), V::Num(v.as_f64().unwrap()));
        }
        let expected_route = probe["route"].as_str().map(|s| s.to_string());

        let (db, rb) = layout.encode_progressive(&reading);
        let rec = layout.decode_progressive(&db, &rb).unwrap();

        assert_eq!(layout.cell(&rec), layout.cell(&reading));
        assert_eq!(w::route_node(&g, node, &rec), expected_route);
        assert_eq!(
            layout.decode_decision(&layout.encode_decision(&reading)).unwrap(),
            expected_route
        );
    }
}

#[test]
fn test_decode_decision_rejects_out_of_range_bits_without_panicking() {
    // `bits` is untrusted wire data. A crafted code that decodes to an index past the last band
    // must return Err, not panic on an out-of-bounds slice read.
    let corpus = load_corpus();
    let (_, layout) = layout_from_corpus(&corpus);

    let oob = z::encode(layout.routes.len() + 100).expect("encode a large index");
    let err = layout.decode_decision(&oob);
    assert!(err.is_err(), "out-of-range band index must be an error, got {err:?}");
    assert!(err.unwrap_err().contains("outside the layout"));

    // Garbage that isn't a Fibonacci code (no trailing "11") errors cleanly, never panics.
    assert!(layout.decode_decision("101010").is_err());
    // And a valid round-trip still succeeds.
    let corpus_probe = &corpus["probes"][0];
    if let Some(r_obj) = corpus_probe["reading"].as_object() {
        let mut reading = HashMap::new();
        for (k, v) in r_obj {
            reading.insert(k.clone(), V::Num(v.as_f64().unwrap()));
        }
        assert!(layout.decode_decision(&layout.encode_decision(&reading)).is_ok());
    }
}

#[test]
fn test_frozen_tessellation_matches() {
    let corpus = load_corpus();
    let (_, layout) = layout_from_corpus(&corpus);

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
}

#[test]
fn test_decision_stream_cheaper_than_linear_for_multidim() {
    let corpus = load_corpus();
    let (g, layout) = layout_from_corpus(&corpus);
    let parts = q::build_partitions(&g);

    let mut readings = Vec::new();
    for p in [0.0, 25.0, 50.0] {
        for r in [0.0, 25.0, 50.0] {
            for v in [0.0, 50.0, 90.0] {
                let mut rd = HashMap::new();
                rd.insert("pitch".to_string(), V::Num(p));
                rd.insert("roll".to_string(), V::Num(r));
                rd.insert("vibration".to_string(), V::Num(v));
                readings.push(rd);
            }
        }
    }

    let lin: usize = readings
        .iter()
        .map(|rd| w::encode_reading(&parts, rd).unwrap().len())
        .sum();
    let dec: usize = readings.iter().map(|rd| layout.encode_decision(rd).len()).sum();
    assert!(dec < lin);
}

// ---------------------------------------------------------------- 0.1.1: fallible twins
// The `try_` variants must agree with the panicking API on every valid input (std's
// `slice[i]` vs `slice.get(i)` contract) and return Err, never panic, on the inputs the
// panicking API documents as preconditions.

#[test]
fn test_try_variants_agree_with_panicking_api_on_valid_inputs() {
    let corpus = load_corpus();
    let (_g, layout) = layout_from_corpus(&corpus);
    for probe in corpus["probes"].as_array().unwrap() {
        let reading: HashMap<String, V> = probe["reading"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), V::from_json(v)))
            .collect();
        assert_eq!(layout.try_cell(&reading).unwrap(), layout.cell(&reading));
        assert_eq!(layout.try_index(&reading).unwrap(), layout.index(&reading));
        assert_eq!(layout.try_band_id(&reading).unwrap(), layout.band_id(&reading));
        assert_eq!(
            layout.try_encode_decision(&reading).unwrap(),
            layout.encode_decision(&reading)
        );
        assert_eq!(
            layout.try_encode_progressive(&reading).unwrap(),
            layout.encode_progressive(&reading)
        );
        let n = layout.index(&reading);
        assert_eq!(layout.try_route_of(n).unwrap(), layout.route_of(n));
        assert_eq!(layout.try_reconstruct(n).unwrap(), layout.reconstruct(n));
    }
}

#[test]
fn test_try_variants_err_instead_of_panicking() {
    let corpus = load_corpus();
    let (_g, layout) = layout_from_corpus(&corpus);
    let empty: HashMap<String, V> = HashMap::new();
    assert!(layout.try_cell(&empty).unwrap_err().contains("missing spiral field"));
    assert!(layout.try_index(&empty).is_err());
    assert!(layout.try_band_id(&empty).is_err());
    assert!(layout.try_encode_decision(&empty).is_err());
    assert!(layout.try_encode_progressive(&empty).is_err());
    let big = layout.size + 100;
    assert!(layout.try_route_of(big).unwrap_err().contains("outside the spiral"));
    assert!(layout.try_reconstruct(big).is_err());
    assert!(layout.try_reconstruct_band(usize::MAX).unwrap_err().contains("outside the layout"));
}
