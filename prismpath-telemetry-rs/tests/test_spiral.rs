use prismpath_rs::{parse, V};
use prismpath_telemetry_rs::{quantizer, spiral, wire, zeckendorf};
use serde_json::Value;
use std::collections::HashMap;

fn load_corpus() -> Value {
    let path = std::path::Path::new("../prismpath/telemetry/conformance/spiral.json");
    let content = std::fs::read_to_string(path).expect("read spiral.json");
    serde_json::from_str(&content).expect("parse spiral.json")
}

fn layout_from_corpus(corpus: &Value) -> (prismpath_rs::Graph, spiral::SpiralLayout) {
    let flow = corpus["flow"].as_str().unwrap();
    let node = corpus["node"].as_str().unwrap();
    let graph = parse(flow);
    let layout = spiral::SpiralLayout::new(&graph, node).unwrap();
    (graph, layout)
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
        let seq = spiral::mixed_radix_gray(&radices);
        let size: usize = radices.iter().product();
        assert_eq!(seq.len(), size);

        let unique: std::collections::HashSet<_> = seq.iter().cloned().collect();
        assert_eq!(unique.len(), size);

        for pair in seq.windows(2) {
            let previous = &pair[0];
            let next = &pair[1];
            let diffs: Vec<usize> = (0..radices.len()).filter(|&digit_index| previous[digit_index] != next[digit_index]).collect();
            assert_eq!(diffs.len(), 1);
            let idx = diffs[0];
            let diff = (previous[idx] as isize - next[idx] as isize).abs();
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
        .map(|field| (field.clone(), layout.parts[field].representative(0)))
        .collect();
    assert_eq!(layout.band_id(&baseline_reading), 0);
}

#[test]
fn test_route_of_is_an_integer_band_compare() {
    let corpus = load_corpus();
    let (_, layout) = layout_from_corpus(&corpus);
    for spiral_index in 0..layout.size {
        let mut expect = None;
        for band in 0..layout.routes.len() {
            if spiral_index < layout.band_base[band] + layout.band_width[band] {
                expect = layout.routes[band].clone();
                break;
            }
        }
        assert_eq!(layout.route_of(spiral_index), expect);
        let _ = spiral::radius2(spiral_index as u32);
        let _ = spiral::theta_u32(spiral_index as u32);
    }
}

#[test]
fn test_decisions_preserved_through_the_spiral() {
    let corpus = load_corpus();
    let (graph, layout) = layout_from_corpus(&corpus);
    let node = corpus["node"].as_str().unwrap();

    for probe in corpus["probes"].as_array().unwrap() {
        let r_obj = probe["reading"].as_object().unwrap();
        let mut reading = HashMap::new();
        for (field, value) in r_obj {
            reading.insert(field.clone(), V::Num(value.as_f64().unwrap()));
        }
        let expected_route = probe["route"].as_str().map(|route| route.to_string());

        let direct = wire::route_node(&graph, node, &reading);
        let via_band = wire::route_node(&graph, node, &layout.reconstruct_band(layout.band_id(&reading)));
        let via_index = layout.route_of(layout.index(&reading));

        assert_eq!(direct, expected_route);
        assert_eq!(via_band, expected_route);
        assert_eq!(via_index, expected_route);
    }
}

#[test]
fn test_progressive_round_trip_recovers_the_cell() {
    let corpus = load_corpus();
    let (graph, layout) = layout_from_corpus(&corpus);
    let node = corpus["node"].as_str().unwrap();

    for probe in corpus["probes"].as_array().unwrap() {
        let r_obj = probe["reading"].as_object().unwrap();
        let mut reading = HashMap::new();
        for (field, value) in r_obj {
            reading.insert(field.clone(), V::Num(value.as_f64().unwrap()));
        }
        let expected_route = probe["route"].as_str().map(|route| route.to_string());

        let (decision_bits, refine_bits) = layout.encode_progressive(&reading);
        let rec = layout.decode_progressive(&decision_bits, &refine_bits).unwrap();

        assert_eq!(layout.cell(&rec), layout.cell(&reading));
        assert_eq!(wire::route_node(&graph, node, &rec), expected_route);
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

    let oob = zeckendorf::encode(layout.routes.len() + 100).expect("encode a large index");
    let err = layout.decode_decision(&oob);
    assert!(err.is_err(), "out-of-range band index must be an error, got {err:?}");
    assert!(err.unwrap_err().contains("outside the layout"));

    // Garbage that isn't a Fibonacci code (no trailing "11") errors cleanly, never panics.
    assert!(layout.decode_decision("101010").is_err());
    // And a valid round-trip still succeeds.
    let corpus_probe = &corpus["probes"][0];
    if let Some(r_obj) = corpus_probe["reading"].as_object() {
        let mut reading = HashMap::new();
        for (field, value) in r_obj {
            reading.insert(field.clone(), V::Num(value.as_f64().unwrap()));
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
        .map(|entry| entry.as_str().unwrap().to_string())
        .collect();
    assert_eq!(layout.fields, corpus_fields);

    let corpus_radices: Vec<usize> = corpus["radices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry.as_u64().unwrap() as usize)
        .collect();
    assert_eq!(layout.radices, corpus_radices);
    assert_eq!(layout.size, corpus["size"].as_u64().unwrap() as usize);

    let got_bands: Vec<Value> = layout
        .routes
        .iter()
        .enumerate()
        .map(|(band, route)| {
            serde_json::json!({
                "route": route,
                "base": layout.band_base[band],
                "width": layout.band_width[band]
            })
        })
        .collect();
    assert_eq!(got_bands, corpus["bands"].as_array().unwrap().clone());

    let got_cells: Vec<Value> = (0..layout.size)
        .map(|spiral_index| {
            serde_json::json!({
                "cell": layout.cell_of[spiral_index],
                "n": spiral_index,
                "band": layout.band_index[&layout.route_of(spiral_index)],
                "route": layout.route_of(spiral_index)
            })
        })
        .collect();
    assert_eq!(got_cells, corpus["cells"].as_array().unwrap().clone());
}

#[test]
fn test_decision_stream_cheaper_than_linear_for_multidim() {
    let corpus = load_corpus();
    let (graph, layout) = layout_from_corpus(&corpus);
    let parts = quantizer::build_partitions(&graph);

    let mut readings = Vec::new();
    for pitch in [0.0, 25.0, 50.0] {
        for roll in [0.0, 25.0, 50.0] {
            for vibration in [0.0, 50.0, 90.0] {
                let mut reading = HashMap::new();
                reading.insert("pitch".to_string(), V::Num(pitch));
                reading.insert("roll".to_string(), V::Num(roll));
                reading.insert("vibration".to_string(), V::Num(vibration));
                readings.push(reading);
            }
        }
    }

    let lin: usize = readings
        .iter()
        .map(|reading| wire::encode_reading(&parts, reading).unwrap().len())
        .sum();
    let dec: usize = readings.iter().map(|reading| layout.encode_decision(reading).len()).sum();
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
            .map(|(field, value)| (field.clone(), V::from_json(value)))
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
        let spiral_index = layout.index(&reading);
        assert_eq!(layout.try_route_of(spiral_index).unwrap(), layout.route_of(spiral_index));
        assert_eq!(layout.try_reconstruct(spiral_index).unwrap(), layout.reconstruct(spiral_index));
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
