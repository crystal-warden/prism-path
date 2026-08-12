//! The frozen-corpus gate: prismpath-fusion-rs replays the SAME
//! `adapters/fusion/conformance/spiral_fusion.json` the Python adapter passes — flow pinned by
//! sha256, the tessellation compared cell-for-cell, the 34 boundary probes replayed through the
//! Rust kernel's routing AND the spiral index (the telemetry-referee, three ways), and the flow
//! itself PROVEN Level M by the prismpath-rs proof layer. Parity is measured, not asserted.

use prismpath_rs::{flow_level_m, parse, V};
use prismpath_telemetry_rs::{spiral::SpiralLayout, wire};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

fn corpus() -> Value {
    let path = format!(
        "{}/../adapters/fusion/conformance/spiral_fusion.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("read spiral_fusion.json"))
        .expect("parse corpus")
}

#[test]
fn flow_hash_pins_and_matches_the_checkout() {
    let c = corpus();
    let flow = c["flow"].as_str().expect("flow");
    let digest = hex::encode(Sha256::digest(flow.as_bytes()));
    assert_eq!(digest, c["flow_sha256"].as_str().unwrap(), "corpus flow_sha256 self-pin");
    // The corpus must also match the flow file in this checkout — drift is loud, not silent.
    let on_disk = std::fs::read_to_string(format!(
        "{}/../adapters/fusion/flows/fusion_triage.md",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("read fusion_triage.md");
    assert_eq!(flow, on_disk, "frozen corpus flow drifted from flows/fusion_triage.md");
}

#[test]
fn fusion_triage_is_proven_level_m_by_the_rust_prover() {
    let c = corpus();
    let g = parse(c["flow"].as_str().unwrap());
    let (lm, bad) = flow_level_m(&g);
    assert!(lm, "fusion_triage must be Level M; non-member edges: {bad:?}");
    assert!(bad.is_empty());
}

#[test]
fn tessellation_matches_the_frozen_corpus_cell_for_cell() {
    let c = corpus();
    let g = parse(c["flow"].as_str().unwrap());
    let node = c["node"].as_str().unwrap();
    let l = SpiralLayout::new(&g, node).expect("layout");

    let fields: Vec<String> =
        c["fields"].as_array().unwrap().iter().map(|f| f.as_str().unwrap().to_string()).collect();
    assert_eq!(l.fields, fields, "field order");
    let radices: Vec<usize> =
        c["radices"].as_array().unwrap().iter().map(|r| r.as_u64().unwrap() as usize).collect();
    assert_eq!(l.radices, radices, "radices");
    assert_eq!(l.size, c["size"].as_u64().unwrap() as usize, "cell count");

    let bands = c["bands"].as_array().unwrap();
    assert_eq!(l.routes.len(), bands.len(), "band count");
    for (i, b) in bands.iter().enumerate() {
        let route = b["route"].as_str().map(|s| s.to_string());
        assert_eq!(l.routes[i], route, "band {i} route");
        assert_eq!(l.band_base[i], b["base"].as_u64().unwrap() as usize, "band {i} base");
        assert_eq!(l.band_width[i], b["width"].as_u64().unwrap() as usize, "band {i} width");
    }

    for cell in c["cells"].as_array().unwrap() {
        let n = cell["n"].as_u64().unwrap() as usize;
        let coords: Vec<usize> =
            cell["cell"].as_array().unwrap().iter().map(|x| x.as_u64().unwrap() as usize).collect();
        assert_eq!(l.cell_of[n], coords, "cell_of[{n}]");
        let route = cell["route"].as_str().map(|s| s.to_string());
        assert_eq!(l.route_of(n), route, "route_of({n})");
        let band = cell["band"].as_u64().unwrap() as usize;
        assert_eq!(l.band_index[&route], band, "band_index of cell {n}");
    }
}

#[test]
fn probes_route_identically_three_ways() {
    let c = corpus();
    let g = parse(c["flow"].as_str().unwrap());
    let node = c["node"].as_str().unwrap();
    let l = SpiralLayout::new(&g, node).expect("layout");

    let probes = c["probes"].as_array().unwrap();
    assert!(!probes.is_empty());
    for p in probes {
        let reading: HashMap<String, V> = p["reading"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), V::from_json(v)))
            .collect();
        let expected = p["route"].as_str().map(|s| s.to_string());

        // (1) direct evaluation — the kernel's field-routing tier
        let direct = wire::route_node(&g, node, &reading);
        assert_eq!(direct, expected, "direct route for {:?}", p["reading"]);

        // (2) quantize -> spiral index -> band -> route (decision preserved through the wire)
        let n = l.index(&reading);
        assert_eq!(l.route_of(n), expected, "spiral-index route for {:?}", p["reading"]);

        // (3) band id agrees with the band the expected route owns
        let band = l.band_id(&reading);
        assert_eq!(l.band_index[&expected], band, "band id for {:?}", p["reading"]);
    }
    eprintln!("fusion probes: {}/{} decisions preserved, three ways", probes.len(), probes.len());
}
