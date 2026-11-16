// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The streaming Merkle root against the Python reference: replay `tests/fixtures/merkle_stream.json`
//! (the crate copy of `prismpath/portable/conformance/merkle_stream.json`, written by
//! `gen_merkle_stream_fixtures.py`), feeding each set's leaves to an `Accumulator` one at a time and
//! requiring, after every leaf, the root Python's batch tree gave over that prefix, byte for byte; and the
//! batch `root_of_bytes` over every prefix too.
#![cfg(feature = "merkle")]

use prismpath_rs::merkle::{root_of_bytes, Accumulator, MERKLE_SCHEME};
use serde_json::Value;

fn vectors() -> Value {
    let path = format!("{}/tests/fixtures/merkle_stream.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).expect("read merkle_stream.json")).expect("parse merkle_stream.json")
}

#[test]
fn every_prefix_root_matches_the_python_reference() {
    let doc = vectors();
    assert_eq!(doc["scheme"].as_str(), Some(MERKLE_SCHEME));
    let sets = doc["sets"].as_array().unwrap();
    assert_eq!(sets.iter().map(|set| set["name"].as_str().unwrap()).collect::<Vec<_>>(), ["rfc6962", "hash_leaves", "varied_lengths"]);
    let mut checked = 0;
    for set in sets {
        let name = set["name"].as_str().unwrap();
        let leaves: Vec<Vec<u8>> = set["leaves"].as_array().unwrap().iter().map(|leaf| hex::decode(leaf.as_str().unwrap()).unwrap()).collect();
        let roots = set["roots"].as_array().unwrap();
        assert_eq!(roots.len(), leaves.len() + 1, "{name}");
        let mut acc = Accumulator::new();
        assert!(roots[0].is_null() && acc.root().is_none() && root_of_bytes(&[]).is_none(), "{name}");
        for (count, leaf) in leaves.iter().enumerate().map(|(index, leaf)| (index + 1, leaf)) {
            acc.add(leaf).unwrap();
            let expected = roots[count].as_str().unwrap();
            assert_eq!(acc.root().map(hex::encode).as_deref(), Some(expected), "{name}: accumulator at {count} leaves");
            assert_eq!(root_of_bytes(&leaves[..count]).map(hex::encode).as_deref(), Some(expected), "{name}: tree at {count} leaves");
            checked += 1;
        }
    }
    assert_eq!(checked, 8 + 300 + 70);
}
