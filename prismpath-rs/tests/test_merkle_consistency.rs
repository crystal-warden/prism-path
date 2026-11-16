// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! RFC 6962 consistency proofs against the Python reference: replay `tests/fixtures/merkle_consistency.json`
//! (the crate copy of `prismpath/portable/conformance/merkle_consistency.json`, written by
//! `gen_merkle_consistency_fixtures.py`). Every proof the batch `consistency_proof` gives is the one Python
//! gave, byte for byte, and verifies; the streaming `ProofWindow` the collector keeps gives the same proofs
//! from every old size it still holds, with its window full and sliding; and the transparency-dev reference
//! probes verify exactly when they are valid.
#![cfg(feature = "merkle")]

use prismpath_rs::merkle::{consistency_proof, root_of_bytes, verify_consistency, Accumulator, ProofError, ProofWindow, MERKLE_SCHEME};
use serde_json::Value;

fn vectors() -> Value {
    let path = format!("{}/tests/fixtures/merkle_consistency.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).expect("read merkle_consistency.json")).expect("parse merkle_consistency.json")
}

fn unhex(value: &Value) -> Vec<u8> {
    value.as_str().map(|text| hex::decode(text).unwrap()).unwrap_or_default()
}

fn hashes(value: &Value) -> Vec<Vec<u8>> {
    value.as_array().map(|items| items.iter().map(unhex).collect()).unwrap_or_default()
}

fn leaf_hash(leaf: &[u8]) -> [u8; 32] {
    prismpath_rs::merkle::leaf_hash(leaf).try_into().unwrap()
}

struct Case {
    old: u64,
    new: u64,
    old_root: Vec<u8>,
    new_root: Vec<u8>,
    proof: Vec<Vec<u8>>,
}

fn sets() -> Vec<(String, Vec<Vec<u8>>, Vec<Case>)> {
    let doc = vectors();
    assert_eq!(doc["scheme"].as_str(), Some(MERKLE_SCHEME));
    doc["sets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|set| {
            let leaves = hashes(&set["leaves"]);
            let cases = set["proofs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|case| Case {
                    old: case["old"].as_u64().unwrap(),
                    new: case["new"].as_u64().unwrap(),
                    old_root: unhex(&case["old_root"]),
                    new_root: unhex(&case["new_root"]),
                    proof: hashes(&case["proof"]),
                })
                .collect();
            (set["name"].as_str().unwrap().to_string(), leaves, cases)
        })
        .collect()
}

#[test]
fn every_batch_proof_is_the_python_reference_and_verifies() {
    let mut checked = 0u64;
    for (name, leaves, cases) in sets() {
        for case in &cases {
            let new = case.new as usize;
            assert_eq!(root_of_bytes(&leaves[..new]), Some(case.new_root.clone()), "{name}: root at {new}");
            let proof = consistency_proof(&leaves[..new], case.old as usize).unwrap();
            assert_eq!(proof, case.proof, "{name}: proof {} -> {}", case.old, case.new);
            assert!(verify_consistency(case.old, case.new, &case.old_root, &case.new_root, &proof), "{name}: {} -> {}", case.old, case.new);
            if !proof.is_empty() {
                let mut bad = proof.clone();
                bad[0][0] ^= 1;
                assert!(!verify_consistency(case.old, case.new, &case.old_root, &case.new_root, &bad));
            }
            checked += 1;
        }
    }
    assert_eq!(checked, vectors()["counts"]["proofs"].as_u64().unwrap());
}

/// A window of `capacity` leaves started at `base` leaves of the set, fed the rest one at a time; at each
/// count every case ending there whose old size the window still holds is proved and compared.
fn replay_window(leaves: &[Vec<u8>], cases: &[Case], base: usize, capacity: usize) -> u64 {
    let mut start = Accumulator::new();
    for leaf in &leaves[..base] {
        start.add(leaf).unwrap();
    }
    let mut window = ProofWindow::starting_at(start, capacity);
    let mut proved = 0;
    for (count, leaf) in leaves.iter().enumerate().skip(base).map(|(index, leaf)| (index + 1, leaf)) {
        window.add_leaf_hash(&leaf_hash(leaf)).unwrap();
        assert_eq!(window.count(), count as u64);
        assert!(window.base() >= base as u64 && window.count() - window.base() <= capacity as u64);
        for case in cases.iter().filter(|case| case.new == count as u64) {
            let proof = window.proof(case.old);
            if case.old < window.base() {
                assert_eq!(proof, Err(ProofError::OutsideWindow), "{} -> {} under base {}", case.old, case.new, window.base());
                continue;
            }
            let proof: Vec<Vec<u8>> = proof.unwrap().iter().map(|hash| hash.to_vec()).collect();
            assert_eq!(proof, case.proof, "window from {base} (capacity {capacity}): {} -> {}", case.old, case.new);
            // and from the old tree's own state, as the collector keeps it for each client
            let old = window.accumulator_at(case.old).unwrap();
            assert_eq!(old.root().map(|root| root.to_vec()).unwrap_or_default(), case.old_root);
            let again: Vec<Vec<u8>> = window.proof_from(&old).unwrap().iter().map(|hash| hash.to_vec()).collect();
            assert_eq!(again, case.proof);
            proved += 1;
        }
        assert_eq!(window.proof(window.count() + 1), Err(ProofError::Ahead));
    }
    proved
}

#[test]
fn the_streaming_window_gives_the_same_proofs() {
    let mut proved = 0;
    for (name, leaves, cases) in sets() {
        let n = leaves.len();
        for base in [0, 1, 3, n / 3, n / 2] {
            for capacity in [1, 2, 5, 16, 64, n + 1] {
                if base <= n {
                    proved += replay_window(&leaves, &cases, base, capacity);
                }
            }
        }
        assert!(proved > 0, "{name}");
    }
    assert!(proved > 1000, "{proved} window proofs");
}

#[test]
fn the_transparency_dev_probes() {
    let doc = vectors();
    let probes = doc["probes"].as_array().unwrap();
    assert_eq!(probes.len() as u64, doc["counts"]["probes"].as_u64().unwrap());
    for probe in probes {
        let got = verify_consistency(
            probe["old"].as_u64().unwrap(),
            probe["new"].as_u64().unwrap(),
            &unhex(&probe["old_root"]),
            &unhex(&probe["new_root"]),
            &hashes(&probe["proof"]),
        );
        assert_eq!(got, probe["valid"].as_bool().unwrap(), "{}", probe["name"]);
    }
}
