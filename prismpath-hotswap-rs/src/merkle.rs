// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The Merkle tree under the audit log, checked here and not built: the same tree
//! `prismpath/ledgers/ledger_ots.py` builds (Bitcoin style, the last node of an odd layer is paired
//! with itself, nodes are SHA-256 of the concatenated child bytes, leaves are the SHA-256 of an
//! event's canonical JSON). A root and an inclusion path computed by Python verify here byte for
//! byte, and the reverse.
//!
//! Where the reference raises on malformed input (a leaf or sibling that is not hex) these functions
//! return `Err`, never a quiet `false`, so a damaged proof is told apart from a proof that fails.

use crate::pyval::from_hex;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn hash_pair(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().to_vec()
}

fn decode(leaf_hex: &str) -> Result<Vec<u8>, String> {
    from_hex(leaf_hex).ok_or_else(|| format!("not a hex string: {leaf_hex:?}"))
}

/// The root over the leaves (each a hex SHA-256), or `""` for none: what
/// `root_statement.merkle_root` returns and an audit log's root statement signs.
pub fn merkle_root(leaves_hex: &[String]) -> Result<String, String> {
    if leaves_hex.is_empty() {
        return Ok(String::new());
    }
    let mut layer = leaves_hex.iter().map(|leaf| decode(leaf)).collect::<Result<Vec<_>, _>>()?;
    while layer.len() > 1 {
        if layer.len() % 2 == 1 {
            let last = layer.last().expect("non-empty").clone();
            layer.push(last);
        }
        layer = layer.chunks(2).map(|pair| hash_pair(&pair[0], &pair[1])).collect();
    }
    Ok(hex::encode(&layer[0]))
}

/// One step of an inclusion path: the side the sibling sits on and its hex hash. As in the
/// reference, any side other than `"R"` means the sibling is on the left.
pub type PathStep = (String, String);

/// Walk a leaf up its inclusion path and compare with the root (`ledger_ots.verify_leaf`).
pub fn verify_leaf(leaf_hex: &str, path: &[PathStep], root_hex: &str) -> Result<bool, String> {
    let mut current = decode(leaf_hex)?;
    for (side, sibling) in path {
        let sibling = decode(sibling)?;
        current = if side == "R" { hash_pair(&current, &sibling) } else { hash_pair(&sibling, &current) };
    }
    Ok(hex::encode(current) == root_hex)
}

/// An inclusion path as it sits in a receipt bundle: a JSON array of `[side, sibling]` pairs.
pub fn path_from_json(path: &Value) -> Result<Vec<PathStep>, String> {
    let steps = path.as_array().ok_or("an inclusion path is a list of [side, sibling] pairs")?;
    steps
        .iter()
        .map(|step| match step.as_array().map(Vec::as_slice) {
            Some([Value::String(side), Value::String(sibling)]) => Ok((side.clone(), sibling.clone())),
            _ => Err(format!("an inclusion path step is a [side, sibling] pair of strings, not {step}")),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(index: u8) -> String {
        hex::encode(Sha256::digest([index]))
    }

    #[test]
    fn empty_is_the_empty_string_and_one_leaf_is_itself() {
        assert_eq!(merkle_root(&[]).unwrap(), "");
        assert_eq!(merkle_root(&[leaf(1)]).unwrap(), leaf(1));
    }

    #[test]
    fn odd_layers_pair_the_last_node_with_itself() {
        let a = hex::decode(leaf(1)).unwrap();
        let b = hex::decode(leaf(2)).unwrap();
        let c = hex::decode(leaf(3)).unwrap();
        let expected = hash_pair(&hash_pair(&a, &b), &hash_pair(&c, &c));
        assert_eq!(merkle_root(&[leaf(1), leaf(2), leaf(3)]).unwrap(), hex::encode(expected));
    }

    #[test]
    fn a_path_verifies_and_a_changed_one_does_not() {
        let leaves = [leaf(1), leaf(2), leaf(3)];
        let root = merkle_root(&leaves).unwrap();
        let sibling = hex::encode(hash_pair(&hex::decode(leaf(3)).unwrap(), &hex::decode(leaf(3)).unwrap()));
        let path = vec![("R".to_string(), leaf(2)), ("R".to_string(), sibling.clone())];
        assert!(verify_leaf(&leaf(1), &path, &root).unwrap());
        let wrong_side = vec![("L".to_string(), leaf(2)), ("R".to_string(), sibling)];
        assert!(!verify_leaf(&leaf(1), &wrong_side, &root).unwrap());
        assert!(!verify_leaf(&leaf(2), &path, &root).unwrap());
    }

    #[test]
    fn malformed_hex_is_an_error_not_a_failed_proof() {
        assert!(verify_leaf("zz", &[], "").is_err());
        assert!(verify_leaf(&leaf(1), &[("R".to_string(), "zz".to_string())], "").is_err());
        assert!(merkle_root(&["zz".to_string()]).is_err());
    }

    #[test]
    fn paths_read_from_json() {
        let ok = serde_json::json!([["R", "ab"], ["L", "cd"]]);
        assert_eq!(path_from_json(&ok).unwrap().len(), 2);
        assert!(path_from_json(&serde_json::json!([["R"]])).is_err());
        assert!(path_from_json(&serde_json::json!("R")).is_err());
    }
}
