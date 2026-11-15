// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The Merkle tree under the audit log, checked here and not built: the RFC 6962 tree
//! `prismpath/ledgers/ledger_ots.py` builds (`prismpath_rs::merkle` holds the one Rust implementation: a
//! leaf hashes as SHA-256(0x00 || leaf), a node as SHA-256(0x01 || left || right), split at the largest
//! power of two below the count, nothing duplicated; leaves are the SHA-256 of an event's canonical
//! bytes). A root and an inclusion path computed by Python verify here byte for byte, and the reverse.
//!
//! Where the reference raises on malformed input (a leaf or sibling that is not hex) these functions
//! return `Err`, never a quiet `false`, so a damaged proof is told apart from a proof that fails.

use crate::pyval::from_hex;
use prismpath_rs::merkle as tree;
use serde_json::Value;

fn decode(leaf_hex: &str) -> Result<Vec<u8>, String> {
    from_hex(leaf_hex).ok_or_else(|| format!("not a hex string: {leaf_hex:?}"))
}

/// The root over the leaves (each a hex SHA-256), or `""` for none: what
/// `root_statement.merkle_root` returns and an audit log's root statement signs.
pub fn merkle_root(leaves_hex: &[String]) -> Result<String, String> {
    let leaves = leaves_hex.iter().map(|leaf| decode(leaf)).collect::<Result<Vec<_>, _>>()?;
    Ok(tree::root_of_bytes(&leaves).map(hex::encode).unwrap_or_default())
}

/// One step of an inclusion path: the side the sibling sits on and its hex hash. As in the
/// reference, any side other than `"R"` means the sibling is on the left.
pub type PathStep = (String, String);

/// Walk a leaf up its inclusion path and compare with the root (`ledger_ots.verify_leaf`).
pub fn verify_leaf(leaf_hex: &str, path: &[PathStep], root_hex: &str) -> Result<bool, String> {
    let leaf = decode(leaf_hex)?;
    let steps = path
        .iter()
        .map(|(side, sibling)| Ok((side == "R", decode(sibling)?)))
        .collect::<Result<Vec<_>, String>>()?;
    Ok(hex::encode(tree::fold(&leaf, &steps)) == root_hex)
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
    use sha2::{Digest, Sha256};

    fn leaf(index: u8) -> String {
        hex::encode(Sha256::digest([index]))
    }

    fn unhex(text: &str) -> Vec<u8> {
        hex::decode(text).unwrap()
    }

    #[test]
    fn empty_is_the_empty_string_and_one_leaf_is_its_leaf_hash() {
        assert_eq!(merkle_root(&[]).unwrap(), "");
        assert_eq!(merkle_root(&[leaf(1)]).unwrap(), hex::encode(tree::leaf_hash(&unhex(&leaf(1)))));
    }

    #[test]
    fn three_leaves_split_at_two_with_nothing_duplicated() {
        let [a, b, c] = [1, 2, 3].map(|index| tree::leaf_hash(&unhex(&leaf(index))));
        let expected = tree::node_hash(&tree::node_hash(&a, &b), &c);
        assert_eq!(merkle_root(&[leaf(1), leaf(2), leaf(3)]).unwrap(), hex::encode(expected));
        assert_ne!(merkle_root(&[leaf(1), leaf(2), leaf(3)]).unwrap(),
                   merkle_root(&[leaf(1), leaf(2), leaf(3), leaf(3)]).unwrap());
    }

    #[test]
    fn a_path_verifies_and_a_changed_one_does_not() {
        let leaves = [leaf(1), leaf(2), leaf(3)];
        let root = merkle_root(&leaves).unwrap();
        let c = hex::encode(tree::leaf_hash(&unhex(&leaf(3))));
        let b = hex::encode(tree::leaf_hash(&unhex(&leaf(2))));
        let path = vec![("R".to_string(), b.clone()), ("R".to_string(), c.clone())];
        assert!(verify_leaf(&leaf(1), &path, &root).unwrap());
        let wrong_side = vec![("L".to_string(), b), ("R".to_string(), c)];
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
