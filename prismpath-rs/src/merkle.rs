// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The Merkle tree every PrismPath ledger shares, the Rust twin of `prismpath/ledgers/ledger_ots.py`:
//! RFC 6962's (Certificate Transparency, section 2.1). A leaf hashes as SHA-256(0x00 || leaf), an inner
//! node as SHA-256(0x01 || left || right), and a tree over n leaves splits at k, the largest power of two
//! below n, with nothing duplicated, so [a, b, c] and [a, b, c, c] have different roots and no leaf can be
//! presented as a node. The audit log, root statements, core runs, the context ledger and the self healing
//! transport all build this one tree; a root or an inclusion path computed in Python verifies here byte for
//! byte, and the reverse.
//!
//! The tree before it (Bitcoin style: no prefixes, the last node of an odd layer paired with itself) is
//! retired, and the formats that carry these roots were bumped with it.

use sha2::{Digest, Sha256};

/// The scheme name the formats that carry these roots stand for (`ledger_ots.MERKLE_SCHEME`).
pub const MERKLE_SCHEME: &str = "rfc6962-sha256";

/// SHA-256(0x00 || leaf): the hash of a leaf's bytes.
pub fn leaf_hash(leaf: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(leaf);
    hasher.finalize().to_vec()
}

/// SHA-256(0x01 || left || right): the hash of an inner node.
pub fn node_hash(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().to_vec()
}

/// RFC 6962's k for a tree over `count` (at least 2) leaves: the largest power of two below it.
pub fn split_point(count: usize) -> usize {
    debug_assert!(count >= 2);
    1usize << (usize::BITS - 1 - (count - 1).leading_zeros())
}

fn subtree_root(hashes: &[Vec<u8>]) -> Vec<u8> {
    if hashes.len() == 1 {
        return hashes[0].clone();
    }
    let k = split_point(hashes.len());
    node_hash(&subtree_root(&hashes[..k]), &subtree_root(&hashes[k..]))
}

/// One step of an inclusion path: `'R'` when the sibling is on the right, `'L'` when on the left, and the
/// sibling's hash in hex.
pub type Step = (char, String);

fn subtree(hashes: &[Vec<u8>]) -> (Vec<u8>, Vec<Vec<Step>>) {
    if hashes.len() == 1 {
        return (hashes[0].clone(), vec![Vec::new()]);
    }
    let k = split_point(hashes.len());
    let (left, left_paths) = subtree(&hashes[..k]);
    let (right, right_paths) = subtree(&hashes[k..]);
    let mut paths = Vec::with_capacity(hashes.len());
    for mut path in left_paths {
        path.push(('R', hex::encode(&right)));
        paths.push(path);
    }
    for mut path in right_paths {
        path.push(('L', hex::encode(&left)));
        paths.push(path);
    }
    (node_hash(&left, &right), paths)
}

/// The root over leaves given as their bytes, or None for none (RFC 6962 MTH).
pub fn root_of_bytes(leaves: &[Vec<u8>]) -> Option<Vec<u8>> {
    if leaves.is_empty() {
        return None;
    }
    let hashes: Vec<Vec<u8>> = leaves.iter().map(|leaf| leaf_hash(leaf)).collect();
    Some(subtree_root(&hashes))
}

/// The root and an inclusion path per leaf over leaves given as their bytes, or (None, []) for none.
pub fn root_and_paths_of_bytes(leaves: &[Vec<u8>]) -> (Option<Vec<u8>>, Vec<Vec<Step>>) {
    if leaves.is_empty() {
        return (None, Vec::new());
    }
    let hashes: Vec<Vec<u8>> = leaves.iter().map(|leaf| leaf_hash(leaf)).collect();
    let (root, paths) = subtree(&hashes);
    (Some(root), paths)
}

/// Fold a leaf's bytes up its path; the root it reaches.
pub fn fold(leaf: &[u8], path: &[(bool, Vec<u8>)]) -> Vec<u8> {
    let mut current = leaf_hash(leaf);
    for (sibling_on_right, sibling) in path {
        current = if *sibling_on_right { node_hash(&current, sibling) } else { node_hash(sibling, &current) };
    }
    current
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(text: &str) -> Vec<u8> {
        hex::decode(text).unwrap()
    }

    /// RFC 6962's own construction over the eight inputs of the Certificate Transparency test vectors
    /// (the reference Go and C++ implementations' `merkle_tree_test`), the roots of the first n for n = 1..8.
    #[test]
    fn known_answer_vectors() {
        let inputs = ["", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"];
        let roots = [
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
            "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
            "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
            "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
            "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
            "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
        ];
        let leaves: Vec<Vec<u8>> = inputs.iter().map(|text| unhex(text)).collect();
        for count in 1..=8 {
            assert_eq!(hex::encode(root_of_bytes(&leaves[..count]).unwrap()), roots[count - 1], "{count} leaves");
        }
    }

    #[test]
    fn a_repeated_last_leaf_changes_the_root() {
        let leaves: Vec<Vec<u8>> = [b"a", b"b", b"c"].iter().map(|leaf| Sha256::digest(leaf).to_vec()).collect();
        let mut four = leaves.clone();
        four.push(leaves[2].clone());
        assert_ne!(root_of_bytes(&leaves), root_of_bytes(&four));
    }

    #[test]
    fn every_path_folds_to_the_root_for_odd_and_even_sizes() {
        for count in 1..=40usize {
            let leaves: Vec<Vec<u8>> = (0..count).map(|index| Sha256::digest([index as u8]).to_vec()).collect();
            let (root, paths) = root_and_paths_of_bytes(&leaves);
            let root = root.unwrap();
            assert_eq!(Some(root.clone()), root_of_bytes(&leaves));
            for (leaf, path) in leaves.iter().zip(&paths) {
                let steps: Vec<(bool, Vec<u8>)> = path.iter().map(|(side, hash)| (*side == 'R', unhex(hash))).collect();
                assert_eq!(fold(leaf, &steps), root, "{count} leaves");
            }
        }
    }

    #[test]
    fn split_points() {
        assert_eq!([2, 3, 4, 5, 8, 9].map(split_point), [1, 2, 2, 4, 4, 8]);
    }
}
