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

/// The most peaks an [`Accumulator`] holds: one per bit of its 64-bit leaf count, so 2 KiB of state.
pub const MAX_PEAKS: usize = 64;

fn leaf_hash_into(leaf: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(leaf);
    hasher.finalize().into()
}

fn node_hash_into(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// The leaf count reached 2^64 - 1, the most a 64-bit count and 64 peaks can hold; the leaf was not added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccumulatorFull;

/// The same root as [`root_of_bytes`], kept as leaves arrive in fixed state: no heap, no recursion.
///
/// It holds the peaks, the roots of the perfect subtrees the leaves so far fall into, one per set bit of
/// the count: `peaks[h]` is the root of a subtree of 2^h leaves when bit h of `count` is set, and unused
/// otherwise. Adding a leaf is binary counter carry: the new leaf hash merges with the peak of each set
/// low bit, the older peak as the left child, and lands at the first clear bit. The root folds the peaks
/// from the shortest up, each taller peak the left child of what is folded so far, which is RFC 6962's
/// split applied once per peak. `formal/Core/Merkle.lean` (`acc_root_eq_mth`) proves this equal to the
/// tree for every nonempty list, and the Python twin is `root_statement.MerkleAccumulator`.
#[derive(Clone)]
pub struct Accumulator {
    peaks: [[u8; 32]; MAX_PEAKS],
    count: u64,
}

impl Default for Accumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl Accumulator {
    /// An accumulator over no leaves.
    pub const fn new() -> Self {
        Self { peaks: [[0u8; 32]; MAX_PEAKS], count: 0 }
    }

    /// How many leaves have been added.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Add a leaf given as its bytes (hashed as SHA-256(0x00 || leaf)).
    pub fn add(&mut self, leaf: &[u8]) -> Result<(), AccumulatorFull> {
        self.add_leaf_hash(&leaf_hash_into(leaf))
    }

    /// Add a leaf given as its leaf hash, SHA-256(0x00 || leaf), already computed.
    pub fn add_leaf_hash(&mut self, leaf_hash: &[u8; 32]) -> Result<(), AccumulatorFull> {
        let next = self.count.checked_add(1).ok_or(AccumulatorFull)?;
        let mut node = *leaf_hash;
        let mut height = 0usize;
        while self.count & (1u64 << height) != 0 {
            node = node_hash_into(&self.peaks[height], &node);
            height += 1;
        }
        // `next` did not overflow, so some bit at or below 63 of `count` is clear and `height` < 64.
        self.peaks[height] = node;
        self.count = next;
        Ok(())
    }

    /// The root over the leaves added so far, or None for none.
    pub fn root(&self) -> Option<[u8; 32]> {
        if self.count == 0 {
            return None;
        }
        let lowest = self.count.trailing_zeros() as usize;
        let mut node = self.peaks[lowest];
        for height in lowest + 1..MAX_PEAKS {
            if self.count & (1u64 << height) != 0 {
                node = node_hash_into(&self.peaks[height], &node);
            }
        }
        Some(node)
    }
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

    fn accumulated(leaves: &[Vec<u8>]) -> Option<Vec<u8>> {
        let mut acc = Accumulator::new();
        for leaf in leaves {
            acc.add(leaf).unwrap();
        }
        acc.root().map(|root| root.to_vec())
    }

    #[test]
    fn the_accumulator_gives_the_known_answer_vectors() {
        let inputs = ["", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"];
        let leaves: Vec<Vec<u8>> = inputs.iter().map(|text| unhex(text)).collect();
        for count in 1..=8 {
            assert_eq!(accumulated(&leaves[..count]), root_of_bytes(&leaves[..count]), "{count} leaves");
        }
        assert_eq!(hex::encode(accumulated(&leaves).unwrap()), "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328");
    }

    #[test]
    fn the_accumulator_equals_the_tree_for_every_count_to_a_thousand() {
        let leaves: Vec<Vec<u8>> = (0..1000u32).map(|index| Sha256::digest(index.to_be_bytes()).to_vec()).collect();
        let mut acc = Accumulator::new();
        assert_eq!(acc.root(), None);
        assert_eq!(root_of_bytes(&leaves[..0]), None);
        for count in 1..=leaves.len() {
            acc.add(&leaves[count - 1]).unwrap();
            assert_eq!(acc.count(), count as u64);
            assert_eq!(acc.root().map(|root| root.to_vec()), root_of_bytes(&leaves[..count]), "{count} leaves");
        }
    }

    #[test]
    fn add_leaf_hash_is_add_after_the_leaf_hash() {
        let mut by_bytes = Accumulator::new();
        let mut by_hash = Accumulator::new();
        for index in 0..37u8 {
            let leaf = vec![index; index as usize];
            by_bytes.add(&leaf).unwrap();
            by_hash.add_leaf_hash(&leaf_hash(&leaf).try_into().unwrap()).unwrap();
            assert_eq!(by_bytes.root(), by_hash.root());
        }
    }

    #[test]
    fn a_full_count_refuses_the_next_leaf_and_keeps_its_root() {
        let mut acc = Accumulator::new();
        acc.count = u64::MAX;
        let before = acc.root();
        assert_eq!(acc.add(b"one more"), Err(AccumulatorFull));
        assert_eq!(acc.count(), u64::MAX);
        assert_eq!(acc.root(), before);
    }

    #[test]
    fn split_points() {
        assert_eq!([2, 3, 4, 5, 8, 9].map(split_point), [1, 2, 2, 4, 4, 8]);
    }
}
