// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! Self-healing transport — Merkle-committed blocks + selective retransmission.

use prismpath_rs::merkle;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Split a bitstream into fixed-size blocks (the retransmit unit). Always >= 1 block.
pub fn chunk(bits: &str, block_bits: usize) -> Result<Vec<String>, String> {
    if block_bits == 0 {
        return Err("block_bits must be positive".to_string());
    }
    if bits.is_empty() {
        return Ok(vec!["".to_string()]);
    }
    let chars: Vec<char> = bits.chars().collect();
    let mut out = Vec::new();
    for chunk in chars.chunks(block_bits) {
        out.push(chunk.iter().collect());
    }
    Ok(out)
}

fn leaf_bytes(block: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(block.as_bytes());
    hasher.finalize().to_vec()
}

/// (root_hex, per-block inclusion proof) over the block hashes: the RFC 6962 tree of `ledger_ots`
/// (`prismpath_rs::merkle`), each leaf the SHA-256 of a block, so it matches the Python byte for byte.
pub fn commit(blocks: &[String]) -> (String, Vec<Vec<(String, String)>>) {
    if blocks.is_empty() {
        return ("".to_string(), vec![]);
    }
    let leaves: Vec<Vec<u8>> = blocks.iter().map(|block| leaf_bytes(block)).collect();
    let (root, paths) = merkle::root_and_paths_of_bytes(&leaves);
    let proofs = paths
        .into_iter()
        .map(|path| path.into_iter().map(|(side, hash)| (side.to_string(), hash)).collect())
        .collect();
    (hex::encode(root.expect("blocks is non-empty")), proofs)
}

pub fn verify_block(block: &str, proof: &[(String, String)], root: &str) -> bool {
    let mut steps = Vec::with_capacity(proof.len());
    for (side, sib) in proof {
        match hex::decode(sib) {
            Ok(bytes) => steps.push((side == "R", bytes)),
            Err(_) => return false,
        }
    }
    hex::encode(merkle::fold(&leaf_bytes(block), &steps)) == root
}

#[derive(Debug, Clone)]
pub struct Sender {
    pub blocks: Vec<String>,
    pub block_bits: usize,
    pub root: String,
    pub proofs: Vec<Vec<(String, String)>>,
}

impl Sender {
    pub fn new(bits: &str, block_bits: usize) -> Result<Self, String> {
        let blocks = chunk(bits, block_bits)?;
        let (root, proofs) = commit(&blocks);
        Ok(Sender {
            blocks,
            block_bits,
            root,
            proofs,
        })
    }

    pub fn n_blocks(&self) -> usize {
        self.blocks.len()
    }

    pub fn serve(&self, idx: usize) -> (String, Vec<(String, String)>) {
        (self.blocks[idx].clone(), self.proofs[idx].clone())
    }
}

#[derive(Debug, Clone)]
pub struct Receiver {
    pub root: String,
    pub n: usize,
    blocks: HashMap<usize, String>,
}

impl Receiver {
    pub fn new(root: String, n_blocks: usize) -> Self {
        Receiver {
            root,
            n: n_blocks,
            blocks: HashMap::new(),
        }
    }

    pub fn accept(&mut self, idx: usize, block: &str, proof: &[(String, String)]) -> bool {
        if idx >= self.n {
            return false;
        }
        if !verify_block(block, proof, &self.root) {
            return false;
        }
        self.blocks.insert(idx, block.to_string());
        true
    }

    pub fn missing(&self) -> Vec<usize> {
        (0..self.n).filter(|i| !self.blocks.contains_key(i)).collect()
    }

    pub fn complete(&self) -> bool {
        self.blocks.len() == self.n
    }

    pub fn assemble(&self) -> Result<String, String> {
        if !self.complete() {
            return Err(format!(
                "cannot assemble: blocks still missing (provable gap): {:?}",
                self.missing()
            ));
        }
        let mut out = String::new();
        for i in 0..self.n {
            out.push_str(&self.blocks[&i]);
        }
        Ok(out)
    }
}

pub fn repair(sender: &Sender, receiver: &mut Receiver) -> Vec<usize> {
    let mut retransmitted = Vec::new();
    for idx in receiver.missing() {
        let (block, proof) = sender.serve(idx);
        if receiver.accept(idx, &block, &proof) {
            retransmitted.push(idx);
        }
    }
    retransmitted
}
