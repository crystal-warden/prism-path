//! Self-healing transport — Merkle-committed blocks + selective retransmission.

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

fn leaf_hash(block: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(block.as_bytes());
    hex::encode(hasher.finalize())
}

/// (root_hex, per-block inclusion proof) over block hashes — reproduces ledger_ots's Merkle tree byte-for-byte.
pub fn commit(blocks: &[String]) -> (String, Vec<Vec<(String, String)>>) {
    if blocks.is_empty() {
        return ("".to_string(), vec![]);
    }
    let leaves_hex: Vec<String> = blocks.iter().map(|b| leaf_hash(b)).collect();
    let mut layers: Vec<Vec<Vec<u8>>> = vec![leaves_hex
        .iter()
        .map(|h| hex::decode(h).expect("valid hex"))
        .collect()];

    while layers.last().unwrap().len() > 1 {
        let mut cur = layers.last().unwrap().clone();
        if cur.len() % 2 == 1 {
            let last = cur.last().unwrap().clone();
            cur.push(last);
        }
        let mut next_layer = Vec::new();
        for i in (0..cur.len()).step_by(2) {
            let mut hasher = Sha256::new();
            hasher.update(&cur[i]);
            hasher.update(&cur[i + 1]);
            next_layer.push(hasher.finalize().to_vec());
        }
        layers.push(next_layer);
    }

    let root = hex::encode(&layers.last().unwrap()[0]);

    let mut proofs = Vec::new();
    for idx in 0..blocks.len() {
        let mut path = Vec::new();
        let mut cur_idx = idx;
        for layer in layers.iter().take(layers.len() - 1) {
            let mut layer_l = layer.clone();
            if layer_l.len() % 2 == 1 {
                let last = layer_l.last().unwrap().clone();
                layer_l.push(last);
            }
            if cur_idx % 2 == 0 {
                path.push(("R".to_string(), hex::encode(&layer_l[cur_idx + 1])));
            } else {
                path.push(("L".to_string(), hex::encode(&layer_l[cur_idx - 1])));
            }
            cur_idx /= 2;
        }
        proofs.push(path);
    }

    (root, proofs)
}

pub fn verify_block(block: &str, proof: &[(String, String)], root: &str) -> bool {
    let leaf_hex = leaf_hash(block);
    let mut cur = match hex::decode(leaf_hex) {
        Ok(c) => c,
        Err(_) => return false,
    };

    for (side, sib) in proof {
        let s = match hex::decode(sib) {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
        let mut hasher = Sha256::new();
        if side == "R" {
            hasher.update(&cur);
            hasher.update(&s);
        } else {
            hasher.update(&s);
            hasher.update(&cur);
        }
        cur = hasher.finalize().to_vec();
    }

    hex::encode(&cur) == root
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
