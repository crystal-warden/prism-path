// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! Daily-chained epochs + retention — bound what the edge stores without losing provability.

use crate::selfheal;
use sha2::{Digest, Sha256};

pub fn chain_root(prev_chained: &str, merkle_root: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev_chained.as_bytes());
    hasher.update(merkle_root.as_bytes());
    hex::encode(hasher.finalize())
}

#[derive(Debug, Clone, PartialEq)]
pub struct Epoch {
    pub id: usize,
    pub blocks: Option<Vec<String>>,
    pub merkle_root: String,
    pub chained_root: String,
    pub acked: bool,
    pub dropped_under_pressure: bool,
}

impl Epoch {
    pub fn has_data(&self) -> bool {
        self.blocks.is_some()
    }
}

#[derive(Debug, Clone)]
pub struct EpochStore {
    pub block_bits: usize,
    pub max_data_epochs: usize,
    pub epochs: Vec<Epoch>,
}

impl EpochStore {
    pub fn new(block_bits: usize, max_data_epochs: usize) -> Self {
        EpochStore {
            block_bits,
            max_data_epochs,
            epochs: Vec::new(),
        }
    }

    pub fn seal(&mut self, bits: &str) -> Epoch {
        // chunk only errs when block_bits == 0, a construction-time misconfiguration (see new()).
        let blocks = selfheal::chunk(bits, self.block_bits).expect("block_bits must be > 0 (set at EpochStore::new)");
        let (merkle_root, _proofs) = selfheal::commit(&blocks);
        let prev = self
            .epochs
            .last()
            .map(|ep| ep.chained_root.as_str())
            .unwrap_or("");
        let chained = chain_root(prev, &merkle_root);
        let ep = Epoch {
            id: self.epochs.len(),
            blocks: Some(blocks),
            merkle_root,
            chained_root: chained,
            acked: false,
            dropped_under_pressure: false,
        };
        self.epochs.push(ep.clone());
        self.enforce_cap();
        // just pushed above, and enforce_cap only nulls `blocks` (never removes epochs) -> non-empty.
        self.epochs.last().expect("epochs non-empty after push").clone()
    }

    pub fn ack(&mut self, chained_root: &str) -> usize {
        let idx = self.epochs.iter().position(|ep| ep.chained_root == chained_root);
        let Some(target_idx) = idx else {
            return 0;
        };
        let mut dropped = 0;
        for ep in &mut self.epochs[..=target_idx] {
            ep.acked = true;
            if ep.has_data() {
                ep.blocks = None;
                dropped += 1;
            }
        }
        dropped
    }

    fn enforce_cap(&mut self) {
        while self.epochs.iter().filter(|ep| ep.has_data()).count() > self.max_data_epochs {
            if let Some(victim) = self.epochs.iter_mut().find(|ep| ep.has_data()) {
                if !victim.acked {
                    victim.dropped_under_pressure = true;
                }
                victim.blocks = None;
            } else {
                break;
            }
        }
    }

    pub fn chain(&self) -> Vec<String> {
        self.epochs.iter().map(|ep| ep.chained_root.clone()).collect()
    }

    pub fn verify_chain(&self) -> bool {
        let mut prev = "";
        for ep in &self.epochs {
            if ep.chained_root != chain_root(prev, &ep.merkle_root) {
                return false;
            }
            prev = &ep.chained_root;
        }
        true
    }

    pub fn retransmittable(&self) -> Vec<usize> {
        self.epochs
            .iter()
            .filter(|ep| ep.has_data())
            .map(|ep| ep.id)
            .collect()
    }

    pub fn gaps(&self) -> Vec<usize> {
        self.epochs
            .iter()
            .filter(|ep| ep.dropped_under_pressure)
            .map(|ep| ep.id)
            .collect()
    }
}
