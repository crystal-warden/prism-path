// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! Sealing: every record the collector drains is a leaf of one RFC 6962 tree per session, kept by
//! `prismpath_rs::merkle::Accumulator` (the streaming form `formal/Core/Merkle.lean` proves equal to the
//! tree). A leaf's bytes are SHA-256 of the record's bytes, the leaf `prismpath-ebpf/merkle.h` gives a
//! receipt, so a selector session's seal is the root `seal_receipts` computes over the same receipts.
//!
//! A seal states the count, the root and the peaks. The peaks with the count are the accumulator's whole
//! state, so a client that joins mid session is sent a seal at the point it joined and can check every
//! later seal from the leaves it receives, without the leaves before it.

use prismpath_rs::merkle::Accumulator;
use serde_json::{json, Value};

/// The most leaves one session seals: past it a count would not be a canon/2 integer.
pub const MAX_LEAVES: u64 = (1 << 53) - 1;

pub struct Sealer {
    acc: Accumulator,
    pub malformed: u64,
    sealed_at: u64,
}

impl Default for Sealer {
    fn default() -> Self {
        Self::new()
    }
}

impl Sealer {
    pub fn new() -> Sealer {
        Sealer { acc: Accumulator::new(), malformed: 0, sealed_at: 0 }
    }

    /// A session that carries on from `acc` (a join seal's peaks, or a test's large count).
    pub fn from_accumulator(acc: Accumulator) -> Sealer {
        let sealed_at = acc.count();
        Sealer { acc, malformed: 0, sealed_at }
    }

    pub fn count(&self) -> u64 {
        self.acc.count()
    }

    /// Add one leaf; false (and nothing added) once the session holds [`MAX_LEAVES`].
    pub fn add(&mut self, leaf: &[u8; 32]) -> bool {
        if self.acc.count() >= MAX_LEAVES {
            return false;
        }
        self.acc.add(leaf).is_ok()
    }

    /// Leaves added since the last [`seal`](Self::seal) that was not a join.
    pub fn unsealed(&self) -> u64 {
        self.acc.count() - self.sealed_at
    }

    /// The seal record of the tree so far. `trigger` says why it was cut: `interval`, `count` and `final`
    /// move the sealed mark; `join` is the state handed to one new client and leaves it.
    pub fn seal(&mut self, source: &str, session: &str, trigger: &str) -> Value {
        if trigger != "join" {
            self.sealed_at = self.acc.count();
        }
        seal_record(&self.acc, source, session, trigger, self.malformed)
    }
}

pub fn seal_record(acc: &Accumulator, source: &str, session: &str, trigger: &str, malformed: u64) -> Value {
    let mut record = json!({
        "kind": "seal",
        "source": source,
        "session": session,
        "trigger": trigger,
        "count": acc.count(),
        "malformed": malformed,
        "peaks": acc.peaks().iter().map(hex::encode).collect::<Vec<_>>(),
    });
    if let Some(root) = acc.root() {
        record["root"] = json!(hex::encode(root));
    }
    record
}
