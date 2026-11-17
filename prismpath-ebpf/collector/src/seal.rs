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
//!
//! Every seal after the first a client is sent also carries `consistency`: the RFC 6962 consistency proof
//! from the count of the last seal that client was sent to this one, so a client that missed records (a
//! `gap`) or reconnected proves the new tree holds the one it verified. The proofs come from a
//! [`ProofWindow`]: the tree's state at the window's base and the leaf hashes since, at most
//! `proof_window` of them (32 bytes each, 2 MiB at the default 65,536), so the collector's memory stays
//! bounded however long the session runs. An old size before the window is named (`missing: "window"`),
//! never guessed at.

use prismpath_rs::merkle::{Accumulator, ProofError, ProofWindow};
use serde_json::{json, Value};

/// The most leaves one session seals: past it a count would not be a canon/2 integer.
pub const MAX_LEAVES: u64 = (1 << 53) - 1;

/// The leaf hashes the collector keeps for consistency proofs by default: 2 MiB, 64 count seals at the
/// default seal count.
pub const DEFAULT_PROOF_WINDOW: usize = 1 << 16;

pub struct Sealer {
    acc: Accumulator,
    window: ProofWindow,
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
        Sealer::from_accumulator_with_window(Accumulator::new(), DEFAULT_PROOF_WINDOW)
    }

    /// A session that carries on from `acc` (a join seal's peaks, or a test's large count).
    pub fn from_accumulator(acc: Accumulator) -> Sealer {
        Sealer::from_accumulator_with_window(acc, DEFAULT_PROOF_WINDOW)
    }

    /// A session that carries on from `acc`, keeping `window` leaf hashes for consistency proofs.
    pub fn from_accumulator_with_window(acc: Accumulator, window: usize) -> Sealer {
        let sealed_at = acc.count();
        Sealer { window: ProofWindow::starting_at(acc.clone(), window), acc, malformed: 0, sealed_at }
    }

    pub fn count(&self) -> u64 {
        self.acc.count()
    }

    /// The tree's state now.
    pub fn accumulator(&self) -> &Accumulator {
        &self.acc
    }

    /// The tree's state at an earlier count the window still holds.
    pub fn accumulator_at(&self, count: u64) -> Option<Accumulator> {
        self.window.accumulator_at(count)
    }

    /// Add one leaf; false (and nothing added) once the session holds [`MAX_LEAVES`].
    pub fn add(&mut self, leaf: &[u8; 32]) -> bool {
        if self.acc.count() >= MAX_LEAVES {
            return false;
        }
        let hash: [u8; 32] = prismpath_rs::merkle::leaf_hash(leaf).try_into().expect("a leaf hash is 32 bytes");
        if self.acc.add_leaf_hash(&hash).is_err() {
            return false;
        }
        self.window.add_leaf_hash(&hash).expect("the window counts what the accumulator counts");
        true
    }

    /// Leaves added since the last sealing seal (any but a join).
    pub fn unsealed(&self) -> u64 {
        self.acc.count() - self.sealed_at
    }

    /// Mark the tree sealed at its count, for a seal that is not a join.
    pub fn mark(&mut self, trigger: &str) {
        if trigger != "join" {
            self.sealed_at = self.acc.count();
        }
    }

    /// The seal record of the tree so far, with no consistency member (a client's first seal). `trigger`
    /// says why it was cut: `interval`, `count` and `final` move the sealed mark; `join` leaves it.
    pub fn seal(&mut self, source: &str, session: &str, trigger: &str) -> Value {
        self.mark(trigger);
        seal_record(&self.acc, source, session, trigger, self.malformed)
    }

    /// The seal record for a client whose last seal was the tree at `prior` (None: it has had none): the
    /// proof from there to now, or the reason there is none. Does not move the sealed mark.
    pub fn seal_for(&self, prior: Option<&Accumulator>, source: &str, session: &str, trigger: &str) -> Value {
        let mut record = seal_record(&self.acc, source, session, trigger, self.malformed);
        if let Some(prior) = prior {
            let proof = if prior.count() == 0 { Ok(Vec::new()) } else { self.window.proof_from(prior) };
            record["consistency"] = self.consistency(prior.count(), proof);
        }
        record
    }

    /// The join seal for a client that resumes at `count` leaves of this session.
    pub fn seal_resumed(&self, count: u64, source: &str, session: &str) -> Value {
        let mut record = seal_record(&self.acc, source, session, "join", self.malformed);
        // Every tree extends the empty one, whatever the window holds.
        let proof = if count == 0 { Ok(Vec::new()) } else { self.window.proof(count) };
        record["consistency"] = self.consistency(count, proof);
        record
    }

    fn consistency(&self, from: u64, proof: Result<Vec<[u8; 32]>, ProofError>) -> Value {
        match proof {
            Ok(proof) => json!({"from": from, "proof": proof.iter().map(hex::encode).collect::<Vec<_>>()}),
            Err(ProofError::Ahead) => json!({"from": from, "missing": "ahead"}),
            Err(ProofError::OutsideWindow) => json!({"from": from, "missing": "window"}),
        }
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
