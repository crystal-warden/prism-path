// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! Authenticated ACK / retransmission-control channel.

use crate::epochs::EpochStore;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// The refusal of a value that has no canon/2 form: a sequence number beyond plus or minus 2^53 minus 1.
/// `prismpath.canon.EncodingError` raises the same refusal in Python, so a caller handles it, it is never a panic.
pub use prismpath_rs::durable::CanonicalError;

/// What an ACK's tag covers: the canon/2 domain and the canon/2 bytes of
/// `{"encoding": "canon/2", "root": root, "seq": seq}` (`ackchannel._canon` in Python). A `seq` beyond
/// plus or minus 2^53 minus 1 has no canon/2 form and is refused with `CanonicalError`.
pub fn canon(root: &str, seq: i64) -> Result<Vec<u8>, CanonicalError> {
    let doc = serde_json::json!({"encoding": prismpath_rs::durable::CANON2, "root": root, "seq": seq});
    let mut message = prismpath_rs::durable::CANON2_DOMAIN.to_vec();
    message.extend(prismpath_rs::durable::canon2_bytes(&doc)?);
    Ok(message)
}

/// The tag of an ACK. A `seq` with no canon/2 form is refused with `CanonicalError`.
pub fn sign_ack(secret: &[u8], root: &str, seq: i64) -> Result<String, CanonicalError> {
    let mut mac = HmacSha256::new_from_slice(secret).map_err(|error| CanonicalError(error.to_string()))?;
    mac.update(&canon(root, seq)?);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// Whether `tag` is the tag of this ACK. A `seq` with no canon/2 form is refused with `CanonicalError`, as
/// Python's `verify_ack` raises, rather than answered `false` or panicked on.
pub fn verify_ack(secret: &[u8], root: &str, seq: i64, tag: &str) -> Result<bool, CanonicalError> {
    let expected = sign_ack(secret, root, seq)?;
    Ok(expected.eq_ignore_ascii_case(tag))
}

#[derive(Debug, Clone, PartialEq)]
pub struct AckResponse {
    pub accepted: bool,
    pub reason: String,
    pub dropped: usize,
}

#[derive(Debug, Clone)]
pub struct AckReceiver {
    pub store: EpochStore,
    pub secret: Vec<u8>,
    pub last_seq: i64,
}

impl AckReceiver {
    pub fn new(store: EpochStore, secret: &[u8]) -> Self {
        AckReceiver {
            store,
            secret: secret.to_vec(),
            last_seq: -1,
        }
    }

    /// Apply an ACK. A `seq` beyond plus or minus 2^53 minus 1 is refused with `CanonicalError` (Python raises
    /// `EncodingError`), and nothing is dropped or recorded.
    pub fn on_ack(&mut self, root: &str, seq: i64, tag: &str) -> Result<AckResponse, CanonicalError> {
        if !verify_ack(&self.secret, root, seq, tag)? {
            return Ok(AckResponse {
                accepted: false,
                reason: "bad-tag".to_string(),
                dropped: 0,
            });
        }
        if seq <= self.last_seq {
            return Ok(AckResponse {
                accepted: false,
                reason: "stale-seq".to_string(),
                dropped: 0,
            });
        }
        self.last_seq = seq;
        let dropped = self.store.ack(root);
        Ok(AckResponse {
            accepted: true,
            reason: "ok".to_string(),
            dropped,
        })
    }
}
