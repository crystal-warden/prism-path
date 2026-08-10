//! Authenticated ACK / retransmission-control channel.

use crate::epochs::EpochStore;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub fn canon(root: &str, seq: i64) -> Vec<u8> {
    format!(r#"{{"root":"{}","seq":{}}}"#, root, seq).into_bytes()
}

pub fn sign_ack(secret: &[u8], root: &str, seq: i64) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC supports keys of any length");
    mac.update(&canon(root, seq));
    hex::encode(mac.finalize().into_bytes())
}

pub fn verify_ack(secret: &[u8], root: &str, seq: i64, tag: &str) -> bool {
    let expected = sign_ack(secret, root, seq);
    expected.eq_ignore_ascii_case(tag)
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

    pub fn on_ack(&mut self, root: &str, seq: i64, tag: &str) -> AckResponse {
        if !verify_ack(&self.secret, root, seq, tag) {
            return AckResponse {
                accepted: false,
                reason: "bad-tag".to_string(),
                dropped: 0,
            };
        }
        if seq <= self.last_seq {
            return AckResponse {
                accepted: false,
                reason: "stale-seq".to_string(),
                dropped: 0,
            };
        }
        self.last_seq = seq;
        let dropped = self.store.ack(root);
        AckResponse {
            accepted: true,
            reason: "ok".to_string(),
            dropped,
        }
    }
}
