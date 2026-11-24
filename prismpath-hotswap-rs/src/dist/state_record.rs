// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The state record (spec-policy-distribution.md, section 15.1), `prismpath/distribution/state_record.py` in
//! Rust: the byte string an enforcement point signs with its instance key after every transition and as its
//! heartbeat (H1 to H4, H9, H10).
//!
//! `build` writes and signs one, `read` checks one against the instance public key it should be signed by
//! and refuses with `fleet:state-invalid` when it does not read or does not verify. Both sides of H1 live
//! here, so the PEP and a reader never disagree on an offset.

use super::{Refused, STATE_INVALID};
use ed25519_dalek::{Signer, SigningKey};
use prismpath_rs::causes;
use sha2::{Digest, Sha256};

pub const MAGIC: &[u8; 4] = b"PPSR";
pub const VERSION: u8 = 1;
pub const PAYLOAD_TYPE: &str = "application/vnd.prismpath.dist-state";
/// H1 `event`, by its code.
pub const EVENTS: [&str; 10] =
    ["beat", "staged", "refused", "committed", "aborted", "trust-applied", "lapsed", "rolled-back", "provisioned", "held"];
/// H1 `status`, its low bits.
pub const STATES: [&str; 3] = ["no-policy", "active", "locked"];
pub const STAGED_BIT: u8 = 0x80;
pub const DEV_BUILD_BIT: u8 = 0x40;
pub const HELD_BIT: u8 = 0x20;
pub const MAX_BODY: usize = 1024;
pub const MAX_EXTENSIONS: usize = 512;
pub const SIGNATURE_SIZE: usize = 64;
/// Bytes 0 to 143, the fixed part.
pub const HEAD_SIZE: usize = 144;

/// The first 16 bytes of a SHA-256 given in hex, or zeros for none.
pub fn prefix(hex64: Option<&str>) -> [u8; 16] {
    let mut out = [0u8; 16];
    if let Some(text) = hex64.filter(|text| !text.is_empty()) {
        if let Ok(raw) = hex::decode(text) {
            let size = raw.len().min(16);
            out[..size].copy_from_slice(&raw[..size]);
        }
    }
    out
}

/// The first 16 bytes of the SHA-256 of a stream name.
pub fn stream_prefix(stream: &str) -> [u8; 16] {
    first16(&Sha256::digest(stream.as_bytes()))
}

/// H1: the PEP id is the first 16 bytes of the SHA-256 of the instance public key.
pub fn pep_id(instance_public: &[u8; 32]) -> [u8; 16] {
    first16(&Sha256::digest(instance_public))
}

fn first16(digest: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

/// One state record, as its fields. Hashes are the 16 byte prefixes H1 carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateRecord {
    pub event: &'static str,
    pub state: &'static str,
    pub cause: Option<String>,
    pub pep_id: [u8; 16],
    pub counter: u64,
    pub time: u64,
    pub stream: [u8; 16],
    pub active_policy: [u8; 16],
    pub active_release: [u8; 16],
    pub active_seq: u64,
    pub floor: u64,
    pub staged_release: [u8; 16],
    pub staged_seq: u64,
    pub trust_seq: u64,
    pub epoch: u64,
    pub staged: bool,
    pub dev_build: bool,
    pub held: bool,
    pub body: Vec<u8>,
    pub extensions: Vec<u8>,
}

impl StateRecord {
    /// A record of `event` in `state` with every other field zero, for a PEP to fill in.
    pub fn new(event: &'static str, state: &'static str) -> StateRecord {
        StateRecord {
            event,
            state,
            cause: None,
            pep_id: [0; 16],
            counter: 0,
            time: 0,
            stream: [0; 16],
            active_policy: [0; 16],
            active_release: [0; 16],
            active_seq: 0,
            floor: 0,
            staged_release: [0; 16],
            staged_seq: 0,
            trust_seq: 0,
            epoch: 0,
            staged: false,
            dev_build: false,
            held: false,
            body: Vec::new(),
            extensions: Vec::new(),
        }
    }

    pub fn status(&self) -> Result<u8, String> {
        let state = STATES.iter().position(|name| *name == self.state).ok_or_else(|| format!("{:?} is not a state", self.state))?;
        Ok(state as u8
            | if self.staged { STAGED_BIT } else { 0 }
            | if self.dev_build { DEV_BUILD_BIT } else { 0 }
            | if self.held { HELD_BIT } else { 0 })
    }

    /// Bytes 0 to 148+m+x, the part the signature covers.
    pub fn unsigned_bytes(&self) -> Result<Vec<u8>, String> {
        if self.event == "refused" && self.cause.is_none() {
            return Err("a refused record carries the cause it was refused with".to_string());
        }
        if self.body.len() > MAX_BODY || self.extensions.len() > MAX_EXTENSIONS {
            return Err("a state record body or extension area beyond its bound".to_string());
        }
        let code = match &self.cause {
            None => 0,
            Some(cause) => causes::code(cause).ok_or_else(|| format!("{cause:?} is not a registered cause"))?,
        };
        let event = EVENTS.iter().position(|name| *name == self.event).ok_or_else(|| format!("{:?} is not an event", self.event))?;
        let mut out = Vec::with_capacity(HEAD_SIZE + 4 + self.body.len() + self.extensions.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&[VERSION, event as u8, self.status()?, code]);
        out.extend_from_slice(&self.pep_id);
        out.extend_from_slice(&self.counter.to_le_bytes());
        out.extend_from_slice(&self.time.to_le_bytes());
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.stream);
        out.extend_from_slice(&self.active_policy);
        out.extend_from_slice(&self.active_release);
        out.extend_from_slice(&self.active_seq.to_le_bytes());
        out.extend_from_slice(&self.floor.to_le_bytes());
        out.extend_from_slice(&self.staged_release);
        out.extend_from_slice(&self.staged_seq.to_le_bytes());
        out.extend_from_slice(&self.trust_seq.to_le_bytes());
        debug_assert_eq!(out.len(), HEAD_SIZE);
        out.extend_from_slice(&(self.body.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.body);
        out.extend_from_slice(&(self.extensions.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.extensions);
        Ok(out)
    }
}

/// H1: the instance key signs the DSSE pre-authentication encoding of the record's bytes with its own
/// payload type.
pub fn signed_message(unsigned: &[u8]) -> Vec<u8> {
    let mut out = format!("DSSEv1 {} {PAYLOAD_TYPE} {} ", PAYLOAD_TYPE.len(), unsigned.len()).into_bytes();
    out.extend_from_slice(unsigned);
    out
}

/// The signed record. `instance_key` is the PEP's own instance key and no other (H2).
pub fn build(record: &StateRecord, instance_key: &SigningKey) -> Result<Vec<u8>, String> {
    let mut unsigned = record.unsigned_bytes()?;
    let signature = instance_key.sign(&signed_message(&unsigned));
    unsigned.extend_from_slice(&signature.to_bytes());
    Ok(unsigned)
}

fn invalid(detail: &str) -> Refused {
    Refused::new(STATE_INVALID, detail)
}

fn u64_at(data: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(data[at..at + 8].try_into().expect("eight bytes"))
}

fn sixteen_at(data: &[u8], at: usize) -> [u8; 16] {
    data[at..at + 16].try_into().expect("sixteen bytes")
}

fn u16_at(data: &[u8], at: usize) -> usize {
    usize::from(u16::from_le_bytes([data[at], data[at + 1]]))
}

/// The record, the bytes its signature covers and the signature.
fn parse(data: &[u8]) -> Result<(StateRecord, &[u8], &[u8]), Refused> {
    if data.len() < HEAD_SIZE + 4 + SIGNATURE_SIZE {
        return Err(invalid("shorter than a state record"));
    }
    let (version, event, status, code) = (data[4], usize::from(data[5]), data[6], data[7]);
    if &data[..4] != MAGIC || version != VERSION || event >= EVENTS.len() || usize::from(status & 0x1F) >= STATES.len() {
        return Err(invalid("magic, version, event or state"));
    }
    if status & 0x1C != 0 {
        return Err(invalid("a status bit this version does not define"));
    }
    let cause = match code {
        0 => None,
        code => Some(causes::name(code).ok_or_else(|| invalid("an unregistered cause"))?.to_string()),
    };
    let m = u16_at(data, HEAD_SIZE);
    if m > MAX_BODY || data.len() < HEAD_SIZE + 2 + m + 2 + SIGNATURE_SIZE {
        return Err(invalid("a body length"));
    }
    let x = u16_at(data, HEAD_SIZE + 2 + m);
    let end = HEAD_SIZE + 4 + m + x;
    if x > MAX_EXTENSIONS || data.len() != end + SIGNATURE_SIZE {
        return Err(invalid("an extension length or a record length"));
    }
    let record = StateRecord {
        event: EVENTS[event],
        state: STATES[usize::from(status & 0x03)],
        cause,
        pep_id: sixteen_at(data, 8),
        counter: u64_at(data, 24),
        time: u64_at(data, 32),
        epoch: u64_at(data, 40),
        stream: sixteen_at(data, 48),
        active_policy: sixteen_at(data, 64),
        active_release: sixteen_at(data, 80),
        active_seq: u64_at(data, 96),
        floor: u64_at(data, 104),
        staged_release: sixteen_at(data, 112),
        staged_seq: u64_at(data, 128),
        trust_seq: u64_at(data, 136),
        staged: status & STAGED_BIT != 0,
        dev_build: status & DEV_BUILD_BIT != 0,
        held: status & HELD_BIT != 0,
        body: data[HEAD_SIZE + 2..HEAD_SIZE + 2 + m].to_vec(),
        extensions: data[HEAD_SIZE + 4 + m..end].to_vec(),
    };
    Ok((record, &data[..end], &data[end..]))
}

/// The PEP id a record names, read before its signature is checked, so a reader can find the enrolled key
/// to check it with (H6 step 1). `fleet:state-invalid` when it does not read.
pub fn named_pep(data: &[u8]) -> Result<[u8; 16], Refused> {
    parse(data).map(|(record, _, _)| record.pep_id)
}

/// H1, H2, H6 step 1: the record in `data`, signed by the instance key whose 32 raw public bytes are
/// `instance_public` and naming that key's PEP id. Anything else is `fleet:state-invalid`.
pub fn read(data: &[u8], instance_public: &[u8; 32]) -> Result<StateRecord, Refused> {
    let (record, unsigned, signature) = parse(data)?;
    if record.pep_id != pep_id(instance_public) {
        return Err(invalid("the record names another PEP"));
    }
    if !crate::verify_ed25519(instance_public, &signed_message(unsigned), signature) {
        return Err(invalid("the signature does not verify under the instance key"));
    }
    Ok(record)
}
