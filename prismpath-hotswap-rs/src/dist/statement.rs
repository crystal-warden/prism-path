// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The controller statement (spec-policy-distribution.md, H9 and H16), `prismpath/distribution/statement.py` in
//! Rust: the one thing the controller key signs.
//!
//! A statement names the present on one stream with an epoch id, and with `fresh` 1 it also carries the end of the
//! controller's trust chain, the highest `seq` the controller holds on the stream and when the statement stops
//! counting for freshness. It is 102 bytes, or 126 with the freshness fields, and it is signed by the controller's
//! instance key over the DSSE pre-authentication encoding of the bytes before the signature, with its own payload
//! type. Integers are little endian.
//!
//! ```text
//! offset  size  field
//! 0       4     magic "PPEP"
//! 4       1     version, 1
//! 5       8     key sequence (K6, K7)
//! 13      16    first 16 bytes of SHA-256 of the stream name
//! 29      8     epoch id
//! 37      1     fresh, 0 or 1
//! 38      8     trust sequence      (fresh 1 only)
//! 46      8     stream seq          (fresh 1 only)
//! 54      8     expires             (fresh 1 only)
//! n       64    Ed25519 signature
//! ```
//!
//! `build` writes and signs one, `parse` reads one without checking its signature (`dist:bad-format` when it does
//! not read), and `verify` answers the statement only when it reads and its signature verifies under the public
//! key given. Whether a PEP takes what a statement says is the PEP's (`Pep::take_statement`). The statement rides
//! in the `offers` answer as `epoch`, in base64url without padding, which `decode_offered` reads and
//! `encode_offered` writes; the frame of type 6 belongs to the frame binding, which this crate does not build.

use super::{Refused, BAD_FORMAT};
use ed25519_dalek::{Signer, SigningKey};

pub const MAGIC: &[u8; 4] = b"PPEP";
pub const VERSION: u8 = 1;
/// H9: the payload type the controller key signs under, apart from the envelope's (S1).
pub const PAYLOAD_TYPE: &str = "application/vnd.prismpath.dist-epoch";
pub const SIGNATURE_SIZE: usize = 64;
const HEAD: usize = 38;
const FRESH_FIELDS: usize = 24;
/// The two lengths of a statement: without and with the freshness fields.
pub const SIZE: usize = HEAD + SIGNATURE_SIZE;
pub const FRESH_SIZE: usize = HEAD + FRESH_FIELDS + SIGNATURE_SIZE;
/// The longest `epoch` member of an `offers` answer read as a statement, as the Python binding bounds it.
pub const OFFERED_MAX: usize = 256;

const _: () = assert!(SIZE == 102 && FRESH_SIZE == 126);

/// One controller statement. `stream` is the 16 byte prefix of SHA-256 of the stream name. The three freshness
/// fields are 0 when `fresh` is false.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Statement {
    pub key_seq: u64,
    pub stream: [u8; 16],
    pub epoch: u64,
    pub fresh: bool,
    pub trust_seq: u64,
    pub stream_seq: u64,
    pub expires: u64,
}

impl Statement {
    /// The bytes before the signature: 38, or 62 with the freshness fields.
    pub fn unsigned_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEAD + FRESH_FIELDS);
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&self.key_seq.to_le_bytes());
        out.extend_from_slice(&self.stream);
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.push(u8::from(self.fresh));
        if self.fresh {
            out.extend_from_slice(&self.trust_seq.to_le_bytes());
            out.extend_from_slice(&self.stream_seq.to_le_bytes());
            out.extend_from_slice(&self.expires.to_le_bytes());
        }
        out
    }
}

/// H9: the controller key signs the DSSE encoding of the statement's bytes with its own payload type.
pub fn signed_message(unsigned: &[u8]) -> Vec<u8> {
    let mut out = format!("DSSEv1 {} {PAYLOAD_TYPE} {} ", PAYLOAD_TYPE.len(), unsigned.len()).into_bytes();
    out.extend_from_slice(unsigned);
    out
}

/// The signed statement. `controller_key` is the controller's instance key (K6, F5).
pub fn build(statement: &Statement, controller_key: &SigningKey) -> Vec<u8> {
    let mut out = statement.unsigned_bytes();
    let signature = controller_key.sign(&signed_message(&out));
    out.extend_from_slice(&signature.to_bytes());
    out
}

fn u64_at(data: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(data[at..at + 8].try_into().expect("eight bytes"))
}

/// (statement, the signed bytes, the signature), or `dist:bad-format`: another length, magic, version or `fresh`
/// byte, or a length that is not the one its `fresh` byte gives.
pub fn parse(data: &[u8]) -> Result<(Statement, &[u8], [u8; SIGNATURE_SIZE]), Refused> {
    if data.len() != SIZE && data.len() != FRESH_SIZE {
        return Err(Refused::new(BAD_FORMAT, format!("a controller statement of {} bytes", data.len())));
    }
    let fresh = data[37];
    let length = if fresh == 1 { FRESH_SIZE } else { SIZE };
    if &data[..4] != MAGIC || data[4] != VERSION || fresh > 1 || data.len() != length {
        return Err(Refused::new(BAD_FORMAT, "a controller statement's magic, version, fresh byte or length"));
    }
    let mut stream = [0u8; 16];
    stream.copy_from_slice(&data[13..29]);
    let mut statement =
        Statement { key_seq: u64_at(data, 5), stream, epoch: u64_at(data, 29), fresh: fresh == 1, ..Statement::default() };
    if statement.fresh {
        statement.trust_seq = u64_at(data, 38);
        statement.stream_seq = u64_at(data, 46);
        statement.expires = u64_at(data, 54);
    }
    let end = data.len() - SIGNATURE_SIZE;
    let signature: [u8; SIGNATURE_SIZE] = data[end..].try_into().expect("64 bytes");
    Ok((statement, &data[..end], signature))
}

/// The statement in `data` when it reads and its signature verifies under `controller_public`, the 32 raw bytes of
/// the controller key, else None. A statement with no key to check it against is None (K6).
pub fn verify(data: &[u8], controller_public: Option<&[u8; 32]>) -> Option<Statement> {
    let public = controller_public?;
    let (statement, unsigned, signature) = parse(data).ok()?;
    crate::verify_ed25519(public, &signed_message(unsigned), &signature).then_some(statement)
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// H9: a statement as the `epoch` member of an `offers` answer, base64url without padding.
pub fn encode_offered(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let bits = chunk.iter().enumerate().fold(0u32, |bits, (at, byte)| bits | (u32::from(*byte) << (16 - 8 * at)));
        for at in 0..=chunk.len() {
            out.push(char::from(ALPHABET[((bits >> (18 - 6 * at)) & 63) as usize]));
        }
    }
    out
}

/// H9: the statement in the `epoch` member of an `offers` answer, or None when the member is not one: empty, longer
/// than 256 characters, or not base64url without padding. An epoch id that comes with no statement is not one. This
/// reads strictly, where Python's decoder passes over characters outside the alphabet, so a member Python reads may
/// be none here; DIVERGENCES.md says so.
pub fn decode_offered(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.is_empty() || bytes.len() > OFFERED_MAX || bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut bits = 0u32;
        for (at, byte) in chunk.iter().enumerate() {
            let value = ALPHABET.iter().position(|letter| letter == byte)?;
            bits |= (value as u32) << (18 - 6 * at);
        }
        let whole = chunk.len() - 1;
        for at in 0..whole {
            out.push((bits >> (16 - 8 * at)) as u8);
        }
        // the bits past the last whole byte are zeros in the one spelling of these bytes
        if whole < 3 && bits & ((1 << (24 - 8 * whole)) - 1) != 0 {
            return None;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn a_statement_is_102_or_126_bytes_and_reads_back() {
        let short = Statement { key_seq: 3, stream: [1; 16], epoch: 9, ..Statement::default() };
        let fresh = Statement { fresh: true, trust_seq: 4, stream_seq: 5, expires: 1_800_000_000, ..short };
        let (short_bytes, fresh_bytes) = (build(&short, &key()), build(&fresh, &key()));
        assert_eq!((short_bytes.len(), fresh_bytes.len()), (102, 126));
        assert_eq!(&short_bytes[..4], b"PPEP");
        let public = key().verifying_key().to_bytes();
        assert_eq!(verify(&short_bytes, Some(&public)), Some(short));
        assert_eq!(verify(&fresh_bytes, Some(&public)), Some(fresh));
        assert_eq!(verify(&fresh_bytes, None), None);
        assert_eq!(verify(&fresh_bytes, Some(&SigningKey::from_bytes(&[8u8; 32]).verifying_key().to_bytes())), None);
    }

    #[test]
    fn a_statement_that_does_not_read_is_refused() {
        let short = build(&Statement { epoch: 1, ..Statement::default() }, &key());
        let fresh = build(&Statement { epoch: 1, fresh: true, ..Statement::default() }, &key());
        let mut wrong_fresh = short.clone();
        wrong_fresh[37] = 1;
        let mut two = short.clone();
        two[37] = 2;
        let mut short_marked = fresh.clone();
        short_marked[37] = 0;
        for broken in [
            short[..101].to_vec(),
            [short.as_slice(), &[0]].concat(),
            [b"PPEX".as_slice(), &short[4..]].concat(),
            [&short[..4], &[2], &short[5..]].concat(),
            wrong_fresh,
            two,
            short_marked,
        ] {
            assert_eq!(parse(&broken).unwrap_err().cause, BAD_FORMAT);
            assert_eq!(verify(&broken, Some(&key().verifying_key().to_bytes())), None);
        }
        let mut changed = short.clone();
        changed[30] ^= 1;
        assert!(parse(&changed).is_ok());
        assert_eq!(verify(&changed, Some(&key().verifying_key().to_bytes())), None);
    }

    #[test]
    fn the_offered_form_is_base64url_without_padding() {
        for length in 0..8 {
            let data: Vec<u8> = (0..length).map(|at| (at * 37 + 250) as u8).collect();
            let text = encode_offered(&data);
            assert!(!text.contains('='));
            if length > 0 {
                assert_eq!(decode_offered(&text), Some(data));
            }
        }
        let statement = build(&Statement { epoch: 5, ..Statement::default() }, &key());
        assert_eq!(decode_offered(&encode_offered(&statement)), Some(statement));
        for bad in ["", "A", "AB=", "AB+/", "AB C", "AF", "AAB", &"A".repeat(257)] {
            assert_eq!(decode_offered(bad), None, "{bad}");
        }
        assert_eq!(decode_offered("AA"), Some(vec![0]));
        assert_eq!(decode_offered("_-8"), Some(vec![0xff, 0xef]));
    }
}
