// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The distribution envelope (spec-policy-distribution.md, section 4), `prismpath/distribution/envelope.py`
//! in Rust: the canon/2 document that names one artifact body by hash, the bytes a signature covers,
//! and the sealed envelope, one byte string on every transport.
//!
//! `read` is the reader of E1, E2, E5 and E8 and refuses with the registered cause. `EnvelopeDoc::to_bytes`
//! and `build` write an envelope and refuse one a reader would refuse. `release_id` is E10 and
//! `envelope_id` E3. `signed_message` is the DSSE pre-authentication encoding a signature covers (S1).
//! `seal` and `unseal` are the container of S2, signatures first. Nothing here decides whether an
//! envelope is trusted. That is `verify::verify`.

use super::{
    is_stream, load, require, ArtifactKind, Canon2Tag, DistFormat, Hex64, MaybeHex64, Meta, Refused, SortedSet,
    TargetKind, BAD_FORMAT, MAX_SEQ,
};
use ed25519_dalek::{Signer, SigningKey};
use prismpath_rs::canon2::{codec, Doc};
use serde::{Deserialize, Serialize};

pub const PAYLOAD_TYPE: &str = "application/vnd.prismpath.dist+json"; // S1, S7
pub const MAGIC: &[u8; 4] = b"PPDE";
pub const CONTAINER_VERSION: u8 = 1;
pub const MAX_ENVELOPE: usize = 2048; // E6
pub const MAX_ENTRIES: usize = 4; // S2
pub const MAX_BODY: i64 = 16_777_215; // E1 body_size
pub const TRUST_STREAM: &str = "@trust";
pub const KEY_ID_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 64;
pub const ENTRY_SIZE: usize = KEY_ID_SIZE + SIGNATURE_SIZE;
const HEADER_SIZE: usize = 6; // magic, container version, k
const LENGTH_SIZE: usize = 2; // n, after the k entries
/// B9: nothing past 2,440 bytes is read.
pub const MAX_SEALED: usize = HEADER_SIZE + ENTRY_SIZE * MAX_ENTRIES + LENGTH_SIZE + MAX_ENVELOPE;

/// K: the key id is the SHA-256 of the 32 raw public bytes.
pub fn key_id(public_raw: &[u8; 32]) -> Hex64 {
    Hex64::of(public_raw)
}

/// E3: the SHA-256 of the envelope bytes. Signatures are not part of it.
pub fn envelope_id(envelope_bytes: &[u8]) -> Hex64 {
    Hex64::of(envelope_bytes)
}

/// E10: the SHA-256 of the canon/2 bytes of the sorted `[artifact, body_sha256]` pairs of every artifact
/// in the release. The signer computes it over the whole release. A trust kind is never one of them: a
/// `trust.widening` envelope binds to its release by carrying the same `release` (E7).
pub fn release_id(artifacts: &[(ArtifactKind, Hex64)]) -> Result<Hex64, Refused> {
    let mut pairs: Vec<(&str, &str)> = artifacts.iter().map(|(artifact, body)| (artifact.name(), body.as_str())).collect();
    pairs.sort_unstable();
    require(!pairs.is_empty() && pairs.windows(2).all(|pair| pair[0].0 != pair[1].0), "a release names each artifact once")?;
    require(artifacts.iter().all(|(artifact, _)| artifact.may_be_installed()), "a release id names no trust kind")?;
    let bytes = codec::to_bytes(&pairs).map_err(|error| Refused::new(BAD_FORMAT, error.to_string()))?;
    Ok(Hex64::of(&bytes))
}

/// The fifteen members of E1, as the document is written. The field list is the member list: a member
/// missing or extra, or a value of another kind, does not read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeDoc {
    pub artifact: ArtifactKind,
    pub body_sha256: Hex64,
    pub body_size: i64,
    pub encoding: Canon2Tag,
    pub expires: i64,
    pub format: DistFormat,
    pub meta: Doc,
    pub not_before: i64,
    pub policy_sha256: Hex64,
    pub release: Hex64,
    pub replaces: MaybeHex64,
    pub seq: i64,
    pub stream: String,
    pub targets: SortedSet<TargetKind>,
    pub widens: bool,
}

impl EnvelopeDoc {
    /// The rules of E1 and E5 a member's type does not carry.
    fn check(&self) -> Result<(), Refused> {
        require(!self.targets.is_empty(), "targets is empty")?;
        require((0..=MAX_BODY).contains(&self.body_size), "body_size")?;
        require((1..=MAX_SEQ).contains(&self.seq), "seq")?;
        require((0..=MAX_SEQ).contains(&self.not_before) && (0..=MAX_SEQ).contains(&self.expires), "a time member")?;
        let trust_stream = self.stream == TRUST_STREAM;
        require(is_stream(&self.stream) || trust_stream, "stream")?;
        require(
            !trust_stream || (self.policy_sha256 == Hex64::zero() && self.release == Hex64::zero()),
            "a @trust envelope's policy_sha256 and release are 64 zeros",
        )?;
        if self.artifact.is_trust() || self.artifact.is_install() {
            require(self.expires == 0, "a trust or an install kind's expires is 0")?; // E5, X4, IS1
        } else {
            require(self.expires > self.not_before, "expires is not above not_before")?; // E5
        }
        Ok(())
    }

    /// E1 and E11 `meta`: the members section 3 lists for the artifact, each in its form, read as the
    /// artifact's own type.
    fn read_meta(&self) -> Result<Meta, Refused> {
        (self.artifact.row().meta)(self.meta.clone())
            .map_err(|error| Refused::new(BAD_FORMAT, format!("meta for {} ({error})", self.artifact)))
    }

    /// The canon/2 bytes of the envelope. A writer refuses every envelope `read` would refuse, so
    /// nothing it writes is unreadable.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Refused> {
        let raw = codec::to_bytes(self)
            .map_err(|error| Refused::new(BAD_FORMAT, format!("the envelope has no canon/2 form ({error})")))?;
        read(&raw)?;
        Ok(raw)
    }
}

/// The bytes of `doc` naming `body`: `body_sha256` and `body_size` are taken from the body.
pub fn build(mut doc: EnvelopeDoc, body: &[u8]) -> Result<Vec<u8>, Refused> {
    doc.body_sha256 = Hex64::of(body);
    doc.body_size = i64::try_from(body.len()).map_err(|_| Refused::new(BAD_FORMAT, "body_size"))?;
    doc.to_bytes()
}

/// A distribution envelope that `read` accepted, with the bytes it was read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    doc: EnvelopeDoc,
    meta: Meta,
    raw: Vec<u8>,
}

impl std::ops::Deref for Envelope {
    type Target = EnvelopeDoc;
    fn deref(&self) -> &EnvelopeDoc {
        &self.doc
    }
}

impl Envelope {
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    pub fn envelope_id(&self) -> Hex64 {
        envelope_id(&self.raw)
    }

    /// `meta` read as its artifact's form (E11).
    pub fn form(&self) -> &Meta {
        &self.meta
    }
}

/// E1, E2, E5 and E8: the envelope in `envelope_bytes`, or `Refused` with `document:not-canonical` for
/// canon/2 that is not its canonical spelling and `dist:bad-format` for anything else that is not the
/// format.
pub fn read(envelope_bytes: &[u8]) -> Result<Envelope, Refused> {
    require(!envelope_bytes.is_empty() && envelope_bytes.len() <= MAX_ENVELOPE, "an envelope's length")?;
    let doc: EnvelopeDoc = load(envelope_bytes, "envelope")?;
    doc.check()?;
    let meta = doc.read_meta()?;
    let envelope = Envelope { doc, meta, raw: envelope_bytes.to_vec() };
    if envelope.artifact.is_install() || envelope.artifact == ArtifactKind::OperatorAnswer {
        super::install::check_envelope(&envelope)?; // IS1, IS11, OP2
    }
    Ok(envelope)
}

/// S1: what every signature covers, the DSSE pre-authentication encoding of the envelope bytes with the
/// payload type `application/vnd.prismpath.dist+json`.
pub fn signed_message(envelope_bytes: &[u8]) -> Vec<u8> {
    let mut out = format!("DSSEv1 {} {PAYLOAD_TYPE} {} ", PAYLOAD_TYPE.len(), envelope_bytes.len()).into_bytes();
    out.extend_from_slice(envelope_bytes);
    out
}

/// One entry of the signature block: a key id and a 64 byte Ed25519 signature (S2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Entry {
    pub key_id: [u8; KEY_ID_SIZE],
    pub signature: [u8; SIGNATURE_SIZE],
}

impl Entry {
    pub fn key_id_hex(&self) -> Hex64 {
        Hex64::from_raw(&self.key_id)
    }
}

/// S2: the sealed envelope, `envelope_bytes` with one entry per signer, entries sorted by key id.
/// Refuses no signer, more than four and a repeated key.
pub fn seal(envelope_bytes: &[u8], signers: &[SigningKey]) -> Result<Vec<u8>, Refused> {
    require(!envelope_bytes.is_empty() && envelope_bytes.len() <= MAX_ENVELOPE, "an envelope's length")?;
    let message = signed_message(envelope_bytes);
    let mut entries: Vec<Entry> = signers
        .iter()
        .map(|key| Entry {
            key_id: key_id(&key.verifying_key().to_bytes()).raw(),
            signature: key.sign(&message).to_bytes(),
        })
        .collect();
    entries.sort_unstable();
    require((1..=MAX_ENTRIES).contains(&entries.len()), "one to four signers")?;
    require(entries.windows(2).all(|pair| pair[0].key_id != pair[1].key_id), "a key signs twice")?;
    Ok(seal_entries(envelope_bytes, &entries))
}

/// The S2 byte layout of `entries` as given, then `envelope_bytes`, with no check. The writer's last
/// step, and how a test writes a container `unseal` refuses.
pub fn seal_entries(envelope_bytes: &[u8], entries: &[Entry]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_SIZE + ENTRY_SIZE * entries.len() + LENGTH_SIZE + envelope_bytes.len());
    out.extend_from_slice(MAGIC);
    out.push(CONTAINER_VERSION);
    out.push(entries.len() as u8);
    for entry in entries {
        out.extend_from_slice(&entry.key_id);
        out.extend_from_slice(&entry.signature);
    }
    out.extend_from_slice(&(envelope_bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(envelope_bytes);
    out
}

/// S2: the envelope bytes and the entries of a sealed envelope. Any other length, magic or version, an
/// unsorted or repeated key id, zero or more than four entries and an envelope length outside 1 to 2048
/// are `dist:bad-format`. Nothing past 2,440 bytes is read (B9).
pub fn unseal(sealed: &[u8]) -> Result<(&[u8], Vec<Entry>), Refused> {
    require((HEADER_SIZE..=MAX_SEALED).contains(&sealed.len()), "a sealed envelope's length")?;
    require(&sealed[..4] == MAGIC && sealed[4] == CONTAINER_VERSION, "magic or container version")?;
    let count = usize::from(sealed[5]);
    require((1..=MAX_ENTRIES).contains(&count), "one to four entries")?;
    let start = HEADER_SIZE + ENTRY_SIZE * count;
    require(sealed.len() >= start + LENGTH_SIZE, "shorter than its entries")?;
    let size = usize::from(u16::from_le_bytes([sealed[start], sealed[start + 1]]));
    require((1..=MAX_ENVELOPE).contains(&size), "an envelope length")?;
    require(sealed.len() == start + LENGTH_SIZE + size, "a length other than its envelope")?;
    let entries: Vec<Entry> = sealed[HEADER_SIZE..start]
        .chunks_exact(ENTRY_SIZE)
        .map(|chunk| {
            let mut entry = Entry { key_id: [0; KEY_ID_SIZE], signature: [0; SIGNATURE_SIZE] };
            entry.key_id.copy_from_slice(&chunk[..KEY_ID_SIZE]);
            entry.signature.copy_from_slice(&chunk[KEY_ID_SIZE..]);
            entry
        })
        .collect();
    require(entries.windows(2).all(|pair| pair[0].key_id < pair[1].key_id), "entries unsorted or a key id repeated")?;
    Ok((&sealed[start + LENGTH_SIZE..], entries))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_signed_bytes_are_the_dsse_encoding() {
        assert_eq!(signed_message(b"{}"), b"DSSEv1 35 application/vnd.prismpath.dist+json 2 {}".to_vec());
        assert_eq!(MAX_SEALED, 2440);
    }

    #[test]
    fn a_release_id_refuses_a_trust_kind_a_repeat_and_nothing() {
        let hash = Hex64::of(b"x");
        assert!(release_id(&[(ArtifactKind::PolicyPpt, hash.clone())]).is_ok());
        assert!(release_id(&[]).is_err());
        assert!(release_id(&[(ArtifactKind::PolicyPpt, hash.clone()), (ArtifactKind::PolicyPpt, hash.clone())]).is_err());
        assert!(release_id(&[(ArtifactKind::PolicyPpt, hash.clone()), (ArtifactKind::TrustWidening, hash)]).is_err());
    }

    #[test]
    fn seal_refuses_no_signer_five_and_a_key_twice() {
        let keys: Vec<SigningKey> = (0u8..5).map(|seed| SigningKey::from_bytes(&[seed; 32])).collect();
        assert!(seal(b"{}", &[]).is_err());
        assert!(seal(b"{}", &keys).is_err());
        assert!(seal(b"{}", &[keys[0].clone(), keys[0].clone()]).is_err());
        let sealed = seal(b"{}", &keys[..2]).unwrap();
        let (envelope, entries) = unseal(&sealed).unwrap();
        assert_eq!((envelope, entries.len()), (&b"{}"[..], 2));
    }
}
