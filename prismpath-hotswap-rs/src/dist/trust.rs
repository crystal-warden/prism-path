// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The trust store of an enforcement point (spec-policy-distribution.md, section 5),
//! `prismpath/distribution/trust.py` in Rust: the trusted keys with their roles (K4), the retired key
//! ids, what revocation has refused, the floors revocation raised, the trust sequence, the threshold
//! and the time floor (T1), and its durable file, a canon/2 document with format
//! `prismpath.dist-trust-store/1` (K1).
//!
//! `counting` is S3 to S5, which entries of a sealed envelope count and the one cause when too few do.
//! A store that cannot be read refuses every envelope with `dist:unknown-key` (K1). The store changes
//! only by provisioning, a rotation and a revocation (K3). `apply_revocation` is the store after a verified
//! revocation (R1 to R6) and `apply_rotation` the store after a verified rotation (O1, O3, K5). `Anchor` is
//! the trust anchor a PEP is provisioned with (P2, P3).

use super::envelope::{Entry, Envelope};
use super::install::{self, AnchorPart, Record};
use super::{
    load, require, Anchor2Format, AnchorFormat, ArtifactKind, Canon2Tag, Hex64, MaybeHex64, Refused, SortedSet, Stream, TargetKind,
    TrustStoreFormat, Verdict, AUTHORITY, BAD_FORMAT, CONTROLLER, MAX_SEQ, ROTATION_INVALID, SIG_INVALID, SIG_REVOKED_KEY,
    TOO_LARGE, TRUST_REPLAY, UNKNOWN_KEY,
};
use crate::host::HostError;
use prismpath_rs::canon2::codec;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// S6: the only threshold in this version.
pub const THRESHOLD: i64 = 1;

/// A key role (K4): a lower case letter, then up to 31 of `a-z`, `0-9` and `-`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Role(String);

impl Role {
    pub fn authority() -> Role {
        Role(AUTHORITY.to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Role {
    type Error = String;
    fn try_from(text: String) -> Result<Role, String> {
        let bytes = text.as_bytes();
        let well_formed = (1..=32).contains(&bytes.len())
            && bytes[0].is_ascii_lowercase()
            && bytes[1..].iter().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-');
        if well_formed {
            Ok(Role(text))
        } else {
            Err(format!("{text:?} is not a key role"))
        }
    }
}

impl From<Role> for String {
    fn from(role: Role) -> String {
        role.0
    }
}

/// K5: the same bounds in every implementation, at most 8 keys that are not retired and 16 retired ids.
pub const MAX_KEYS: usize = 8;
pub const MAX_RETIRED: usize = 16;

/// A key the store holds: its 32 raw public bytes in hex and its role (K4). A key in a role this
/// version does not know is kept and never counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Key {
    pub public: Hex64,
    pub role: Role,
}

/// What an enforcement point holds about keys, as its durable file is written. `keys` maps a key id to
/// its key. The `revoked_*` sets are the latest revocation list, which holds every key id an earlier one
/// held (R6), and `floors` the floor revocation raised for the PEP's stream. `retired` is the retired key
/// ids, oldest first, at most 16, and `keys` holds at most 8 keys that are not retired (K5). A store whose
/// file could not be read has `readable` false and counts nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustStore {
    pub encoding: Canon2Tag,
    pub floors: BTreeMap<Stream, i64>,
    pub format: TrustStoreFormat,
    pub keys: BTreeMap<Hex64, Key>,
    pub retired: Vec<Hex64>,
    pub revoked_envelopes: SortedSet<Hex64>,
    pub revoked_keys: SortedSet<Hex64>,
    pub revoked_policies: SortedSet<Hex64>,
    pub threshold: i64,
    pub time_floor: i64,
    pub trust_id: MaybeHex64,
    pub trust_seq: i64,
    #[serde(skip, default = "readable")]
    readable: bool,
}

fn readable() -> bool {
    true
}

impl Default for TrustStore {
    fn default() -> TrustStore {
        TrustStore {
            encoding: Canon2Tag,
            floors: BTreeMap::new(),
            format: TrustStoreFormat,
            keys: BTreeMap::new(),
            retired: Vec::new(),
            revoked_envelopes: SortedSet::default(),
            revoked_keys: SortedSet::default(),
            revoked_policies: SortedSet::default(),
            threshold: THRESHOLD,
            time_floor: 0,
            trust_id: MaybeHex64::default(),
            trust_seq: 0,
            readable: true,
        }
    }
}

impl TrustStore {
    /// A store holding `public_keys` (32 raw bytes each) in `role`, for provisioning and tests.
    pub fn with_keys(public_keys: &[[u8; 32]], role: &Role) -> TrustStore {
        let keys = public_keys
            .iter()
            .map(|raw| (Hex64::of(raw), Key { public: Hex64::from_raw(raw), role: role.clone() }))
            .collect();
        TrustStore { keys, ..TrustStore::default() }
    }

    /// The store a PEP holds when its file cannot be read: it counts nothing (K1).
    pub fn unreadable() -> TrustStore {
        TrustStore { readable: false, ..TrustStore::default() }
    }

    pub fn is_readable(&self) -> bool {
        self.readable
    }

    /// The canon/2 bytes of the durable file.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Refused> {
        require(self.readable, "an unreadable trust store has no file")?;
        let raw = codec::to_bytes(self).map_err(|error| Refused::new(super::BAD_FORMAT, error.to_string()))?;
        TrustStore::from_bytes(&raw)?;
        Ok(raw)
    }

    /// The store in `raw`, or `Refused` (`dist:bad-format`, `document:not-canonical`) when it is not one.
    pub fn from_bytes(raw: &[u8]) -> Result<TrustStore, Refused> {
        let store: TrustStore = load(raw, "trust store")?;
        require(store.threshold == THRESHOLD, "trust store threshold")?;
        require(
            (0..=MAX_SEQ).contains(&store.time_floor) && (0..=MAX_SEQ).contains(&store.trust_seq),
            "trust store integer",
        )?;
        require(store.floors.values().all(|seq| (1..=MAX_SEQ).contains(seq)), "trust store floors")?;
        require(
            store.keys.iter().all(|(kid, key)| Hex64::of(&key.public.raw()) == *kid),
            "a trust store key id that is not its key's",
        )?;
        let retired: std::collections::BTreeSet<&Hex64> = store.retired.iter().collect();
        require(
            retired.len() == store.retired.len()
                && store.retired.len() <= MAX_RETIRED
                && store.retired.iter().all(|kid| store.keys.contains_key(kid)),
            "trust store retired",
        )?;
        require(store.keys.keys().filter(|kid| !retired.contains(kid)).count() <= MAX_KEYS, "trust store keys beyond the bound")?;
        Ok(store)
    }

    /// The store at `path`. A missing, unreadable or malformed file is a store that counts nothing
    /// (K1), never an empty store that a provisioning step could be skipped into.
    pub fn load(path: &str) -> TrustStore {
        std::fs::read(path)
            .ok()
            .and_then(|raw| TrustStore::from_bytes(&raw).ok())
            .unwrap_or_else(TrustStore::unreadable)
    }

    /// Write the store durably at `path`, the old file or the new one and never a torn one. An
    /// unreadable store is never written over a file.
    pub fn save(&self, path: &str) -> Result<(), HostError> {
        if !self.readable {
            return Err(HostError::Io(format!(
                "{path}: an unreadable trust store is not saved; provision the enforcement point again"
            )));
        }
        let bytes = self.to_bytes().map_err(|refused| HostError::Io(format!("{path}: {refused}")))?;
        crate::host::atomic_write_bytes(path, &bytes)
    }

    /// S3 to S5. An entry counts when its key id names a key the store holds in `role`, that key is
    /// neither revoked nor retired, and its signature over `message` verifies. Any other entry is
    /// skipped, as DSSE skips it, and a key id only finds the key. The envelope is signed when at least
    /// the threshold count. Otherwise the one cause is `sig:revoked-key` when an entry verifies under a
    /// revoked or retired key, `sig:invalid` when an entry names a held key and does not verify, and
    /// `dist:unknown-key` otherwise.
    pub fn counting(&self, entries: &[Entry], message: &[u8], role: &str) -> Verdict {
        if !self.readable {
            return Verdict::refused(UNKNOWN_KEY);
        }
        let (mut counting, mut revoked_verifies, mut held_fails) = (0i64, false, false);
        for entry in entries {
            let kid = entry.key_id_hex();
            let Some(key) = self.keys.get(&kid) else { continue };
            if !crate::verify_ed25519(&key.public.raw(), message, &entry.signature) {
                held_fails = true;
                continue;
            }
            if self.retired.contains(&kid) || self.revoked_keys.contains(&kid) {
                revoked_verifies = true;
            } else if key.role.as_str() == role {
                counting += 1;
            }
        }
        if counting >= self.threshold {
            Verdict::default()
        } else if revoked_verifies {
            Verdict::refused(SIG_REVOKED_KEY)
        } else if held_fails {
            Verdict::refused(SIG_INVALID)
        } else {
            Verdict::refused(UNKNOWN_KEY)
        }
    }

    /// O2 to O4 and K5 for a rotation whose envelope already counts under this store (V3) and reads (V11): the
    /// key in `add` signs it too, so it is signed under the store it leaves as well, `add` is neither the PEP's
    /// own instance key nor a revoked key, `retire` names a key the store holds, and no ninth key is made.
    /// `others` is every install and operator key id the install record holds or retired (K4).
    pub fn check_rotation(
        &self,
        body: &[u8],
        entries: &[Entry],
        message: &[u8],
        instance_key_id: Option<&Hex64>,
        others: &std::collections::BTreeSet<Hex64>,
    ) -> Option<&'static str> {
        let Ok(rotation) = super::read_rotation(body) else { return None };
        let added = rotation.add.raw();
        let added_id = Hex64::of(&added);
        let elsewhere = self.keys.get(&added_id).is_some_and(|key| key.role.as_str() != AUTHORITY);
        if instance_key_id == Some(&added_id)
            || self.revoked_keys.contains(&added_id)
            || self.retired.contains(&added_id)
            || others.contains(&added_id)
            || elsewhere
        {
            // O4, K4: never the instance key, a revoked key, a retired one or a key held in another role, the
            // install, operator and controller keys included (IS7)
            return Some(ROTATION_INVALID);
        }
        if let Some(retire) = &rotation.retire.0 {
            if !self.keys.contains_key(retire) {
                return Some(ROTATION_INVALID); // O3
            }
        }
        let mut live: std::collections::BTreeSet<&Hex64> = self.keys.keys().filter(|kid| !self.retired.contains(kid)).collect();
        live.insert(&added_id);
        if let Some(retire) = &rotation.retire.0 {
            live.remove(retire);
        }
        if live.len() > MAX_KEYS {
            return Some(TOO_LARGE); // K5: a ninth key
        }
        let signed = entries.iter().find(|entry| entry.key_id_hex() == added_id);
        match signed {
            Some(entry) if crate::verify_ed25519(&added, message, &entry.signature) => None, // O2
            _ => Some(ROTATION_INVALID),
        }
    }
}

impl TrustStore {
    /// R6 for a revocation list that already reads (V11): it holds every key id the current list holds, since a
    /// key once revoked stays revoked. None, or `dist:trust-replay`.
    pub fn check_revocation(&self, body: &[u8]) -> Option<&'static str> {
        let listed = super::read_revocation(body).ok()?;
        if self.revoked_keys.iter().all(|kid| listed.keys.contains(kid)) {
            None
        } else {
            Some(TRUST_REPLAY)
        }
    }

    /// The store after a verified `trust.revocation` (`envelope`, already through V2 to V11, so its `seq` is the
    /// trust sequence plus one, R1, and it drops no key, R6). The PEP holds this list and no other (R2, R6). A
    /// floor it raises is kept for `stream`, the PEP's own, and only rises (R4). The caller makes the result
    /// durable before it reports it (R3).
    pub fn apply_revocation(&self, envelope: &Envelope, body: &[u8], stream: Option<&Stream>) -> Result<TrustStore, Refused> {
        require(
            envelope.artifact == ArtifactKind::TrustRevocation && envelope.seq == self.trust_seq + 1,
            "only a verified revocation at the next trust sequence is applied (R1)",
        )?;
        require(self.check_revocation(body).is_none(), "a revocation list that drops a revoked key is never applied (R6)")?;
        let listed = super::read_revocation(body)?;
        let ours = |name: &Stream| stream.is_none_or(|own| own == name);
        let mut floors: BTreeMap<Stream, i64> =
            self.floors.iter().filter(|(name, _)| ours(name)).map(|(name, seq)| (name.clone(), *seq)).collect();
        for (name, seq) in listed.floors.iter().filter(|(name, _)| ours(name)) {
            let raised = floors.get(name).copied().unwrap_or(0).max(*seq);
            floors.insert(name.clone(), raised);
        }
        Ok(TrustStore {
            revoked_keys: listed.keys,
            revoked_envelopes: listed.envelopes,
            revoked_policies: listed.policies,
            floors,
            trust_seq: envelope.seq,
            trust_id: MaybeHex64(Some(envelope.envelope_id())),
            ..self.clone()
        })
    }

    /// The store after a verified `trust.rotation` at the next trust sequence (O1): the new key is held in the
    /// authority role and the retired one no longer counts (O3), though a release already active under it stays.
    /// A seventeenth retired id forgets the oldest, and its key with it (K5).
    pub fn apply_rotation(&self, envelope: &Envelope, body: &[u8]) -> Result<TrustStore, Refused> {
        require(
            envelope.artifact == ArtifactKind::TrustRotation && envelope.seq == self.trust_seq + 1,
            "only a verified rotation at the next trust sequence is applied (O1)",
        )?;
        let rotation = super::read_rotation(body)?;
        let added = rotation.add.raw();
        let mut keys = self.keys.clone();
        keys.insert(Hex64::of(&added), Key { public: rotation.add.clone(), role: Role::authority() });
        let mut retired = self.retired.clone();
        if let Some(retire) = rotation.retire.0 {
            if !retired.contains(&retire) {
                retired.push(retire);
            }
        }
        while retired.len() > MAX_RETIRED {
            // K5: the oldest retired id is forgotten, and its signature then reads as an unknown key's
            let forgotten = retired.remove(0);
            keys.remove(&forgotten);
        }
        Ok(TrustStore {
            keys,
            retired,
            trust_seq: envelope.seq,
            trust_id: MaybeHex64(Some(envelope.envelope_id())),
            ..self.clone()
        })
    }

    /// R5, O3: an entry by a key the store holds in `role`, not revoked, verifies. A retired key still holds up
    /// a release already active under it, where it no longer counts for a new envelope (S5).
    pub fn holds_up(&self, entries: &[Entry], message: &[u8], role: &str) -> bool {
        entries.iter().any(|entry| {
            let kid = entry.key_id_hex();
            self.keys.get(&kid).is_some_and(|key| {
                key.role.as_str() == role
                    && !self.revoked_keys.contains(&kid)
                    && crate::verify_ed25519(&key.public.raw(), message, &entry.signature)
            })
        })
    }

    /// Make the store unreadable, as a store whose file could not be read is (K1).
    pub fn into_unreadable(self) -> TrustStore {
        TrustStore { readable: false, ..self }
    }
}

// ------------------------------------------------------------------ the trust anchor (P2, P3)

/// The canon/2 document of a `/1` trust anchor, its members exactly these.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnchorDoc {
    encoding: Canon2Tag,
    format: AnchorFormat,
    keys: BTreeMap<Hex64, Key>,
    stream: Stream,
    target: TargetKind,
    threshold: i64,
}

/// P4: the canon/2 document of a `/2` trust anchor, with the controller key, `fresh` and the install part.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Anchor2Doc {
    controller: Hex64,
    encoding: Canon2Tag,
    format: Anchor2Format,
    fresh: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    install: Option<AnchorPart>,
    keys: BTreeMap<Hex64, Key>,
    stream: Stream,
    target: TargetKind,
    threshold: i64,
}

/// A trust anchor (P2 step 3, P4): the authority keys, the threshold, the PEP's target kind and its stream, and
/// from `/2` the first controller key (K6) and `fresh`, the longest lifetime in seconds of a fresh statement (H16),
/// and the install record its `install` member brings. A `/1` anchor names no controller key, no install part and
/// `fresh` 0. `fingerprint` is the SHA-256 of its bytes, which the operator compares (P2 step 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {
    pub keys: BTreeMap<Hex64, Key>,
    pub threshold: i64,
    pub target: TargetKind,
    pub stream: Stream,
    pub fingerprint: Hex64,
    pub controller: Option<Hex64>,
    pub fresh: i64,
    pub install: Option<Record>,
}

impl Anchor {
    /// P3: the trust store an anchor provisions, with the trust sequence and the time floor at their start. The
    /// controller key is held in its own role (K4, K6) and counts on no envelope.
    pub fn store(&self) -> TrustStore {
        let mut keys = self.keys.clone();
        if let Some(controller) = &self.controller {
            keys.insert(Hex64::of(&controller.raw()), Key { public: controller.clone(), role: Role(CONTROLLER.to_string()) });
        }
        TrustStore { keys, threshold: self.threshold, ..TrustStore::default() }
    }

    /// The id of the controller key the anchor names.
    pub fn controller_id(&self) -> Option<Hex64> {
        self.controller.as_ref().map(|public| Hex64::of(&public.raw()))
    }
}

/// The canon/2 bytes of a `/1` anchor trusting `public_keys` (32 raw bytes each) in `role`. The owner's tool.
pub fn anchor_bytes(public_keys: &[[u8; 32]], target: TargetKind, stream: &Stream, role: &Role) -> Result<Vec<u8>, Refused> {
    let doc = AnchorDoc {
        encoding: Canon2Tag,
        format: AnchorFormat,
        keys: TrustStore::with_keys(public_keys, role).keys,
        stream: stream.clone(),
        target,
        threshold: THRESHOLD,
    };
    let raw = prismpath_rs::canon2::codec::to_bytes(&doc).map_err(|error| Refused::new(BAD_FORMAT, error.to_string()))?;
    read_anchor(&raw)?;
    Ok(raw)
}

/// The canon/2 bytes of a `/2` anchor (P4): authority keys `public_keys`, the controller key, `fresh` and the
/// install part, if any. The owner's tool, which writes only an anchor `read_anchor` reads.
pub fn anchor2_bytes(
    public_keys: &[[u8; 32]],
    target: TargetKind,
    stream: &Stream,
    controller: &[u8; 32],
    fresh: i64,
    install: Option<AnchorPart>,
) -> Result<Vec<u8>, Refused> {
    let doc = Anchor2Doc {
        controller: Hex64::from_raw(controller),
        encoding: Canon2Tag,
        format: Anchor2Format,
        fresh,
        install,
        keys: TrustStore::with_keys(public_keys, &Role::authority()).keys,
        stream: stream.clone(),
        target,
        threshold: THRESHOLD,
    };
    let raw = prismpath_rs::canon2::codec::to_bytes(&doc).map_err(|error| Refused::new(BAD_FORMAT, error.to_string()))?;
    read_anchor(&raw)?;
    Ok(raw)
}

fn check_keys(keys: &BTreeMap<Hex64, Key>, extra: usize) -> Result<(), Refused> {
    require(!keys.is_empty(), "a trust anchor with no key")?;
    require(keys.len() + extra <= MAX_KEYS, "a trust anchor with more keys than a trust store holds (K5)")?;
    require(keys.iter().all(|(kid, key)| Hex64::of(&key.public.raw()) == *kid), "a trust anchor key id that is not its key's")?;
    // P4: in both formats `keys` holds authority keys only
    require(keys.values().all(|key| key.role.as_str() == AUTHORITY), "a trust anchor whose keys name another role than authority (P4)")
}

/// The anchor in `raw`, `/2` or `/1` (P4), or `Refused` (`dist:bad-format`, `document:not-canonical`). Every entry
/// of `keys` is an authority key, the controller key is none of them, and no key of the install part is one of
/// them, so no key is in two roles (P2 step 3, K4). A `/1` anchor that holds an install member is no anchor.
pub fn read_anchor(raw: &[u8]) -> Result<Anchor, Refused> {
    let format = match prismpath_rs::canon2::read(raw) {
        Ok(prismpath_rs::canon2::Doc::Obj(members)) => {
            members.iter().find(|(name, _)| name == "format").and_then(|(_, value)| match value {
                prismpath_rs::canon2::Doc::Str(text) => Some(text.clone()),
                _ => None,
            })
        }
        _ => None,
    };
    if format.as_deref() == Some(Anchor2Format::TEXT) {
        let doc: Anchor2Doc = load(raw, "trust anchor")?;
        require(doc.threshold == THRESHOLD, "a trust anchor's threshold")?;
        require((0..=MAX_SEQ).contains(&doc.fresh), "a trust anchor's fresh")?;
        check_keys(&doc.keys, 1)?;
        let controller_id = Hex64::of(&doc.controller.raw());
        require(!doc.keys.contains_key(&controller_id), "the anchor's controller key is also an authority key (K4, K6)")?;
        let install = doc.install.as_ref().map(install::read_anchor_part).transpose()?;
        if let Some(record) = &install {
            let named: Vec<&Hex64> = record.keys.keys().chain(record.operators.keys()).collect();
            require(
                named.iter().all(|kid| !doc.keys.contains_key(*kid) && **kid != controller_id),
                "an anchor that holds one key in two roles (P2 step 3, K4)",
            )?;
        }
        return Ok(Anchor {
            keys: doc.keys,
            threshold: doc.threshold,
            target: doc.target,
            stream: doc.stream,
            fingerprint: Hex64::of(raw),
            controller: Some(doc.controller),
            fresh: doc.fresh,
            install,
        });
    }
    let doc: AnchorDoc = load(raw, "trust anchor")?;
    require(doc.threshold == THRESHOLD, "a trust anchor's threshold")?;
    check_keys(&doc.keys, 0)?;
    Ok(Anchor {
        keys: doc.keys,
        threshold: doc.threshold,
        target: doc.target,
        stream: doc.stream,
        fingerprint: Hex64::of(raw),
        controller: None,
        fresh: 0,
        install: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> TrustStore {
        let mut store = TrustStore::with_keys(&[[7u8; 32]], &Role::authority());
        store.floors.insert(Stream::try_from("host/demo").unwrap(), 3);
        store.revoked_keys.insert(Hex64::of(b"k"));
        store
    }

    #[test]
    fn a_store_round_trips_through_its_file_byte_for_byte() {
        let bytes = store().to_bytes().unwrap();
        let read = TrustStore::from_bytes(&bytes).unwrap();
        assert_eq!(read, store());
        assert_eq!(read.to_bytes().unwrap(), bytes);
    }

    #[test]
    fn a_store_that_does_not_read_counts_nothing() {
        let text = String::from_utf8(store().to_bytes().unwrap()).unwrap();
        for broken in [
            text.replace("\"threshold\":1", "\"threshold\":2"),
            text.replace("\"trust_seq\":0", "\"trust_seq\":-1"),
            text.replace(",\"trust_seq\":0", ""),
            text.replace("\"role\":\"authority\"", "\"role\":\"Authority\""),
            text.replace("\"host/demo\":3", "\"host/demo\":0"),
        ] {
            assert_eq!(TrustStore::from_bytes(broken.as_bytes()).unwrap_err().cause, super::super::BAD_FORMAT, "{broken}");
        }
        let wrong_id = text.replacen(&Hex64::of(&[7u8; 32]).to_string(), &"0".repeat(64), 1);
        assert!(TrustStore::from_bytes(wrong_id.as_bytes()).is_err());
        assert!(!TrustStore::load("/nonexistent/prismpath/trust.store").is_readable());
        assert_eq!(TrustStore::unreadable().counting(&[], b"", AUTHORITY), Verdict::refused(UNKNOWN_KEY));
        assert!(TrustStore::unreadable().save("/nonexistent/prismpath/trust.store").is_err());
    }

    #[test]
    fn a_store_saves_and_loads_again() {
        let dir = std::env::temp_dir().join(format!("pp_dist_trust_{}", std::process::id()));
        let path = dir.join("trust.store");
        let path = path.to_str().unwrap();
        store().save(path).unwrap();
        assert_eq!(TrustStore::load(path), store());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
