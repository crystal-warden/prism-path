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
//! only by provisioning, a rotation and a revocation (K3), applied by the code that owns them.

use super::envelope::Entry;
use super::{
    load, require, Canon2Tag, Hex64, MaybeHex64, Refused, SortedSet, Stream, TrustStoreFormat, Verdict, AUTHORITY,
    MAX_SEQ, ROTATION_INVALID, SIG_INVALID, SIG_REVOKED_KEY, TOO_LARGE, UNKNOWN_KEY,
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
    pub fn check_rotation(&self, body: &[u8], entries: &[Entry], message: &[u8], instance_key_id: Option<&Hex64>) -> Option<&'static str> {
        let Ok(rotation) = super::read_rotation(body) else { return None };
        let added = rotation.add.raw();
        let added_id = Hex64::of(&added);
        if instance_key_id == Some(&added_id) || self.revoked_keys.contains(&added_id) {
            return Some(ROTATION_INVALID); // O4
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
