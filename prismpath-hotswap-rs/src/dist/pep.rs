// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The enforcement point machine of policy distribution (spec-policy-distribution.md, section 9),
//! `prismpath/distribution/pep.py` in Rust, one per stream. What a target does with a committed release is
//! its adapter's; this crate has the `host` adapter, over `PolicyHost`. The machine verifies, keeps the floor,
//! the time floor and the trust store, stages, commits, aborts, rolls back, lapses at expiry or holds, and
//! signs a state record for every transition.
//!
//! Its durable store is `<state>/dist/`, under the file names the Python machine uses, each canon/2 and written
//! whole (the old one or the new one). The two machines are not held to open each other's directory: the audit
//! log here is the host's unsigned one, and DIVERGENCES.md lists what else differs. The last two files below
//! are this machine's only:
//!
//! ```text
//! anchor.json    the confirmed trust anchor (P2), which names the target kind and the stream
//! anchor.pending an anchor the operator has not confirmed yet (P2 step 4)
//! trust.json     the trust store (K1)
//! floor.json     the floor (Q1)
//! counter.json   the state record counter (H3)
//! setting.json   the expiry response the PEP was provisioned with (X10)
//! staged.json    the staged release
//! pending.json   the intent record of a commit or a rollback
//! active.json    the active release and the one it replaced (RB1)
//! blobs/         sealed envelopes and bodies under their SHA-256
//! audit.log      the audit log
//! owed.json      a lapse made durable whose runtime step or report is not done yet
//! epoch.json     the highest epoch id the controller sent (H9)
//! ```
//!
//! A commit is durable in the order of C4: the intent, the floor, the audit event, the artifacts under
//! content addressed names (staging already wrote them, each synced), the active record, the runtime switch,
//! the clean up. A restart reads only what the active record names, and finishes or reports an interrupted
//! commit. [`Pep::set_commit_hook`] runs before each of those steps, and an error stands for a process that
//! died there.
//!
//! A store that cannot be read is answered by failing closed: an unreadable trust store refuses every
//! envelope and decides nothing (K1, X3), and an unreadable floor, anchor or setting locks the PEP (Q5) until
//! it is provisioned again (P3). A counter that cannot be read also locks the PEP, and its records count on
//! from its time in microseconds, so none repeats (H3). Each of those records writes the counter again, so the
//! next start reads it and is not locked: a lock from the counter alone ends at a restart, where P3 has only
//! provisioning end a lock. The Python machine does the same, and the two change together if P3 is to hold
//! for the counter.
//!
//! A flip or a lapse that fails after its record is durable leaves the runtime perhaps holding another release
//! than the PEP: the PEP is reconciling. It decides nothing, and a commit, a rollback and a lapse wait, but it
//! verifies and stages, applies trust statements, aborts, provisions and goes on sending state records. Those
//! say `no-policy`, with the release the runtime may still hold as the active one and, after a flip, the
//! release the PEP made active as the staged one. Only a tick, or a start, tries the runtime again, and first
//! holds the PEP's active release to expiry and revocation. A release that fell then was never run: what ran is
//! withdrawn, the commit is reported `refused` with the cause it fell for, and the PEP lapses with it. Otherwise
//! the runtime is made to match and the owed `committed`, `rolled-back` or `lapsed` record goes. What is owed
//! leaves `pending.json` or `owed.json` only after its record is made, so a restart sends it too, and the
//! lapsed audit event is written once across one. A confirm withdraws the runtime first and ends the state.
//! A home holding the private half of a trusted authority key is refused at start (K2).

use super::envelope::{self as env, Envelope};
use super::state_record::{self, StateRecord};
use super::trust::{read_anchor, TrustStore};
use super::verify::{self, Floor, PepKind, PepView, Staged, SKEW};
use super::{
    load, ActiveFormat, ArtifactKind, EpochFormat, OwedFormat, Canon2Tag, CounterFormat, FloorFormat, Hex64, MaybeHex64, Meta, PendingFormat,
    Refused, SettingFormat, SortedSet, StagedFormat, Stream, Target, TargetKind, AUTHORITY, EXPIRED, FLOOR_LOST, HELD,
    INCOMPLETE, MAX_SEQ, NOT_STAGED, NOT_YET_VALID, POLICY_LAPSED, REVOKED, SEQ_REPLAY, SIDECAR_MISMATCH,
    SIDECAR_MISSING, UNKNOWN_KEY, WIDENING_UNSIGNED,
};
use crate::host::{abspath, atomic_write_bytes, fsync_dir, AuditLog, Fields, HostError, PolicyHost};
use ed25519_dalek::SigningKey;
use prismpath_rs::canon2::codec;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

/// X6: the expiry responses a deployment chooses from.
pub const REFUSE: &str = "refuse";
pub const HOLD: &str = "hold";

/// Why a call to the machine did not end in a state record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PepError {
    /// The PEP refuses to start or to be provisioned (K2, X10, an anchor for another kind), or has no release
    /// kept to roll back to (RB1).
    Refused(String),
    /// A durable write or the audit log failed, or the commit hook stopped a step.
    Host(HostError),
}

impl std::fmt::Display for PepError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PepError::Refused(text) => formatter.write_str(text),
            PepError::Host(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for PepError {}

impl From<HostError> for PepError {
    fn from(error: HostError) -> PepError {
        PepError::Host(error)
    }
}

impl From<crate::host::AuditWriteError> for PepError {
    fn from(error: crate::host::AuditWriteError) -> PepError {
        PepError::Host(HostError::from(error))
    }
}

fn refused(text: impl Into<String>) -> PepError {
    PepError::Refused(text.into())
}

/// A step of a commit or a rollback (C4), in the order they run. The commit hook sees each one before it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PepStep {
    Intent,
    Floor,
    Evidence,
    ActiveRecord,
    Runtime,
    Cleanup,
}

impl PepStep {
    pub const ALL: [PepStep; 6] =
        [PepStep::Intent, PepStep::Floor, PepStep::Evidence, PepStep::ActiveRecord, PepStep::Runtime, PepStep::Cleanup];

    pub fn name(self) -> &'static str {
        match self {
            PepStep::Intent => "intent",
            PepStep::Floor => "floor",
            PepStep::Evidence => "evidence",
            PepStep::ActiveRecord => "active_record",
            PepStep::Runtime => "runtime",
            PepStep::Cleanup => "cleanup",
        }
    }
}

/// Runs before a commit step; an `Err` stops the commit there, as a process dying there would.
pub type PepHook = Box<dyn Fn(PepStep) -> Result<(), String>>;

/// W1: whether a staged release allows more than the active one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparison {
    Larger,
    NotLarger,
    CannotDecide,
}

/// The interface between the machine and the runtime a target kind protects. `check` is the target's own
/// part of V11, run at commit over the whole staged release, since one artifact may name another (C2).
/// `compare` answers W1. `activate` makes the runtime use a committed release and `deactivate` makes it
/// refuse. An adapter never verifies a signature, reads a clock or touches a floor. Those are the machine's.
pub trait Adapter {
    fn kind(&self) -> TargetKind;

    /// The directory the runtime keeps its files in, which K2 scans for an authority private key.
    fn home(&self) -> Option<String> {
        None
    }

    /// The qualification envelope a `policy.ppt` is admitted under.
    fn qualification(&self) -> Option<Value> {
        None
    }

    /// The adapter's bound on a body (E6).
    fn body_bound(&self) -> i64 {
        env::MAX_BODY
    }

    fn check(&self, _artifact: ArtifactKind, _body: &[u8], _staged: &Release) -> Option<String> {
        None
    }

    fn compare(&self, _active: &Release, _staged: &Release) -> Comparison {
        Comparison::CannotDecide
    }

    fn activate(&self, release: &Release) -> Result<(), PepError>;

    fn deactivate(&self, cause: &str) -> Result<(), PepError>;
}

// ------------------------------------------------------------------ the durable documents

/// One envelope of a release as the store holds it: its envelope id and the blob names of the sealed
/// envelope and of the body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeldDoc {
    pub body: Hex64,
    pub envelope_id: Hex64,
    pub sealed: Hex64,
}

/// A release as `staged.json`, `pending.json` and `active.json` write it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseDoc {
    pub held: BTreeMap<ArtifactKind, HeldDoc>,
    pub policy_sha256: Hex64,
    pub release: Hex64,
    pub replaces: MaybeHex64,
    pub seq: i64,
    pub stream: String,
    pub widens: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FloorDoc {
    encoding: Canon2Tag,
    format: FloorFormat,
    ids: SortedSet<Hex64>,
    seq: i64,
    stream: Stream,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CounterDoc {
    counter: i64,
    encoding: Canon2Tag,
    format: CounterFormat,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SettingDoc {
    encoding: Canon2Tag,
    expiry: String,
    format: SettingFormat,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StagedDoc {
    encoding: Canon2Tag,
    format: StagedFormat,
    release: ReleaseDoc,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingDoc {
    encoding: Canon2Tag,
    format: PendingFormat,
    op: String,
    release: Option<ReleaseDoc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveDoc {
    encoding: Canon2Tag,
    format: ActiveFormat,
    previous: Option<ReleaseDoc>,
    release: Option<ReleaseDoc>,
}

/// A release as the PEP holds it (E7): what its envelopes share, the blob names of each, and the envelopes,
/// bodies and body paths read from the blobs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    pub stream: String,
    pub seq: i64,
    pub policy_sha256: Hex64,
    pub release: Hex64,
    pub replaces: MaybeHex64,
    pub widens: bool,
    pub held: BTreeMap<ArtifactKind, HeldDoc>,
    pub envelopes: BTreeMap<ArtifactKind, Envelope>,
    pub bodies: BTreeMap<ArtifactKind, Vec<u8>>,
    pub paths: BTreeMap<ArtifactKind, String>,
}

impl Release {
    fn of(envelope: &Envelope) -> Release {
        Release {
            stream: envelope.stream.clone(),
            seq: envelope.seq,
            policy_sha256: envelope.policy_sha256.clone(),
            release: envelope.release.clone(),
            replaces: envelope.replaces.clone(),
            widens: envelope.widens,
            held: BTreeMap::new(),
            envelopes: BTreeMap::new(),
            bodies: BTreeMap::new(),
            paths: BTreeMap::new(),
        }
    }

    pub fn document(&self) -> ReleaseDoc {
        ReleaseDoc {
            held: self.held.clone(),
            policy_sha256: self.policy_sha256.clone(),
            release: self.release.clone(),
            replaces: self.replaces.clone(),
            seq: self.seq,
            stream: self.stream.clone(),
            widens: self.widens,
        }
    }

    pub fn envelope_ids(&self) -> BTreeSet<Hex64> {
        self.held.values().map(|held| held.envelope_id.clone()).collect()
    }

    pub fn names(&self, stream: &str, seq: i64, policy_sha256: &Hex64) -> bool {
        self.stream == stream && self.seq == seq && self.policy_sha256 == *policy_sha256
    }
}

/// The PEP's directory: whole canon/2 documents and content addressed blobs, each write synced.
struct Store {
    dir: String,
    blobs: String,
}

impl Store {
    fn new(dir: &str) -> Result<Store, HostError> {
        let dir = abspath(dir);
        let blobs = format!("{dir}/blobs");
        std::fs::create_dir_all(&blobs).map_err(|error| HostError::Io(format!("{blobs}: {error}")))?;
        Ok(Store { dir, blobs })
    }

    fn path(&self, name: &str) -> String {
        format!("{}/{name}", self.dir)
    }

    fn exists(&self, name: &str) -> bool {
        std::path::Path::new(&self.path(name)).exists()
    }

    /// The document `name`, or `Refused` when it is missing or is not its form.
    fn read<T: DeserializeOwned>(&self, name: &str) -> Result<T, Refused> {
        let raw = std::fs::read(self.path(name)).map_err(|error| Refused::new(super::BAD_FORMAT, format!("{name}: {error}")))?;
        load(&raw, name)
    }

    fn write<T: Serialize>(&self, name: &str, doc: &T) -> Result<(), HostError> {
        let raw = codec::to_bytes(doc).map_err(|error| HostError::Canonical(format!("{name}: {error}")))?;
        atomic_write_bytes(&self.path(name), &raw)
    }

    fn write_bytes(&self, name: &str, data: &[u8]) -> Result<(), HostError> {
        atomic_write_bytes(&self.path(name), data)
    }

    fn remove(&self, name: &str) -> Result<(), HostError> {
        match std::fs::remove_file(self.path(name)) {
            Ok(()) => fsync_dir(&self.dir),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(HostError::Io(format!("{}: {error}", self.path(name)))),
        }
    }

    fn blob_path(&self, name: &Hex64) -> String {
        format!("{}/{name}", self.blobs)
    }

    fn put(&self, data: &[u8]) -> Result<Hex64, HostError> {
        let name = Hex64::of(data);
        if self.get(&name).is_none() {
            atomic_write_bytes(&self.blob_path(&name), data)?;
        }
        Ok(name)
    }

    /// The blob `name`, or None when it is missing or its bytes are not its name's.
    fn get(&self, name: &Hex64) -> Option<Vec<u8>> {
        std::fs::read(self.blob_path(name)).ok().filter(|data| Hex64::of(data) == *name)
    }

    /// Remove every blob not in `keep`. A removal that fails leaves a file nothing reads.
    fn keep_only(&self, keep: &BTreeSet<Hex64>) {
        let Ok(entries) = std::fs::read_dir(&self.blobs) else { return };
        let mut removed = false;
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let kept = Hex64::try_from(name.as_str()).is_ok_and(|hash| keep.contains(&hash));
            if !kept {
                removed |= std::fs::remove_file(entry.path()).is_ok();
            }
        }
        if removed {
            let _ = fsync_dir(&self.blobs);
        }
    }
}

/// K2: the bound of the scan of a home for an authority key, and the directory of a home it never enters.
const K2_SCAN: usize = 4096;
const K2_SKIP: &str = "runs";
/// The DER of a PKCS8 Ed25519 private key before its 32 byte seed (RFC 8410).
const PKCS8_ED25519: [u8; 16] = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];

/// The public halves of the Ed25519 private keys in the file at `path`: each `PRIVATE KEY` block of a PEM file
/// that holds one anywhere, as the Python tools write a key, or a raw 32 byte seed, as this crate's `keygen`
/// writes one. A file over 16,384 bytes holds none.
fn private_keys_in(path: &std::path::Path) -> Vec<[u8; 32]> {
    let Some(data) = std::fs::metadata(path).ok().filter(|meta| meta.len() <= 16_384).and_then(|_| std::fs::read(path).ok()) else {
        return Vec::new();
    };
    let seeds: Vec<[u8; 32]> = if data.len() == 32 {
        data.as_slice().try_into().ok().into_iter().collect()
    } else if data.windows(10).any(|window| window == b"-----BEGIN") && data.windows(11).any(|window| window == b"PRIVATE KEY") {
        std::str::from_utf8(&data).map_or_else(|_| Vec::new(), |text| pem_private_blocks(text).iter().filter_map(|der| pkcs8_seed(der)).collect())
    } else {
        Vec::new()
    };
    seeds.iter().map(|seed| SigningKey::from_bytes(seed).verifying_key().to_bytes()).collect()
}

/// The DER of each `PRIVATE KEY` block of a PEM text, each block read on its own, so a private key block
/// beside a public one is still found. Whitespace inside a block, a carriage return among it, is skipped.
fn pem_private_blocks(text: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("-----BEGIN ") {
        let after = &rest[start + 11..];
        let Some(label_end) = after.find("-----") else { break };
        let label = &after[..label_end];
        let body = &after[label_end + 5..];
        let end_marker = format!("-----END {label}-----");
        let Some(end) = body.find(&end_marker) else { break };
        if label.ends_with("PRIVATE KEY") {
            let base64: String = body[..end].chars().filter(|c| !c.is_whitespace()).collect();
            if let Some(der) = base64_decode(&base64) {
                out.push(der);
            }
        }
        rest = &body[end + end_marker.len()..];
    }
    out
}

/// The seed of a PKCS8 Ed25519 private key (RFC 8410), version 1, or version 2 with its public key after it.
fn pkcs8_seed(der: &[u8]) -> Option<[u8; 32]> {
    let v1 = der.len() == 48 && der[..16] == PKCS8_ED25519;
    let mut v2_head = PKCS8_ED25519;
    v2_head[1] = 0x51;
    v2_head[4] = 0x01;
    let v2 = der.len() == 83 && der[..16] == v2_head && der[48..51] == [0x81, 0x21, 0x00];
    if !(v1 || v2) {
        return None;
    }
    let seed: [u8; 32] = der[16..48].try_into().ok()?;
    if v2 && SigningKey::from_bytes(&seed).verifying_key().to_bytes()[..] != der[51..] {
        return None;
    }
    Some(seed)
}

/// Standard base64 with padding, or None.
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let value = |byte: u8| match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    };
    let bytes = text.as_bytes();
    if bytes.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let pad = chunk.iter().rev().take_while(|byte| **byte == b'=').count();
        if pad > 2 {
            return None;
        }
        let mut word = 0u32;
        for byte in &chunk[..4 - pad] {
            word = word << 6 | u32::from(value(*byte)?);
        }
        word <<= 6 * pad as u32;
        let three = [(word >> 16) as u8, (word >> 8) as u8, word as u8];
        out.extend_from_slice(&three[..3 - pad]);
    }
    Some(out)
}

/// What `decide` answers: the decision made under the active release, or the cause every decision is
/// refused with (X3), and the hold mark a receipt carries (X7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision<T> {
    pub decision: Option<T>,
    pub cause: Option<&'static str>,
    pub mark: Option<&'static str>,
}

/// One enforcement point following one stream. `adapter` is the target's, `instance_key` the PEP's own,
/// `clock` a function answering Unix seconds. `has_clock` false is a PEP with no real time clock (T2, T3).
/// The expiry response is the deployment's setting (X6), `refuse` unless the target kind allows `hold`, and
/// it is fixed for the life of the PEP (X10).
pub struct Pep<A: Adapter> {
    pub adapter: A,
    pub audit: AuditLog,
    target: Target,
    instance_key: SigningKey,
    instance_key_id: Hex64,
    clock: Box<dyn Fn() -> i64>,
    expiry_response: String,
    has_clock: bool,
    store: Store,
    epoch: u64,
    held: bool,
    outbox: Vec<Vec<u8>>,
    hook: Option<PepHook>,
    locked: bool,
    provisioned: bool,
    stream: Option<Stream>,
    trust: TrustStore,
    floor: Floor,
    counter: i64,
    active: Option<Release>,
    previous: Option<Release>,
    staged: Option<Release>,
    pending: Option<PendingDoc>,
    /// The runtime may not hold what the PEP holds: a flip or a lapse failed after its record was durable. The
    /// PEP decides nothing and reports nothing until `match_runtime` succeeds again.
    unreconciled: bool,
    /// The transition whose record and audit event wait for the runtime to match (C5, X1, H4).
    owed: Option<Owed>,
    /// While reconciling, the release the runtime may still hold, which the records report as active.
    may_hold: Option<Release>,
}

/// A transition already durable whose record is not sent yet: a flip whose runtime step failed, which
/// `pending.json` holds across a restart, or a lapse whose runtime step failed, which `owed.json` holds.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Owed {
    Flip { event: &'static str },
    Lapse { cause: String, seq: Option<i64> },
}

/// `owed.json`: a lapse made durable whose runtime step and report are not done yet, naming the release that
/// lapsed by its seq and envelope ids.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwedDoc {
    cause: String,
    encoding: Canon2Tag,
    envelopes: SortedSet<Hex64>,
    format: OwedFormat,
    seq: Option<i64>,
}

/// `epoch.json`: the highest epoch id the controller sent (H9), so a restart never reports a lower one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EpochDoc {
    encoding: Canon2Tag,
    epoch: i64,
    format: EpochFormat,
}

/// What a call answers while the runtime may hold another release than the PEP.
const RECONCILING: &str = "the runtime does not hold the PEP's release yet; the next tick tries again";

impl<A: Adapter> Pep<A> {
    /// The PEP over `<state_dir>/dist/`: its durable state read, its setting and key separation checked,
    /// an interrupted commit finished or reported, and the runtime made to match what it holds.
    pub fn new(
        state_dir: &str,
        adapter: A,
        instance_key: SigningKey,
        clock: Box<dyn Fn() -> i64>,
        expiry_response: &str,
        has_clock: bool,
    ) -> Result<Pep<A>, PepError> {
        let kind = adapter.kind();
        let target = kind.target().ok_or_else(|| refused(format!("no enforcement point of kind {kind} is built")))?;
        if expiry_response != REFUSE && expiry_response != HOLD {
            return Err(refused(format!("the expiry response is {REFUSE} or {HOLD}, not {expiry_response:?}")));
        }
        if expiry_response == HOLD && !target.expiry_hold {
            return Err(refused(format!("a {kind} PEP has no HOLD setting; it always refuses at expiry (X6, X10)")));
        }
        let store = Store::new(&format!("{state_dir}/dist"))?;
        let audit = AuditLog::open(&store.path("audit.log"))?;
        let instance_key_id = env::key_id(&instance_key.verifying_key().to_bytes());
        let mut pep = Pep {
            adapter,
            audit,
            target,
            instance_key,
            instance_key_id,
            clock,
            expiry_response: expiry_response.to_string(),
            has_clock,
            store,
            epoch: 0,
            held: false,
            outbox: Vec::new(),
            hook: None,
            locked: false,
            provisioned: false,
            stream: None,
            trust: TrustStore::unreadable(),
            floor: Floor::default(),
            counter: 0,
            active: None,
            previous: None,
            staged: None,
            pending: None,
            unreconciled: false,
            owed: None,
            may_hold: None,
        };
        pep.load()?;
        pep.check_setting()?;
        pep.check_separation(&pep.trust.clone())?;
        pep.recover()?;
        Ok(pep)
    }

    /// Install (or clear) the fault injection point. See the module note.
    pub fn set_commit_hook(&mut self, hook: Option<PepHook>) {
        self.hook = hook;
    }

    fn fault(&self, step: PepStep) -> Result<(), PepError> {
        match &self.hook {
            Some(hook) => hook(step).map_err(|_| PepError::Host(HostError::Injected(step.name().to_string()))),
            None => Ok(()),
        }
    }

    // ------------------------------------------------------------------ the durable state
    fn trust_path(&self) -> String {
        self.store.path("trust.json")
    }

    fn load(&mut self) -> Result<(), PepError> {
        self.provisioned = self.store.exists("anchor.json");
        if !self.provisioned {
            return Ok(()); // P1: nothing to believe yet
        }
        self.trust = TrustStore::load(&self.trust_path());
        if let Ok(doc) = self.store.read::<EpochDoc>("epoch.json") {
            self.epoch = u64::try_from(doc.epoch).unwrap_or(0); // H9: what a restart reports is never lower
        }
        // H3: the counter is kept apart from the floor. One that cannot be read must still never repeat: the PEP
        // locks, and its records count on from its time in microseconds, above any counter it can have sent one
        // record at a time.
        match self.store.read::<CounterDoc>("counter.json") {
            Ok(doc) if (0..=MAX_SEQ).contains(&doc.counter) => self.counter = doc.counter,
            _ => {
                self.counter = self.time().saturating_mul(1_000_000);
                self.locked = true;
            }
        }
        let anchored = std::fs::read(self.store.path("anchor.json"))
            .map_err(|error| Refused::new(super::BAD_FORMAT, error.to_string()))
            .and_then(|raw| read_anchor(&raw));
        match anchored {
            Ok(anchor) => {
                let floor = self.store.read::<FloorDoc>("floor.json");
                match floor {
                    Ok(floor) if floor.stream == anchor.stream && (0..=MAX_SEQ).contains(&floor.seq) => {
                        self.floor = Floor { seq: floor.seq, ids: floor.ids.iter().cloned().collect() };
                    }
                    _ => self.locked = true, // Q5
                }
                self.stream = Some(anchor.stream);
            }
            Err(_) => self.locked = true,
        }
        if self.locked {
            return Ok(());
        }
        if self.store.exists("active.json") {
            let read = self
                .store
                .read::<ActiveDoc>("active.json")
                .and_then(|doc| Ok((self.release_of(doc.release.as_ref())?, self.release_of(doc.previous.as_ref())?)));
            match read {
                Ok((active, previous)) => {
                    self.active = active;
                    self.previous = previous;
                }
                Err(refusal) => {
                    self.audit.append(
                        "distribution",
                        "active_unreadable",
                        vec![("reason", json!(refusal.to_string())), ("result", json!("not_restored"))],
                    )?;
                }
            }
        }
        if self.store.exists("staged.json") {
            self.staged =
                self.store.read::<StagedDoc>("staged.json").and_then(|doc| self.release_of(Some(&doc.release))).ok().flatten();
        }
        if self.store.exists("pending.json") {
            self.pending = Some(self.store.read::<PendingDoc>("pending.json").unwrap_or(PendingDoc {
                encoding: Canon2Tag,
                format: PendingFormat,
                op: "unknown".to_string(),
                release: None,
            }));
        }
        Ok(())
    }

    /// X10: the expiry response is fixed at provisioning. A start with another one is refused, and one that
    /// cannot be read locks the PEP.
    fn check_setting(&mut self) -> Result<(), PepError> {
        if !self.provisioned {
            return Ok(());
        }
        match self.store.read::<SettingDoc>("setting.json") {
            Err(_) => self.locked = true,
            Ok(doc) if doc.expiry != self.expiry_response => {
                return Err(refused(format!(
                    "this PEP was provisioned to {} at expiry, not to {} (X10)",
                    doc.expiry, self.expiry_response
                )));
            }
            Ok(_) => {}
        }
        Ok(())
    }

    /// A release document read back with every blob it names, or `Refused` when one is missing or not its
    /// name's. Nothing the record does not name is ever read (C4).
    fn release_of(&self, doc: Option<&ReleaseDoc>) -> Result<Option<Release>, Refused> {
        let Some(doc) = doc else { return Ok(None) };
        let mut release = Release {
            stream: doc.stream.clone(),
            seq: doc.seq,
            policy_sha256: doc.policy_sha256.clone(),
            release: doc.release.clone(),
            replaces: doc.replaces.clone(),
            widens: doc.widens,
            held: BTreeMap::new(),
            envelopes: BTreeMap::new(),
            bodies: BTreeMap::new(),
            paths: BTreeMap::new(),
        };
        for (artifact, held) in &doc.held {
            let (Some(sealed), Some(body)) = (self.store.get(&held.sealed), self.store.get(&held.body)) else {
                return Err(Refused::new(super::BAD_FORMAT, format!("a blob of {artifact} is missing or not its name's")));
            };
            let envelope = env::read(env::unseal(&sealed)?.0)?;
            if envelope.envelope_id() != held.envelope_id || envelope.artifact != *artifact {
                return Err(Refused::new(super::BAD_FORMAT, format!("the blob of {artifact} is another envelope")));
            }
            release.held.insert(*artifact, held.clone());
            release.envelopes.insert(*artifact, envelope);
            release.bodies.insert(*artifact, body);
            release.paths.insert(*artifact, self.store.blob_path(&held.body));
        }
        Ok(Some(release))
    }

    /// K2: the instance key is never a trusted key, and the home holds no private half of one. The scan of the
    /// home is bounded as the Python machine bounds it: not the PEP's own store, not the `runs` a home keeps, no
    /// deeper than two levels, no file over 16,384 bytes and at most 4,096 files.
    fn check_separation(&self, trust: &TrustStore) -> Result<(), PepError> {
        if trust.keys.contains_key(&self.instance_key_id) {
            return Err(refused("the instance key is also a trusted authority key (K2)"));
        }
        let Some(home) = self.adapter.home().filter(|home| std::path::Path::new(home).is_dir()) else { return Ok(()) };
        if trust.keys.is_empty() {
            return Ok(());
        }
        let store = std::path::PathBuf::from(&self.store.dir);
        let mut looked = 0usize;
        let mut directories = vec![(std::path::PathBuf::from(abspath(&home)), 0usize)];
        while let Some((directory, depth)) = directories.pop() {
            let Ok(entries) = std::fs::read_dir(&directory) else { continue };
            let mut entries: Vec<_> = entries.flatten().collect();
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                let path = entry.path();
                let Ok(kind) = entry.file_type() else { continue };
                if kind.is_dir() {
                    if depth < 2 && path != store && entry.file_name() != K2_SKIP {
                        directories.push((path, depth + 1));
                    }
                    continue;
                }
                looked += 1;
                if looked > K2_SCAN {
                    return Ok(());
                }
                if private_keys_in(&path).iter().any(|public| trust.keys.contains_key(&env::key_id(public))) {
                    return Err(refused(format!("{} holds the private half of a trusted authority key (K2)", path.display())));
                }
            }
        }
        Ok(())
    }

    /// Finish or report an interrupted commit or rollback (C4), hold the staged and the active release to the
    /// revocation test again (R5) and check expiry (X1), all before the runtime is made to match what the PEP
    /// holds, so a release that fell while the PEP was down never runs again.
    fn recover(&mut self) -> Result<(), PepError> {
        if let Some(pending) = self.pending.take() {
            let finished = match (&self.active, &pending.release) {
                (Some(active), Some(target)) => active.document() == *target,
                _ => false,
            };
            if finished {
                // the flip happened: its record goes once the runtime matches, and its clean up with it. Before a
                // commit's flip the runtime held the release it replaced, which a commit keeps as the previous one
                let rollback = pending.op == "rollback";
                self.owed = Some(Owed::Flip { event: if rollback { "rolled-back" } else { "committed" } });
                self.may_hold = if rollback { None } else { self.previous.clone() };
                self.unreconciled = true;
            } else {
                self.audit.append(
                    "distribution",
                    "commit_incomplete",
                    vec![("op", json!(pending.op)), ("result", json!("incomplete"))],
                )?;
                self.store.remove("pending.json")?;
            }
        }
        if self.store.exists("owed.json") && !self.locked {
            // owed only when the active record no longer names a release and the lapsed one is at or below the
            // floor; otherwise the lapse never reached its active record, or the file is another's, and it goes.
            // A locked PEP read no active record, so the file waits for provisioning, which removes it
            let owed = self.store.read::<OwedDoc>("owed.json").ok().filter(|doc| {
                self.active.is_none() && doc.seq.is_none_or(|seq| (0..=self.floor.seq).contains(&seq))
            });
            match owed {
                Some(doc) => {
                    self.owed = Some(Owed::Lapse { cause: doc.cause, seq: doc.seq });
                    self.unreconciled = true;
                }
                None => self.store.remove("owed.json")?,
            }
        }
        // a flip that died before its clean up leaves the release it made active also staged: it is done
        let done = match (&self.staged, &self.active) {
            (Some(staged), Some(active)) => staged.stream == active.stream && staged.seq <= active.seq,
            _ => false,
        };
        if done {
            self.drop_staged()?;
        }
        self.drop_fallen_staged()?;
        if self.unreconciled {
            // a runtime that still fails leaves the PEP refusing until a tick reconciles it
            return self.reconcile().map(|_| ()).or(Ok(()));
        }
        self.check_active()?;
        self.match_runtime()
    }

    fn match_runtime(&self) -> Result<(), PepError> {
        match (self.own_refusal(), &self.active) {
            (None, Some(active)) => self.adapter.activate(active),
            (Some(cause), _) => self.adapter.deactivate(self.owed_cause().unwrap_or(cause)),
            (None, None) => self.adapter.deactivate(POLICY_LAPSED),
        }
    }

    /// The cause of a lapse whose report is owed, which the runtime is told when it is made to refuse.
    fn owed_cause(&self) -> Option<&str> {
        match &self.owed {
            Some(Owed::Lapse { cause, .. }) => Some(cause),
            _ => None,
        }
    }

    // ------------------------------------------------------------------ what the PEP is
    pub fn state(&self) -> &'static str {
        if self.locked {
            "locked"
        } else if self.unreconciled {
            "no-policy" // every decision is refused, whatever the runtime may still hold
        } else if self.active.is_some() && self.trust.is_readable() {
            "active"
        } else {
            "no-policy"
        }
    }

    /// True while the runtime may hold another release than the PEP: a flip or a lapse failed past its active
    /// record, and a tick has not made the runtime match yet.
    pub fn is_reconciling(&self) -> bool {
        self.unreconciled
    }

    /// X3: None while a release is active, else the cause every decision is refused with.
    pub fn refusal(&self) -> Option<&'static str> {
        if self.unreconciled {
            Some(POLICY_LAPSED)
        } else {
            self.own_refusal()
        }
    }

    /// The refusal of what the PEP holds, whatever its runtime holds: what `match_runtime` makes the runtime do.
    fn own_refusal(&self) -> Option<&'static str> {
        if self.locked {
            Some(FLOOR_LOST)
        } else if self.active.is_some() && self.trust.is_readable() {
            None
        } else {
            Some(POLICY_LAPSED)
        }
    }

    /// T1: the larger of the clock and the time floor.
    pub fn time(&self) -> i64 {
        (self.clock)().max(if self.trust.is_readable() { self.trust.time_floor } else { 0 })
    }

    pub fn active(&self) -> Option<&Release> {
        self.active.as_ref()
    }

    pub fn previous(&self) -> Option<&Release> {
        self.previous.as_ref()
    }

    pub fn staged(&self) -> Option<&Release> {
        self.staged.as_ref()
    }

    pub fn floor(&self) -> &Floor {
        &self.floor
    }

    pub fn trust(&self) -> &TrustStore {
        &self.trust
    }

    pub fn is_provisioned(&self) -> bool {
        self.provisioned
    }

    pub fn is_held(&self) -> bool {
        self.held
    }

    pub fn instance_public(&self) -> [u8; 32] {
        self.instance_key.verifying_key().to_bytes()
    }

    /// The path of one of the store's files, `trust.json` or `floor.json` say.
    pub fn store_path(&self, name: &str) -> String {
        self.store.path(name)
    }

    /// Hold `trust` as the trust store from now on, in memory only, as a store changed under a staged
    /// release holds it. For the tests of what the machine checks again at commit (C3), so only with the
    /// `test-support` feature, which the crate's own tests turn on and no build of it does.
    #[cfg(feature = "test-support")]
    pub fn replace_trust(&mut self, trust: TrustStore) {
        self.trust = trust;
    }

    fn view(&self) -> Option<PepView> {
        Some(PepView {
            kind: PepKind::try_from(self.adapter.kind()).ok()?,
            stream: self.stream.clone()?,
            floor: self.floor.clone(),
            active: self.active.as_ref().map(|active| active.policy_sha256.clone()),
            staged: self.staged.as_ref().map(|staged| Staged {
                stream: staged.stream.clone(),
                seq: staged.seq,
                policy_sha256: staged.policy_sha256.clone(),
                release: staged.release.clone(),
                replaces: staged.replaces.clone(),
                widens: staged.widens,
            }),
            qualification: self.adapter.qualification(),
            body_bound: self.adapter.body_bound(),
            has_clock: self.has_clock,
            instance_key_id: Some(self.instance_key_id.clone()),
        })
    }

    /// A signed state record of the PEP as it is now (H1), after the expiry check every report comes after (X1).
    pub fn record(&mut self, event: &'static str, cause: Option<&str>) -> Result<Vec<u8>, PepError> {
        self.check_active()?;
        self.make_record(event, cause)
    }

    /// Every state record made since the last drain, oldest first: what the PEP sends (H4). A transition found
    /// on the way into a call, such as a lapse, is in it before the call's own record.
    pub fn drain(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.outbox)
    }

    /// Make one record, its counter durable first (H3), and put it in the outbox.
    fn make_record(&mut self, event: &'static str, cause: Option<&str>) -> Result<Vec<u8>, PepError> {
        self.counter += 1;
        if self.provisioned {
            self.store.write("counter.json", &CounterDoc { counter: self.counter, encoding: Canon2Tag, format: CounterFormat })?;
        }
        let unsigned = |value: i64| u64::try_from(value).unwrap_or(0);
        let prefix = |hash: Option<&Hex64>| state_record::prefix(hash.map(Hex64::as_str));
        // While reconciling the record says what the runtime may hold, as the active release, and the release the
        // PEP made active and the runtime may not run yet, as the staged one; its state is no-policy (DIVERGENCES)
        let (active, staged) = match (&self.owed, self.unreconciled) {
            (Some(Owed::Flip { .. }), true) => (self.may_hold.as_ref(), self.active.as_ref()),
            (_, true) => (self.may_hold.as_ref(), self.staged.as_ref()),
            _ => (self.active.as_ref(), self.staged.as_ref()),
        };
        let record = StateRecord {
            cause: cause.map(str::to_string),
            pep_id: state_record::pep_id(&self.instance_public()),
            counter: unsigned(self.counter),
            time: unsigned(self.time()),
            epoch: self.epoch,
            stream: state_record::stream_prefix(self.stream.as_ref().map_or("", Stream::as_str)),
            active_policy: prefix(active.map(|release| &release.policy_sha256)),
            active_release: prefix(active.map(|release| &release.release)),
            active_seq: unsigned(active.map_or(0, |release| release.seq)),
            floor: unsigned(self.reported_floor()),
            staged_release: prefix(staged.map(|release| &release.release)),
            staged_seq: unsigned(staged.map_or(0, |release| release.seq)),
            trust_seq: unsigned(if self.trust.is_readable() { self.trust.trust_seq } else { 0 }),
            staged: staged.is_some(),
            dev_build: super::DEV_BUILD,
            held: self.held,
            ..StateRecord::new(event, self.state())
        };
        let signed = state_record::build(&record, &self.instance_key).map_err(PepError::Refused)?;
        self.outbox.push(signed.clone());
        Ok(signed)
    }

    /// H1, R4: the floor V8 holds, the larger of the committed floor and the one a revocation raised.
    pub fn reported_floor(&self) -> i64 {
        let raised = match (&self.stream, self.trust.is_readable()) {
            (Some(stream), true) => self.trust.floors.get(stream).copied().unwrap_or(0),
            _ => 0,
        };
        self.floor.seq.max(raised)
    }

    /// H9: keep the highest epoch id the controller sent. It changes nothing else.
    pub fn see_epoch(&mut self, epoch: u64) -> Result<(), PepError> {
        if epoch > self.epoch {
            self.epoch = epoch;
            if self.provisioned {
                let epoch = i64::try_from(epoch).unwrap_or(MAX_SEQ).min(MAX_SEQ);
                self.store.write("epoch.json", &EpochDoc { encoding: Canon2Tag, epoch, format: EpochFormat })?;
            }
        }
        Ok(())
    }

    /// X5, B5: which of the offered blobs this PEP does not hold. An offer is a hint and changes nothing.
    pub fn needs(&self, blobs: &[Hex64]) -> Vec<Hex64> {
        blobs.iter().filter(|name| self.store.get(name).is_none()).cloned().collect()
    }

    /// X5: a blob the PEP already holds under its SHA-256.
    pub fn blob(&self, name: &Hex64) -> Option<Vec<u8>> {
        self.store.get(name)
    }

    // ------------------------------------------------------------------ G1, G2: stage
    fn refuse(&mut self, cause: &str, mut details: Fields) -> Result<Vec<u8>, PepError> {
        details.push(("cause", json!(cause)));
        details.push(("result", json!("refused")));
        self.audit.append("distribution", "refused", details)?;
        self.make_record("refused", Some(cause))
    }

    /// B4, B9: the binding refused the blob `name` before anything was staged. The refusal is the PEP's own,
    /// in its audit log and its records, and nothing else changes.
    pub fn refuse_fetched(&mut self, cause: &str, name: &Hex64) -> Result<Vec<u8>, PepError> {
        self.check_active()?;
        self.refuse(cause, vec![("blob", json!(name.as_str()))])
    }

    /// Verify one sealed envelope and its body and hold it (G1). Returns the stage-ack state record.
    pub fn stage(&mut self, sealed: &[u8], body: &[u8]) -> Result<Vec<u8>, PepError> {
        self.check_active()?;
        if self.locked {
            return self.refuse(FLOOR_LOST, Vec::new());
        }
        let view = match (self.provisioned, self.view()) {
            (true, Some(view)) => view,
            _ => return self.refuse(UNKNOWN_KEY, Vec::new()), // P1, P2 step 4
        };
        let verdict = verify::verify(sealed, body, &self.trust, &view, (self.clock)());
        if let Some(time_floor) = verdict.time_floor {
            if self.trust.is_readable() && time_floor > self.trust.time_floor {
                self.trust.time_floor = time_floor; // V13, T1
                self.trust.save(&self.trust_path())?;
            }
        }
        let envelope_id = json!(verdict.envelope.as_ref().map(|envelope| envelope.envelope_id().to_string()));
        if let Some(cause) = &verdict.cause {
            return self.refuse(cause, vec![("envelope_id", envelope_id)]);
        }
        if verdict.unchanged {
            return self.make_record("beat", None); // Q3, R1: changes nothing, reports its state
        }
        let envelope = verdict.envelope.expect("an accepted verdict carries its envelope");
        match envelope.artifact {
            ArtifactKind::TrustRevocation => return self.apply_revocation(&envelope, body),
            ArtifactKind::TrustRotation => return self.apply_rotation(&envelope, body),
            _ => {}
        }
        if let Some(staged) = &self.staged {
            if staged.stream == envelope.stream && envelope.seq < staged.seq {
                return self.refuse(SEQ_REPLAY, vec![("envelope_id", envelope_id)]); // G2
            }
        }
        // built beside the staged release and held only once every write is durable, so a write that fails
        // leaves the staged release as it was
        let mut staged = match &self.staged {
            Some(staged) if staged.seq == envelope.seq => staged.clone(),
            _ => Release::of(&envelope),
        };
        let held = HeldDoc { body: self.store.put(body)?, envelope_id: envelope.envelope_id(), sealed: self.store.put(sealed)? };
        staged.paths.insert(envelope.artifact, self.store.blob_path(&held.body));
        staged.held.insert(envelope.artifact, held);
        staged.bodies.insert(envelope.artifact, body.to_vec());
        staged.envelopes.insert(envelope.artifact, envelope.clone());
        self.store.write("staged.json", &StagedDoc { encoding: Canon2Tag, format: StagedFormat, release: staged.document() })?;
        self.staged = Some(staged);
        self.keep_blobs(); // a replaced release's blobs go (G2)
        self.audit.append(
            "distribution",
            "staged",
            vec![
                ("envelope_id", envelope_id),
                ("artifact", json!(envelope.artifact.name())),
                ("seq", json!(envelope.seq)),
                ("release", json!(envelope.release.as_str())),
                ("result", json!("staged")),
            ],
        )?;
        self.make_record("staged", None)
    }

    // ------------------------------------------------------------------ B2: the trust statements
    /// Make the store a verified trust statement leaves durable before anything reports it (B2, R3).
    fn adopt(&mut self, envelope: &Envelope, store: TrustStore) -> Result<(), PepError> {
        store.save(&self.trust_path())?;
        self.trust = store;
        self.audit.append(
            "distribution",
            "trust-applied",
            vec![
                ("envelope_id", json!(envelope.envelope_id().as_str())),
                ("seq", json!(envelope.seq)),
                ("artifact", json!(envelope.artifact.name())),
                ("result", json!("applied")),
            ],
        )?;
        Ok(())
    }

    /// Apply a verified revocation at once, then drop the staged release and lapse the active one when the
    /// revocation removed the ground they stand on (R5). A held PEP lapses the same way, which ends the hold (X8).
    fn apply_revocation(&mut self, envelope: &Envelope, body: &[u8]) -> Result<Vec<u8>, PepError> {
        let store = self.trust.apply_revocation(envelope, body, self.stream.as_ref()).map_err(|refusal| refused(refusal.to_string()))?;
        self.adopt(envelope, store)?;
        self.drop_fallen_staged()?;
        self.check_active()?;
        self.make_record("trust-applied", None)
    }

    /// Apply a verified rotation at once (O3). A release active under a key it retires stays active until it
    /// expires or is replaced, and a staged one that no longer has a counting signature is dropped (S5).
    fn apply_rotation(&mut self, envelope: &Envelope, body: &[u8]) -> Result<Vec<u8>, PepError> {
        let store = self.trust.apply_rotation(envelope, body).map_err(|refusal| refused(refusal.to_string()))?;
        self.adopt(envelope, store)?;
        self.drop_fallen_staged()?;
        self.make_record("trust-applied", None)
    }

    /// R5: a staged release that no longer stands is dropped.
    fn drop_fallen_staged(&mut self) -> Result<(), PepError> {
        let fallen = self.staged.as_ref().is_some_and(|staged| self.trust.is_readable() && !self.stands(staged, false));
        if fallen {
            self.drop_staged()?;
        }
        Ok(())
    }

    /// R5: a release still stands when no envelope of it is listed by id or policy hash, its `seq` is not below
    /// a floor a revocation raised, and every envelope of it is still signed. A key that was only retired still
    /// holds up a release already active under it (O3), and a staged release needs a counting signature (S5),
    /// as it would at commit.
    fn stands(&self, release: &Release, active: bool) -> bool {
        if release.seq < self.raised_floor(&release.stream) {
            return false;
        }
        release.held.values().all(|held| {
            if self.trust.revoked_envelopes.contains(&held.envelope_id) || self.trust.revoked_policies.contains(&release.policy_sha256) {
                return false;
            }
            let Some(sealed) = self.store.get(&held.sealed) else { return false };
            let Ok((envelope_bytes, entries)) = env::unseal(&sealed) else { return false };
            let message = env::signed_message(envelope_bytes);
            if active {
                self.trust.holds_up(&entries, &message, AUTHORITY)
            } else {
                self.trust.counting(&entries, &message, AUTHORITY).ok()
            }
        })
    }

    fn raised_floor(&self, stream: &str) -> i64 {
        Stream::try_from(stream).ok().and_then(|stream| self.trust.floors.get(&stream).copied()).unwrap_or(0)
    }

    // ------------------------------------------------------------------ C1 to C5: commit
    fn drop_staged(&mut self) -> Result<(), PepError> {
        self.staged = None;
        self.store.remove("staged.json")?;
        self.keep_blobs();
        Ok(())
    }

    fn keep_blobs(&self) {
        let keep: BTreeSet<Hex64> = [&self.active, &self.previous, &self.staged]
            .into_iter()
            .flatten()
            .flat_map(|release| release.held.values().flat_map(|held| [held.sealed.clone(), held.body.clone()]))
            .collect();
        self.store.keep_only(&keep);
    }

    /// C3, RB2: time (T3 when `early`, T4) and revocation (V7) again for every envelope of `release`, and at a
    /// commit (`early`) a counting signature again (V3), since a rotation may have retired its key.
    fn still_valid(&self, release: &Release, early: bool) -> Option<String> {
        let time = self.time();
        for (artifact, envelope) in &release.envelopes {
            if early {
                let sealed = self.store.get(&release.held[artifact].sealed).unwrap_or_default();
                let (envelope_bytes, entries) = env::unseal(&sealed).map(|(bytes, entries)| (bytes.to_vec(), entries)).unwrap_or_default();
                let counted = self.trust.counting(&entries, &env::signed_message(&envelope_bytes), AUTHORITY);
                if let Some(cause) = counted.cause {
                    return Some(cause);
                }
            }
            if early && self.has_clock && envelope.not_before - time > SKEW {
                return Some(NOT_YET_VALID.to_string());
            }
            if envelope.expires != 0 && time >= envelope.expires {
                return Some(EXPIRED.to_string());
            }
            if self.trust.revoked_envelopes.contains(&envelope.envelope_id()) || self.trust.revoked_policies.contains(&envelope.policy_sha256) {
                return Some(REVOKED.to_string());
            }
        }
        None
    }

    /// Make the staged release named by `stream`, `seq` and `policy_sha256` active (C1 to C5). A delay in
    /// milliseconds (B8) belongs to the frame binding, which this crate does not build, so any delay but 0 is
    /// refused and nothing changes.
    pub fn commit(&mut self, stream: &str, seq: i64, policy_sha256: &Hex64, delay_ms: u16) -> Result<Vec<u8>, PepError> {
        if delay_ms != 0 {
            return Err(refused(format!(
                "a commit delay of {delay_ms} ms (B8) is the frame binding's, which this crate does not build; commit with no delay"
            )));
        }
        if self.unreconciled {
            return Err(refused(RECONCILING)); // a commit changes the runtime, which must match first
        }
        self.check_active()?;
        if self.locked {
            return self.refuse(FLOOR_LOST, Vec::new());
        }
        if !self.trust.is_readable() {
            return self.refuse(UNKNOWN_KEY, Vec::new()); // K1: decides nothing, commits nothing
        }
        let Some(staged) = self.staged.clone().filter(|staged| staged.names(stream, seq, policy_sha256)) else {
            return self.make_record("refused", Some(NOT_STAGED)); // C1: nothing changes
        };
        if !self.target.needs.iter().all(|artifact| staged.held.contains_key(artifact)) {
            return self.refuse(INCOMPLETE, vec![("seq", json!(seq))]); // C2
        }
        for (artifact, body) in &staged.bodies {
            if let Some(cause) = self.adapter.check(*artifact, body, &staged) {
                return self.refuse(&cause, vec![("seq", json!(seq))]);
            }
        }
        if let Some(cause) = self.still_valid(&staged, true) {
            // C3
            self.drop_staged()?;
            return self.refuse(&cause, vec![("seq", json!(seq))]);
        }
        let floor = Floor { seq: staged.seq, ids: staged.envelope_ids() };
        let previous = self.active.clone();
        self.flip("commit", staged, previous, floor)
    }

    /// C4, one step after another, each synced: intent, floor (a commit only), evidence, the artifacts (already
    /// blobs), the active record, the runtime, the clean up.
    fn flip(&mut self, op: &str, release: Release, previous: Option<Release>, floor: Floor) -> Result<Vec<u8>, PepError> {
        self.fault(PepStep::Intent)?;
        self.store.write(
            "pending.json",
            &PendingDoc { encoding: Canon2Tag, format: PendingFormat, op: op.to_string(), release: Some(release.document()) },
        )?;
        let committing = op == "commit";
        if committing {
            self.fault(PepStep::Floor)?;
            let stream = self.stream.clone().ok_or_else(|| refused("a PEP that follows no stream commits nothing"))?;
            self.store.write(
                "floor.json",
                &FloorDoc { encoding: Canon2Tag, format: FloorFormat, ids: floor.ids.iter().cloned().collect(), seq: floor.seq, stream },
            )?;
            self.floor = floor;
        }
        let event = if committing { "committed" } else { "rolled-back" };
        self.fault(PepStep::Evidence)?;
        self.audit.append(
            "distribution",
            event,
            vec![
                ("stream", json!(release.stream)),
                ("seq", json!(release.seq)),
                ("release", json!(release.release.as_str())),
                ("policy_sha256", json!(release.policy_sha256.as_str())),
                ("envelopes", json!(release.envelope_ids().iter().map(Hex64::as_str).collect::<Vec<_>>())),
                ("result", json!(event)),
            ],
        )?;
        self.fault(PepStep::ActiveRecord)?;
        self.store.write(
            "active.json",
            &ActiveDoc {
                encoding: Canon2Tag,
                format: ActiveFormat,
                previous: previous.as_ref().map(Release::document),
                release: Some(release.document()),
            },
        )?;
        if self.staged.as_ref().is_some_and(|staged| staged.seq <= release.seq) {
            self.staged = None;
        }
        let ran = self.active.replace(release);
        self.previous = previous;
        self.held = false;
        self.owed = Some(Owed::Flip { event });
        self.may_hold = ran;
        let matched = self.fault(PepStep::Runtime).and_then(|()| self.match_runtime()); // X3
        if let Err(error) = matched {
            // the active record names the new release and the runtime may still hold the old one: no decision is
            // made until a tick makes the runtime match, and the record is sent then
            self.unreconciled = true;
            return Err(error);
        }
        self.settle()
    }

    /// C4's end once the runtime matches: the owed record, durable, then what it owes goes (the intent record,
    /// `owed.json`) and the clean up runs. A record that cannot be made leaves the PEP reconciling, so the next
    /// tick sends it.
    fn settle(&mut self) -> Result<Vec<u8>, PepError> {
        let owed = self.owed.clone().expect("a transition to settle");
        self.unreconciled = false;
        let made = match &owed {
            Owed::Flip { event } => self.make_record(event, None),
            Owed::Lapse { cause, seq } => self.report_lapse(cause, *seq),
        };
        let record = match made {
            Ok(record) => record,
            Err(error) => {
                self.unreconciled = true;
                return Err(error);
            }
        };
        self.owed = None;
        self.may_hold = None;
        self.fault(PepStep::Cleanup)?;
        match owed {
            Owed::Flip { .. } => self.cleanup()?,
            Owed::Lapse { .. } => {
                self.keep_blobs();
                self.store.remove("owed.json")?;
            }
        }
        Ok(record)
    }

    /// The lapsed audit event, once across a crash before `owed.json` goes, and the lapsed record.
    fn report_lapse(&mut self, cause: &str, seq: Option<i64>) -> Result<Vec<u8>, PepError> {
        let written = self.audit.last_event().is_some_and(|event| {
            event["action"] == "lapsed" && event["data"]["seq"] == json!(seq) && event["data"]["cause"] == json!(cause)
        });
        if !written {
            self.audit.append("distribution", "lapsed", vec![("seq", json!(seq)), ("cause", json!(cause)), ("result", json!("lapsed"))])?;
        }
        self.make_record("lapsed", Some(cause))
    }

    /// Make the runtime hold what the PEP holds again after a flip or a lapse failed past its record, then send
    /// what the transition owed. One try: the caller is a tick or a start. The PEP's active release is held to
    /// expiry and revocation first, as at a start, so a release that fell meanwhile is never installed: the
    /// runtime withdraws what it ran, the commit is reported refused with the cause it fell for, and the PEP
    /// lapses with that cause. The record of the last transition reported, if any.
    fn reconcile(&mut self) -> Result<Option<Vec<u8>>, PepError> {
        if !self.unreconciled {
            return Ok(None);
        }
        let fallen = match (&self.active, self.locked || !self.trust.is_readable()) {
            (Some(active), false) if !self.stands(active, true) => Some(REVOKED),
            (Some(active), false)
                if self.expiry_response == REFUSE && self.still_valid(active, false).as_deref() == Some(EXPIRED) =>
            {
                Some(EXPIRED)
            }
            _ => None,
        };
        let (Some(cause), Some(Owed::Flip { .. })) = (fallen, &self.owed) else {
            self.match_runtime()?;
            if self.owed.is_none() {
                self.unreconciled = false;
                return Ok(None);
            }
            return self.settle().map(Some);
        };
        // the release that fell never ran: what ran is withdrawn, then the PEP's lapse is made durable
        self.adapter.deactivate(cause)?;
        let fell = self.active.clone().expect("a fallen release");
        let seq = Some(fell.seq);
        self.store.write(
            "owed.json",
            &OwedDoc { cause: cause.to_string(), encoding: Canon2Tag, envelopes: fell.envelope_ids().into_iter().collect(), format: OwedFormat, seq },
        )?;
        self.store.write(
            "active.json",
            &ActiveDoc { encoding: Canon2Tag, format: ActiveFormat, previous: self.previous.as_ref().map(Release::document), release: None },
        )?;
        self.active = None;
        self.owed = Some(Owed::Lapse { cause: cause.to_string(), seq });
        self.may_hold = None;
        self.store.remove("pending.json")?;
        self.unreconciled = false;
        if let Err(error) = self.refuse(cause, vec![("seq", json!(fell.seq))]) {
            self.unreconciled = true;
            return Err(error);
        }
        self.settle().map(Some)
    }

    fn cleanup(&mut self) -> Result<(), PepError> {
        if self.staged.is_none() {
            self.store.remove("staged.json")?;
        }
        self.keep_blobs();
        self.store.remove("pending.json")?;
        Ok(())
    }

    // ------------------------------------------------------------------ A1: abort
    /// Drop the staged release when the abort names it, and change nothing otherwise (A1).
    pub fn abort(&mut self, stream: &str, seq: i64, policy_sha256: &Hex64) -> Result<Vec<u8>, PepError> {
        self.check_active()?;
        if !self.staged.as_ref().is_some_and(|staged| staged.names(stream, seq, policy_sha256)) {
            return self.make_record("beat", None);
        }
        self.drop_staged()?;
        self.audit.append(
            "distribution",
            "aborted",
            vec![("stream", json!(stream)), ("seq", json!(seq)), ("result", json!("aborted"))],
        )?;
        self.make_record("aborted", None)
    }

    // ------------------------------------------------------------------ X1 to X9: expiry and hold
    /// X1: check the active release's expiry, at least once a minute. It lapses to `no-policy`, or under HOLD is
    /// held (X7). The state record of a transition, None when nothing changed.
    /// A tick is also the one call that tries again to make a runtime that failed match the PEP (C4).
    pub fn tick(&mut self) -> Result<Option<Vec<u8>>, PepError> {
        if self.unreconciled {
            if let Some(record) = self.reconcile()? {
                return Ok(Some(record));
            }
        }
        self.check_active()
    }

    /// What every entry point and the periodic tick run first: an active release that no longer stands lapses
    /// with `dist:revoked` (R5), and an expired one lapses or is held (X1, X7).
    fn check_active(&mut self) -> Result<Option<Vec<u8>>, PepError> {
        if self.unreconciled {
            return Ok(None); // the next tick holds the active release to expiry and revocation before it installs
        }
        if self.locked || !self.trust.is_readable() {
            return Ok(None);
        }
        let Some(active) = self.active.clone() else { return Ok(None) };
        if !self.stands(&active, true) {
            return self.lapse_now(REVOKED).map(Some);
        }
        if self.still_valid(&active, false).as_deref() != Some(EXPIRED) {
            return Ok(None);
        }
        if self.expiry_response == HOLD {
            if self.held {
                return Ok(None);
            }
            self.held = true;
            self.audit.append(
                "distribution",
                "held",
                vec![("seq", json!(active.seq)), ("cause", json!(HELD)), ("result", json!("held"))],
            )?;
            return self.make_record("held", Some(HELD)).map(Some);
        }
        self.lapse_now(EXPIRED).map(Some)
    }

    /// X1, R5: go to `no-policy` with `cause`, durably, and make the runtime refuse. Refused while the runtime
    /// may hold another release than the PEP.
    pub fn lapse(&mut self, cause: &str) -> Result<Vec<u8>, PepError> {
        if self.unreconciled {
            return Err(refused(RECONCILING));
        }
        self.lapse_now(cause)
    }

    fn lapse_now(&mut self, cause: &str) -> Result<Vec<u8>, PepError> {
        let lapsed = self.active.clone();
        let seq = lapsed.as_ref().map(|release| release.seq);
        let envelopes = lapsed.as_ref().map(Release::envelope_ids).unwrap_or_default().into_iter().collect();
        // what is owed first, then the record: a write that fails leaves the release active, and the next
        // check lapses it again
        self.store.write("owed.json", &OwedDoc { cause: cause.to_string(), encoding: Canon2Tag, envelopes, format: OwedFormat, seq })?;
        let written = self.store.write(
            "active.json",
            &ActiveDoc { encoding: Canon2Tag, format: ActiveFormat, previous: self.previous.as_ref().map(Release::document), release: None },
        );
        if let Err(error) = written {
            let _ = self.store.remove("owed.json");
            return Err(error.into());
        }
        self.active = None;
        self.held = false;
        self.owed = Some(Owed::Lapse { cause: cause.to_string(), seq });
        self.may_hold = lapsed;
        if let Err(error) = self.adapter.deactivate(cause) {
            // the host may still run the release that fell: no decision is made until a tick withdraws it, and the
            // lapse is reported then
            self.unreconciled = true;
            return Err(error);
        }
        self.settle()
    }

    /// X7: `held` on every receipt written while the PEP holds an expired release, else None.
    pub fn receipt_mark(&self) -> Option<&'static str> {
        self.held.then_some("held")
    }

    /// One decision through the PEP, after the expiry check (X1). With no active release, or locked, it is
    /// refused with the cause of X3 and `under_release` is not called.
    pub fn decide<T>(&mut self, under_release: impl FnOnce() -> T) -> Result<Decision<T>, PepError> {
        if self.unreconciled {
            return Ok(Decision { decision: None, cause: self.refusal(), mark: None }); // no retry here (tick)
        }
        self.check_active()?;
        Ok(match self.refusal() {
            Some(cause) => Decision { decision: None, cause: Some(cause), mark: None },
            None => Decision { decision: Some(under_release()), cause: None, mark: self.receipt_mark() },
        })
    }

    // ------------------------------------------------------------------ RB1, RB2, X9: rollback
    /// Return to the release the active one replaced (RB1), never lowering the floor. Refused while held (X9),
    /// with the cause of the check a commit would fail (RB2), below a floor a revocation raised, and when the
    /// kept release may allow more than the active one without a widening statement that covers it (RB3).
    pub fn rollback(&mut self) -> Result<Vec<u8>, PepError> {
        if self.unreconciled {
            return Err(refused(RECONCILING)); // a rollback changes the runtime, which must match first
        }
        self.check_active()?;
        if self.held {
            return self.refuse(HELD, Vec::new());
        }
        if self.locked {
            return self.refuse(FLOOR_LOST, Vec::new());
        }
        if !self.trust.is_readable() {
            return self.refuse(UNKNOWN_KEY, Vec::new());
        }
        let Some(kept) = self.previous.clone() else {
            return Err(refused("no release is kept to roll back to (RB1)"));
        };
        let mut cause = self.still_valid(&kept, true); // RB2: what a commit checks, as it is active anew
        if cause.is_none() && kept.seq < self.raised_floor(&kept.stream) {
            cause = Some(SEQ_REPLAY.to_string()); // R4: below a floor a revocation raised
        }
        if let Some(cause) = cause {
            return self.refuse(&cause, vec![("seq", json!(kept.seq))]);
        }
        if !self.covers(&kept) {
            return self.refuse(WIDENING_UNSIGNED, vec![("seq", json!(kept.seq))]);
        }
        let floor = self.floor.clone();
        self.flip("rollback", kept, None, floor)
    }

    /// RB3: a rollback to `kept` does not widen silently. It is not larger by the adapter's comparison, or
    /// `kept` holds a widening statement whose `from` is empty or holds the active policy hash (W4).
    fn covers(&self, kept: &Release) -> bool {
        let active = self.active.as_ref();
        if active.is_some_and(|active| self.adapter.compare(active, kept) == Comparison::NotLarger) {
            return true;
        }
        let Some(statement) = kept.bodies.get(&ArtifactKind::TrustWidening) else { return false };
        let Ok(widening) = super::read_widening(statement) else { return false };
        widening.from.is_empty() || active.is_some_and(|active| widening.from.contains(&active.policy_sha256))
    }

    // ------------------------------------------------------------------ P2, P3: provisioning
    /// P2 step 3: receive a trust anchor and return its fingerprint for the operator to compare. The PEP follows
    /// no stream until `confirm` is given that fingerprint (P2 step 4).
    pub fn provision(&mut self, anchor: &[u8]) -> Result<Hex64, PepError> {
        let read = read_anchor(anchor).map_err(|refusal| refused(refusal.to_string()))?;
        if read.target != self.adapter.kind() {
            return Err(refused(format!("the anchor is for a {} PEP, not a {} one", read.target, self.adapter.kind())));
        }
        self.store.write_bytes("anchor.pending", anchor)?;
        self.audit.append(
            "distribution",
            "anchor_received",
            vec![("fingerprint", json!(read.fingerprint.as_str())), ("result", json!("pending"))],
        )?;
        Ok(read.fingerprint)
    }

    /// P2 step 4, P3: the operator confirmed `fingerprint`. The trust store, the floor and the time floor start
    /// again from the anchor, whatever was held before, and a locked PEP is unlocked. The runtime is withdrawn
    /// first, so a PEP reconciling a runtime that failed leaves that state here too.
    pub fn confirm(&mut self, fingerprint: &Hex64) -> Result<Vec<u8>, PepError> {
        let raw = std::fs::read(self.store.path("anchor.pending")).map_err(|_| refused("no anchor is waiting to be confirmed"))?;
        let read = read_anchor(&raw).map_err(|refusal| refused(refusal.to_string()))?;
        if *fingerprint != read.fingerprint {
            return Err(refused("the fingerprint is not the waiting anchor's"));
        }
        let store = read.store();
        self.check_separation(&store)?;
        // only now, with the new store known to be one, does anything held go
        self.adapter.deactivate(POLICY_LAPSED)?;
        self.active = None;
        self.previous = None;
        self.staged = None;
        self.unreconciled = false;
        self.owed = None;
        self.may_hold = None;
        for name in ["active.json", "staged.json", "pending.json", "owed.json"] {
            self.store.remove(name)?;
        }
        store.save(&self.trust_path())?;
        self.trust = store;
        self.store.write(
            "floor.json",
            &FloorDoc { encoding: Canon2Tag, format: FloorFormat, ids: SortedSet::default(), seq: 0, stream: read.stream.clone() },
        )?;
        self.store.write("counter.json", &CounterDoc { counter: self.counter, encoding: Canon2Tag, format: CounterFormat })?;
        let epoch = i64::try_from(self.epoch).unwrap_or(MAX_SEQ).min(MAX_SEQ); // H9: kept across provisioning
        self.store.write("epoch.json", &EpochDoc { encoding: Canon2Tag, epoch, format: EpochFormat })?;
        self.store.write("setting.json", &SettingDoc { encoding: Canon2Tag, expiry: self.expiry_response.clone(), format: SettingFormat })?;
        self.store.write_bytes("anchor.json", &raw)?;
        self.store.remove("anchor.pending")?;
        self.stream = Some(read.stream.clone());
        self.floor = Floor::default();
        self.locked = false;
        self.provisioned = true;
        self.held = false;
        self.active = None;
        self.previous = None;
        self.staged = None;
        self.keep_blobs();
        self.audit.append(
            "distribution",
            "provisioned",
            vec![
                ("fingerprint", json!(read.fingerprint.as_str())),
                ("stream", json!(read.stream.as_str())),
                ("result", json!("provisioned")),
            ],
        )?;
        self.make_record("provisioned", None)
    }
}

// ------------------------------------------------------------------ the host adapter

/// The `host` adapter: the software tier of `PolicyHost` as a distribution target (section 3). A committed
/// release is installed with `PolicyHost::install_verified`, the commit half `swap` also ends in, and a PEP
/// with no release is `PolicyHost::withdraw`, so the host holds nothing and allows nothing (X3). The adapter's
/// own check is the spiral sidecar: when the `policy.ppt` envelope's `meta.packing` declares one, the release
/// needs a `policy.spiral` whose SHA-256 is the declared `sidecar_sha256` (C2, V11).
pub struct HostAdapter {
    pub host: PolicyHost,
}

impl HostAdapter {
    pub fn new(host: PolicyHost) -> HostAdapter {
        HostAdapter { host }
    }
}

fn packing_of(release: &Release) -> Option<Hex64> {
    match release.envelopes.get(&ArtifactKind::PolicyPpt).map(Envelope::form) {
        Some(Meta::PolicyPpt(meta)) => meta.packing.as_ref().map(|packing| packing.sidecar_sha256.clone()),
        _ => None,
    }
}

fn host_error(error: HostError) -> PepError {
    PepError::Host(error)
}

impl Adapter for HostAdapter {
    fn kind(&self) -> TargetKind {
        TargetKind::Host
    }

    fn home(&self) -> Option<String> {
        Some(self.host.state_dir.clone())
    }

    fn qualification(&self) -> Option<Value> {
        Some(self.host.envelope.clone())
    }

    fn check(&self, artifact: ArtifactKind, body: &[u8], staged: &Release) -> Option<String> {
        let declared = packing_of(staged);
        if artifact == ArtifactKind::PolicyPpt && declared.is_some() && !staged.held.contains_key(&ArtifactKind::PolicySpiral) {
            return Some(SIDECAR_MISSING.to_string());
        }
        if artifact == ArtifactKind::PolicySpiral && declared != Some(Hex64::of(body)) {
            return Some(SIDECAR_MISMATCH.to_string());
        }
        None
    }

    fn activate(&self, release: &Release) -> Result<(), PepError> {
        let (Some(image), Some(envelope)) =
            (release.bodies.get(&ArtifactKind::PolicyPpt), release.envelopes.get(&ArtifactKind::PolicyPpt))
        else {
            return Err(refused("a host release holds a policy.ppt"));
        };
        let sha256 = crate::sha256_hex(image);
        let current = self.host.active_info();
        if current["active"] == json!(sha256) && current["version"] == json!(release.seq) {
            return Ok(()); // a restart that finds the host already there
        }
        let Meta::PolicyPpt(meta) = envelope.form() else {
            return Err(refused("a policy.ppt envelope whose meta is not its form"));
        };
        let counts = crate::read_ppt_header(image).map_err(refused)?.to_value();
        let mut distribution = json!({"stream": release.stream, "seq": release.seq, "release": release.release.as_str(),
                                      "envelope_id": envelope.envelope_id().as_str()});
        if let Some(spiral) = release.bodies.get(&ArtifactKind::PolicySpiral) {
            distribution["spiral_sha256"] = json!(crate::sha256_hex(spiral));
        }
        let mut record = Map::new();
        record.insert("sha256".into(), json!(sha256));
        record.insert("version".into(), json!(release.seq));
        record.insert("key_id".into(), Value::Null);
        record.insert("envelope_id".into(), json!(meta.qualification.as_str()));
        record.insert("unsigned".into(), json!(false));
        record.insert("overlay_of".into(), meta.overlay_of.as_ref().map_or(Value::Null, |overlay| json!(overlay.as_str())));
        record.insert("counts".into(), counts);
        record.insert("since".into(), json!(self.host.now_iso()));
        record.insert("ppt_path".into(), json!(abspath(&release.paths[&ArtifactKind::PolicyPpt])));
        record.insert("distribution".into(), distribution.clone());
        self.host.install_verified(image.clone(), record, vec![("distribution", distribution)]).map_err(host_error)?;
        Ok(())
    }

    fn deactivate(&self, cause: &str) -> Result<(), PepError> {
        self.host.withdraw(cause).map_err(host_error)?;
        Ok(())
    }
}
