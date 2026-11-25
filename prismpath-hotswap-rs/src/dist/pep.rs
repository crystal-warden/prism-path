// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The enforcement point machine of policy distribution (spec-policy-distribution.md, section 9),
//! `prismpath/distribution/pep.py` in Rust, one per stream. What a target does with a committed release is
//! its adapter's; this crate has the `host` adapter, over `PolicyHost`. The machine verifies, keeps the floor,
//! the time floor and the trust store, holds every release to the widening rule (V12) at staging, at commit
//! and at a rollback, stages, commits, aborts, rolls back, lapses at expiry or holds, and signs a state record
//! for every transition.
//!
//! Its durable store is `<state>/dist/`, under the file names the Python machine uses, each canon/2 and written
//! whole (the old one or the new one). The two machines are not held to open each other's directory: the audit
//! log here is the host's unsigned one, and DIVERGENCES.md lists what else differs.
//!
//! ```text
//! anchor.json    the confirmed trust anchor (P2), which names the target kind and the stream
//! anchor.pending an anchor the operator has not confirmed yet (P2 step 4)
//! trust.json     the trust store (K1)
//! floor.json     the floor (Q1)
//! counter.json   the state record counter (H3)
//! setting.json   the expiry response the PEP was provisioned with (X10)
//! staged.json    the staged release
//! pending.json   the intent record of a commit, a rollback or a lapse (C4, C7)
//! active.json    the active release and the one it replaced (RB1)
//! fresh.json     the latest fresh controller statement, where freshness is on (H16)
//! blobs/         sealed envelopes and bodies under their SHA-256
//! audit.log      the audit log
//! ```
//!
//! A commit is durable in the order of C4: the intent, the floor, the audit event, the artifacts under
//! content addressed names (staging already wrote them, each synced), the active record, the runtime step,
//! the state record, the clean up. A lapse is durable in the order of C7. A restart reads only what the active
//! record names, and finishes or reports an interrupted transition. [`Pep::set_commit_hook`] runs before each
//! of those steps, and an error stands for a process that died there.
//!
//! A store that cannot be read is answered by failing closed: an unreadable trust store refuses every
//! envelope and decides nothing (K1, X3), and an unreadable floor, anchor or setting locks the PEP (Q5) until
//! it is provisioned again (P3). A counter that cannot be read also locks the PEP, and its records count on
//! from its time in microseconds, so none repeats (H3). Each of those records writes the counter again, so the
//! next start reads it and is not locked: a lock from the counter alone ends at a restart, where P3 has only
//! provisioning end a lock. The Python machine does the same, and the two change together if P3 is to hold
//! for the counter.
//!
//! A runtime step that fails after the record it switches to is durable makes the PEP `reconciling` (section
//! 9.5). It withdraws the runtime at once (C10), refuses every decision, commit and rollback with
//! `dist:reconciling` (C8) and goes on verifying, staging, aborting and applying trust statements. Only a tick
//! and a start try the runtime again (C9), each try holding the held release, and the running release while
//! the withdrawal has not worked, to revocation and expiry first (C10). Every record it sends has status 3
//! and the entry of H14. A switch between two releases whose bodies are the same, as a renewal's are, never
//! enters the state (C10). Provisioning withdraws the runtime first and is refused when it does not (P5).
//!
//! Section 21 is the `install` module's and this machine's: install statements and install trust statements under
//! an install record kept in two copies apart from the trust store (IS1 to IS13), a fallback policy that decides
//! whenever no release does, handed to the runtime in place of a withdrawn release (FB1 to FB9), a ceiling list
//! every release and install set is held inside (CL1 to CL3), and an action floor the machine asks first on every
//! request in every state (AF1 to AF10, `floor`). The floor of a `host` lives in the machine and not in its runtime,
//! so applying one has no runtime step, and DIVERGENCES.md says so.
//!
//! The controller key is held in its own role, apart from every other (K4, K6), named by a `/2` anchor or by a
//! `trust.controller` (K7). The epoch id (H9) is taken only from a controller statement that verifies under that
//! key at the key sequence the trust store holds for it, is never lowered and is kept in memory only, starting again
//! at 0 at every start, at provisioning and at a `trust.controller` (H15). Where the anchor sets `fresh`, a fresh
//! statement is kept durably, a newer one written only once the kept one has used half its life, and the PEP lapses
//! as at expiry once its time passes the kept one's `expires` plus SKEW; a PEP with no clock takes one raise of its
//! time floor per start from a fresh statement (H16).
//!
//! A home holding the private half of a trusted authority key is refused at start (K2).

use super::envelope::{self as env, Envelope};
use super::floor::{self as floors, Answer, Request};
use super::install::{self, AsName, InstallSet, Installed, Record, SetKind};
use super::state_record::{self, StateRecord};
use super::statement::{self as statements, Statement};
use super::trust::{read_anchor, Anchor, TrustStore};
use super::verify::{self, Floor, InstallView, PepKind, PepView, Staged, SKEW};
use super::{
    load, ActiveFormat, ArtifactKind, PendingInstallFormat, Canon2Tag, CounterFormat, FloorFormat, FreshFormat, Hex64, MaybeHex64, Meta, PendingFormat,
    Refused, SettingFormat, SortedSet, StagedFormat, Stream, Target, TargetKind, AUTHORITY, BAD_FORMAT, EXPIRED, FLOOR_LOST, HELD,
    INCOMPLETE, MAX_SEQ, NOT_STAGED, NOT_YET_VALID, POLICY_LAPSED, REVOKED, SEQ_REPLAY, SIDECAR_MISMATCH,
    SIDECAR_MISSING, UNKNOWN_KEY, WIDENING_UNSIGNED, RECONCILING, ABOVE_CEILING, FALLBACK, FLOOR_ALLOWED, INSTALL_LOST,
    INSTALL_WIDENED, TRUST_REPLAY,
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

// ------------------------------------------------------------------ V12: the widening rule
// `prismpath/distribution/widening.py` in Rust, for the artifacts a Rust row uses. A kind that can decide would
// compare with these (W1) and a kind that cannot compares what its row's `compares` names (W2). Whether a release
// is larger is never an adapter's.

/// W1 for one artifact. `policy.ppt` and `gateway.routes` have no order, so any change is larger (section 9.4).
/// `policy.spiral`, `sandbox.profile` and `net.edge` follow the policy of their release and are held to it
/// elsewhere (C2, `dist:derived-mismatch`), so they are not larger. Any other artifact compares only as unchanged
/// bytes here, so a change of one cannot be decided, which counts as larger.
pub fn compare_artifact(artifact: ArtifactKind, active: Option<&[u8]>, staged: Option<&[u8]>) -> Comparison {
    if matches!(artifact, ArtifactKind::PolicySpiral | ArtifactKind::SandboxProfile | ArtifactKind::NetEdge) {
        return Comparison::NotLarger;
    }
    let (Some(active), Some(staged)) = (active, staged) else {
        return if staged.is_some() { Comparison::Larger } else { Comparison::NotLarger };
    };
    match (active == staged, artifact) {
        (true, _) => Comparison::NotLarger,
        (false, ArtifactKind::PolicyPpt | ArtifactKind::GatewayRoutes) => Comparison::Larger,
        (false, _) => Comparison::CannotDecide,
    }
}

/// W1 for a whole release, trust kinds left out. None for `active` is no policy, and any release is larger than
/// that. Larger when one artifact is, and not decided when one is not and none is larger.
pub fn compare_release(active: Option<&BTreeMap<ArtifactKind, Vec<u8>>>, staged: &BTreeMap<ArtifactKind, Vec<u8>>) -> Comparison {
    let Some(active) = active else { return Comparison::Larger };
    let run = |bodies: &BTreeMap<ArtifactKind, Vec<u8>>| -> BTreeMap<ArtifactKind, Vec<u8>> {
        bodies.iter().filter(|(artifact, _)| !artifact.is_trust()).map(|(artifact, body)| (*artifact, body.clone())).collect()
    };
    let (active, staged) = (run(active), run(staged));
    if active == staged {
        return Comparison::NotLarger;
    }
    let mut answer = Comparison::NotLarger;
    for (artifact, body) in &staged {
        match compare_artifact(*artifact, active.get(artifact).map(Vec::as_slice), Some(body)) {
            Comparison::Larger => return Comparison::Larger,
            Comparison::CannotDecide => answer = Comparison::CannotDecide,
            Comparison::NotLarger => {}
        }
    }
    answer
}

/// W4: a widening statement covers a PEP when its `from` is empty or holds the PEP's active policy hash.
pub fn covers(statement: Option<&[u8]>, active_policy: Option<&Hex64>) -> bool {
    let Some(widening) = statement.and_then(|body| super::read_widening(body).ok()) else { return false };
    widening.from.is_empty() || active_policy.is_some_and(|policy| widening.from.contains(policy))
}

/// W11: a change statement stands for a release on a PEP whose active policy hash is its `from`. A PEP with no
/// policy has none, so no change statement stands for a first install.
pub fn changes(change: Option<&[u8]>, active_policy: Option<&Hex64>) -> bool {
    let Some(change) = change.and_then(|body| super::read_change(body).ok()) else { return false };
    active_policy == Some(&change.from)
}

/// V12 for a release with these `widens` and `replaces` on a PEP of `target` whose active policy hash is
/// `active_policy`. `answer` is the PEP's own comparison: of the release when it can decide (W1), and on a kind
/// that cannot, of the artifacts its row compares, a table any change of which is larger (W2). `statement` is the
/// body of the `trust.widening` envelope staged for the same release. None when the release may be staged or
/// committed, else `dist:widening-unsigned`. Going from no policy to any is larger on every kind, so a first
/// install whose `widens` is false is refused with a statement or without, as is a larger release that says it
/// does not widen (W6). Otherwise a larger release needs a statement that covers the PEP (W3, W4). `change` is the
/// body of a `trust.change` envelope staged for the same release. On a kind that cannot decide it stands in place of
/// a widening statement for a release whose `widens` is false and whose `replaces` is the active policy hash, when its
/// `from` is that hash (W11). The PEP compares nothing more than W2 does.
pub fn widening_check(
    target: &super::Target,
    widens: bool,
    replaces: &MaybeHex64,
    active_policy: Option<&Hex64>,
    answer: Option<Comparison>,
    statement: Option<&[u8]>,
    change: Option<&[u8]>,
) -> Option<&'static str> {
    let answer = if active_policy.is_none() { Some(Comparison::Larger) } else { answer };
    let larger = if target.decides {
        answer != Some(Comparison::NotLarger)
    } else {
        // W2: on the signature alone only a renewal of the active policy, and what it compares as larger is larger
        widens || replaces.0.as_ref() != active_policy || answer == Some(Comparison::Larger)
    };
    if !larger {
        return None;
    }
    if !target.decides
        && !widens
        && replaces.0.as_ref() == active_policy
        && target.applies.contains(&ArtifactKind::TrustChange)
        && changes(change, active_policy)
    {
        return None; // W11: the authority signed that the table allows nothing more
    }
    if !widens && (target.decides || answer == Some(Comparison::Larger)) {
        return Some(WIDENING_UNSIGNED); // W6: the signer said it does not widen, and it does
    }
    (!covers(statement, active_policy)).then_some(WIDENING_UNSIGNED)
}

/// The interface between the machine and the runtime a target kind protects. `check` is the target's own
/// part of V11, run at commit over the whole staged release, since one artifact may name another (C2).
/// `activate` makes the runtime use a committed release and `deactivate` makes it refuse. An adapter never
/// verifies a signature, reads a clock, touches a floor or says whether a release is larger (W1). Those are the
/// machine's.
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

    /// AF10: the layout document a table kind was built with, without which it takes no action floor.
    fn floor_layout(&self) -> Option<Vec<u8>> {
        None
    }

    fn activate(&self, release: &Release) -> Result<(), PepError>;

    fn deactivate(&self, cause: &str) -> Result<(), PepError>;

    /// C10, FB1: withdraw the release and run the PEP's fallback set, given in the shape of a release, in its
    /// place. A runtime that runs what `activate` gives it runs the fallback set the same way.
    fn withdraw_to(&self, fallback: &Release, _cause: &str) -> Result<(), PepError> {
        self.activate(fallback)
    }
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

/// H16: the latest fresh controller statement, its `expires` and the PEP's time when it was kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FreshDoc {
    at: i64,
    encoding: Canon2Tag,
    expires: i64,
    format: FreshFormat,
    statement: String,
}

/// H16: the fresh statement the PEP keeps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kept {
    pub statement: Vec<u8>,
    pub expires: i64,
    pub at: i64,
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
/// The intent record of a commit, a rollback or a lapse (C7): the transition, the release it makes active or
/// none, the cause of a lapse, the release the runtime ran when it started, in full, and whether the runtime
/// was withdrawn since (C10). The last three are read as none and false when absent, as in the Python form.
struct PendingDoc {
    #[serde(default)]
    cause: Option<String>,
    encoding: Canon2Tag,
    format: PendingFormat,
    op: String,
    release: Option<ReleaseDoc>,
    #[serde(default)]
    running: Option<ReleaseDoc>,
    #[serde(default)]
    withdrawn: bool,
}

/// P2 step 3: the install statements brought with a waiting anchor, each sealed envelope and body in hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingInstallDoc {
    encoding: Canon2Tag,
    format: PendingInstallFormat,
    statements: Vec<(String, String)>,
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

    /// A release with the names of `doc` and nothing read yet.
    fn named(doc: &ReleaseDoc) -> Release {
        Release {
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
/// writes one. Only a regular file is opened, its type checked first, so a FIFO or a device in the home never
/// stops the scan, and a file over 16,384 bytes holds none. The file is read as bytes, so a byte that is not
/// UTF-8 anywhere in it hides no block.
fn private_keys_in(path: &std::path::Path) -> Vec<[u8; 32]> {
    use std::io::Read;
    const BOUND: u64 = 16_384;
    let regular = std::fs::metadata(path).is_ok_and(|meta| meta.is_file() && meta.len() <= BOUND);
    let Some(file) = regular.then(|| std::fs::File::open(path).ok()).flatten() else { return Vec::new() };
    if !file.metadata().is_ok_and(|meta| meta.is_file()) {
        return Vec::new();
    }
    let mut data = Vec::new();
    if file.take(BOUND + 1).read_to_end(&mut data).is_err() || data.len() as u64 > BOUND {
        return Vec::new();
    }
    let seeds: Vec<[u8; 32]> = if data.len() == 32 {
        data.as_slice().try_into().ok().into_iter().collect()
    } else if find(&data, b"-----BEGIN").is_some() && find(&data, b"PRIVATE KEY").is_some() {
        pem_private_blocks(&data).iter().filter_map(|der| pkcs8_seed(der)).collect()
    } else {
        Vec::new()
    };
    seeds.iter().map(|seed| SigningKey::from_bytes(seed).verifying_key().to_bytes()).collect()
}

/// Where `needle` first starts in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

/// The DER of each `PRIVATE KEY` block of a PEM text, each block read on its own, so a private key block
/// beside a public one is still found. A `-----BEGIN` with no label line or no matching end line is passed
/// over and the scan goes on after it, so it hides no block that follows. The header lines of RFC 1421 a
/// block may open with, up to the blank line after them, are skipped, and whitespace in the base64 is too.
fn pem_private_blocks(text: &[u8]) -> Vec<Vec<u8>> {
    const BEGIN: &[u8] = b"-----BEGIN ";
    const DASHES: &[u8] = b"-----";
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = find(rest, BEGIN) {
        let after = &rest[start + BEGIN.len()..];
        let next = &rest[start + 1..]; // where the scan goes on when this is no block
        let Some(label_end) = find(after, DASHES).filter(|end| !after[..*end].contains(&b'\n')) else {
            rest = next;
            continue;
        };
        let label = &after[..label_end];
        let body = &after[label_end + DASHES.len()..];
        let end_marker = [b"-----END ".as_slice(), label, DASHES].concat();
        let Some(end) = find(body, &end_marker) else {
            rest = next;
            continue;
        };
        if label.ends_with(b"PRIVATE KEY") {
            if let Some(der) = base64_decode(&pem_base64(&body[..end])) {
                out.push(der);
            }
        }
        rest = &body[end + end_marker.len()..];
    }
    out
}

/// The base64 of a PEM block's body: its RFC 1421 header lines, when its first line is one, are dropped up to
/// and with the blank line that ends them, and every whitespace byte is dropped.
fn pem_base64(body: &[u8]) -> Vec<u8> {
    let lines: Vec<&[u8]> = body.split(|byte| *byte == b'\n').map(|line| line.strip_suffix(b"\r").unwrap_or(line)).collect();
    let first = lines.iter().position(|line| !line.iter().all(u8::is_ascii_whitespace)).unwrap_or(lines.len());
    let headed = lines.get(first).is_some_and(|line| line.contains(&b':'));
    let from = if headed {
        lines[first..].iter().position(|line| line.iter().all(u8::is_ascii_whitespace)).map_or(lines.len(), |blank| first + blank + 1)
    } else {
        first
    };
    lines[from.min(lines.len())..].concat().into_iter().filter(|byte| !byte.is_ascii_whitespace()).collect()
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
fn base64_decode(bytes: &[u8]) -> Option<Vec<u8>> {
    let value = |byte: u8| match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    };
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

/// What `decide` answers: the decision made under the active release or the fallback policy, or the cause every
/// decision is refused with (X3, C8), and the hold mark a receipt carries (X7). A PEP that holds an install record
/// names the basis and the policy hash of the set that decided (RC1), and `floor` is the action floor's answer
/// when it answered (AF1, AF7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision<T> {
    pub decision: Option<T>,
    pub cause: Option<&'static str>,
    pub mark: Option<&'static str>,
    pub basis: Option<&'static str>,
    pub policy_sha256: Option<Hex64>,
    pub floor: Option<FloorAnswer>,
}

/// AF1, AF7, AF8, RC3: what the action floor answered: always an allow on `host` (AF2), with `dist:floor-allowed`,
/// the floor rule that allowed, `would`, the outcome, cause and policy hash of the set the release or the fallback
/// policy would have decided with (None when no set would), whether it is an override, and for a counted override
/// the start of its window and the count after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FloorAnswer {
    pub rule: String,
    pub would: Option<(&'static str, Option<&'static str>, Hex64)>,
    pub overrides: bool,
    pub counted: Option<(i64, i64)>,
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
    /// Section 9.5 while it lasts.
    reconciling: Option<Reconciling>,
    /// C10: the runtime step of a switch between two releases with the same bodies failed. The PEP stays
    /// active and each tick tries the step again.
    retry_runtime: bool,
    /// C12: the seq and cause of a lapse whose audit event a start found written before the death that cut it
    /// short, so the lapse the start's checks make again is not audited twice. Only a start sets it.
    lapse_audited: Option<(Option<i64>, String)>,
    /// IS10: the install part, its second copy on a second medium where the deployment gives one.
    pub installed: Installed,
    /// IS10: the install kinds a start found lost, reported once the start is done.
    lost: Vec<SetKind>,
    /// IS8, P2 step 4: the envelope ids of the install statements brought with the waiting anchor.
    printed: Vec<Hex64>,
    /// H9, H15: the epoch id, in memory only and 0 at every start.
    epoch: u64,
    /// H16: the anchor's `fresh`, 0 for freshness off, and the fresh statement kept.
    fresh: i64,
    kept: Option<Kept>,
    /// H16: a PEP with no clock has taken its one raise of the time floor of this start.
    time_taken: bool,
}

/// The record a transition owes once its runtime step works (C9, H14). `Installed` is a fallback policy applied
/// whose runtime step it is (FB8), widened or not (IS12).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Owed {
    Nothing,
    Committed,
    RolledBack,
    Lapsed(String),
    Installed(bool),
}

impl Owed {
    /// The event, `fallback` in place of `lapsed` for a PEP that goes to its fallback policy (FB3).
    fn event(&self, fallback: bool) -> &'static str {
        match self {
            Owed::Nothing => "beat",
            Owed::Committed => "committed",
            Owed::RolledBack => "rolled-back",
            Owed::Lapsed(_) if fallback => "fallback",
            Owed::Lapsed(_) => "lapsed",
            Owed::Installed(true) => "install-widened",
            Owed::Installed(false) => "install-applied",
        }
    }

    fn cause(&self) -> Option<&str> {
        match self {
            Owed::Lapsed(cause) => Some(cause),
            Owed::Installed(true) => Some(INSTALL_WIDENED),
            _ => None,
        }
    }

    fn subject(&self) -> Option<&'static str> {
        matches!(self, Owed::Installed(_)).then_some(SetKind::Fallback.name())
    }
}

/// The state of section 9.5. The held release is the active one. `running` is the release the runtime may
/// still run, kept only while the withdrawal has not worked (C10).
#[derive(Debug, Clone)]
struct Reconciling {
    owed: Owed,
    running: Option<Release>,
    withdrawn: bool,
    /// The cause the running release fell for, named in every record until the withdrawal works (C10).
    running_fell: Option<&'static str>,
}

impl<A: Adapter> Pep<A> {
    /// The PEP over `<state_dir>/dist/`: its durable state read, its setting and key separation checked, an
    /// interrupted transition finished or reported, and the runtime step of a start made (C6). A start whose
    /// runtime step fails still starts, `reconciling`.
    pub fn new(
        state_dir: &str,
        adapter: A,
        instance_key: SigningKey,
        clock: Box<dyn Fn() -> i64>,
        expiry_response: &str,
        has_clock: bool,
    ) -> Result<Pep<A>, PepError> {
        Pep::with_install_copy(state_dir, adapter, instance_key, clock, expiry_response, has_clock, None)
    }

    /// `new` with the second copy of the install record on `install_copy`, a directory on a second file system
    /// where the deployment gives one (IS10). With none both copies are under `<state_dir>/dist/`, and one loss of
    /// that file system takes both.
    pub fn with_install_copy(
        state_dir: &str,
        adapter: A,
        instance_key: SigningKey,
        clock: Box<dyn Fn() -> i64>,
        expiry_response: &str,
        has_clock: bool,
        install_copy: Option<&str>,
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
        let installed = Installed::new(&store.dir, install_copy);
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
            reconciling: None,
            retry_runtime: false,
            lapse_audited: None,
            installed,
            lost: Vec::new(),
            printed: Vec::new(),
            epoch: 0,
            fresh: 0,
            kept: None,
            time_taken: false,
        };
        pep.load()?;
        pep.check_setting()?;
        pep.check_separation(&pep.trust.clone())?;
        pep.recover()?;
        for kind in std::mem::take(&mut pep.lost) {
            pep.refuse_about(INSTALL_LOST, Some(kind.name()), vec![("artifact", json!(kind.name()))])?; // IS10
        }
        if pep.installed.record_lost {
            pep.refuse(INSTALL_LOST, Vec::new())?;
        }
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
        self.lost = self.installed.load(); // apart from the store Q5 can lose (IS10)
        self.trust = TrustStore::load(&self.trust_path());
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
                self.fresh = anchor.fresh;
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
                cause: None,
                encoding: Canon2Tag,
                format: PendingFormat,
                op: "unknown".to_string(),
                release: None,
                running: None,
                withdrawn: false,
            }));
        }
        self.kept = self.read_fresh();
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
        let mut release = Release::named(doc);
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

    /// The running release an intent record names (C7). C11 keeps its blobs, so it reads whole; one that does
    /// not is still named in the records, and its envelopes, which the tests of C10 read, are missing.
    fn running_of(&self, doc: &ReleaseDoc) -> Release {
        self.release_of(Some(doc)).ok().flatten().unwrap_or_else(|| Release { held: doc.held.clone(), ..Release::named(doc) })
    }

    /// K2: the instance key is never a trusted key, and the home holds no private half of one. The scan has the
    /// bounds of the Python machine's `_check_separation`: not the PEP's own store, not the `runs` a home keeps,
    /// no deeper than two levels, no file over 16,384 bytes and at most 4,096 files. What it reads in a file is
    /// wider than Python's, as DIVERGENCES.md says.
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

    /// A start: finish or report an interrupted transition (C4, C7), hold the staged and the active release to
    /// the revocation test again (R5) and check expiry (X1), then make the runtime run what the active record
    /// names. A transition the intent record shows durable is owed its record, which goes once the runtime step
    /// works, and the intent record with it (C12). The runtime runs what the intent record says it ran, whether the
    /// transition flipped or not (C7), and with no intent record the held release. When that is not the held
    /// release the start holds both to the tests of C10, so a held release that fell while the PEP was down is
    /// never installed. A step that fails between two releases with the same bodies, as a renewal's, keeps the
    /// PEP active (C10), and any other makes it reconciling (C6).
    fn recover(&mut self) -> Result<(), PepError> {
        let before = self.audit.last_event(); // what the log held before this start wrote to it
        let mut owed = Owed::Nothing;
        let mut running = self.active.clone(); // C7: with no intent record the held release may be running
        let mut withdrawn = false;
        if let Some(intent) = self.pending.take().filter(|_| !self.locked) {
            // a locked PEP read no active record, so its intent record waits for provisioning, which removes it
            let flipped = match intent.op.as_str() {
                "commit" | "rollback" => {
                    matches!((&self.active, &intent.release), (Some(active), Some(target)) if active.document() == *target)
                }
                "lapse" => self.active.is_none() && intent.release.is_none(),
                _ => false,
            };
            if matches!(intent.op.as_str(), "commit" | "rollback" | "lapse") {
                withdrawn = intent.withdrawn;
                running = if withdrawn { None } else { intent.running.as_ref().map(|doc| self.running_of(doc)) };
            }
            if flipped {
                owed = match intent.op.as_str() {
                    "commit" => Owed::Committed,
                    "rollback" => Owed::RolledBack,
                    _ => Owed::Lapsed(intent.cause.clone().unwrap_or_else(|| POLICY_LAPSED.to_string())),
                };
            } else {
                // C12: a lapse that died after its audit event and before its active record is not audited again
                // when the checks of this start lapse the release again
                let audited = before.as_ref().filter(|event| {
                    intent.op == "lapse" && event["action"] == "lapsed" && event["data"]["cause"] == json!(intent.cause)
                });
                self.lapse_audited = audited.map(|event| event["data"]["seq"].as_i64()).zip(intent.cause.clone());
                self.audit.append(
                    "distribution",
                    "commit_incomplete",
                    vec![("op", json!(intent.op)), ("result", json!("incomplete"))],
                )?;
                self.store.remove("pending.json")?;
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
        let runs_held = !withdrawn && running.as_ref().map(Release::document) == self.active.as_ref().map(Release::document);
        if owed == Owed::Nothing && runs_held {
            let lapsed = self.check_active()?;
            self.lapse_audited = None;
            if lapsed.is_some() {
                return Ok(()); // a lapse made its own runtime step
            }
        } else {
            // C10's tests come before the step, as in every try. A transition the intent record shows flipped
            // may have run its release part way, and one that did not flip never ran the held release.
            self.reconciling = Some(Reconciling { owed: owed.clone(), running, withdrawn, running_fell: None });
            let tested = self.run_tests(owed == Owed::Nothing);
            self.lapse_audited = None;
            let state = self.reconciling.take().expect("set above");
            tested?;
            (owed, running) = (state.owed, state.running);
        }
        let stepped = self.step(&owed);
        match stepped {
            Ok(()) if owed == Owed::Nothing => {
                if self.fallback_decides() {
                    // FB3: a start with nothing committed goes to its fallback policy
                    let cause = if self.locked { FLOOR_LOST } else { FALLBACK };
                    self.make_record("fallback", Some(cause))?;
                }
                Ok(())
            }
            Ok(()) => self.settle(owed).map(|_| ()),
            Err(error) if owed != Owed::Nothing && self.same_bodies(running.as_ref()) => self.renewal_failed(owed, &error).map(|_| ()),
            Err(error) => self.enter_reconciling(owed, running, &error.to_string()).map(|_| ()), // C6: it still starts
        }
    }

    /// The runtime step: run the held release, or the fallback set or nothing when none is held or the PEP is
    /// locked (X3, C13, FB1).
    fn step(&self, owed: &Owed) -> Result<(), PepError> {
        match (self.own_refusal(), &self.active) {
            (None, Some(held)) => self.adapter.activate(held),
            (refusal, _) => self.withdraw(owed.cause().or(refusal).unwrap_or(POLICY_LAPSED)),
        }
    }

    /// C10, FB1: make the runtime run no release: the fallback set where the PEP holds one, else nothing.
    fn withdraw(&self, cause: &str) -> Result<(), PepError> {
        match self.installed.held(SetKind::Fallback) {
            Some(fallback) => self.adapter.withdraw_to(&self.release_of_set(fallback), cause),
            None => self.adapter.deactivate(cause),
        }
    }

    /// FB1: an install set in the shape of a release, for a runtime that runs it in place of one, each body's path
    /// the first copy of it that reads.
    pub fn release_of_set(&self, set: &InstallSet) -> Release {
        let mut release = Release {
            stream: self.stream.as_ref().map_or_else(String::new, |stream| stream.as_str().to_string()),
            seq: set.seq(),
            policy_sha256: set.doc.policy_sha256.clone(),
            release: set.doc.release.clone(),
            replaces: set.doc.replaces.clone(),
            widens: set.doc.widens,
            held: BTreeMap::new(),
            envelopes: BTreeMap::new(),
            bodies: BTreeMap::new(),
            paths: BTreeMap::new(),
        };
        for (name, held) in &set.doc.statements {
            let AsName::Artifact(artifact) = name else { continue };
            release.held.insert(*artifact, held.clone());
            release.envelopes.insert(*artifact, set.envelopes[name].clone());
            release.bodies.insert(*artifact, set.bodies[name].clone());
            release.paths.insert(*artifact, self.installed.body_path(held));
        }
        release
    }

    /// FB1, FB2, C8: the fallback policy decides while no release does, in `no-policy`, in `locked` and while
    /// reconciling once the runtime is withdrawn, and never under a hold (FB6).
    pub fn fallback_decides(&self) -> bool {
        if self.installed.held(SetKind::Fallback).is_none() || self.held {
            return false;
        }
        match &self.reconciling {
            Some(state) => state.withdrawn,
            None => self.own_refusal().is_some(),
        }
    }

    /// FB3: the event of a lapse, `fallback` where the PEP holds a fallback policy.
    fn owed_event(&self, owed: &Owed) -> &'static str {
        owed.event(self.installed.held(SetKind::Fallback).is_some())
    }

    // ------------------------------------------------------------------ what the PEP is
    pub fn state(&self) -> &'static str {
        if self.locked {
            "locked"
        } else if self.reconciling.is_some() {
            "reconciling"
        } else if self.active.is_some() && self.trust.is_readable() {
            "active"
        } else {
            "no-policy"
        }
    }

    /// C6: true while the runtime may not run what the PEP holds.
    pub fn is_reconciling(&self) -> bool {
        self.reconciling.is_some()
    }

    /// C10: the release the runtime may still run while the withdrawal has not worked, else None.
    pub fn running(&self) -> Option<&Release> {
        self.reconciling.as_ref().filter(|state| !state.withdrawn).and_then(|state| state.running.as_ref())
    }

    /// X3, C8: None while a release decides, else the cause every decision is refused with.
    pub fn refusal(&self) -> Option<&'static str> {
        match (self.locked, &self.reconciling) {
            (false, Some(_)) => Some(RECONCILING),
            _ => self.own_refusal(),
        }
    }

    /// The refusal of what the PEP holds, whatever its runtime runs: what the runtime step makes it do.
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

    fn view(&self, message: bool) -> Option<PepView> {
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
            install: Some(InstallView {
                record: self.installed.record.clone(),
                staged: self.installed.staged.clone(),
                ceiling: self.installed.held(SetKind::Ceiling).cloned(),
                message,
                layout: self.adapter.floor_layout(),
            }),
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

    /// Make one record, its counter durable first (H3), and put it in the outbox. The active fields name the
    /// held release in every state, and a reconciling PEP's record carries the entry of H14.
    fn make_record(&mut self, event: &'static str, cause: Option<&str>) -> Result<Vec<u8>, PepError> {
        self.make_record_about(event, cause, None)
    }

    /// `make_record` with the subject of H10, the install kind an event of `staged`, `refused`, `install-applied`
    /// or `install-widened` is about.
    fn make_record_about(&mut self, event: &'static str, cause: Option<&str>, subject: Option<&'static str>) -> Result<Vec<u8>, PepError> {
        self.counter += 1;
        if self.provisioned {
            self.store.write("counter.json", &CounterDoc { counter: self.counter, encoding: Canon2Tag, format: CounterFormat })?;
        }
        let unsigned = |value: i64| u64::try_from(value).unwrap_or(0);
        let prefix = |hash: Option<&Hex64>| state_record::prefix(hash.map(Hex64::as_str));
        let (active, staged) = (self.active.as_ref(), self.staged.as_ref());
        let record = StateRecord {
            cause: cause.map(str::to_string),
            pep_id: state_record::pep_id(&self.instance_public()),
            counter: unsigned(self.counter),
            time: unsigned(self.time()),
            epoch: self.epoch, // H9, H15
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
            fallback: self.fallback_decides(),
            extensions: [
                self.install_entry(event, subject).map_or_else(Vec::new, |entry| entry.extension()),
                self.reconciling_entry().map_or_else(Vec::new, |entry| entry.extension()),
            ]
            .concat(),
            ..StateRecord::new(event, self.state())
        };
        let signed = state_record::build(&record, &self.instance_key).map_err(PepError::Refused)?;
        self.outbox.push(signed.clone());
        Ok(signed)
    }

    /// H10: the install entry of a PEP that holds an install record or held one it lost, None otherwise.
    fn install_entry(&self, event: &str, subject: Option<&'static str>) -> Option<state_record::InstallEntry> {
        let record = self.installed.record.as_ref().filter(|_| !self.installed.record_lost);
        if record.is_none() && !self.installed.record_lost {
            return None;
        }
        let about = ["staged", "refused", "answered", "install-applied", "install-widened"].contains(&event).then_some(subject).flatten();
        Some(state_record::InstallEntry {
            install_id: record.map_or([0; 16], Record::install_id),
            trust_seq: record.map_or(0, |record| u64::try_from(record.trust_seq).unwrap_or(0)),
            subject: about.unwrap_or("none"),
            answers: record.map_or(0, |record| record.answers),
            overrides: record.map_or(0, |record| record.overrides),
        })
    }

    /// H14: the reconciling entry, or None outside the state. A locked PEP names the cause `dist:floor-lost` and
    /// no running release (C13). The floor field is the set id of the action floor the PEP holds, which on `host` is
    /// the one it asks, since the floor lives in the machine; zeros for none.
    fn reconciling_entry(&self) -> Option<state_record::ReconcilingEntry> {
        let state = self.reconciling.as_ref()?;
        let running = self.running();
        let prefix = |hash: Option<&Hex64>| state_record::prefix(hash.map(Hex64::as_str));
        let cause = if self.locked { Some(FLOOR_LOST) } else { state.owed.cause().or(state.running_fell) };
        let floor = self.installed.held(SetKind::Floor).map_or([0; 16], |set| state_record::prefix(Some(set.set_id().as_str())));
        Some(state_record::ReconcilingEntry {
            owed: self.owed_event(&state.owed),
            cause: cause.map(str::to_string),
            running_policy: prefix(running.map(|release| &release.policy_sha256)),
            running_release: prefix(running.map(|release| &release.release)),
            running_seq: u64::try_from(running.map_or(0, |release| release.seq)).unwrap_or(0),
            floor,
        })
    }

    /// H1, R4: the floor V8 holds, the larger of the committed floor and the one a revocation raised.
    pub fn reported_floor(&self) -> i64 {
        let raised = match (&self.stream, self.trust.is_readable()) {
            (Some(stream), true) => self.trust.floors.get(stream).copied().unwrap_or(0),
            _ => 0,
        };
        self.floor.seq.max(raised)
    }

    // ------------------------------------------------------------------ H9, H15, H16: the controller statement
    /// H9: take the epoch id of a controller statement that reads, names this PEP's stream, verifies under the
    /// controller key the trust store holds (not revoked, K6) and carries the key sequence the store holds for it,
    /// when that id is above the one held. Any other statement changes nothing and makes no record. Where freshness
    /// is on (H16), a statement that passes those checks may also give freshness. Answers whether the epoch id was
    /// taken. A statement changes nothing but the epoch id, the kept fresh statement and, once per start on a PEP
    /// with no clock, the time floor. A reconciling PEP takes one too and tries no runtime (C8).
    pub fn take_statement(&mut self, data: &[u8]) -> Result<bool, PepError> {
        let Some(stream) = self.stream.clone().filter(|_| self.provisioned && !self.locked && self.trust.is_readable()) else {
            return Ok(false);
        };
        let Some(read) = statements::verify(data, self.trust.controller_public().as_ref()) else { return Ok(false) };
        if read.stream != state_record::stream_prefix(stream.as_str()) || i64::try_from(read.key_seq).ok() != Some(self.trust.key_sequence()) {
            return Ok(false);
        }
        let taken = read.epoch > self.epoch;
        if taken {
            self.epoch = read.epoch; // H9: never lowered
        }
        if self.fresh > 0 {
            self.freshen(&read, data)?;
        }
        Ok(taken)
    }

    /// H9: `take_statement` for the `epoch` member of an `offers` answer, base64url without padding. A member that is
    /// not one, an epoch id with no statement among them, changes nothing.
    pub fn take_offered(&mut self, epoch: &str) -> Result<bool, PepError> {
        match statements::decode_offered(epoch) {
            Some(data) => self.take_statement(&data),
            None => Ok(false),
        }
    }

    /// H9, H15: the epoch id the PEP holds and puts in every record.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// H16: the fresh statement the PEP keeps, None when freshness is off or none is kept.
    pub fn kept(&self) -> Option<&Kept> {
        self.kept.as_ref()
    }

    /// H16: a fresh statement has `fresh` 1, a trust sequence not below the PEP's, a stream seq not below its floor,
    /// an `expires` later than the kept one's and at most `fresh` plus SKEW ahead of the PEP's time. A PEP with no
    /// clock takes, from the first statement after each start that passes every other check, its `expires` less
    /// `fresh` as a raise of its time floor (T1). The latest fresh statement is kept durably, written before it
    /// counts, and a newer one is written only when the kept one has used half its life. An `expires` past what a
    /// canon/2 document holds exactly gives no freshness and no time.
    fn freshen(&mut self, read: &Statement, data: &[u8]) -> Result<(), PepError> {
        let unsigned = |value: i64| u64::try_from(value).unwrap_or(0);
        if !read.fresh || read.trust_seq < unsigned(self.trust.trust_seq) || read.stream_seq < unsigned(self.reported_floor()) {
            return Ok(());
        }
        let Some(expires) = i64::try_from(read.expires).ok().filter(|expires| *expires <= MAX_SEQ) else { return Ok(()) };
        if self.kept.as_ref().is_some_and(|kept| expires <= kept.expires) {
            return Ok(());
        }
        if !self.has_clock && !self.time_taken {
            self.time_taken = true; // once per start, from no other statement
            let floor = expires - self.fresh;
            if floor > self.trust.time_floor {
                self.trust.time_floor = floor; // T1
                self.trust.save(&self.trust_path())?;
            }
        }
        let time = self.time();
        if i128::from(expires) - i128::from(time) > i128::from(self.fresh) + i128::from(SKEW) {
            return Ok(());
        }
        if let Some(kept) = &self.kept {
            if 2 * (i128::from(time) - i128::from(kept.at)) < i128::from(kept.expires) - i128::from(kept.at) {
                return Ok(()); // the kept one has not used half its life
            }
        }
        let kept = Kept { statement: data.to_vec(), expires, at: time };
        self.store.write(
            "fresh.json",
            &FreshDoc { at: kept.at, encoding: Canon2Tag, expires, format: FreshFormat, statement: hex::encode(&kept.statement) },
        )?;
        self.kept = Some(kept);
        Ok(())
    }

    /// The kept fresh statement (H16), or None. One that does not read is none, so the PEP lapses at its next
    /// statement's lapse rather than on a file it cannot trust; it is checked again under the controller key.
    fn read_fresh(&self) -> Option<Kept> {
        if self.fresh == 0 || !self.store.exists("fresh.json") {
            return None;
        }
        let doc = self.store.read::<FreshDoc>("fresh.json").ok()?;
        let statement = hex::decode(&doc.statement).ok()?;
        let read = statements::verify(&statement, self.trust.controller_public().as_ref())?;
        (i64::try_from(read.expires).ok() == Some(doc.expires) && doc.at >= 0).then_some(Kept { statement, expires: doc.expires, at: doc.at })
    }

    /// H16: freshness is on and the PEP's time passed the kept statement's `expires` plus SKEW.
    fn stale(&self) -> bool {
        self.fresh > 0 && self.kept.as_ref().is_some_and(|kept| i128::from(self.time()) > i128::from(kept.expires) + i128::from(SKEW))
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
    fn refuse(&mut self, cause: &str, details: Fields) -> Result<Vec<u8>, PepError> {
        self.refuse_about(cause, None, details)
    }

    fn refuse_about(&mut self, cause: &str, subject: Option<&'static str>, mut details: Fields) -> Result<Vec<u8>, PepError> {
        details.push(("cause", json!(cause)));
        if let Some(subject) = subject {
            details.push(("subject", json!(subject)));
        }
        details.push(("result", json!("refused")));
        self.audit.append("distribution", "refused", details)?;
        self.make_record_about("refused", Some(cause), subject)
    }

    /// B4, B9: the binding refused the blob `name` before anything was staged. The refusal is the PEP's own,
    /// in its audit log and its records, and nothing else changes.
    pub fn refuse_fetched(&mut self, cause: &str, name: &Hex64) -> Result<Vec<u8>, PepError> {
        self.check_active()?;
        self.refuse(cause, vec![("blob", json!(name.as_str()))])
    }

    /// Verify one sealed envelope and its body and hold it (G1). Returns the stage-ack state record. An envelope
    /// that is not a widening statement is held to the widening rule against the active release (V12), with the
    /// statement already staged for its release, so a statement is staged before the release it covers (W3). A
    /// reconciling PEP stages as in any other state, and the rule compares with the held release (C8).
    pub fn stage(&mut self, sealed: &[u8], body: &[u8]) -> Result<Vec<u8>, PepError> {
        self.check_active()?;
        if !self.provisioned {
            return self.refuse(UNKNOWN_KEY, Vec::new()); // P1, P2 step 4
        }
        self.stage_one(sealed, body, true)
    }

    /// `stage` once the PEP is provisioned. `message` false is a statement brought by provisioning (IS4, IS13). A
    /// locked PEP still takes install statements, because its install record is kept apart from the store it lost
    /// (IS6). A PEP whose install record is lost takes nothing but the trust statements, and one whose ceiling is lost
    /// takes no install set but a ceiling and no release (IS10).
    fn stage_one(&mut self, sealed: &[u8], body: &[u8], message: bool) -> Result<Vec<u8>, PepError> {
        let Some(view) = self.view(message) else {
            return self.refuse(if self.locked { FLOOR_LOST } else { UNKNOWN_KEY }, Vec::new());
        };
        let verdict = verify::verify(sealed, body, &self.trust, &view, (self.clock)());
        let artifact = verdict.envelope.as_ref().map(|envelope| envelope.artifact);
        let installing = artifact.is_some_and(ArtifactKind::is_install);
        let mut subject = artifact.filter(|_| installing).map(ArtifactKind::name);
        if artifact == Some(ArtifactKind::InstallChange) {
            // H10: the set an install change statement carries, or none when its body does not read
            subject = install::read_install_change(body).ok().map(|(kind, _)| kind.name());
        }
        let on_trust = artifact.is_some_and(ArtifactKind::on_trust_stream);
        let id_of = |verdict: &super::Verdict| json!(verdict.envelope.as_ref().map(|envelope| envelope.envelope_id().to_string()));
        if self.installed.record_lost && !on_trust {
            return self.refuse_about(INSTALL_LOST, subject, vec![("envelope_id", id_of(&verdict))]); // IS10
        }
        if self.locked && !installing {
            return self.refuse(FLOOR_LOST, Vec::new()); // Q5: a locked PEP takes install statements only
        }
        let ceiling_or_trust = matches!(artifact, Some(ArtifactKind::InstallCeiling | ArtifactKind::InstallTrust));
        if self.installed.ceiling_lost && artifact.is_some() && !on_trust && !ceiling_or_trust {
            return self.refuse_about(INSTALL_LOST, subject, vec![("envelope_id", id_of(&verdict))]); // IS10: frozen
        }
        if let Some(time_floor) = verdict.time_floor {
            if self.trust.is_readable() && time_floor > self.trust.time_floor {
                self.trust.time_floor = time_floor; // V13, T1
                self.trust.save(&self.trust_path())?;
            }
        }
        let envelope_id = id_of(&verdict);
        if let Some(cause) = &verdict.cause {
            return self.refuse_about(cause, subject, vec![("envelope_id", envelope_id)]);
        }
        if verdict.unchanged {
            return self.make_record("beat", None); // Q3, R1, IS6: changes nothing, reports its state
        }
        let envelope = verdict.envelope.expect("an accepted verdict carries its envelope");
        if installing {
            return self.stage_install(&envelope, sealed, body);
        }
        match envelope.artifact {
            ArtifactKind::TrustRevocation => return self.apply_revocation(&envelope, body),
            ArtifactKind::TrustRotation => return self.apply_rotation(&envelope, body),
            ArtifactKind::TrustController => return self.apply_controller(&envelope, body),
            _ => {}
        }
        if let Some(staged) = &self.staged {
            if staged.stream == envelope.stream && envelope.seq < staged.seq {
                return self.refuse(SEQ_REPLAY, vec![("envelope_id", envelope_id)]); // G2
            }
        }
        if envelope.artifact.is_statement() {
            // W11: a release carries one statement, a widening statement or a change statement, never both
            let other = if envelope.artifact == ArtifactKind::TrustChange { ArtifactKind::TrustWidening } else { ArtifactKind::TrustChange };
            let same = self.staged.as_ref().filter(|staged| staged.stream == envelope.stream && staged.seq == envelope.seq);
            if same.is_some_and(|staged| staged.bodies.contains_key(&other)) {
                return self.refuse(BAD_FORMAT, vec![("envelope_id", envelope_id)]);
            }
        }
        if envelope.artifact == ArtifactKind::TrustChange
            && !changes(Some(body), self.active.as_ref().map(|active| &active.policy_sha256))
        {
            return self.refuse(WIDENING_UNSIGNED, vec![("envelope_id", envelope_id)]); // W11: a first install widens
        }
        if !envelope.artifact.is_statement() {
            let same = self.staged.as_ref().filter(|staged| staged.stream == envelope.stream && staged.seq == envelope.seq);
            let statement = same.and_then(|staged| staged.bodies.get(&ArtifactKind::TrustWidening)).cloned();
            let change = same.and_then(|staged| staged.bodies.get(&ArtifactKind::TrustChange)).cloned();
            let artifacts = BTreeMap::from([(envelope.artifact, body.to_vec())]);
            let statements = (statement.as_deref(), change.as_deref());
            if let Some(cause) = self.widening(envelope.widens, &envelope.replaces, &artifacts, statements, false) {
                return self.refuse(cause, vec![("envelope_id", envelope_id)]); // V12
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
        self.keep_blobs(); // a replaced release's blobs go (G2), never the running release's (C11)
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

    // ------------------------------------------------------------------ IS4 to IS12: the install statements
    /// IS4: an `install.trust` is applied as soon as it verifies (IS11). A statement of a set is staged durably, as
    /// G1 stages an envelope, with event `staged` and its subject, a set at a higher `seq` replacing the one staged of
    /// its kind, and the set is applied when it is whole.
    fn stage_install(&mut self, envelope: &Envelope, sealed: &[u8], body: &[u8]) -> Result<Vec<u8>, PepError> {
        if envelope.artifact == ArtifactKind::InstallChange {
            return self.stage_install_change(envelope, sealed, body);
        }
        let Some(kind) = SetKind::of(envelope.artifact) else { return self.apply_install_trust(envelope, body) };
        let whole = self.installed.stage(kind, envelope, sealed, body)?.whole();
        let named = install::install_meta(envelope).map_or("", |meta| meta.as_name.name());
        self.audit.append(
            "distribution",
            "staged",
            vec![
                ("envelope_id", json!(envelope.envelope_id().as_str())),
                ("artifact", json!(kind.name())),
                ("as", json!(named)),
                ("seq", json!(envelope.seq)),
                ("release", json!(envelope.release.as_str())),
                ("result", json!("staged")),
            ],
        )?;
        let ack = self.make_record_about("staged", None, Some(kind.name()))?;
        if !whole {
            return Ok(ack);
        }
        self.apply_set(kind)
    }

    /// IS15: an install change statement is staged before the set it carries, durably and with event `staged` whose
    /// subject is that set's kind. One staged on a PEP that holds no set of the kind, or whose `from` is not the held
    /// set's policy hash, is `dist:widening-unsigned`, and the rule is held again when the set is applied.
    fn stage_install_change(&mut self, envelope: &Envelope, sealed: &[u8], body: &[u8]) -> Result<Vec<u8>, PepError> {
        let (kind, _from) = install::read_install_change(body).map_err(|refusal| refused(refusal.to_string()))?;
        let held = self.installed.held(kind).map(|held| held.policy_sha256().clone());
        if !install::changes_set(Some(body), kind, held.as_ref()) {
            return self.refuse_about(WIDENING_UNSIGNED, Some(kind.name()), vec![("envelope_id", json!(envelope.envelope_id().as_str()))]);
        }
        self.installed.stage_change(kind, envelope, sealed, body)?;
        self.audit.append(
            "distribution",
            "staged",
            vec![
                ("envelope_id", json!(envelope.envelope_id().as_str())),
                ("artifact", json!(ArtifactKind::InstallChange.name())),
                ("set", json!(kind.name())),
                ("seq", json!(envelope.seq)),
                ("release", json!(envelope.release.as_str())),
                ("result", json!("staged")),
            ],
        )?;
        self.make_record_about("staged", None, Some(kind.name()))
    }

    fn refuse_set(&mut self, kind: SetKind, cause: &str, seq: i64) -> Result<Vec<u8>, PepError> {
        self.installed.drop_staged(kind)?;
        self.refuse_about(cause, Some(kind.name()), vec![("seq", json!(seq))])
    }

    /// IS4, IS6, IS12, CL3: apply the whole set staged of `kind`. It is held to its `seq` again, to the target's own
    /// check over the whole set, to the ceiling the PEP holds now (an action floor and a fallback policy inside it,
    /// and a ceiling the held ones are inside), and to the widening rule of IS12. The marks, both copies of every
    /// statement and the record are durable before the event, `install-widened` for a set that stands out and
    /// `install-applied` otherwise. The empty set withdraws its kind. A ceiling the active release is above lapses
    /// it (CL3), and a fallback policy that now decides is run (FB8).
    fn apply_set(&mut self, kind: SetKind) -> Result<Vec<u8>, PepError> {
        let staged = self.installed.staged.get(&kind).cloned().expect("a whole staged set");
        let record = self.installed.record.clone().expect("a staged set verified under a record");
        let seq = staged.seq();
        if seq <= record.seq(kind) {
            return self.refuse_set(kind, SEQ_REPLAY, seq);
        }
        let empty = staged.is_empty_set();
        let as_release = self.release_of_set(&staged);
        for (artifact, body) in &as_release.bodies {
            if let Some(cause) = self.adapter.check(*artifact, body, &as_release) {
                return self.refuse_set(kind, &cause, seq);
            }
        }
        let ceiling = self.installed.held(SetKind::Ceiling).cloned();
        let table = |set: &InstallSet| set.bodies.get(&AsName::Artifact(ArtifactKind::PolicyPpt)).cloned();
        if kind != SetKind::Ceiling && !empty && !install::table_inside(ceiling.as_ref(), table(&staged).as_deref()) {
            return self.refuse_set(kind, ABOVE_CEILING, seq); // CL3, IS4: the ceiling held at apply
        }
        if kind == SetKind::Ceiling && !empty {
            for other in [SetKind::Floor, SetKind::Fallback] {
                if let Some(held) = self.installed.held(other) {
                    if !install::table_inside(Some(&staged), table(held).as_deref()) {
                        return self.refuse_set(kind, ABOVE_CEILING, seq); // CL3: the engineer narrows those first
                    }
                }
            }
        }
        // IS10, IS12: a ceiling after a lost one is held to the set the record names for it
        let lost = install::Lost {
            lost: kind == SetKind::Ceiling && self.installed.ceiling_lost,
            named: self.installed.lost_ceiling.as_ref().filter(|_| kind == SetKind::Ceiling),
        };
        let (cause, stands_out) = install::widens_ok(kind, record.held(kind), &staged, lost);
        if let Some(cause) = cause {
            return self.refuse_set(kind, cause, seq);
        }
        // CL3: a ceiling that narrows below the active release is no widening; the release lapses and says so itself
        let active_table = self.active.as_ref().and_then(|active| active.bodies.get(&ArtifactKind::PolicyPpt)).cloned();
        let lapses = kind == SetKind::Ceiling && !empty && active_table.is_some() && !install::table_inside(Some(&staged), active_table.as_deref());
        let change = staged.doc.change.as_ref().filter(|_| !stands_out).map(|held| held.envelope_id.clone());
        let mut staged = staged;
        (staged.doc.change, staged.change_body) = (None, None); // the change statement is no member of the set held
        let before = self.fallback_decides();
        let ceiling_mark = (kind == SetKind::Ceiling).then_some(!empty);
        self.installed.mark(true, false, ceiling_mark)?; // IS9: before the first install statement is applied
        self.installed.keep_both(&staged)?;
        let mut next = record.clone();
        next.sets[kind as usize] = (!empty).then(|| staged.clone());
        next.seqs[kind as usize] = seq;
        next.applied[kind as usize] = Some(staged.set_id());
        self.installed.save(next)?;
        self.installed.drop_staged(kind)?;
        if kind == SetKind::Ceiling {
            self.installed.ceiling_lost = false;
        }
        let event = if stands_out { "install-widened" } else { "install-applied" };
        let mut details = vec![
            ("artifact", json!(kind.name())),
            ("seq", json!(seq)),
            ("set_id", json!(staged.set_id().as_str())),
            ("envelopes", json!(self.installed.statement_ids().iter().map(Hex64::as_str).collect::<Vec<_>>())),
            ("result", json!(event)),
        ];
        if let Some(change) = change {
            details.push(("change", json!(change.as_str()))); // IS15: the statement the set was taken on
        }
        self.audit.append("distribution", event, details)?;
        let cause = stands_out.then_some(INSTALL_WIDENED);
        if lapses {
            let applied = self.make_record_about(event, cause, Some(kind.name()))?;
            self.lapse(ABOVE_CEILING)?; // CL3, as under R5
            return Ok(applied);
        }
        if kind == SetKind::Fallback && self.reconciling.is_some() {
            if self.reconciling.as_ref().is_some_and(|state| state.withdrawn) && self.withdraw(&self.withdraw_cause()).is_err() {
                // C8: the withdrawn runtime runs the new set, and when it does not the next tick tries again (C9)
                if let Some(state) = self.reconciling.as_mut() {
                    state.withdrawn = false;
                }
            }
            return self.make_record_about(event, cause, Some(kind.name()));
        }
        if kind == SetKind::Fallback && (before || self.fallback_decides()) {
            return self.runtime_step(Owed::Installed(stands_out), None); // FB8: the new fallback set decides at once
        }
        self.make_record_about(event, cause, Some(kind.name()))
    }

    /// IS11: apply a verified `install.trust` at once, durably before its event. It widens when it adds a key of
    /// either role or lowers the threshold.
    fn apply_install_trust(&mut self, envelope: &Envelope, body: &[u8]) -> Result<Vec<u8>, PepError> {
        let record = self.installed.record.clone().expect("an install trust statement verified under a record");
        let widened = envelope.widens || install::trust_widens(&record, body);
        let next = record.apply_trust(envelope, body).map_err(|refusal| refused(refusal.to_string()))?;
        self.installed.mark(true, false, None)?;
        self.installed.save(next)?;
        let event = if widened { "install-widened" } else { "install-applied" };
        self.audit.append(
            "distribution",
            event,
            vec![
                ("artifact", json!(ArtifactKind::InstallTrust.name())),
                ("seq", json!(envelope.seq)),
                ("envelope_id", json!(envelope.envelope_id().as_str())),
                ("result", json!(event)),
            ],
        )?;
        self.make_record_about(event, widened.then_some(INSTALL_WIDENED), Some(ArtifactKind::InstallTrust.name()))
    }

    /// V12 against the held release (C8). `artifacts` are the bodies judged and `statements` the widening statement
    /// and the change statement staged for the same release. A kind that cannot decide compares what its row compares (W2), so on `host` a
    /// table that is not byte for byte the active one is larger. One that can decide compares one artifact at
    /// staging and the whole release at commit (`whole`), which also sees an artifact the release drops.
    fn widening(
        &self,
        widens: bool,
        replaces: &MaybeHex64,
        artifacts: &BTreeMap<ArtifactKind, Vec<u8>>,
        statements: (Option<&[u8]>, Option<&[u8]>),
        whole: bool,
    ) -> Option<&'static str> {
        let active = self.active.as_ref();
        let mut answer = None;
        if let (false, Some(active)) = (self.target.decides, active) {
            for (artifact, body) in artifacts.iter().filter(|(artifact, _)| self.target.compares.contains(artifact)) {
                let held = active.bodies.get(artifact);
                if held.is_some() && compare_artifact(*artifact, held.map(Vec::as_slice), Some(body)) != Comparison::NotLarger {
                    answer = Some(Comparison::Larger);
                }
            }
        }
        if self.target.decides {
            answer = Some(match (whole, active, artifacts.iter().next()) {
                (true, _, _) => compare_release(active.map(|active| &active.bodies), artifacts),
                (false, Some(active), Some((artifact, body))) => {
                    compare_artifact(*artifact, active.bodies.get(artifact).map(Vec::as_slice), Some(body))
                }
                _ => Comparison::Larger,
            });
        }
        let (statement, change) = statements;
        widening_check(&self.target, widens, replaces, active.map(|active| &active.policy_sha256), answer, statement, change)
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
    /// A reconciling PEP holds both its releases to the test (C10) and tries no runtime.
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
        self.check_active()?;
        self.make_record("trust-applied", None)
    }

    /// Apply a verified `trust.controller` at once (K7). The epoch id starts again at 0 (H15), so the next statement
    /// under the new key sequence is taken whatever id it carries.
    fn apply_controller(&mut self, envelope: &Envelope, body: &[u8]) -> Result<Vec<u8>, PepError> {
        let store = self.trust.apply_controller(envelope, body).map_err(|refusal| refused(refusal.to_string()))?;
        self.adopt(envelope, store)?;
        self.epoch = 0;
        self.check_active()?;
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

    /// The blobs of the active, the kept and the staged release, and of the running release until the
    /// withdrawal works (C11), stay. Every other blob goes.
    fn keep_blobs(&self) {
        let running = self.running().cloned();
        let keep: BTreeSet<Hex64> = [&self.active, &self.previous, &self.staged, &running]
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
    /// refused and nothing changes. A reconciling PEP answers `refused` with `dist:reconciling` and keeps the
    /// staged release (C8).
    pub fn commit(&mut self, stream: &str, seq: i64, policy_sha256: &Hex64, delay_ms: u16) -> Result<Vec<u8>, PepError> {
        if delay_ms != 0 {
            return Err(refused(format!(
                "a commit delay of {delay_ms} ms (B8) is the frame binding's, which this crate does not build; commit with no delay"
            )));
        }
        self.check_active()?;
        if self.locked {
            return self.refuse(FLOOR_LOST, Vec::new());
        }
        if self.reconciling.is_some() {
            return self.refuse(RECONCILING, vec![("seq", json!(seq))]);
        }
        if self.installed.record_lost || self.installed.ceiling_lost {
            return self.refuse(INSTALL_LOST, vec![("seq", json!(seq))]); // IS10: a lost ceiling never fails open
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
        let mut cause = self.still_valid(&staged, true); // C3
        if cause.is_none() && !self.inside_ceiling(&staged) {
            cause = Some(ABOVE_CEILING.to_string()); // CL2: the ceiling may have changed since staging
        }
        if let Some(cause) = cause {
            self.drop_staged()?;
            return self.refuse(&cause, vec![("seq", json!(seq))]);
        }
        // C3: V12 again against what is active now, since a lapse, a rollback or another commit may have changed it.
        // A refused release stays staged.
        let statements = (
            staged.bodies.get(&ArtifactKind::TrustWidening).map(Vec::as_slice),
            staged.bodies.get(&ArtifactKind::TrustChange).map(Vec::as_slice),
        );
        if let Some(cause) = self.widening(staged.widens, &staged.replaces, &staged.bodies, statements, true) {
            return self.refuse(cause, vec![("seq", json!(seq))]);
        }
        let floor = Floor { seq: staged.seq, ids: staged.envelope_ids() };
        let previous = self.active.clone();
        self.installed.mark(false, true, None)?; // L2: before the commit, in the anchor part
        self.flip("commit", staged, previous, floor)
    }

    /// CL2: the release's table is on the held ceiling's list.
    fn inside_ceiling(&self, release: &Release) -> bool {
        install::table_inside(self.installed.held(SetKind::Ceiling), release.bodies.get(&ArtifactKind::PolicyPpt).map(Vec::as_slice))
    }

    /// C7: the intent record of a transition.
    fn write_intent(&self, op: &str, release: Option<&Release>, cause: Option<&str>, running: Option<&Release>, withdrawn: bool) -> Result<(), PepError> {
        let doc = PendingDoc {
            cause: cause.map(str::to_string),
            encoding: Canon2Tag,
            format: PendingFormat,
            op: op.to_string(),
            release: release.map(Release::document),
            running: running.map(Release::document),
            withdrawn,
        };
        Ok(self.store.write("pending.json", &doc)?)
    }

    fn write_active(&self, release: Option<&Release>, previous: Option<&Release>) -> Result<(), HostError> {
        self.store.write(
            "active.json",
            &ActiveDoc {
                encoding: Canon2Tag,
                format: ActiveFormat,
                previous: previous.map(Release::document),
                release: release.map(Release::document),
            },
        )
    }

    /// C4, one step after another, each synced: intent, floor (a commit only), evidence, the artifacts (already
    /// blobs), the active record, the runtime step, the state record, the clean up.
    fn flip(&mut self, op: &str, release: Release, previous: Option<Release>, floor: Floor) -> Result<Vec<u8>, PepError> {
        let running = self.active.clone(); // the runtime runs the held release, since the PEP is not reconciling
        self.fault(PepStep::Intent)?;
        self.write_intent(op, Some(&release), None, running.as_ref(), false)?;
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
        self.write_active(Some(&release), previous.as_ref())?;
        self.previous = previous;
        if self.staged.as_ref().is_some_and(|staged| staged.seq <= release.seq) {
            self.staged = None;
        }
        self.active = Some(release);
        self.held = false;
        self.retry_runtime = false;
        self.fault(PepStep::Runtime)?;
        self.runtime_step(if committing { Owed::Committed } else { Owed::RolledBack }, running)
    }

    /// The runtime step of a transition whose record is durable. When it works the state record goes, then the
    /// clean up. When it fails between two releases whose bodies are the same the PEP stays as it is and each tick
    /// tries again, and otherwise it is reconciling (C6, C10).
    fn runtime_step(&mut self, owed: Owed, running: Option<Release>) -> Result<Vec<u8>, PepError> {
        let Err(error) = self.step(&owed) else { return self.settle(owed) };
        if self.same_bodies(running.as_ref()) {
            return self.renewal_failed(owed, &error);
        }
        self.enter_reconciling(owed, running, &error.to_string())
    }

    /// C10: the runtime step of a switch between two releases with the same bodies failed. The PEP stays as it is
    /// with the runtime running, writes the failure to its audit log, sends the record the transition owes and
    /// tries the step again at each tick.
    fn renewal_failed(&mut self, owed: Owed, error: &PepError) -> Result<Vec<u8>, PepError> {
        self.audit.append(
            "distribution",
            "runtime_failed",
            vec![("error", json!(error.to_string())), ("result", json!("tried again at the next tick"))],
        )?;
        self.retry_runtime = true;
        self.settle(owed)
    }

    /// C10: the held release and `running` have the same bodies, so a switch between them changes nothing the
    /// runtime decides with. The trust kinds are not run, so they are left out.
    fn same_bodies(&self, running: Option<&Release>) -> bool {
        let (Some(held), Some(running)) = (self.active.as_ref(), running) else { return false };
        let run = |release: &Release| -> BTreeMap<ArtifactKind, Vec<u8>> {
            release.bodies.iter().filter(|(artifact, _)| !artifact.is_trust()).map(|(artifact, body)| (*artifact, body.clone())).collect()
        };
        !held.bodies.is_empty() && run(held) == run(running)
    }

    /// The state record a transition owes, then the clean up, which takes the intent record (C12).
    fn settle(&mut self, owed: Owed) -> Result<Vec<u8>, PepError> {
        let record = self.make_record_about(self.owed_event(&owed), owed.cause(), owed.subject())?;
        self.fault(PepStep::Cleanup)?;
        self.cleanup()?;
        Ok(record)
    }

    fn cleanup(&mut self) -> Result<(), PepError> {
        if self.staged.is_none() {
            self.store.remove("staged.json")?;
        }
        self.keep_blobs();
        self.store.remove("pending.json")?;
        Ok(())
    }

    // ------------------------------------------------------------------ section 9.5: reconciling
    /// What the runtime is told when it is withdrawn.
    fn withdraw_cause(&self) -> String {
        match &self.reconciling {
            _ if self.locked => FLOOR_LOST.to_string(),
            Some(Reconciling { owed: Owed::Lapsed(cause), .. }) => cause.clone(),
            _ => RECONCILING.to_string(),
        }
    }

    /// C6, C10, C12: the runtime step failed. The PEP withdraws the runtime at once, unless the step that failed
    /// was the withdrawal itself, writes `reconciling` with the runtime's error and sends a record with that
    /// event. When the withdrawal works the intent record notes it and only the held release is tracked.
    fn enter_reconciling(&mut self, owed: Owed, running: Option<Release>, error: &str) -> Result<Vec<u8>, PepError> {
        let stepped_withdrawal = self.locked || self.active.is_none() || !self.trust.is_readable();
        self.reconciling = Some(Reconciling { owed, running, withdrawn: false, running_fell: None });
        if !stepped_withdrawal && self.withdraw(&self.withdraw_cause()).is_ok() {
            self.note_withdrawn()?;
        }
        let withdrawn = self.reconciling.as_ref().is_some_and(|state| state.withdrawn);
        self.audit.append(
            "distribution",
            "reconciling",
            vec![("error", json!(error)), ("withdrawn", json!(withdrawn)), ("result", json!("reconciling"))],
        )?;
        self.run_tests(true)?;
        self.make_record("reconciling", None)
    }

    /// C10: the withdrawal worked. The runtime runs no release, and the intent record says so.
    fn note_withdrawn(&mut self) -> Result<(), PepError> {
        if let Some(state) = self.reconciling.as_mut() {
            state.withdrawn = true;
            state.running = None;
            state.running_fell = None;
        }
        if let Ok(mut intent) = self.store.read::<PendingDoc>("pending.json") {
            intent.running = None;
            intent.withdrawn = true;
            self.store.write("pending.json", &intent)?;
        }
        Ok(())
    }

    /// C10, H14: the runtime may run `release`, which the PEP names until a withdrawal works, and the intent
    /// record says so (C7).
    fn note_running(&mut self, release: &Release) -> Result<(), PepError> {
        if let Some(state) = self.reconciling.as_mut() {
            state.withdrawn = false;
            state.running = Some(release.clone());
            state.running_fell = None;
        }
        if let Ok(mut intent) = self.store.read::<PendingDoc>("pending.json") {
            intent.running = Some(release.document());
            intent.withdrawn = false;
            self.store.write("pending.json", &intent)?;
        }
        Ok(())
    }

    /// Whether `release` fell, and for what: the test of R5, then expiry (X1), then the ceiling (CL3). HOLD is for
    /// `mesh` and `cfs`, which never reconcile, so expiry always fells a release here (C10).
    fn fell(&self, release: &Release) -> Option<&'static str> {
        if release.envelopes.len() != release.held.len() {
            return None; // a running release whose blobs do not read: it is still named, and its tests wait
        }
        if !self.stands(release, true) {
            Some(REVOKED)
        } else if self.still_valid(release, false).as_deref() == Some(EXPIRED) || self.stale() {
            Some(EXPIRED) // X1, and H16's freshness
        } else if !self.inside_ceiling(release) {
            Some(ABOVE_CEILING)
        } else {
            None
        }
    }

    /// C10: hold the held release, and the running one while the withdrawal has not worked, to the tests. A
    /// held release that falls becomes a lapse with the cause it fell for, never installed. A PEP whose trust
    /// store does not read treats the held release as none and runs no test. No runtime is tried here.
    fn run_tests(&mut self, untried: bool) -> Result<(), PepError> {
        if self.reconciling.is_none() || self.locked || !self.trust.is_readable() {
            return Ok(());
        }
        let running_fell = self.running().and_then(|running| self.fell(running));
        if let Some(state) = self.reconciling.as_mut() {
            state.running_fell = state.running_fell.or(running_fell);
        }
        if let Some(cause) = self.active.as_ref().and_then(|held| self.fell(held)) {
            self.held_falls(cause, untried)?;
        }
        Ok(())
    }

    /// C10: a held release that falls was never run. Its transition becomes a lapse: the intent record is written
    /// again, the `lapsed` audit event, then an active record that names no release. The PEP owes `lapsed` with
    /// that cause and no longer the record of the commit or the rollback, and the floor stays where it was (Q4).
    ///
    /// `untried` is true when no runtime step of the held release can have begun since it was last withdrawn, which
    /// a restart of a transition that flipped cannot say. The audit event says the release never ran when that is
    /// so and the runtime is not named as running it. The commit hook sees the intent record, the audit event and
    /// the active record, as in a lapse (C7).
    fn held_falls(&mut self, cause: &'static str, untried: bool) -> Result<(), PepError> {
        let Some(fell) = self.active.clone() else { return Ok(()) };
        let state = self.reconciling.clone().expect("only a reconciling PEP");
        let running = if state.withdrawn { None } else { state.running.as_ref() };
        let never_ran = untried && running.is_none_or(|running| running.document() != fell.document());
        self.fault(PepStep::Intent)?;
        self.write_intent("lapse", None, Some(cause), running, state.withdrawn)?;
        self.fault(PepStep::Evidence)?;
        self.audit_lapse(Some(fell.seq), cause, never_ran)?;
        self.fault(PepStep::ActiveRecord)?;
        self.write_active(None, self.previous.as_ref())?;
        self.active = None;
        self.held = false;
        if let Some(state) = self.reconciling.as_mut() {
            state.owed = Owed::Lapsed(cause.to_string());
        }
        self.keep_blobs();
        Ok(())
    }

    /// The `lapsed` audit event, written once for a transition (C12): not when a start found it already written.
    fn audit_lapse(&mut self, seq: Option<i64>, cause: &str, never_ran: bool) -> Result<(), PepError> {
        if self.lapse_audited.take().is_some_and(|(audited, audited_cause)| audited == seq && audited_cause == cause) {
            return Ok(());
        }
        let mut fields: Fields = vec![("seq", json!(seq)), ("cause", json!(cause))];
        if never_ran {
            fields.push(("ran", json!(false)));
        }
        fields.push(("result", json!("lapsed")));
        self.audit.append("distribution", "lapsed", fields)?;
        Ok(())
    }

    /// C9: one try. The tests of C10, the withdrawal again when it has not worked, then the held release run
    /// with nothing more when none is held. When the switch works the state ends and the record the transition
    /// owed goes, a `beat` when nothing was. When it fails the next tick tries again.
    ///
    /// An install that fails may have switched the runtime part way, as a host whose record flipped before its
    /// clean up failed has, so from the moment it starts the runtime may run the held release (C10, H14, X3). The
    /// intent record says so before the install, and a failed install is followed at once by the withdrawal. Only
    /// when that fails too does the PEP go on naming the held release as the one the runtime may run.
    fn try_runtime(&mut self) -> Result<Option<Vec<u8>>, PepError> {
        self.run_tests(true)?;
        let Some(state) = self.reconciling.clone() else { return Ok(None) };
        if !state.withdrawn {
            if self.withdraw(&self.withdraw_cause()).is_err() {
                return Ok(None);
            }
            self.note_withdrawn()?;
        }
        if let (None, Some(held)) = (self.own_refusal(), self.active.clone()) {
            self.note_running(&held)?;
            if self.adapter.activate(&held).is_err() {
                if self.withdraw(&self.withdraw_cause()).is_ok() {
                    self.note_withdrawn()?;
                }
                return Ok(None);
            }
        }
        self.leave().map(Some)
    }

    /// C9, C10: with the runtime withdrawn and no release held the switch is done, so the state ends at once,
    /// with no runtime call.
    fn end_if_switched(&mut self) -> Result<Option<Vec<u8>>, PepError> {
        match &self.reconciling {
            Some(state) if state.withdrawn && !self.locked && self.active.is_none() => self.leave().map(Some),
            _ => Ok(None),
        }
    }

    /// C9, C12: the state ends. The owed record, then `reconciled`, then the clean up, which takes the intent
    /// record.
    fn leave(&mut self) -> Result<Vec<u8>, PepError> {
        let state = self.reconciling.take().expect("only a reconciling PEP leaves the state");
        let event = self.owed_event(&state.owed);
        let record = match self.make_record_about(event, state.owed.cause(), state.owed.subject()) {
            Ok(record) => record,
            Err(error) => {
                self.reconciling = Some(state);
                return Err(error);
            }
        };
        self.audit.append("distribution", "reconciled", vec![("result", json!("reconciled"))])?;
        if !self.locked {
            // a locked PEP read no active record, so what it names and the intent record wait for provisioning
            self.fault(PepStep::Cleanup)?;
            self.cleanup()?;
        }
        Ok(record)
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
    /// held (X7). The state record of a transition, None when nothing changed. A tick is one of the two calls
    /// that try the runtime again (C9), and the one that tries again the failed step of a renewal (C10).
    pub fn tick(&mut self) -> Result<Option<Vec<u8>>, PepError> {
        if self.reconciling.is_some() {
            return self.try_runtime();
        }
        let record = self.check_active()?;
        if self.retry_runtime && self.reconciling.is_none() {
            let retried = match &self.active {
                Some(held) => self.adapter.activate(held),
                None => Ok(()),
            };
            self.retry_runtime = retried.is_err();
        }
        Ok(record)
    }

    /// What every entry point and the periodic tick run first: an active release that no longer stands lapses
    /// with `dist:revoked` (R5), one above the held ceiling with `dist:above-ceiling` (CL3), and an expired one, or one whose freshness ran out (H16), lapses or is held (X1,
    /// X7). A reconciling PEP runs the tests of C10 instead, which try no runtime.
    fn check_active(&mut self) -> Result<Option<Vec<u8>>, PepError> {
        if self.reconciling.is_some() {
            self.run_tests(true)?;
            return self.end_if_switched();
        }
        if self.locked || !self.trust.is_readable() {
            return Ok(None);
        }
        let Some(active) = self.active.clone() else { return Ok(None) };
        if !self.stands(&active, true) {
            return self.lapse_now(REVOKED).map(Some);
        }
        if !self.inside_ceiling(&active) {
            return self.lapse_now(ABOVE_CEILING).map(Some); // CL3: also when a restart came between the two
        }
        if self.still_valid(&active, false).as_deref() != Some(EXPIRED) && !self.stale() {
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

    /// X1, R5: go to `no-policy` with `cause`, durably, and make the runtime run nothing. A reconciling PEP
    /// lapses its held release as C10 does one that fell.
    pub fn lapse(&mut self, cause: &str) -> Result<Vec<u8>, PepError> {
        if self.reconciling.is_none() {
            return self.lapse_now(cause);
        }
        let cause = super::CAUSES.into_iter().find(|known| *known == cause).ok_or_else(|| refused(format!("{cause} is not a cause")))?;
        if !self.locked {
            self.held_falls(cause, true)?;
        }
        match self.end_if_switched()? {
            Some(record) => Ok(record),
            None => self.make_record("beat", None),
        }
    }

    /// C7: the intent record, the audit event, the active record that names no release, the runtime step, the
    /// state record, then the clean up.
    fn lapse_now(&mut self, cause: &str) -> Result<Vec<u8>, PepError> {
        let running = self.active.clone();
        let seq = running.as_ref().map(|release| release.seq);
        self.fault(PepStep::Intent)?;
        self.write_intent("lapse", None, Some(cause), running.as_ref(), false)?;
        self.fault(PepStep::Evidence)?;
        self.audit_lapse(seq, cause, false)?;
        self.fault(PepStep::ActiveRecord)?;
        self.write_active(None, self.previous.as_ref())?;
        self.active = None;
        self.held = false;
        self.retry_runtime = false;
        self.fault(PepStep::Runtime)?;
        self.runtime_step(Owed::Lapsed(cause.to_string()), running)
    }

    /// X7: `held` on every receipt written while the PEP holds an expired release, else None.
    pub fn receipt_mark(&self) -> Option<&'static str> {
        self.held.then_some("held")
    }

    /// One decision through the PEP, after the expiry check (X1). With no active release, locked or reconciling,
    /// it is refused with the cause of X3 or C8 and `under_release` is not called, unless the fallback policy decides
    /// (FB1): the runtime then runs the fallback set, so `under_release` decides under it. No decision tries the
    /// runtime. `decide_request` asks the action floor first.
    pub fn decide<T>(&mut self, under_release: impl FnOnce() -> T) -> Result<Decision<T>, PepError> {
        self.decide_request(None, under_release)
    }

    /// AF1: a PEP that holds an action floor asks it first on `request`, the register file of the request and the
    /// age of each independent register's value, in every state. When the floor allows, nothing else decides, and
    /// `under_release` is not called. Otherwise the decision is made exactly as with no floor (AF2).
    pub fn decide_request<T>(&mut self, request: Option<&Request>, under_release: impl FnOnce() -> T) -> Result<Decision<T>, PepError> {
        self.check_active()?;
        let receipts = self.installed.record.is_some() || self.installed.record_lost;
        if let (Some(request), Some(floor)) = (request, self.installed.held(SetKind::Floor).cloned()) {
            if let Some(answer) = self.floor_answer(&floor, request)? {
                return Ok(Decision {
                    decision: None,
                    cause: Some(FLOOR_ALLOWED), // RC3
                    mark: self.receipt_mark(),
                    basis: Some("floor"),
                    policy_sha256: Some(floor.policy_sha256().clone()),
                    floor: Some(answer),
                });
            }
        }
        let decided = |decision, basis: Option<&'static str>, policy: Option<Hex64>, mark| Decision {
            decision,
            cause: None,
            mark,
            basis,
            policy_sha256: policy,
            floor: None,
        };
        Ok(match self.refusal() {
            Some(_) if self.fallback_decides() => {
                let policy = self.installed.held(SetKind::Fallback).map(|set| set.policy_sha256().clone());
                decided(Some(under_release()), Some("fallback"), policy, None)
            }
            Some(cause) => Decision { decision: None, cause: Some(cause), mark: None, basis: None, policy_sha256: None, floor: None },
            None => {
                let policy = self.active.as_ref().map(|active| active.policy_sha256.clone()).filter(|_| receipts);
                decided(Some(under_release()), receipts.then_some("release"), policy, self.receipt_mark())
            }
        })
    }

    /// AF7: what the active release, or the fallback policy when that decides, answers the request, and the policy
    /// hash of the set it asked. None when no set would have decided.
    fn would(&self, request: &Request) -> Option<(Answer, Hex64)> {
        if self.refusal().is_none() {
            let active = self.active.as_ref()?;
            return Some((floors::ask(active.bodies.get(&ArtifactKind::PolicyPpt)?, request, false, None), active.policy_sha256.clone()));
        }
        if self.fallback_decides() {
            let fallback = self.installed.held(SetKind::Fallback)?;
            let table = fallback.bodies.get(&AsName::Artifact(ArtifactKind::PolicyPpt))?;
            return Some((floors::ask(table, request, false, None), fallback.policy_sha256().clone()));
        }
        None
    }

    /// AF1, AF2, AF7, AF8: the action floor's answer, None when it is silent. A table floor only allows (AF2). The
    /// release or the fallback policy is asked too and its answer is `would`. An override, a floor allow whose
    /// `would` is not an allow, of a rule past the signed `rate` leaves the floor silent, since a `host` floor may
    /// only allow, and the release decides. The count of a counted override, and the counts of floor answers and
    /// overrides of the state record (H10), are durable before the PEP acts.
    fn floor_answer(&mut self, floor: &InstallSet, request: &Request) -> Result<Option<FloorAnswer>, PepError> {
        let Some(table) = floor.bodies.get(&AsName::Artifact(ArtifactKind::PolicyPpt)) else { return Ok(None) };
        let answer = floors::ask(table, request, true, self.adapter.floor_layout().as_deref());
        if !answer.allows() {
            return Ok(None); // AF2: silent
        }
        let rule = answer.rule.clone().unwrap_or_default();
        let would = self.would(request);
        let overrides = !would.as_ref().is_some_and(|(answer, _)| answer.allows());
        let mut counted = None;
        if let (true, Some(rate)) = (overrides, floor.rate()) {
            let mut book = floors::Book::load(self.installed.paths("rates.json"));
            counted = book.spend(&rule, rate, self.time())?;
            if counted.is_none() {
                return Ok(None); // AF8: past the rate the release decides
            }
        }
        if let Some(record) = self.installed.record.clone() {
            let next = Record {
                answers: record.answers.saturating_add(1),
                overrides: record.overrides.saturating_add(u32::from(overrides)),
                ..record
            };
            self.installed.save(next)?;
        }
        let would = would.and_then(|(answer, policy)| answer.outcome.map(|outcome| (outcome, answer.cause, policy)));
        Ok(Some(FloorAnswer { rule, would, overrides, counted }))
    }

    // ------------------------------------------------------------------ RB1, RB2, X9: rollback
    /// Return to the release the active one replaced (RB1), never lowering the floor. Refused while held (X9),
    /// while reconciling (C8), with the cause of the check a commit would fail (RB2), below a floor a revocation
    /// raised, and when the kept release may allow more than the active one without a widening statement that
    /// covers it (RB3).
    pub fn rollback(&mut self) -> Result<Vec<u8>, PepError> {
        self.check_active()?;
        if self.held {
            return self.refuse(HELD, Vec::new());
        }
        if self.locked {
            return self.refuse(FLOOR_LOST, Vec::new());
        }
        if self.reconciling.is_some() {
            return self.refuse(RECONCILING, Vec::new());
        }
        if self.installed.record_lost || self.installed.ceiling_lost {
            return self.refuse(INSTALL_LOST, Vec::new()); // IS10
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
        if cause.is_none() && !self.inside_ceiling(&kept) {
            // CL2: the kept release is dropped
            self.previous = None;
            self.write_active(self.active.as_ref(), None)?;
            self.keep_blobs();
            return self.refuse(ABOVE_CEILING, vec![("seq", json!(kept.seq))]);
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

    /// RB3: a rollback to `kept` falls under W1 to W7 as a release staged against the active one would, by the
    /// rule a commit uses. A release identical to the active one is never larger. On `host` a kept table that is
    /// not the active one is larger (W2), a larger `kept` whose `widens` is false is refused even with a statement
    /// (W6), and otherwise it needs a widening statement that covers the PEP (W4).
    fn covers(&self, kept: &Release) -> bool {
        if self.active.as_ref().is_some_and(|active| active.release == kept.release) {
            return true;
        }
        let statements = (
            kept.bodies.get(&ArtifactKind::TrustWidening).map(Vec::as_slice),
            kept.bodies.get(&ArtifactKind::TrustChange).map(Vec::as_slice),
        );
        self.widening(kept.widens, &kept.replaces, &kept.bodies, statements, true).is_none()
    }

    // ------------------------------------------------------------------ P2, P3, P5: provisioning
    /// P2 step 3: receive a trust anchor and return its fingerprint for the operator to compare. The PEP follows
    /// no stream until `confirm` is given that fingerprint (P2 step 4).
    pub fn provision(&mut self, anchor: &[u8]) -> Result<Hex64, PepError> {
        self.provision_with(anchor, &[])
    }

    /// P2 step 3 with the install statements the engineer brings beside the anchor. An anchor whose keys are not
    /// apart from each other, from the instance key and from what the PEP holds in another role, or whose `domain`
    /// is not the hash of the domain the PEP was built with, is refused and leaves the PEP as it was (K4, P4).
    /// `printed` is what the PEP prints beside the fingerprint: the envelope id of each install statement (IS8).
    pub fn provision_with(&mut self, anchor: &[u8], statements: &[(Vec<u8>, Vec<u8>)]) -> Result<Hex64, PepError> {
        let read = read_anchor(anchor).map_err(|refusal| refused(refusal.to_string()))?;
        if read.target != self.adapter.kind() {
            return Err(refused(format!("the anchor is for a {} PEP, not a {} one", read.target, self.adapter.kind())));
        }
        self.check_separation(&read.store())?;
        self.check_roles(&read)?;
        self.provisioned_record(&read)?; // IS6: refused here, the PEP left as it was
        let mut ids = Vec::new();
        for (sealed, _) in statements {
            let (envelope_bytes, _) = env::unseal(sealed).map_err(|refusal| refused(refusal.to_string()))?;
            ids.push(env::envelope_id(envelope_bytes));
        }
        let pending = PendingInstallDoc {
            encoding: Canon2Tag,
            format: PendingInstallFormat,
            statements: statements.iter().map(|(sealed, body)| (hex::encode(sealed), hex::encode(body))).collect(),
        };
        self.store.write("install.pending", &pending)?;
        self.store.write_bytes("anchor.pending", anchor)?;
        self.printed = ids.clone();
        self.audit.append(
            "distribution",
            "anchor_received",
            vec![
                ("fingerprint", json!(read.fingerprint.as_str())),
                ("install", json!(ids.iter().map(Hex64::as_str).collect::<Vec<_>>())),
                ("result", json!("pending")),
            ],
        )?;
        Ok(read.fingerprint)
    }

    /// IS8, P2 step 4: the envelope ids of the install statements brought with the waiting anchor, which the PEP
    /// prints beside its fingerprint.
    pub fn printed(&self) -> &[Hex64] {
        &self.printed
    }

    /// P2 step 3, P4, K4: no key of the anchor is the instance key or a key the PEP holds in another role or has
    /// retired in any role, its install part's domain is the one the PEP was built with, and an anchor that reaches
    /// a PEP holding an install record is checked against its install and operator keys too.
    fn check_roles(&self, read: &Anchor) -> Result<(), PepError> {
        let held = self.installed.record.as_ref();
        let mut authority: BTreeSet<Hex64> = read.keys.keys().cloned().collect();
        authority.extend(read.controller_id());
        if held.is_some_and(|held| !authority.is_disjoint(&held.ids())) {
            return Err(refused("an anchor key is an install or an operator key the PEP holds or retired (K4)"));
        }
        let Some(part) = &read.install else { return Ok(()) };
        let named: BTreeSet<Hex64> = part.keys.keys().chain(part.operators.keys()).cloned().collect();
        if named.contains(&self.instance_key_id) {
            return Err(refused("an install or operator key of the anchor is the PEP's instance key (K4)"));
        }
        if self.trust.is_readable() && named.iter().any(|kid| self.trust.keys.contains_key(kid) || self.trust.retired.contains(kid)) {
            return Err(refused("an install or operator key of the anchor is a key the trust store holds or retired (K4)"));
        }
        if let Some(held) = held {
            let crossed = part.keys.keys().any(|kid| held.operators.contains_key(kid) || held.retired.contains(kid))
                || part.operators.keys().any(|kid| held.keys.contains_key(kid) || held.retired.contains(kid));
            if crossed {
                return Err(refused("an install or operator key of the anchor is held in another role or retired (K4)"));
            }
        }
        if part.domain != install::domain_sha256(self.adapter.qualification().as_ref()) {
            return Err(refused("the anchor's domain is not the hash of the domain this PEP was built with (P4, CL4)"));
        }
        Ok(())
    }

    /// IS6, P4: the install record a provisioning leaves. An anchor with no install part leaves the held one as it
    /// is. One whose install trust sequence is below the held one is refused, one at the same number brings the same
    /// key set, and one above it may bring another: every key it leaves out is retired, and only a key set that
    /// shares no key with the held one starts the install sequences again and drops the held sets. The install trust
    /// id becomes the anchor's fingerprint.
    fn provisioned_record(&self, read: &Anchor) -> Result<Option<Record>, PepError> {
        let held = self.installed.record.clone();
        let Some(part) = read.install.clone() else { return Ok(held) };
        let part = Record { trust_id: Some(read.fingerprint.clone()), ..part };
        let Some(held) = held else { return Ok(Some(part)) };
        if part.trust_seq < held.trust_seq {
            return Err(refused(format!("{TRUST_REPLAY}: the anchor's install trust sequence is below the PEP's (IS6)")));
        }
        let same = (&part.keys, &part.operators, part.threshold) == (&held.keys, &held.operators, held.threshold);
        if part.trust_seq == held.trust_seq {
            if !same {
                return Err(refused(format!("{TRUST_REPLAY}: an anchor at the held install trust sequence brings another key set (IS6)")));
            }
            return Ok(Some(Record { trust_id: Some(read.fingerprint.clone()), domain: part.domain, ..held }));
        }
        let dropped: Vec<Hex64> =
            held.keys.keys().chain(held.operators.keys()).filter(|kid| !part.keys.contains_key(*kid) && !part.operators.contains_key(*kid)).cloned().collect();
        let mut retired = held.retired.clone();
        let mut sorted = dropped;
        sorted.sort();
        for kid in sorted {
            if !retired.contains(&kid) {
                retired.push(kid);
            }
        }
        let excess = retired.len().saturating_sub(install::MAX_RETIRED);
        retired.drain(..excess);
        let counts = |record: Record| Record { retired: retired.clone(), answers: held.answers, overrides: held.overrides, ..record };
        if part.keys.keys().any(|kid| held.keys.contains_key(kid)) {
            return Ok(Some(counts(Record { seqs: held.seqs, sets: held.sets.clone(), applied: held.applied.clone(), ..part })));
        }
        Ok(Some(counts(part))) // disjoint: the install sequences start again and the held sets go
    }

    /// P2 step 3: every install statement the engineer brings verifies under the install record the provisioning
    /// leaves, before anything changes.
    fn precheck(&self, read: &Anchor, store: &TrustStore, record: Option<&Record>, brought: &[(Vec<u8>, Vec<u8>)]) -> Result<(), PepError> {
        if brought.is_empty() {
            return Ok(());
        }
        let Some(record) = record else { return Err(refused("install statements came with an anchor that holds no install keys")) };
        for (sealed, body) in brought {
            let view = PepView {
                kind: PepKind::try_from(self.adapter.kind()).map_err(refused)?,
                stream: read.stream.clone(),
                floor: Floor::default(),
                active: None,
                staged: None,
                qualification: self.adapter.qualification(),
                body_bound: self.adapter.body_bound(),
                has_clock: self.has_clock,
                instance_key_id: Some(self.instance_key_id.clone()),
                install: Some(InstallView { record: Some(record.clone()), message: false, layout: self.adapter.floor_layout(), ..InstallView::default() }),
            };
            let verdict = verify::verify(sealed, body, store, &view, (self.clock)());
            if !verdict.envelope.as_ref().is_some_and(|envelope| envelope.artifact.is_install()) {
                return Err(refused("only install statements come with an anchor (P2 step 3)"));
            }
            if let Some(cause) = verdict.cause.filter(|cause| ![ABOVE_CEILING, SEQ_REPLAY, INCOMPLETE].contains(&cause.as_str())) {
                return Err(refused(format!("{cause}: an install statement brought with the anchor does not verify")));
            }
        }
        Ok(())
    }

    /// IS13: an install provisioning brings install statements and no anchor, by the channel of P2 step 3. Each is
    /// held to IS5 and IS6 as any install statement is, with no message rule, and reported with the event IS12 gives
    /// its set. The trust store, the floors, the time floor and the PEP's state stay as they were, and a locked PEP
    /// stays locked. It is written to the audit log as a provisioning. Returns the records it made.
    pub fn provision_install(&mut self, statements: &[(Vec<u8>, Vec<u8>)]) -> Result<Vec<Vec<u8>>, PepError> {
        if !self.provisioned || self.installed.record.is_none() {
            return Err(refused("an install provisioning reaches a PEP that holds an install record (IS13)"));
        }
        let sent = self.outbox.len();
        for (sealed, body) in statements {
            self.stage_one(sealed, body, false)?;
        }
        let ids: Vec<String> = self.installed.statement_ids().iter().map(|id| id.to_string()).collect();
        self.audit.append("distribution", "install-provisioned", vec![("install", json!(ids)), ("result", json!("provisioned"))])?;
        Ok(self.outbox[sent..].to_vec())
    }

    /// P2 step 4, P3, P5: the operator confirmed `fingerprint`. The runtime is withdrawn first, and when it does
    /// not withdraw provisioning is refused and nothing changes. Then the trust store, the floor, the time floor,
    /// the epoch id and the kept fresh statement start again from the anchor, whatever was held before, a locked PEP is unlocked, and a reconciling
    /// one leaves the state with its intent record gone and the record it owed not sent.
    pub fn confirm(&mut self, fingerprint: &Hex64) -> Result<Vec<u8>, PepError> {
        let raw = std::fs::read(self.store.path("anchor.pending")).map_err(|_| refused("no anchor is waiting to be confirmed"))?;
        let read = read_anchor(&raw).map_err(|refusal| refused(refusal.to_string()))?;
        if *fingerprint != read.fingerprint {
            return Err(refused("the fingerprint is not the waiting anchor's"));
        }
        let store = read.store();
        self.check_separation(&store)?;
        self.check_roles(&read)?;
        let new_record = self.provisioned_record(&read)?;
        let brought: Vec<(Vec<u8>, Vec<u8>)> = self
            .store
            .read::<PendingInstallDoc>("install.pending")
            .map(|doc| {
                doc.statements
                    .iter()
                    .filter_map(|(sealed, body)| Some((hex::decode(sealed).ok()?, hex::decode(body).ok()?)))
                    .collect()
            })
            .unwrap_or_default();
        self.precheck(&read, &store, new_record.as_ref(), &brought)?;
        // only now, with the new store known to be one and the runtime withdrawn, does anything held go (P5)
        self.adapter
            .deactivate(POLICY_LAPSED)
            .map_err(|error| refused(format!("the runtime does not withdraw, so the PEP is not provisioned over it (P5): {error}")))?;
        // the runtime runs nothing from here, so the PEP holds nothing either, even when a write below fails (X3)
        self.reconciling = None;
        self.retry_runtime = false;
        self.held = false;
        self.active = None;
        self.previous = None;
        self.staged = None;
        for name in ["active.json", "staged.json", "pending.json", "fresh.json"] {
            self.store.remove(name)?;
        }
        // P3, H15, H16
        self.fresh = read.fresh;
        self.kept = None;
        self.epoch = 0;
        self.time_taken = false;
        store.save(&self.trust_path())?;
        self.trust = store;
        self.store.write(
            "floor.json",
            &FloorDoc { encoding: Canon2Tag, format: FloorFormat, ids: SortedSet::default(), seq: 0, stream: read.stream.clone() },
        )?;
        self.store.write("counter.json", &CounterDoc { counter: self.counter, encoding: Canon2Tag, format: CounterFormat })?;
        self.store.write("setting.json", &SettingDoc { encoding: Canon2Tag, expiry: self.expiry_response.clone(), format: SettingFormat })?;
        self.store.write_bytes("anchor.json", &raw)?;
        self.store.remove("anchor.pending")?;
        self.store.remove("install.pending")?;
        self.stream = Some(read.stream.clone());
        self.floor = Floor::default();
        self.locked = false;
        self.provisioned = true;
        self.keep_blobs();
        match new_record {
            None => self.installed.clear()?,
            Some(record) => {
                self.installed.mark(true, false, None)?; // IS9: before the first statement is applied
                // IS10: a lost ceiling stays lost, and marked, while the record keeps the install sequences; only the
                // empty ceiling, which cleared the mark, and a key set that shares no key, which starts them again,
                // leave no ceiling to hold
                let still_lost = self.installed.named_lost(&record);
                self.installed.ceiling_lost = self.installed.ceiling_lost && still_lost;
                let held_ceiling = record.held(SetKind::Ceiling).is_some() || still_lost;
                self.installed.save(record)?;
                self.installed.mark(false, false, Some(held_ceiling))?;
                self.installed.clear_staged()?;
            }
        }
        let sent = self.outbox.len();
        for (sealed, body) in &brought {
            self.stage_one(sealed, body, false)?;
        }
        let applied: Vec<Vec<u8>> = self.outbox.drain(sent..).collect(); // P3: provisioning reports as its own event
        let public = self.instance_public();
        let widened = applied.iter().any(|one| state_record::read(one, &public).is_ok_and(|record| record.event == "install-widened"));
        self.audit.append(
            "distribution",
            "provisioned",
            vec![
                ("fingerprint", json!(read.fingerprint.as_str())),
                ("stream", json!(read.stream.as_str())),
                ("install", json!(self.installed.statement_ids().iter().map(Hex64::as_str).collect::<Vec<_>>())),
                ("result", json!("provisioned")),
            ],
        )?;
        let record = self.make_record("provisioned", widened.then_some(INSTALL_WIDENED))?;
        if self.fallback_decides() {
            if let Err(error) = self.step(&Owed::Nothing) {
                self.enter_reconciling(Owed::Nothing, None, &error.to_string())?; // C6: after the record is durable
            }
        }
        Ok(record)
    }
}

// ------------------------------------------------------------------ the host adapter

/// The `host` adapter: the software tier of `PolicyHost` as a distribution target (section 3). A committed
/// release is installed with `PolicyHost::install_verified`, the commit half `swap` also ends in, and a PEP
/// with no release is `PolicyHost::withdraw`, so the host holds nothing and allows nothing (X3). The adapter's
/// own check is the spiral sidecar: when the `policy.ppt` envelope's `meta.packing` declares one, the release
/// needs a `policy.spiral` whose SHA-256 is the declared `sidecar_sha256` (C2, V11).
///
/// The fallback set is run the same way, in place of a withdrawn release (FB1). `layout` is the layout document the
/// deployment built the host with (AF10), whose labels the action floor is held to; a host with none takes no
/// action floor.
pub struct HostAdapter {
    pub host: PolicyHost,
    pub layout: Option<Vec<u8>>,
}

impl HostAdapter {
    pub fn new(host: PolicyHost) -> HostAdapter {
        HostAdapter { host, layout: None }
    }

    /// A host built with the layout document `layout` (AF10).
    pub fn with_layout(host: PolicyHost, layout: Vec<u8>) -> HostAdapter {
        HostAdapter { host, layout: Some(layout) }
    }
}

fn packing_of(release: &Release) -> Option<Hex64> {
    match release.envelopes.get(&ArtifactKind::PolicyPpt).map(|envelope| envelope.form().artifact_form()) {
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

    fn floor_layout(&self) -> Option<Vec<u8>> {
        self.layout.clone()
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
        let Meta::PolicyPpt(meta) = envelope.form().artifact_form() else {
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
