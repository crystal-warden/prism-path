// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! PolicyHost + AuditLog — the Attested + Audited-and-atomic half (policy_host.py / audit_log.py).
//!
//! The audit log is append-only JSONL whose leaves are sha256 over each event's canonical form, rolled
//! into a Bitcoin-style Merkle root (duplicate-last-if-odd), so a log written by either runtime
//! verifies on the other. An event is written as canon/2 (it names `"encoding": "canon/2"` and its time
//! is the integer `ts_us`, microseconds since the epoch), and its line is its canon/2 bytes; an event
//! without the tag, written before the migration, is hashed over its canon/1 compact bytes
//! (`durable::document_bytes`), so an old log and a root anchored over it still verify.
//! Anti-rollback is the same fsync'd `active_version` file floor (software tier: tamper-EVIDENT
//! through the ledger, not tamper-proof — the eFUSE counter is the hardware follow-on).
//!
//! # The commit protocol
//!
//! A swap that passed every check is committed in the order `policy_host.py` fixes, each step durable
//! (the file and its directory entry fsynced) before the next:
//!
//! 1. the intent record, `<state_dir>/pending_swap`, naming the image hash and version;
//! 2. the version floor, `<state_dir>/active_version`;
//! 3. the audit event, the evidence that the swap was accepted;
//! 4. the new image, `active-<sha256>.ppt`, written beside the one in use and never over it;
//! 5. the active policy record, `active_policy.json`, naming that image in `image_file`: the flip
//!    point, an atomic rename, and then the reference flip in memory, an assignment that cannot fail;
//! 6. every image the record does not name removed, then the intent record removed.
//!
//! A rollback is the same commit with the last-known-good policy as its target: the intent record
//! (marked `"op": "rollback"`), the audit event, the image, the record, the clean up, and no floor step
//! because a rollback never lowers the floor. An audit event that cannot be written is an
//! `AuditWriteError` with nothing flipped.
//!
//! A failure at 1 to 5 returns an error and leaves the previous policy active, because the record still
//! names an image that is still there. A death at any step leaves exactly one policy a restarted host
//! can restore, the previous one up to the record rename and the new one after it. What it leaves
//! behind is an intent record, possibly a floor one step ahead of the last accepted swap, and possibly
//! an image the record does not name, which is never read and is removed by the next commit that
//! finishes. Recovery reads the intent record at the next start and at the next swap: it is written to
//! the log as `swap_incomplete` (`rollback_incomplete` for a rollback), and when the record already
//! names the intended policy the commit is finished. The same image at the same version may commit
//! again although the floor already equals its version. A different version, or a different image at
//! that version, is still refused by the floor. A state directory written with the image called
//! `active.ppt` (a record without `image_file`) is read as it was and moved to the new layout by the
//! next swap or rollback. [`PolicyHost::set_commit_hook`] is the fault injection point the crash tests
//! use: it runs before each step and an error stands for a process that died there.
//!
//! The event line is the event's canon/2 bytes, so the file is byte for byte what Python writes for the
//! same event. The intent record and the active policy record are canon/2 documents too.

use crate::{check_envelope, read_ppt_header, sha256_hex, validate_image, verify_pack};
use prismpath_rs::durable;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Write;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

// ------------------------------------------------------------------------------- errors

/// The audit event could not be persisted. The in memory log was not changed; nothing was committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditWriteError(pub String);

impl std::fmt::Display for AuditWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for AuditWriteError {}

/// Everything a host operation can refuse to do. A swap that is merely rejected is not an error: it is
/// an audited `{"ok": false}` result, unless the caller asked for `strict`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostError {
    /// The audit log could not take an event (`AuditWriteError`).
    Audit(AuditWriteError),
    /// A state file could not be read or written (an `OSError` in the reference).
    Io(String),
    /// The intent record exists and cannot be read (a `RuntimeError` in the reference).
    IntentUnreadable(String),
    /// `swap(.., strict)` was refused; the reasons are those of the audited rejection (`SwapRejected`).
    SwapRejected(Vec<String>),
    /// A verified manifest whose version is not an integer the host can compare.
    BadManifest(String),
    /// A record about to be written has no canonical JSON form (`CanonicalError` in the reference); nothing was written.
    Canonical(String),
    /// Raised by the commit hook before the named step.
    Injected(String),
}

impl HostError {
    /// The class name the host trace corpus records for this error.
    pub fn kind(&self) -> &'static str {
        match self {
            HostError::Audit(_) => "AuditWriteError",
            HostError::Io(_) => "OSError",
            HostError::IntentUnreadable(_) => "IntentUnreadable",
            HostError::SwapRejected(_) => "SwapRejected",
            HostError::BadManifest(_) => "BadManifest",
            HostError::Canonical(_) => "CanonicalError",
            HostError::Injected(_) => "Injected",
        }
    }
}

impl std::fmt::Display for HostError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HostError::Audit(error) => write!(f, "{error}"),
            HostError::Io(text) => write!(f, "{text}"),
            HostError::IntentUnreadable(text) => write!(f, "unreadable intent record {text}"),
            HostError::SwapRejected(reasons) => write!(f, "{}", reasons.join(",")),
            HostError::BadManifest(text) => write!(f, "{text}"),
            HostError::Canonical(text) => write!(f, "{text}"),
            HostError::Injected(step) => write!(f, "injected fault before {step}"),
        }
    }
}

impl std::error::Error for HostError {}

impl From<AuditWriteError> for HostError {
    fn from(error: AuditWriteError) -> HostError {
        HostError::Audit(error)
    }
}

// ----------------------------------------------------------------------------------- clock

/// The two clocks the protocol reads: epoch microseconds for an event's `ts_us`, and the ISO-8601 second a
/// policy has been active `since`. Tests replace them with counters so timestamps are part of the
/// expected bytes.
#[derive(Clone)]
pub struct Clock {
    epoch: Arc<dyn Fn() -> i64 + Send + Sync>,
    iso: Arc<dyn Fn() -> String + Send + Sync>,
}

impl Clock {
    pub fn system() -> Clock {
        Clock { epoch: Arc::new(now_epoch), iso: Arc::new(now_iso) }
    }

    pub fn new(
        epoch: impl Fn() -> i64 + Send + Sync + 'static,
        iso: impl Fn() -> String + Send + Sync + 'static,
    ) -> Clock {
        Clock { epoch: Arc::new(epoch), iso: Arc::new(iso) }
    }
}

fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_micros()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn now_iso() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    iso_from_epoch(secs)
}

/// ISO-8601 UTC to the second, matching Python's `isoformat(timespec="seconds")` + `"+00:00"`.
pub fn iso_from_epoch(secs: u64) -> String {
    let days = secs / 86_400;
    let (hour, minute, second) = ((secs % 86_400) / 3600, (secs % 3600) / 60, secs % 60);
    // civil date from days-since-epoch (Howard Hinnant's algorithm)
    let shifted_days = days as i64 + 719_468;
    let era = shifted_days.div_euclid(146_097);
    let doe = shifted_days.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let mth = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if mth <= 2 { year + 1 } else { year };
    format!("{year:04}-{mth:02}-{day:02}T{hour:02}:{minute:02}:{second:02}+00:00")
}

// -------------------------------------------------------------------- files (canon.py)

fn io_text(path: &str, error: &std::io::Error) -> String {
    format!("{path}: {error}")
}

/// `canon.atomic_write_bytes`: the old file or the new one, never a torn one. Parent created, temp
/// file beside the target, flushed and fsynced, then renamed over it.
fn atomic_write_bytes(path: &str, data: &[u8]) -> Result<(), HostError> {
    let io = |error: std::io::Error| HostError::Io(io_text(path, &error));
    if let Some(dir) = std::path::Path::new(path).parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir).map_err(io)?;
        }
    }
    let tmp = format!("{path}.tmp");
    let mut file = std::fs::File::create(&tmp).map_err(|error| HostError::Io(io_text(&tmp, &error)))?;
    file.write_all(data).map_err(io)?;
    file.flush().map_err(io)?;
    file.sync_all().map_err(io)?;
    drop(file);
    std::fs::rename(&tmp, path).map_err(io)?;
    fsync_parent(path)
}

/// Make a rename or removal in `dir` durable. Windows cannot open a directory, so there it is a no-op.
fn fsync_dir(dir: &str) -> Result<(), HostError> {
    #[cfg(unix)]
    {
        let dir = if dir.is_empty() { "." } else { dir };
        std::fs::File::open(dir).and_then(|handle| handle.sync_all()).map_err(|error| HostError::Io(io_text(dir, &error)))
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

fn fsync_parent(path: &str) -> Result<(), HostError> {
    fsync_dir(&std::path::Path::new(path).parent().map_or_else(String::new, |dir| dir.to_string_lossy().into_owned()))
}

const LEGACY_IMAGE: &str = "active.ppt";

/// The content addressed image a record names: `active-<sha256>.ppt`.
pub fn image_file_name(sha256: &str) -> String {
    format!("active-{sha256}.ppt")
}

fn is_image_file(name: &str) -> bool {
    name.strip_prefix("active-")
        .and_then(|rest| rest.strip_suffix(".ppt"))
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
}

/// An image file, or the temp file of one, that a finished commit removes unless the record names it.
fn is_image_leaving(name: &str) -> bool {
    let name = name.strip_suffix(".tmp").unwrap_or(name);
    name == LEGACY_IMAGE || is_image_file(name)
}

/// `os.path.abspath`: joined to the working directory and normalised lexically, no symlink resolved.
fn abspath(path: &str) -> String {
    use std::path::Component;
    let given = std::path::Path::new(path);
    let joined = if given.is_absolute() {
        given.to_path_buf()
    } else {
        std::env::current_dir().map(|dir| dir.join(given)).unwrap_or_else(|_| given.to_path_buf())
    };
    let mut out = std::path::PathBuf::new();
    for component in joined.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !matches!(out.components().next_back(), None | Some(Component::RootDir)) {
                    out.pop();
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out.to_string_lossy().into_owned()
}

fn errno_text(error: &std::io::Error) -> String {
    error.raw_os_error().map_or_else(|| "None".to_string(), |code| code.to_string())
}

/// Python's `str.strip()`: Unicode white space and the four information separators.
fn py_strip(text: &str) -> &str {
    text.trim_matches(|ch: char| ch.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&ch))
}

/// `int(text.strip() or "0")` for the digits a version file can hold, or `None` where Python raises
/// `ValueError`. A value beyond 128 bits saturates, so a floor too large to compare refuses everything
/// instead of nothing.
fn py_int(text: &str) -> Option<i128> {
    let stripped = py_strip(text);
    if stripped.is_empty() {
        return Some(0);
    }
    let (negative, digits) = match stripped.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, stripped.strip_prefix('+').unwrap_or(stripped)),
    };
    if digits.is_empty() || digits.starts_with('_') || digits.ends_with('_') || digits.contains("__") {
        return None;
    }
    let mut value: i128 = 0;
    for ch in digits.chars().filter(|ch| *ch != '_') {
        let digit = ch.to_digit(10)?;
        value = value.saturating_mul(10).saturating_add(i128::from(digit));
    }
    Some(if negative { -value } else { value })
}

// -------------------------------------------------------------------- Merkle (ledger_ots.py)

fn digest_bytes(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

/// One step of an inclusion path: the side the sibling is on (`'R'` or `'L'`) and its hash in hex.
pub type ProofStep = (char, String);

/// Bitcoin-style Merkle root over hex leaves (duplicate last if odd). None for an empty list.
pub fn merkle_root(leaves_hex: &[String]) -> Option<String> {
    merkle_root_and_paths(leaves_hex).0
}

/// `ledger_ots.merkle_root_and_paths`: the root and an inclusion path for every leaf.
pub fn merkle_root_and_paths(leaves_hex: &[String]) -> (Option<String>, Vec<Vec<ProofStep>>) {
    if leaves_hex.is_empty() {
        return (None, Vec::new());
    }
    let mut layers: Vec<Vec<Vec<u8>>> =
        vec![leaves_hex.iter().map(|leaf| hex::decode(leaf).unwrap_or_default()).collect()];
    while layers.last().expect("non-empty").len() > 1 {
        let mut current = layers.last().expect("non-empty").clone();
        if current.len() % 2 == 1 {
            current.push(current.last().expect("non-empty").clone());
        }
        let next = current.chunks(2).map(|pair| digest_bytes(&[pair[0].as_slice(), pair[1].as_slice()].concat())).collect();
        layers.push(next);
    }
    let root = hex::encode(&layers.last().expect("non-empty")[0]);
    let paths = (0..leaves_hex.len())
        .map(|leaf_index| {
            let mut index = leaf_index;
            let mut path = Vec::new();
            for layer_ref in &layers[..layers.len() - 1] {
                let mut layer = layer_ref.clone();
                if layer.len() % 2 == 1 {
                    layer.push(layer.last().expect("non-empty").clone());
                }
                if index % 2 == 0 {
                    path.push(('R', hex::encode(&layer[index + 1])));
                } else {
                    path.push(('L', hex::encode(&layer[index - 1])));
                }
                index /= 2;
            }
            path
        })
        .collect();
    (Some(root), paths)
}

/// `ledger_ots.verify_leaf`: fold the path over the leaf and compare with the root.
pub fn verify_leaf(leaf_hex: &str, path: &[ProofStep], root_hex: &str) -> bool {
    let Ok(mut current) = hex::decode(leaf_hex) else { return false };
    for (side, sibling_hex) in path {
        let Ok(sibling) = hex::decode(sibling_hex) else { return false };
        current = if *side == 'R' {
            digest_bytes(&[current.as_slice(), sibling.as_slice()].concat())
        } else {
            digest_bytes(&[sibling.as_slice(), current.as_slice()].concat())
        };
    }
    hex::encode(current) == root_hex
}

/// `audit_log.verify`: a leaf's inclusion against a root. An empty root verifies nothing.
pub fn verify(leaf: &str, proof: &[ProofStep], root: &str) -> bool {
    !root.is_empty() && verify_leaf(leaf, proof, root)
}

/// `AuditLog.prove`'s result: `{"path": [...], "peaks": [root]}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    pub path: Vec<ProofStep>,
    pub peaks: Vec<String>,
}

impl Proof {
    pub fn to_value(&self) -> Value {
        json!({
            "path": self.path.iter().map(|(side, hash)| json!([side.to_string(), hash])).collect::<Vec<_>>(),
            "peaks": self.peaks,
        })
    }
}

// ------------------------------------------------------------------------------ AuditLog

/// The data of one event in insertion order, which is the order the line is written in.
pub type Fields = Vec<(&'static str, Value)>;

struct AuditState {
    events: Vec<Value>,
    leaves: Vec<String>,
    skipped: Vec<usize>,
}

/// Append-only JSONL audit log with Merkle-leaf commitment per event. `append` persists the event and
/// only then commits it to the tree, so an event the file does not hold never has a leaf.
pub struct AuditLog {
    pub path: String,
    state: Mutex<AuditState>,
    clock: Clock,
}

/// A record the host writes and later reads back: tagged canon/2 and written as its canon/2 bytes, refused
/// with nothing written when it has no canon/2 form (a float, an integer beyond plus or minus 2^53 minus
/// 1), as `canon.canon2_bytes` refuses it in Python.
fn canonical_record(record: &Value) -> Result<Vec<u8>, HostError> {
    durable::canon2_bytes(&durable::tagged(record.clone())).map_err(|error| HostError::Canonical(error.to_string()))
}

/// Every event reaching here was read by `durable::read_document` or was built by `append` from canon/2
/// checked parts, so it has a form under the encoding it names.
fn leaf_hex(ev: &Value) -> String {
    hex::encode(Sha256::digest(durable::document_bytes(ev).expect("an event read or built under its encoding")))
}

/// The lines of a text file the way Python's universal newline iteration yields them.
fn python_lines(text: &str) -> Vec<String> {
    text.replace("\r\n", "\n").replace('\r', "\n").split('\n').map(str::to_string).collect()
}

impl AuditLog {
    pub fn open(path: &str) -> Result<AuditLog, HostError> {
        AuditLog::open_with(path, Clock::system())
    }

    /// Read the log at `path` (empty path or no file: an empty log). A line that is not JSON is not
    /// an event: its number is recorded in `skipped` and the log no longer verifies. A file that
    /// cannot be read, or is not UTF-8, is an error, as in the reference.
    pub fn open_with(path: &str, clock: Clock) -> Result<AuditLog, HostError> {
        let mut state = AuditState { events: Vec::new(), leaves: Vec::new(), skipped: Vec::new() };
        if !path.is_empty() && std::path::Path::new(path).exists() {
            let bytes = std::fs::read(path).map_err(|error| HostError::Io(io_text(path, &error)))?;
            let text = String::from_utf8(bytes)
                .map_err(|error| HostError::Io(format!("{path}: not valid UTF-8: {error}")))?;
            for (offset, raw) in python_lines(&text).iter().enumerate() {
                let line = py_strip(raw);
                if line.is_empty() {
                    continue;
                }
                match durable::read_document(line) {
                    Ok(event) => {
                        state.leaves.push(leaf_hex(&event));
                        state.events.push(event);
                    }
                    Err(_) => state.skipped.push(offset + 1),
                }
            }
        }
        Ok(AuditLog { path: path.to_string(), state: Mutex::new(state), clock })
    }

    pub fn events(&self) -> Vec<Value> {
        locked(&self.state).events.clone()
    }

    pub fn leaves(&self) -> Vec<String> {
        locked(&self.state).leaves.clone()
    }

    /// Line numbers of the lines that were not events.
    pub fn skipped(&self) -> Vec<usize> {
        locked(&self.state).skipped.clone()
    }

    /// Persist the event, then commit it to the tree. Returns `AuditWriteError`, with the log
    /// unchanged, when the file cannot take it. The line is flushed and fsynced before the leaf exists.
    pub fn append(&self, actor: &str, action: &str, data: Fields) -> Result<Value, AuditWriteError> {
        let mut state = locked(&self.state);
        let index = state.events.len();
        let ts_us = (self.clock.epoch)();
        let mut data_map = Map::new();
        for (key, value) in &data {
            data_map.insert((*key).to_string(), value.clone());
        }
        let event = json!({
            "idx": index, "id": index.to_string(), "ts_us": ts_us,
            "actor": actor, "action": action, "data": Value::Object(data_map), "encoding": durable::CANON2,
        });
        // canon/2: a float, an out of range integer or nesting too deep is refused before anything is written
        let mut line = durable::canon2_bytes(&event)
            .map_err(|error| AuditWriteError(format!("audit event has no canonical JSON form: {error}")))?;
        let leaf = hex::encode(Sha256::digest(&line));
        line.push(b'\n');
        if !self.path.is_empty() {
            let failed = |error: std::io::Error| {
                AuditWriteError(format!("audit event not persisted to {}: {error}", self.path))
            };
            let absolute = abspath(&self.path);
            if let Some(dir) = std::path::Path::new(&absolute).parent() {
                std::fs::create_dir_all(dir).map_err(failed)?;
            }
            let mut file = std::fs::OpenOptions::new().create(true).append(true).open(&self.path).map_err(failed)?;
            file.write_all(&line).map_err(failed)?;
            file.flush().map_err(failed)?;
            file.sync_all().map_err(failed)?;
        }
        state.leaves.push(leaf);
        state.events.push(event.clone());
        Ok(event)
    }

    /// True when the file holds exactly the events in memory, line for line. A log with no path is
    /// never persisted and answers false, so an in memory log cannot be mistaken for evidence. A file
    /// that cannot be read, or is not UTF-8, is an error and not a false, as in the reference.
    pub fn verify_persisted(&self) -> Result<bool, HostError> {
        if self.path.is_empty() || !std::path::Path::new(&self.path).exists() {
            return Ok(false);
        }
        let state = locked(&self.state);
        let bytes = std::fs::read(&self.path).map_err(|error| HostError::Io(io_text(&self.path, &error)))?;
        let text = String::from_utf8(bytes)
            .map_err(|error| HostError::Io(format!("{}: not valid UTF-8: {error}", self.path)))?;
        let mut on_disk = Vec::new();
        for raw in python_lines(&text) {
            let line = py_strip(&raw);
            if line.is_empty() {
                continue;
            }
            match durable::read_document(line) {
                Ok(event) => on_disk.push(leaf_hex(&event)),
                Err(_) => return Ok(false),
            }
        }
        Ok(on_disk == state.leaves)
    }

    /// The Merkle root over all event leaves (hex); empty string for an empty log.
    pub fn current_root(&self) -> String {
        merkle_root(&locked(&self.state).leaves).unwrap_or_default()
    }

    /// Every leaf's inclusion proof verifies against the current root: structural integrity of what
    /// is in memory, and nothing about the file. A log with a line that was not an event does not
    /// verify. `verify_persisted` answers the persistence question.
    pub fn verify_log(&self) -> bool {
        let state = locked(&self.state);
        if !state.skipped.is_empty() {
            return false;
        }
        if state.leaves.is_empty() {
            return true;
        }
        let (root, paths) = merkle_root_and_paths(&state.leaves);
        let root = root.unwrap_or_default();
        state.leaves.iter().zip(&paths).all(|(leaf, path)| verify_leaf(leaf, path, &root))
    }

    /// Inclusion proof for event `leaf_index`; `None` when the index is out of range (an `IndexError`).
    pub fn prove(&self, leaf_index: i64) -> Option<Proof> {
        let state = locked(&self.state);
        let (root, mut paths) = merkle_root_and_paths(&state.leaves);
        let index = usize::try_from(leaf_index).ok().filter(|index| *index < paths.len())?;
        Some(Proof { path: paths.swap_remove(index), peaks: root.into_iter().collect() })
    }
}

// ---------------------------------------------------------------------------- PolicyHost

/// The policy a host holds: the record `active_policy.json` carries, and the image it names.
#[derive(Debug, Clone)]
pub struct ActivePolicy {
    pub record: Map<String, Value>,
    pub image: Vec<u8>,
}

impl ActivePolicy {
    fn field(&self, name: &str) -> Value {
        self.record.get(name).cloned().unwrap_or(Value::Null)
    }

    pub fn sha256(&self) -> Option<String> {
        self.record.get("sha256").and_then(|value| value.as_str()).map(str::to_string)
    }
}

/// A step of the commit protocol, in the order they run. The commit hook sees each one before it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitStep {
    Intent,
    Floor,
    Evidence,
    ActiveImage,
    ActiveRecord,
    Clear,
}

impl CommitStep {
    pub const ALL: [CommitStep; 6] = [
        CommitStep::Intent,
        CommitStep::Floor,
        CommitStep::Evidence,
        CommitStep::ActiveImage,
        CommitStep::ActiveRecord,
        CommitStep::Clear,
    ];

    pub fn name(self) -> &'static str {
        match self {
            CommitStep::Intent => "intent",
            CommitStep::Floor => "floor",
            CommitStep::Evidence => "evidence",
            CommitStep::ActiveImage => "active_image",
            CommitStep::ActiveRecord => "active_record",
            CommitStep::Clear => "clear",
        }
    }

    pub fn from_name(name: &str) -> Option<CommitStep> {
        CommitStep::ALL.into_iter().find(|step| step.name() == name)
    }
}

/// Runs before a commit step; an `Err` stops the commit there, as a process dying there would.
pub type CommitHook = Box<dyn Fn(CommitStep) -> Result<(), String> + Send + Sync>;

struct HostState {
    active: Option<ActivePolicy>,
    /// The file the record names for the active policy, `active.ppt` in the old layout.
    active_file: String,
    prev: Option<ActivePolicy>,
    recovery_recorded: bool,
}

/// Holds the single active policy; `swap` runs signature -> envelope -> monotonic-version ->
/// shadow-stage -> commit -> single atomic reference flip, auditing every attempt. The state is behind
/// one lock, held for the whole of `swap` and `rollback`, so a host can be shared between threads.
pub struct PolicyHost {
    pub state_dir: String,
    pub pubkey_paths: Vec<String>,
    pub envelope: Value,
    pub revoked: Vec<String>,
    pub audit: AuditLog,
    clock: Clock,
    state: Mutex<HostState>,
    hook: Mutex<Option<CommitHook>>,
    version_path: String,
}

impl PolicyHost {
    pub fn new(
        state_dir: &str,
        pubkey_paths: Vec<String>,
        envelope: Value,
        revoked: Vec<String>,
    ) -> Result<PolicyHost, HostError> {
        PolicyHost::new_with(state_dir, pubkey_paths, envelope, revoked, None, Clock::system())
    }

    /// A host over `state_dir`: records an interrupted commit it finds there, then restores the policy
    /// the last accepted swap committed (or records `active_unreadable` and holds none).
    pub fn new_with(
        state_dir: &str,
        pubkey_paths: Vec<String>,
        envelope: Value,
        revoked: Vec<String>,
        audit_path: Option<&str>,
        clock: Clock,
    ) -> Result<PolicyHost, HostError> {
        std::fs::create_dir_all(state_dir).map_err(|error| HostError::Io(io_text(state_dir, &error)))?;
        let audit_file = audit_path.map_or_else(|| format!("{state_dir}/swaps.log"), str::to_string);
        let host = PolicyHost {
            state_dir: state_dir.to_string(),
            pubkey_paths,
            envelope,
            revoked,
            audit: AuditLog::open_with(&audit_file, clock.clone())?,
            clock,
            state: Mutex::new(HostState { active: None, active_file: LEGACY_IMAGE.to_string(), prev: None, recovery_recorded: false }),
            hook: Mutex::new(None),
            version_path: format!("{state_dir}/active_version"),
        };
        {
            let mut state = locked(&host.state);
            let pending = host.recover(&mut state)?;
            host.load_active(&mut state)?;
            host.complete_recovery(&state, pending.as_ref());
        }
        Ok(host)
    }

    /// Install (or clear) the fault injection point. See the module note.
    pub fn set_commit_hook(&self, hook: Option<CommitHook>) {
        *locked(&self.hook) = hook;
    }

    fn fault(&self, step: CommitStep) -> Result<(), HostError> {
        match locked(&self.hook).as_ref() {
            Some(hook) => hook(step).map_err(|_| HostError::Injected(step.name().to_string())),
            None => Ok(()),
        }
    }

    // -- persisted monotonic version (anti-rollback floor) --
    fn stored_version(&self) -> Result<i128, HostError> {
        match std::fs::read(&self.version_path) {
            Ok(bytes) => Ok(String::from_utf8(bytes).ok().and_then(|text| py_int(&text)).unwrap_or(0)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(error) => Err(HostError::Io(io_text(&self.version_path, &error))),
        }
    }

    fn persist_version(&self, version: i64) -> Result<(), HostError> {
        atomic_write_bytes(&self.version_path, version.to_string().as_bytes())
    }

    // -- the intent record --
    fn pending_path(&self) -> String {
        format!("{}/pending_swap", self.state_dir)
    }

    fn read_pending(&self) -> Result<Option<Value>, HostError> {
        let path = self.pending_path();
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(HostError::IntentUnreadable(format!("{path}: {error}"))),
        };
        let text = String::from_utf8(bytes).map_err(|error| HostError::IntentUnreadable(format!("{path}: {error}")))?;
        let pending: Value =
            durable::read_document(&text).map_err(|error| HostError::IntentUnreadable(format!("{path}: {error}")))?;
        if !pending.is_object() {
            return Err(HostError::IntentUnreadable(format!("{path}: not an object")));
        }
        Ok(Some(pending))
    }

    fn write_pending(&self, to_hash: &str, version: &Value, op: Option<&str>) -> Result<(), HostError> {
        let mut record = json!({"to_hash": to_hash, "version": version});
        if let Some(op) = op {
            record["op"] = json!(op);
        }
        let bytes = canonical_record(&record)?;
        atomic_write_bytes(&self.pending_path(), &bytes)
    }

    fn clear_pending(&self) -> Result<(), HostError> {
        let path = self.pending_path();
        match std::fs::remove_file(&path) {
            Ok(()) => fsync_dir(&self.state_dir),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(HostError::Io(io_text(&path, &error))),
        }
    }

    /// Record an interrupted commit, once per process, and return its intent so the floor check can
    /// let the same swap complete. The audit append may itself fail; then the error propagates and
    /// nothing else happens, the fail closed answer when evidence cannot be recorded.
    fn recover(&self, state: &mut HostState) -> Result<Option<Value>, HostError> {
        let pending = self.read_pending()?;
        if let Some(record) = pending.as_ref() {
            if !state.recovery_recorded {
                let stored = self.stored_version()?;
                let action = if record.get("op") == Some(&json!("rollback")) { "rollback_incomplete" } else { "swap_incomplete" };
                self.audit.append(
                    "policy_host",
                    action,
                    vec![
                        ("to_hash", record.get("to_hash").cloned().unwrap_or(Value::Null)),
                        ("version", record.get("version").cloned().unwrap_or(Value::Null)),
                        ("stored_version", number_of(stored)),
                        ("result", json!("incomplete")),
                    ],
                )?;
                state.recovery_recorded = true;
            }
        }
        Ok(pending)
    }

    // -- the active policy record: what a fresh host over this state directory restores --
    fn active_record_path(&self) -> String {
        format!("{}/active_policy.json", self.state_dir)
    }

    /// The image under its own name, then the record naming it, each durable before the next. The
    /// image of the policy in use is never written over, and an image already there under the new name
    /// is written again whatever it holds, so a leftover is never trusted. Returns the file name.
    fn persist_active(&self, policy: &ActivePolicy) -> Result<String, HostError> {
        let name = image_file_name(&policy.sha256().unwrap_or_default());
        self.fault(CommitStep::ActiveImage)?;
        atomic_write_bytes(&format!("{}/{name}", self.state_dir), &policy.image)?;
        self.fault(CommitStep::ActiveRecord)?;
        let mut record = policy.record.clone();
        record.insert("image_file".into(), json!(name));
        let bytes = canonical_record(&Value::Object(record))?;
        atomic_write_bytes(&self.active_record_path(), &bytes)?;
        Ok(name)
    }

    /// After the record is durable: remove every image the record does not name (the superseded one,
    /// a leftover of a dead commit, the image of the old layout), then the intent record. A removal
    /// that fails only leaves a file nothing reads.
    fn finish_commit(&self, keep: &str) -> Result<(), HostError> {
        let leavings: Vec<String> = std::fs::read_dir(&self.state_dir)
            .map(|entries| {
                entries
                    .filter_map(|entry| entry.ok().map(|entry| entry.file_name().to_string_lossy().into_owned()))
                    .filter(|name| name != keep && is_image_leaving(name))
                    .collect()
            })
            .unwrap_or_default();
        let mut removed = false;
        for name in &leavings {
            removed |= std::fs::remove_file(format!("{}/{name}", self.state_dir)).is_ok();
        }
        if removed {
            let _ = fsync_dir(&self.state_dir);
        }
        self.fault(CommitStep::Clear)?;
        self.clear_pending()
    }

    /// A commit that died after the record flip, before its clean up, is finished: the record names the
    /// intended policy, so the superseded images and the intent record are removed. A commit that died
    /// before the flip is left as it is; the old policy is active and the retry completes it. Clean up
    /// that fails is left for the next start.
    fn complete_recovery(&self, state: &HostState, pending: Option<&Value>) {
        let (Some(pending), Some(active)) = (pending, state.active.as_ref()) else { return };
        if Some(&active.field("sha256")) == pending.get("to_hash") && Some(&active.field("version")) == pending.get("version") {
            let _ = self.finish_commit(&state.active_file);
        }
    }

    fn unreadable(&self, fields: Fields) -> Result<(), HostError> {
        self.audit.append("policy_host", "active_unreadable", fields)?;
        Ok(())
    }

    /// Restore the policy a previous process committed. Nothing on disk means nothing active. A record
    /// whose image is missing, unreadable or of another digest is not restored, and the ledger says so;
    /// the host then holds no active policy, the fail closed answer.
    fn load_active(&self, state: &mut HostState) -> Result<(), HostError> {
        let record_path = self.active_record_path();
        let text = match std::fs::read(&record_path) {
            Ok(bytes) => String::from_utf8(bytes).map_err(|error| error.to_string()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => Err(error.to_string()),
        };
        let parsed = text.and_then(|text| durable::read_document(&text).map_err(|error| error.to_string()));
        let record = match parsed {
            Ok(Value::Object(mut record)) => {
                // the tag says how the record was read, not what is active
                record.remove(durable::ENCODING_KEY);
                record
            }
            Ok(_) => {
                return self.unreadable(vec![("reason", json!("record:not-an-object")), ("result", json!("not_restored"))]);
            }
            Err(error) => {
                return self.unreadable(vec![
                    ("reason", json!(format!("record:unreadable:{error}"))),
                    ("result", json!("not_restored")),
                ]);
            }
        };
        let to_hash = record.get("sha256").cloned().unwrap_or(Value::Null);
        // A record without `image_file` is the old layout, whose image is `active.ppt`.
        let name = match record.get("image_file") {
            None => LEGACY_IMAGE.to_string(),
            Some(Value::String(name)) if name == LEGACY_IMAGE || is_image_file(name) => name.clone(),
            Some(_) => {
                return self.unreadable(vec![
                    ("to_hash", to_hash),
                    ("reason", json!("record:image-file-invalid")),
                    ("result", json!("not_restored")),
                ]);
            }
        };
        let image = match std::fs::read(format!("{}/{name}", self.state_dir)) {
            Ok(image) => image,
            Err(error) => {
                return self.unreadable(vec![
                    ("to_hash", to_hash),
                    ("reason", json!(format!("image:unreadable:{}", errno_text(&error)))),
                    ("result", json!("not_restored")),
                ]);
            }
        };
        if Some(&Value::String(sha256_hex(&image))) != record.get("sha256") {
            return self.unreadable(vec![
                ("to_hash", to_hash),
                ("reason", json!("image:digest-mismatch")),
                ("result", json!("not_restored")),
            ]);
        }
        state.active = Some(ActivePolicy { record, image });
        state.active_file = name;
        Ok(())
    }

    fn reject(
        &self,
        state: &HostState,
        to_hash: Option<&str>,
        version: Value,
        reasons: Vec<String>,
        strict: bool,
    ) -> Result<Value, HostError> {
        self.audit.append(
            "policy_host",
            "swap_rejected",
            vec![
                ("from_hash", state.active.as_ref().and_then(ActivePolicy::sha256).map_or(Value::Null, Value::String)),
                ("to_hash", to_hash.map_or(Value::Null, |hash| json!(hash))),
                ("version", version),
                ("reasons", json!(reasons)),
                ("result", json!("rejected")),
            ],
        )?;
        if strict {
            return Err(HostError::SwapRejected(reasons));
        }
        Ok(json!({"ok": false, "reasons": reasons}))
    }

    /// Verify -> envelope -> version -> stage -> commit -> flip. The active policy only changes on
    /// full success; every outcome is one audit event.
    pub fn swap(&self, ppt_path: &str, allow_unsigned: bool) -> Result<Value, HostError> {
        self.swap_with(ppt_path, allow_unsigned, false)
    }

    /// `swap` with the reference's `strict` flag: a refusal is audited and then returned as
    /// `HostError::SwapRejected`.
    pub fn swap_with(&self, ppt_path: &str, allow_unsigned: bool, strict: bool) -> Result<Value, HostError> {
        let mut state = locked(&self.state);
        let pending = self.recover(&mut state)?;
        let image = match std::fs::read(ppt_path) {
            Ok(bytes) => bytes,
            Err(error) => {
                let reason = format!("image:unreadable:{}", errno_text(&error));
                return self.reject(&state, None, Value::Null, vec![reason], strict);
            }
        };
        let to_hash = sha256_hex(&image);

        let manifest: Value;
        let mut floor_version: Option<i64> = None;
        if allow_unsigned {
            let caps: Option<BTreeMap<String, u64>> =
                self.envelope.get("caps").and_then(|caps_value| caps_value.as_object()).map(|caps_object| {
                    caps_object.iter().filter_map(|(name, value)| value.as_u64().map(|limit| (name.clone(), limit))).collect()
                });
            let (ok, reasons) = validate_image(&image, caps.as_ref());
            if !ok {
                return self.reject(&state, Some(&to_hash), Value::Null, reasons, strict);
            }
            manifest = json!({"image_sha256": to_hash, "version": null, "key_id": null,
                              "envelope_id": self.envelope.get("envelope_id"), "unsigned": true});
        } else {
            let (ok, reasons, verified) = verify_pack(ppt_path, &self.pubkey_paths, &self.revoked);
            if !ok {
                return self.reject(&state, Some(&to_hash), Value::Null, reasons, strict);
            }
            let verified = verified.expect("ok verify has a manifest");
            let (ok, reasons) = check_envelope(&verified, &image, &self.envelope);
            if !ok {
                let version = verified.get("version").cloned().unwrap_or(Value::Null);
                return self.reject(&state, Some(&to_hash), version, reasons, strict);
            }
            let version = verified.get("version").and_then(Value::as_i64).ok_or_else(|| {
                HostError::BadManifest("the verified manifest's version is not an integer".to_string())
            })?;
            let stored = self.stored_version()?;
            // The floor admits one exception: the very swap an interrupted commit had already
            // advanced the floor for, identified by both its version and its image hash.
            let resuming = pending.as_ref().is_some_and(|record| {
                record.get("op") != Some(&json!("rollback")) && record.get("version") == Some(&json!(version)) && record.get("to_hash") == Some(&json!(to_hash))
            });
            let version_wide = i128::from(version);
            if version_wide < stored || (version_wide == stored && !resuming) {
                return self.reject(
                    &state,
                    Some(&to_hash),
                    json!(version),
                    vec![format!("version:not-monotonic:{version}<={stored}")],
                    strict,
                );
            }
            floor_version = Some(version);
            manifest = verified;
        }

        // stage a shadow: fully parse the image into its views before any flip
        let staged = match read_ppt_header(&image) {
            Ok(header) => header,
            Err(error) => {
                let version = manifest.get("version").cloned().unwrap_or(Value::Null);
                return self.reject(&state, Some(&to_hash), version, vec![error], strict);
            }
        };

        let manifest_field = |name: &str| manifest.get(name).cloned().unwrap_or(Value::Null);
        let unsigned = manifest.get("unsigned").and_then(Value::as_bool).unwrap_or(false);
        let mut record = Map::new();
        record.insert("sha256".into(), json!(to_hash));
        record.insert("version".into(), manifest_field("version"));
        record.insert("key_id".into(), manifest_field("key_id"));
        record.insert("envelope_id".into(), manifest_field("envelope_id"));
        record.insert("unsigned".into(), json!(unsigned));
        record.insert("overlay_of".into(), manifest_field("overlay_of"));
        record.insert("counts".into(), staged.to_value());
        record.insert("since".into(), json!((self.clock.iso)()));
        record.insert("ppt_path".into(), json!(abspath(ppt_path)));
        let new_active = ActivePolicy { record, image };

        // commit: intent, floor, evidence, image, record and flip, clean up; see the module note
        self.fault(CommitStep::Intent)?;
        self.write_pending(&to_hash, &manifest_field("version"), None)?;
        if let Some(version) = floor_version {
            self.fault(CommitStep::Floor)?;
            self.persist_version(version)?;
        }
        self.fault(CommitStep::Evidence)?;
        self.audit.append(
            "policy_host",
            "swap",
            vec![
                ("from_hash", state.active.as_ref().and_then(ActivePolicy::sha256).map_or(Value::Null, Value::String)),
                ("to_hash", json!(to_hash)),
                ("version", manifest_field("version")),
                ("key_id", manifest_field("key_id")),
                ("envelope_id", manifest_field("envelope_id")),
                ("unsigned", json!(unsigned)),
                ("overlay_of", manifest_field("overlay_of")),
                ("result", json!("accepted")),
            ],
        )?;
        let file = self.persist_active(&new_active)?;
        state.prev = state.active.replace(new_active);
        state.active_file = file;
        self.finish_commit(&state.active_file)?;
        let mut out = active_value(state.active.as_ref());
        out["ok"] = Value::Bool(true);
        Ok(out)
    }

    pub fn active_info(&self) -> Value {
        active_value(locked(&self.state).active.as_ref())
    }

    /// Restore the last-known-good policy (one deep). Committed in the swap's order, intent then
    /// evidence then the image and the record, so an event that cannot be written is an
    /// `AuditWriteError` with the previous policy still active and nothing flipped. Does NOT lower the
    /// version floor (anti-rollback still holds against replayed old packs).
    pub fn rollback(&self) -> Result<Value, HostError> {
        let mut state = locked(&self.state);
        self.recover(&mut state)?;
        let Some(target) = state.prev.clone() else {
            return Ok(json!({"ok": false, "reasons": ["rollback:no-previous"]}));
        };
        let (to_hash, version) = (target.field("sha256"), target.field("version"));
        self.fault(CommitStep::Intent)?;
        self.write_pending(target.sha256().as_deref().unwrap_or_default(), &version, Some("rollback"))?;
        self.fault(CommitStep::Evidence)?;
        self.audit.append(
            "policy_host",
            "rollback",
            vec![("to_hash", to_hash), ("version", version), ("result", json!("rolled_back"))],
        )?;
        let file = self.persist_active(&target)?;
        state.active = Some(target);
        state.prev = None;
        state.active_file = file;
        self.finish_commit(&state.active_file)?;
        let mut out = active_value(state.active.as_ref());
        out["ok"] = Value::Bool(true);
        Ok(out)
    }

    /// Append a point-in-time attestation of the active policy to the ledger.
    pub fn attest(&self) -> Result<Value, HostError> {
        let active = self.active_info();
        self.audit.append(
            "policy_host",
            "attestation",
            vec![
                ("active", active.get("active").cloned().unwrap_or(Value::Null)),
                ("version", active.get("version").cloned().unwrap_or(Value::Null)),
                ("overlay_of", active.get("overlay_of").cloned().unwrap_or(Value::Null)),
                ("ts", json!((self.clock.iso)())),
            ],
        )?;
        Ok(active)
    }

    /// The swap/attestation timeline, oldest first.
    pub fn history(&self) -> Vec<Value> {
        self.audit.events()
    }
}

fn number_of(value: i128) -> Value {
    i64::try_from(value).map_or_else(|_| json!(value.to_string()), |small| json!(small))
}

fn active_value(active: Option<&ActivePolicy>) -> Value {
    match active {
        None => json!({"active": null}),
        Some(policy) => json!({
            "active": policy.field("sha256"), "version": policy.field("version"), "since": policy.field("since"),
            "unsigned": policy.field("unsigned"), "envelope_id": policy.field("envelope_id"),
            "overlay_of": policy.field("overlay_of"),
        }),
    }
}
