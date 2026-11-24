// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! What the Rust enforcement point tests share, `prismpath/tests/_dist.py` in Rust: the corpus generator's
//! fixed keys, times and image, read from the shipped corpus so nothing here runs the generator, a signer that
//! seals releases and trust statements, and a provisioned host PEP over a scratch directory.
#![allow(dead_code)]

use super::common::Scratch;
use ed25519_dalek::SigningKey;
use prismpath_hotswap_rs::dist::envelope::{self as env, EnvelopeDoc};
use prismpath_hotswap_rs::dist::pep::{HostAdapter, Pep, PepError, REFUSE};
use prismpath_hotswap_rs::dist::state_record::{self, StateRecord};
use prismpath_hotswap_rs::dist::trust::{anchor_bytes, Role};
use prismpath_hotswap_rs::dist::{ArtifactKind, Canon2Tag, DistFormat, Hex64, MaybeHex64, Stream, TargetKind};
use prismpath_hotswap_rs::host::PolicyHost;
use prismpath_rs::canon2;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::OnceLock;

pub const STREAM: &str = "host/demo";
pub const NOT_BEFORE: i64 = 1_800_000_000;
pub const EXPIRES: i64 = NOT_BEFORE + 30 * 86400;
pub const NOW: i64 = NOT_BEFORE + 3600;
/// The byte of the corpus image `when x >= 5` that holds its threshold.
const THRESHOLD_AT: usize = 32;

pub fn corpus() -> &'static Value {
    static CORPUS: OnceLock<Value> = OnceLock::new();
    CORPUS.get_or_init(|| {
        let path = format!("{}/tests/fixtures/distribution.json", env!("CARGO_MANIFEST_DIR"));
        serde_json::from_str(&std::fs::read_to_string(path).expect("read distribution.json")).expect("parse distribution.json")
    })
}

fn round_trip() -> &'static Value {
    corpus()["cases"].as_array().unwrap().iter().find(|case| case["name"] == "001_round_trip").expect("case 001")
}

/// The test key whose seed is the SHA-256 of `prismpath.dist test key <name>`.
pub fn test_key(name: &str) -> SigningKey {
    SigningKey::from_bytes(&Sha256::digest(format!("prismpath.dist test key {name}").as_bytes()).into())
}

pub fn public(name: &str) -> [u8; 32] {
    test_key(name).verifying_key().to_bytes()
}

pub fn key_id(name: &str) -> Hex64 {
    env::key_id(&public(name))
}

pub fn h(data: &[u8]) -> Hex64 {
    Hex64::of(data)
}

/// The image `when x >= <threshold>`: the corpus image, whose only threshold byte is set.
pub fn image(threshold: u8) -> Vec<u8> {
    let mut body = hex::decode(round_trip()["body"].as_str().unwrap()).unwrap();
    assert_eq!(body[THRESHOLD_AT], 5, "the corpus image is when x >= 5");
    body[THRESHOLD_AT] = threshold;
    body
}

/// The qualification envelope the corpus's host PEP admits images under.
pub fn qualification() -> Value {
    round_trip()["pep"]["qualification"].clone()
}

/// The `meta` of a `policy.ppt` envelope for any of the images above, which share their counts and WCET.
pub fn image_meta() -> Value {
    let sealed = hex::decode(round_trip()["sealed"].as_str().unwrap()).unwrap();
    let (envelope_bytes, _) = env::unseal(&sealed).unwrap();
    let doc: Value = serde_json::from_slice(envelope_bytes).unwrap();
    doc["meta"].clone()
}

pub fn release_of(body: &[u8]) -> Hex64 {
    env::release_id(&[(ArtifactKind::PolicyPpt, h(body))]).unwrap()
}

/// What `seal` writes besides the body, each defaulting to a one artifact `policy.ppt` release at seq 1 that
/// replaces nothing and says it widens, which every release but a renewal of the active table does on `host`
/// (W2, W6). `Point::stage` and the reconciling rig stage the owner's widening statement before such a release
/// (W3), and `renewal` is the release that goes in on its signature alone.
#[derive(Clone)]
pub struct Args {
    pub seq: i64,
    pub signers: Vec<&'static str>,
    pub release: Option<Hex64>,
    pub policy: Option<Hex64>,
    pub not_before: i64,
    pub expires: i64,
    pub meta: Option<Value>,
    pub stream: String,
    pub targets: Vec<TargetKind>,
    pub widens: bool,
    pub replaces: Option<Hex64>,
}

impl Default for Args {
    fn default() -> Args {
        Args {
            seq: 1,
            signers: vec!["A"],
            release: None,
            policy: None,
            not_before: NOT_BEFORE,
            expires: EXPIRES,
            meta: None,
            stream: STREAM.to_string(),
            targets: vec![TargetKind::Host],
            widens: true,
            replaces: None,
        }
    }
}

pub fn at(seq: i64) -> Args {
    Args { seq, ..Args::default() }
}

pub fn by(seq: i64, signer: &'static str) -> Args {
    Args { seq, signers: vec![signer], ..Args::default() }
}

/// A renewal at `seq` of the active release whose policy hash is `active`: `widens` false and `replaces` that
/// hash, so with the active table byte for byte it goes in on its signature alone (W2).
pub fn renewal(seq: i64, active: &[u8]) -> Args {
    Args { seq, widens: false, replaces: Some(h(active)), ..Args::default() }
}

/// The envelope bytes for `body`.
pub fn envelope(artifact: ArtifactKind, body: &[u8], args: &Args) -> Vec<u8> {
    let trust_stream = matches!(artifact, ArtifactKind::TrustRevocation | ArtifactKind::TrustRotation);
    let meta = args.meta.clone().unwrap_or_else(|| if artifact == ArtifactKind::PolicyPpt { image_meta() } else { json!({}) });
    let doc = EnvelopeDoc {
        artifact,
        body_sha256: Hex64::zero(),
        body_size: 0,
        encoding: Canon2Tag,
        expires: if artifact.is_trust() { 0 } else { args.expires },
        format: DistFormat,
        meta: canon2::from_json(&meta).unwrap(),
        not_before: args.not_before,
        policy_sha256: if trust_stream { Hex64::zero() } else { args.policy.clone().unwrap_or_else(|| h(body)) },
        release: if trust_stream {
            Hex64::zero()
        } else {
            args.release.clone().unwrap_or_else(|| env::release_id(&[(artifact, h(body))]).unwrap())
        },
        replaces: if trust_stream { MaybeHex64::default() } else { MaybeHex64(args.replaces.clone()) },
        seq: args.seq,
        stream: if trust_stream { env::TRUST_STREAM.to_string() } else { args.stream.clone() },
        targets: args.targets.iter().copied().collect(),
        widens: !trust_stream && args.widens,
    };
    env::build(doc, body).unwrap()
}

/// A sealed envelope for `body`, by default a `policy.ppt` release of one artifact signed by A.
pub fn seal(artifact: ArtifactKind, body: &[u8], args: &Args) -> Vec<u8> {
    let signers: Vec<SigningKey> = args.signers.iter().map(|name| test_key(name)).collect();
    env::seal(&envelope(artifact, body, args), &signers).unwrap()
}

pub fn ppt(body: &[u8], args: &Args) -> Vec<u8> {
    seal(ArtifactKind::PolicyPpt, body, args)
}

/// The canon/2 body of a revocation list (section 10).
pub fn revocation(envelopes: &[Hex64], keys: &[Hex64], policies: &[Hex64], floors: &[(&str, i64)]) -> Vec<u8> {
    let sorted = |items: &[Hex64]| {
        let mut out: Vec<String> = items.iter().map(|item| item.to_string()).collect();
        out.sort();
        out.dedup();
        out
    };
    let floors: serde_json::Map<String, Value> = floors.iter().map(|(stream, seq)| (stream.to_string(), json!(seq))).collect();
    canon2::write_json(&json!({"encoding": "canon/2", "format": "prismpath.dist-revocation/1", "envelopes": sorted(envelopes),
                               "keys": sorted(keys), "policies": sorted(policies), "floors": floors}))
    .unwrap()
}

/// The canon/2 body of a rotation (section 11) adding the test key `add` and retiring the test key `retire`.
pub fn rotation(add: &str, retire: Option<&str>) -> Vec<u8> {
    let retire = retire.map(|name| key_id(name).to_string()).unwrap_or_default();
    canon2::write_json(&json!({"encoding": "canon/2", "format": "prismpath.dist-rotation/1",
                               "add": hex::encode(public(add)), "retire": retire}))
    .unwrap()
}

/// The canon/2 body of a widening statement (W4).
pub fn widening(from: &[Hex64]) -> Vec<u8> {
    let from: Vec<String> = from.iter().map(|hash| hash.to_string()).collect();
    canon2::write_json(&json!({"encoding": "canon/2", "format": "prismpath.dist-widening/1", "from": from})).unwrap()
}

/// The names of the test keys a test signs with.
const SIGNERS: [&str; 7] = ["A", "B", "R", "Q", "U", "X", "C"];

/// The owner's widening statement (W4) from the policy hashes `from` for the `policy.ppt` release `sealed`,
/// signed by the key that signed it and sharing its stream, seq, hashes, `replaces` and `widens` (E7).
pub fn statement_of(sealed: &[u8], from: &[Hex64]) -> (Vec<u8>, Vec<u8>) {
    let (envelope_bytes, entries) = env::unseal(sealed).unwrap();
    let envelope = env::read(envelope_bytes).unwrap();
    let first = entries.first().unwrap().key_id;
    let signer = SIGNERS.iter().find(|name| key_id(name).raw() == first).copied().unwrap_or("A");
    let statement = widening(from);
    let args = Args {
        seq: envelope.seq,
        signers: vec![signer],
        release: Some(envelope.release.clone()),
        policy: Some(envelope.policy_sha256.clone()),
        not_before: envelope.not_before,
        stream: envelope.stream.clone(),
        targets: envelope.targets.iter().copied().collect(),
        widens: envelope.widens,
        replaces: envelope.replaces.0.clone(),
        ..Args::default()
    };
    (seal(ArtifactKind::TrustWidening, &statement, &args), statement)
}

/// The canon/2 body of a change statement (W10) from the policy hash `from`.
pub fn change(from: &Hex64) -> Vec<u8> {
    canon2::write_json(&json!({"basis": "prismpath.table-compare/1", "encoding": "canon/2",
                               "format": "prismpath.dist-change/1", "from": from.to_string()}))
    .unwrap()
}

/// The authority's change statement (W10) from `from` for the `policy.ppt` release `sealed`, sharing its stream,
/// seq, hashes and `replaces`, with `widens` as given (E7 asks the release's own).
pub fn change_of(sealed: &[u8], from: &Hex64, widens: bool) -> (Vec<u8>, Vec<u8>) {
    let envelope = env::read(env::unseal(sealed).unwrap().0).unwrap();
    let body = change(from);
    let args = Args {
        seq: envelope.seq,
        release: Some(envelope.release.clone()),
        policy: Some(envelope.policy_sha256.clone()),
        not_before: envelope.not_before,
        stream: envelope.stream.clone(),
        targets: envelope.targets.iter().copied().collect(),
        widens,
        replaces: envelope.replaces.0.clone(),
        ..Args::default()
    };
    (seal(ArtifactKind::TrustChange, &body, &args), body)
}

/// The owner's widening statement covering any PEP for `sealed`, or None when `sealed` is not a `policy.ppt`
/// release that says it widens.
pub fn covering_statement(sealed: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let envelope = env::read(env::unseal(sealed).ok()?.0).ok()?;
    (envelope.artifact == ArtifactKind::PolicyPpt && envelope.widens).then(|| statement_of(sealed, &[]))
}

/// A sealed trust statement on `@trust`, signed by every test key in `signers` (O2 asks for two).
pub fn trust_statement(artifact: ArtifactKind, body: &[u8], seq: i64, signers: &[&'static str], targets: &[TargetKind]) -> Vec<u8> {
    seal(artifact, body, &Args { seq, signers: signers.to_vec(), targets: targets.to_vec(), ..Args::default() })
}

/// A provisioned host PEP over a scratch directory, with its clock, its instance key and the authority keys
/// its anchor trusts. A restart is `open`, a fresh PEP over the same directory.
pub struct Point {
    pub scratch: Scratch,
    pub now: Rc<Cell<i64>>,
    pub key: SigningKey,
    pub authorities: Vec<&'static str>,
    pub expiry: &'static str,
    pub pep: Pep<HostAdapter>,
}

impl Point {
    pub fn new(tag: &str) -> Point {
        Point::with(tag, test_key("I"), &["A"], REFUSE).unwrap()
    }

    pub fn with(tag: &str, key: SigningKey, authorities: &[&'static str], expiry: &'static str) -> Result<Point, PepError> {
        let scratch = Scratch::new(&format!("dist_pep_{tag}"));
        let now = Rc::new(Cell::new(NOW));
        let pep = open_pep(&scratch.join("host"), &now, &key, authorities, expiry, true)?;
        Ok(Point { scratch, now, key, authorities: authorities.to_vec(), expiry, pep })
    }

    pub fn state_dir(&self) -> PathBuf {
        self.scratch.join("host")
    }

    /// A fresh PEP over the state directory, as after a restart.
    pub fn open(&self) -> Result<Pep<HostAdapter>, PepError> {
        open_pep(&self.state_dir(), &self.now, &self.key, &self.authorities, self.expiry, true)
    }

    pub fn reopen(&mut self) {
        self.pep = self.open().unwrap();
    }

    pub fn anchor(&self) -> Vec<u8> {
        anchor_of(&self.authorities)
    }

    pub fn read(&self, signed: &[u8]) -> StateRecord {
        state_record::read(signed, &self.key.verifying_key().to_bytes()).unwrap()
    }

    /// Stage `sealed`, after the owner's widening statement when it is a release that says it widens (W3).
    pub fn stage(&mut self, sealed: &[u8], body: &[u8]) -> StateRecord {
        if let Some((statement_sealed, statement)) = covering_statement(sealed) {
            self.pep.stage(&statement_sealed, &statement).unwrap();
        }
        let signed = self.pep.stage(sealed, body).unwrap();
        self.read(&signed)
    }

    pub fn commit(&mut self, body: &[u8], args: &Args) -> StateRecord {
        self.stage(&ppt(body, args), body);
        let signed = self.pep.commit(STREAM, args.seq, &args.policy.clone().unwrap_or_else(|| h(body)), 0).unwrap();
        self.read(&signed)
    }

    pub fn commit_at(&mut self, body: &[u8], seq: i64) -> StateRecord {
        self.commit(body, &at(seq))
    }

    /// Stage a rotation adding `add` and retiring `retire`, signed by the first authority and the new key.
    pub fn rotate(&mut self, seq: i64, add: &'static str, retire: Option<&str>) -> StateRecord {
        let body = rotation(add, retire);
        let sealed = trust_statement(ArtifactKind::TrustRotation, &body, seq, &[self.authorities[0], add], &[TargetKind::Host]);
        self.stage(&sealed, &body)
    }

    /// Stage a revocation list at trust sequence `seq`, which applies it (B2).
    pub fn revoke(&mut self, seq: i64, body: &[u8]) -> StateRecord {
        let sealed = trust_statement(ArtifactKind::TrustRevocation, body, seq, &["A"], &[TargetKind::Host]);
        self.stage(&sealed, body)
    }

    /// The policy the host itself holds, by its hash.
    pub fn host_active(&self) -> Value {
        self.pep.adapter.host.active_info()["active"].clone()
    }

    pub fn actions(&self) -> Vec<String> {
        self.pep.audit.events().iter().map(|event| event["action"].as_str().unwrap_or_default().to_string()).collect()
    }
}

pub fn anchor_of(authorities: &[&str]) -> Vec<u8> {
    let keys: Vec<[u8; 32]> = authorities.iter().map(|name| public(name)).collect();
    anchor_bytes(&keys, TargetKind::Host, &Stream::try_from(STREAM).unwrap(), &Role::authority()).unwrap()
}

pub fn host_at(dir: &std::path::Path) -> PolicyHost {
    PolicyHost::new(dir.to_str().unwrap(), Vec::new(), qualification(), Vec::new()).unwrap()
}

pub fn clock_of(now: &Rc<Cell<i64>>) -> Box<dyn Fn() -> i64> {
    let now = now.clone();
    Box::new(move || now.get())
}

/// A host PEP over `dir`, provisioned with an anchor trusting `authorities` on its first open when `provision`.
pub fn open_pep(
    dir: &std::path::Path,
    now: &Rc<Cell<i64>>,
    key: &SigningKey,
    authorities: &[&str],
    expiry: &str,
    provision: bool,
) -> Result<Pep<HostAdapter>, PepError> {
    let adapter = HostAdapter::new(host_at(dir));
    let mut pep = Pep::new(dir.to_str().unwrap(), adapter, key.clone(), clock_of(now), expiry, true)?;
    if provision && !pep.is_provisioned() {
        let fingerprint = pep.provision(&anchor_of(authorities))?;
        pep.confirm(&fingerprint)?;
    }
    Ok(pep)
}
