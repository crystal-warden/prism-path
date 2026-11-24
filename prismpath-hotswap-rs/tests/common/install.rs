// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! What the section 21 tests of the Rust host PEP share, `prismpath/tests/_dist.py`'s install half in Rust: the
//! engineer's install keys and tool, a table image builder for action floors over the registers `cmd`, `p`, `w`
//! and `q`, the layout document the host is built with, and a host PEP provisioned from a `/2` anchor that holds an
//! install part.
#![allow(dead_code)]

use super::common::Scratch;
use super::dist::*;
use ed25519_dalek::SigningKey;
use prismpath_hotswap_rs::dist::envelope::{self as env, EnvelopeDoc};
use prismpath_hotswap_rs::dist::floor::{self, LayoutField, Request};
use prismpath_hotswap_rs::dist::install::{self, AsName};
use prismpath_hotswap_rs::dist::pep::{HostAdapter, Pep, PepError, REFUSE};
use prismpath_hotswap_rs::dist::state_record::{self, InstallEntry, StateRecord};
use prismpath_hotswap_rs::dist::trust::anchor2_bytes;
use prismpath_hotswap_rs::dist::{ArtifactKind, Canon2Tag, DistFormat, Hex64, MaybeHex64, Stream, TargetKind};
use prismpath_rs::canon2;
use serde_json::{json, Value};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::rc::Rc;

pub const FLOOR: ArtifactKind = ArtifactKind::InstallFloor;
pub const FALLBACK: ArtifactKind = ArtifactKind::InstallFallback;
pub const CEILING: ArtifactKind = ArtifactKind::InstallCeiling;
pub const TRUST: ArtifactKind = ArtifactKind::InstallTrust;
pub const PPT: AsName = AsName::Artifact(ArtifactKind::PolicyPpt);

// ------------------------------------------------------------------ tables and the layout (AF9, AF10)

/// The layout the host is built with: `cmd` the command, `p` its parameter, `w` an independent reading with a
/// staleness bound of 5 seconds and `q` the proposer's own reading.
pub fn layout() -> Vec<u8> {
    floor::layout_body(&[
        field("cmd", 0, "command", 0, 255, 0),
        field("p", 1, "parameter", 0, 100, 0),
        field("w", 2, "independent", 0, 1, 5),
        field("q", 3, "proposer", 0, 1, 0),
    ])
    .unwrap()
}

pub fn field(name: &str, register: i64, role: &str, min: i64, max: i64, stale: i64) -> LayoutField {
    LayoutField { max, min, name: name.to_string(), register, role: role.to_string(), stale }
}

/// One test of a condition: register, comparison, value.
pub type Test = (u16, u8, i32);
pub const EQ: u8 = floor::OP_EQ;
pub const GE: u8 = floor::OP_GE;
pub const LE: u8 = floor::OP_LE;
pub const OR: u16 = floor::OPC_OR;

/// A table whose start node 0 holds one edge per condition to the terminal node 1, each condition the
/// conjunction of its tests, over the four registers. `decision_nodes` 2 gives node 1 an edge too.
pub fn table_with(conditions: &[Vec<Test>], decision_nodes: usize, or_first_two: bool) -> Vec<u8> {
    let mut atoms: Vec<(u16, u8, u8, i32)> = Vec::new();
    let mut words: Vec<u16> = Vec::new();
    let mut edges: Vec<(u16, u16, u16)> = Vec::new();
    for condition in conditions {
        let start = words.len() as u16;
        if condition.is_empty() {
            words.push(floor::OPC_TRUE); // an edge that tests nothing
        }
        for (position, (register, op, value)) in condition.iter().enumerate() {
            words.push(atoms.len() as u16);
            atoms.push((*register, *op, 2, *value));
            if position > 0 {
                words.push(if or_first_two && position == 1 { OR } else { floor::OPC_AND });
            }
        }
        edges.push((1, start, words.len() as u16 - start));
    }
    let mut nodes = vec![(0u16, edges.len() as u16), (edges.len() as u16, 0u16)];
    if decision_nodes == 2 {
        let start = words.len() as u16;
        words.push(floor::OPC_TRUE);
        edges.push((0, start, 1));
        nodes[1] = (nodes[1].0, 1);
    }
    let mut out = Vec::new();
    let max_stack = 4u16;
    for word in [
        0x5050u16, 0x4D54, 1, 4, 0, atoms.len() as u16, nodes.len() as u16, edges.len() as u16, words.len() as u16, 0, 0, 1,
        max_stack, 0,
    ] {
        out.extend_from_slice(&word.to_le_bytes());
    }
    for (register, op, kind, value) in atoms {
        out.extend_from_slice(&register.to_le_bytes());
        out.extend_from_slice(&[op, kind]);
        out.extend_from_slice(&value.to_le_bytes());
    }
    for (offset, count) in nodes {
        out.extend_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
    }
    for (target, offset, count) in edges {
        for word in [target, offset, count] {
            out.extend_from_slice(&word.to_le_bytes());
        }
    }
    for word in words {
        out.extend_from_slice(&word.to_le_bytes());
    }
    let (ok, reasons) = prismpath_hotswap_rs::validate_image(&out, None);
    assert!(ok, "{reasons:?}");
    out
}

pub fn table(conditions: &[Vec<Test>]) -> Vec<u8> {
    table_with(conditions, 1, false)
}

/// The good floor: command 3 with its parameter from 2 to 5.
pub fn good_table() -> Vec<u8> {
    table(&[vec![(0, EQ, 3), (1, GE, 2), (1, LE, 5)]])
}

/// A narrow floor of command `command` with its parameter from 2 to 5.
pub fn floor_of(command: i32) -> Vec<u8> {
    table(&[vec![(0, EQ, command), (1, GE, 2), (1, LE, 5)]])
}

/// A register file of the four registers, each an int.
pub fn regs(values: [i32; 4]) -> Vec<u8> {
    let mut out = 0u32.to_le_bytes().to_vec();
    for value in values {
        out.extend_from_slice(&2i32.to_le_bytes());
        out.extend_from_slice(&value.to_le_bytes());
    }
    out
}

pub fn request(values: [i32; 4]) -> Request {
    Request { regs: regs(values), ages: BTreeMap::new() }
}

/// The `meta` of a `policy.ppt` of any table: its fields, counts and WCET and the qualification it is admitted under.
pub fn table_meta(image: &[u8]) -> Value {
    let header = prismpath_hotswap_rs::read_ppt_header(image).unwrap();
    json!({"fields": {"x": "int"}, "qualification": "dist-demo",
           "counts": {"atoms": header.atoms, "nodes": header.nodes, "edges": header.edges, "prog_words": header.prog_words,
                      "max_steps": header.max_steps, "max_stack": header.max_stack},
           "wcet_cycles": prismpath_hotswap_rs::wcet_cycles(image).unwrap()})
}

// ------------------------------------------------------------------ the engineer's tool

pub const INSTALL_KEYS: [&str; 3] = ["N1", "N2", "N3"];

/// What `set` writes besides the bodies: by default seq 1, signed by N1 and N2, `widens` true, replacing nothing.
#[derive(Clone)]
pub struct SetArgs {
    pub seq: i64,
    pub signers: Vec<&'static str>,
    pub widens: bool,
    pub replaces: Option<Hex64>,
    pub rate: Option<(i64, i64)>,
    pub command: Option<i64>,
    pub layout: Option<Hex64>,
    pub not_before: i64,
    pub policy: Option<Hex64>,
    pub release: Option<Hex64>,
    pub meta: Option<Value>,
    pub stream: String,
    pub targets: Vec<TargetKind>,
}

impl Default for SetArgs {
    fn default() -> SetArgs {
        SetArgs {
            seq: 1,
            signers: vec!["N1", "N2"],
            widens: true,
            replaces: None,
            rate: None,
            command: None,
            layout: None,
            not_before: NOT_BEFORE,
            policy: None,
            release: None,
            meta: None,
            stream: STREAM.to_string(),
            targets: vec![TargetKind::Host],
        }
    }
}

pub fn seq(seq: i64) -> SetArgs {
    SetArgs { seq, ..SetArgs::default() }
}

pub fn statement_doc(kind: ArtifactKind, name: AsName, body: &[u8], args: &SetArgs, release: &Hex64, policy: &Hex64) -> Vec<u8> {
    env::build(statement_envelope(kind, name, body, args, release, policy), body).unwrap()
}

/// The document of one statement, its body hash and size taken from `body` and no reader's check made.
pub fn statement_envelope(kind: ArtifactKind, name: AsName, body: &[u8], args: &SetArgs, release: &Hex64, policy: &Hex64) -> EnvelopeDoc {
    let mut meta = match (name, &args.meta) {
        (_, Some(meta)) => meta.clone(),
        (AsName::Artifact(ArtifactKind::PolicyPpt), None) => table_meta(body),
        _ => json!({}),
    };
    meta["as"] = json!(name.name());
    if kind == FLOOR && name == PPT {
        meta["command"] = json!(args.command.unwrap_or(0));
        meta["layout"] = json!(args.layout.clone().unwrap_or_else(|| h(&layout())).as_str());
    }
    if let Some((allows, window)) = args.rate {
        meta["rate"] = json!({"allows": allows, "window": window});
    }
    EnvelopeDoc {
        artifact: kind,
        body_sha256: h(body),
        body_size: body.len() as i64,
        encoding: Canon2Tag,
        expires: 0,
        format: DistFormat,
        meta: canon2::from_json(&meta).unwrap(),
        not_before: args.not_before,
        policy_sha256: policy.clone(),
        release: release.clone(),
        replaces: MaybeHex64(args.replaces.clone()),
        seq: args.seq,
        stream: args.stream.clone(),
        targets: args.targets.iter().copied().collect(),
        widens: args.widens,
    }
}

/// The (sealed, body) pairs of one install set of `kind` holding `bodies`, signed by `args.signers`. The policy hash
/// is the table's, the list's for a policy list, and 64 zeros for the empty set.
pub fn set(kind: ArtifactKind, bodies: &[(AsName, Vec<u8>)], args: &SetArgs) -> Vec<(Vec<u8>, Vec<u8>)> {
    let pairs: Vec<(AsName, Hex64)> = bodies.iter().map(|(name, body)| (*name, h(body))).collect();
    let release = args.release.clone().unwrap_or_else(|| install::install_release_id(&pairs).unwrap());
    let primary = bodies.iter().find(|(name, _)| matches!(name, AsName::PolicyList | AsName::Artifact(ArtifactKind::PolicyPpt)));
    let policy = args.policy.clone().unwrap_or_else(|| match primary {
        Some((_, body)) => h(body),
        None => Hex64::zero(),
    });
    let signers: Vec<SigningKey> = args.signers.iter().map(|name| test_key(name)).collect();
    bodies
        .iter()
        .map(|(name, body)| (env::seal(&statement_doc(kind, *name, body, args, &release, &policy), &signers).unwrap(), body.clone()))
        .collect()
}

pub fn floor_set(image: &[u8], args: &SetArgs) -> Vec<(Vec<u8>, Vec<u8>)> {
    set(FLOOR, &[(PPT, image.to_vec())], args)
}

pub fn fallback_set(image: &[u8], args: &SetArgs) -> Vec<(Vec<u8>, Vec<u8>)> {
    set(FALLBACK, &[(PPT, image.to_vec())], args)
}

/// A ceiling listing `tables`. A first ceiling does not widen (IS12), so `widens` follows `args`.
pub fn ceiling_set(tables: &[&[u8]], args: &SetArgs) -> Vec<(Vec<u8>, Vec<u8>)> {
    set(CEILING, &[(AsName::PolicyList, install::ceiling_body(tables).unwrap())], args)
}

pub fn empty_set(kind: ArtifactKind, args: &SetArgs) -> Vec<(Vec<u8>, Vec<u8>)> {
    set(kind, &[(AsName::None, Vec::new())], args)
}

/// A sealed `install.trust` at install trust sequence `seq` naming the test keys `keys` and `operators` at
/// `threshold`, signed by `signers`.
pub fn install_trust(keys: &[&str], threshold: i64, operators: &[&str], seq: i64, signers: &[&'static str], widens: bool) -> (Vec<u8>, Vec<u8>) {
    let publics: Vec<[u8; 32]> = keys.iter().map(|name| public(name)).collect();
    let operators: Vec<[u8; 32]> = operators.iter().map(|name| public(name)).collect();
    let body = install::trust_body(&publics, threshold, &operators).unwrap();
    let doc = EnvelopeDoc {
        artifact: TRUST,
        body_sha256: Hex64::zero(),
        body_size: 0,
        encoding: Canon2Tag,
        expires: 0,
        format: DistFormat,
        meta: canon2::from_json(&json!({})).unwrap(),
        not_before: NOT_BEFORE,
        policy_sha256: Hex64::zero(),
        release: Hex64::zero(),
        replaces: MaybeHex64::default(),
        seq,
        stream: STREAM.to_string(),
        targets: vec![TargetKind::Host].into_iter().collect(),
        widens,
    };
    let keys: Vec<SigningKey> = signers.iter().map(|name| test_key(name)).collect();
    (env::seal(&env::build(doc, &body).unwrap(), &keys).unwrap(), body)
}

/// IS14: a sealed install change statement for the set of `kind` whose table is `table`, sealed with `args` as that set
/// is (its `seq`, `replaces`, `widens`, signers, targets and `not_before`), from the policy hash `from`.
pub fn install_change(kind: ArtifactKind, table: &[u8], args: &SetArgs, from: &Hex64) -> (Vec<u8>, Vec<u8>) {
    change_body_of(kind.name(), table, args, from)
}

/// An install change statement whose body names the set kind `set` as text, so a test can name a ceiling.
pub fn change_body_of(set: &str, table: &[u8], args: &SetArgs, from: &Hex64) -> (Vec<u8>, Vec<u8>) {
    let body = canon2::write_json(&json!({"basis": "prismpath.table-compare/1", "encoding": "canon/2",
                                          "format": "prismpath.dist-install-change/1", "from": from.as_str(), "set": set}))
    .unwrap();
    let release = args.release.clone().unwrap_or_else(|| install::install_release_id(&[(PPT, h(table))]).unwrap());
    let doc = EnvelopeDoc {
        artifact: ArtifactKind::InstallChange,
        body_sha256: h(&body),
        body_size: body.len() as i64,
        encoding: Canon2Tag,
        expires: 0,
        format: DistFormat,
        meta: canon2::from_json(&json!({})).unwrap(),
        not_before: args.not_before,
        policy_sha256: args.policy.clone().unwrap_or_else(|| h(table)),
        release,
        replaces: MaybeHex64(args.replaces.clone()),
        seq: args.seq,
        stream: args.stream.clone(),
        targets: args.targets.iter().copied().collect(),
        widens: args.widens,
    };
    let keys: Vec<SigningKey> = args.signers.iter().map(|name| test_key(name)).collect();
    (env::seal(&env::build(doc, &body).unwrap(), &keys).unwrap(), body)
}

/// The domain the test host is built with (P4, CL4).
pub fn domain() -> Hex64 {
    install::domain_sha256(Some(&qualification()))
}

/// A `/2` anchor trusting authority A, controller C, and the install keys `keys` at `threshold` with `operators`, at
/// install trust sequence `seq`.
pub fn anchor2(keys: &[&str], threshold: i64, operators: &[&str], seq: i64) -> Vec<u8> {
    let checked = anchor2_checked(&["A"], "C", Some((keys, threshold, operators, seq, domain())));
    assert_eq!(checked, anchor2_with(&["A"], "C", Some((keys, threshold, operators, seq, domain()))), "the tool and the test write one anchor");
    checked
}

/// An anchor's install part: the install keys, the threshold, the operator keys, the install trust sequence and the
/// domain.
pub type Part<'a> = (&'a [&'a str], i64, &'a [&'a str], i64, Hex64);

pub fn anchor2_with(authorities: &[&str], controller: &str, part: Option<Part>) -> Vec<u8> {
    let sorted = |names: &[&str]| {
        let mut out: Vec<String> = names.iter().map(|name| hex::encode(public(name))).collect();
        out.sort();
        out
    };
    let keys: serde_json::Map<String, Value> =
        authorities.iter().map(|name| (key_id(name).to_string(), json!({"public": hex::encode(public(name)), "role": "authority"}))).collect();
    let mut doc = json!({"controller": hex::encode(public(controller)), "encoding": "canon/2", "format": "prismpath.dist-trust/2",
                         "fresh": 0, "keys": keys, "stream": STREAM, "target": "host", "threshold": 1});
    if let Some((keys, threshold, operators, seq, domain)) = part {
        doc["install"] = json!({"domain": domain.as_str(), "keys": sorted(keys), "operators": sorted(operators), "seq": seq,
                                "threshold": threshold});
    }
    canon2::write_json(&doc).unwrap()
}

/// The `/2` anchor the owner's tool writes, which refuses what a reader refuses.
pub fn anchor2_checked(authorities: &[&str], controller: &str, part: Option<Part>) -> Vec<u8> {
    let authorities: Vec<[u8; 32]> = authorities.iter().map(|name| public(name)).collect();
    let part = part.map(|(keys, threshold, operators, seq, domain)| {
        let keys: Vec<[u8; 32]> = keys.iter().map(|name| public(name)).collect();
        let operators: Vec<[u8; 32]> = operators.iter().map(|name| public(name)).collect();
        install::anchor_part(&keys, threshold, &operators, seq, &domain)
    });
    anchor2_bytes(&authorities, TargetKind::Host, &Stream::try_from(STREAM).unwrap(), &public(controller), 0, part).unwrap()
}

// ------------------------------------------------------------------ a host PEP with an install part

/// A host PEP built with the layout, provisioned from a `/2` anchor holding the install keys N1 to N3 at the
/// threshold given, over a scratch directory. `copy` is the second medium of its install record, or none.
pub struct Installer {
    pub scratch: Scratch,
    pub now: Rc<Cell<i64>>,
    pub key: SigningKey,
    pub copy: Option<PathBuf>,
    pub pep: Pep<HostAdapter>,
}

impl Installer {
    pub fn new(tag: &str, threshold: i64) -> Installer {
        Installer::with(tag, &anchor2(&INSTALL_KEYS, threshold, &[], 0), &[], false)
    }

    pub fn with(tag: &str, anchor: &[u8], brought: &[(Vec<u8>, Vec<u8>)], copy: bool) -> Installer {
        let scratch = Scratch::new(&format!("dist_install_{tag}"));
        let now = Rc::new(Cell::new(NOW));
        let copy = copy.then(|| scratch.join("medium2"));
        let key = test_key("I");
        let mut pep = open_installer(&scratch.join("host"), &now, &key, copy.as_deref()).unwrap();
        let fingerprint = pep.provision_with(anchor, brought).unwrap();
        pep.confirm(&fingerprint).unwrap();
        pep.drain();
        Installer { scratch, now, key, copy, pep }
    }

    pub fn state_dir(&self) -> PathBuf {
        self.scratch.join("host")
    }

    pub fn dist(&self) -> PathBuf {
        self.state_dir().join("dist")
    }

    pub fn open(&self) -> Result<Pep<HostAdapter>, PepError> {
        open_installer(&self.state_dir(), &self.now, &self.key, self.copy.as_deref())
    }

    pub fn reopen(&mut self) {
        self.pep = self.open().unwrap();
    }

    pub fn read(&self, signed: &[u8]) -> StateRecord {
        state_record::read(signed, &self.key.verifying_key().to_bytes()).unwrap()
    }

    /// Stage every statement of `statements` in a message, and the record of the last.
    pub fn send(&mut self, statements: &[(Vec<u8>, Vec<u8>)]) -> StateRecord {
        let mut last = None;
        for (sealed, body) in statements {
            last = Some(self.pep.stage(sealed, body).unwrap());
        }
        self.read(&last.expect("one statement at least"))
    }

    /// The (event, cause) of `record`.
    pub fn about(record: &StateRecord) -> (&'static str, Option<&str>) {
        (record.event, record.cause.as_deref())
    }

    pub fn entry(record: &StateRecord) -> InstallEntry {
        state_record::install_entry(record).unwrap().expect("an install entry")
    }

    /// Stage and commit the release of `body` at `seq` with its widening statement (W3), the record of the commit.
    pub fn commit(&mut self, body: &[u8], args: &Args) -> StateRecord {
        let sealed = ppt(body, args);
        if let Some((statement_sealed, statement)) = covering_statement(&sealed) {
            self.pep.stage(&statement_sealed, &statement).unwrap();
        }
        self.pep.stage(&sealed, body).unwrap();
        let signed = self.pep.commit(STREAM, args.seq, &h(body), 0).unwrap();
        self.read(&signed)
    }

    pub fn held(&self, kind: ArtifactKind) -> Option<Hex64> {
        let kind = install::SetKind::of(kind).unwrap();
        self.pep.installed.held(kind).map(|set| set.policy_sha256().clone())
    }

    pub fn seq_of(&self, kind: ArtifactKind) -> i64 {
        self.pep.installed.record.as_ref().map_or(0, |record| record.seq(install::SetKind::of(kind).unwrap()))
    }

    pub fn actions(&self) -> Vec<String> {
        self.pep.audit.events().iter().map(|event| event["action"].as_str().unwrap_or_default().to_string()).collect()
    }

    pub fn host_active(&self) -> Value {
        self.pep.adapter.host.active_info()["active"].clone()
    }
}

pub fn open_installer(dir: &std::path::Path, now: &Rc<Cell<i64>>, key: &SigningKey, copy: Option<&std::path::Path>) -> Result<Pep<HostAdapter>, PepError> {
    let adapter = HostAdapter::with_layout(host_at(dir), layout());
    Pep::with_install_copy(dir.to_str().unwrap(), adapter, key.clone(), clock_of(now), REFUSE, true, copy.map(|path| path.to_str().unwrap()))
}

/// The bytes of `doc` sealed by `signers` with no reader's check, so a test can send what a reader refuses.
pub fn raw_sealed(doc: &EnvelopeDoc, body: &[u8], signers: &[&str]) -> Vec<u8> {
    let mut doc = doc.clone();
    doc.body_sha256 = h(body);
    doc.body_size = body.len() as i64;
    let raw = prismpath_rs::canon2::codec::to_bytes(&doc).unwrap();
    let keys: Vec<SigningKey> = signers.iter().map(|name| test_key(name)).collect();
    env::seal(&raw, &keys).unwrap()
}

/// The document of a floor statement of `image`, for a test to change one member of.
pub fn floor_doc(image: &[u8], args: &SetArgs) -> EnvelopeDoc {
    let release = install::install_release_id(&[(PPT, h(image))]).unwrap();
    statement_envelope(FLOOR, PPT, image, args, &release, &h(image))
}

/// A well formed `operator.answer` for the PEP whose instance key is I, signed by `signer` (OP2).
pub fn answer(signer: &str) -> (Vec<u8>, Vec<u8>) {
    let pep = hex::encode(state_record::pep_id(&public("I")));
    let body = canon2::write_json(&json!({"answer": "allow", "encoding": "canon/2", "format": "prismpath.dist-answer/1",
                                          "pep": pep, "receipt": h(b"a receipt").as_str()}))
    .unwrap();
    let doc = EnvelopeDoc {
        artifact: ArtifactKind::OperatorAnswer,
        body_sha256: Hex64::zero(),
        body_size: 0,
        encoding: Canon2Tag,
        expires: NOW + 600,
        format: DistFormat,
        meta: canon2::from_json(&json!({})).unwrap(),
        not_before: NOW,
        policy_sha256: h(&good_table()),
        release: Hex64::zero(),
        replaces: MaybeHex64::default(),
        seq: 1,
        stream: STREAM.to_string(),
        targets: vec![TargetKind::Host].into_iter().collect(),
        widens: false,
    };
    let sealed = env::seal(&env::build(doc, &body).unwrap(), &[test_key(signer)]).unwrap();
    (sealed, body)
}
