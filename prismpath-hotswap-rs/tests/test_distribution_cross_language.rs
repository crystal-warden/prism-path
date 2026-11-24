// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! Policy distribution across the two runtimes (spec-policy-distribution.md, I1, H1, H6). A release sealed by
//! the Python writer and stored and offered by the Python reference controller is staged and committed by the
//! Rust host PEP, and every state record it sends is accepted by that controller, which then expects the new
//! release of it. The reverse: a release sealed by the Rust writer under a Rust written anchor is stored by
//! the Python controller, committed by the Python host PEP, and the state records the Python PEP signed read
//! in Rust as they read in Python.
//!
//! The controller's clock is pinned at one time, inside its first heartbeat interval, and that is a limit of
//! what this shows. The Rust PEP holds no controller key, so every record it signs carries epoch 0 (H9, H15),
//! and the controller on main takes epoch 0 only while its own epoch is 1. Past one interval it files each such
//! record `fleet:state-replay`. H6 says epoch 0 is no replay from a PEP that holds no controller key, and the
//! controller takes that in its own pull request. The Python half runs through `PRISMPATH_PYTHON`; see
//! `common::python_for_cross_language` for when this skips (CI sets `PRISMPATH_REQUIRE_CROSS_LANGUAGE`, so
//! it cannot skip there).

#[path = "common/mod.rs"]
mod common;
#[path = "common/dist.rs"]
mod dist;

use dist::*;
use prismpath_hotswap_rs::dist::envelope as env;
use prismpath_hotswap_rs::dist::pep::{HostAdapter, Pep, REFUSE};
use prismpath_hotswap_rs::dist::state_record;
use prismpath_hotswap_rs::dist::{ArtifactKind, Hex64};
use prismpath_hotswap_rs::host::PolicyHost;
use serde_json::{json, Value};
use std::cell::Cell;
use std::rc::Rc;

/// One step of the Python side, named by `op` in `PP_IN`, printing one JSON report. The controller keeps its
/// state in `dir` between steps, as the reference controller does between processes.
const PYTHON: &str = r#"
import hashlib, json, os, sys
sys.path.insert(0, os.environ["PP_REPO"])
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization as ser
from prismpath import canon
from prismpath.distribution import envelope as env, state_record, trust
from prismpath.distribution.controller import Controller
from prismpath.distribution.pep import Pep
from prismpath.distribution.adapters.host import HostAdapter
from prismpath.hotswap import policy_pack as pp
from prismpath.hotswap.policy_host import PolicyHost
from prismpath.kernel import ppt_compile
from prismpath.ledgers.root_statement import InstanceKey

STREAM, NOT_BEFORE = "host/demo", 1_800_000_000
EXPIRES, NOW = NOT_BEFORE + 30 * 86400, NOT_BEFORE + 3600
QUALIFICATION = {"caps": dict(pp.DEFAULT_CAPS), "envelope_id": "dist-demo", "fields": {"x": "int"}}
step = json.loads(open(os.environ["PP_IN"]).read())
directory = step["dir"]

def key(name):
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(f"prismpath.dist test key {name}".encode()).digest())

def public(name):
    return key(name).public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)

def instance(name):
    return InstanceKey(key(name), public(name))

def controller():
    # pinned inside the first heartbeat interval, where epoch 0 is the epoch before the controller's (see the note)
    return Controller(os.path.join(directory, "controller"), instance("C"), clock=lambda: NOW)

def findings(control):
    return {pep: member.findings for pep, member in control.members.items()}

out = {}
if step["op"] == "python_seals":
    control = controller()
    anchor = trust.anchor_bytes([public("A")], target="host", stream=STREAM)
    control.add_anchor(anchor, QUALIFICATION)
    body = ppt_compile.compile_predicate("when x >= 5").serialize()
    header = pp.read_ppt_header(body)
    meta = {"counts": {name: header[name] for name in ("atoms", "nodes", "edges", "prog_words", "max_steps", "max_stack")},
            "fields": {"x": "int"}, "qualification": "dist-demo", "wcet_cycles": pp.wcet_cycles(body)}
    # a first install is larger than no policy, so it says it widens and carries the owner's statement (W3, W6)
    policy, release = canon.sha256_hex(body), env.release_id([("policy.ppt", canon.sha256_hex(body))])
    statement = canon.canon2_bytes({canon.ENCODING_KEY: canon.CANON2, "format": "prismpath.dist-widening/1", "from": []})
    common = dict(stream=STREAM, seq=1, targets=["host"], not_before=NOT_BEFORE, policy_sha256=policy, release=release,
                  widens=True)
    statement_sealed = env.seal(env.build("trust.widening", statement, expires=0, **common), [key("A")])
    sealed = env.seal(env.build("policy.ppt", body, meta=meta, expires=EXPIRES, **common), [key("A")])
    control.put(statement_sealed, statement)
    control.put(sealed, body)
    pep = control.enroll(bytes.fromhex(step["rust_public"]), "host", STREAM)
    control.offer("default", STREAM, 1)
    control.save()
    out = {"anchor": anchor.hex(), "sealed": sealed.hex(), "body": body.hex(), "statement_sealed": statement_sealed.hex(),
           "statement": statement.hex(), "pep": pep,
           "epoch": control.answer(pep)["epoch"], "qualification": QUALIFICATION}
elif step["op"] in ("receive", "receive_and_commit"):
    control = controller()
    out["findings_filed"] = [control.receive(bytes.fromhex(record)) for record in step["records"]]
    if step["op"] == "receive_and_commit":
        control.commit("default")
        out["commit"] = control.answer(step["pep"])["commit"]
    member = control.members[step["pep"]]
    out["last"] = member.last
    out["expected"] = list(member.expected)
    out["rollout"] = control.rollouts[-1].state
    out["member_state"] = control.rollouts[-1].members[step["pep"]]
    out["findings"] = findings(control)
    control.save()
elif step["op"] == "python_commits":
    sealed, body = bytes.fromhex(step["sealed"]), bytes.fromhex(step["body"])
    statement_sealed, statement = bytes.fromhex(step["statement_sealed"]), bytes.fromhex(step["statement"])
    control = controller()
    control.add_anchor(bytes.fromhex(step["anchor"]), QUALIFICATION)
    control.put(statement_sealed, statement)
    stored = control.put(sealed, body)
    point = instance("P")
    pep_id = control.enroll(point.public_raw, "host", STREAM)
    control.offer("default", STREAM, 1)
    state = os.path.join(directory, "python_host")
    host = PolicyHost(state, [], dict(QUALIFICATION), instance_key=point)
    pep = Pep(state, HostAdapter(host), point, lambda: NOW)
    pep.confirm(pep.provision(bytes.fromhex(step["anchor"])))
    pep.stage(statement_sealed, statement)
    pep.stage(sealed, body)
    receives = [control.receive(record) for record in pep.drain()]
    control.commit("default")
    pep.commit(STREAM, 1, canon.sha256_hex(body))
    records = pep.drain()
    receives += [control.receive(record) for record in records]
    out = {"public": point.public_raw.hex(), "records": [record.hex() for record in records],
           "findings_filed": receives, "rollout": control.rollouts[-1].state, "envelope_id": stored.envelope_id,
           "host_active": host.active()["active"], "findings": findings(control)}
print(json.dumps(out))
"#;

struct Python {
    python: String,
    repo: String,
    dir: common::Scratch,
}

impl Python {
    fn new(what: &str) -> Option<Python> {
        let repo = format!("{}/..", env!("CARGO_MANIFEST_DIR"));
        let python = common::python_for_cross_language(&repo, what)?;
        Some(Python { python, repo, dir: common::Scratch::new("dist_cross") })
    }

    fn run(&self, step: Value) -> Value {
        let mut step = step;
        step["dir"] = json!(self.dir.to_str().unwrap());
        let input = self.dir.join("step.json");
        std::fs::write(&input, step.to_string()).unwrap();
        let out = std::process::Command::new(&self.python)
            .arg("-c")
            .arg(PYTHON)
            .env("PP_REPO", &self.repo)
            .env("PP_IN", &input)
            .output()
            .expect("run the Python half");
        assert!(out.status.success(), "the Python half failed: {}", String::from_utf8_lossy(&out.stderr));
        serde_json::from_slice(&out.stdout).unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&out.stdout)))
    }
}

fn hex_of(records: &[Vec<u8>]) -> Vec<String> {
    records.iter().map(hex::encode).collect()
}

/// The Rust host PEP with a release Python sealed committed, every record accepted by the Python controller.
struct Committed {
    pep: Pep<HostAdapter>,
    instance: ed25519_dalek::SigningKey,
    pep_id: String,
    now: Rc<Cell<i64>>,
}

fn rust_commits_what_python_sealed(python: &Python) -> Committed {
    let instance = test_key("R1");
    let offered = python.run(json!({"op": "python_seals", "rust_public": hex::encode(instance.verifying_key().to_bytes())}));
    let pep_id = offered["pep"].as_str().unwrap().to_string();
    assert_eq!(pep_id, hex::encode(state_record::pep_id(&instance.verifying_key().to_bytes())));
    let decode = |name: &str| hex::decode(offered[name].as_str().unwrap()).unwrap();
    let (anchor, sealed, body) = (decode("anchor"), decode("sealed"), decode("body"));
    let (statement_sealed, statement) = (decode("statement_sealed"), decode("statement"));
    assert_eq!(body, image(5), "Python compiles the image the corpus carries");

    let state = python.dir.join("rust_host");
    let host = PolicyHost::new(state.to_str().unwrap(), Vec::new(), offered["qualification"].clone(), Vec::new()).unwrap();
    let now = Rc::new(Cell::new(NOW));
    let mut pep = Pep::new(state.to_str().unwrap(), HostAdapter::new(host), instance.clone(), clock_of(&now), REFUSE, true).unwrap();
    let fingerprint = pep.provision(&anchor).unwrap();
    assert_eq!(fingerprint, h(&anchor));
    pep.confirm(&fingerprint).unwrap();
    for (sealed, body) in [(&statement_sealed, &statement), (&sealed, &body)] {
        let staged = state_record::read(&pep.stage(sealed, body).unwrap(), &instance.verifying_key().to_bytes()).unwrap();
        assert_eq!(staged.event, "staged");
    }

    let first = python.run(json!({"op": "receive_and_commit", "records": hex_of(&pep.drain()), "pep": pep_id}));
    assert_eq!(first["findings_filed"], json!([null, null, null]), "{first}");
    assert_eq!(first["member_state"], json!("committing"));
    let commit = &first["commit"][0];
    assert_eq!((commit["stream"].clone(), commit["seq"].clone()), (json!(STREAM), json!(1)));
    let policy = Hex64::try_from(commit["policy"].as_str().unwrap()).unwrap();
    assert_eq!(policy, h(&body));

    let committed = state_record::read(&pep.commit(STREAM, 1, &policy, 0).unwrap(), &instance.verifying_key().to_bytes()).unwrap();
    assert_eq!((committed.event, committed.state, committed.active_seq), ("committed", "active", 1));
    let last = python.run(json!({"op": "receive", "records": hex_of(&pep.drain()), "pep": pep_id}));
    assert_eq!(last["findings_filed"], json!([null]), "{last}");
    assert_eq!(last["findings"][&pep_id], json!({}));
    assert_eq!((last["rollout"].clone(), last["member_state"].clone()), (json!("committed"), json!("committed")));
    assert_eq!(last["last"]["event"], json!("committed"));
    assert_eq!(last["last"]["policy"], json!(&h(&body).as_str()[..32]));
    assert_eq!(last["expected"][0], json!(h(&body).as_str()));
    assert_eq!(pep.adapter.host.active_info()["active"], json!(h(&body).as_str()));
    Committed { pep, instance, pep_id, now }
}

/// case_052, case_085: a release Python sealed and its controller offers is committed by the Rust host PEP, and the
/// Python controller accepts each record the Rust PEP signed, the staged ack, the commit's record and the
/// expectation it then holds of the PEP among them.
#[test]
fn a_release_python_sealed_is_committed_by_the_rust_host_and_its_records_are_accepted() {
    let Some(python) = Python::new("the Rust host PEP against the Python controller") else { return };
    rust_commits_what_python_sealed(&python);
    println!("cross-language distribution: the Python controller accepted the Rust host PEP's records");
}

/// case_052, case_085: the reverse. A release the Rust writer sealed under an anchor the Rust writer wrote is stored by
/// the Python controller and committed by the Python host PEP, the controller accepts its records, and each
/// record reads in Rust under the Python PEP's instance key with the fields the commit set.
#[test]
fn a_release_rust_sealed_is_committed_by_the_python_host_and_its_records_read_in_rust() {
    let Some(python) = Python::new("the Python host PEP against the Rust writer") else { return };
    let body = image(7);
    // a first install is larger than no policy, so it says it widens and carries the owner's statement (W3, W6)
    let release = release_of(&body);
    let sealed = ppt(&body, &Args { release: Some(release.clone()), widens: true, ..at(1) });
    let statement = widening(&[]);
    let statement_args = Args { release: Some(release), policy: Some(h(&body)), widens: true, ..at(1) };
    let statement_sealed = seal(ArtifactKind::TrustWidening, &statement, &statement_args);
    let anchor = anchor_of(&["A"]);
    let done = python.run(json!({"op": "python_commits", "anchor": hex::encode(&anchor), "sealed": hex::encode(&sealed),
                                 "body": hex::encode(&body), "statement_sealed": hex::encode(&statement_sealed),
                                 "statement": hex::encode(&statement)}));
    assert_eq!(done["envelope_id"], json!(env::envelope_id(env::unseal(&sealed).unwrap().0).as_str()));
    assert!(done["findings_filed"].as_array().unwrap().iter().all(Value::is_null), "{done}");
    assert_eq!(done["rollout"], json!("committed"));
    assert_eq!(done["host_active"], json!(h(&body).as_str()));
    let public: [u8; 32] = hex::decode(done["public"].as_str().unwrap()).unwrap().try_into().unwrap();
    assert_eq!(public, dist::public("P"));
    let records: Vec<_> = done["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|record| state_record::read(&hex::decode(record.as_str().unwrap()).unwrap(), &public).unwrap())
        .collect();
    let committed = records.last().unwrap();
    assert_eq!((committed.event, committed.state, committed.active_seq, committed.floor), ("committed", "active", 1, 1));
    assert_eq!(committed.active_policy, state_record::prefix(Some(h(&body).as_str())));
    assert_eq!(committed.active_release, state_record::prefix(Some(env::release_id(&[(ArtifactKind::PolicyPpt, h(&body))]).unwrap().as_str())));
    assert_eq!(committed.stream, state_record::stream_prefix(STREAM));
    assert_eq!(committed.pep_id, state_record::pep_id(&public));
    let mut changed = hex::decode(done["records"][0].as_str().unwrap()).unwrap();
    changed[30] ^= 1;
    assert_eq!(state_record::read(&changed, &public).unwrap_err().cause, "fleet:state-invalid");
    println!("cross-language distribution: Rust read the Python host PEP's records of a release Rust sealed");
}

/// case_046, case_077: a refused record and a lapsed record of the Rust host PEP reach the Python controller, which
/// accepts both as signed by the PEP it enrolled. It files nothing for the refusal, which leaves the release it
/// expects active, and files the lapse as the policy mismatch it is.
#[test]
fn a_refused_and_a_lapsed_record_of_the_rust_host_reach_the_python_controller() {
    let Some(python) = Python::new("the Rust host PEP's refusal and lapse against the Python controller") else { return };
    let Committed { mut pep, instance, pep_id, now } = rust_commits_what_python_sealed(&python);
    let public_key = instance.verifying_key().to_bytes();
    let unknown = ppt(&image(7), &by(2, "U"));
    let refused = state_record::read(&pep.stage(&unknown, &image(7)).unwrap(), &public_key).unwrap();
    assert_eq!((refused.event, refused.cause.as_deref()), ("refused", Some("dist:unknown-key")));
    let first = python.run(json!({"op": "receive", "records": hex_of(&pep.drain()), "pep": pep_id}));
    assert_eq!(first["findings_filed"], json!([null]), "{first}");
    assert_eq!((first["last"]["event"].clone(), first["last"]["cause"].clone()), (json!("refused"), json!("dist:unknown-key")));
    now.set(EXPIRES);
    let lapsed = state_record::read(&pep.tick().unwrap().unwrap(), &public_key).unwrap();
    assert_eq!((lapsed.event, lapsed.cause.as_deref(), lapsed.state), ("lapsed", Some("dist:expired"), "no-policy"));
    let second = python.run(json!({"op": "receive", "records": hex_of(&pep.drain()), "pep": pep_id}));
    assert_eq!(second["findings_filed"], json!(["fleet:policy-mismatch"]), "{second}");
    let last = &second["last"];
    assert_eq!((last["event"].clone(), last["cause"].clone(), last["state"].clone()), (json!("lapsed"), json!("dist:expired"), json!("no-policy")));
    let findings = second["findings"][&pep_id].as_object().unwrap();
    assert!(!findings.contains_key("fleet:state-invalid") && !findings.contains_key("fleet:state-replay"), "{second}");
    println!("cross-language distribution: the Python controller accepted the Rust host PEP's refused and lapsed records");
}
