// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The Rust enforcement point machine with the host adapter (spec-policy-distribution.md, sections 5, 6, 9,
//! 10, 11, 12, 14, 15 and 17), step by step as `prismpath/tests/test_distribution_pep.py` and its siblings
//! run the Python machine. Each test names the conformance case of section 20 it covers. A restart is a
//! fresh `Pep` over the same state directory, and a death in a commit is the commit hook stopping a step.

#[path = "common/mod.rs"]
mod common;
#[path = "common/dist.rs"]
mod dist;

use dist::*;
use prismpath_hotswap_rs::dist::envelope as env;
use prismpath_hotswap_rs::dist::pep::{Adapter, HostAdapter, Pep, PepError, PepStep, Release, HOLD, REFUSE};
use prismpath_hotswap_rs::dist::state_record::{self, StateRecord};
use prismpath_hotswap_rs::dist::trust::TrustStore;
use prismpath_hotswap_rs::dist::{ArtifactKind, Hex64, Stream, TargetKind};
use prismpath_hotswap_rs::host::{CommitStep, PolicyHost};
use prismpath_rs::canon2;
use serde_json::json;
use std::cell::Cell;
use std::rc::Rc;

/// The state record a call on the point's PEP returned, read under its instance key.
macro_rules! rec {
    ($point:ident, $call:expr) => {{
        let signed = $call.unwrap();
        $point.read(&signed)
    }};
}

fn old() -> Vec<u8> {
    image(5)
}

fn new() -> Vec<u8> {
    image(7)
}

fn newer() -> Vec<u8> {
    image(9)
}

fn event_cause(record: &StateRecord) -> (&'static str, Option<&str>) {
    (record.event, record.cause.as_deref())
}

fn prefix(hash: &Hex64) -> [u8; 16] {
    state_record::prefix(Some(hash.as_str()))
}

/// case_016: K1, X3. After the trust store becomes unreadable the restarted PEP refuses every envelope with
/// dist:unknown-key, refuses every decision and its host holds no policy.
#[test]
fn case_016_an_unreadable_trust_store_decides_nothing() {
    let mut point = Point::new("016");
    point.commit_at(&old(), 1);
    let trust = point.pep.store_path("trust.json");
    std::fs::OpenOptions::new().write(true).open(&trust).unwrap().set_len(10).unwrap();
    point.reopen();
    assert_eq!((point.pep.state(), point.pep.refusal()), ("no-policy", Some("dist:policy-lapsed")));
    assert_eq!(point.host_active(), json!(null));
    assert_eq!(point.stage(&ppt(&new(), &at(2)), &new()).cause.as_deref(), Some("dist:unknown-key"));
    assert_eq!(point.pep.decide(|| "allow").unwrap().cause, Some("dist:policy-lapsed"));
    assert_eq!(rec!(point, point.pep.commit(STREAM, 2, &h(&new()), 0)).cause.as_deref(), Some("dist:unknown-key"));
}

/// case_017: K2. At provisioning, and at a later start over a store that trusts it.
#[test]
fn case_017_an_instance_key_that_is_a_trusted_key_is_refused_at_start() {
    assert!(matches!(Point::with("017a", test_key("A"), &["A"], REFUSE), Err(PepError::Refused(_))));
    let mut point = Point::with("017b", test_key("I"), &["A", "B"], REFUSE).unwrap();
    point.key = test_key("B");
    assert!(matches!(point.open(), Err(PepError::Refused(_))));
}

/// case_023: Q4, RB1, A1. The kept release carries a widening statement, so the rollback is not a silent
/// widening (RB3).
#[test]
fn case_023_a_rollback_and_an_abort_leave_the_floor_where_it_was() {
    let mut point = Point::new("023");
    let release = release_of(&old());
    point.stage(&ppt(&old(), &Args { release: Some(release.clone()), ..at(1) }), &old());
    let statement = widening(&[]);
    let args = Args { release: Some(release), policy: Some(h(&old())), ..at(1) };
    assert_eq!(point.stage(&seal(ArtifactKind::TrustWidening, &statement, &args), &statement).event, "staged");
    point.pep.commit(STREAM, 1, &h(&old()), 0).unwrap();
    point.commit_at(&new(), 2);
    let record = rec!(point, point.pep.rollback());
    assert_eq!((record.event, record.active_seq, record.floor), ("rolled-back", 1, 2));
    assert_eq!((point.host_active(), point.pep.floor().seq), (json!(h(&old()).as_str()), 2));
    point.stage(&ppt(&newer(), &at(3)), &newer());
    point.pep.abort(STREAM, 3, &h(&newer())).unwrap();
    point.reopen();
    assert_eq!((point.pep.floor().seq, point.pep.active().unwrap().seq), (2, 1));
    assert!(point.pep.previous().is_none());
    assert_eq!(point.stage(&ppt(&new(), &at(2)), &new()).event, "beat"); // Q3, at the floor
    assert_eq!(point.stage(&ppt(&old(), &at(1)), &old()).cause.as_deref(), Some("dist:seq-replay"));
}

/// case_024: Q5, X3.
#[test]
fn case_024_a_floor_that_cannot_be_read_locks_the_pep() {
    let mut point = Point::new("024");
    point.commit_at(&old(), 1);
    std::fs::write(point.pep.store_path("floor.json"), b"{").unwrap();
    point.reopen();
    assert_eq!((point.pep.state(), point.pep.refusal()), ("locked", Some("dist:floor-lost")));
    assert_eq!(point.host_active(), json!(null));
    assert_eq!(point.stage(&ppt(&new(), &at(2)), &new()).cause.as_deref(), Some("dist:floor-lost"));
    assert_eq!(rec!(point, point.pep.commit(STREAM, 1, &h(&old()), 0)).cause.as_deref(), Some("dist:floor-lost"));
    assert_eq!(rec!(point, point.pep.record("beat", None)).state, "locked");
}

/// case_026: T1, V13. The time floor is durable, so a restart with the clock set back still refuses.
#[test]
fn case_026_a_clock_set_back_cannot_bring_an_expired_envelope_back() {
    let mut point = Point::new("026");
    let late = EXPIRES - 100;
    point.now.set(late);
    point.stage(&ppt(&old(), &Args { not_before: late, ..at(1) }), &old());
    point.now.set(NOW);
    let early = ppt(&new(), &Args { expires: late - 10, ..at(2) });
    assert_eq!(point.stage(&early, &new()).cause.as_deref(), Some("dist:expired"));
    point.reopen();
    assert_eq!(point.stage(&early, &new()).cause.as_deref(), Some("dist:expired"));
}

/// case_031: B2, R3. The trust store on disk already holds it when the PEP reports `trust-applied`.
#[test]
fn case_031_a_revocation_is_applied_when_it_verifies_with_no_commit() {
    let mut point = Point::new("031");
    let record = point.revoke(1, &revocation(&[], &[key_id("B")], &[], &[]));
    assert_eq!((record.event, record.cause.as_deref(), record.trust_seq), ("trust-applied", None, 1));
    let on_disk = TrustStore::load(&point.pep.store_path("trust.json"));
    assert_eq!(on_disk.trust_seq, 1);
    assert!(on_disk.revoked_keys.contains(&key_id("B")));
    assert!(point.actions().contains(&"trust-applied".to_string()));
    point.reopen();
    assert_eq!(point.pep.trust().revoked_keys, on_disk.revoked_keys);
}

/// case_043: E7, V10.
#[test]
fn case_043_another_policy_at_the_staged_seq_is_incomplete() {
    let mut point = Point::new("043");
    point.stage(&ppt(&old(), &at(1)), &old());
    let other = ppt(&old(), &Args { policy: Some(Hex64::try_from("ab".repeat(32)).unwrap()), ..at(1) });
    assert_eq!(point.stage(&other, &old()).cause.as_deref(), Some("dist:incomplete"));
    assert_eq!(point.pep.staged().unwrap().policy_sha256, h(&old()));
}

/// case_046: G1.
#[test]
fn case_046_staged_and_refused_are_acked_and_in_the_audit_log() {
    let mut point = Point::new("046");
    let record = point.stage(&ppt(&old(), &at(1)), &old());
    assert_eq!((record.event, record.staged, record.staged_seq, record.cause.as_deref()), ("staged", true, 1, None));
    let refused = point.stage(&ppt(&new(), &by(2, "U")), &new());
    assert_eq!(event_cause(&refused), ("refused", Some("dist:unknown-key")));
    let events: Vec<(String, Option<String>)> = point
        .pep
        .audit
        .events()
        .iter()
        .filter(|event| event["action"] == "staged" || event["action"] == "refused")
        .map(|event| (event["action"].as_str().unwrap().to_string(), event["data"]["cause"].as_str().map(str::to_string)))
        .collect();
    assert_eq!(events, vec![("staged".to_string(), None), ("refused".to_string(), Some("dist:unknown-key".to_string()))]);
    point.reopen();
    assert_eq!(point.pep.staged().unwrap().seq, 1); // durable before the ack
}

/// case_047: G2.
#[test]
fn case_047_a_higher_seq_replaces_the_staged_release_and_a_lower_one_is_refused() {
    let mut point = Point::new("047");
    point.stage(&ppt(&old(), &at(2)), &old());
    assert_eq!(point.stage(&ppt(&new(), &at(3)), &new()).staged_seq, 3);
    assert_eq!(point.stage(&ppt(&old(), &at(2)), &old()).cause.as_deref(), Some("dist:seq-replay"));
    assert_eq!(point.pep.staged().unwrap().seq, 3);
    assert!(point.pep.blob(&h(&old())).is_none()); // the replaced release's blobs went
}

/// case_048: C1.
#[test]
fn case_048_a_commit_that_names_nothing_staged() {
    let mut point = Point::new("048");
    let record = rec!(point, point.pep.commit(STREAM, 1, &h(&old()), 0));
    assert_eq!((record.cause.as_deref(), record.state), (Some("dist:not-staged"), "no-policy"));
    point.stage(&ppt(&old(), &at(1)), &old());
    assert_eq!(rec!(point, point.pep.commit(STREAM, 1, &h(&new()), 0)).cause.as_deref(), Some("dist:not-staged"));
    assert!(point.pep.staged().is_some());
}

/// case_050: C3. The revoked half stands for a revocation applied after staging, as the store holds it.
#[test]
fn case_050_a_staged_release_that_expires_or_is_revoked_before_its_commit_is_dropped() {
    let mut point = Point::new("050");
    point.stage(&ppt(&old(), &Args { expires: NOW + 10, ..at(1) }), &old());
    point.now.set(NOW + 10);
    assert_eq!(rec!(point, point.pep.commit(STREAM, 1, &h(&old()), 0)).cause.as_deref(), Some("dist:expired"));
    assert!(point.pep.staged().is_none());
    point.stage(&ppt(&new(), &at(2)), &new());
    let mut trust = point.pep.trust().clone();
    trust.revoked_policies.insert(h(&new()));
    point.pep.replace_trust(trust);
    assert_eq!(rec!(point, point.pep.commit(STREAM, 2, &h(&new()), 0)).cause.as_deref(), Some("dist:revoked"));
    assert!(point.pep.staged().is_none());
    assert_eq!(point.pep.state(), "no-policy");
}

/// Where case 51 kills a commit: the machine's own steps, and the host's steps inside its install.
#[derive(Debug, Clone, Copy)]
enum Death {
    Pep(PepStep),
    Host(CommitStep),
}

const BEFORE_FLIP: [PepStep; 4] = [PepStep::Intent, PepStep::Floor, PepStep::Evidence, PepStep::ActiveRecord];

/// The restarted PEP and its host hold one release, the expected one, and nothing else is active.
fn one_policy(point: &mut Point, seq: i64) {
    point.reopen();
    let body = if seq == 1 { old() } else { new() };
    let active = point.pep.active().expect("a release is active");
    assert_eq!((point.pep.state(), active.seq), ("active", seq));
    assert_eq!(active.bodies[&ArtifactKind::PolicyPpt], body);
    let host = point.pep.adapter.host.active_info();
    assert_eq!((host["active"].clone(), host["version"].clone()), (json!(h(&body).as_str()), json!(seq)));
    assert!(!std::path::Path::new(&point.pep.store_path("pending.json")).exists());
}

/// case_051: C4. Killed before the active record flips, the old release is active after a restart and the commit
/// can be made again. Killed after, the new release is active, and the host's own record follows the PEP's,
/// whatever step of its own install died.
#[test]
fn case_051_a_commit_killed_at_each_step_leaves_one_policy() {
    let deaths = PepStep::ALL.iter().map(|step| Death::Pep(*step)).chain(CommitStep::ALL.iter().map(|step| Death::Host(*step)));
    for death in deaths {
        let mut point = Point::new("051");
        point.commit_at(&old(), 1);
        point.stage(&ppt(&new(), &at(2)), &new());
        match death {
            Death::Pep(step) => point.pep.set_commit_hook(Some(Box::new(move |at| if at == step { Err("died".into()) } else { Ok(()) }))),
            Death::Host(step) => point
                .pep
                .adapter
                .host
                .set_commit_hook(Some(Box::new(move |at| if at == step { Err("died".into()) } else { Ok(()) }))),
        }
        assert!(point.pep.commit(STREAM, 2, &h(&new()), 0).is_err(), "{death:?}");
        let before_flip = matches!(death, Death::Pep(step) if BEFORE_FLIP.contains(&step));
        one_policy(&mut point, if before_flip { 1 } else { 2 });
        let incomplete = point.actions().iter().filter(|action| *action == "commit_incomplete").count();
        let intent_written = before_flip && !matches!(death, Death::Pep(PepStep::Intent));
        assert_eq!(incomplete, usize::from(intent_written), "{death:?}");
        if before_flip {
            assert_eq!(point.pep.staged().unwrap().seq, 2, "{death:?}");
            let record = rec!(point, point.pep.commit(STREAM, 2, &h(&new()), 0));
            assert_eq!((record.event, record.active_seq), ("committed", 2), "{death:?}");
            one_policy(&mut point, 2);
        }
    }
}

/// case_052: C5, H4.
#[test]
fn case_052_a_commit_reports_committed_with_the_new_hash() {
    let mut point = Point::new("052");
    let record = point.commit_at(&old(), 1);
    assert_eq!((record.event, record.state, record.active_seq, record.floor), ("committed", "active", 1, 1));
    assert_eq!(record.active_policy, prefix(&h(&old())));
    assert!(!record.staged);
    assert_eq!(record.active_release, prefix(&point.pep.active().unwrap().release));
    assert_eq!(point.host_active(), json!(h(&old()).as_str()));
}

/// case_053: A1.
#[test]
fn case_053_an_abort_drops_the_staged_release_and_an_abort_for_another_changes_nothing() {
    let mut point = Point::new("053");
    point.commit_at(&old(), 1);
    point.stage(&ppt(&new(), &at(2)), &new());
    assert_eq!(rec!(point, point.pep.abort(STREAM, 3, &h(&new()))).event, "beat");
    assert!(point.pep.staged().is_some());
    let record = rec!(point, point.pep.abort(STREAM, 2, &h(&new())));
    assert_eq!((record.event, record.staged, record.active_seq, record.floor), ("aborted", false, 1, 1));
    assert!(point.actions().contains(&"aborted".to_string()));
    point.reopen();
    assert!(point.pep.staged().is_none());
}

/// case_066: R1. One above the trust sequence is applied, the same again changes nothing, an older one and one
/// that skips a number are dist:trust-replay.
#[test]
fn case_066_a_revocation_is_taken_at_the_next_trust_sequence_only() {
    let mut point = Point::new("066");
    let first = revocation(&[], &[key_id("B")], &[], &[]);
    let sealed = trust_statement(ArtifactKind::TrustRevocation, &first, 1, &["A"], &[TargetKind::Host]);
    assert_eq!(point.stage(&sealed, &first).event, "trust-applied");
    let again = point.stage(&sealed, &first);
    assert_eq!((again.event, again.trust_seq), ("beat", 1));
    point.revoke(2, &first);
    assert_eq!(point.revoke(1, &first).cause.as_deref(), Some("dist:trust-replay"));
    assert_eq!(point.revoke(4, &first).cause.as_deref(), Some("dist:trust-replay"));
    assert_eq!(point.pep.trust().trust_seq, 2);
}

/// case_069: R5. The active envelope, the active policy hash, the only key that signed it, or a floor above its
/// seq: each time the PEP goes to no-policy with event lapsed and dist:revoked, and a staged release on the same
/// ground is dropped.
#[test]
fn case_069_a_revocation_that_removes_the_active_releases_ground_lapses_it() {
    for ground in ["envelope", "policy", "key", "floor"] {
        let mut point = Point::with(&format!("069_{ground}"), test_key("I"), &["A", "B"], REFUSE).unwrap();
        point.commit(&old(), &by(3, "B"));
        let staged = ppt(&old(), &by(4, "B"));
        point.stage(&staged, &old());
        let active_id = point.pep.active().unwrap().held[&ArtifactKind::PolicyPpt].envelope_id.clone();
        let staged_id = env::envelope_id(env::unseal(&staged).unwrap().0);
        let body = match ground {
            "envelope" => revocation(&[active_id, staged_id], &[], &[], &[]),
            "policy" => revocation(&[], &[], &[h(&old())], &[]),
            "key" => revocation(&[], &[key_id("B")], &[], &[]),
            _ => revocation(&[], &[], &[], &[(STREAM, 5)]),
        };
        point.pep.drain();
        point.revoke(1, &body);
        let sent: Vec<(&str, Option<String>)> =
            point.pep.drain().iter().map(|data| point.read(data)).map(|record| (record.event, record.cause)).collect();
        assert_eq!(sent, vec![("lapsed", Some("dist:revoked".to_string())), ("trust-applied", None)], "{ground}");
        assert_eq!(point.pep.state(), "no-policy", "{ground}");
        assert!(point.pep.staged().is_none(), "{ground}");
        assert_eq!(point.host_active(), json!(null), "{ground}");
        point.reopen();
        assert_eq!(point.pep.state(), "no-policy", "{ground}");
    }
}

/// case_070: R6. The list is dist:trust-replay and is not applied, and the key is still refused.
#[test]
fn case_070_a_later_list_that_drops_a_key_is_refused() {
    let mut point = Point::with("070", test_key("I"), &["A", "B"], REFUSE).unwrap();
    point.revoke(1, &revocation(&[], &[key_id("B")], &[], &[]));
    assert_eq!(point.revoke(2, &revocation(&[], &[], &[], &[])).cause.as_deref(), Some("dist:trust-replay"));
    assert_eq!(point.pep.trust().trust_seq, 1);
    assert!(point.pep.trust().revoked_keys.contains(&key_id("B")));
    assert_eq!(point.stage(&ppt(&new(), &by(1, "B")), &new()).cause.as_deref(), Some("sig:revoked-key"));
}

/// case_072: O1, O2, O3. Applied with no commit and durable before it is reported, then a pack signed only by the
/// new key commits.
#[test]
fn case_072_a_rotation_signed_by_the_old_and_the_new_key_then_a_pack_under_the_new_key() {
    let mut point = Point::new("072");
    let record = point.rotate(1, "B", None);
    assert_eq!((record.event, record.trust_seq), ("trust-applied", 1));
    assert!(TrustStore::load(&point.pep.store_path("trust.json")).keys.contains_key(&key_id("B")));
    assert_eq!(point.commit(&old(), &by(1, "B")).event, "committed");
}

/// case_073: O3, S5. Also the retired half of case 13.
#[test]
fn case_073_a_retired_key_no_longer_counts_and_its_active_release_keeps_deciding() {
    let mut point = Point::new("073");
    point.commit(&old(), &by(1, "A"));
    assert_eq!(point.rotate(1, "B", Some("A")).event, "trust-applied");
    assert!(point.pep.trust().retired.contains(&key_id("A")));
    assert_eq!(point.stage(&ppt(&new(), &by(2, "A")), &new()).cause.as_deref(), Some("sig:revoked-key"));
    assert_eq!((point.pep.state(), point.pep.refusal()), ("active", None));
    point.reopen();
    assert_eq!(point.pep.state(), "active");
    assert_eq!(point.commit(&new(), &by(2, "B")).event, "committed");
}

/// case_077: X1, X2, X3.
#[test]
fn case_077_a_release_lapses_at_expiry_with_no_message() {
    let mut point = Point::new("077");
    point.commit_at(&old(), 1);
    point.now.set(EXPIRES - 1);
    assert!(point.pep.tick().unwrap().is_none());
    assert_eq!(point.pep.refusal(), None);
    assert_eq!(point.pep.decide(|| "allow").unwrap().decision, Some("allow"));
    point.now.set(EXPIRES);
    let record = rec!(point, point.pep.tick().unwrap());
    assert_eq!((record.event, record.cause.as_deref(), record.state), ("lapsed", Some("dist:expired"), "no-policy"));
    assert_eq!(point.pep.refusal(), Some("dist:policy-lapsed"));
    assert_eq!(point.pep.decide(|| "allow").unwrap().cause, Some("dist:policy-lapsed"));
    assert_eq!(point.host_active(), json!(null));
    point.reopen();
    assert_eq!(point.pep.state(), "no-policy");
    assert!(point.pep.tick().unwrap().is_none());
}

/// case_079: X4, E5. A trust envelope with expires other than 0 is bad format, and a revocation made ten years
/// before it is read is applied.
#[test]
fn case_079_a_trust_envelope_never_expires() {
    let mut point = Point::new("079");
    let body = revocation(&[], &[key_id("B")], &[], &[]);
    let doc = json!({"artifact": "trust.revocation", "body_sha256": h(&body).as_str(), "body_size": body.len(),
                     "encoding": "canon/2", "expires": NOW + 1, "format": "prismpath.dist/1", "meta": {},
                     "not_before": NOW - 10 * 365 * 86400, "policy_sha256": Hex64::zero().as_str(),
                     "release": Hex64::zero().as_str(), "replaces": "", "seq": 1, "stream": "@trust",
                     "targets": ["host"], "widens": false});
    let expiring = env::seal(&canon2::write_json(&doc).unwrap(), &[test_key("A")]).unwrap();
    assert_eq!(point.stage(&expiring, &body).cause.as_deref(), Some("dist:bad-format"));
    let mut lasting = doc.clone();
    lasting["expires"] = json!(0);
    let lasting = env::seal(&canon2::write_json(&lasting).unwrap(), &[test_key("A")]).unwrap();
    assert_eq!(point.stage(&lasting, &body).event, "trust-applied");
}

/// case_082: P1. No message installs a first key.
#[test]
fn case_082_a_pep_with_an_empty_trust_store_takes_no_rotation() {
    let scratch = common::Scratch::new("dist_pep_082");
    let now = Rc::new(Cell::new(NOW));
    let key = test_key("I");
    let mut pep = open_pep(&scratch.join("host"), &now, &key, &["A"], REFUSE, false).unwrap();
    let body = rotation("B", None);
    let sealed = trust_statement(ArtifactKind::TrustRotation, &body, 1, &["B"], &[TargetKind::Host]);
    let record = state_record::read(&pep.stage(&sealed, &body).unwrap(), &key.verifying_key().to_bytes()).unwrap();
    assert_eq!(record.cause.as_deref(), Some("dist:unknown-key"));
    assert!(!std::path::Path::new(&pep.store_path("trust.json")).exists());
    assert!(pep.trust().keys.is_empty());
}

/// case_084: P3, Q5. Provisioning starts the trust store, the floor and the time floor again, and is its own event
/// in the audit log.
#[test]
fn case_084_provisioning_unlocks_a_locked_pep() {
    let mut point = Point::new("084");
    point.commit_at(&old(), 4);
    std::fs::write(point.pep.store_path("floor.json"), b"").unwrap();
    point.reopen();
    assert_eq!(point.pep.state(), "locked");
    let fingerprint = point.pep.provision(&point.anchor()).unwrap();
    let record = rec!(point, point.pep.confirm(&fingerprint));
    assert_eq!((record.event, record.state, record.floor), ("provisioned", "no-policy", 0));
    assert!(point.actions().contains(&"provisioned".to_string()));
    assert_eq!(point.pep.refusal(), Some("dist:policy-lapsed"));
    point.reopen();
    assert_eq!(point.pep.state(), "no-policy");
}

/// A record of every field, signed by the instance key I.
fn full_record() -> StateRecord {
    StateRecord {
        cause: None,
        pep_id: state_record::pep_id(&public("I")),
        counter: 7,
        time: 1_800_000_000,
        epoch: 9,
        stream: state_record::stream_prefix(STREAM),
        active_policy: prefix(&h(b"policy")),
        active_release: prefix(&h(b"release")),
        active_seq: 3,
        floor: 3,
        staged_release: prefix(&h(b"staged")),
        staged_seq: 4,
        trust_seq: 2,
        staged: true,
        dev_build: false,
        held: false,
        body: b"facet".to_vec(),
        extensions: vec![1, 0, 0],
        ..StateRecord::new("committed", "active")
    }
}

/// case_085: H1, H2, H6. Every field comes back, the layout is H1's, and any changed byte, a record of another PEP
/// and a record under another key are fleet:state-invalid.
#[test]
fn case_085_a_state_record_round_trips_and_a_changed_byte_is_invalid() {
    let (key, record) = (test_key("I"), full_record());
    let signed = state_record::build(&record, &key).unwrap();
    assert_eq!(state_record::read(&signed, &public("I")).unwrap(), record);
    assert_eq!((&signed[..4], signed[4], signed[5], signed[6]), (&b"PPSR"[..], 1, 3, 0x81));
    assert_eq!(&signed[24..32], &7u64.to_le_bytes());
    assert_eq!(&signed[40..48], &9u64.to_le_bytes());
    assert_eq!(&signed[144..146], &5u16.to_le_bytes());
    assert_eq!(signed.len(), 144 + 2 + 5 + 2 + 3 + 64);
    for index in 0..signed.len() {
        let mut changed = signed.clone();
        changed[index] ^= 0x01;
        assert_eq!(state_record::read(&changed, &public("I")).unwrap_err().cause, "fleet:state-invalid", "byte {index}");
    }
    let other = test_key("J");
    let by_other = state_record::build(&record, &other).unwrap();
    for (data, public_key) in [
        (signed.clone(), public("J")),
        (by_other, public("J")),
        (signed[..signed.len() - 1].to_vec(), public("I")),
        ([signed.as_slice(), &[0]].concat(), public("I")),
    ] {
        assert_eq!(state_record::read(&data, &public_key).unwrap_err().cause, "fleet:state-invalid");
    }
    let refused = StateRecord { cause: Some("dist:expired".to_string()), pep_id: record.pep_id, ..StateRecord::new("refused", "no-policy") };
    let signed = state_record::build(&refused, &key).unwrap();
    assert_eq!(state_record::read(&signed, &public("I")).unwrap().cause.as_deref(), Some("dist:expired"));
    assert!(state_record::build(&StateRecord::new("refused", "no-policy"), &key).is_err());
}

/// case_101: L2. A valid ppt-pack/1 with a higher version, swapped into the host the PEP follows.
#[test]
fn case_101_a_pep_that_committed_refuses_the_older_pack_form() {
    let mut point = Point::new("101");
    point.commit_at(&old(), 1);
    let keys = point.scratch.join("keys");
    let (private, public_path, _) = prismpath_hotswap_rs::keygen(keys.to_str().unwrap(), "authority").unwrap();
    let ppt_path = point.scratch.join("policy.ppt");
    std::fs::write(&ppt_path, new()).unwrap();
    let fields = [("x".to_string(), "int".to_string())].into_iter().collect();
    prismpath_hotswap_rs::build_pack(ppt_path.to_str().unwrap(), &fields, 99, "dist-demo", &private, &public_path, "2026-01-01T00:00:00+00:00")
        .unwrap();
    let host = PolicyHost::new(point.state_dir().to_str().unwrap(), vec![public_path], qualification(), Vec::new()).unwrap();
    assert_eq!(host.swap(ppt_path.to_str().unwrap(), false).unwrap(), json!({"ok": false, "reasons": ["dist:legacy-refused"]}));
    assert_eq!(host.rollback().unwrap(), json!({"ok": false, "reasons": ["dist:legacy-refused"]}));
    assert_eq!(host.active_info()["active"], json!(h(&old()).as_str()));
    // the same pack goes in where no enforcement point was provisioned
    let fresh = point.scratch.join("fresh");
    let pubs = vec![keys.join("authority.pub").to_str().unwrap().to_string()];
    let plain = PolicyHost::new(fresh.to_str().unwrap(), pubs, qualification(), Vec::new()).unwrap();
    assert_eq!(plain.swap(ppt_path.to_str().unwrap(), false).unwrap()["ok"], json!(true));
}

/// A PEP of a kind with no row yet, as the agent, gateway and xdp kinds are in this crate.
struct Unbuilt(TargetKind);

impl Adapter for Unbuilt {
    fn kind(&self) -> TargetKind {
        self.0
    }
    fn activate(&self, _release: &Release) -> Result<(), PepError> {
        Ok(())
    }
    fn deactivate(&self, _cause: &str) -> Result<(), PepError> {
        Ok(())
    }
}

/// case_111: X6, X10. A host has no HOLD setting, so a host PEP given one refuses to start, and so does an agent,
/// a gateway and an xdp PEP, whose kinds have no enforcement point built here.
#[test]
fn case_111_a_host_an_agent_a_gateway_and_an_xdp_pep_refuse_to_start_with_hold() {
    let error = Point::with("111", test_key("I"), &["A"], HOLD).err().expect("a host PEP with HOLD refuses to start");
    assert!(matches!(&error, PepError::Refused(text) if text.contains("HOLD")), "{error}");
    let scratch = common::Scratch::new("dist_pep_111");
    for kind in [TargetKind::Agent, TargetKind::Gateway, TargetKind::Xdp] {
        let started = Pep::new(scratch.join(kind.name()).to_str().unwrap(), Unbuilt(kind), test_key("I"), Box::new(|| NOW), HOLD, true);
        let expected = format!("no enforcement point of kind {} is built", kind.name());
        assert!(matches!(&started, Err(PepError::Refused(text)) if *text == expected), "{kind}");
    }
    // a host PEP provisioned to refuse is refused a start with HOLD later (X10)
    let point = Point::new("111_later");
    let adapter = HostAdapter::new(host_at(&point.state_dir()));
    let later = Pep::new(point.state_dir().to_str().unwrap(), adapter, test_key("I"), Box::new(|| NOW), HOLD, true);
    assert!(matches!(later, Err(PepError::Refused(_))));
}

/// case_123: O1, R1. Two above the trust sequence is dist:trust-replay, then the one it skipped is applied, then the
/// first again is applied, since it is now the next.
#[test]
fn case_123_a_rotation_that_skips_a_number_waits_for_the_one_it_skipped() {
    let mut point = Point::new("123");
    let body = rotation("Q", None);
    let second = trust_statement(ArtifactKind::TrustRotation, &body, 2, &["A", "Q"], &[TargetKind::Host]);
    assert_eq!(point.stage(&second, &body).cause.as_deref(), Some("dist:trust-replay"));
    assert_eq!(point.rotate(1, "B", None).event, "trust-applied");
    assert_eq!(point.stage(&second, &body).event, "trust-applied");
    assert_eq!(point.pep.trust().trust_seq, 2);
    assert!(point.pep.trust().keys.contains_key(&key_id("B")) && point.pep.trust().keys.contains_key(&key_id("Q")));
}

/// case_126: V11, C2. With no policy.spiral the commit is spiral:sidecar-missing, with a wrong one
/// spiral:sidecar-hash-mismatch, and with the right one it commits. A packing whose profile is not the spiral is
/// refused when it is staged.
#[test]
fn case_126_a_declared_spiral_sidecar_is_needed_and_must_be_the_declared_one() {
    let mut point = Point::new("126");
    let (sidecar, wrong) = (b"spiral sidecar bytes".to_vec(), b"another sidecar".to_vec());
    let mut meta = image_meta();
    meta["packing"] = json!({"profile": "spiral", "sidecar_sha256": h(&sidecar).as_str()});
    for (seq, spiral, cause) in [(1, None, Some("spiral:sidecar-missing")), (2, Some(&wrong), Some("spiral:sidecar-hash-mismatch")), (3, Some(&sidecar), None)] {
        let mut pairs = vec![(ArtifactKind::PolicyPpt, h(&old()))];
        if let Some(spiral) = spiral {
            pairs.push((ArtifactKind::PolicySpiral, h(spiral)));
        }
        let release = env::release_id(&pairs).unwrap();
        let args = Args { release: Some(release), policy: Some(h(&old())), ..at(seq) };
        point.stage(&ppt(&old(), &Args { meta: Some(meta.clone()), ..args.clone() }), &old());
        if let Some(spiral) = spiral {
            assert_eq!(point.stage(&seal(ArtifactKind::PolicySpiral, spiral, &args), spiral).event, "staged");
        }
        let record = rec!(point, point.pep.commit(STREAM, seq, &h(&old()), 0));
        assert_eq!(record.cause.as_deref(), cause, "seq {seq}");
    }
    let active = point.pep.active().unwrap();
    assert_eq!((active.seq, &active.bodies[&ArtifactKind::PolicySpiral]), (3, &sidecar));
    let distribution = point.pep.adapter.host.history().iter().rev().find(|event| event["action"] == "swap").unwrap()["data"]["distribution"].clone();
    assert_eq!(distribution["spiral_sha256"], json!(h(&sidecar).as_str()));
    let mut other = image_meta();
    other["packing"] = json!({"profile": "zigzag", "sidecar_sha256": h(&sidecar).as_str()});
    let zigzag = ppt(&new(), &Args { meta: Some(other), ..at(4) });
    assert_eq!(point.stage(&zigzag, &new()).cause.as_deref(), Some("packing:unknown-profile"));
}

/// case_130: R6, R8, the enforcement point's half. A list raises a floor past a revoked envelope and is applied,
/// the next list drops that envelope and is applied with the PEP holding only the latest list, and the envelope
/// sent again is dist:seq-replay, refused by the floor rather than the list. The sealing tool's and the
/// controller's half are the Python reference's.
#[test]
fn case_130_a_list_that_drops_an_envelope_a_floor_passed_holds_it_out_by_the_floor() {
    let mut point = Point::new("130");
    let sealed = ppt(&old(), &at(1));
    let revoked = env::envelope_id(env::unseal(&sealed).unwrap().0);
    point.revoke(1, &revocation(std::slice::from_ref(&revoked), &[key_id("R")], &[], &[]));
    let raised = point.revoke(2, &revocation(std::slice::from_ref(&revoked), &[key_id("R")], &[], &[(STREAM, 2)]));
    assert_eq!((raised.event, raised.floor), ("trust-applied", 2));
    let dropped = point.revoke(3, &revocation(&[], &[key_id("R")], &[], &[]));
    assert_eq!((dropped.event, dropped.trust_seq, dropped.floor), ("trust-applied", 3, 2));
    let trust = point.pep.trust();
    assert!(trust.revoked_envelopes.is_empty() && trust.revoked_keys.contains(&key_id("R")));
    assert_eq!(trust.floors[&Stream::try_from(STREAM).unwrap()], 2);
    assert_eq!(point.stage(&sealed, &old()).cause.as_deref(), Some("dist:seq-replay"));
}

/// case_134: V5, R1. A revocation whose targets names only mesh is applied by a host PEP, so the one trust
/// sequence counts the same for it as for a mesh node, and it takes the rotation naming every kind that follows.
#[test]
fn case_134_a_trust_statement_reaches_a_host_pep_whatever_its_targets() {
    let mut point = Point::new("134");
    let body = revocation(&[], &[key_id("R")], &[], &[]);
    let only_mesh = trust_statement(ArtifactKind::TrustRevocation, &body, 1, &["A"], &[TargetKind::Mesh]);
    let rotation_body = rotation("B", None);
    let every = trust_statement(ArtifactKind::TrustRotation, &rotation_body, 2, &["A", "B"], TargetKind::ALL);
    assert_eq!(point.stage(&only_mesh, &body).event, "trust-applied");
    assert_eq!(point.stage(&every, &rotation_body).event, "trust-applied");
    assert_eq!(point.pep.trust().trust_seq, 2);
    assert!(point.pep.trust().keys.contains_key(&key_id("B")));
}

/// H3, H9 and the outbox: the counter rises with every record and across a restart, the epoch only rises, and a
/// record is in the outbox once.
#[test]
fn every_record_counts_on_and_is_sent_once() {
    let mut point = Point::new("counter");
    point.pep.drain();
    point.pep.see_epoch(5).unwrap();
    point.pep.see_epoch(3).unwrap();
    let first = rec!(point, point.pep.record("beat", None));
    point.reopen();
    let second = rec!(point, point.pep.record("beat", None));
    assert!(second.counter > first.counter);
    assert_eq!((first.epoch, second.epoch), (5, 5), "H9: a restart never reports a lower epoch");
    assert_eq!(point.pep.drain().len(), 1);
    assert!(point.pep.drain().is_empty());
    let unknown = point.pep.needs(&[h(&old()), h(b"nothing")]);
    assert_eq!(unknown.len(), 2);
}

/// The host's own record follows the PEP: withdraw on a lapse holds nothing, and a host that holds the release
/// already is not installed again on a restart.
#[test]
fn the_host_follows_the_pep_and_is_not_installed_twice() {
    let mut point = Point::new("host_follows");
    point.commit_at(&old(), 1);
    let swaps = |point: &Point| point.pep.adapter.host.history().iter().filter(|event| event["action"] == "swap").count();
    assert_eq!(swaps(&point), 1);
    point.reopen();
    assert_eq!(swaps(&point), 1);
    point.pep.lapse("dist:expired").unwrap();
    assert_eq!(point.host_active(), json!(null));
    let withdrawn = point.pep.adapter.host.history().into_iter().filter(|event| event["action"] == "withdraw").count();
    assert_eq!(withdrawn, 1);
}

// ------------------------------------------------------------------ what a failure part way leaves

fn set_mode(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// X1, C4: a lapse whose record cannot be written leaves the release active and the host holding it, so the next
/// check lapses it, and the host then holds nothing.
#[test]
fn a_lapse_whose_record_cannot_be_written_lapses_at_the_next_check() {
    let mut point = Point::new("lapse_write");
    point.commit_at(&old(), 1);
    point.now.set(EXPIRES);
    let dist = point.state_dir().join("dist");
    set_mode(&dist, 0o555);
    let first = point.pep.tick();
    set_mode(&dist, 0o755);
    assert!(first.is_err(), "the record could not be written");
    assert!(point.pep.active().is_some(), "the release stays until its lapse is durable");
    let second = rec!(point, point.pep.tick().unwrap());
    assert_eq!(event_cause(&second), ("lapsed", Some("dist:expired")));
    assert_eq!(point.host_active(), json!(null));
    assert!(!std::fs::read_to_string(dist.join("active.json")).unwrap().contains("policy.ppt"));
}

/// Kill the host's install at `step` on every try until `hook` is cleared.
fn host_dies_at(point: &mut Point, step: CommitStep) {
    point.pep.adapter.host.set_commit_hook(Some(Box::new(move |at| if at == step { Err("died".into()) } else { Ok(()) })));
}

/// C4, X3: when the runtime fails inside a commit, after the active record names the new release, the PEP decides
/// nothing and sends no record until the runtime holds what it holds. Each check tries again, and once the host
/// takes the release the PEP reports it, the intent record gone.
#[test]
fn a_runtime_that_fails_inside_a_commit_is_reconciled_before_anything_is_decided_or_reported() {
    for death in ["pep_runtime", "host_evidence", "host_record"] {
        let mut point = Point::new("reconcile");
        point.commit_at(&old(), 1);
        point.stage(&ppt(&new(), &at(2)), &new());
        match death {
            "pep_runtime" => point.pep.set_commit_hook(Some(Box::new(|at| if at == PepStep::Runtime { Err("died".into()) } else { Ok(()) }))),
            "host_evidence" => host_dies_at(&mut point, CommitStep::Evidence),
            _ => host_dies_at(&mut point, CommitStep::ActiveRecord),
        }
        assert!(point.pep.commit(STREAM, 2, &h(&new()), 0).is_err(), "{death}");
        point.pep.set_commit_hook(None);
        if death != "pep_runtime" {
            // the host still fails: every decision is refused, and a beat says no-policy with the old release as
            // what the runtime may hold and the new one as not yet running
            assert_eq!(point.host_active(), json!(h(&old()).as_str()), "{death}");
            let decided = point.pep.decide(|| "allowed by the old image").unwrap();
            assert_eq!((decided.decision, decided.cause), (None, Some("dist:policy-lapsed")), "{death}");
            assert_eq!(point.pep.refusal(), Some("dist:policy-lapsed"));
            let beat = rec!(point, point.pep.record("beat", None));
            assert_eq!((beat.state, beat.active_seq, beat.staged, beat.staged_seq), ("no-policy", 1, true, 2), "{death}");
            assert_eq!(beat.active_policy, prefix(&h(&old())), "{death}");
            point.pep.adapter.host.set_commit_hook(None);
        }
        point.pep.tick().unwrap();
        let beat = rec!(point, point.pep.record("beat", None));
        assert_eq!((beat.state, beat.active_seq, beat.active_policy), ("active", 2, prefix(&h(&new()))), "{death}");
        assert_eq!(point.host_active(), json!(h(&new()).as_str()), "{death}");
        assert_eq!(point.pep.decide(|| "allowed").unwrap().decision, Some("allowed"), "{death}");
        assert!(!point.state_dir().join("dist/pending.json").exists(), "{death}");
    }
}

/// A trust anchor of `count` test keys, written by hand past the writer, which refuses more than eight.
fn anchor_with(count: usize) -> Vec<u8> {
    let names = ["A", "B", "C", "D", "E", "F", "G", "H", "J"];
    let keys: serde_json::Map<String, serde_json::Value> = names[..count]
        .iter()
        .map(|name| (key_id(name).to_string(), json!({"public": hex::encode(public(name)), "role": "authority"})))
        .collect();
    canon2::write_json(&json!({"encoding": "canon/2", "format": "prismpath.dist-trust/1", "keys": keys, "stream": STREAM,
                               "target": "host", "threshold": 1}))
    .unwrap()
}

/// K5, P2, P3: an anchor holding more keys than a trust store may is refused when it is received and when it is
/// confirmed, and a refused confirm leaves the running release, its host and its files as they were.
#[test]
fn an_anchor_beyond_the_key_bound_is_refused_and_leaves_the_running_policy() {
    use prismpath_hotswap_rs::dist::trust::{anchor_bytes, read_anchor, Role};
    let mut point = Point::new("anchor_bound");
    point.commit_at(&old(), 1);
    let nine: Vec<[u8; 32]> = ["A", "B", "C", "D", "E", "F", "G", "H", "J"].iter().map(|name| public(name)).collect();
    assert!(anchor_bytes(&nine, TargetKind::Host, &Stream::try_from(STREAM).unwrap(), &Role::authority()).is_err());
    assert!(read_anchor(&anchor_with(8)).is_ok());
    let raw = anchor_with(9);
    assert_eq!(read_anchor(&raw).unwrap_err().cause, "dist:bad-format");
    assert!(matches!(point.pep.provision(&raw), Err(PepError::Refused(_))));
    std::fs::write(point.pep.store_path("anchor.pending"), &raw).unwrap();
    assert!(matches!(point.pep.confirm(&h(&raw)), Err(PepError::Refused(_))));
    assert_eq!((point.pep.state(), point.host_active()), ("active", json!(h(&old()).as_str())));
    assert_eq!(point.pep.decide(|| "ran").unwrap().decision, Some("ran"));
    point.reopen();
    assert_eq!((point.pep.state(), point.pep.trust().keys.len()), ("active", 1));
}

/// The PKCS8 PEM of the test key `name`, as the Python tools write an Ed25519 private key.
fn pem_of(name: &str) -> Vec<u8> {
    use base64::Engine;
    let mut der = vec![0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
    der.extend_from_slice(&test_key(name).to_bytes());
    let text = base64::engine::general_purpose::STANDARD.encode(der);
    format!("-----BEGIN PRIVATE KEY-----\n{text}\n-----END PRIVATE KEY-----\n").into_bytes()
}

/// K2, as case 18 is on Python (its row runs on Python only, so this carries no case token): a host PEP whose
/// state directory holds the private half of a trusted authority key refuses to start, a PEM key as Python writes
/// one or a raw seed as this crate's keygen does. The scan is Python's: a key the store does not trust, one in
/// `runs`, one three levels down and one over 16,384 bytes are not found.
#[test]
fn a_host_pep_with_an_authority_private_key_in_its_home_refuses_to_start() {
    let point = Point::new("k2_home");
    let home = point.state_dir();
    let refuses = |path: &std::path::Path, data: &[u8]| {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, data).unwrap();
        let opened = point.open();
        std::fs::remove_file(path).unwrap();
        match opened {
            Err(PepError::Refused(text)) => {
                assert!(text.contains("(K2)"), "{text}");
                true
            }
            Err(other) => panic!("{other}"),
            Ok(_) => false,
        }
    };
    assert!(refuses(&home.join("keys/authority.key"), &pem_of("A")));
    assert!(refuses(&home.join("keys/authority.seed"), &test_key("A").to_bytes()));
    assert!(refuses(&home.join("a/b/authority.key"), &pem_of("A")), "two levels down is scanned");
    assert!(!refuses(&home.join("keys/other.key"), &pem_of("U")), "a key the store does not trust");
    assert!(!refuses(&home.join("runs/authority.key"), &pem_of("A")), "runs is not scanned");
    assert!(!refuses(&home.join("a/b/c/authority.key"), &pem_of("A")), "three levels down is not scanned");
    let mut large = pem_of("A");
    large.resize(16_385, b'\n');
    assert!(!refuses(&home.join("keys/large.key"), &large), "a file over the bound");
    assert!(point.open().is_ok());
}

/// G1: a stage whose blob cannot be written leaves the release staged before it as it was.
#[test]
fn a_stage_whose_write_fails_keeps_the_staged_release() {
    let mut point = Point::new("stage_write");
    let release = release_of(&old());
    point.stage(&ppt(&old(), &Args { release: Some(release.clone()), ..at(1) }), &old());
    let statement = widening(&[]);
    let args = Args { release: Some(release), policy: Some(h(&old())), ..at(1) };
    let blobs = point.state_dir().join("dist/blobs");
    set_mode(&blobs, 0o555);
    let failed = point.pep.stage(&seal(ArtifactKind::TrustWidening, &statement, &args), &statement);
    set_mode(&blobs, 0o755);
    assert!(failed.is_err());
    let staged = point.pep.staged().expect("the staged release is still held");
    assert_eq!((staged.seq, staged.held.len()), (1, 1));
    assert_eq!(rec!(point, point.pep.commit(STREAM, 1, &h(&old()), 0)).event, "committed");
}

/// B8: a commit with a delay is the frame binding's, which this crate does not build. It is refused, says so, and
/// changes and reports nothing.
#[test]
fn a_commit_with_a_delay_is_refused() {
    let mut point = Point::new("delay");
    point.stage(&ppt(&old(), &at(1)), &old());
    point.pep.drain();
    let refused = point.pep.commit(STREAM, 1, &h(&old()), 250);
    assert!(matches!(&refused, Err(PepError::Refused(text)) if text.contains("(B8)")), "{refused:?}");
    assert!(point.pep.drain().is_empty());
    assert!(point.pep.staged().is_some() && point.pep.active().is_none());
}

// ------------------------------------------------------------------ what a reconcile reports

/// The event, cause and active seq of each record in `records`.
fn summary(point: &Point, records: &[Vec<u8>]) -> Vec<(&'static str, Option<String>, u64)> {
    records.iter().map(|data| point.read(data)).map(|record| (record.event, record.cause, record.active_seq)).collect()
}

/// What the PEP sent since the last drain, as `summary` gives it.
fn drained(point: &mut Point) -> Vec<(&'static str, Option<String>, u64)> {
    let records = point.pep.drain();
    summary(point, &records)
}

fn runtime_dies(point: &mut Point) {
    point.pep.set_commit_hook(Some(Box::new(|at| if at == PepStep::Runtime { Err("died".into()) } else { Ok(()) })));
}

fn count(point: &Point, action: &str) -> usize {
    point.actions().iter().filter(|name| *name == action).count()
}

fn host_events(point: &Point, action: &str) -> Vec<serde_json::Value> {
    point.pep.adapter.host.history().into_iter().filter(|event| event["action"] == action).map(|event| event["data"].clone()).collect()
}

/// C5, H4: a flip whose runtime step failed sends its `committed` record once a tick makes the runtime match, in
/// the same process and after a restart. After the restart the release it made active is no longer staged, so
/// committing its seq again is refused and the release kept for a rollback stays the one it replaced.
#[test]
fn a_reconciled_flip_sends_its_record_then_and_after_a_restart() {
    let mut point = Point::new("owed_flip");
    point.commit_at(&old(), 1);
    point.stage(&ppt(&new(), &at(2)), &new());
    point.pep.drain();
    runtime_dies(&mut point);
    assert!(point.pep.commit(STREAM, 2, &h(&new()), 0).is_err());
    point.pep.set_commit_hook(None);
    assert!(point.pep.drain().is_empty());
    let ticked = rec!(point, point.pep.tick().unwrap());
    assert_eq!((ticked.event, ticked.active_seq), ("committed", 2));
    assert_eq!(drained(&mut point), vec![("committed", None, 2)]);
    assert_eq!(count(&point, "committed"), 2, "one for each commit, the audit event of this one written once");

    let mut point = Point::new("owed_flip_restart");
    point.commit_at(&old(), 1);
    point.stage(&ppt(&new(), &at(2)), &new());
    runtime_dies(&mut point);
    assert!(point.pep.commit(STREAM, 2, &h(&new()), 0).is_err());
    point.reopen();
    assert_eq!(drained(&mut point), vec![("committed", None, 2)]);
    assert!(point.pep.staged().is_none() && !point.state_dir().join("dist/staged.json").exists());
    assert_eq!(rec!(point, point.pep.commit(STREAM, 2, &h(&new()), 0)).cause.as_deref(), Some("dist:not-staged"));
    assert_eq!((point.pep.active().unwrap().seq, point.pep.previous().unwrap().seq), (2, 1));
}

/// X1, X3, H4: a lapse whose host withdraw fails leaves the PEP refusing every decision and sending no record,
/// and a pub lapse refused too, while the host still holds the expired release. A beat in that time says
/// no-policy with the expired release as what the runtime may hold, and provisioning may start. A tick once the
/// host can let go withdraws it, and the `lapsed` record and audit event go then with `dist:expired`, the host
/// told that cause. A restart in between reports the lapse the same way.
#[test]
fn a_lapse_whose_withdraw_fails_is_reported_with_its_cause_once_the_host_lets_go() {
    for restart in [false, true] {
        let mut point = Point::new("owed_lapse");
        point.commit_at(&old(), 1);
        point.pep.drain();
        point.now.set(EXPIRES);
        let home = point.state_dir();
        set_mode(&home, 0o555);
        assert!(point.pep.tick().is_err());
        assert!(point.pep.is_reconciling());
        assert_eq!(point.pep.state(), "no-policy");
        assert_eq!(point.pep.decide(|| "ran").unwrap().decision, None);
        let beat = rec!(point, point.pep.record("beat", None));
        assert_eq!((beat.event, beat.state, beat.active_seq), ("beat", "no-policy", 1));
        assert!(point.pep.lapse("dist:revoked").is_err());
        assert!(point.pep.provision(&point.anchor()).is_ok());
        assert!(point.pep.tick().is_err());
        assert_eq!(point.host_active(), json!(h(&old()).as_str()));
        point.pep.drain();
        set_mode(&home, 0o755);
        if restart {
            point.reopen();
        } else {
            assert_eq!(event_cause(&rec!(point, point.pep.tick().unwrap())), ("lapsed", Some("dist:expired")));
        }
        assert_eq!(drained(&mut point), vec![("lapsed", Some("dist:expired".to_string()), 0)], "restart {restart}");
        assert_eq!(point.host_active(), json!(null));
        assert_eq!(count(&point, "lapsed"), 1);
        let withdrawn = host_events(&point, "withdraw");
        assert_eq!(withdrawn.len(), 1, "a withdraw tried again writes its evidence once");
        assert_eq!(withdrawn[0]["cause"], json!("dist:expired"));
        assert!(!point.state_dir().join("dist/owed.json").exists());
    }
}

/// C4: while the runtime fails, a decision or a record does not try the install again, and a tick tries it once,
/// its evidence written once in the host's log.
#[test]
fn while_reconciling_only_a_tick_tries_the_install_and_its_evidence_is_written_once() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    let mut point = Point::new("reconcile_once");
    point.commit_at(&old(), 1);
    point.stage(&ppt(&new(), &at(2)), &new());
    let tries = Arc::new(AtomicUsize::new(0));
    let counted = tries.clone();
    point.pep.adapter.host.set_commit_hook(Some(Box::new(move |at| {
        if at == CommitStep::Intent {
            counted.fetch_add(1, Ordering::SeqCst);
        }
        if at == CommitStep::ActiveRecord { Err("died".into()) } else { Ok(()) }
    })));
    assert!(point.pep.commit(STREAM, 2, &h(&new()), 0).is_err());
    let before = point.pep.adapter.host.history().len();
    for _ in 0..20 {
        assert_eq!(point.pep.decide(|| 1).unwrap().decision, None);
        assert_eq!(rec!(point, point.pep.record("beat", None)).state, "no-policy");
    }
    assert_eq!((tries.load(Ordering::SeqCst), point.pep.adapter.host.history().len()), (1, before));
    for _ in 0..3 {
        assert!(point.pep.tick().is_err());
    }
    assert_eq!(tries.load(Ordering::SeqCst), 4, "one install for the commit and one for each tick");
    let installs = host_events(&point, "swap").iter().filter(|data| data["to_hash"] == json!(h(&new()).as_str())).count();
    assert_eq!(installs, 1);
}

/// X1, C3: a release that expires while its install fails is never installed. The tick after reports the commit
/// refused with the cause it fell for, never `committed`, then the lapse, and the host withdraws the release it held
/// all along.
#[test]
fn a_release_that_expires_while_reconciling_is_never_installed() {
    let mut point = Point::new("reconcile_expired");
    point.commit_at(&old(), 1);
    point.stage(&ppt(&new(), &at(2)), &new());
    host_dies_at(&mut point, CommitStep::ActiveRecord);
    assert!(point.pep.commit(STREAM, 2, &h(&new()), 0).is_err());
    point.pep.drain();
    assert!(point.pep.is_reconciling());
    assert_eq!((point.pep.state(), point.pep.refusal()), ("no-policy", Some("dist:policy-lapsed")));
    point.now.set(EXPIRES + 10);
    point.pep.adapter.host.set_commit_hook(None);
    assert_eq!(event_cause(&rec!(point, point.pep.tick().unwrap())), ("lapsed", Some("dist:expired")));
    assert_eq!(
        drained(&mut point),
        vec![("refused", Some("dist:expired".to_string()), 0), ("lapsed", Some("dist:expired".to_string()), 0)]
    );
    let withdrawn = host_events(&point, "withdraw");
    assert_eq!(withdrawn.len(), 1);
    assert_eq!(withdrawn[0]["from_hash"], json!(h(&old()).as_str()), "the host never held the new release");
    assert_eq!(point.host_active(), json!(null));
}

/// K2: a PEM file is read block by block, so a private key block followed by a public key block is found, and so
/// are a key with carriage returns and a version 2 key carrying its public half.
#[test]
fn the_k2_scan_reads_each_pem_block_on_its_own() {
    use base64::Engine;
    let point = Point::new("k2_blocks");
    let path = point.state_dir().join("keys/authority.pem");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let public_half = base64::engine::general_purpose::STANDARD.encode([&[0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00][..], &public("A")].concat());
    let mut v2 = vec![0x30, 0x51, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
    v2.extend_from_slice(&test_key("A").to_bytes());
    v2.extend_from_slice(&[0x81, 0x21, 0x00]);
    v2.extend_from_slice(&public("A"));
    let v2_pem = format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n", base64::engine::general_purpose::STANDARD.encode(&v2));
    let with_public = [pem_of("A"), format!("-----BEGIN PUBLIC KEY-----\n{public_half}\n-----END PUBLIC KEY-----\n").into_bytes()].concat();
    let crlf = String::from_utf8(pem_of("A")).unwrap().replace('\n', "\r\n").into_bytes();
    for (name, data) in [("private then public", with_public), ("carriage returns", crlf), ("version 2", v2_pem.into_bytes())] {
        std::fs::write(&path, &data).unwrap();
        assert!(matches!(point.open(), Err(PepError::Refused(text)) if text.contains("(K2)")), "{name}");
    }
    std::fs::remove_file(&path).unwrap();
    assert!(point.open().is_ok());
}

/// K2: the scan stops after 4,096 files, so a key past them is not found, and the same key past ten files is.
#[test]
fn the_k2_scan_looks_at_no_more_than_4096_files() {
    let point = Point::new("k2_cap");
    let home = point.state_dir();
    std::fs::create_dir_all(home.join("a_keys")).unwrap();
    std::fs::write(home.join("a_keys/authority.key"), pem_of("A")).unwrap();
    // the scan takes the directories of one level last name first, so z_many is looked at before a_keys
    std::fs::create_dir_all(home.join("z_many")).unwrap();
    for index in 0..10 {
        std::fs::write(home.join(format!("z_many/{index:05}")), b"x").unwrap();
    }
    assert!(matches!(point.open(), Err(PepError::Refused(_))), "found past ten files");
    for index in 10..4096 {
        std::fs::write(home.join(format!("z_many/{index:05}")), b"x").unwrap();
    }
    assert!(point.open().is_ok(), "not found past 4,096 files");
}

// ------------------------------------------------------------------ while reconciling, and what is owed

fn owed_doc(seq: i64) -> Vec<u8> {
    canon2::write_json(&json!({"cause": "dist:expired", "encoding": "canon/2", "envelopes": [], "format": "prismpath.dist-owed/1",
                               "seq": seq}))
    .unwrap()
}

fn events_of(point: &mut Point) -> Vec<&'static str> {
    drained(point).into_iter().map(|(event, _, _)| event).collect()
}

/// R5, B2: a revocation staged while the runtime fails is applied, and the release it revokes is never installed:
/// the next tick reports that commit refused with dist:revoked, then the lapse, and nothing is decided under it.
#[test]
fn a_revocation_staged_while_reconciling_is_applied_and_its_release_never_installed() {
    let mut point = Point::new("revoke_reconciling");
    point.commit_at(&old(), 1);
    point.stage(&ppt(&new(), &at(2)), &new());
    host_dies_at(&mut point, CommitStep::ActiveRecord);
    assert!(point.pep.commit(STREAM, 2, &h(&new()), 0).is_err());
    point.pep.drain();
    let applied = point.revoke(1, &revocation(&[], &[], &[h(&new())], &[]));
    assert_eq!((applied.event, applied.trust_seq, applied.state, applied.active_seq), ("trust-applied", 1, "no-policy", 1));
    point.pep.drain();
    point.pep.adapter.host.set_commit_hook(None);
    point.pep.tick().unwrap();
    assert_eq!(
        drained(&mut point),
        vec![("refused", Some("dist:revoked".to_string()), 0), ("lapsed", Some("dist:revoked".to_string()), 0)]
    );
    assert_eq!(host_events(&point, "withdraw")[0]["from_hash"], json!(h(&old()).as_str()));
    assert_eq!(point.host_active(), json!(null));
    assert_eq!(point.pep.decide(|| "ran").unwrap().decision, None);
}

/// P3, H4: a PEP whose install keeps failing still beats, and provisioning ends the state, since confirming
/// withdraws the runtime first. Abort and staging work meanwhile, a commit and a rollback wait.
#[test]
fn provisioning_ends_a_reconcile_that_cannot_finish_and_records_go_on_meanwhile() {
    let mut point = Point::new("stuck");
    point.commit_at(&old(), 1);
    point.stage(&ppt(&new(), &at(2)), &new());
    host_dies_at(&mut point, CommitStep::ActiveRecord);
    assert!(point.pep.commit(STREAM, 2, &h(&new()), 0).is_err());
    assert!(point.pep.rollback().is_err() && point.pep.commit(STREAM, 2, &h(&new()), 0).is_err());
    assert_eq!(rec!(point, point.pep.record("beat", None)).state, "no-policy");
    assert_eq!(point.stage(&ppt(&newer(), &at(3)), &newer()).event, "staged");
    assert_eq!(rec!(point, point.pep.abort(STREAM, 3, &h(&newer()))).event, "aborted");
    let fingerprint = point.pep.provision(&point.anchor()).unwrap();
    let provisioned = rec!(point, point.pep.confirm(&fingerprint));
    assert_eq!((provisioned.event, provisioned.state, provisioned.active_seq), ("provisioned", "no-policy", 0));
    assert!(!point.pep.is_reconciling());
    assert_eq!(point.host_active(), json!(null));
}

/// C4: a host install that died is not taken for another envelope of the same image and version, which writes its
/// own evidence, and a withdraw with nothing active clears the intent of the install that died.
#[test]
fn the_host_writes_the_evidence_of_another_envelope_of_the_same_image() {
    let mut point = Point::new("dedupe_envelope");
    point.stage(&ppt(&old(), &at(1)), &old());
    host_dies_at(&mut point, CommitStep::ActiveRecord);
    assert!(point.pep.commit(STREAM, 1, &h(&old()), 0).is_err());
    point.pep.adapter.host.set_commit_hook(None);
    point.now.set(EXPIRES + 10);
    point.pep.tick().unwrap();
    assert!(!point.state_dir().join("pending_swap").exists());
    let fingerprint = point.pep.provision(&point.anchor()).unwrap();
    point.pep.confirm(&fingerprint).unwrap();
    let later = Args { expires: EXPIRES + 100_000, ..at(1) };
    let sealed = ppt(&old(), &later);
    point.stage(&sealed, &old());
    assert_eq!(rec!(point, point.pep.commit(STREAM, 1, &h(&old()), 0)).event, "committed");
    let swaps = host_events(&point, "swap");
    assert_eq!(swaps.len(), 2);
    let installed = env::envelope_id(env::unseal(&sealed).unwrap().0);
    assert_eq!(swaps[1]["distribution"]["envelope_id"], json!(installed.as_str()));
}

/// X1, H4: a lapse whose audit event cannot be written stays owed, so the next tick sends it, and the lapsed audit
/// event is written once even when a restart finds the lapse owed again after it was written.
#[test]
fn a_lapse_whose_report_fails_is_sent_later_and_audited_once() {
    let mut point = Point::new("lapse_audit");
    point.commit_at(&old(), 1);
    point.pep.drain();
    point.now.set(EXPIRES);
    let log = point.state_dir().join("dist/audit.log");
    set_mode(&log, 0o444);
    assert!(point.pep.tick().is_err());
    set_mode(&log, 0o644);
    assert!(point.pep.is_reconciling());
    let owed = std::fs::read(point.pep.store_path("owed.json")).unwrap();
    assert_eq!(event_cause(&rec!(point, point.pep.tick().unwrap())), ("lapsed", Some("dist:expired")));
    assert!(!point.state_dir().join("dist/owed.json").exists());
    assert_eq!(count(&point, "lapsed"), 1);
    // a crash after the audit event and before owed.json went
    std::fs::write(point.pep.store_path("owed.json"), &owed).unwrap();
    point.reopen();
    assert_eq!(drained(&mut point), vec![("lapsed", Some("dist:expired".to_string()), 0)]);
    assert_eq!(count(&point, "lapsed"), 1);
}

/// H9: the records a restart sends, an owed one first, carry the highest epoch the controller sent before it.
#[test]
fn a_restart_reports_the_epoch_it_had_seen() {
    let mut point = Point::new("epoch_restart");
    point.commit_at(&old(), 1);
    point.pep.see_epoch(41).unwrap();
    point.stage(&ppt(&new(), &at(2)), &new());
    runtime_dies(&mut point);
    assert!(point.pep.commit(STREAM, 2, &h(&new()), 0).is_err());
    point.reopen();
    let records = point.pep.drain();
    assert!(!records.is_empty());
    assert!(records.iter().all(|data| point.read(data).epoch == 41));
    assert_eq!(point.read(records.last().unwrap()).event, "committed");
}

/// owed.json is believed only where the lapse reached its active record: not with a release active, not above the
/// floor, and not on a locked start, where it waits for provisioning.
#[test]
fn an_owed_lapse_is_believed_only_where_it_happened() {
    let mut point = Point::new("owed_stale");
    point.commit_at(&old(), 1);
    std::fs::write(point.pep.store_path("owed.json"), owed_doc(1)).unwrap();
    point.reopen();
    assert_eq!((point.pep.state(), events_of(&mut point)), ("active", vec![]), "with a release active");
    assert!(!point.state_dir().join("dist/owed.json").exists());

    point.now.set(EXPIRES);
    point.pep.tick().unwrap();
    std::fs::write(point.pep.store_path("owed.json"), owed_doc(99)).unwrap();
    point.reopen();
    assert!(events_of(&mut point).is_empty(), "above the floor");
    assert!(!point.state_dir().join("dist/owed.json").exists());

    std::fs::write(point.pep.store_path("owed.json"), owed_doc(1)).unwrap();
    std::fs::write(point.pep.store_path("floor.json"), b"{").unwrap();
    point.reopen();
    assert_eq!((point.pep.state(), events_of(&mut point)), ("locked", vec![]), "on a locked start");
    assert!(point.state_dir().join("dist/owed.json").exists());
    let fingerprint = point.pep.provision(&point.anchor()).unwrap();
    point.pep.confirm(&fingerprint).unwrap();
    assert!(!point.state_dir().join("dist/owed.json").exists());
}

/// P3: a confirm drops a lapse still owed, so no restart after it reports that lapse.
#[test]
fn a_confirm_drops_an_owed_lapse() {
    let mut point = Point::new("confirm_owed");
    point.commit_at(&old(), 1);
    point.now.set(EXPIRES);
    let home = point.state_dir();
    set_mode(&home, 0o555);
    assert!(point.pep.tick().is_err());
    set_mode(&home, 0o755);
    let fingerprint = point.pep.provision(&point.anchor()).unwrap();
    point.pep.confirm(&fingerprint).unwrap();
    point.reopen();
    assert!(!events_of(&mut point).contains(&"lapsed"));
}

/// X1: a lapse whose active record cannot be written leaves no owed.json behind.
#[test]
fn a_lapse_that_cannot_write_its_record_leaves_nothing_owed() {
    let mut point = Point::new("owed_cleared");
    point.commit_at(&old(), 1);
    point.now.set(EXPIRES);
    let blocker = point.state_dir().join("dist/active.json.tmp");
    std::fs::create_dir_all(&blocker).unwrap();
    assert!(point.pep.tick().is_err());
    std::fs::remove_dir_all(&blocker).unwrap();
    assert!(!point.state_dir().join("dist/owed.json").exists());
    assert!(point.pep.active().is_some() && !point.pep.is_reconciling());
}

/// K2: every private key block of a file is read, so a trusted key after an untrusted one, or after a public key
/// block, is found.
#[test]
fn the_k2_scan_finds_a_trusted_key_in_any_block() {
    let point = Point::new("k2_any_block");
    let path = point.state_dir().join("keys/keys.pem");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let public_block = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n-----END PUBLIC KEY-----\n".to_vec();
    for (name, data) in [("untrusted then trusted", [pem_of("U"), pem_of("A")].concat()), ("public then private", [public_block, pem_of("A")].concat())] {
        std::fs::write(&path, &data).unwrap();
        assert!(matches!(point.open(), Err(PepError::Refused(text)) if text.contains("(K2)")), "{name}");
    }
}
