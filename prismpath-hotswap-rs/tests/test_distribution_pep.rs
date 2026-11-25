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
    point.stage(&ppt(&old(), &at(1)), &old());
    assert!(point.pep.staged().unwrap().held.contains_key(&ArtifactKind::TrustWidening));
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

/// case_308: C2, E10, the `host` half. A release whose signed release id covers a `policy.ppt` and a `policy.spiral`
/// is committed with only its `policy.ppt` staged: `dist:incomplete`, and the release active before stays active. The
/// same table with a release id over what is staged then commits.
#[test]
fn case_308_a_withheld_artifact_at_commit_on_host_is_incomplete() {
    let mut point = Point::new("308");
    point.commit_at(&old(), 1);
    let release = env::release_id(&[(ArtifactKind::PolicyPpt, h(&new())), (ArtifactKind::PolicySpiral, h(b"a withheld spiral"))]).unwrap();
    let record = point.commit(&new(), &Args { release: Some(release), ..at(2) });
    assert_eq!(event_cause(&record), ("refused", Some("dist:incomplete")));
    assert_eq!(point.pep.active().map(|active| active.policy_sha256.clone()), Some(h(&old())));
    assert_eq!(point.pep.floor().seq, 1);
    assert_eq!(point.commit_at(&new(), 3).event, "committed");
}

/// case_046: G1.
#[test]
fn case_046_staged_and_refused_are_acked_and_in_the_audit_log() {
    let mut point = Point::new("046");
    let record = point.stage(&ppt(&old(), &at(1)), &old());
    assert_eq!((record.event, record.staged, record.staged_seq, record.cause.as_deref()), ("staged", true, 1, None));
    let signed = point.pep.stage(&ppt(&new(), &by(2, "U")), &new()).unwrap();
    assert_eq!(event_cause(&point.read(&signed)), ("refused", Some("dist:unknown-key")));
    let events: Vec<(String, Option<String>)> = point
        .pep
        .audit
        .events()
        .iter()
        .filter(|event| event["data"]["artifact"] != "trust.widening")
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
/// whatever step of its own install failed.
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
        let answer = point.pep.commit(STREAM, 2, &h(&new()), 0);
        match death {
            Death::Pep(_) => assert!(answer.is_err(), "{death:?}"),
            // a host step that fails is a runtime step that fails, which leaves the PEP reconciling (C6)
            Death::Host(_) => assert_eq!(point.read(&answer.unwrap()).event, "reconciling", "{death:?}"),
        }
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

/// H3, H15 and the outbox: the counter rises with every record and across a restart, the epoch id is 0 in every
/// record since this PEP holds no controller key, and a record is in the outbox once.
#[test]
fn every_record_counts_on_and_is_sent_once() {
    let mut point = Point::new("counter");
    point.pep.drain();
    let first = rec!(point, point.pep.record("beat", None));
    point.reopen();
    let second = rec!(point, point.pep.record("beat", None));
    assert!(second.counter > first.counter);
    assert_eq!((first.epoch, second.epoch), (0, 0));
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
    let sealed = ppt(&old(), &at(1));
    let (statement_sealed, statement) = covering_statement(&sealed).unwrap();
    point.pep.stage(&statement_sealed, &statement).unwrap();
    let blobs = point.state_dir().join("dist/blobs");
    set_mode(&blobs, 0o555);
    let failed = point.pep.stage(&sealed, &old());
    set_mode(&blobs, 0o755);
    assert!(failed.is_err());
    let staged = point.pep.staged().expect("the staged release is still held");
    assert_eq!((staged.seq, staged.held.keys().copied().collect::<Vec<_>>()), (1, vec![ArtifactKind::TrustWidening]));
    point.pep.stage(&sealed, &old()).unwrap();
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

fn host_events(point: &Point, action: &str) -> Vec<serde_json::Value> {
    point.pep.adapter.host.history().into_iter().filter(|event| event["action"] == action).map(|event| event["data"].clone()).collect()
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

// ------------------------------------------------------------------ the host's own record

/// Kill the host's install at `step` on every try until `hook` is cleared.
fn host_dies_at(point: &mut Point, step: CommitStep) {
    point.pep.adapter.host.set_commit_hook(Some(Box::new(move |at| if at == step { Err("died".into()) } else { Ok(()) })));
}

/// C4: a host install that died is not taken for another envelope of the same image and version, which writes its
/// own evidence, and a withdraw with nothing active clears the intent of the install that died.
#[test]
fn the_host_writes_the_evidence_of_another_envelope_of_the_same_image() {
    let mut point = Point::new("dedupe_envelope");
    point.stage(&ppt(&old(), &at(1)), &old());
    host_dies_at(&mut point, CommitStep::ActiveRecord);
    assert_eq!(rec!(point, point.pep.commit(STREAM, 1, &h(&old()), 0)).event, "reconciling");
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

/// X1, C7: a lapse whose active record cannot be written leaves the release active and the PEP not reconciling.
#[test]
fn a_lapse_whose_active_record_cannot_be_written_leaves_the_release_active() {
    let mut point = Point::new("lapse_active_record");
    point.commit_at(&old(), 1);
    point.now.set(EXPIRES);
    let blocker = point.state_dir().join("dist/active.json.tmp");
    std::fs::create_dir_all(&blocker).unwrap();
    assert!(point.pep.tick().is_err());
    std::fs::remove_dir_all(&blocker).unwrap();
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

/// The PEM of the test key `name` with an RFC 1421 header line and the blank line after it.
fn pem_with_header(name: &str) -> Vec<u8> {
    let pem = String::from_utf8(pem_of(name)).unwrap();
    pem.replacen("-----BEGIN PRIVATE KEY-----\n", "-----BEGIN PRIVATE KEY-----\nComment: written by hand\n\n", 1).into_bytes()
}

/// K2: a `-----BEGIN` with no end line hides no key block after it, a block whose base64 follows RFC 1421 header
/// lines is read, and a byte that is not UTF-8 anywhere in the file stops nothing.
#[test]
fn the_k2_scan_reads_past_an_unterminated_block_header_lines_and_bytes_that_are_not_utf8() {
    let point = Point::new("k2_bytes");
    let path = point.state_dir().join("keys/keys.pem");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let unterminated = [b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n".to_vec(), pem_of("A")].concat();
    let not_utf8 = [b"\xff\xfe not text\n".to_vec(), pem_of("A")].concat();
    for (name, data) in [("unterminated", unterminated), ("header lines", pem_with_header("A")), ("not UTF-8", not_utf8)] {
        std::fs::write(&path, &data).unwrap();
        assert!(matches!(point.open(), Err(PepError::Refused(text)) if text.contains("(K2)")), "{name}");
    }
    std::fs::write(&path, pem_with_header("U")).unwrap();
    assert!(point.open().is_ok(), "an untrusted key with header lines is not refused");
}

/// K2: the scan opens only regular files, so a FIFO in the home, which no process writes, does not stop the start,
/// and a key after it is still found.
#[test]
fn the_k2_scan_opens_only_regular_files() {
    let point = Point::new("k2_fifo");
    let home = point.state_dir();
    let fifo = home.join("a_fifo");
    assert!(std::process::Command::new("mkfifo").arg(&fifo).status().unwrap().success());
    let open_in_thread = |home: std::path::PathBuf| {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let now = Rc::new(Cell::new(NOW));
            let opened = open_pep(&home, &now, &test_key("I"), &["A"], REFUSE, false);
            let _ = sender.send(opened.map(|_| ()).map_err(|error| error.to_string()));
        });
        receiver.recv_timeout(std::time::Duration::from_secs(20)).expect("the start returns with a FIFO in the home")
    };
    assert!(open_in_thread(home.clone()).is_ok());
    std::fs::write(home.join("b_key.pem"), pem_of("A")).unwrap();
    assert!(open_in_thread(home.clone()).is_err_and(|text| text.contains("(K2)")));
    std::fs::remove_file(&fifo).unwrap();
}

/// C4: a restart after a flip died past its active record drops the copy of the release it made active from the
/// staged release, so committing its seq again is dist:not-staged and the release kept for a rollback is still the
/// one it replaced.
#[test]
fn a_restart_after_a_flip_past_its_active_record_drops_the_staged_copy() {
    let mut point = Point::new("flip_restart");
    point.commit_at(&old(), 1);
    point.stage(&ppt(&new(), &at(2)), &new());
    point.pep.set_commit_hook(Some(Box::new(|at| if at == PepStep::Runtime { Err("died".into()) } else { Ok(()) })));
    assert!(point.pep.commit(STREAM, 2, &h(&new()), 0).is_err());
    point.reopen();
    assert!(point.pep.staged().is_none() && !point.state_dir().join("dist/staged.json").exists());
    assert_eq!(rec!(point, point.pep.commit(STREAM, 2, &h(&new()), 0)).cause.as_deref(), Some("dist:not-staged"));
    assert_eq!((point.pep.active().unwrap().seq, point.pep.previous().unwrap().seq), (2, 1));
}

// ------------------------------------------------------------------ V12: the widening rule (W1 to W7, RB3, C3)

/// The stage ack of `sealed` staged with nothing before it.
fn stage_alone(point: &mut Point, sealed: &[u8], body: &[u8]) -> StateRecord {
    let signed = point.pep.stage(sealed, body).unwrap();
    point.read(&signed)
}

/// case_062: W4, W5. On a host PEP running `old`, another table that says it widens commits with a statement whose
/// `from` holds the active hash and with one whose `from` is empty, and is refused with one whose `from` holds only
/// another hash.
#[test]
fn case_062_a_statement_covers_when_from_holds_the_active_hash_or_is_empty() {
    let mut point = Point::new("062");
    point.commit_at(&old(), 1);
    for (seq, body, from, committed) in [(2, new(), vec![h(&old())], true), (3, newer(), vec![], true), (4, old(), vec![h(b"another")], false)] {
        let active = point.pep.active().unwrap().policy_sha256.clone();
        let sealed = ppt(&body, &Args { replaces: Some(active), ..at(seq) });
        let (statement_sealed, statement) = statement_of(&sealed, &from);
        assert_eq!(stage_alone(&mut point, &statement_sealed, &statement).event, "staged");
        let staged = stage_alone(&mut point, &sealed, &body);
        if committed {
            assert_eq!(staged.event, "staged", "{seq}");
            assert_eq!(event_cause(&rec!(point, point.pep.commit(STREAM, seq, &h(&body), 0))), ("committed", None), "{seq}");
        } else {
            assert_eq!(event_cause(&staged), ("refused", Some("dist:widening-unsigned")), "{seq}");
        }
    }
    assert_eq!(point.pep.active().unwrap().seq, 3);
}

/// case_294: W10, W11, W2, the host half. A table carried by a change statement from the active hash, with `widens`
/// false and `replaces` that hash, commits on the authority's signatures, and the same table alone is refused with
/// the held table still active. The mesh half runs on the C core from the corpus.
#[test]
fn case_294_a_table_carried_by_a_change_statement_commits_without_a_widening_statement() {
    let mut point = Point::new("294");
    point.commit_at(&old(), 1);
    let sealed = ppt(&new(), &Args { widens: false, replaces: Some(h(&old())), ..at(2) });
    assert_eq!(event_cause(&stage_alone(&mut point, &sealed, &new())), ("refused", Some("dist:widening-unsigned")));
    let (change_sealed, change) = change_of(&sealed, &h(&old()), false);
    assert_eq!(stage_alone(&mut point, &change_sealed, &change).event, "staged");
    assert_eq!(stage_alone(&mut point, &sealed, &new()).event, "staged");
    assert_eq!(event_cause(&rec!(point, point.pep.commit(STREAM, 2, &h(&new()), 0))), ("committed", None));
    assert_eq!(point.pep.active().unwrap().seq, 2);
}

/// case_295: W10, W11, the host half. A change statement whose `widens` is true is dist:bad-format, one on a first
/// install and one from another hash are dist:widening-unsigned, and one after a widening statement of the same
/// release is dist:bad-format, each with the held table still active.
#[test]
fn case_295_a_change_statement_never_stands_for_a_widening() {
    let mut first = Point::new("295a");
    let sealed = ppt(&old(), &Args { widens: false, replaces: Some(h(b"another")), ..at(1) });
    let (change_sealed, change) = change_of(&sealed, &h(b"another"), false);
    assert_eq!(event_cause(&stage_alone(&mut first, &change_sealed, &change)), ("refused", Some("dist:widening-unsigned")));
    assert!(first.pep.active().is_none());

    let mut point = Point::new("295b");
    point.commit_at(&old(), 1);
    let says_widens = ppt(&new(), &Args { widens: true, replaces: Some(h(&old())), ..at(2) });
    let (change_sealed, change) = change_of(&says_widens, &h(&old()), true);
    assert_eq!(event_cause(&stage_alone(&mut point, &change_sealed, &change)), ("refused", Some("dist:bad-format")));
    let other = ppt(&new(), &Args { widens: false, replaces: Some(h(b"another")), ..at(2) });
    let (change_sealed, change) = change_of(&other, &h(b"another"), false);
    assert_eq!(event_cause(&stage_alone(&mut point, &change_sealed, &change)), ("refused", Some("dist:widening-unsigned")));
    let sealed = ppt(&new(), &Args { widens: false, replaces: Some(h(&old())), ..at(2) });
    let (statement_sealed, statement) = statement_of(&sealed, &[h(&old())]);
    assert_eq!(stage_alone(&mut point, &statement_sealed, &statement).event, "staged");
    let (change_sealed, change) = change_of(&sealed, &h(&old()), false);
    assert_eq!(event_cause(&stage_alone(&mut point, &change_sealed, &change)), ("refused", Some("dist:bad-format")));
    assert_eq!(point.pep.active().unwrap().seq, 1);
}

/// case_294, case_295: W10, W11, the corpus half. Each commit case of the corpus for the change statement on a host,
/// sealed by the Python reference, answers on the Rust PEP as Python records it.
#[test]
fn case_294_295_the_corpus_change_statements_answer_on_the_rust_host_as_recorded() {
    let entries: Vec<&serde_json::Value> = corpus()["commits"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| [294, 295].contains(&entry["case"].as_i64().unwrap()) && entry["kind"] == "host")
        .collect();
    assert_eq!(entries.len(), 6);
    for entry in entries {
        let name = entry["name"].as_str().unwrap();
        let mut point = Point::new(&format!("corpus_{name}"));
        point.now.set(entry["now"].as_i64().unwrap());
        let mut last = None;
        for step in entry["steps"].as_array().unwrap() {
            let signed = if step["op"] == "stage" {
                let bytes = |key: &str| hex::decode(step[key].as_str().unwrap()).unwrap();
                point.pep.stage(&bytes("sealed"), &bytes("body")).unwrap()
            } else {
                let policy = Hex64::try_from(step["policy_sha256"].as_str().unwrap().to_string()).unwrap();
                point.pep.commit(STREAM, step["seq"].as_i64().unwrap(), &policy, 0).unwrap()
            };
            last = Some(point.read(&signed));
        }
        let record = last.unwrap();
        let expect = &entry["expect"];
        assert_eq!(record.cause.as_deref(), expect["cause"].as_str(), "{name}");
        assert_eq!(point.pep.active().map_or(0, |active| active.seq), expect["active_seq"].as_i64().unwrap(), "{name}");
    }
}

/// case_063: W2, W3. A first install is larger than no policy: with no statement it is refused and nothing is
/// staged, and with the owner's statement it commits.
#[test]
fn case_063_a_first_install_needs_a_widening_statement() {
    let mut point = Point::new("063");
    let sealed = ppt(&old(), &at(1));
    assert_eq!(event_cause(&stage_alone(&mut point, &sealed, &old())), ("refused", Some("dist:widening-unsigned")));
    assert!(point.pep.staged().is_none());
    let (statement_sealed, statement) = statement_of(&sealed, &[]);
    stage_alone(&mut point, &statement_sealed, &statement);
    assert_eq!(stage_alone(&mut point, &sealed, &old()).event, "staged");
    assert_eq!(event_cause(&rec!(point, point.pep.commit(STREAM, 1, &h(&old()), 0))), ("committed", None));
}

/// case_139: W2, W6. A first install that says it does not widen is refused even with a statement whose `from` is
/// empty, and no release is active.
#[test]
fn case_139_a_first_install_that_says_it_does_not_widen_is_refused_with_a_statement() {
    let mut point = Point::new("139");
    let sealed = ppt(&old(), &Args { widens: false, ..at(1) });
    let (statement_sealed, statement) = statement_of(&sealed, &[]);
    assert_eq!(stage_alone(&mut point, &statement_sealed, &statement).event, "staged");
    assert_eq!(event_cause(&stage_alone(&mut point, &sealed, &old())), ("refused", Some("dist:widening-unsigned")));
    // only the statement is staged, so the release cannot commit (C2)
    assert_eq!(event_cause(&rec!(point, point.pep.commit(STREAM, 1, &h(&old()), 0))), ("refused", Some("dist:incomplete")));
    assert!(point.pep.active().is_none());
}

/// case_140: RB3, W2, W6. A host PEP that rolls back from another table to a kept renewal that says it does not
/// widen and holds a widening statement whose `from` is empty is refused, and the active release stays.
#[test]
fn case_140_a_rollback_to_a_kept_renewal_that_says_it_does_not_widen_is_refused() {
    let mut point = Point::new("140");
    point.commit_at(&old(), 1);
    let kept = ppt(&old(), &renewal(2, &old()));
    let (statement_sealed, statement) = statement_of(&kept, &[]);
    stage_alone(&mut point, &statement_sealed, &statement);
    assert_eq!(stage_alone(&mut point, &kept, &old()).event, "staged", "a renewal goes in, its statement unneeded");
    point.pep.commit(STREAM, 2, &h(&old()), 0).unwrap();
    point.commit(&new(), &Args { replaces: Some(h(&old())), ..at(3) });
    let refused = rec!(point, point.pep.rollback());
    assert_eq!(event_cause(&refused), ("refused", Some("dist:widening-unsigned")));
    assert_eq!((point.pep.active().unwrap().seq, point.host_active()), (3, json!(h(&new()).as_str())));
}

/// RB3, W2: the rollback shares the commit's rule. A kept table that says it widens and holds a statement from
/// the active hash rolls back, and the same rollback is refused once a statement from another hash is all it has.
#[test]
fn a_rollback_is_held_to_the_rule_a_commit_is() {
    for (from, rolled) in [(vec![], true), (vec![h(b"another")], false)] {
        let mut point = Point::new(&format!("rollback_rule_{}", from.len()));
        let first = ppt(&old(), &at(1));
        let (statement_sealed, statement) = statement_of(&first, &from);
        stage_alone(&mut point, &statement_sealed, &statement);
        // a first install has no active hash, so only a `from` that is empty covers it
        let staged = stage_alone(&mut point, &first, &old());
        if !rolled {
            assert_eq!(event_cause(&staged), ("refused", Some("dist:widening-unsigned")));
            continue;
        }
        point.pep.commit(STREAM, 1, &h(&old()), 0).unwrap();
        point.commit(&new(), &Args { replaces: Some(h(&old())), ..at(2) });
        assert_eq!(rec!(point, point.pep.rollback()).event, "rolled-back");
    }
}

/// W2, W6: on a host another table is larger whatever the signer says, so one that says it does not widen and
/// replaces the active hash is refused even with a statement whose `from` is empty, and the active table again
/// at a higher seq goes in on its signature alone.
#[test]
fn another_table_that_says_it_does_not_widen_is_refused_even_with_a_statement() {
    let mut point = Point::new("w6_table");
    point.commit_at(&old(), 1);
    let other = ppt(&new(), &renewal(2, &old()));
    let (statement_sealed, statement) = statement_of(&other, &[]);
    stage_alone(&mut point, &statement_sealed, &statement);
    assert_eq!(event_cause(&stage_alone(&mut point, &other, &new())), ("refused", Some("dist:widening-unsigned")));
    let same = ppt(&old(), &renewal(3, &old()));
    assert_eq!(stage_alone(&mut point, &same, &old()).event, "staged");
    let says_it_widens = ppt(&old(), &Args { replaces: Some(h(&old())), ..at(4) });
    assert_eq!(event_cause(&stage_alone(&mut point, &says_it_widens, &old())), ("refused", Some("dist:widening-unsigned")),
               "a release that says it widens needs a statement, whatever it compares as (W2)");
}

/// case_143: C3, V12, W2. A renewal staged with `widens` false and no statement, whose active release expires before
/// the commit, goes from no policy to one at commit, so it is refused with dist:widening-unsigned, stays staged and
/// nothing is active.
#[test]
fn case_143_a_renewal_whose_active_release_lapsed_before_its_commit_is_refused() {
    let mut point = Point::new("143");
    point.commit_at(&old(), 1);
    let staged = stage_alone(&mut point, &ppt(&old(), &Args { expires: EXPIRES + 86400, ..renewal(2, &old()) }), &old());
    assert_eq!(staged.event, "staged");
    point.now.set(EXPIRES);
    let refused = rec!(point, point.pep.commit(STREAM, 2, &h(&old()), 0));
    assert_eq!(event_cause(&refused), ("refused", Some("dist:widening-unsigned")));
    assert_eq!((refused.state, refused.staged_seq), ("no-policy", 2));
    assert!(point.pep.active().is_none() && point.pep.staged().is_some());
    assert_eq!(point.host_active(), json!(null));
}

/// P3, P5, X3, review note 8. A confirm whose write fails after the runtime withdrew holds nothing either, so it
/// never reports `active` over a withdrawn runtime.
#[test]
fn a_confirm_whose_write_fails_after_the_withdrawal_holds_nothing() {
    let mut point = Point::new("confirm_write");
    point.commit_at(&old(), 1);
    let fingerprint = point.pep.provision(&point.anchor()).unwrap();
    let trust = point.pep.store_path("trust.json");
    std::fs::remove_file(&trust).unwrap();
    std::fs::create_dir(&trust).unwrap(); // the trust store cannot be written over
    assert!(point.pep.confirm(&fingerprint).is_err());
    assert_eq!(point.host_active(), json!(null));
    assert!(point.pep.active().is_none() && point.pep.previous().is_none() && point.pep.staged().is_none());
    assert_ne!(point.pep.state(), "active");
    assert_eq!(point.pep.decide(|| "ran").unwrap().decision, None);
}

/// Runs one `commits` entry of the corpus on a host PEP provisioned to trust A on the corpus stream, as the Python
/// replay does: each `stage` step and each `commit` step at the entry's `now`. The cause of the last state record
/// and the seq of the release active after it.
fn replay_commit_entry(entry: &serde_json::Value, tag: &str) -> (Option<String>, i64) {
    assert_eq!(entry["kind"], "host", "{}", entry["name"]);
    let mut point = Point::new(tag);
    point.now.set(entry["now"].as_i64().unwrap());
    let mut last = None;
    for step in entry["steps"].as_array().unwrap() {
        let signed = if step["op"] == "stage" {
            let (sealed, body) = (hex::decode(step["sealed"].as_str().unwrap()).unwrap(), hex::decode(step["body"].as_str().unwrap()).unwrap());
            point.pep.stage(&sealed, &body).unwrap()
        } else {
            let seq = step["seq"].as_i64().unwrap();
            point.pep.commit(STREAM, seq, &Hex64::try_from(step["policy_sha256"].as_str().unwrap().to_string()).unwrap(), 0).unwrap()
        };
        last = Some(point.read(&signed));
    }
    let active = point.pep.active().map_or(0, |release| release.seq);
    (last.unwrap().cause, active)
}

fn commit_entries(case: i64) -> Vec<&'static serde_json::Value> {
    let found: Vec<_> = corpus()["commits"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| entry["case"] == case && entry["runs_on"].as_array().unwrap().iter().any(|one| one == "R"))
        .collect();
    assert!(!found.is_empty(), "the corpus has commit entries for case {case} that run on Rust");
    found
}

/// case_137: C2, E10. A first install whose signed release id names an artifact that is not staged (here a
/// `policy.spiral` its `policy.ppt` does not declare, which the transport withheld) is `dist:incomplete`, and no
/// release is active. The corpus entry Python recorded replays to the same cause and the same empty floor.
#[test]
fn case_137_a_first_install_whose_release_id_names_an_unstaged_artifact_is_incomplete() {
    for entry in commit_entries(137) {
        let (cause, active) = replay_commit_entry(entry, "137");
        assert_eq!((cause.as_deref(), active), (entry["expect"]["cause"].as_str(), entry["expect"]["active_seq"].as_i64().unwrap()), "{}", entry["name"]);
        assert_eq!((cause.as_deref(), active), (Some("dist:incomplete"), 0));
    }
    // the same first install by hand: the release id names a spiral that was never staged
    let mut point = Point::new("137_by_hand");
    let spiral = h(b"a spiral sidecar the transport withheld");
    let release = env::release_id(&[(ArtifactKind::PolicyPpt, h(&old())), (ArtifactKind::PolicySpiral, spiral)]).unwrap();
    point.stage(&ppt(&old(), &Args { release: Some(release), ..at(1) }), &old());
    let record = rec!(point, point.pep.commit(STREAM, 1, &h(&old()), 0));
    assert_eq!(record.cause.as_deref(), Some("dist:incomplete"));
    assert!(point.pep.active().is_none());
    assert_eq!(point.host_active(), json!(null));
}

/// case_138: C2, E10. An update whose signed release id names an artifact that is not staged is `dist:incomplete`
/// and the old release stays active, and the same update whose release id names only what is staged commits.
#[test]
fn case_138_an_update_whose_release_id_names_an_unstaged_artifact_keeps_the_old_release() {
    for entry in commit_entries(138) {
        let (cause, active) = replay_commit_entry(entry, "138");
        assert_eq!((cause.as_deref(), active), (entry["expect"]["cause"].as_str(), entry["expect"]["active_seq"].as_i64().unwrap()), "{}", entry["name"]);
    }
    let mut point = Point::new("138_by_hand");
    assert_eq!(point.commit_at(&old(), 1).cause, None);
    let spiral = h(b"a spiral sidecar the transport withheld");
    let release = env::release_id(&[(ArtifactKind::PolicyPpt, h(&new())), (ArtifactKind::PolicySpiral, spiral)]).unwrap();
    let args = Args { release: Some(release), replaces: Some(h(&old())), ..at(2) };
    let record = point.commit(&new(), &args);
    assert_eq!(record.cause.as_deref(), Some("dist:incomplete"));
    assert_eq!(point.pep.active().unwrap().seq, 1);
    assert_eq!(point.pep.active().unwrap().policy_sha256, h(&old()));
    assert_eq!(point.commit(&new(), &Args { replaces: Some(h(&old())), ..at(3) }).cause, None);
    assert_eq!(point.pep.active().unwrap().seq, 3);
}

/// case_281: E8, V5, ID8. An envelope of `identity.bundle` or `identity.map` for target `gateway` is well formed, so
/// a `host` PEP refuses it with `dist:target-mismatch` and not `dist:bad-format`, and an artifact name the closed
/// list does not hold is `dist:bad-format`. Rust builds the `host` kind only, so the `mesh` refusal is the C core's and
/// Python's, and the `gateway` PEP that accepts and reads the two bodies (ID1, ID2) is Python's; the names, the
/// kinds' roles and their body bound are the format's, which Rust reads and writes as Python does.
#[test]
fn case_281_the_identity_kinds_are_artifacts_a_host_pep_reads_and_refuses_for_another_target() {
    use prismpath_hotswap_rs::dist::verify::{self, PepView};
    let point = Point::new("281");
    let pep = PepView::new(TargetKind::Host, STREAM).unwrap();
    assert!(PepView::new(TargetKind::Gateway, STREAM).is_err(), "Rust builds no gateway PEP");
    let (bundle, map) = (canon2::write_json(&json!({"domains": {}, "encoding": "canon/2", "format": "prismpath.dist-identity-bundle/1"})).unwrap(),
                         canon2::write_json(&json!({"encoding": "canon/2", "entries": [], "format": "prismpath.dist-identity-map/1"})).unwrap());
    for (artifact, body) in [(ArtifactKind::IdentityBundle, &bundle), (ArtifactKind::IdentityMap, &map)] {
        assert_eq!(ArtifactKind::from_name(artifact.name()), Some(artifact));
        let args = Args { targets: vec![TargetKind::Gateway], seq: 2, ..Args::default() };
        let sealed = seal(artifact, body, &args);
        let verdict = verify::verify(&sealed, body, point.pep.trust(), &pep, NOW);
        assert_eq!(verdict.cause.as_deref(), Some("dist:target-mismatch"), "{artifact}");
        // a trusted release for the host itself is no better: no host PEP uses an identity kind
        let for_host = seal(artifact, body, &Args { seq: 2, ..Args::default() });
        assert_eq!(verify::verify(&for_host, body, point.pep.trust(), &pep, NOW).cause.as_deref(), Some("dist:target-mismatch"), "{artifact} for host");
    }
    // an artifact name the closed list does not hold is dist:bad-format, in the writer and in the reader
    let sealed = seal(ArtifactKind::IdentityMap, &map, &Args { targets: vec![TargetKind::Gateway], seq: 1, ..Args::default() });
    let (envelope_bytes, _) = env::unseal(&sealed).unwrap();
    let mut doc: serde_json::Value = serde_json::from_slice(envelope_bytes).unwrap();
    doc["artifact"] = json!("identity.other");
    let raw = canon2::write_json(&doc).unwrap();
    assert!(env::read(&raw).is_err());
    let resealed = env::seal(&raw, &[test_key("A")]).unwrap();
    assert_eq!(verify::verify(&resealed, &map, point.pep.trust(), &pep, NOW).cause.as_deref(), Some("dist:bad-format"));
    assert_eq!(ArtifactKind::from_name("identity.other"), None);
}
