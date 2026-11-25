// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! Section 21 in the Rust host PEP (spec-policy-distribution.md, 21.1 to 21.4): install statements and install
//! trust statements under an install record kept apart from the trust store, the fallback policy, the ceiling and
//! the action floor, as `prismpath/tests/test_distribution_install.py` and `test_distribution_floor.py` run the
//! Python machine. Each test names the conformance case of section 20 it covers, its `host` half where the case
//! names other kinds too.

#[path = "common/mod.rs"]
mod common;
#[path = "common/dist.rs"]
mod dist;
#[path = "common/install.rs"]
mod installs;

use dist::*;
use installs::*;
use prismpath_hotswap_rs::dist::envelope as env;
use prismpath_hotswap_rs::dist::floor;
use prismpath_hotswap_rs::dist::install::{self, SetKind};
use prismpath_hotswap_rs::dist::pep::PepError;
use prismpath_hotswap_rs::dist::state_record;
use prismpath_hotswap_rs::dist::trust::{anchor_bytes, Role};
use prismpath_hotswap_rs::dist::{ArtifactKind, Hex64, Stream, TargetKind};
use serde_json::json;

fn about(record: &state_record::StateRecord) -> (&'static str, Option<&str>) {
    Installer::about(record)
}

/// Provision `point` again with `anchor` and `brought`, the error text when it is refused.
fn provision(point: &mut Installer, anchor: &[u8], brought: &[(Vec<u8>, Vec<u8>)]) -> Result<state_record::StateRecord, String> {
    let fingerprint = point.pep.provision_with(anchor, brought).map_err(|error| error.to_string())?;
    let signed = point.pep.confirm(&fingerprint).map_err(|error| error.to_string())?;
    Ok(point.read(&signed))
}

/// The causes of the `refused` audit events since `from`.
fn refusals_since(point: &Installer, from: usize) -> Vec<String> {
    point.pep.audit.events()[from..]
        .iter()
        .filter(|event| event["action"] == "refused")
        .map(|event| event["data"]["cause"].as_str().unwrap_or_default().to_string())
        .collect()
}

fn floor_decides(point: &mut Installer, values: [i32; 4]) -> Option<&'static str> {
    point.pep.decide_request(Some(&request(values)), || "release").unwrap().basis
}

// ------------------------------------------------------------------ IS1, IS2, IS8, IS10, P4: provisioning

/// case_161: IS1, IS2, IS8, IS10, P4, the `host` half. A host PEP provisioned with an anchor holding two install keys,
/// an action floor and a fallback policy prints the envelope id of every install statement beside the anchor
/// fingerprint, its `provisioned` audit event names them, and both sets are held after a restart.
#[test]
fn case_161_an_anchor_brings_install_statements_that_are_printed_and_held_after_a_restart() {
    let floor = floor_set(&good_table(), &seq(1));
    let fallback = fallback_set(&image(9), &seq(1));
    let brought: Vec<_> = floor.iter().chain(fallback.iter()).cloned().collect();
    let anchor = anchor2(&["N1", "N2"], 2, &[], 0);
    let scratch = common::Scratch::new("dist_install_161");
    let now = std::rc::Rc::new(std::cell::Cell::new(NOW));
    let key = test_key("I");
    let mut pep = open_installer(&scratch.join("host"), &now, &key, None).unwrap();
    let fingerprint = pep.provision_with(&anchor, &brought).unwrap();
    let ids: Vec<Hex64> = brought.iter().map(|(sealed, _)| env::envelope_id(env::unseal(sealed).unwrap().0)).collect();
    assert_eq!(fingerprint, h(&anchor));
    assert_eq!(pep.printed(), ids.as_slice());
    let signed = pep.confirm(&fingerprint).unwrap();
    let record = state_record::read(&signed, &public("I")).unwrap();
    assert_eq!(about(&record), ("provisioned", Some("dist:install-widened"))); // H13: a first set at provisioning
    let provisioned = pep.audit.events().into_iter().rev().find(|event| event["action"] == "provisioned").unwrap();
    let mut named: Vec<String> = ids.iter().map(Hex64::to_string).collect();
    named.sort();
    assert_eq!(provisioned["data"]["install"], json!(named));
    drop(pep);
    let pep = open_installer(&scratch.join("host"), &now, &key, None).unwrap();
    assert_eq!(pep.installed.held(SetKind::Floor).map(|set| set.policy_sha256().clone()), Some(h(&good_table())));
    assert_eq!(pep.installed.held(SetKind::Fallback).map(|set| set.policy_sha256().clone()), Some(h(&image(9))));
    assert!(pep.trust().keys.keys().all(|kid| *kid != key_id("N1") && *kid != key_id("N2")), "K3: never in the trust store");
}

/// case_163: IS2, K4, O4, the `host` half. An anchor that holds one key in both roles and one whose install key is
/// the instance key are refused at provisioning; a release, a widening statement, a revocation and a rotation
/// signed only by install keys are `dist:unknown-key`; a rotation adding an install key or a retired install key is
/// `dist:rotation-invalid`.
#[test]
fn case_163_install_keys_and_authority_keys_are_strictly_apart() {
    let both = anchor2_with(&["A"], "C", Some((&["A", "N2"], 1, &[], 0, domain())));
    assert!(prismpath_hotswap_rs::dist::trust::read_anchor(&both).is_err());
    let mut point = Installer::new("163", 2);
    let instance = anchor2_with(&["A"], "C", Some((&["I", "N2"], 1, &[], 0, domain())));
    assert!(point.pep.provision_with(&instance, &[]).is_err());
    let by_install = Args { signers: vec!["N1", "N2"], ..at(1) };
    assert_eq!(point.send(&[(ppt(&image(5), &by_install), image(5))]).cause.as_deref(), Some("dist:unknown-key"));
    let (statement, body) = statement_of(&ppt(&image(5), &at(1)), &[]);
    let resigned = env::seal(env::unseal(&statement).unwrap().0, &[test_key("N1"), test_key("N2")]).unwrap();
    assert_eq!(point.send(&[(resigned, body)]).cause.as_deref(), Some("dist:unknown-key"));
    let list = revocation(&[], &[], &[], &[]);
    let revoke = trust_statement(ArtifactKind::TrustRevocation, &list, 1, &["N1", "N2"], &[TargetKind::Host]);
    assert_eq!(point.send(&[(revoke, list)]).cause.as_deref(), Some("dist:unknown-key"));
    let body = rotation("B", None);
    let rotate = trust_statement(ArtifactKind::TrustRotation, &body, 1, &["N1", "N2"], &[TargetKind::Host]);
    assert_eq!(point.send(&[(rotate, body)]).cause.as_deref(), Some("dist:unknown-key"));
    let body = rotation("N3", None);
    let rotate = trust_statement(ArtifactKind::TrustRotation, &body, 1, &["A", "N3"], &[TargetKind::Host]);
    assert_eq!(point.send(&[(rotate, body)]).cause.as_deref(), Some("dist:rotation-invalid"));
    point.send(&[install_trust(&["N1", "N2"], 2, &[], 1, &["N1", "N2"], false)]); // N3 is retired
    let body = rotation("N3", None);
    let rotate = trust_statement(ArtifactKind::TrustRotation, &body, 1, &["A", "N3"], &[TargetKind::Host]);
    assert_eq!(point.send(&[(rotate, body)]).cause.as_deref(), Some("dist:rotation-invalid"));
    assert_eq!(point.pep.trust().trust_seq, 0);
}

/// case_230: P4, CL4, K3, K4. A `/1` anchor holding an `install` member and a `/2` anchor whose `domain` is not
/// the hash of the domain the PEP was built with are refused at provisioning; a good `/2` anchor provisions the
/// install keys into the install record and none into the trust store, and a release one of them signs is
/// `dist:unknown-key`.
#[test]
fn case_230_the_install_part_of_a_second_version_anchor_goes_to_the_install_record() {
    let one = anchor_of(&["A"]);
    let mut doc: serde_json::Value = serde_json::from_slice(&one).unwrap();
    doc["install"] = serde_json::to_value(install::anchor_part(&[public("N1")], 1, &[], 0, &domain())).unwrap();
    let with_part = prismpath_rs::canon2::write_json(&doc).unwrap();
    assert!(prismpath_hotswap_rs::dist::trust::read_anchor(&with_part).is_err());
    let scratch = common::Scratch::new("dist_install_230");
    let now = std::rc::Rc::new(std::cell::Cell::new(NOW));
    let mut pep = open_installer(&scratch.join("host"), &now, &test_key("I"), None).unwrap();
    assert!(pep.provision_with(&with_part, &[]).is_err());
    let other = anchor2_with(&["A"], "C", Some((&["N1"], 1, &[], 0, h(b"another domain"))));
    assert!(pep.provision_with(&other, &[]).is_err());
    let fingerprint = pep.provision_with(&anchor2(&["N1", "N2"], 2, &[], 0), &[]).unwrap();
    pep.confirm(&fingerprint).unwrap();
    let record = pep.installed.record.clone().unwrap();
    assert_eq!(record.keys.keys().cloned().collect::<Vec<_>>(), {
        let mut ids = vec![key_id("N1"), key_id("N2")];
        ids.sort();
        ids
    });
    assert!(!pep.trust().keys.contains_key(&key_id("N1")) && !pep.trust().keys.contains_key(&key_id("N2")));
    let signed = pep.stage(&ppt(&image(5), &Args { signers: vec!["N1"], ..at(1) }), &image(5)).unwrap();
    assert_eq!(state_record::read(&signed, &public("I")).unwrap().cause.as_deref(), Some("dist:unknown-key"));
}

/// case_235: P4, P2, K4. An anchor whose `keys` holds an entry in the role `install` is `dist:bad-format`. A PEP that
/// holds an install record is provisioned from a `/1` anchor and from a `/2` anchor with no `install` member with
/// its install record, sets and sequences unchanged, and refuses a `/1` anchor whose authority key is a held install
/// key and one whose authority key is an operator key it retired.
#[test]
fn case_235_an_anchor_without_an_install_part_leaves_the_install_record_as_it_was() {
    let install_role = anchor_bytes(&[public("A")], TargetKind::Host, &Stream::try_from(STREAM).unwrap(), &Role::try_from("install".to_string()).unwrap());
    assert_eq!(install_role.unwrap_err().cause, "dist:bad-format");
    let mut point = Installer::with("235", &anchor2(&INSTALL_KEYS, 2, &["O1", "O2"], 0), &[], false);
    point.send(&floor_set(&good_table(), &seq(4)));
    let before = point.pep.installed.record.clone().unwrap();
    assert_eq!(provision(&mut point, &anchor_of(&["A"]), &[]).unwrap().event, "provisioned");
    assert_eq!(point.pep.installed.record.clone().unwrap(), before);
    assert_eq!(provision(&mut point, &anchor2_with(&["A"], "C", None), &[]).unwrap().event, "provisioned");
    assert_eq!(point.pep.installed.record.clone().unwrap(), before);
    assert!(provision(&mut point, &anchor_of(&["N1"]), &[]).is_err());
    point.send(&[install_trust(&INSTALL_KEYS, 2, &["O1"], 1, &["N1", "N2"], false)]); // O2 is retired
    assert!(point.pep.installed.record.as_ref().unwrap().retired.contains(&key_id("O2")));
    assert!(provision(&mut point, &anchor_of(&["O2"]), &[]).is_err());
}

/// case_236: P2, K4. An anchor whose operator key is the instance key, one whose install key is also an operator
/// key, and one whose install key is the instance key are refused at provisioning and the PEP is unchanged.
#[test]
fn case_236_an_anchor_whose_roles_overlap_the_instance_key_or_each_other_is_refused() {
    let mut point = Installer::new("236", 2);
    let before = point.pep.installed.record.clone();
    for anchor in [
        anchor2_with(&["A"], "C", Some((&["N1"], 1, &["I"], 0, domain()))),
        anchor2_with(&["A"], "C", Some((&["N1"], 1, &["N1"], 0, domain()))),
        anchor2_with(&["A"], "C", Some((&["I"], 1, &[], 0, domain()))),
    ] {
        let refused = match prismpath_hotswap_rs::dist::trust::read_anchor(&anchor) {
            Err(_) => true,
            Ok(_) => point.pep.provision_with(&anchor, &[]).is_err(),
        };
        assert!(refused);
    }
    assert_eq!(point.pep.installed.record, before);
    assert_eq!(point.pep.state(), "no-policy");
}

/// case_280: P2, K4, K6, the `host` half. An anchor whose controller key is an install key, an operator key or the
/// PEP's instance key is refused at provisioning, and the PEP is unchanged.
#[test]
fn case_280_an_anchor_whose_controller_key_is_in_another_role_is_refused() {
    let mut point = Installer::with("280", &anchor2(&INSTALL_KEYS, 2, &["O1"], 0), &[], false);
    let before = point.pep.installed.record.clone();
    let as_install = anchor2_with(&["A"], "N1", Some((&["N1"], 1, &[], 1, domain())));
    let as_operator = anchor2_with(&["A"], "O1", Some((&["N2"], 1, &["O1"], 1, domain())));
    assert!(prismpath_hotswap_rs::dist::trust::read_anchor(&as_install).is_err());
    assert!(prismpath_hotswap_rs::dist::trust::read_anchor(&as_operator).is_err());
    let as_instance = anchor2_with(&["A"], "I", None);
    assert!(matches!(point.pep.provision_with(&as_instance, &[]), Err(PepError::Refused(_))));
    // a held operator key named as the controller key of an anchor with no install part
    assert!(point.pep.provision_with(&anchor2_with(&["A"], "O1", None), &[]).is_err());
    assert_eq!(point.pep.installed.record, before);
}

/// case_224: K4, O4, IS11. An anchor whose operator key is an authority key or an install key is refused at
/// provisioning; a rotation adding an operator key or a retired operator key, an `install.trust` that puts one key
/// in both lists and one adding to `operators` a key retired as an install key are `dist:rotation-invalid`; one
/// that drops an operator key is applied with the key retired, and one that adds it again is `dist:rotation-invalid`.
#[test]
fn case_224_operator_keys_are_apart_from_every_other_role() {
    assert!(prismpath_hotswap_rs::dist::trust::read_anchor(&anchor2_with(&["A"], "C", Some((&["N1"], 1, &["A"], 0, domain())))).is_err());
    assert!(prismpath_hotswap_rs::dist::trust::read_anchor(&anchor2_with(&["A"], "C", Some((&["N1"], 1, &["N1"], 0, domain())))).is_err());
    let mut point = Installer::with("224", &anchor2(&INSTALL_KEYS, 2, &["O1", "O2"], 0), &[], false);
    let rotate = |add: &'static str| {
        let body = rotation(add, None);
        (trust_statement(ArtifactKind::TrustRotation, &body, 1, &["A", add], &[TargetKind::Host]), body)
    };
    assert_eq!(point.send(&[rotate("O1")]).cause.as_deref(), Some("dist:rotation-invalid"));
    assert_eq!(point.send(&[install_trust(&["N1", "N2", "N3", "O1"], 2, &["O1", "O2"], 1, &["N1", "N2"], true)]).cause.as_deref(), Some("dist:rotation-invalid"));
    point.send(&[install_trust(&["N1", "N2"], 2, &["O1", "O2"], 1, &["N1", "N2"], false)]); // N3 retired
    assert_eq!(point.send(&[install_trust(&["N1", "N2"], 2, &["N3", "O1", "O2"], 2, &["N1", "N2", "N3"], true)]).cause.as_deref(), Some("dist:rotation-invalid"));
    let dropped = point.send(&[install_trust(&["N1", "N2"], 2, &["O1"], 2, &["N1", "N2"], false)]);
    assert_eq!(dropped.event, "install-applied");
    assert!(point.pep.installed.record.as_ref().unwrap().retired.contains(&key_id("O2")));
    assert_eq!(point.send(&[rotate("O2")]).cause.as_deref(), Some("dist:rotation-invalid"));
    assert_eq!(point.send(&[install_trust(&["N1", "N2"], 2, &["O1", "O2"], 3, &["N1", "N2", "O2"], true)]).cause.as_deref(), Some("dist:rotation-invalid"));
}

/// case_261: K6, K4, S3, O4, IS11, the `host` half. A release, a revocation and a rotation signed only by the
/// controller key are `dist:unknown-key`, and a rotation and an `install.trust` that try to add the controller key
/// are `dist:rotation-invalid`. The controller key is held in its own role, which counts on no envelope.
#[test]
fn case_261_the_controller_key_signs_no_envelope_and_is_never_added_in_another_role() {
    let mut point = Installer::new("261", 2);
    assert_eq!(point.send(&[(ppt(&image(5), &by(1, "C")), image(5))]).cause.as_deref(), Some("dist:unknown-key"));
    let list = revocation(&[], &[], &[], &[]);
    let revoke = trust_statement(ArtifactKind::TrustRevocation, &list, 1, &["C"], &[TargetKind::Host]);
    assert_eq!(point.send(&[(revoke, list)]).cause.as_deref(), Some("dist:unknown-key"));
    let body = rotation("B", None);
    assert_eq!(point.send(&[(trust_statement(ArtifactKind::TrustRotation, &body, 1, &["C", "B"], &[TargetKind::Host]), body)]).cause.as_deref(), Some("dist:unknown-key"));
    let body = rotation("C", None);
    assert_eq!(point.send(&[(trust_statement(ArtifactKind::TrustRotation, &body, 1, &["A", "C"], &[TargetKind::Host]), body)]).cause.as_deref(), Some("dist:rotation-invalid"));
    assert_eq!(point.send(&[install_trust(&["C", "N1", "N2", "N3"], 2, &[], 1, &["C", "N1", "N2"], true)]).cause.as_deref(), Some("dist:rotation-invalid"));
}

// ------------------------------------------------------------------ IS1 to IS6: what a statement must be

/// case_162: IS1, IS2, IS5. An install statement signed only by authority keys, one with `expires` 30 days on, one
/// whose `targets` names two kinds, one for another stream, one whose body is one byte short, one whose body fails
/// the check of the artifact `as` names, one with no `as`, and, on a PEP with a clock, one whose `not_before` is
/// 301 seconds ahead: each refused with its cause and what the PEP holds unchanged.
#[test]
fn case_162_an_install_statement_is_refused_for_each_thing_it_gets_wrong() {
    let mut point = Installer::new("162", 2);
    let body = good_table();
    let doc = floor_doc(&body, &seq(1));
    let by_authority = raw_sealed(&doc, &body, &["A"]);
    let expires = raw_sealed(&prismpath_hotswap_rs::dist::envelope::EnvelopeDoc { expires: NOT_BEFORE + 30 * 86400, ..doc.clone() }, &body, &["N1", "N2"]);
    let two = raw_sealed(&prismpath_hotswap_rs::dist::envelope::EnvelopeDoc { targets: [TargetKind::Host, TargetKind::Mesh].into_iter().collect(), ..doc.clone() }, &body, &["N1", "N2"]);
    let stream = floor_set(&body, &SetArgs { stream: "host/other".into(), ..seq(1) }).remove(0).0;
    let sealed = floor_set(&body, &seq(1)).remove(0).0;
    let bad = table(&[vec![(0, EQ, 3), (1, GE, 2), (1, LE, 5)]]);
    let mut broken = bad.clone();
    broken[0] ^= 1; // not a table: the check of policy.ppt refuses it
    let broken_sealed = raw_sealed(&floor_doc(&broken, &SetArgs { meta: Some(table_meta(&bad)), ..seq(1) }), &broken, &["N1", "N2"]);
    let mut no_as = doc.clone();
    if let prismpath_rs::canon2::Doc::Obj(members) = &mut no_as.meta {
        members.retain(|(name, _)| name != "as");
    }
    let no_as = raw_sealed(&no_as, &body, &["N1", "N2"]);
    let ahead = floor_set(&body, &SetArgs { not_before: NOW + 301, ..seq(1) }).remove(0).0;
    let cases: Vec<(Vec<u8>, Vec<u8>, &str)> = vec![
        (by_authority, body.clone(), "dist:unknown-key"),
        (expires, body.clone(), "dist:bad-format"),
        (two, body.clone(), "dist:bad-format"),
        (stream, body.clone(), "dist:target-mismatch"),
        (sealed, body[..body.len() - 1].to_vec(), "dist:body-mismatch"),
        (broken_sealed, broken.clone(), "image:bad-magic"),
        (no_as, body.clone(), "dist:bad-format"),
        (ahead, body.clone(), "dist:not-yet-valid"),
    ];
    let before = point.pep.installed.record.clone();
    for (sealed, body, cause) in cases {
        let record = point.send(&[(sealed, body)]);
        assert_eq!(about(&record), ("refused", Some(cause)));
        assert_eq!(point.pep.installed.record, before);
        assert!(point.pep.installed.staged.is_empty());
    }
}

/// case_165: IS2. With three install keys and an install threshold of 2, a statement with one good signature is
/// `dist:unknown-key`, one with two is applied, and one with one good signature and one by a retired install key is
/// `sig:revoked-key`.
#[test]
fn case_165_an_install_statement_counts_against_the_install_threshold() {
    let mut point = Installer::new("165", 2);
    let one = floor_set(&good_table(), &SetArgs { signers: vec!["N1"], ..seq(1) });
    assert_eq!(point.send(&one).cause.as_deref(), Some("dist:unknown-key"));
    assert_eq!(point.send(&floor_set(&good_table(), &seq(1))).event, "install-widened");
    point.send(&[install_trust(&["N1", "N2", "N4"], 2, &[], 1, &["N1", "N2", "N4"], true)]); // N3 retired
    let retired = floor_set(&floor_of(4), &SetArgs { signers: vec!["N1", "N3"], ..seq(2) });
    assert_eq!(point.send(&retired).cause.as_deref(), Some("sig:revoked-key"));
}

/// case_166: IS4, IS2. On an install threshold of 1 a well signed action floor and a well signed `install.trust` in a
/// message are `dist:target-mismatch` and nothing changes; an install provisioning of the same floor holds it.
#[test]
fn case_166_an_install_threshold_of_1_takes_install_statements_by_provisioning_only() {
    let mut point = Installer::new("166", 1);
    let floor = floor_set(&good_table(), &SetArgs { signers: vec!["N1"], ..seq(1) });
    assert_eq!(point.send(&floor).cause.as_deref(), Some("dist:target-mismatch"));
    assert_eq!(point.send(&[install_trust(&INSTALL_KEYS, 1, &[], 1, &["N1"], false)]).cause.as_deref(), Some("dist:target-mismatch"));
    assert_eq!(point.held(FLOOR), None);
    assert_eq!(point.pep.installed.record.as_ref().unwrap().trust_seq, 0);
    let records = point.pep.provision_install(&floor).unwrap();
    assert_eq!(point.read(records.last().unwrap()).event, "install-widened");
    assert_eq!(point.held(FLOOR), Some(h(&good_table())));
}

/// case_169: IS6. A PEP holding an action floor at `seq` 3 refuses one at 2 and another at 3, takes the same one again
/// as no change, applies one at 5, refuses one at 4, and applies a fallback policy at 1.
#[test]
fn case_169_each_install_kind_keeps_its_own_install_sequence() {
    let mut point = Installer::new("169", 2);
    let held = floor_set(&good_table(), &seq(3));
    point.send(&held);
    assert_eq!(point.send(&floor_set(&floor_of(4), &seq(2))).cause.as_deref(), Some("dist:seq-replay"));
    assert_eq!(point.send(&floor_set(&floor_of(4), &seq(3))).cause.as_deref(), Some("dist:seq-replay"));
    assert_eq!(about(&point.send(&held)), ("beat", None));
    let five = SetArgs { replaces: Some(h(&good_table())), ..seq(5) };
    assert_eq!(point.send(&floor_set(&floor_of(4), &five)).event, "install-widened");
    assert_eq!(point.send(&floor_set(&floor_of(6), &seq(4))).cause.as_deref(), Some("dist:seq-replay"));
    assert_eq!(point.send(&fallback_set(&image(9), &seq(1))).event, "install-widened");
    assert_eq!((point.seq_of(FLOOR), point.seq_of(FALLBACK), point.held(FLOOR)), (5, 1, Some(h(&floor_of(4)))));
}

/// case_171: IS6, FB1. A `locked` PEP with an install threshold of 2 applies a fallback policy at a higher `seq` and
/// stays `locked`.
#[test]
fn case_171_a_locked_pep_still_takes_install_statements() {
    let mut point = Installer::new("171", 2);
    std::fs::write(point.dist().join("floor.json"), b"not a floor").unwrap();
    point.reopen();
    assert_eq!(point.pep.state(), "locked");
    let record = point.send(&fallback_set(&image(9), &seq(1)));
    assert_eq!((record.event, record.state, record.fallback), ("install-widened", "locked", true));
    assert_eq!(point.pep.state(), "locked");
}

/// case_175: IS11, IS7. An `install.trust` two above the install trust sequence, one without the signature of the
/// key it adds, one with fewer signatures than the threshold, one with five keys, one with a threshold of 0, one
/// adding the instance key, a trusted authority key, a key id on the revocation list or a retired install key, and
/// one signed only by authority keys: each refused with its cause, and the trust store is what it was.
#[test]
fn case_175_an_install_trust_statement_is_refused_for_each_thing_it_gets_wrong() {
    let mut point = Installer::new("175", 2);
    let list = revocation(&[], &[key_id("R")], &[], &[]);
    point.send(&[(trust_statement(ArtifactKind::TrustRevocation, &list, 1, &["A"], &[TargetKind::Host]), list)]);
    point.send(&[install_trust(&["N1", "N2"], 2, &[], 1, &["N1", "N2"], false)]); // N3 retired
    let trust = point.pep.trust().clone();
    let keys = |extra: &'static str| vec!["N1", "N2", extra];
    let five = {
        let publics: Vec<String> = ["N1", "N2", "N4", "N5", "N6"].iter().map(|name| hex::encode(public(name))).collect();
        let mut sorted = publics.clone();
        sorted.sort();
        prismpath_rs::canon2::write_json(&json!({"encoding": "canon/2", "format": "prismpath.dist-install-trust/1",
                                                 "keys": sorted, "operators": [], "threshold": 2})).unwrap()
    };
    let pair = {
        let mut keys: Vec<String> = ["N1", "N2"].iter().map(|name| hex::encode(public(name))).collect();
        keys.sort();
        keys
    };
    let zero = prismpath_rs::canon2::write_json(&json!({"encoding": "canon/2", "format": "prismpath.dist-install-trust/1",
                                                        "keys": pair, "operators": [], "threshold": 0})).unwrap();
    let with_body = |body: &[u8], signers: &[&str]| {
        let (sealed, _) = install_trust(&["N1", "N2"], 2, &[], 2, &["N1", "N2"], true);
        let (bytes, _) = env::unseal(&sealed).unwrap();
        let doc: prismpath_hotswap_rs::dist::envelope::EnvelopeDoc = prismpath_rs::canon2::codec::from_bytes(bytes).unwrap();
        (raw_sealed(&doc, body, signers), body.to_vec())
    };
    let cases = vec![
        (install_trust(&keys("N4"), 2, &[], 3, &["N1", "N2", "N4"], true), "dist:trust-replay"),
        (install_trust(&keys("N4"), 2, &[], 2, &["N1", "N2"], true), "dist:rotation-invalid"),
        (install_trust(&keys("N4"), 2, &[], 2, &["N1", "N4"], true), "dist:unknown-key"),
        (with_body(&five, &["N1", "N2"]), "dist:too-large"),
        (with_body(&zero, &["N1", "N2"]), "dist:bad-format"),
        (install_trust(&keys("I"), 2, &[], 2, &["N1", "N2", "I"], true), "dist:rotation-invalid"),
        (install_trust(&keys("A"), 2, &[], 2, &["N1", "N2", "A"], true), "dist:rotation-invalid"),
        (install_trust(&keys("R"), 2, &[], 2, &["N1", "N2", "R"], true), "dist:rotation-invalid"),
        (install_trust(&keys("N3"), 2, &[], 2, &["N1", "N2", "N3"], true), "dist:rotation-invalid"),
        (install_trust(&keys("N4"), 2, &[], 2, &["A"], true), "dist:unknown-key"),
    ];
    for (statement, cause) in cases {
        assert_eq!(point.send(&[statement]).cause.as_deref(), Some(cause));
    }
    assert_eq!(point.pep.trust(), &trust);
    assert_eq!(point.pep.installed.record.as_ref().unwrap().trust_seq, 1);
}

/// case_176: IS11. Four install keys at a threshold of 4 cannot add a fifth in one statement, which needs five
/// signatures and a sealed envelope holds four (S2), so the sealing refuses it. The engineer drops a key with the
/// threshold at 3, then adds the new one, and both statements are applied.
#[test]
fn case_176_a_statement_that_needs_five_signatures_is_made_in_two() {
    let four = ["N1", "N2", "N3", "N4"];
    let mut point = Installer::with("176", &anchor2(&four, 4, &[], 0), &[], false);
    let body = install::trust_body(&["N1", "N2", "N3", "N4", "N5"].map(public), 4, &[]);
    assert_eq!(body.unwrap_err().cause, "dist:too-large"); // five keys is past the bound as well
    let (sealed, _) = install_trust(&["N1", "N2", "N3", "N5"], 4, &[], 1, &["N1", "N2", "N3", "N4"], true);
    let (bytes, _) = env::unseal(&sealed).unwrap();
    assert!(env::seal(bytes, &["N1", "N2", "N3", "N4", "N5"].map(test_key)).is_err(), "S2: four signatures at most");
    // the first lowers the threshold, which widens (IS11)
    assert_eq!(point.send(&[install_trust(&["N1", "N2", "N3"], 3, &[], 1, &["N1", "N2", "N3", "N4"], true)]).event, "install-widened");
    assert_eq!(point.send(&[install_trust(&["N1", "N2", "N3", "N5"], 3, &[], 2, &["N1", "N2", "N3", "N5"], true)]).event, "install-widened");
    assert_eq!(point.pep.installed.record.as_ref().unwrap().threshold, 3);
}

/// case_177: IS11. Nine install keys are retired one after another, so the ninth retirement forgets the first id, and
/// a floor signed by the first retired key and one current key is `dist:unknown-key`.
#[test]
fn case_177_a_ninth_retired_install_key_forgets_the_first() {
    let mut point = Installer::with("177", &anchor2(&["N1", "N2", "K0"], 2, &[], 0), &[], false);
    let names = ["K0", "K1", "K2", "K3", "K4", "K5", "K6", "K7", "K8", "K9"];
    for index in 0..9 {
        let (old, new) = (names[index], names[index + 1]);
        let record = point.send(&[install_trust(&["N1", "N2", new], 2, &[], index as i64 + 1, &["N1", "N2", new], true)]);
        assert_eq!(record.event, "install-widened", "retiring {old}");
    }
    let retired = &point.pep.installed.record.as_ref().unwrap().retired;
    assert_eq!(retired.len(), 8);
    assert!(!retired.contains(&key_id("K0")));
    let floor = floor_set(&good_table(), &SetArgs { signers: vec!["K0", "N1"], ..seq(1) });
    assert_eq!(point.send(&floor).cause.as_deref(), Some("dist:unknown-key"));
}

/// case_178: IS1, IS6, IS12. The empty set of the action floor at a higher `seq` withdraws the floor with event
/// `install-applied` and the PEP holds none; the held floor sent again is `dist:seq-replay`; the empty ceiling is
/// applied with event `install-widened`.
#[test]
fn case_178_the_empty_set_withdraws_its_install_kind() {
    let mut point = Installer::new("178", 2);
    let held = floor_set(&good_table(), &seq(1));
    point.send(&held);
    point.send(&ceiling_set(&[&good_table(), &image(5)], &SetArgs { widens: false, ..seq(1) }));
    let empty = point.send(&empty_set(FLOOR, &SetArgs { widens: false, replaces: Some(h(&good_table())), ..seq(2) }));
    assert_eq!(about(&empty), ("install-applied", None));
    assert_eq!(point.held(FLOOR), None);
    assert_eq!(point.send(&held).cause.as_deref(), Some("dist:seq-replay"));
    let ceiling = point.held(CEILING).unwrap();
    let empty = point.send(&empty_set(CEILING, &SetArgs { widens: false, replaces: Some(ceiling), ..seq(2) }));
    assert_eq!(about(&empty), ("refused", Some("dist:widening-unsigned")));
    let empty = point.send(&empty_set(CEILING, &SetArgs { widens: true, ..seq(2) }));
    assert_eq!(about(&empty), ("install-widened", Some("dist:install-widened")));
    assert_eq!(point.held(CEILING), None);
    // the empty set is not held, so the install id counts zeros for both, and what follows replaces nothing
    let id = Installer::entry(&empty).install_id;
    let record = point.pep.installed.record.clone().unwrap();
    assert_eq!(id, record.install_id());
    assert_eq!(point.send(&floor_set(&floor_of(4), &SetArgs { widens: false, ..seq(3) })).cause.as_deref(), Some("dist:widening-unsigned"));
    assert_eq!(point.send(&floor_set(&floor_of(4), &seq(3))).event, "install-widened");
}

/// case_218: IS11, IS12, AF8. An `install.trust` that adds a key with `widens` false is `dist:widening-unsigned`, one
/// that lowers the threshold with `widens` true is applied with event `install-widened`, and a floor at a higher
/// `seq` with the same table and a looser `rate` and `widens` false is `dist:widening-unsigned`.
#[test]
fn case_218_a_wider_install_trust_or_a_looser_rate_must_say_it_widens() {
    let mut point = Installer::new("218", 2);
    point.send(&floor_set(&good_table(), &SetArgs { rate: Some((2, 60)), ..seq(1) }));
    assert_eq!(point.send(&[install_trust(&["N1", "N2", "N3", "N4"], 2, &[], 1, &["N1", "N2", "N4"], false)]).cause.as_deref(), Some("dist:widening-unsigned"));
    let lower = point.send(&[install_trust(&INSTALL_KEYS, 1, &[], 1, &["N1", "N2"], true)]);
    assert_eq!((lower.event, Installer::entry(&lower).subject), ("install-widened", "install.trust"));
    let looser = SetArgs { widens: false, replaces: Some(h(&good_table())), rate: Some((3, 60)), signers: vec!["N1"], ..seq(2) };
    assert_eq!(point.pep.installed.record.as_ref().unwrap().threshold, 1);
    let records = point.pep.provision_install(&floor_set(&good_table(), &looser)).unwrap();
    assert_eq!(point.read(records.last().unwrap()).cause.as_deref(), Some("dist:widening-unsigned"));
    let same = SetArgs { rate: Some((2, 60)), ..looser };
    let records = point.pep.provision_install(&floor_set(&good_table(), &same)).unwrap();
    assert_eq!(point.read(records.last().unwrap()).event, "install-applied");
}

/// case_221: OP1, IS11, H13, the PEP half. An anchor enrolls one operator key; an `install.trust` adding a second
/// with `widens` false is `dist:widening-unsigned` and with `widens` true is applied with event `install-widened`;
/// one adding a key that is an install key is `dist:rotation-invalid`; an operator key signing an install statement
/// and a release is `dist:unknown-key` twice. The controller's half is the Python controller's (H13).
#[test]
fn case_221_an_operator_key_is_enrolled_by_the_engineer_and_signs_nothing_else() {
    let mut point = Installer::with("221", &anchor2(&INSTALL_KEYS, 2, &["O1"], 0), &[], false);
    assert!(point.pep.installed.record.as_ref().unwrap().operators.contains_key(&key_id("O1")));
    assert_eq!(point.send(&[install_trust(&INSTALL_KEYS, 2, &["O1", "O2"], 1, &["N1", "N2", "O2"], false)]).cause.as_deref(), Some("dist:widening-unsigned"));
    assert_eq!(point.send(&[install_trust(&INSTALL_KEYS, 2, &["O1", "O2"], 1, &["N1", "N2", "O2"], true)]).event, "install-widened");
    assert_eq!(point.send(&[install_trust(&INSTALL_KEYS, 2, &["N3", "O1", "O2"], 2, &["N1", "N2"], true)]).cause.as_deref(), Some("dist:rotation-invalid"));
    assert_eq!(point.send(&floor_set(&good_table(), &SetArgs { signers: vec!["O1"], ..seq(1) })).cause.as_deref(), Some("dist:unknown-key"));
    assert_eq!(point.send(&[(ppt(&image(5), &by(1, "O1")), image(5))]).cause.as_deref(), Some("dist:unknown-key"));
}

/// case_223: IS1, IS5, the `host` half. A floor whose `meta` carries counts that differ from the table is
/// `manifest:count-mismatch`, one with no `qualification` is `dist:bad-format`, and one whose members are those of
/// its `policy.ppt` is applied.
#[test]
fn case_223_a_host_floor_carries_the_members_of_its_policy_ppt() {
    let mut point = Installer::new("223", 2);
    let body = good_table();
    let mut counts = table_meta(&body);
    counts["counts"]["atoms"] = json!(9);
    assert_eq!(point.send(&floor_set(&body, &SetArgs { meta: Some(counts), ..seq(1) })).cause.as_deref(), Some("manifest:count-mismatch"));
    let mut missing = table_meta(&body);
    missing.as_object_mut().unwrap().remove("qualification");
    let doc = floor_doc(&body, &SetArgs { meta: Some(missing), ..seq(1) });
    assert_eq!(point.send(&[(raw_sealed(&doc, &body, &["N1", "N2"]), body.clone())]).cause.as_deref(), Some("dist:bad-format"));
    assert_eq!(point.send(&floor_set(&body, &seq(1))).event, "install-widened");
}

/// case_225: V5, V13, OP1, OP2, the `host` half. A `host` PEP, which has no escalation, is sent a well signed
/// `operator.answer`, by an operator key it holds and by one it does not: `dist:target-mismatch` each time.
#[test]
fn case_225_a_host_takes_no_operator_answer() {
    let mut point = Installer::with("225", &anchor2(&INSTALL_KEYS, 2, &["O1"], 0), &[], false);
    let time_floor = point.pep.trust().time_floor;
    assert_eq!(point.send(&[answer("O1")]).cause.as_deref(), Some("dist:target-mismatch"));
    assert_eq!(point.send(&[answer("O9")]).cause.as_deref(), Some("dist:target-mismatch"));
    assert_eq!(point.pep.trust().time_floor, time_floor);
}

/// case_233: IS13, IS11. On an install threshold of 1 with two operator keys, an install provisioning that carries an
/// `install.trust` dropping one of them is applied with the key retired, the trust state and the floor of section 6
/// unchanged, and an answer that key signs is `dist:target-mismatch`.
#[test]
fn case_233_an_install_provisioning_takes_an_operator_key_back() {
    let mut point = Installer::with("233", &anchor2(&INSTALL_KEYS, 1, &["O1", "O2"], 0), &[], false);
    point.commit(&image(5), &at(3));
    let (trust, floor) = (point.pep.trust().clone(), point.pep.floor().clone());
    let records = point.pep.provision_install(&[install_trust(&INSTALL_KEYS, 1, &["O1"], 1, &["N1"], false)]).unwrap();
    assert_eq!(point.read(records.last().unwrap()).event, "install-applied");
    let record = point.pep.installed.record.clone().unwrap();
    assert!(record.retired.contains(&key_id("O2")) && !record.operators.contains_key(&key_id("O2")));
    assert_eq!((point.pep.trust(), point.pep.floor()), (&trust, &floor));
    assert!(point.actions().contains(&"install-provisioned".to_string()));
    assert_eq!(point.send(&[answer("O2")]).cause.as_deref(), Some("dist:target-mismatch"));
}

// ------------------------------------------------------------------ IS6, IS9, IS10, IS13: provisioning and loss

/// The older pack form of `body` (`ppt-pack/1`), signed by a key the host trusts, and the host that trusts it.
fn older_form(state_dir: &std::path::Path, scratch: &std::path::Path, body: &[u8]) -> (prismpath_hotswap_rs::host::PolicyHost, String) {
    let keys = scratch.join("keys");
    let (private, public_path, _) = prismpath_hotswap_rs::keygen(keys.to_str().unwrap(), "authority").unwrap();
    let ppt_path = scratch.join("older.ppt");
    std::fs::write(&ppt_path, body).unwrap();
    let fields = [("x".to_string(), "int".to_string())].into_iter().collect();
    prismpath_hotswap_rs::build_pack(ppt_path.to_str().unwrap(), &fields, 99, "dist-demo", &private, &public_path, "2026-01-01T00:00:00+00:00")
        .unwrap();
    let host = prismpath_hotswap_rs::host::PolicyHost::new(state_dir.to_str().unwrap(), vec![public_path], qualification(), Vec::new()).unwrap();
    (host, ppt_path.to_str().unwrap().to_string())
}

fn legacy_refused(point_dir: &std::path::Path, scratch: &std::path::Path) -> bool {
    let (host, path) = older_form(point_dir, scratch, &image(7));
    host.swap(&path, false).unwrap() == json!({"ok": false, "reasons": ["dist:legacy-refused"]})
}

/// case_170: IS6, IS10, P4. A PEP holding an action floor at `seq` 5 and a fallback policy is provisioned with its
/// own install key set and a floor at 4 (`dist:seq-replay`), with an anchor alone (the held floor stays), with an
/// anchor whose install trust sequence is lower (`dist:trust-replay`), with a higher one that shares a key, drops
/// another and brings a floor at 1 (the key set changes, the dropped key is retired, the install trust id is the
/// anchor's fingerprint and the floor at 1 is `dist:seq-replay`), and with a higher one that shares no key and
/// brings a floor at 1 and no fallback policy (the floor at 1 is held, every old key is retired and the fallback
/// policy dropped). The floor at 5 is then `sig:revoked-key`.
#[test]
fn case_170_a_provisioning_starts_the_install_sequences_again_only_with_a_disjoint_key_set() {
    let first = anchor2(&INSTALL_KEYS, 2, &[], 2);
    let mut point = Installer::with("170", &first, &[], false);
    let five = floor_set(&good_table(), &seq(5));
    point.send(&five);
    point.send(&fallback_set(&image(9), &seq(1)));
    let from = point.pep.audit.events().len();
    provision(&mut point, &first, &floor_set(&floor_of(4), &seq(4))).unwrap();
    assert_eq!(refusals_since(&point, from), ["dist:seq-replay"]);
    provision(&mut point, &first, &[]).unwrap();
    assert_eq!((point.held(FLOOR), point.seq_of(FLOOR)), (Some(h(&good_table())), 5));
    let lower = provision(&mut point, &anchor2(&INSTALL_KEYS, 2, &[], 1), &[]).unwrap_err();
    assert!(lower.contains("dist:trust-replay"), "{lower}");
    let shares = anchor2(&["N1", "N2", "N4"], 2, &[], 3);
    let from = point.pep.audit.events().len();
    provision(&mut point, &shares, &floor_set(&floor_of(4), &seq(1))).unwrap();
    assert_eq!(refusals_since(&point, from), ["dist:seq-replay"]);
    let record = point.pep.installed.record.clone().unwrap();
    assert!(record.keys.contains_key(&key_id("N4")) && record.retired == vec![key_id("N3")]);
    assert_eq!((record.trust_id, record.trust_seq), (Some(h(&shares)), 3));
    assert!(point.held(FALLBACK).is_some());
    let disjoint = anchor2(&["M1", "M2"], 2, &[], 4);
    provision(&mut point, &disjoint, &floor_set(&floor_of(4), &SetArgs { signers: vec!["M1", "M2"], ..seq(1) })).unwrap();
    let record = point.pep.installed.record.clone().unwrap();
    assert_eq!((point.held(FLOOR), point.seq_of(FLOOR), point.held(FALLBACK)), (Some(h(&floor_of(4))), 1, None));
    assert!(["N1", "N2", "N3", "N4"].iter().all(|name| record.retired.contains(&key_id(name))));
    assert_eq!(point.send(&five).cause.as_deref(), Some("sig:revoked-key"));
}

/// case_172: IS7, AF3, the PEP half. A revocation that lists an install key id, the floor's envelope ids and its
/// policy hash is applied with the floor deciding as before and the install key still counting, and a rotation
/// whose `retire` names an install key is `dist:rotation-invalid`. The sealing tool and the controller are the
/// Python reference's; this crate has neither.
#[test]
fn case_172_a_revocation_never_reaches_an_install_statement() {
    let mut point = Installer::new("172", 2);
    let floor = floor_set(&good_table(), &seq(1));
    point.send(&floor);
    let ids: Vec<Hex64> = floor.iter().map(|(sealed, _)| env::envelope_id(env::unseal(sealed).unwrap().0)).collect();
    let list = revocation(&ids, &[key_id("N1")], &[h(&good_table())], &[]);
    let applied = point.send(&[(trust_statement(ArtifactKind::TrustRevocation, &list, 1, &["A"], &[TargetKind::Host]), list)]);
    assert_eq!(applied.event, "trust-applied");
    assert_eq!(floor_decides(&mut point, [3, 3, 0, 0]), Some("floor"));
    assert_eq!(point.send(&fallback_set(&image(9), &SetArgs { signers: vec!["N1", "N2"], ..seq(1) })).event, "install-widened");
    let body = prismpath_rs::canon2::write_json(&json!({"encoding": "canon/2", "format": "prismpath.dist-rotation/1",
                                                        "add": hex::encode(public("B")), "retire": key_id("N1").as_str()})).unwrap();
    let rotate = trust_statement(ArtifactKind::TrustRotation, &body, 2, &["A", "B"], &[TargetKind::Host]);
    assert_eq!(point.send(&[(rotate, body)]).cause.as_deref(), Some("dist:rotation-invalid"));
}

/// case_174: IS11, AF3. An `install.trust` signed by two old keys and a new one adds the new key, a floor the new
/// key signs follows, a second `install.trust` drops an old key, a floor the dropped key and one other sign is
/// `sig:revoked-key`, and after a restart the fallback policy the dropped key signed is still held.
#[test]
fn case_174_an_install_key_retired_later_does_not_remove_what_it_signed() {
    let mut point = Installer::with("174", &anchor2(&["N1", "N2"], 2, &[], 0), &[], false);
    point.send(&fallback_set(&image(9), &seq(1)));
    assert_eq!(point.send(&[install_trust(&["N1", "N2", "N4"], 2, &[], 1, &["N1", "N2", "N4"], true)]).event, "install-widened");
    assert_eq!(point.send(&floor_set(&good_table(), &SetArgs { signers: vec!["N1", "N4"], ..seq(1) })).event, "install-widened");
    assert_eq!(point.send(&[install_trust(&["N2", "N4"], 2, &[], 2, &["N2", "N4"], false)]).event, "install-applied");
    let dropped = floor_set(&floor_of(4), &SetArgs { signers: vec!["N1", "N2"], ..seq(2) });
    assert_eq!(point.send(&dropped).cause.as_deref(), Some("sig:revoked-key"));
    point.reopen();
    assert_eq!(point.held(FALLBACK), Some(h(&image(9))));
}

/// case_182: IS9, L2. A PEP that holds an install statement and has committed nothing refuses its older signed
/// form, again after a second provisioning, and again after its install record is made unreadable.
#[test]
fn case_182_an_install_statement_closes_the_older_forms_for_good() {
    let mut point = Installer::new("182", 2);
    point.send(&floor_set(&good_table(), &seq(1)));
    assert!(legacy_refused(&point.state_dir(), &point.scratch.join("a")));
    provision(&mut point, &anchor2(&INSTALL_KEYS, 2, &[], 0), &[]).unwrap();
    assert!(legacy_refused(&point.state_dir(), &point.scratch.join("b")));
    for path in [point.dist().join("install/record.json"), point.dist().join("install-copy/record.json")] {
        std::fs::write(path, b"unreadable").unwrap();
    }
    point.reopen();
    assert!(point.pep.installed.record_lost);
    assert!(legacy_refused(&point.state_dir(), &point.scratch.join("c")));
}

/// case_234: L2, P3. A PEP that never held an install statement and committed a release refuses an older signed
/// form, is provisioned again, and still refuses that form on the same stream.
#[test]
fn case_234_no_provisioning_reopens_the_older_forms() {
    let mut point = Point::new("234");
    point.commit_at(&image(5), 1);
    assert!(legacy_refused(&point.state_dir(), &point.scratch.join("a")));
    let fingerprint = point.pep.provision(&point.anchor()).unwrap();
    point.pep.confirm(&fingerprint).unwrap();
    assert_eq!(point.pep.floor().seq, 0);
    assert!(legacy_refused(&point.state_dir(), &point.scratch.join("b")));
}

/// case_183: IS10, IS6. A start with one byte of the first copy of the action floor changed uses the second copy; a
/// start with no good copy reports `refused` with `dist:install-lost`, no longer counts the floor in its install id
/// and decides as a PEP that never had one; the same floor again changes nothing and holds none; one at a new `seq`
/// is applied. A PEP with one copy of its install record unreadable uses the second; with both unreadable it holds
/// no set, reports `dist:install-lost`, keeps deciding under its release, and takes no install statement by message
/// and no release until it is provisioned.
#[test]
fn case_183_a_lost_install_set_or_record_fails_to_what_the_pep_would_be_without_it() {
    let mut point = Installer::new("183", 2);
    let floor = floor_set(&good_table(), &seq(1));
    point.send(&floor);
    let body = h(&good_table()).to_string();
    let (first, second) = (point.dist().join("install/blobs").join(&body), point.dist().join("install-copy/blobs").join(&body));
    let mut changed = std::fs::read(&first).unwrap();
    changed[40] ^= 1;
    std::fs::write(&first, &changed).unwrap();
    point.reopen();
    assert_eq!(point.held(FLOOR), Some(h(&good_table())));
    std::fs::write(&first, &changed).unwrap();
    std::fs::write(&second, &changed).unwrap();
    point.reopen();
    let lost = point.pep.drain().iter().map(|one| point.read(one)).find(|record| record.event == "refused").unwrap();
    assert_eq!(about(&lost), ("refused", Some("dist:install-lost")));
    assert_eq!(Installer::entry(&lost).subject, "install.floor");
    assert_eq!(point.held(FLOOR), None);
    let mut without = point.pep.installed.record.clone().unwrap();
    without.sets = [None, None, None];
    assert_eq!(Installer::entry(&lost).install_id, without.install_id());
    let decision = point.pep.decide_request(Some(&request([3, 3, 0, 0])), || "release").unwrap();
    assert_eq!((decision.basis, decision.cause), (None, Some("dist:policy-lapsed")));
    assert_eq!(about(&point.send(&floor)), ("beat", None));
    assert_eq!(point.held(FLOOR), None);
    assert_eq!(point.send(&floor_set(&good_table(), &seq(2))).event, "install-widened");

    let mut point = Installer::new("183b", 2);
    point.send(&floor_set(&good_table(), &seq(1)));
    point.commit(&image(5), &at(1));
    std::fs::write(point.dist().join("install/record.json"), b"unreadable").unwrap();
    point.reopen();
    assert_eq!(point.held(FLOOR), Some(h(&good_table())));
    std::fs::write(point.dist().join("install-copy/record.json"), b"unreadable").unwrap();
    point.reopen();
    assert!(point.pep.installed.record_lost && point.held(FLOOR).is_none());
    assert!(point.pep.drain().iter().any(|one| point.read(one).cause.as_deref() == Some("dist:install-lost")));
    assert_eq!((point.pep.state(), point.pep.decide(|| "release").unwrap().decision), ("active", Some("release")));
    assert_eq!(point.send(&floor_set(&good_table(), &seq(2))).cause.as_deref(), Some("dist:install-lost"));
    assert_eq!(point.send(&[(ppt(&image(7), &at(2)), image(7))]).cause.as_deref(), Some("dist:install-lost"));
    provision(&mut point, &anchor2(&INSTALL_KEYS, 2, &[], 0), &[]).unwrap();
    assert_eq!(point.send(&floor_set(&good_table(), &seq(2))).event, "install-widened");
}

/// case_226: IS10, the `host` half. A host PEP with one file system, so both copies of its install record on it,
/// loses both: it holds no set, reports `dist:install-lost`, keeps deciding under its release, and takes no install
/// statement by message and no release until it is provisioned. With a second medium the record survives the first.
#[test]
fn case_226_one_medium_lost_takes_both_copies_of_the_install_record() {
    let mut point = Installer::new("226", 2);
    point.send(&fallback_set(&image(9), &seq(1)));
    point.commit(&image(5), &at(1));
    std::fs::remove_dir_all(point.dist().join("install")).unwrap();
    std::fs::remove_dir_all(point.dist().join("install-copy")).unwrap();
    point.reopen();
    assert!(point.pep.installed.record_lost && point.held(FALLBACK).is_none());
    assert!(point.pep.drain().iter().any(|one| point.read(one).cause.as_deref() == Some("dist:install-lost")));
    assert_eq!(point.pep.decide(|| "release").unwrap().decision, Some("release"));
    assert_eq!(point.send(&fallback_set(&image(9), &seq(2))).cause.as_deref(), Some("dist:install-lost"));
    assert_eq!(point.send(&[(ppt(&image(7), &at(2)), image(7))]).cause.as_deref(), Some("dist:install-lost"));
    provision(&mut point, &anchor2(&INSTALL_KEYS, 2, &[], 0), &[]).unwrap();
    assert!(!point.pep.installed.record_lost);

    let anchor = anchor2(&INSTALL_KEYS, 2, &[], 0);
    let mut point = Installer::with("226b", &anchor, &[], true);
    point.send(&fallback_set(&image(9), &seq(1)));
    std::fs::remove_dir_all(point.dist().join("install")).unwrap();
    point.reopen();
    assert_eq!(point.held(FALLBACK), Some(h(&image(9))));
}

/// case_227: IS13, IS6, P3. A PEP with an install threshold of 1, a floor of section 6 at 7, a time floor a day ahead
/// of its clock and an action floor at `seq` 2 applies an install provisioning with an action floor at 3 with event
/// `install-applied` and its floor of section 6, trust sequence and time floor unchanged; the same again changes
/// nothing; one at 2 is `dist:seq-replay`; a release at `seq` 6 is `dist:seq-replay`; a `locked` PEP takes an install
/// provisioning and stays `locked`.
#[test]
fn case_227_an_install_provisioning_changes_only_the_install_part() {
    let mut point = Installer::new("227", 1);
    point.commit(&image(5), &at(7));
    point.now.set(NOW - 86_400);
    let one = |seq: i64, widens: bool| SetArgs { signers: vec!["N1"], widens, replaces: (!widens).then(|| h(&good_table())), ..SetArgs { seq, ..SetArgs::default() } };
    point.pep.provision_install(&floor_set(&good_table(), &one(2, true))).unwrap();
    let (floor, trust_seq, time_floor) = (point.pep.floor().clone(), point.pep.trust().trust_seq, point.pep.trust().time_floor);
    assert!(time_floor > NOW - 86_400);
    let three = floor_set(&good_table(), &one(3, false));
    let records = point.pep.provision_install(&three).unwrap();
    assert_eq!(about(&point.read(records.last().unwrap())), ("install-applied", None));
    assert_eq!((point.pep.floor(), point.pep.trust().trust_seq, point.pep.trust().time_floor), (&floor, trust_seq, time_floor));
    let records = point.pep.provision_install(&three).unwrap();
    assert_eq!(point.read(records.last().unwrap()).event, "beat");
    let records = point.pep.provision_install(&floor_set(&good_table(), &one(2, false))).unwrap();
    assert_eq!(point.read(records.last().unwrap()).cause.as_deref(), Some("dist:seq-replay"));
    assert_eq!(point.send(&[(ppt(&image(7), &at(6)), image(7))]).cause.as_deref(), Some("dist:seq-replay"));
    std::fs::write(point.dist().join("floor.json"), b"not a floor").unwrap();
    point.reopen();
    let records = point.pep.provision_install(&floor_set(&good_table(), &one(4, false))).unwrap();
    let last = point.read(records.last().unwrap());
    assert_eq!((last.event, last.state), ("install-applied", "locked"));
    assert_eq!(point.pep.state(), "locked");
}

/// case_215: IS10. A PEP whose every copy of its ceiling is unreadable reports `refused` with `dist:install-lost`,
/// keeps its release deciding, refuses an offered release, a rollback and an action floor with `dist:install-lost`,
/// then applies a ceiling at a new `seq` and stages a release inside it. A PEP that held a ceiling and whose install
/// record does not read refuses a release with `dist:install-lost` until it is provisioned.
#[test]
fn case_215_a_lost_ceiling_never_fails_open() {
    let mut point = Installer::new("215", 2);
    let tables: [&[u8]; 3] = [&image(5), &image(7), &good_table()];
    point.send(&ceiling_set(&tables, &SetArgs { widens: false, ..seq(1) }));
    point.commit(&image(5), &at(1));
    point.commit(&image(7), &at(2));
    let list = h(&install::ceiling_body(&tables).unwrap()).to_string();
    for dir in ["install/blobs", "install-copy/blobs"] {
        std::fs::write(point.dist().join(dir).join(&list), b"unreadable").unwrap();
    }
    point.reopen();
    assert!(point.pep.drain().iter().any(|one| about(&point.read(one)) == ("refused", Some("dist:install-lost"))));
    assert_eq!(point.pep.decide(|| "release").unwrap().decision, Some("release"));
    assert_eq!(point.send(&[(ppt(&image(5), &at(3)), image(5))]).cause.as_deref(), Some("dist:install-lost"));
    let rolled = point.pep.rollback().unwrap();
    assert_eq!(point.read(&rolled).cause.as_deref(), Some("dist:install-lost"));
    assert_eq!(point.send(&floor_set(&good_table(), &seq(1))).cause.as_deref(), Some("dist:install-lost"));
    // IS12: the resend follows the lost set, so it names that set's policy hash and not the empty string
    assert_eq!(point.send(&ceiling_set(&tables, &SetArgs { widens: false, ..seq(2) })).cause.as_deref(), Some("dist:widening-unsigned"));
    let lost = h(&install::ceiling_body(&tables).unwrap());
    assert_eq!(point.send(&ceiling_set(&tables, &SetArgs { widens: false, replaces: Some(lost), ..seq(2) })).event, "install-applied");
    let sealed = ppt(&image(5), &Args { widens: false, replaces: Some(h(&image(7))), ..at(3) });
    assert_eq!(point.send(&[(sealed, image(5))]).cause.as_deref(), Some("dist:widening-unsigned"));
    assert_eq!(point.send(&[covering_statement(&ppt(&image(5), &at(3))).unwrap(), (ppt(&image(5), &at(3)), image(5))]).event, "staged");

    let mut point = Installer::new("215b", 2);
    point.send(&ceiling_set(&tables, &SetArgs { widens: false, ..seq(1) }));
    point.commit(&image(5), &at(1));
    for path in ["install/record.json", "install-copy/record.json"] {
        std::fs::write(point.dist().join(path), b"unreadable").unwrap();
    }
    point.reopen();
    assert!(point.pep.installed.ceiling_lost);
    assert_eq!(point.send(&[(ppt(&image(7), &at(2)), image(7))]).cause.as_deref(), Some("dist:install-lost"));
    provision(&mut point, &anchor2(&INSTALL_KEYS, 2, &[], 0), &[]).unwrap();
    assert_eq!(point.send(&[covering_statement(&ppt(&image(7), &at(2))).unwrap(), (ppt(&image(7), &at(2)), image(7))]).event, "staged");
}

// ------------------------------------------------------------------ FB1 to FB8: the fallback policy

fn fallback_point(tag: &str) -> Installer {
    let mut point = Installer::new(tag, 2);
    point.send(&fallback_set(&image(9), &seq(1)));
    point
}

fn lock(point: &mut Installer) {
    std::fs::write(point.dist().join("floor.json"), b"not a floor").unwrap();
    point.reopen();
    assert_eq!(point.pep.state(), "locked");
}

fn assert_fallback(point: &mut Installer, record: &state_record::StateRecord, cause: &str, state: &str) {
    assert_eq!(about(record), ("fallback", Some(cause)));
    assert!(record.fallback, "FB2: bit 4");
    assert_eq!((record.state, record.active_policy, record.active_seq), (state, [0u8; 16], 0));
    let decision = point.pep.decide(|| "fallback").unwrap();
    assert_eq!((decision.decision, decision.basis), (Some("fallback"), Some("fallback")));
    assert_eq!(decision.policy_sha256, Some(h(&image(9))));
    assert_eq!(point.host_active(), json!(h(&image(9)).as_str()), "FB1: the host runs the fallback table");
}

/// case_195: FB1, FB2, FB3, the `host` half. A host PEP with a fallback policy whose release expires, whose active
/// release is revoked, which starts with nothing committed and which loses its floor of section 6 goes to the
/// fallback policy each time: event `fallback` with `dist:expired`, `dist:revoked`, `dist:fallback` and
/// `dist:floor-lost`, bit 4 set, status 0 three times and 2 once, zeros for the active hash, and no decision is
/// `dist:policy-lapsed`.
#[test]
fn case_195_the_fallback_policy_decides_whenever_no_release_does() {
    let mut point = fallback_point("195a");
    point.commit(&image(5), &at(1));
    point.now.set(EXPIRES);
    let signed = point.pep.tick().unwrap().unwrap();
    let record = point.read(&signed);
    assert_fallback(&mut point, &record, "dist:expired", "no-policy");

    let mut point = fallback_point("195b");
    point.commit(&image(5), &at(1));
    let release = env::envelope_id(env::unseal(&ppt(&image(5), &at(1))).unwrap().0);
    let list = revocation(&[release], &[], &[], &[]);
    point.send(&[(trust_statement(ArtifactKind::TrustRevocation, &list, 1, &["A"], &[TargetKind::Host]), list)]);
    let lapsed = point.pep.drain().iter().map(|one| point.read(one)).find(|record| record.event == "fallback").unwrap();
    assert_fallback(&mut point, &lapsed, "dist:revoked", "no-policy");

    let mut point = fallback_point("195c");
    point.reopen();
    let started = point.pep.drain().iter().map(|one| point.read(one)).find(|record| record.event == "fallback").unwrap();
    assert_fallback(&mut point, &started, "dist:fallback", "no-policy");

    let mut point = fallback_point("195d");
    point.commit(&image(5), &at(1));
    lock(&mut point);
    let locked = point.pep.drain().iter().map(|one| point.read(one)).find(|record| record.event == "fallback").unwrap();
    assert_fallback(&mut point, &locked, "dist:floor-lost", "locked");
}

/// case_197: FB1, X3. A PEP with an action floor and no fallback policy whose release expires is `no-policy` with
/// event `lapsed` and `dist:expired`, bit 4 clear, and every request the floor is silent on is `dist:policy-lapsed`.
#[test]
fn case_197_with_no_fallback_policy_a_lapse_refuses_as_before() {
    let mut point = Installer::new("197", 2);
    point.send(&floor_set(&good_table(), &seq(1)));
    point.commit(&image(5), &at(1));
    point.now.set(EXPIRES);
    let signed = point.pep.tick().unwrap().unwrap();
    let record = point.read(&signed);
    assert_eq!((about(&record), record.state, record.fallback), (("lapsed", Some("dist:expired")), "no-policy", false));
    let silent = point.pep.decide_request(Some(&request([9, 3, 0, 0])), || "release").unwrap();
    assert_eq!((silent.basis, silent.cause), (None, Some("dist:policy-lapsed")));
}

/// case_199: FB5, FB2. A PEP under its fallback policy refuses a release with no widening statement and one whose
/// statement's `from` holds the fallback policy's hash with `dist:widening-unsigned`, and commits one whose
/// statement's `from` is empty with bit 4 clear. A `locked` PEP under its fallback policy admits no release and
/// decides under the fallback policy until it is provisioned.
#[test]
fn case_199_only_a_widening_release_ends_the_fallback_policy() {
    let mut point = fallback_point("199");
    let sealed = ppt(&image(5), &at(1));
    assert_eq!(point.send(&[(sealed.clone(), image(5))]).cause.as_deref(), Some("dist:widening-unsigned"));
    let from_fallback = statement_of(&sealed, &[h(&image(9))]);
    point.send(&[from_fallback]);
    assert_eq!(point.send(&[(sealed.clone(), image(5))]).cause.as_deref(), Some("dist:widening-unsigned"));
    let record = point.commit(&image(5), &at(2));
    assert_eq!((record.event, record.fallback, record.state), ("committed", false, "active"));

    let mut point = fallback_point("199b");
    lock(&mut point);
    let refused = point.send(&[covering_statement(&ppt(&image(5), &at(1))).unwrap(), (ppt(&image(5), &at(1)), image(5))]);
    assert_eq!(refused.cause.as_deref(), Some("dist:floor-lost"));
    assert_eq!(point.pep.decide(|| "fallback").unwrap().basis, Some("fallback"));
    provision(&mut point, &anchor2(&INSTALL_KEYS, 2, &[], 0), &[]).unwrap();
    assert_eq!(point.pep.state(), "no-policy");
    assert_eq!(point.commit(&image(5), &at(1)).event, "committed");
}

/// case_201: FB7, X2. A cut off PEP with a fallback policy decides under its release until `expires`, then under the
/// fallback policy for a whole year with no message.
#[test]
fn case_201_a_cut_off_pep_falls_to_its_fallback_policy_for_as_long_as_it_is_cut_off() {
    let mut point = fallback_point("201");
    point.commit(&image(5), &at(1));
    point.now.set(EXPIRES - 1);
    assert_eq!(point.pep.decide(|| "x").unwrap().basis, Some("release"));
    point.now.set(EXPIRES);
    assert_eq!(point.pep.decide(|| "x").unwrap().basis, Some("fallback"));
    point.now.set(EXPIRES + 365 * 86_400);
    point.pep.tick().unwrap();
    assert_eq!(point.pep.decide(|| "x").unwrap().basis, Some("fallback"));
}

/// case_202: FB8, IS12, the `host` half. A PEP under its fallback policy decides under each new fallback policy at
/// once with bit 4 still set; on `host` every changed table is larger (IS12), so each says it widens and is applied
/// with event `install-widened`. A PEP with an active release holds the new one with the same event while its
/// release keeps deciding.
#[test]
fn case_202_a_new_fallback_policy_decides_at_once_where_the_fallback_policy_decides() {
    let mut point = fallback_point("202");
    for (seq, table) in [(2, image(8)), (3, image(3))] {
        let record = point.send(&fallback_set(&table, &SetArgs { replaces: Some(point.held(FALLBACK).unwrap()), ..SetArgs { seq, ..SetArgs::default() } }));
        assert_eq!((record.event, record.fallback), ("install-widened", true));
        assert_eq!(point.host_active(), json!(h(&table).as_str()));
    }
    let unsigned = fallback_set(&image(2), &SetArgs { widens: false, replaces: Some(h(&image(3))), ..seq(4) });
    assert_eq!(point.send(&unsigned).cause.as_deref(), Some("dist:widening-unsigned"));

    let mut point = fallback_point("202b");
    point.commit(&image(5), &at(1));
    let record = point.send(&fallback_set(&image(3), &SetArgs { replaces: Some(h(&image(9))), ..seq(2) }));
    assert_eq!((record.event, record.fallback, record.state), ("install-widened", false, "active"));
    assert_eq!(point.held(FALLBACK), Some(h(&image(3))));
    assert_eq!(point.host_active(), json!(h(&image(5)).as_str()));
}

// ------------------------------------------------------------------ CL1 to CL3: the ceiling

/// case_204: CL2, C3, RB2. A release inside the ceiling is staged, a narrower ceiling it is above is applied and it
/// is still staged, and its commit is `dist:above-ceiling` and drops it. The same with a kept release and a rollback.
#[test]
fn case_204_a_staged_or_kept_release_meets_a_newer_ceiling_at_commit_and_at_rollback() {
    let mut point = Installer::new("204", 2);
    point.send(&ceiling_set(&[&image(5), &image(7)], &SetArgs { widens: false, ..seq(1) }));
    point.commit(&image(5), &at(1));
    let sealed = ppt(&image(7), &at(2));
    point.send(&[covering_statement(&sealed).unwrap(), (sealed, image(7))]);
    let narrower = SetArgs { widens: false, replaces: point.held(CEILING), ..seq(2) };
    assert_eq!(point.send(&ceiling_set(&[&image(5)], &narrower)).event, "install-applied");
    assert!(point.pep.staged().is_some());
    let signed = point.pep.commit(STREAM, 2, &h(&image(7)), 0).unwrap();
    let record = point.read(&signed);
    assert_eq!(record.cause.as_deref(), Some("dist:above-ceiling"));
    assert!(point.pep.staged().is_none());

    let mut point = Installer::new("204b", 2);
    point.send(&ceiling_set(&[&image(5), &image(7)], &SetArgs { widens: false, ..seq(1) }));
    point.commit(&image(5), &at(1));
    point.commit(&image(7), &at(2));
    let narrower = SetArgs { widens: false, replaces: point.held(CEILING), ..seq(2) };
    point.send(&ceiling_set(&[&image(7)], &narrower));
    assert!(point.pep.previous().is_some());
    let rolled = point.pep.rollback().unwrap();
    assert_eq!(point.read(&rolled).cause.as_deref(), Some("dist:above-ceiling"));
    assert!(point.pep.previous().is_none());
}

/// case_205: CL3, IS12, AF1, the `host` half. A PEP with a ceiling refuses an action floor above it, a fallback
/// policy above it and a ceiling its held floor is above with `dist:above-ceiling`, nothing changed. A ceiling its
/// active release is above, with `widens` false, narrows, so it is applied with event `install-applied` and the release lapses with
/// `dist:above-ceiling`, to the fallback policy where it holds one and to `no-policy` where it does not.
#[test]
fn case_205_everything_a_pep_decides_under_is_inside_its_ceiling() {
    let mut point = Installer::new("205", 2);
    point.send(&ceiling_set(&[&image(5), &good_table()], &SetArgs { widens: false, ..seq(1) }));
    point.send(&floor_set(&good_table(), &seq(1)));
    let before = point.pep.installed.record.clone();
    assert_eq!(point.send(&floor_set(&floor_of(4), &seq(2))).cause.as_deref(), Some("dist:above-ceiling"));
    assert_eq!(point.send(&fallback_set(&image(9), &seq(1))).cause.as_deref(), Some("dist:above-ceiling"));
    let replaces = point.held(CEILING);
    assert_eq!(point.send(&ceiling_set(&[&image(5)], &SetArgs { widens: false, replaces: replaces.clone(), ..seq(2) })).cause.as_deref(), Some("dist:above-ceiling"));
    assert_eq!(point.pep.installed.record, before);

    for (tag, fallback) in [("205b", true), ("205c", false)] {
        let mut point = Installer::new(tag, 2);
        let (five, seven, nine) = (image(5), image(7), image(9));
        let listed: Vec<&[u8]> = if fallback { vec![&five, &nine] } else { vec![&five, &seven] };
        point.send(&ceiling_set(&listed, &SetArgs { widens: false, ..seq(1) }));
        if fallback {
            point.send(&fallback_set(&image(9), &seq(1)));
        }
        point.commit(&image(5), &at(1));
        let narrower: Vec<&[u8]> = if fallback { vec![&nine] } else { vec![&seven] };
        let applied = point.send(&ceiling_set(&narrower, &SetArgs { widens: false, replaces: point.held(CEILING), ..seq(2) }));
        assert_eq!(about(&applied), ("install-applied", None)); // IS12: a narrower ceiling is no widening
        let lapse = point.pep.drain().iter().map(|one| point.read(one)).last().unwrap();
        let event = if fallback { "fallback" } else { "lapsed" };
        assert_eq!((about(&lapse), lapse.state), ((event, Some("dist:above-ceiling")), "no-policy"));
    }
}

// ------------------------------------------------------------------ AF1 to AF10: the action floor

fn floor_point(tag: &str) -> Installer {
    let mut point = Installer::new(tag, 2);
    point.send(&floor_set(&good_table(), &seq(1)));
    point
}

/// case_186: AF1, the `host` half. A request the action floor allows is allowed with basis `floor` by a PEP whose
/// active release refuses it, in `no-policy`, in `locked` and under the fallback policy.
#[test]
fn case_186_the_action_floor_allows_in_every_state() {
    let inside = [3, 3, 0, 0];
    let mut point = floor_point("186");
    assert_eq!(floor_decides(&mut point, inside), Some("floor"), "no-policy");
    point.commit(&image(5), &at(1));
    assert_eq!(point.pep.decide_request(None, || "refuse").unwrap().basis, Some("release"));
    assert_eq!(floor_decides(&mut point, inside), Some("floor"), "a release that refuses cmd 3");
    lock(&mut point);
    assert_eq!(floor_decides(&mut point, inside), Some("floor"), "locked");
    let mut point = floor_point("186b");
    point.send(&fallback_set(&image(9), &seq(1)));
    assert!(point.pep.fallback_decides());
    let decision = point.pep.decide_request(Some(&request(inside)), || "fallback").unwrap();
    assert_eq!((decision.basis, decision.cause, decision.decision), (Some("floor"), Some("dist:floor-allowed"), None));
}

/// case_188: AF2, the `host` half. A table floor only allows, so a request it refuses, and a decision with no request
/// it can read, leave the release's own answer, and in `no-policy` with no fallback policy `dist:policy-lapsed`.
#[test]
fn case_188_a_floor_that_does_not_allow_is_silent() {
    let mut point = floor_point("188");
    point.commit(&image(5), &at(1));
    let refused = point.pep.decide_request(Some(&request([9, 3, 0, 0])), || "release").unwrap();
    assert_eq!((refused.basis, refused.decision), (Some("release"), Some("release")));
    assert_eq!(point.pep.decide_request(None, || "release").unwrap().basis, Some("release"));
    let mut point = floor_point("188b");
    for asked in [Some(request([9, 3, 0, 0])), None] {
        let decision = point.pep.decide_request(asked.as_ref(), || "release").unwrap();
        assert_eq!((decision.basis, decision.cause), (None, Some("dist:policy-lapsed")));
    }
}

/// case_189: AF3. A PEP with an action floor whose release expires, which is sent a revocation of everything the
/// authority signed, loses its floor of section 6, is sent every unsigned message type, sees the key that signed its
/// floor retired and runs ten years past the floor's `not_before`, still has its floor allow the same request.
#[test]
fn case_189_the_action_floor_never_lapses() {
    let inside = [3, 3, 0, 0];
    let mut point = floor_point("189");
    point.commit(&image(5), &at(1));
    point.now.set(EXPIRES);
    point.pep.tick().unwrap();
    assert_eq!(floor_decides(&mut point, inside), Some("floor"));
    let release = env::envelope_id(env::unseal(&ppt(&image(5), &at(1))).unwrap().0);
    let list = revocation(&[release], &[key_id("A")], &[h(&image(5))], &[(STREAM, 99)]);
    point.send(&[(trust_statement(ArtifactKind::TrustRevocation, &list, 1, &["A"], &[TargetKind::Host]), list)]);
    assert_eq!(floor_decides(&mut point, inside), Some("floor"));
    lock(&mut point);
    assert_eq!(floor_decides(&mut point, inside), Some("floor"));
    point.pep.commit(STREAM, 2, &h(&image(7)), 0).unwrap();
    point.pep.abort(STREAM, 2, &h(&image(7))).unwrap();
    point.pep.rollback().unwrap();
    point.pep.tick().unwrap();
    point.pep.record("beat", None).unwrap();
    assert_eq!(floor_decides(&mut point, inside), Some("floor"));
    point.send(&[install_trust(&["N2", "N3"], 2, &[], 1, &["N2", "N3"], false)]); // N1 signed the floor
    assert_eq!(floor_decides(&mut point, inside), Some("floor"));
    point.now.set(NOT_BEFORE + 10 * 365 * 86_400);
    point.reopen();
    assert_eq!(floor_decides(&mut point, inside), Some("floor"));
}

/// case_190: AF4, the PEP half. A PEP whose release refuses a request the floor allows commits a renewal of that
/// release with no widening statement, and the floor still allows the request. The controller's half is the Python
/// controller's.
#[test]
fn case_190_a_release_is_never_held_to_the_action_floor() {
    let mut point = floor_point("190");
    point.commit(&image(5), &at(1));
    let renewal = renewal(2, &image(5));
    point.send(&[(ppt(&image(5), &renewal), image(5))]);
    let signed = point.pep.commit(STREAM, 2, &h(&image(5)), 0).unwrap();
    let record = point.read(&signed);
    assert_eq!(record.event, "committed");
    assert_eq!(floor_decides(&mut point, [3, 3, 0, 0]), Some("floor"));
}

/// case_193: AF7, RC1, the `host` half. A floor allow records `would`: allow where the release would allow, refuse
/// with the release's cause where it would refuse, each with the release's policy hash, and none with no release and
/// no fallback policy; the override count rises by two. A table has no escalation (AF2), so the escalating half is
/// the kinds' that have one.
#[test]
fn case_193_a_floor_allow_records_what_the_release_would_have_done() {
    let mut point = floor_point("193");
    let ask = |point: &mut Installer| point.pep.decide_request(Some(&request([3, 3, 0, 0])), || "release").unwrap().floor.unwrap();
    let none = ask(&mut point);
    assert_eq!((none.would.clone(), none.overrides), (None, true));
    point.commit(&image(2), &at(1));
    let allows = ask(&mut point);
    assert_eq!((allows.would.clone(), allows.overrides), (Some(("allow", None, h(&image(2)))), false));
    point.commit(&image(5), &at(2));
    let refuses = ask(&mut point);
    assert_eq!((refuses.would.clone(), refuses.overrides), (Some(("refuse", Some("route:no-matching-edge"), h(&image(5)))), true));
    let signed = point.pep.record("beat", None).unwrap();
    let record = point.read(&signed);
    let entry = Installer::entry(&record);
    assert_eq!((entry.answers, entry.overrides), (3, 2));
}

/// case_207: RC1, the `host` half. Decisions name their basis and the policy hash of the set that decided: `release`
/// for one the release allows and one it refuses, `floor` for one the floor allows, `fallback` for one the fallback
/// policy allows and one it refuses, and no basis with `dist:policy-lapsed` for a refusal in `no-policy` with no
/// fallback policy. This crate has no receipt writer of its own; the decision carries the receipt's fields.
#[test]
fn case_207_every_decision_names_its_basis_and_the_set_that_decided() {
    let mut point = floor_point("207");
    let none = point.pep.decide(|| "refuse").unwrap();
    assert_eq!((none.basis, none.cause, none.policy_sha256), (None, Some("dist:policy-lapsed"), None));
    point.commit(&image(5), &at(1));
    for answer in ["allow", "refuse"] {
        let decision = point.pep.decide(|| answer).unwrap();
        assert_eq!((decision.decision, decision.basis, decision.policy_sha256), (Some(answer), Some("release"), Some(h(&image(5)))));
    }
    let floor = point.pep.decide_request(Some(&request([3, 3, 0, 0])), || "release").unwrap();
    assert_eq!((floor.basis, floor.policy_sha256), (Some("floor"), Some(h(&good_table()))));
    let mut point = floor_point("207b");
    point.send(&fallback_set(&image(9), &seq(1)));
    for answer in ["allow", "refuse"] {
        let decision = point.pep.decide(|| answer).unwrap();
        assert_eq!((decision.decision, decision.basis, decision.policy_sha256), (Some(answer), Some("fallback"), Some(h(&image(9)))));
    }
}

/// case_213: AF9, AF10, the `host` half. A floor table whose edge to the allow tests nothing, one with an edge that
/// tests no command, one with two decision nodes, one with nine allowing edges, one whose `command` names a register
/// the layout does not label, one that allows a command with no bound on a parameter and one whose bound is the
/// field's whole domain are `dist:floor-broad`; one whose `layout` is another layout's hash is
/// `dist:target-mismatch`; one with eight edges that each test one command and bound the parameter is applied,
/// allowing that command inside the bound with basis `floor` and leaving it to the release outside.
#[test]
fn case_213_a_host_floor_table_is_narrow() {
    let mut point = Installer::new("213", 2);
    let bound = |command: i32| vec![(0, EQ, command), (1, GE, 2), (1, LE, 5)];
    let broad: Vec<(Vec<u8>, SetArgs)> = vec![
        (table(&[vec![]]), seq(1)),
        (table(&[vec![(1, GE, 2), (1, LE, 5)]]), seq(2)),
        (table_with(&[bound(3)], 2, false), seq(3)),
        (table(&(0..9).map(bound).collect::<Vec<_>>()), seq(4)),
        (good_table(), SetArgs { command: Some(7), ..seq(5) }),
        (table(&[vec![(0, EQ, 3)]]), seq(6)),
        (table(&[vec![(0, EQ, 3), (1, GE, 0), (1, LE, 100)]]), seq(7)),
    ];
    for (body, args) in broad {
        assert_eq!(point.send(&floor_set(&body, &args)).cause.as_deref(), Some("dist:floor-broad"), "seq {}", args.seq);
    }
    let other = floor::layout_body(&[field("cmd", 0, "command", 0, 9, 0)]).unwrap();
    assert_eq!(point.send(&floor_set(&good_table(), &SetArgs { layout: Some(h(&other)), ..seq(8) })).cause.as_deref(), Some("dist:target-mismatch"));
    assert_eq!(point.held(FLOOR), None);
    let eight = table(&(0..8).map(bound).collect::<Vec<_>>());
    assert_eq!(point.send(&floor_set(&eight, &seq(9))).event, "install-widened");
    assert_eq!(floor_decides(&mut point, [6, 3, 0, 0]), Some("floor"));
    let outside = point.pep.decide_request(Some(&request([6, 7, 0, 0])), || "release").unwrap();
    assert_eq!((outside.basis, outside.cause), (None, Some("dist:policy-lapsed")));
}

/// AF10: a floor rule that tests an independent register is silent when its value is absent or older than its
/// staleness bound, and a floor that tests the proposer's own register is `dist:floor-broad`.
#[test]
fn a_floor_rule_reads_an_independent_field_only_while_it_is_fresh() {
    let mut point = Installer::new("af10", 2);
    let proposer = table(&[vec![(0, EQ, 3), (1, GE, 2), (1, LE, 5), (3, EQ, 1)]]);
    assert_eq!(point.send(&floor_set(&proposer, &seq(1))).cause.as_deref(), Some("dist:floor-broad"));
    let independent = table(&[vec![(0, EQ, 3), (1, GE, 2), (1, LE, 5), (2, EQ, 1)]]);
    point.send(&floor_set(&independent, &seq(2)));
    let mut asked = request([3, 3, 1, 0]);
    assert_eq!(point.pep.decide_request(Some(&asked), || "x").unwrap().basis, None, "absent");
    asked.ages.insert(2, 6);
    assert_eq!(point.pep.decide_request(Some(&asked), || "x").unwrap().basis, None, "stale");
    asked.ages.insert(2, 5);
    assert_eq!(point.pep.decide_request(Some(&asked), || "x").unwrap().basis, Some("floor"));
}

/// AF8: past the signed rate a `host` floor, which may only allow, is silent on an override and the release decides;
/// an allow the release would make too is never counted.
#[test]
fn a_host_floor_is_silent_past_its_rate() {
    let mut point = Installer::new("af8", 2);
    point.send(&floor_set(&good_table(), &SetArgs { rate: Some((2, 60)), ..seq(1) }));
    point.commit(&image(5), &at(1));
    let inside = [3, 3, 0, 0];
    let first = point.pep.decide_request(Some(&request(inside)), || "release").unwrap().floor.unwrap();
    assert_eq!(first.counted, Some((NOW, 1)));
    assert_eq!(floor_decides(&mut point, inside), Some("floor"));
    assert_eq!(floor_decides(&mut point, inside), Some("release"), "past the rate");
    point.reopen();
    assert_eq!(floor_decides(&mut point, inside), Some("release"), "a restart does not begin a new window");
    point.now.set(NOW + 60);
    assert_eq!(floor_decides(&mut point, inside), Some("floor"));
}

// ------------------------------------------------------------------ IS14, IS15: the install change statement

fn narrower_table() -> Vec<u8> {
    table(&[vec![(0, EQ, 3), (1, GE, 3), (1, LE, 5)]])
}

fn carried(seq_: i64, replaces: &Hex64) -> SetArgs {
    SetArgs { widens: false, replaces: Some(replaces.clone()), ..seq(seq_) }
}

/// case_296: IS14, IS2, V5, IS4, the `host` half. A host PEP holding an action floor refuses an install change
/// statement that says it widens, replaces nothing, names another hash than its `replaces`, carries a ceiling or the
/// empty set with `dist:bad-format`, one signed by authority keys with `dist:unknown-key`, and a second one for a set
/// that has one staged with `dist:incomplete`. A PEP whose install threshold is 1 takes none in a message.
#[test]
fn case_296_an_install_change_statement_out_of_its_form_is_refused() {
    let mut point = floor_point("296");
    let held = h(&good_table());
    let narrow = narrower_table();
    let good = carried(2, &held);
    let staged_before = point.pep.installed.staged.clone();
    let wrong = [
        install_change(FLOOR, &narrow, &SetArgs { widens: true, ..good.clone() }, &held),
        install_change(FLOOR, &narrow, &SetArgs { replaces: None, ..good.clone() }, &held),
        install_change(FLOOR, &narrow, &carried(2, &h(&image(9))), &held),
        change_body_of("install.ceiling", &narrow, &good, &held),
        install_change(FLOOR, &narrow, &SetArgs { policy: Some(Hex64::zero()), ..good.clone() }, &held),
    ];
    for one in &wrong {
        assert_eq!(point.send(std::slice::from_ref(one)).cause.as_deref(), Some("dist:bad-format"));
    }
    let by_authority = install_change(FLOOR, &narrow, &SetArgs { signers: vec!["A"], ..good.clone() }, &held);
    assert_eq!(point.send(&[by_authority]).cause.as_deref(), Some("dist:unknown-key"));
    assert_eq!(point.pep.installed.staged, staged_before);
    let staged = point.send(&[install_change(FLOOR, &narrow, &good, &held)]);
    assert_eq!((about(&staged), Installer::entry(&staged).subject), (("staged", None), "install.floor"));
    let again = install_change(FLOOR, &narrow, &SetArgs { not_before: NOT_BEFORE + 1, ..good.clone() }, &held);
    let refused = point.send(&[again]);
    assert_eq!((about(&refused), Installer::entry(&refused).subject), (("refused", Some("dist:incomplete")), "install.floor"));
    let floor = floor_set(&good_table(), &seq(1));
    let mut one = Installer::with("296b", &anchor2(&INSTALL_KEYS, 1, &[], 0), &floor, false);
    let refused = one.send(&[install_change(FLOOR, &narrow, &SetArgs { signers: vec!["N1"], ..good }, &held)]);
    assert_eq!(about(&refused), ("refused", Some("dist:target-mismatch")));
}

/// case_297: IS15, IS12, the `host` half. With a change statement from the held set's policy hash, a floor table and
/// a fallback table that allow less with `widens` false are applied with event `install-applied` and no cause, and a
/// narrower floor with no change statement is `dist:widening-unsigned` with the floor before it still held.
#[test]
fn case_297_a_narrower_floor_or_fallback_carried_by_a_change_statement_is_applied() {
    let mut point = floor_point("297");
    point.send(&fallback_set(&image(9), &seq(1)));
    let narrow = narrower_table();
    let staged = point.send(&[install_change(FLOOR, &narrow, &carried(2, &h(&good_table())), &h(&good_table()))]);
    assert_eq!(about(&staged), ("staged", None));
    let applied = point.send(&floor_set(&narrow, &carried(2, &h(&good_table()))));
    assert_eq!(about(&applied), ("install-applied", None));
    assert_eq!(point.held(FLOOR), Some(h(&narrow)));
    let applied = point.send(&[
        install_change(FALLBACK, &image(7), &carried(2, &h(&image(9))), &h(&image(9))),
        fallback_set(&image(7), &carried(2, &h(&image(9))))[0].clone(),
    ]);
    assert_eq!(about(&applied), ("install-applied", None));
    let event = point.pep.audit.events().into_iter().rev().find(|event| event["action"] == "install-applied").unwrap();
    assert!(event["data"]["change"].is_string(), "IS15: the audit names the change statement the set was taken on");
    let alone = table(&[vec![(0, EQ, 3), (1, GE, 4), (1, LE, 5)]]);
    let refused = point.send(&floor_set(&alone, &carried(3, &h(&narrow))));
    assert_eq!(about(&refused), ("refused", Some("dist:widening-unsigned")));
    assert_eq!(point.held(FLOOR), Some(h(&narrow)));
}

/// case_298: IS15, AF8, V10, the `host` half. A change statement on a PEP with no floor, and one from another hash,
/// are `dist:widening-unsigned` with nothing staged. Beside a change statement a floor with a looser rate is
/// `dist:widening-unsigned`, and a set that says it widens is `dist:incomplete`.
#[test]
fn case_298_a_change_statement_stands_only_for_a_set_it_can_carry() {
    let mut point = Installer::new("298", 2);
    let narrow = narrower_table();
    let held = h(&good_table());
    let refused = point.send(&[install_change(FLOOR, &narrow, &carried(2, &held), &held)]);
    assert_eq!(about(&refused), ("refused", Some("dist:widening-unsigned")));
    point.send(&floor_set(&good_table(), &SetArgs { rate: Some((3, 60)), ..seq(1) }));
    let other = h(&image(9));
    let refused = point.send(&[install_change(FLOOR, &narrow, &carried(2, &other), &other)]);
    assert_eq!(about(&refused), ("refused", Some("dist:widening-unsigned")));
    assert!(point.pep.installed.staged.is_empty());
    let looser = SetArgs { rate: Some((5, 60)), ..carried(2, &held) };
    assert_eq!(about(&point.send(&[install_change(FLOOR, &narrow, &looser, &held)])), ("staged", None));
    assert_eq!(about(&point.send(&floor_set(&narrow, &looser))), ("refused", Some("dist:widening-unsigned")));
    let rated = SetArgs { rate: Some((3, 60)), ..carried(3, &held) };
    let widens = SetArgs { widens: true, ..rated.clone() };
    assert_eq!(about(&point.send(&[install_change(FLOOR, &narrow, &rated, &held)])), ("staged", None));
    assert_eq!(about(&point.send(&floor_set(&narrow, &widens))), ("refused", Some("dist:incomplete")));
}

/// case_299: IS15, IS4, the `host` half. A change statement staged survives a restart, and the narrower floor it
/// carries is then applied with event `install-applied`.
#[test]
fn case_299_a_staged_change_statement_survives_a_restart() {
    let mut point = floor_point("299");
    let narrow = narrower_table();
    let args = carried(2, &h(&good_table()));
    point.send(&[install_change(FLOOR, &narrow, &args, &h(&good_table()))]);
    point.reopen();
    assert!(point.pep.installed.staged.get(&SetKind::Floor).is_some_and(|set| set.change_body.is_some()));
    assert_eq!(about(&point.send(&floor_set(&narrow, &args))), ("install-applied", None));
}

// ------------------------------------------------------------------ IS10, IS12: a ceiling after a lost one

fn lose_ceiling(point: &mut Installer, tables: &[&[u8]]) {
    let list = h(&install::ceiling_body(tables).unwrap()).to_string();
    for dir in ["install/blobs", "install-copy/blobs"] {
        std::fs::write(point.dist().join(dir).join(&list), b"unreadable").unwrap();
    }
    point.reopen();
    assert!(point.pep.installed.ceiling_lost, "lost at the start");
}

/// case_307: IS10, IS12, the `host` half. A PEP whose ceiling no copy holds is sent, with `widens` false, the empty
/// ceiling, a wider list, a narrower list whose `replaces` is the lost list's policy hash and the lost list again with
/// `replaces` empty, each `dist:widening-unsigned` with the ceiling still lost, also after a restart; then the lost
/// list again naming the lost hash is `install-applied`. On another such PEP a narrower list with `widens` true is
/// `install-widened`. A PEP whose ceiling is lost and that is provisioned with an anchor sharing its install keys
/// stays lost, before and after a restart, and refuses a release with `dist:install-lost`.
#[test]
fn case_307_a_ceiling_after_a_lost_one_stands_out_unless_it_is_the_lost_one_again() {
    let tables: [&[u8]; 2] = [&image(5), &image(7)];
    let lost = h(&install::ceiling_body(&tables).unwrap());
    let mut point = Installer::new("307", 2);
    point.send(&ceiling_set(&tables, &SetArgs { widens: false, ..seq(1) }));
    point.commit(&image(5), &at(1));
    lose_ceiling(&mut point, &tables);
    let quiet = |replaces: Option<Hex64>| SetArgs { widens: false, replaces, ..seq(2) };
    let unsigned = Some("dist:widening-unsigned");
    assert_eq!(point.send(&empty_set(ArtifactKind::InstallCeiling, &quiet(Some(lost.clone())))).cause.as_deref(), unsigned);
    assert_eq!(point.send(&ceiling_set(&[&image(5), &image(7), &image(9)], &quiet(Some(lost.clone())))).cause.as_deref(), unsigned);
    assert_eq!(point.send(&ceiling_set(&[&image(5)], &quiet(Some(lost.clone())))).cause.as_deref(), unsigned);
    assert_eq!(point.send(&ceiling_set(&tables, &quiet(None))).cause.as_deref(), unsigned);
    assert!(point.pep.installed.ceiling_lost);
    point.reopen();
    assert!(point.pep.installed.ceiling_lost, "still named, still lost after a restart");
    assert_eq!(point.pep.installed.lost_ceiling.as_ref().map(|doc| doc.policy_sha256.clone()), Some(lost.clone()));
    assert_eq!(about(&point.send(&ceiling_set(&tables, &quiet(Some(lost.clone()))))), ("install-applied", None));
    assert!(!point.pep.installed.ceiling_lost);

    let mut other = Installer::new("307b", 2);
    other.send(&ceiling_set(&tables, &SetArgs { widens: false, ..seq(1) }));
    lose_ceiling(&mut other, &tables);
    let widened = other.send(&ceiling_set(&[&image(5)], &SetArgs { widens: true, ..seq(2) }));
    assert_eq!(about(&widened), ("install-widened", Some("dist:install-widened")));

    let mut kept = Installer::new("307c", 2);
    kept.send(&ceiling_set(&tables, &SetArgs { widens: false, ..seq(1) }));
    kept.commit(&image(5), &at(1));
    lose_ceiling(&mut kept, &tables);
    provision(&mut kept, &anchor2(&INSTALL_KEYS, 2, &[], 1), &[]).unwrap(); // IS6: a higher install trust seq, the same keys
    assert!(kept.pep.installed.ceiling_lost && kept.pep.installed.marks.ceiling);
    let release = ppt(&image(7), &at(2));
    let staged = |point: &mut Installer| {
        let statement = covering_statement(&release).unwrap();
        point.send(&[statement, (release.clone(), image(7))])
    };
    assert_eq!(staged(&mut kept).cause.as_deref(), Some("dist:install-lost"));
    kept.reopen();
    assert!(kept.pep.installed.ceiling_lost, "the mark is kept, so the restart knows a ceiling was held");
    assert_eq!(staged(&mut kept).cause.as_deref(), Some("dist:install-lost"));
}

/// IS10: a crash between the first ceiling's mark and its record leaves the mark set and the record's ceiling
/// sequence at 0, which no ceiling ever reached, so the PEP is not frozen as one whose ceiling is lost (Python's
/// `seqs[CEILING]` test).
#[test]
fn a_first_ceiling_cut_between_its_mark_and_its_record_is_no_lost_ceiling() {
    let mut point = Installer::new("first_mark", 2);
    point.send(&floor_set(&good_table(), &seq(1)));
    let marks = std::fs::read_to_string(point.dist().join("marks.json")).unwrap();
    std::fs::write(point.dist().join("marks.json"), marks.replace("\"ceiling\":false", "\"ceiling\":true")).unwrap();
    point.reopen();
    assert!(point.pep.installed.marks.ceiling && !point.pep.installed.ceiling_lost);
    let release = ppt(&image(5), &at(1));
    let statement = covering_statement(&release).unwrap();
    assert_eq!(point.send(&[statement, (release, image(5))]).event, "staged");
}

/// IS12, OP4: a looser `answer_rate` is larger, as a looser `rate` is, so with `widens` false it is
/// `dist:widening-unsigned`, and a tighter one is applied.
#[test]
fn a_looser_answer_rate_widens_an_action_floor() {
    let mut point = Installer::new("answer_rate", 2);
    let meta = |allows: i64, window: i64| {
        let mut meta = table_meta(&good_table());
        meta["answer_rate"] = json!({"allows": allows, "window": window});
        meta
    };
    point.send(&floor_set(&good_table(), &SetArgs { meta: Some(meta(5, 60)), ..seq(1) }));
    let held = Some(h(&good_table()));
    let quiet = |seq_: i64, meta_: serde_json::Value| SetArgs { meta: Some(meta_), widens: false, replaces: held.clone(), ..seq(seq_) };
    assert_eq!(point.send(&floor_set(&good_table(), &quiet(2, meta(9, 60)))).cause.as_deref(), Some("dist:widening-unsigned"));
    assert_eq!(point.send(&floor_set(&good_table(), &quiet(2, meta(5, 30)))).cause.as_deref(), Some("dist:widening-unsigned"));
    assert_eq!(about(&point.send(&floor_set(&good_table(), &quiet(2, meta(3, 60))))), ("install-applied", None));
}
