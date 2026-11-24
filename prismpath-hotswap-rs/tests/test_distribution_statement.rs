// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The controller key and the controller statement on the Rust host PEP (spec-policy-distribution.md, K6, K7, H9,
//! H15 and H16), `prismpath/tests/test_distribution_statement.py` in Rust: the `trust.controller` kind, the epoch
//! id a PEP takes only from a verified statement, and the freshness a fresh statement gives. Each test names the
//! conformance case of section 20 it covers. This crate builds the `host` kind alone, so a case that names a `mesh`
//! or a `cfs` PEP runs here on a `host` PEP that stands for it: two streams for the broadcast of case 276, and a host
//! with no clock for the clockless node of case 278. The controller's half of case 256 is in
//! `test_distribution_cross_language.rs`, against the Python controller.

#[path = "common/mod.rs"]
mod common;
#[path = "common/dist.rs"]
mod dist;
#[path = "common/install.rs"]
mod installs;

use dist::*;
use prismpath_hotswap_rs::dist::pep::REFUSE;
use prismpath_hotswap_rs::dist::statement::{self as statements, encode_offered};
use prismpath_hotswap_rs::dist::trust::{anchor2_bytes, TrustStore};
use prismpath_hotswap_rs::dist::{state_record, ArtifactKind, Hex64, Stream, TargetKind};
use prismpath_rs::canon2;

const YEAR: i64 = 365 * 86400;

fn old() -> Vec<u8> {
    image(5)
}

/// A fresh statement by C until `expires`, at trust sequence `trust_seq` and stream seq `stream_seq`.
fn fresh(epoch: u64, expires: i64, trust_seq: u64, stream_seq: u64) -> Vec<u8> {
    signed_by("C", Said { epoch, fresh: true, trust_seq, stream_seq, expires: expires as u64, ..Said::default() })
}

fn controller_id(store: &TrustStore) -> Option<Hex64> {
    store.controller().map(|(kid, _)| kid.clone())
}

#[test]
fn the_trust_store_writes_its_key_sequence_only_once_it_holds_a_controller_key() {
    let bare = Point::new("store_bare");
    let text = String::from_utf8(bare.pep.trust().to_bytes().unwrap()).unwrap();
    assert!(!text.contains("key_seq"), "a store that never held a controller key keeps its bytes");
    let held = Point::controlled("store_held", "C", 0, true);
    let bytes = held.pep.trust().to_bytes().unwrap();
    assert!(String::from_utf8(bytes.clone()).unwrap().contains("\"key_seq\":0,\"keys\""));
    assert_eq!(TrustStore::from_bytes(&bytes).unwrap().to_bytes().unwrap(), bytes);
    let null = String::from_utf8(bytes.clone()).unwrap().replace("\"key_seq\":0", "\"key_seq\":null");
    assert!(TrustStore::from_bytes(null.as_bytes()).is_err(), "key_seq is a number when it is there");
    let twice = String::from_utf8(bytes).unwrap().replace("\"role\":\"authority\"", "\"role\":\"controller\"");
    assert!(TrustStore::from_bytes(twice.as_bytes()).is_err(), "one controller key at most (K6)");
}

/// case_256: H15, H9, the `host` PEP's half. After a restart it reports epoch 0, and once it takes a current
/// statement it reports that epoch id again.
#[test]
fn case_256_a_restarted_pep_reports_epoch_0_until_it_takes_a_statement() {
    let mut point = Point::controlled("256", "C", 0, true);
    assert!(point.take(&said(1)));
    assert_eq!(point.epoch(), 1);
    point.reopen();
    assert_eq!(point.epoch(), 0);
    assert!(point.take(&said(1)));
    assert_eq!(point.epoch(), 1);
}

/// case_257: H9, K6. An epoch id with no statement, a statement signed by an authority key, one by an unknown key,
/// one with a byte changed and one with another key sequence change nothing and send no record, and a PEP with no
/// controller key takes no good statement.
#[test]
fn case_257_a_pep_takes_no_epoch_from_anything_but_a_good_statement() {
    let mut point = Point::controlled("257", "C", 0, true);
    point.pep.drain();
    assert!(!point.pep.take_offered("9").unwrap() && !point.pep.take_offered("").unwrap());
    let good = said(5);
    let mut changed = good.clone();
    changed[30] ^= 1;
    for bad in [signed_by("A", Said { epoch: 5, ..Said::default() }), signed_by("U", Said { epoch: 5, ..Said::default() }), changed,
                signed_by("C", Said { key_seq: 1, epoch: 5, ..Said::default() })] {
        assert!(!point.take(&bad));
    }
    assert!(point.pep.drain().is_empty());
    assert_eq!(point.epoch(), 0);
    let mut bare = Point::new("257_bare"); // a /1 anchor names no controller key
    bare.pep.drain();
    assert!(!bare.take(&good));
    assert!(bare.pep.drain().is_empty());
    assert_eq!(bare.epoch(), 0);
}

/// case_258: H9. A statement above the id held is taken, the same again and a lower one change nothing. The
/// statement of an `offers` answer, base64url without padding, is taken the same way.
#[test]
fn case_258_a_higher_epoch_is_taken_and_never_lowered() {
    let mut point = Point::controlled("258", "C", 0, true);
    assert!(point.pep.take_offered(&encode_offered(&said(6))).unwrap());
    assert!(!point.take(&said(6)) && !point.take(&said(2)));
    assert_eq!((point.pep.epoch(), point.epoch()), (6, 6));
}

/// case_259: K7, H9, H15. A `trust.controller` naming a new key is applied with `trust-applied` and epoch 0. Then a
/// statement by the old key, one by the new key with the old key sequence, and one by the new key with the new key
/// sequence and an epoch id below the one held before: nothing, nothing, taken.
#[test]
fn case_259_a_trust_controller_names_a_new_key_and_starts_the_epoch_again() {
    let mut point = Point::controlled("259", "C", 0, true);
    assert!(point.take(&said(9)));
    let applied = point.rekey("D", 1, "A");
    assert_eq!((applied.event, applied.epoch, applied.trust_seq), ("trust-applied", 0, 1));
    assert_eq!(controller_id(point.pep.trust()), Some(key_id("D")));
    assert_eq!(point.pep.trust().key_sequence(), 1);
    assert!(point.pep.trust().retired.contains(&key_id("C")));
    assert!(!point.take(&signed_by("C", Said { key_seq: 1, epoch: 20, ..Said::default() })));
    assert!(!point.take(&signed_by("D", Said { key_seq: 0, epoch: 20, ..Said::default() })));
    assert!(point.take(&signed_by("D", Said { key_seq: 1, epoch: 3, ..Said::default() })));
    assert_eq!(point.pep.epoch(), 3);
    assert_eq!(controller_id(point.open().unwrap().trust()), Some(key_id("D")), "durable in the trust store");
}

/// case_260: K6, K7, K4. A `trust.controller` whose key is an authority key, the PEP's instance key, an install key,
/// an operator key, a revoked key, the controller key it replaced before and a retired key is `dist:rotation-invalid`
/// each time, and an anchor whose controller key is also an authority key is refused at provisioning.
#[test]
fn case_260_a_trust_controller_may_not_name_a_key_of_another_role() {
    let anchor = anchor2_of(&["A", "B"], "C", 0);
    let mut point = Point::anchored("260", test_key("I"), &["A", "B"], anchor, REFUSE, true).unwrap();
    let mut causes = vec![point.rekey("A", 1, "A").cause, point.rekey("I", 1, "A").cause];
    let mut installer = installs::Installer::with("260_install", &installs::anchor2(&installs::INSTALL_KEYS, 2, &["O1"], 0), &[], false);
    for key in ["N1", "O1"] {
        let body = controller_key(key);
        let sealed = trust_statement(ArtifactKind::TrustController, &body, 1, &["A"], &[TargetKind::Host]);
        causes.push(installer.send(&[(sealed, body)]).cause);
    }
    point.revoke(1, &revocation(&[], &[key_id("R")], &[], &[]));
    causes.push(point.rekey("R", 2, "A").cause);
    assert_eq!(point.rekey("D", 2, "A").event, "trust-applied");
    causes.push(point.rekey("C", 3, "A").cause); // the key D replaced
    assert_eq!(point.rotate(3, "E", Some("B")).event, "trust-applied");
    causes.push(point.rekey("B", 4, "A").cause); // retired as an authority key
    assert_eq!(causes, vec![Some("dist:rotation-invalid".to_string()); 7]);
    assert_eq!((point.pep.trust().trust_seq, installer.pep.trust().trust_seq), (3, 0));

    let stream = Stream::try_from(STREAM).unwrap();
    assert!(anchor2_bytes(&[public("A")], TargetKind::Host, &stream, &public("A"), 0, None).is_err());
    let mut doc: serde_json::Value = serde_json::from_slice(&point.anchor()).unwrap();
    doc["controller"] = serde_json::json!(hex::encode(public("A")));
    let shared = canon2::write_json(&doc).unwrap();
    let before = point.pep.trust().clone();
    assert!(point.pep.provision(&shared).is_err());
    assert!(!point.state_dir().join("dist").join("anchor.pending").exists());
    assert_eq!(point.pep.trust(), &before);
}

/// case_262: K6, K7, R2. After the controller key is revoked a good statement is not taken. A `trust.controller`
/// naming a new key follows, and a statement under it is.
#[test]
fn case_262_a_revoked_controller_key_gives_nothing_until_a_new_key_is_named() {
    let mut point = Point::controlled("262", "C", 0, true);
    point.revoke(1, &revocation(&[], &[key_id("C")], &[], &[]));
    assert!(!point.take(&said(4)));
    assert_eq!(point.pep.epoch(), 0);
    assert_eq!(point.rekey("D", 2, "A").event, "trust-applied");
    assert!(point.take(&signed_by("D", Said { key_seq: 2, epoch: 4, ..Said::default() })));
    assert_eq!(point.pep.epoch(), 4);
}

/// case_269: H16, X1, the `host` half. With `fresh` 3600 the PEP takes a fresh statement and, cut off for 3901
/// seconds, lapses with dist:expired; at 3900 it is still active.
#[test]
fn case_269_a_pep_cut_off_past_its_fresh_statement_lapses() {
    let mut point = Point::controlled("269", "C", 3600, true);
    point.commit_at(&old(), 1);
    assert!(point.take(&fresh(1, NOW + 3600, 0, 1)));
    assert!(point.pep.kept().is_some());
    point.now.set(NOW + 3900);
    assert!(point.pep.tick().unwrap().is_none());
    assert_eq!(point.pep.state(), "active");
    point.now.set(NOW + 3901);
    let signed = point.pep.tick().unwrap().unwrap();
    let lapsed = point.read(&signed);
    assert_eq!((lapsed.event, lapsed.cause.as_deref(), lapsed.state), ("lapsed", Some("dist:expired"), "no-policy"));
}

/// case_270: H16, H9, T1. With `fresh` 3600, a statement for another stream changes nothing, one whose trust sequence
/// is below the PEP's, one whose stream seq is below its floor and one 3901 seconds ahead give no freshness, one 3900
/// seconds ahead gives it and one with `fresh` 0 gives none. The epoch ids of all but the first are taken, and the
/// time floor does not move.
#[test]
fn case_270_what_gives_freshness() {
    let mut point = Point::controlled("270", "C", 3600, true);
    point.commit_at(&old(), 1);
    point.revoke(1, &revocation(&[], &[], &[], &[]));
    let floor = point.pep.trust().time_floor;
    let good = |epoch: u64, expires: i64| Said { epoch, fresh: true, trust_seq: 1, stream_seq: 1, expires: expires as u64, ..Said::default() };
    let sent = [
        signed_by("C", Said { stream: "other/stream", ..good(1, NOW + 3600) }),
        signed_by("C", Said { trust_seq: 0, ..good(2, NOW + 3600) }),
        signed_by("C", Said { stream_seq: 0, ..good(3, NOW + 3600) }),
        signed_by("C", good(4, NOW + 3901)),
        signed_by("C", good(5, NOW + 3900)),
        signed_by("C", Said { epoch: 6, expires: (NOW + 7200) as u64, ..Said::default() }),
    ];
    let (mut taken, mut kept) = (Vec::new(), Vec::new());
    for data in &sent {
        taken.push(point.take(data));
        kept.push(point.pep.kept().map(|kept| kept.expires));
    }
    assert_eq!(taken, [false, true, true, true, true, true]);
    assert_eq!(kept, [None, None, None, None, Some(NOW + 3900), Some(NOW + 3900)]);
    assert_eq!((point.pep.trust().time_floor, point.pep.epoch()), (floor, 6));
}

/// case_271: H16, P4. A PEP with `fresh` 0 cut off for a year with a release that expires in two decides under it the
/// whole year, and a PEP with `fresh` 3600 still holds its fresh statement after a restart.
#[test]
fn case_271_freshness_off_decides_a_year_and_a_kept_statement_survives_a_restart() {
    let mut off = Point::controlled("271_off", "C", 0, true);
    off.commit(&old(), &Args { expires: NOW + 2 * YEAR, ..at(1) });
    off.now.set(NOW + YEAR);
    assert!(off.pep.tick().unwrap().is_none());
    assert_eq!(off.pep.decide(|| "ran").unwrap().decision, Some("ran"));
    let mut on = Point::controlled("271_on", "C", 3600, true);
    assert!(on.take(&fresh(1, NOW + 3600, 0, 0)));
    let kept = on.pep.kept().cloned();
    assert!(kept.is_some() && on.state_dir().join("dist").join("fresh.json").exists());
    on.reopen();
    assert_eq!(on.pep.kept().cloned(), kept);
    assert_eq!(on.pep.epoch(), 0);
}

/// case_276: H9, on two `host` PEPs standing for the `mesh` nodes. Controller statements for two streams come in
/// turn, as a broadcast carries them, and each PEP takes every statement of its own stream and none of the other's.
#[test]
fn case_276_a_broadcast_starves_no_stream() {
    let streams = ["host/a", "host/b"];
    let mut points: Vec<Point> = streams
        .iter()
        .map(|stream| {
            let anchor = anchor2_on(&["A"], "C", 0, stream);
            Point::anchored(&format!("276_{}", &stream[5..]), test_key(stream), &["A"], anchor, REFUSE, true).unwrap()
        })
        .collect();
    let mut taken = [Vec::new(), Vec::new()];
    for turn in 0..3u64 {
        for stream in streams {
            let data = signed_by("C", Said { stream, epoch: turn + 2, ..Said::default() });
            for (at, point) in points.iter_mut().enumerate() {
                if point.take(&data) {
                    taken[at].push(statements::parse(&data).unwrap().0.stream);
                }
            }
        }
    }
    for (at, stream) in streams.iter().enumerate() {
        assert_eq!(taken[at], vec![state_record::stream_prefix(stream); 3]);
        assert_eq!(points[at].pep.epoch(), 4);
    }
}

/// case_277: H9, H16, H15. A statement by the stolen controller key with epoch id 2^64 - 1 is taken, a good fresh
/// statement still gives freshness, and after a restart the PEP takes the controller's next epoch id.
#[test]
fn case_277_a_stolen_key_at_the_top_keeps_no_good_statement_from_freshness() {
    let mut point = Point::controlled("277", "C", 3600, true);
    assert!(point.take(&said(u64::MAX)));
    assert_eq!(point.epoch(), u64::MAX);
    assert!(!point.take(&fresh(1, NOW + 3600, 0, 0)));
    assert_eq!(point.pep.kept().map(|kept| kept.expires), Some(NOW + 3600));
    point.reopen();
    assert!(point.take(&fresh(2, NOW + 3600, 0, 0)));
    assert_eq!(point.pep.epoch(), 2);
}

/// case_278: H16, T1, T2, on a `host` PEP with no clock standing for the `mesh` node. Off for 30 days, it starts and
/// takes a good fresh statement as a raise of its time floor to its `expires` less 3600, with freshness. One a year
/// ahead in the same start gives none and moves nothing, and a `host` PEP with a clock takes no time and no freshness
/// from one a year ahead.
#[test]
fn case_278_a_clockless_pep_takes_time_once_a_start() {
    let mut node = Point::controlled("278_node", "C", 3600, false);
    node.reopen(); // a start, its clock where it stopped
    let true_time = NOW + 30 * 86400;
    assert!(node.take(&fresh(1, true_time + 3600, 0, 0)));
    assert_eq!(node.pep.trust().time_floor, true_time);
    assert_eq!(node.pep.kept().map(|kept| kept.expires), Some(true_time + 3600));
    assert!(node.take(&fresh(2, true_time + YEAR, 0, 0)));
    assert_eq!(node.pep.trust().time_floor, true_time);
    assert_eq!(node.pep.kept().map(|kept| kept.expires), Some(true_time + 3600));
    let mut host = Point::controlled("278_host", "C", 3600, true);
    let floor = host.pep.trust().time_floor;
    assert!(host.take(&fresh(1, NOW + YEAR, 0, 0)));
    assert_eq!(host.pep.trust().time_floor, floor);
    assert!(host.pep.kept().is_none());
}

/// case_279: K7, K5, H6. A PEP provisioned from a `/1` anchor gains the key a `trust.controller` names and takes a
/// statement under it. A store of 8 authority keys and no controller key refuses one with dist:too-large. A
/// `trust.controller` naming the key already held keeps it at the new key sequence, and a statement under the old
/// key sequence is not taken.
#[test]
fn case_279_a_store_gains_a_controller_key_and_keeps_its_bound() {
    let mut bare = Point::new("279_bare");
    assert!(bare.pep.trust().controller().is_none());
    assert_eq!(bare.rekey("C", 1, "A").event, "trust-applied");
    assert!(bare.take(&signed_by("C", Said { key_seq: 1, epoch: 3, ..Said::default() })));
    assert_eq!(bare.pep.epoch(), 3);
    let eight = ["A", "B", "D", "E", "F", "G", "H", "J"];
    let mut full = Point::with("279_full", test_key("I"), &eight, REFUSE).unwrap();
    assert_eq!(full.pep.trust().keys.len(), 8);
    assert_eq!(full.rekey("C", 1, "A").cause.as_deref(), Some("dist:too-large"));
    let mut held = Point::controlled("279_held", "C", 0, true);
    assert_eq!(held.rekey("C", 1, "A").event, "trust-applied");
    assert_eq!((controller_id(held.pep.trust()), held.pep.trust().key_sequence()), (Some(key_id("C")), 1));
    assert!(!held.pep.trust().retired.contains(&key_id("C")));
    assert!(!held.take(&signed_by("C", Said { key_seq: 0, epoch: 5, ..Said::default() })));
    assert!(held.take(&signed_by("C", Said { key_seq: 1, epoch: 5, ..Said::default() })));
}
