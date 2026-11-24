// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The reconciling state of the Rust enforcement point (spec-policy-distribution.md, section 9.5, H14 and P5)
//! on the `host` target, over a host adapter whose runtime steps the test makes fail. Each test names the
//! conformance case of section 20 it covers. A restart is a fresh `Pep` over the same state directory, and a
//! death is the commit hook stopping a step. This crate builds no action floor and no fallback policy
//! (section 21), so every PEP here holds neither, and the withdrawal leaves the runtime running nothing.

#[path = "common/mod.rs"]
mod common;
#[path = "common/dist.rs"]
mod dist;

use dist::*;
use prismpath_hotswap_rs::dist::pep::{Adapter, Comparison, HostAdapter, Pep, PepError, PepStep, Release, REFUSE};
use prismpath_hotswap_rs::dist::state_record::{self, ReconcilingEntry, StateRecord};
use prismpath_hotswap_rs::dist::{ArtifactKind, TargetKind};
use serde_json::{json, Value};
use std::cell::Cell;
use std::rc::Rc;

/// What the test does to the runtime: whether its install and its withdrawal fail, and how often each was tried.
#[derive(Clone, Default)]
struct Switches {
    fail_activate: Rc<Cell<bool>>,
    fail_withdraw: Rc<Cell<bool>>,
    activations: Rc<Cell<usize>>,
    withdrawals: Rc<Cell<usize>>,
}

impl Switches {
    fn set(&self, activate: bool, withdraw: bool) {
        self.fail_activate.set(activate);
        self.fail_withdraw.set(withdraw);
    }

    fn tries(&self) -> (usize, usize) {
        (self.activations.get(), self.withdrawals.get())
    }
}

/// The host adapter with a runtime that fails when the switches say so, before the host is touched.
struct Flaky {
    host: HostAdapter,
    switches: Switches,
}

impl Adapter for Flaky {
    fn kind(&self) -> TargetKind {
        self.host.kind()
    }

    fn home(&self) -> Option<String> {
        self.host.home()
    }

    fn qualification(&self) -> Option<Value> {
        self.host.qualification()
    }

    fn check(&self, artifact: ArtifactKind, body: &[u8], staged: &Release) -> Option<String> {
        self.host.check(artifact, body, staged)
    }

    fn compare(&self, active: &Release, staged: &Release) -> Comparison {
        self.host.compare(active, staged)
    }

    fn activate(&self, release: &Release) -> Result<(), PepError> {
        self.switches.activations.set(self.switches.activations.get() + 1);
        if self.switches.fail_activate.get() {
            return Err(PepError::Refused("the runtime did not take the release".into()));
        }
        self.host.activate(release)
    }

    fn deactivate(&self, cause: &str) -> Result<(), PepError> {
        self.switches.withdrawals.set(self.switches.withdrawals.get() + 1);
        if self.switches.fail_withdraw.get() {
            return Err(PepError::Refused("the runtime did not withdraw".into()));
        }
        self.host.deactivate(cause)
    }
}

/// A provisioned host PEP over a flaky runtime, its clock and its switches.
struct Rig {
    scratch: common::Scratch,
    now: Rc<Cell<i64>>,
    switches: Switches,
    pep: Pep<Flaky>,
}

impl Rig {
    fn new(tag: &str) -> Rig {
        let scratch = common::Scratch::new(&format!("dist_reconciling_{tag}"));
        let now = Rc::new(Cell::new(NOW));
        let switches = Switches::default();
        let mut pep = Rig::pep_over(&scratch, &now, &switches).unwrap();
        let fingerprint = pep.provision(&anchor_of(&["A"])).unwrap();
        pep.confirm(&fingerprint).unwrap();
        Rig { scratch, now, switches, pep }
    }

    fn pep_over(scratch: &common::Scratch, now: &Rc<Cell<i64>>, switches: &Switches) -> Result<Pep<Flaky>, PepError> {
        let dir = scratch.join("host");
        let flaky = Flaky { host: HostAdapter::new(host_at(&dir)), switches: switches.clone() };
        Pep::new(dir.to_str().unwrap(), flaky, test_key("I"), clock_of(now), REFUSE, true)
    }

    /// A fresh PEP over the same directory and the same runtime switches, as after a restart.
    fn reopen(&mut self) {
        self.pep = Rig::pep_over(&self.scratch, &self.now, &self.switches).unwrap();
    }

    fn path(&self, name: &str) -> std::path::PathBuf {
        self.scratch.join("host").join("dist").join(name)
    }

    fn stage(&mut self, sealed: &[u8], body: &[u8]) -> StateRecord {
        let signed = self.pep.stage(sealed, body).unwrap();
        read(&signed)
    }

    fn commit_at(&mut self, body: &[u8], seq: i64) -> StateRecord {
        self.stage(&ppt(body, &at(seq)), body);
        let signed = self.pep.commit(STREAM, seq, &h(body), 0).unwrap();
        read(&signed)
    }

    /// Stage `body` at `seq` with a widening statement whose `from` is empty, so a rollback to it is covered (RB3).
    fn stage_covered(&mut self, body: &[u8], seq: i64) {
        let release = release_of(body);
        self.stage(&ppt(body, &Args { release: Some(release.clone()), ..at(seq) }), body);
        let statement = widening(&[]);
        let args = Args { release: Some(release), policy: Some(h(body)), ..at(seq) };
        assert_eq!(self.stage(&seal(ArtifactKind::TrustWidening, &statement, &args), &statement).event, "staged");
    }

    fn records(&mut self) -> Vec<StateRecord> {
        self.pep.drain().iter().map(|signed| read(signed)).collect()
    }

    fn host_active(&self) -> Value {
        self.pep.adapter.host.host.active_info()["active"].clone()
    }

    fn actions(&self, action: &str) -> usize {
        self.pep.audit.events().iter().filter(|event| event["action"] == action).count()
    }

    fn revoke(&mut self, seq: i64, body: &[u8]) -> StateRecord {
        let sealed = trust_statement(ArtifactKind::TrustRevocation, body, seq, &["A"], &[TargetKind::Host]);
        self.stage(&sealed, body)
    }
}

/// The state record `signed`, read under the instance key I.
fn read(signed: &[u8]) -> StateRecord {
    state_record::read(signed, &public("I")).unwrap()
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

fn prefix(body: &[u8]) -> [u8; 16] {
    state_record::prefix(Some(h(body).as_str()))
}

fn entry(record: &StateRecord) -> Option<ReconcilingEntry> {
    state_record::reconciling_entry(record).unwrap()
}

/// What a record says of the state: its event, its state and the seq of the held release.
fn said(record: &StateRecord) -> (&'static str, &'static str, u64) {
    (record.event, record.state, record.active_seq)
}

/// The running release an entry names, by its policy prefix and seq, or None for zeros.
fn running(entry: &ReconcilingEntry) -> Option<([u8; 16], u64)> {
    (entry.running_seq != 0).then_some((entry.running_policy, entry.running_seq))
}

/// case_240: C6, C8, C9, C10, X3. A commit whose runtime step fails withdraws the runtime, refuses every
/// decision with dist:reconciling, sends one `reconciling` record and, once a tick's try works, one `committed`
/// record with status active. A tick whose try fails changes nothing.
#[test]
fn case_240_a_failed_commit_withdraws_refuses_and_reports_committed_when_a_try_works() {
    let mut rig = Rig::new("240");
    rig.commit_at(&old(), 1);
    rig.stage(&ppt(&new(), &at(2)), &new());
    rig.pep.drain();
    rig.switches.set(true, false);
    let entered = read(&rig.pep.commit(STREAM, 2, &h(&new()), 0).unwrap());
    assert_eq!(said(&entered), ("reconciling", "reconciling", 2));
    let at_entry = entry(&entered).unwrap();
    assert_eq!((at_entry.owed, running(&at_entry), at_entry.cause), ("committed", None, None), "withdrawn, so nothing runs");
    assert_eq!(rig.host_active(), json!(null), "the runtime was withdrawn at once");
    assert_eq!(entered.active_policy, prefix(&new()), "the active fields name the held release");

    let decided = rig.pep.decide(|| "ran").unwrap();
    assert_eq!((decided.decision, decided.cause), (None, Some("dist:reconciling")));
    assert_eq!(rig.pep.tick().unwrap(), None, "a try that fails changes nothing");
    assert_eq!(rig.pep.state(), "reconciling");
    let beat = read(&rig.pep.record("beat", None).unwrap());
    assert_eq!((beat.state, beat.body.len()), ("reconciling", 0));
    assert!(entry(&beat).is_some(), "every record carries the entry (H14)");

    rig.switches.set(false, false);
    let left = read(&rig.pep.tick().unwrap().unwrap());
    assert_eq!(said(&left), ("committed", "active", 2));
    assert!(entry(&left).is_none() && left.extensions.is_empty());
    let events: Vec<_> = rig.records().iter().map(|record| record.event).collect();
    assert_eq!(events, ["reconciling", "beat", "committed"]);
    assert_eq!(rig.host_active(), json!(h(&new()).as_str()));
    assert_eq!(rig.pep.decide(|| "ran").unwrap().decision, Some("ran"));
    assert_eq!((rig.actions("committed"), rig.actions("reconciling"), rig.actions("reconciled")), (2, 1, 1));
    assert!(!rig.path("pending.json").exists());
}

/// case_241: C6, C7, C9. A rollback, a lapse at expiry and a start whose runtime step fails, with no intent record
/// for the start, are each reconciling, then send `rolled-back`, `lapsed` with dist:expired and a `beat` with
/// status active.
#[test]
fn case_241_a_rollback_a_lapse_and_a_start_reconcile_and_report_what_they_owed() {
    let mut rig = Rig::new("241_rollback");
    rig.stage_covered(&old(), 1);
    rig.pep.commit(STREAM, 1, &h(&old()), 0).unwrap();
    rig.commit_at(&new(), 2);
    rig.switches.set(true, false);
    let entered = read(&rig.pep.rollback().unwrap());
    assert_eq!((said(&entered), entry(&entered).unwrap().owed), (("reconciling", "reconciling", 1), "rolled-back"));
    rig.switches.set(false, false);
    let left = read(&rig.pep.tick().unwrap().unwrap());
    assert_eq!(said(&left), ("rolled-back", "active", 1));
    assert_eq!(rig.host_active(), json!(h(&old()).as_str()));

    let mut rig = Rig::new("241_lapse");
    rig.commit_at(&old(), 1);
    rig.now.set(EXPIRES);
    rig.switches.set(false, true);
    let entered = read(&rig.pep.tick().unwrap().unwrap());
    assert_eq!(said(&entered), ("reconciling", "reconciling", 0));
    let lapse = entry(&entered).unwrap();
    assert_eq!((lapse.owed, lapse.cause.as_deref()), ("lapsed", Some("dist:expired")));
    assert_eq!(running(&lapse), Some((prefix(&old()), 1)), "the withdrawal is the step that failed");
    assert_eq!(rig.host_active(), json!(h(&old()).as_str()));
    rig.switches.set(false, false);
    let left = read(&rig.pep.tick().unwrap().unwrap());
    assert_eq!((left.event, left.cause.as_deref(), left.state), ("lapsed", Some("dist:expired"), "no-policy"));
    assert_eq!(rig.host_active(), json!(null));
    assert_eq!(rig.actions("lapsed"), 1, "the lapse's audit event is written once");

    let mut rig = Rig::new("241_start");
    rig.commit_at(&old(), 1);
    rig.pep.adapter.host.host.withdraw("dist:policy-lapsed").unwrap(); // the runtime lost what it ran
    rig.switches.set(true, true);
    rig.reopen();
    assert!(!rig.path("pending.json").exists());
    let started = rig.records();
    assert_eq!(started.iter().map(said).collect::<Vec<_>>(), [("reconciling", "reconciling", 1)]);
    let start = entry(&started[0]).unwrap();
    assert_eq!((start.owed, running(&start)), ("beat", Some((prefix(&old()), 1))), "the held release may be running (C7)");
    rig.switches.set(false, false);
    let left = read(&rig.pep.tick().unwrap().unwrap());
    assert_eq!(said(&left), ("beat", "active", 1));
    assert_eq!(rig.host_active(), json!(h(&old()).as_str()));
}

/// case_242: C8. A commit for the staged release and a rollback are each answered `refused` with dist:reconciling,
/// nothing changes and the staged release stays staged. A commit with a delay is refused before any state, since
/// this crate does not build the frame binding (B8, DIVERGENCES.md).
#[test]
fn case_242_a_reconciling_pep_refuses_a_commit_and_a_rollback_and_keeps_the_staged_release() {
    let mut rig = Rig::new("242");
    rig.stage_covered(&old(), 1);
    rig.pep.commit(STREAM, 1, &h(&old()), 0).unwrap();
    rig.stage(&ppt(&new(), &at(2)), &new());
    rig.switches.set(true, false);
    rig.pep.commit(STREAM, 2, &h(&new()), 0).unwrap();
    rig.stage(&ppt(&newer(), &at(3)), &newer());
    let tries = rig.switches.tries();
    let committed = read(&rig.pep.commit(STREAM, 3, &h(&newer()), 0).unwrap());
    let rolled = read(&rig.pep.rollback().unwrap());
    for record in [&committed, &rolled] {
        assert_eq!((record.event, record.cause.as_deref(), record.state), ("refused", Some("dist:reconciling"), "reconciling"));
        assert_eq!((record.active_seq, record.staged, record.staged_seq), (2, true, 3));
    }
    assert!(rig.pep.commit(STREAM, 3, &h(&newer()), 500).is_err());
    assert_eq!(rig.pep.staged().unwrap().seq, 3);
    assert_eq!((rig.pep.active().unwrap().seq, rig.pep.floor().seq), (2, 2));
    assert_eq!(rig.switches.tries(), tries, "no call but a tick tries the runtime");
}

/// case_243: C8, C9, G2, A1, R3, the half this crate builds. A reconciling PEP stages a new release with a stage
/// ack that names it, replaces it with a higher one, aborts, applies a revocation and takes an anchor to confirm,
/// and none of these tries the runtime. The controller statement is pending, since this crate does not build the
/// controller key (K6, K7).
#[test]
fn case_243_a_reconciling_pep_stages_aborts_and_applies_trust_statements_without_a_try() {
    let mut rig = Rig::new("243");
    rig.commit_at(&old(), 1);
    rig.stage(&ppt(&new(), &at(2)), &new());
    rig.switches.set(true, true);
    rig.pep.commit(STREAM, 2, &h(&new()), 0).unwrap();
    let tries = rig.switches.tries();
    let staged = rig.stage(&ppt(&newer(), &at(3)), &newer());
    assert_eq!((staged.event, staged.state, staged.staged_release), ("staged", "reconciling", prefix_of_release(&newer())));
    let higher = rig.stage(&ppt(&old(), &at(4)), &old());
    assert_eq!((higher.event, higher.staged_seq), ("staged", 4));
    assert_eq!(read(&rig.pep.abort(STREAM, 4, &h(&old())).unwrap()).event, "aborted");
    let applied = rig.revoke(1, &revocation(&[], &[], &[h(&newer())], &[]));
    assert_eq!((applied.event, applied.state, applied.trust_seq), ("trust-applied", "reconciling", 1));
    rig.pep.provision(&anchor_of(&["A"])).unwrap();
    assert!(rig.path("anchor.pending").exists());
    assert_eq!(rig.switches.tries(), tries);
    assert!(rig.pep.is_reconciling());
}

fn prefix_of_release(body: &[u8]) -> [u8; 16] {
    state_record::prefix(Some(release_of(body).as_str()))
}

/// case_244: C7, H14. A rollback killed after its active record is restarted with a runtime that still fails: the
/// entry names the release the rollback was leaving, from the intent record, and the active fields the kept one.
#[test]
fn case_244_a_restarted_rollback_names_the_release_it_was_leaving() {
    let mut rig = Rig::new("244");
    rig.stage_covered(&old(), 1);
    rig.pep.commit(STREAM, 1, &h(&old()), 0).unwrap();
    rig.commit_at(&new(), 2);
    rig.pep.set_commit_hook(Some(Box::new(|at| if at == PepStep::Runtime { Err("died".into()) } else { Ok(()) })));
    assert!(rig.pep.rollback().is_err());
    rig.switches.set(true, true);
    rig.reopen();
    let records = rig.records();
    let last = records.last().unwrap();
    assert_eq!(said(last), ("reconciling", "reconciling", 1));
    assert_eq!(last.active_policy, prefix(&old()));
    let left = entry(last).unwrap();
    assert_eq!((left.owed, running(&left)), ("rolled-back", Some((prefix(&new()), 2))));
    assert_eq!(rig.pep.running().unwrap().seq, 2);
}

/// case_245: C7. A lapse killed after its intent record and before its active record leaves the release active.
/// The restart reports the lapse incomplete and its checks lapse the release again.
#[test]
fn case_245_a_lapse_killed_before_its_active_record_is_lapsed_again_at_the_start() {
    let mut rig = Rig::new("245");
    rig.commit_at(&old(), 1);
    rig.now.set(EXPIRES);
    rig.pep.set_commit_hook(Some(Box::new(|at| if at == PepStep::ActiveRecord { Err("died".into()) } else { Ok(()) })));
    assert!(rig.pep.tick().is_err());
    assert!(rig.path("pending.json").exists());
    let held = std::fs::read_to_string(rig.path("active.json")).unwrap();
    assert!(held.contains("policy.ppt"), "the active record still names the release");
    rig.reopen();
    let incomplete: Vec<_> = rig.pep.audit.events().into_iter().filter(|event| event["action"] == "commit_incomplete").collect();
    assert_eq!(incomplete.len(), 1);
    assert_eq!(incomplete[0]["data"]["op"], json!("lapse"));
    let records = rig.records();
    assert_eq!(records.iter().map(|record| (record.event, record.cause.clone())).collect::<Vec<_>>(), [("lapsed", Some("dist:expired".into()))]);
    assert_eq!((rig.pep.state(), rig.host_active()), ("no-policy", json!(null)));
}

/// case_246: C10, R5, X1, Q4, H14, the expiry and revocation runs. While a commit is reconciling with its runtime
/// withdrawn, the held release expires, and in another run is revoked: it is never installed, the PEP is
/// `no-policy` at once, sends one `lapsed` record with that cause and no `committed` record, and the floor stays
/// the commit's. The ceiling and fallback runs are pending, since this crate builds no section 21.
#[test]
fn case_246_a_held_release_that_falls_while_withdrawn_is_never_installed() {
    for cause in ["dist:expired", "dist:revoked"] {
        let mut rig = Rig::new(&format!("246_{}", &cause[5..]));
        rig.commit_at(&old(), 1);
        rig.stage(&ppt(&new(), &at(2)), &new());
        rig.switches.set(true, false);
        rig.pep.commit(STREAM, 2, &h(&new()), 0).unwrap();
        rig.pep.drain();
        let activations = rig.switches.tries().0;
        if cause == "dist:expired" {
            rig.now.set(EXPIRES);
            rig.pep.tick().unwrap();
        } else {
            rig.revoke(1, &revocation(&[], &[], &[h(&new())], &[]));
        }
        let records = rig.records();
        let lapsed: Vec<_> = records.iter().filter(|record| record.event == "lapsed").collect();
        assert_eq!(lapsed.len(), 1, "{cause}");
        assert_eq!((lapsed[0].cause.as_deref(), lapsed[0].state, lapsed[0].active_seq), (Some(cause), "no-policy", 0), "{cause}");
        assert!(records.iter().all(|record| record.event != "committed"), "{cause}");
        assert_eq!(rig.switches.tries().0, activations, "{cause}: never installed");
        assert_eq!((rig.pep.state(), rig.pep.floor().seq, rig.host_active()), ("no-policy", 2, json!(null)), "{cause}");
        let never_ran = rig.pep.audit.events().into_iter().filter(|event| event["action"] == "lapsed").collect::<Vec<_>>();
        assert_eq!(never_ran.len(), 1, "{cause}");
        assert_eq!(never_ran[0]["data"]["ran"], json!(false), "{cause}");
    }
}

/// case_247: C10, H14, X1. A commit whose runtime refuses to withdraw names the running release in every record,
/// with dist:expired once it falls, each tick tries the withdrawal again, and the held release is still held to
/// the tests.
#[test]
fn case_247_a_running_release_that_will_not_withdraw_is_named_and_held_to_the_tests() {
    let mut rig = Rig::new("247");
    rig.commit_at(&old(), 1);
    let later = Args { expires: EXPIRES + 86400, ..at(2) };
    rig.stage(&ppt(&new(), &later), &new());
    rig.switches.set(true, true);
    let entered = read(&rig.pep.commit(STREAM, 2, &h(&new()), 0).unwrap());
    let named = entry(&entered).unwrap();
    assert_eq!((running(&named), named.cause), (Some((prefix(&old()), 1)), None));
    let withdrawals = rig.switches.tries().1;
    rig.now.set(EXPIRES);
    for tick in 1..=3 {
        assert_eq!(rig.pep.tick().unwrap(), None);
        assert_eq!(rig.switches.tries().1, withdrawals + tick, "each tick tries the withdrawal again");
    }
    let beat = read(&rig.pep.record("beat", None).unwrap());
    let fell = entry(&beat).unwrap();
    assert_eq!((running(&fell), fell.cause.as_deref(), beat.active_seq), (Some((prefix(&old()), 1)), Some("dist:expired"), 2));
    rig.now.set(EXPIRES + 86400);
    let held_fell = read(&rig.pep.record("beat", None).unwrap());
    let both = entry(&held_fell).unwrap();
    assert_eq!((both.owed, both.cause.as_deref(), held_fell.active_seq), ("lapsed", Some("dist:expired"), 0));
    assert_eq!(running(&both), Some((prefix(&old()), 1)));
}

/// case_248: C11. A rollback whose runtime refuses to withdraw keeps every envelope and body of the release it was
/// leaving through a stage of that release again, an abort and a higher release staged.
#[test]
fn case_248_the_running_release_keeps_its_blobs_until_the_withdrawal_works() {
    let mut rig = Rig::new("248");
    rig.stage_covered(&old(), 1);
    rig.pep.commit(STREAM, 1, &h(&old()), 0).unwrap();
    let leaving = ppt(&new(), &at(2));
    rig.stage(&leaving, &new());
    rig.pep.commit(STREAM, 2, &h(&new()), 0).unwrap();
    rig.switches.set(true, true);
    rig.pep.rollback().unwrap();
    let blobs: Vec<_> = rig.pep.running().unwrap().held.values().flat_map(|held| [held.sealed.clone(), held.body.clone()]).collect();
    assert_eq!(blobs.len(), 2);
    rig.stage(&leaving, &new());
    rig.pep.abort(STREAM, 2, &h(&new())).unwrap();
    rig.stage(&ppt(&newer(), &at(3)), &newer());
    rig.stage(&ppt(&old(), &at(4)), &old());
    for blob in &blobs {
        assert!(rig.pep.blob(blob).is_some(), "{blob}");
    }
    rig.switches.set(false, false);
    rig.pep.tick().unwrap();
    assert!(blobs.iter().all(|blob| rig.pep.blob(blob).is_none()), "they go once the withdrawal works");
}

/// case_249: C12, C4, H3. A commit killed after its state record is made and before its intent record goes is
/// reported again at the restart with a higher counter, and one killed before its record is made once. Each run
/// has one `committed` audit event.
#[test]
fn case_249_a_commit_killed_around_its_record_is_reported_at_the_restart_and_audited_once() {
    for (step, records) in [(PepStep::Cleanup, 2), (PepStep::Runtime, 1)] {
        let mut rig = Rig::new(&format!("249_{}", step.name()));
        rig.stage(&ppt(&old(), &at(1)), &old());
        rig.pep.drain();
        rig.pep.set_commit_hook(Some(Box::new(move |at| if at == step { Err("died".into()) } else { Ok(()) })));
        assert!(rig.pep.commit(STREAM, 1, &h(&old()), 0).is_err());
        let before = rig.records();
        rig.reopen();
        let after = rig.records();
        let committed: Vec<_> = before.iter().chain(&after).filter(|record| record.event == "committed").collect();
        assert_eq!(committed.len(), records, "{step:?}");
        assert!(committed.windows(2).all(|pair| pair[1].counter > pair[0].counter), "{step:?}");
        assert_eq!(rig.actions("committed"), 1, "{step:?}");
        assert!(!rig.path("pending.json").exists(), "{step:?}");
        assert_eq!(rig.host_active(), json!(h(&old()).as_str()), "{step:?}");
    }
}

/// case_250: C13, Q5, X3. A PEP whose floor cannot be read starts with a runtime that refuses to withdraw: it is
/// `locked` with the entry and dist:floor-lost, each tick tries again, and once the runtime obeys it is `locked`
/// with no entry.
#[test]
fn case_250_a_locked_pep_whose_runtime_will_not_withdraw_carries_the_entry() {
    let mut rig = Rig::new("250");
    rig.commit_at(&old(), 1);
    std::fs::write(rig.path("floor.json"), b"{").unwrap();
    rig.switches.set(false, true);
    rig.reopen();
    let started = rig.records();
    assert_eq!(started.iter().map(said).collect::<Vec<_>>(), [("reconciling", "locked", 0)]);
    let locked = entry(&started[0]).unwrap();
    assert_eq!((locked.owed, locked.cause.as_deref(), running(&locked)), ("beat", Some("dist:floor-lost"), None));
    assert_eq!(rig.pep.decide(|| "ran").unwrap().cause, Some("dist:floor-lost"));
    let withdrawals = rig.switches.tries().1;
    assert_eq!(rig.pep.tick().unwrap(), None);
    assert_eq!(rig.switches.tries().1, withdrawals + 1);
    rig.switches.set(false, false);
    let left = read(&rig.pep.tick().unwrap().unwrap());
    assert_eq!((said(&left), entry(&left)), (("beat", "locked", 0), None));
    assert_eq!(rig.host_active(), json!(null));
}

/// case_251: P5, P3, H15. A reconciling PEP is not provisioned over a runtime that refuses to withdraw, and
/// nothing changes. With one that obeys it is provisioned: `no-policy`, no intent record, no owed record sent and
/// epoch 0.
#[test]
fn case_251_provisioning_withdraws_first_and_is_refused_over_a_stuck_runtime() {
    let mut rig = Rig::new("251");
    rig.commit_at(&old(), 1);
    rig.stage(&ppt(&new(), &at(2)), &new());
    rig.switches.set(true, true);
    rig.pep.commit(STREAM, 2, &h(&new()), 0).unwrap();
    rig.pep.drain();
    let fingerprint = rig.pep.provision(&anchor_of(&["A"])).unwrap();
    let held = std::fs::read(rig.path("active.json")).unwrap();
    let refused = rig.pep.confirm(&fingerprint);
    assert!(matches!(&refused, Err(PepError::Refused(text)) if text.contains("(P5)")), "{refused:?}");
    assert!(rig.pep.is_reconciling() && rig.path("pending.json").exists() && rig.path("anchor.pending").exists());
    assert_eq!(std::fs::read(rig.path("active.json")).unwrap(), held);
    assert!(rig.pep.drain().is_empty());

    rig.switches.set(true, false);
    let provisioned = read(&rig.pep.confirm(&fingerprint).unwrap());
    assert_eq!((said(&provisioned), provisioned.epoch, entry(&provisioned)), (("provisioned", "no-policy", 0), 0, None));
    assert!(!rig.pep.is_reconciling() && !rig.path("pending.json").exists());
    assert_eq!(rig.records().iter().map(|record| record.event).collect::<Vec<_>>(), ["provisioned"]);
    assert_eq!(rig.host_active(), json!(null));
    rig.switches.set(false, false);
    assert_eq!(rig.pep.tick().unwrap(), None);
    assert!(rig.pep.drain().is_empty(), "the commit it owed is never sent");
}

/// case_274: C10, X5. A renewal, whose bodies are byte for byte the active release's, whose runtime step fails
/// stays `active` with the runtime running, sends `committed`, writes the failure to its audit log, tries again at
/// the next tick and never withdraws.
#[test]
fn case_274_a_renewal_whose_runtime_step_fails_stays_active() {
    let mut rig = Rig::new("274");
    rig.commit_at(&old(), 1);
    rig.stage(&ppt(&old(), &Args { expires: EXPIRES + 86400, ..at(2) }), &old());
    rig.pep.drain();
    rig.switches.set(true, false);
    let withdrawals = rig.switches.tries().1;
    let committed = read(&rig.pep.commit(STREAM, 2, &h(&old()), 0).unwrap());
    assert_eq!((said(&committed), entry(&committed)), (("committed", "active", 2), None));
    assert_eq!(rig.actions("runtime_failed"), 1);
    assert_eq!(rig.host_active(), json!(h(&old()).as_str()));
    assert_eq!(rig.pep.decide(|| "ran").unwrap().decision, Some("ran"));
    let activations = rig.switches.tries().0;
    assert_eq!(rig.pep.tick().unwrap(), None);
    assert_eq!(rig.switches.tries().0, activations + 1, "the tick tries the step again");
    rig.switches.set(false, false);
    rig.pep.tick().unwrap();
    rig.pep.tick().unwrap();
    assert_eq!(rig.switches.tries(), (activations + 2, withdrawals), "never withdrawn, and tried until it worked");
    assert!(!rig.pep.is_reconciling());
}

/// C10: a switch between two releases whose bodies differ is not a renewal, so a failed step reconciles.
#[test]
fn a_switch_between_different_bodies_reconciles() {
    let mut rig = Rig::new("not_renewal");
    rig.commit_at(&old(), 1);
    rig.stage(&ppt(&new(), &at(2)), &new());
    rig.switches.set(true, false);
    assert_eq!(read(&rig.pep.commit(STREAM, 2, &h(&new()), 0).unwrap()).event, "reconciling");
    assert_eq!(rig.actions("runtime_failed"), 0);
}

/// C9: no decision, record, stage or abort tries the runtime. Only a tick and a start do, one try each.
#[test]
fn only_a_tick_and_a_start_try_the_runtime() {
    let mut rig = Rig::new("only_tick");
    rig.commit_at(&old(), 1);
    rig.stage(&ppt(&new(), &at(2)), &new());
    rig.switches.set(true, true);
    rig.pep.commit(STREAM, 2, &h(&new()), 0).unwrap();
    let tries = rig.switches.tries();
    for _ in 0..5 {
        rig.pep.decide(|| ()).unwrap();
        rig.pep.record("beat", None).unwrap();
    }
    assert_eq!(rig.switches.tries(), tries);
    rig.pep.tick().unwrap();
    assert_eq!(rig.switches.tries(), (tries.0, tries.1 + 1), "the withdrawal that failed is tried first, and alone");
    rig.reopen();
    assert!(rig.pep.is_reconciling());
    let started = rig.records();
    assert_eq!(started.last().map(|record| record.event), Some("reconciling"), "a start that finds the state reports it again");
    assert_eq!(rig.actions("reconciling"), 2);
}
