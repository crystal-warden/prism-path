// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! Crash injection: stop the host before each step of a swap and of a rollback and show what is left
//! behind and what a fresh host does with it. Two ways of stopping. The hook returns an error before
//! the step, so the process lives on and its own memory can be inspected. The abort variant re-runs
//! this test binary as a child that calls `abort()` before the step, a real death with no unwinding
//! and no destructors, and the parent opens the state directory it left.
//!
//! What the protocol promises, and what these tests assert:
//!
//! * before the flip nothing in memory changes, so the previous policy stays active in the process;
//! * the image is content addressed (`active-<sha256>.ppt`) and written beside the one in use, so a
//!   death at any step leaves a record that names an image that is still there: a fresh host restores
//!   exactly one policy, the previous one up to the record rename and the new one after it, and never
//!   says `active_unreadable`;
//! * an image the record does not name is ignored, and the next commit that finishes removes it;
//! * recovery completes the commit: a death after the record flip is finished when the next host
//!   starts, a death before it is completed by the same swap again (the same image at the same
//!   version is admitted although the floor equals it, a different image at that version is not);
//! * a rollback commits in the swap's order and never lowers the floor, an event it cannot write is an
//!   `AuditWriteError` with nothing flipped, and the log verifies against its file at the end.

mod common;

use common::{corpus, fresh_dir, pack_path, stage};
use prismpath_hotswap_rs::host::{CommitStep, HostError, PolicyHost};
use serde_json::Value;
use std::path::Path;

struct Setup {
    doc: Value,
    dir: common::Scratch,
    pubs: Vec<String>,
}

impl Setup {
    fn new(tag: &str) -> Setup {
        let doc = corpus();
        let dir = fresh_dir(tag);
        let pubs = stage(&doc, &dir);
        Setup { doc, dir, pubs }
    }

    fn state(&self) -> String {
        self.dir.join("state").to_str().unwrap().to_string()
    }

    fn host(&self) -> PolicyHost {
        PolicyHost::new(&self.state(), self.pubs.clone(), self.doc["envelopes"]["default"].clone(), Vec::new()).unwrap()
    }

    fn pack(&self, name: &str) -> String {
        pack_path(&self.dir, name)
    }

    fn hash(&self, name: &str) -> String {
        self.doc["packs"][name]["manifest"]["image_sha256"].as_str().unwrap().to_string()
    }
}

fn read(state: &str, name: &str) -> Option<String> {
    std::fs::read_to_string(Path::new(state).join(name)).ok()
}

/// The image files in the state directory, as the hash of what each holds, sorted.
fn images(state: &str) -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(state)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("active") && name.ends_with(".ppt"))
        .collect();
    out.sort();
    out
}

fn names(hashes: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = hashes.iter().map(|hash| format!("active-{hash}.ppt")).collect();
    out.sort();
    out
}

/// The digest the record names and the digest of the image it names: the same, or the state is torn.
fn record_and_image(state: &str) -> (String, String) {
    let record: Value = serde_json::from_str(&read(state, "active_policy.json").unwrap()).unwrap();
    let file = record["image_file"].as_str().unwrap();
    let image = std::fs::read(Path::new(state).join(file)).unwrap();
    assert_eq!(file, format!("active-{}.ppt", record["sha256"].as_str().unwrap()), "the record names the image of its own digest");
    (record["sha256"].as_str().unwrap().to_string(), prismpath_hotswap_rs::sha256_hex(&image))
}

fn swap_events(host: &PolicyHost, to_hash: &str) -> usize {
    host.history().iter().filter(|event| event["action"] == "swap" && event["data"]["to_hash"] == to_hash).count()
}

fn count(host: &PolicyHost, action: &str) -> usize {
    host.history().iter().filter(|event| event["action"] == action).count()
}

fn assert_clean_log(host: &PolicyHost, context: &str) {
    assert!(host.audit.verify_log() && host.audit.verify_persisted().unwrap(), "{context}: the log verifies and matches its file");
    assert_eq!(count(host, "active_unreadable"), 0, "{context}: a restarted host never fails closed here");
}

/// What the state directory holds right after a swap stopped before `step`.
fn assert_swap_left_behind(setup: &Setup, step: CommitStep) {
    let state = setup.state();
    let (v1, v2) = (setup.hash("v1"), setup.hash("v2"));
    assert_eq!(read(&state, "pending_swap").is_some(), step != CommitStep::Intent, "{step:?}: intent record");
    let floor_advanced = !matches!(step, CommitStep::Intent | CommitStep::Floor);
    assert_eq!(read(&state, "active_version").unwrap(), if floor_advanced { "2" } else { "1" }, "{step:?}: floor");
    let evidence_written = !matches!(step, CommitStep::Intent | CommitStep::Floor | CommitStep::Evidence);
    let log = read(&state, "swaps.log").unwrap();
    assert_eq!(log.contains(&format!("\"to_hash\": \"{v2}\"")), evidence_written, "{step:?}: audit event for the new policy");
    // the record is the flip point; the old image is never written over and only removed after it
    let (record_digest, image_digest) = record_and_image(&state);
    assert_eq!(record_digest, if step == CommitStep::Clear { v2.as_str() } else { v1.as_str() }, "{step:?}: the record");
    assert_eq!(image_digest, record_digest, "{step:?}: the record's image is there and is its image");
    let expected = match step {
        CommitStep::ActiveRecord => names(&[&v1, &v2]),
        CommitStep::Clear => names(&[&v2]),
        _ => names(&[&v1]),
    };
    assert_eq!(images(&state), expected, "{step:?}: image files");
    if let Some(pending) = read(&state, "pending_swap") {
        assert!(pending.contains(&v2) && !pending.contains("rollback"), "{step:?}: the intent record names the new image");
    }
}

/// A fresh host over what a stopped swap left, then what completes it.
fn assert_swap_recovery(setup: &Setup, step: CommitStep) {
    let (v1, v2) = (setup.hash("v1"), setup.hash("v2"));
    let intent_written = step != CommitStep::Intent;
    let fresh = setup.host();
    let restored = fresh.active_info()["active"].clone();
    assert_eq!(restored, if step == CommitStep::Clear { v2.as_str() } else { v1.as_str() }, "{step:?}: exactly one policy, the one the record names");
    assert_clean_log(&fresh, &format!("{step:?}"));
    assert_eq!(count(&fresh, "swap_incomplete"), usize::from(intent_written), "{step:?}: the interruption is recorded");
    if intent_written {
        let incomplete = fresh.history().into_iter().find(|event| event["action"] == "swap_incomplete").unwrap();
        assert_eq!(incomplete["data"]["to_hash"], v2.as_str());
        assert_eq!(incomplete["data"]["version"], 2);
        assert_eq!(incomplete["data"]["stored_version"], if matches!(step, CommitStep::Floor) { 1 } else { 2 });
    }

    if step == CommitStep::Clear {
        // the record had flipped: starting the host finished the commit, and the swap is already done
        assert!(read(&setup.state(), "pending_swap").is_none(), "the intent record is cleared at start");
        assert_eq!(images(&setup.state()), names(&[&v2]));
        let again = fresh.swap(&setup.pack("v2"), false).unwrap();
        assert_eq!(again["reasons"], serde_json::json!(["version:not-monotonic:2<=2"]), "the swap is not applied twice");
    } else {
        // a different image at the version the interrupted swap reached, or an older pack, stays refused
        if !matches!(step, CommitStep::Intent | CommitStep::Floor) {
            let other = fresh.swap(&setup.pack("v2b"), false).unwrap();
            assert_eq!(other["reasons"], serde_json::json!(["version:not-monotonic:2<=2"]), "{step:?}: another image at the floor version");
            let older = fresh.swap(&setup.pack("v1"), false).unwrap();
            assert_eq!(older["reasons"], serde_json::json!(["version:not-monotonic:1<=2"]), "{step:?}: an older version");
        }
        // the same swap completes
        let done = fresh.swap(&setup.pack("v2"), false).unwrap_or_else(|error| panic!("{step:?}: the retry failed: {error}"));
        assert_eq!(done["ok"], true, "{step:?}: {done}");
        assert_eq!(done["active"], v2.as_str());
        let evidence_before = matches!(step, CommitStep::ActiveImage | CommitStep::ActiveRecord);
        assert_eq!(swap_events(&fresh, &v2), 1 + usize::from(evidence_before), "{step:?}: accepted swap events for the new policy");
    }
    assert!(read(&setup.state(), "pending_swap").is_none(), "{step:?}: the intent record is cleared");
    assert_eq!(read(&setup.state(), "active_version").unwrap(), "2");
    assert_eq!(images(&setup.state()), names(&[&v2]), "{step:?}: exactly one image is left");
    let (record_digest, image_digest) = record_and_image(&setup.state());
    assert_eq!((record_digest.as_str(), image_digest.as_str()), (v2.as_str(), v2.as_str()));
    assert_clean_log(&fresh, &format!("{step:?} at the end"));
    // and a third host sees it
    assert_eq!(setup.host().active_info()["active"], v2.as_str());
}

/// A rollback stopped before `step`: v1 then v2 were swapped, the rollback targets v1.
fn assert_rollback_left_behind(setup: &Setup, step: CommitStep) {
    let state = setup.state();
    let (v1, v2) = (setup.hash("v1"), setup.hash("v2"));
    assert_eq!(read(&state, "pending_swap").is_some(), step != CommitStep::Intent, "{step:?}: intent record");
    if let Some(pending) = read(&state, "pending_swap") {
        assert!(pending.contains(&v1) && pending.contains("\"op\": \"rollback\""), "{step:?}: the intent names the rollback and its target: {pending}");
    }
    assert_eq!(read(&state, "active_version").unwrap(), "2", "{step:?}: a rollback never moves the floor");
    let evidence_written = matches!(step, CommitStep::ActiveImage | CommitStep::ActiveRecord | CommitStep::Clear);
    assert_eq!(count_in_file(&state, "\"action\": \"rollback\""), usize::from(evidence_written), "{step:?}: the rollback event");
    let (record_digest, image_digest) = record_and_image(&state);
    assert_eq!(record_digest, if step == CommitStep::Clear { v1.as_str() } else { v2.as_str() }, "{step:?}: the record");
    assert_eq!(image_digest, record_digest, "{step:?}: the record's image is there");
    let expected = match step {
        CommitStep::ActiveRecord => names(&[&v1, &v2]),
        CommitStep::Clear => names(&[&v1]),
        _ => names(&[&v2]),
    };
    assert_eq!(images(&state), expected, "{step:?}: image files");
}

fn count_in_file(state: &str, needle: &str) -> usize {
    read(state, "swaps.log").unwrap().matches(needle).count()
}

fn assert_rollback_recovery(setup: &Setup, step: CommitStep) {
    let (v1, v2) = (setup.hash("v1"), setup.hash("v2"));
    let fresh = setup.host();
    let flipped = step == CommitStep::Clear;
    assert_eq!(fresh.active_info()["active"], if flipped { v1.as_str() } else { v2.as_str() }, "{step:?}: exactly one policy, the one the record names");
    assert_clean_log(&fresh, &format!("{step:?}"));
    assert_eq!(count(&fresh, "rollback_incomplete"), usize::from(step != CommitStep::Intent), "{step:?}: the interruption is recorded");
    assert_eq!(count(&fresh, "swap_incomplete"), 0, "{step:?}: a rollback intent is not a swap");
    if flipped {
        assert!(read(&setup.state(), "pending_swap").is_none(), "{step:?}: starting the host finished the commit");
        assert_eq!(images(&setup.state()), names(&[&v1]));
    }
    // a restarted host has no previous policy to roll back to
    assert_eq!(fresh.rollback().unwrap()["reasons"], serde_json::json!(["rollback:no-previous"]));
    // the floor was not lowered by any of it: the old pack stays refused, a newer one commits
    let replay = fresh.swap(&setup.pack("v1"), false).unwrap();
    assert_eq!(replay["reasons"], serde_json::json!(["version:not-monotonic:1<=2"]), "{step:?}");
    assert_eq!(fresh.swap(&setup.pack("v3"), false).unwrap()["ok"], true, "{step:?}");
    assert_eq!(images(&setup.state()), names(&[&setup.hash("v3")]), "{step:?}: the next commit leaves one image");
    assert!(read(&setup.state(), "pending_swap").is_none());
    assert_clean_log(&fresh, &format!("{step:?} at the end"));
    assert_eq!(setup.host().active_info()["active"], setup.hash("v3").as_str());
}

fn expect_injected(result: Result<Value, HostError>, step: CommitStep) {
    match result {
        Err(HostError::Injected(name)) => assert_eq!(name, step.name()),
        other => panic!("expected an injected stop before {step:?}, got {other:?}"),
    }
}

const ROLLBACK_STEPS: [CommitStep; 5] =
    [CommitStep::Intent, CommitStep::Evidence, CommitStep::ActiveImage, CommitStep::ActiveRecord, CommitStep::Clear];

#[test]
fn a_stop_before_each_commit_step_keeps_the_previous_policy_and_recovery_completes_the_swap() {
    for step in CommitStep::ALL {
        let setup = Setup::new(&format!("hook_{}", step.name()));
        let (v1, v2) = (setup.hash("v1"), setup.hash("v2"));
        let host = setup.host();
        assert_eq!(host.swap(&setup.pack("v1"), false).unwrap()["ok"], true);
        host.set_commit_hook(Some(Box::new(move |reached| if reached == step { Err("stop".to_string()) } else { Ok(()) })));
        expect_injected(host.swap(&setup.pack("v2"), false), step);
        host.set_commit_hook(None);

        // in the process that was stopped: nothing flipped, except that a stop at the very last step is after the flip
        let in_memory = host.active_info();
        let expected = if step == CommitStep::Clear { v2.as_str() } else { v1.as_str() };
        assert_eq!(in_memory["active"], expected, "{step:?}: the active policy in the stopped process");

        assert_swap_left_behind(&setup, step);
        assert_swap_recovery(&setup, step);
    }
}

#[test]
fn a_stop_before_each_rollback_step_leaves_one_policy_and_the_floor_where_it_was() {
    for step in ROLLBACK_STEPS {
        let setup = Setup::new(&format!("rollback_hook_{}", step.name()));
        let (v1, v2) = (setup.hash("v1"), setup.hash("v2"));
        let host = setup.host();
        assert_eq!(host.swap(&setup.pack("v1"), false).unwrap()["ok"], true);
        assert_eq!(host.swap(&setup.pack("v2"), false).unwrap()["ok"], true);
        host.set_commit_hook(Some(Box::new(move |reached| if reached == step { Err("stop".to_string()) } else { Ok(()) })));
        expect_injected(host.rollback(), step);
        host.set_commit_hook(None);

        let in_memory = host.active_info();
        assert_eq!(in_memory["active"], if step == CommitStep::Clear { v1.as_str() } else { v2.as_str() }, "{step:?}: the active policy in the stopped process");
        assert_rollback_left_behind(&setup, step);
        if step != CommitStep::Clear {
            // the process is alive and nothing flipped, so the rollback is still there and completes
            assert_eq!(host.rollback().unwrap()["active"], v1.as_str(), "{step:?}: the rollback completes in the same process");
            assert_eq!(images(&setup.state()), names(&[&v1]), "{step:?}");
            assert_eq!(setup.host().active_info()["active"], v1.as_str());
            // and put it back for the restart half
            let again = Setup::new(&format!("rollback_hook_restart_{}", step.name()));
            let host = again.host();
            host.swap(&again.pack("v1"), false).unwrap();
            host.swap(&again.pack("v2"), false).unwrap();
            host.set_commit_hook(Some(Box::new(move |reached| if reached == step { Err("stop".to_string()) } else { Ok(()) })));
            expect_injected(host.rollback(), step);
            host.set_commit_hook(None);
            assert_rollback_recovery(&again, step);
        } else {
            assert_rollback_recovery(&setup, step);
        }
    }
}

#[test]
fn a_rollback_that_cannot_write_its_event_changes_nothing() {
    let setup = Setup::new("rollback_audit_failure");
    let (v1, v2) = (setup.hash("v1"), setup.hash("v2"));
    let host = setup.host();
    host.swap(&setup.pack("v1"), false).unwrap();
    host.swap(&setup.pack("v2"), false).unwrap();
    let state = setup.state();
    let record_before = read(&state, "active_policy.json").unwrap();
    let log = Path::new(&state).join("swaps.log");
    let aside = Path::new(&state).join("swaps.log.bak");
    std::fs::rename(&log, &aside).unwrap();
    std::fs::create_dir(&log).unwrap();
    match host.rollback() {
        Err(HostError::Audit(_)) => {}
        other => panic!("expected an AuditWriteError, got {other:?}"),
    }
    assert_eq!(host.active_info()["active"], v2.as_str(), "the previous policy stays active");
    assert_eq!(read(&state, "active_policy.json").unwrap(), record_before, "the record did not move");
    assert_eq!(images(&state), names(&[&v2]), "no image of the target was written");
    assert_eq!(read(&state, "active_version").unwrap(), "2");
    std::fs::remove_dir(&log).unwrap();
    std::fs::rename(&aside, &log).unwrap();
    assert_eq!(count(&host, "rollback"), 0, "no rollback event was recorded");
    assert_eq!(host.rollback().unwrap()["active"], v1.as_str(), "the rollback is still available and completes");
    assert_eq!(setup.host().active_info()["active"], v1.as_str());
    assert!(host.audit.verify_log() && host.audit.verify_persisted().unwrap());
}

/// The old layout: the image is `active.ppt` and the record has no `image_file`. It is read as it was and
/// the next swap or rollback moves it to the new layout.
#[test]
fn an_old_layout_state_directory_is_read_and_migrated() {
    for by in ["swap", "rollback"] {
        let setup = Setup::new(&format!("legacy_{by}"));
        let (v1, v2) = (setup.hash("v1"), setup.hash("v2"));
        let host = setup.host();
        host.swap(&setup.pack("v1"), false).unwrap();
        host.swap(&setup.pack("v2"), false).unwrap();
        drop(host);
        let state = setup.state();
        std::fs::rename(Path::new(&state).join(format!("active-{v2}.ppt")), Path::new(&state).join("active.ppt")).unwrap();
        let record = read(&state, "active_policy.json").unwrap().replace(&format!("\"image_file\": \"active-{v2}.ppt\", "), "");
        assert!(!record.contains("image_file"));
        std::fs::write(Path::new(&state).join("active_policy.json"), record).unwrap();

        let old = setup.host();
        assert_eq!(old.active_info()["active"], v2.as_str(), "the old layout is still restored");
        assert_clean_log(&old, by);
        if by == "swap" {
            assert_eq!(old.swap(&setup.pack("v3"), false).unwrap()["ok"], true);
            let v3 = setup.hash("v3");
            assert_eq!(images(&state), names(&[&v3]), "active.ppt is gone once the new layout's record is durable");
        } else {
            // a host that loaded the old layout has no previous policy, so swap first
            assert_eq!(old.rollback().unwrap()["reasons"], serde_json::json!(["rollback:no-previous"]));
            assert_eq!(old.swap(&setup.pack("v3"), false).unwrap()["ok"], true);
            assert_eq!(old.rollback().unwrap()["active"], v2.as_str());
            assert_eq!(images(&state), names(&[&v2]));
        }
        let (record_digest, image_digest) = record_and_image(&state);
        assert_eq!(record_digest, image_digest);
        assert_eq!(setup.host().active_info()["active"], record_digest.as_str());
        let _ = v1;
    }
}

/// The child half of the abort test: does nothing unless the parent asked it to crash.
#[test]
fn crash_child_process() {
    let (Ok(step), Ok(dir)) = (std::env::var("PP_CRASH_STEP"), std::env::var("PP_CRASH_DIR")) else { return };
    let step = CommitStep::from_name(&step).expect("a commit step name");
    let rollback = std::env::var("PP_CRASH_OP").is_ok_and(|op| op == "rollback");
    let doc = corpus();
    let dir = std::path::PathBuf::from(dir);
    let host = PolicyHost::new(
        dir.join("state").to_str().unwrap(),
        vec![dir.join("keys/authority.pub").to_str().unwrap().to_string()],
        doc["envelopes"]["default"].clone(),
        Vec::new(),
    )
    .unwrap();
    assert_eq!(host.swap(&pack_path(&dir, "v1"), false).unwrap()["ok"], true);
    if rollback {
        assert_eq!(host.swap(&pack_path(&dir, "v2"), false).unwrap()["ok"], true);
    }
    host.set_commit_hook(Some(Box::new(move |reached| {
        if reached == step {
            std::process::abort();
        }
        Ok(())
    })));
    let _ = if rollback { host.rollback() } else { host.swap(&pack_path(&dir, "v2"), false) };
    // reaching here means the hook never fired
    std::process::exit(3);
}

#[cfg(unix)]
fn run_child(setup: &Setup, step: CommitStep, op: &str) {
    use std::os::unix::process::ExitStatusExt;
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "crash_child_process", "--nocapture", "--test-threads=1"])
        .env("PP_CRASH_STEP", step.name())
        .env("PP_CRASH_OP", op)
        .env("PP_CRASH_DIR", &setup.dir)
        .status()
        .unwrap();
    assert_eq!(status.signal(), Some(6), "{step:?}: the child must die by abort, got {status:?}");
}

#[cfg(unix)]
#[test]
fn a_process_killed_before_each_commit_step_leaves_a_state_a_fresh_host_recovers() {
    for step in CommitStep::ALL {
        let setup = Setup::new(&format!("abort_{}", step.name()));
        run_child(&setup, step, "swap");
        assert_swap_left_behind(&setup, step);
        assert_swap_recovery(&setup, step);
    }
}

#[cfg(unix)]
#[test]
fn a_process_killed_before_each_rollback_step_leaves_a_state_a_fresh_host_recovers() {
    for step in ROLLBACK_STEPS {
        let setup = Setup::new(&format!("abort_rollback_{}", step.name()));
        run_child(&setup, step, "rollback");
        assert_rollback_left_behind(&setup, step);
        assert_rollback_recovery(&setup, step);
    }
}
