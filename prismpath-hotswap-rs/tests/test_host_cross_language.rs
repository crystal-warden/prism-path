// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! A Python host and a Rust host each open the other's state directory: the active policy it
//! restores, the audit log it reads (same leaves, same Merkle root, verified against the file), the
//! version floor it honours, and an interrupted commit it recovers. The Python half runs the reference
//! `PolicyHost` through `PRISMPATH_PYTHON`; see `common::python_for_cross_language` for when this skips
//! (CI sets `PRISMPATH_REQUIRE_CROSS_LANGUAGE`, so it cannot skip there).

mod common;

use common::{corpus, fresh_dir, pack_path, python_for_cross_language, stage};
use prismpath_hotswap_rs::host::{CommitStep, HostError, PolicyHost};
use serde_json::{json, Value};

/// Runs the operations on a Python `PolicyHost` over `state`, prints one JSON report.
const PYTHON_HOST: &str = r#"
import json, os, sys
sys.path.insert(0, os.environ["PP_REPO"])
from prismpath.hotswap import policy_host as ph
from prismpath import canon

state, packs, pub = os.environ["PP_STATE"], os.environ["PP_PACKS"], os.environ["PP_PUB"]
envelope = json.loads(os.environ["PP_ENVELOPE"])
host = ph.PolicyHost(state, [pub], envelope)
results = []
for op in json.loads(os.environ["PP_OPS"]):
    kind, _, arg = op.partition(":")
    if kind == "swap":
        results.append(host.swap(os.path.join(packs, arg + ".ppt")))
    elif kind == "swap_dies_before_evidence":
        real = host.audit.append
        def dying(actor, action, data):
            if action == "swap":
                raise RuntimeError("the process died here")
            return real(actor, action, data)
        host.audit.append = dying
        try:
            host.swap(os.path.join(packs, arg + ".ppt"))
            results.append({"died": False})
        except RuntimeError:
            results.append({"died": True})
        finally:
            host.audit.append = real
    elif kind in ("rollback_dies_before_record", "rollback_dies_before_clear"):
        # a process that died inside a rollback: before the record is written, or after it is
        saved = canon.atomic_write_bytes, host._clear_pending
        def dying(*args, **kwargs):
            raise RuntimeError("the process died here")
        if kind.endswith("record"):
            real_write = canon.atomic_write_bytes
            canon.atomic_write_bytes = lambda path, data, *a, **k: dying() if str(path).endswith("active_policy.json") else real_write(path, data, *a, **k)
        else:
            host._clear_pending = dying
        try:
            host.rollback()
            results.append({"died": False})
        except RuntimeError:
            results.append({"died": True})
        finally:
            canon.atomic_write_bytes, host._clear_pending = saved
    elif kind == "rollback":
        results.append(host.rollback())
    elif kind == "attest":
        results.append(host.attest())
print(json.dumps({
    "results": results, "active": host.active(), "root": host.audit.current_root(),
    "leaves": host.audit.leaves, "actions": [event["action"] for event in host.audit.events],
    "verify_log": host.audit.verify_log(), "verify_persisted": host.audit.verify_persisted(),
    "stored_floor": host._stored_version(), "pending": os.path.exists(host._pending_path()),
}))
"#;

struct Pair {
    python: String,
    doc: Value,
    dir: common::Scratch,
    pubs: Vec<String>,
}

impl Pair {
    fn new(tag: &str, what: &str) -> Option<Pair> {
        let repo = format!("{}/..", env!("CARGO_MANIFEST_DIR"));
        let python = python_for_cross_language(&repo, what)?;
        let doc = corpus();
        let dir = fresh_dir(tag);
        let pubs = stage(&doc, &dir);
        Some(Pair { python, doc, dir, pubs })
    }

    fn state(&self) -> String {
        self.dir.join("state").to_str().unwrap().to_string()
    }

    fn envelope(&self, which: &str) -> Value {
        self.doc["envelopes"][which].clone()
    }

    fn rust_host(&self, which: &str) -> PolicyHost {
        PolicyHost::new(&self.state(), self.pubs.clone(), self.envelope(which), Vec::new()).unwrap()
    }

    fn hash(&self, pack: &str) -> String {
        self.doc["packs"][pack]["manifest"]["image_sha256"].as_str().unwrap().to_string()
    }

    fn pack(&self, pack: &str) -> String {
        pack_path(&self.dir, pack)
    }

    fn python_host(&self, which: &str, ops: &[&str]) -> Value {
        let repo = format!("{}/..", env!("CARGO_MANIFEST_DIR"));
        let out = std::process::Command::new(&self.python)
            .arg("-c")
            .arg(PYTHON_HOST)
            .env("PP_REPO", repo)
            .env("PP_STATE", self.state())
            .env("PP_PACKS", self.dir.join("packs"))
            .env("PP_PUB", &self.pubs[0])
            .env("PP_ENVELOPE", self.envelope(which).to_string())
            .env("PP_OPS", json!(ops).to_string())
            .output()
            .expect("run python");
        let stdout = String::from_utf8_lossy(&out.stdout);
        serde_json::from_str(stdout.trim())
            .unwrap_or_else(|_| panic!("the Python host failed: {stdout} / {}", String::from_utf8_lossy(&out.stderr)))
    }
}

/// What the Rust host sees, in the shape the Python report has.
fn rust_report(host: &PolicyHost) -> Value {
    json!({
        "active": host.active_info(), "root": host.audit.current_root(), "leaves": host.audit.leaves(),
        "actions": host.history().iter().map(|event| event["action"].clone()).collect::<Vec<_>>(),
        "verify_log": host.audit.verify_log(), "verify_persisted": host.audit.verify_persisted().unwrap(),
    })
}

fn assert_same_log(python: &Value, rust: &Value, context: &str) {
    for key in ["root", "leaves", "actions", "verify_log", "verify_persisted"] {
        assert_eq!(python[key], rust[key], "{context}: {key}");
    }
    assert_eq!(python["verify_log"], true, "{context}");
    assert_eq!(python["verify_persisted"], true, "{context}");
}

#[test]
fn a_python_host_and_a_rust_host_each_open_the_others_state_directory() {
    let Some(pair) = Pair::new("xlang_state", "the Python and Rust hosts opening each other's state directory") else { return };

    // Python swaps three packs (the last an overlay); Rust opens what it left
    let python = pair.python_host("default", &["swap:v1", "swap:v2", "swap:v4_overlay", "attest"]);
    assert!(python["results"].as_array().unwrap().iter().all(|result| result["ok"] != false), "{python}");
    let rust = pair.rust_host("default");
    assert_eq!(rust.active_info()["active"], pair.hash("v4_overlay").as_str(), "Rust restores the policy Python committed");
    assert_eq!(rust.active_info()["version"], 4);
    assert_eq!(rust.active_info()["overlay_of"], "baseline-2026-07", "the overlay rides the record");
    assert_same_log(&python, &rust_report(&rust), "Rust reading Python's log");

    // the floor Python persisted binds Rust, and Rust's own accepted swap advances it
    let replay = rust.swap(&pair.pack("v2"), false).unwrap();
    assert_eq!(replay["reasons"], json!(["version:not-monotonic:2<=4"]));
    assert_eq!(rust.swap(&pair.pack("v5"), false).unwrap()["ok"], true);
    assert_eq!(rust.rollback().unwrap()["active"], pair.hash("v4_overlay").as_str());
    rust.attest().unwrap();
    let rust_after = rust_report(&rust);
    assert!(rust_after["verify_log"] == true && rust_after["verify_persisted"] == true);

    // Python opens what Rust left: the rolled back policy is the active one, the log is the same log
    let python = pair.python_host("default", &[]);
    assert_eq!(python["active"]["active"], pair.hash("v4_overlay"), "Python restores the policy Rust committed");
    assert_eq!(python["active"]["overlay_of"], "baseline-2026-07");
    assert_eq!(python["stored_floor"], 5, "the floor Rust persisted");
    assert_same_log(&python, &rust_after, "Python reading Rust's log");
    assert!(python["actions"].as_array().unwrap().iter().any(|action| action == "rollback"));

    // and a swap in Python at the Rust floor, then Rust again
    let python = pair.python_host("default", &["swap:v6"]);
    assert_eq!(python["results"][0]["ok"], true, "{python}");
    let rust = pair.rust_host("default");
    assert_eq!(rust.active_info()["active"], pair.hash("v6").as_str());
    assert_same_log(&python, &rust_report(&rust), "Rust reading the log after Python's swap");
    eprintln!("cross-language host: each runtime restored the other's active policy, floor and log (root {})", &python["root"].as_str().unwrap()[..12]);
}

#[test]
fn an_interrupted_commit_is_recovered_by_the_other_runtime() {
    let Some(pair) = Pair::new("xlang_crash", "the Python and Rust hosts recovering each other's interrupted commit") else { return };

    // Rust stops before the evidence; Python opens, records the interruption and completes the swap
    let rust = pair.rust_host("default");
    assert_eq!(rust.swap(&pair.pack("v1"), false).unwrap()["ok"], true);
    rust.set_commit_hook(Some(Box::new(|step| if step == CommitStep::Evidence { Err("stop".into()) } else { Ok(()) })));
    assert!(matches!(rust.swap(&pair.pack("v2"), false), Err(HostError::Injected(_))));
    drop(rust);
    let python = pair.python_host("default", &["swap:v2b", "swap:v2"]);
    assert_eq!(python["results"][0]["ok"], false, "another image at the floor version stays refused: {python}");
    assert_eq!(python["results"][1]["ok"], true, "the interrupted swap completes in Python: {python}");
    assert_eq!(python["pending"], false);
    let actions: Vec<&str> = python["actions"].as_array().unwrap().iter().map(|action| action.as_str().unwrap()).filter(|action| *action != "legacy_form").collect();
    assert_eq!(actions, ["swap", "swap_incomplete", "swap_rejected", "swap"], "{python}");
    let rust = pair.rust_host("default");
    assert_eq!(rust.active_info()["active"], pair.hash("v2").as_str());
    assert_same_log(&python, &rust_report(&rust), "after Python recovered Rust's commit");

    // Python stops before the evidence; Rust opens, records the interruption and completes the swap
    let python = pair.python_host("default", &["swap_dies_before_evidence:v3"]);
    assert_eq!(python["results"][0]["died"], true, "{python}");
    assert_eq!(python["pending"], true);
    assert_eq!(python["stored_floor"], 3);
    let rust = pair.rust_host("default");
    assert_eq!(rust.active_info()["active"], pair.hash("v2").as_str(), "the previous policy stays active");
    assert_eq!(rust.history().last().unwrap()["action"], "swap_incomplete");
    assert_eq!(rust.history().last().unwrap()["data"]["version"], 3);
    assert_eq!(rust.swap(&pair.pack("v3"), false).unwrap()["ok"], true);
    let python = pair.python_host("default", &[]);
    assert_eq!(python["active"]["active"], pair.hash("v3"));
    assert_eq!(python["pending"], false);
    assert_same_log(&python, &rust_report(&rust), "after Rust recovered Python's commit");
    eprintln!("cross-language host: each runtime recovered the other's interrupted commit");
}

fn images(pair: &Pair) -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(pair.state())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("active") && name.ends_with(".ppt"))
        .collect();
    out.sort();
    out
}

#[test]
fn a_rollback_that_dies_in_one_runtime_is_recovered_by_the_other() {
    let what = "the Python and Rust hosts recovering each other's interrupted rollback";
    let stop_at = |step: CommitStep| -> prismpath_hotswap_rs::host::CommitHook {
        Box::new(move |reached| if reached == step { Err("stop".into()) } else { Ok(()) })
    };

    // Rust dies before the record of a rollback: the image of the target sits beside the one in use
    let Some(pair) = Pair::new("xlang_rollback_rust_record", what) else { return };
    let rust = pair.rust_host("default");
    rust.swap(&pair.pack("v1"), false).unwrap();
    rust.swap(&pair.pack("v2"), false).unwrap();
    rust.set_commit_hook(Some(stop_at(CommitStep::ActiveRecord)));
    assert!(matches!(rust.rollback(), Err(HostError::Injected(_))));
    drop(rust);
    assert_eq!(images(&pair).len(), 2, "the target's image was written beside the one in use");
    let python = pair.python_host("default", &["swap:v3"]);
    assert_eq!(python["results"][0]["ok"], true, "{python}");
    assert_eq!(python["active"]["active"], pair.hash("v3"));
    let actions: Vec<&str> = python["actions"].as_array().unwrap().iter().map(|action| action.as_str().unwrap()).filter(|action| *action != "legacy_form").collect();
    assert_eq!(actions, ["swap", "swap", "rollback", "rollback_incomplete", "swap"], "{python}");
    assert_eq!(python["stored_floor"], 3);
    assert_eq!(images(&pair), vec![format!("active-{}.ppt", pair.hash("v3"))], "the next commit removed the strays");
    assert_same_log(&python, &rust_report(&pair.rust_host("default")), "Rust reading the log after Python finished over Rust's dead rollback");

    // Python dies before the record of a rollback; Rust opens, still sees the policy the record names and carries on
    let Some(pair) = Pair::new("xlang_rollback_python_record", what) else { return };
    let python = pair.python_host("default", &["swap:v1", "swap:v2", "rollback_dies_before_record"]);
    assert_eq!(python["results"][2]["died"], true, "{python}");
    assert_eq!(python["pending"], true);
    let rust = pair.rust_host("default");
    assert_eq!(rust.active_info()["active"], pair.hash("v2").as_str(), "the record still names the policy in use");
    assert_eq!(rust.history().last().unwrap()["action"], "rollback_incomplete");
    assert_eq!(rust.swap(&pair.pack("v3"), false).unwrap()["ok"], true);
    assert_eq!(images(&pair), vec![format!("active-{}.ppt", pair.hash("v3"))]);
    let python = pair.python_host("default", &[]);
    assert_eq!(python["active"]["active"], pair.hash("v3"));
    assert_eq!(python["pending"], false);
    assert_same_log(&python, &rust_report(&rust), "Python reading the log after Rust finished over Python's dead rollback");

    // Rust dies after the record of a rollback, before its clean up: Python finishes it at start
    let Some(pair) = Pair::new("xlang_rollback_rust_clear", what) else { return };
    let rust = pair.rust_host("default");
    rust.swap(&pair.pack("v1"), false).unwrap();
    rust.swap(&pair.pack("v2"), false).unwrap();
    rust.set_commit_hook(Some(stop_at(CommitStep::Clear)));
    assert!(matches!(rust.rollback(), Err(HostError::Injected(_))));
    drop(rust);
    let python = pair.python_host("default", &[]);
    assert_eq!(python["active"]["active"], pair.hash("v1"), "the rollback is what Python restores");
    assert_eq!(python["pending"], false, "Python finished the commit Rust left");
    assert_eq!(images(&pair), vec![format!("active-{}.ppt", pair.hash("v1"))]);
    assert_same_log(&python, &rust_report(&pair.rust_host("default")), "after Python finished Rust's rollback");

    // Python dies after the record of a rollback; Rust finishes it at start
    let Some(pair) = Pair::new("xlang_rollback_python_clear", what) else { return };
    let python = pair.python_host("default", &["swap:v1", "swap:v2", "rollback_dies_before_clear"]);
    assert_eq!(python["results"][2]["died"], true, "{python}");
    assert_eq!(python["pending"], true);
    let rust = pair.rust_host("default");
    assert_eq!(rust.active_info()["active"], pair.hash("v1").as_str(), "the rollback is what Rust restores");
    assert!(!std::path::Path::new(&format!("{}/pending_swap", pair.state())).exists(), "Rust finished the commit Python left");
    assert_eq!(images(&pair), vec![format!("active-{}.ppt", pair.hash("v1"))]);
    assert_same_log(&pair.python_host("default", &[]), &rust_report(&rust), "after Rust finished Python's rollback");
    eprintln!("cross-language host: each runtime recovered the other's interrupted rollback");
}

#[test]
fn a_log_with_non_ascii_text_has_the_same_bytes_and_root_in_both_runtimes() {
    let Some(pair) = Pair::new("xlang_unicode", "the Python and Rust hosts agreeing on a log with non ASCII text") else { return };
    let rust = pair.rust_host("unicode");
    assert_eq!(rust.swap(&pair.pack("unicode_v1"), false).unwrap()["ok"], true);
    rust.attest().unwrap();
    let python = pair.python_host("unicode", &["attest"]);
    assert_same_log(&python, &rust_report(&pair.rust_host("unicode")), "a non ASCII envelope id");
    let log = std::fs::read_to_string(format!("{}/swaps.log", pair.state())).unwrap();
    assert!(!log.is_ascii(), "the log is canon/2, which writes text as raw UTF-8");
    assert!(log.contains("env-\u{e9}\u{2603}\u{1f600}"));
    eprintln!("cross-language host: non ASCII log identical in both runtimes");
}
