// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! Shared by the host trace, crash injection and cross language tests: the corpus, the packs it
//! carries staged on disk, and the counter clock the corpus timestamps come from.
#![allow(dead_code)]

use base64::Engine;
use prismpath_hotswap_rs::host::{iso_from_epoch, Clock};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub fn corpus() -> Value {
    let path = format!("{}/tests/fixtures/host_trace.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).expect("read host_trace.json")).expect("parse host_trace.json")
}

/// A scratch directory that removes itself when it goes out of scope, a failed assertion included, so a test
/// run leaves nothing in the temporary directory. It reads as the path it holds.
pub struct Scratch(PathBuf);

impl Scratch {
    /// A new empty directory `<temp>/pp_<tag>_<process>_<n>`, the number telling apart two made under one tag.
    pub fn new(tag: &str) -> Scratch {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!("pp_{tag}_{}_{}", std::process::id(), NEXT.fetch_add(1, Ordering::SeqCst)));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl std::ops::Deref for Scratch {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for Scratch {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<std::ffi::OsStr> for Scratch {
    fn as_ref(&self) -> &std::ffi::OsStr {
        self.0.as_os_str()
    }
}

pub fn fresh_dir(tag: &str) -> Scratch {
    Scratch::new(&format!("host_{tag}"))
}

/// The clock the corpus was generated under: the Nth epoch read (microseconds) is `base + step * N`, the Nth ISO read
/// is `base_iso + N` seconds.
pub fn counter_clock(doc: &Value) -> Clock {
    let base = doc["clock"]["base_epoch_us"].as_i64().unwrap();
    let step = doc["clock"]["epoch_step_us"].as_i64().unwrap();
    let base_iso = doc["clock"]["base_iso"].as_u64().unwrap();
    let epoch_calls = Arc::new(AtomicU64::new(0));
    let iso_calls = Arc::new(AtomicU64::new(0));
    Clock::new(
        move || base + step * epoch_calls.fetch_add(1, Ordering::SeqCst) as i64,
        move || iso_from_epoch(base_iso + iso_calls.fetch_add(1, Ordering::SeqCst)),
    )
}

/// A manifest as a writer puts it on disk: its canonical canon/2 bytes and a line feed, which is all the
/// strict reader accepts; a manifest canon/2 cannot write (a float) as the compact JSON a careless writer
/// would produce, which the reader refuses before its signature is looked at.
#[allow(dead_code)]
pub fn manifest_file(manifest: &Value) -> Vec<u8> {
    match prismpath_rs::canon2::write_json(manifest) {
        Ok(mut bytes) => {
            bytes.push(b'\n');
            bytes
        }
        Err(_) => {
            let mut bytes = serde_json::to_vec(manifest).unwrap();
            bytes.push(b'\n');
            bytes
        }
    }
}

/// Write every pack of the corpus under `dir/packs` (`<name>.ppt` and its manifest, signature and
/// sidecar where it has them) and the authority's public key under `dir/keys`; returns the key paths.
pub fn stage(doc: &Value, dir: &Path) -> Vec<String> {
    let packs_dir = dir.join("packs");
    std::fs::create_dir_all(&packs_dir).unwrap();
    for (name, pack) in doc["packs"].as_object().unwrap() {
        if pack.get("absent").is_some() {
            continue;
        }
        let base = packs_dir.join(format!("{name}.ppt"));
        let b64 = base64::engine::general_purpose::STANDARD;
        std::fs::write(&base, b64.decode(pack["image_b64"].as_str().unwrap()).unwrap()).unwrap();
        if !pack["manifest"].is_null() {
            std::fs::write(format!("{}.manifest.json", base.display()), manifest_file(&pack["manifest"])).unwrap();
            std::fs::write(format!("{}.manifest.sig", base.display()), hex::decode(pack["sig_hex"].as_str().unwrap()).unwrap()).unwrap();
        }
    }
    let keys = dir.join("keys");
    std::fs::create_dir_all(&keys).unwrap();
    let pub_path = keys.join("authority.pub");
    std::fs::write(&pub_path, hex::decode(doc["authority_pub_hex"].as_str().unwrap()).unwrap()).unwrap();
    vec![pub_path.to_str().unwrap().to_string()]
}

pub fn pack_path(dir: &Path, name: &str) -> String {
    dir.join("packs").join(format!("{name}.ppt")).to_str().unwrap().to_string()
}

/// The interpreter for the cross language legs: `PRISMPATH_PYTHON` when set, else the repository's
/// `.venv`. `PRISMPATH_REQUIRE_CROSS_LANGUAGE` (any non empty value) is what CI sets: with it, a
/// missing interpreter fails the test, because a leg that cannot run proves nothing. Without it a
/// developer machine with no Python skips with a message that says exactly what was skipped.
pub fn python_for_cross_language(repo: &str, what: &str) -> Option<String> {
    let required = std::env::var("PRISMPATH_REQUIRE_CROSS_LANGUAGE").is_ok_and(|value| !value.is_empty());
    let configured = std::env::var("PRISMPATH_PYTHON").ok().filter(|value| !value.is_empty());
    let python = configured.clone().unwrap_or_else(|| format!("{repo}/.venv/bin/python"));
    let found = if configured.is_some() {
        std::process::Command::new(&python).arg("--version").output().is_ok_and(|out| out.status.success())
    } else {
        std::path::Path::new(&python).exists()
    };
    if found {
        return Some(python);
    }
    assert!(
        !required,
        "PRISMPATH_REQUIRE_CROSS_LANGUAGE is set but no Python was found ({python}); set PRISMPATH_PYTHON to an interpreter that can import prismpath and cryptography"
    );
    eprintln!(
        "SKIPPED (not run): {what} needs Python; set PRISMPATH_PYTHON (or make {repo}/.venv) to run it. CI sets PRISMPATH_REQUIRE_CROSS_LANGUAGE so it cannot skip there."
    );
    None
}
