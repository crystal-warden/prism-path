// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! PolicyHost + AuditLog — the Attested + Audited-and-atomic half (policy_host.py / audit_log.py).
//!
//! The audit log is append-only JSONL whose leaves are sha256 over each event's canonical form
//! (Python's compact `sort_keys` bytes — same `py_canonical_string`), rolled into a Bitcoin-style
//! Merkle root (duplicate-last-if-odd), so a log written by either runtime verifies on the other.
//! Anti-rollback is the same fsync'd `active_version` file floor (software tier: tamper-EVIDENT
//! through the ledger, not tamper-proof — the eFUSE counter is the hardware follow-on).

use crate::{check_envelope, read_ppt_header, sha256_hex, validate_image, verify_pack};
use prismpath_rs::durable::py_canonical_string;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Write;

// -------------------------------------------------------------------- Merkle (ledger_ots.py)

fn h(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

/// Bitcoin-style Merkle root over hex leaves (duplicate last if odd). None for an empty list.
pub fn merkle_root(leaves_hex: &[String]) -> Option<String> {
    if leaves_hex.is_empty() {
        return None;
    }
    let mut layer: Vec<Vec<u8>> =
        leaves_hex.iter().map(|s| hex::decode(s).unwrap_or_default()).collect();
    while layer.len() > 1 {
        if layer.len() % 2 == 1 {
            layer.push(layer.last().expect("non-empty").clone());
        }
        layer = layer.chunks(2).map(|p| h(&[p[0].as_slice(), p[1].as_slice()].concat())).collect();
    }
    Some(hex::encode(&layer[0]))
}

// ------------------------------------------------------------------------------ AuditLog

/// Append-only JSONL audit log with Merkle-leaf commitment per event.
pub struct AuditLog {
    pub path: String,
    pub events: Vec<Value>,
    pub leaves: Vec<String>,
}

fn leaf_hex(ev: &Value) -> String {
    hex::encode(Sha256::digest(py_canonical_string(ev, false).as_bytes()))
}

impl AuditLog {
    pub fn open(path: &str) -> AuditLog {
        let mut log = AuditLog { path: path.to_string(), events: Vec::new(), leaves: Vec::new() };
        if let Ok(text) = std::fs::read_to_string(path) {
            for line in text.lines().filter(|l| !l.trim().is_empty()) {
                if let Ok(ev) = serde_json::from_str::<Value>(line) {
                    log.leaves.push(leaf_hex(&ev));
                    log.events.push(ev);
                }
            }
        }
        log
    }

    pub fn append(&mut self, actor: &str, action: &str, data: Value) -> Value {
        let idx = self.events.len();
        let ev = json!({
            "idx": idx, "id": idx.to_string(), "ts": now_epoch(),
            "actor": actor, "action": action, "data": data,
        });
        self.leaves.push(leaf_hex(&ev));
        self.events.push(ev.clone());
        if !self.path.is_empty() {
            if let Some(dir) = std::path::Path::new(&self.path).parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            if let Ok(mut f) =
                std::fs::OpenOptions::new().create(true).append(true).open(&self.path)
            {
                let _ = writeln!(f, "{ev}");
            }
        }
        ev
    }

    pub fn current_root(&self) -> String {
        merkle_root(&self.leaves).unwrap_or_default()
    }

    /// Structural integrity: recompute every leaf from its event and re-derive the root.
    pub fn verify_log(&self) -> bool {
        if self.leaves.len() != self.events.len() {
            return false;
        }
        self.events.iter().zip(&self.leaves).all(|(ev, leaf)| leaf_hex(ev) == *leaf)
            && merkle_root(&self.leaves).is_some() == !self.leaves.is_empty()
    }
}

fn now_epoch() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn now_iso() -> String {
    // ISO-8601 UTC to the second, matching Python's isoformat(timespec="seconds") + "+00:00".
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86_400;
    let (h, m, s) = ((secs % 86_400) / 3600, (secs % 3600) / 60, secs % 60);
    // civil date from days-since-epoch (Howard Hinnant's algorithm)
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mth = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mth <= 2 { y + 1 } else { y };
    format!("{y:04}-{mth:02}-{d:02}T{h:02}:{m:02}:{s:02}+00:00")
}

// ---------------------------------------------------------------------------- PolicyHost

#[derive(Debug, Clone)]
pub struct ActivePolicy {
    pub sha256: String,
    pub version: Option<i64>,
    pub key_id: Option<String>,
    pub envelope_id: Option<String>,
    pub unsigned: bool,
    pub image: Vec<u8>,
    pub since: String,
}

/// Holds the single active policy; `swap` runs signature -> envelope -> monotonic-version ->
/// shadow-stage -> single atomic reference flip, auditing every attempt.
pub struct PolicyHost {
    pub state_dir: String,
    pub pubkey_paths: Vec<String>,
    pub envelope: Value,
    pub revoked: Vec<String>,
    pub audit: AuditLog,
    active: Option<ActivePolicy>,
    prev: Option<ActivePolicy>,
    version_path: String,
}

impl PolicyHost {
    pub fn new(
        state_dir: &str,
        pubkey_paths: Vec<String>,
        envelope: Value,
        revoked: Vec<String>,
    ) -> PolicyHost {
        let _ = std::fs::create_dir_all(state_dir);
        PolicyHost {
            state_dir: state_dir.to_string(),
            pubkey_paths,
            envelope,
            revoked,
            audit: AuditLog::open(&format!("{state_dir}/swaps.log")),
            active: None,
            prev: None,
            version_path: format!("{state_dir}/active_version"),
        }
    }

    fn stored_version(&self) -> i64 {
        std::fs::read_to_string(&self.version_path)
            .ok()
            .and_then(|t| t.trim().parse().ok())
            .unwrap_or(0)
    }

    fn persist_version(&self, version: i64) {
        let tmp = format!("{}.tmp", self.version_path);
        if let Ok(mut f) = std::fs::File::create(&tmp) {
            let _ = f.write_all(version.to_string().as_bytes());
            let _ = f.sync_all();
        }
        let _ = std::fs::rename(&tmp, &self.version_path);
    }

    fn reject(&mut self, to_hash: Option<&str>, version: Option<i64>, reasons: Vec<String>) -> Value {
        self.audit.append(
            "policy_host",
            "swap_rejected",
            json!({
                "from_hash": self.active.as_ref().map(|a| a.sha256.clone()),
                "to_hash": to_hash, "version": version, "reasons": reasons,
                "result": "rejected",
            }),
        );
        json!({"ok": false, "reasons": reasons})
    }

    /// Verify -> envelope -> version -> stage -> atomic flip. The active policy only changes on
    /// full success; every outcome is one audit event.
    pub fn swap(&mut self, ppt_path: &str, allow_unsigned: bool) -> Value {
        let image = match std::fs::read(ppt_path) {
            Ok(i) => i,
            Err(e) => {
                let code = e.raw_os_error().unwrap_or(0);
                return self.reject(None, None, vec![format!("image:unreadable:{code}")]);
            }
        };
        let to_hash = sha256_hex(&image);

        let manifest: Value = if allow_unsigned {
            let caps: Option<BTreeMap<String, u64>> =
                self.envelope.get("caps").and_then(|c| c.as_object()).map(|o| {
                    o.iter().filter_map(|(k, v)| v.as_u64().map(|n| (k.clone(), n))).collect()
                });
            let (ok, reasons) = validate_image(&image, caps.as_ref());
            if !ok {
                return self.reject(Some(&to_hash), None, reasons);
            }
            json!({"image_sha256": to_hash, "version": null, "key_id": null,
                   "envelope_id": self.envelope.get("envelope_id"), "unsigned": true})
        } else {
            let (ok, reasons, manifest) = verify_pack(ppt_path, &self.pubkey_paths, &self.revoked);
            if !ok {
                return self.reject(Some(&to_hash), None, reasons);
            }
            let manifest = manifest.expect("ok verify has a manifest");
            let (ok, reasons) = check_envelope(&manifest, &image, &self.envelope);
            if !ok {
                let v = manifest.get("version").and_then(|v| v.as_i64());
                return self.reject(Some(&to_hash), v, reasons);
            }
            let version = manifest.get("version").and_then(|v| v.as_i64()).unwrap_or(0);
            let floor = self.stored_version();
            if version <= floor {
                return self.reject(
                    Some(&to_hash),
                    Some(version),
                    vec![format!("version:not-monotonic:{version}<={floor}")],
                );
            }
            manifest
        };

        // stage a shadow: fully parse before any flip
        if let Err(e) = read_ppt_header(&image) {
            let v = manifest.get("version").and_then(|v| v.as_i64());
            return self.reject(Some(&to_hash), v, vec![e]);
        }

        // atomic flip
        let new_active = ActivePolicy {
            sha256: to_hash.clone(),
            version: manifest.get("version").and_then(|v| v.as_i64()),
            key_id: manifest.get("key_id").and_then(|k| k.as_str()).map(|s| s.to_string()),
            envelope_id: manifest.get("envelope_id").and_then(|e| e.as_str()).map(|s| s.to_string()),
            unsigned: manifest.get("unsigned").and_then(|u| u.as_bool()).unwrap_or(false),
            image,
            since: now_iso(),
        };
        self.prev = self.active.replace(new_active);
        if let Some(v) = manifest.get("version").and_then(|v| v.as_i64()) {
            self.persist_version(v);
        }

        self.audit.append(
            "policy_host",
            "swap",
            json!({
                "from_hash": self.prev.as_ref().map(|p| p.sha256.clone()),
                "to_hash": to_hash,
                "version": manifest.get("version"),
                "key_id": manifest.get("key_id"),
                "envelope_id": manifest.get("envelope_id"),
                "unsigned": manifest.get("unsigned").and_then(|u| u.as_bool()).unwrap_or(false),
                "result": "accepted",
            }),
        );
        let mut out = self.active_info();
        out["ok"] = Value::Bool(true);
        out
    }

    pub fn active_info(&self) -> Value {
        match &self.active {
            None => json!({"active": null}),
            Some(a) => json!({
                "active": a.sha256, "version": a.version, "since": a.since,
                "unsigned": a.unsigned, "envelope_id": a.envelope_id,
            }),
        }
    }

    /// Restore the last-known-good policy (one deep); the version floor is NOT lowered.
    pub fn rollback(&mut self) -> Value {
        match self.prev.take() {
            None => json!({"ok": false, "reasons": ["rollback:no-previous"]}),
            Some(prev) => {
                self.active = Some(prev);
                let a = self.active.as_ref().expect("just set");
                self.audit.append(
                    "policy_host",
                    "rollback",
                    json!({"to_hash": a.sha256, "version": a.version, "result": "rolled_back"}),
                );
                let mut out = self.active_info();
                out["ok"] = Value::Bool(true);
                out
            }
        }
    }

    /// Append a point-in-time attestation of the active policy to the ledger.
    pub fn attest(&mut self) -> Value {
        let a = self.active_info();
        self.audit.append(
            "policy_host",
            "attestation",
            json!({"active": a.get("active"), "version": a.get("version"), "ts": now_iso()}),
        );
        a
    }
}
