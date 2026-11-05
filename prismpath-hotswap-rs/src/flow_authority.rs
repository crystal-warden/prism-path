// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! Flow manifests, verified: the policy authority's signature on an ordinary Markdown flow, as
//! `prismpath/hotswap/flow_authority.py` defines them. A manifest is a detached JSON document beside
//! the flow (`flow.md.manifest.json`) with its Ed25519 signature (`flow.md.manifest.sig`), the same
//! two file shape a pack manifest has:
//!
//! ```text
//! {"format": "prismpath-flow-manifest/1", "flow": "<name>", "flow_sha256": "<sha256 of the flow>",
//!  "version": 3, "fields": {...}, "key_id": "<sha256 of the authority public key>", "created": "..."}
//! ```
//!
//! The signature covers the canonical compact JSON of the manifest (the bytes a pack manifest's
//! covers; the `format` field keeps the two apart). The flow's hash is the SHA-256 of its UTF-8 text
//! with line endings read as LF, so a checkout that turns LF into CRLF does not unauthorize a flow
//! and a change to any character does.
//!
//! Verify only: this crate holds no signing path for flow manifests. Refusals are the registry
//! causes (`prismpath/kernel/causes.py`), in the order a reader would ask: `sig:missing`,
//! `manifest:bad-format`, `sig:invalid`, `sig:revoked-key`, `manifest:key-id-mismatch`,
//! `flow:sha256-mismatch` (87), `flow:version-replay` (88).
//!
//! The authority key is the one `swap keygen` writes. The instance key that signs root statements
//! must never authorize a flow; `verify_flow` cannot tell the two apart by itself, so a host calls
//! `root_statement::check_separation` first, as the Python `run` does.

use crate::pyval::{py_int, py_str, universal_newlines};
use crate::{canonical_bytes, sha256_hex, verify_ed25519};
use serde_json::{json, Map, Value};

pub const FLOW_MANIFEST_FORMAT: &str = "prismpath-flow-manifest/1";
pub const UNAUTHORIZED: &str = "unauthorized";

pub const SIG_MISSING: &str = "sig:missing";
pub const SIG_INVALID: &str = "sig:invalid";
pub const SIG_REVOKED_KEY: &str = "sig:revoked-key";
pub const MANIFEST_KEY_ID_MISMATCH: &str = "manifest:key-id-mismatch";
pub const MANIFEST_BAD_FORMAT: &str = "manifest:bad-format";
pub const FLOW_SHA256_MISMATCH: &str = "flow:sha256-mismatch";
pub const FLOW_VERSION_REPLAY: &str = "flow:version-replay";

/// SHA-256 of the flow document's UTF-8 text with line endings read as LF. `None` when the bytes
/// are not UTF-8 (the reference cannot read such a flow either).
pub fn flow_sha256(flow: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(flow).ok()?;
    Some(sha256_hex(universal_newlines(text).as_bytes()))
}

/// The manifest's content address: SHA-256 of the canonical bytes its signature covers.
pub fn manifest_sha256(manifest: &Value) -> String {
    sha256_hex(&canonical_bytes(manifest))
}

/// What a root statement and a receipt record as the authorization in force: the manifest hash, the
/// authority key id and the version when it verified, and `"unauthorized"` otherwise.
pub fn authorization_of(manifest: Option<&Value>, ok: bool) -> Value {
    match manifest {
        Some(manifest) if ok => json!({
            "manifest_sha256": manifest_sha256(manifest),
            "key_id": manifest["key_id"],
            "version": manifest["version"],
        }),
        _ => json!(UNAUTHORIZED),
    }
}

/// The result of `verify_flow`.
#[derive(Debug, Clone, PartialEq)]
pub struct FlowVerdict {
    pub ok: bool,
    /// Empty when ok, otherwise exactly one registry cause.
    pub causes: Vec<String>,
    /// The manifest as read, when it was a JSON object (it is returned on most refusals too).
    pub manifest: Option<Value>,
}

impl FlowVerdict {
    fn refuse(cause: &str, manifest: Option<Value>) -> FlowVerdict {
        FlowVerdict { ok: false, causes: vec![cause.to_string()], manifest }
    }

    pub fn authorization(&self) -> Value {
        authorization_of(self.manifest.as_ref(), self.ok)
    }

    pub fn to_json(&self) -> Value {
        json!({
            "ok": self.ok, "causes": self.causes,
            "manifest_sha256": self.manifest.as_ref().map(manifest_sha256),
            "authorization": self.authorization(),
        })
    }
}

/// The authorization check. `flow` is the flow document's bytes, `manifest_text` and `signature` the
/// two files beside it (`None` when absent), `trusted` the raw 32 byte public keys of the authorities
/// the reader trusts (a key of any other length trusts nothing), `revoked` the key ids revoked, and
/// `floor` the versions already accepted, when the deployment keeps them.
pub fn verify_flow(
    flow: &[u8],
    manifest_text: Option<&str>,
    signature: Option<&[u8]>,
    trusted: &[Vec<u8>],
    revoked: &[String],
    floor: Option<&VersionFloor>,
) -> FlowVerdict {
    let (Some(manifest_text), Some(signature)) = (manifest_text, signature) else {
        return FlowVerdict::refuse(SIG_MISSING, None);
    };
    let Ok(manifest) = serde_json::from_str::<Value>(manifest_text) else {
        return FlowVerdict::refuse(MANIFEST_BAD_FORMAT, None);
    };
    let as_object = manifest.is_object().then(|| manifest.clone());
    if !manifest.is_object()
        || manifest.get("format").and_then(Value::as_str) != Some(FLOW_MANIFEST_FORMAT)
        || manifest.get("version").and_then(py_int).is_none()
    {
        return FlowVerdict::refuse(MANIFEST_BAD_FORMAT, as_object);
    }
    let payload = canonical_bytes(&manifest);
    let signer_id = trusted
        .iter()
        .find(|public| verify_ed25519(public, &payload, signature))
        .map(|public| sha256_hex(public));
    let Some(signer_id) = signer_id else { return FlowVerdict::refuse(SIG_INVALID, as_object) };
    if revoked.contains(&signer_id) {
        return FlowVerdict::refuse(SIG_REVOKED_KEY, as_object);
    }
    if manifest.get("key_id").and_then(Value::as_str) != Some(signer_id.as_str()) {
        return FlowVerdict::refuse(MANIFEST_KEY_ID_MISMATCH, as_object);
    }
    let flow_hash = flow_sha256(flow);
    if flow_hash.is_none() || flow_hash.as_deref() != manifest.get("flow_sha256").and_then(Value::as_str) {
        return FlowVerdict::refuse(FLOW_SHA256_MISMATCH, as_object);
    }
    if floor.is_some_and(|floor| !floor.admits(&manifest)) {
        return FlowVerdict::refuse(FLOW_VERSION_REPLAY, as_object);
    }
    FlowVerdict { ok: true, causes: Vec::new(), manifest: as_object }
}

/// The highest version accepted for each flow name, and the flow hash accepted at it
/// (`flow_versions.json` in the deployment's state directory). A version below the floor is refused;
/// the same version is admitted again only with the same flow, so a run can repeat and a second flow
/// at the same version cannot slip in.
///
/// This type holds the floor in memory and reads and writes it as JSON text; where the text is kept,
/// and writing it durably before the flow runs, is the host's. Accepting a manifest after it
/// verified is the one write a verifier-side consumer needs for replay protection.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct VersionFloor {
    pub entries: Map<String, Value>,
}

impl VersionFloor {
    /// Read the floor file's text (a JSON object of flow name to entry).
    pub fn from_json_str(text: &str) -> Result<VersionFloor, String> {
        match serde_json::from_str::<Value>(text).map_err(|error| error.to_string())? {
            Value::Object(entries) => Ok(VersionFloor { entries }),
            _ => Err("the version floor is not a JSON object".to_string()),
        }
    }

    /// The floor file's text, as Python writes it: sorted keys, one space of indent, a final newline.
    pub fn to_json_string(&self) -> String {
        use serde::Serialize;
        let mut buffer = Vec::new();
        let formatter = serde_json::ser::PrettyFormatter::with_indent(b" ");
        let mut serializer = serde_json::Serializer::with_formatter(&mut buffer, formatter);
        Value::Object(self.entries.clone()).serialize(&mut serializer).expect("a JSON object serializes");
        let mut text = String::from_utf8(buffer).expect("JSON is UTF-8");
        text.push('\n');
        text
    }

    /// Whether the floor admits this manifest. An entry that is not `{version, flow_sha256}` admits
    /// nothing.
    pub fn admits(&self, manifest: &Value) -> bool {
        let Some(entry) = self.entries.get(&py_str(manifest.get("flow"))) else { return true };
        let (Some(floor_version), Some(floor_hash)) = (entry.get("version").and_then(py_int), entry.get("flow_sha256")) else {
            return false;
        };
        let Some(version) = manifest.get("version").and_then(py_int) else { return false };
        version > floor_version || (version == floor_version && manifest.get("flow_sha256") == Some(floor_hash))
    }

    /// Raise the floor to this manifest's version. Does nothing when the floor is already at or above it.
    pub fn accept(&mut self, manifest: &Value) -> Result<(), String> {
        let name = py_str(manifest.get("flow"));
        let version = manifest.get("version").and_then(py_int).ok_or("the manifest has no integer version")?;
        if let Some(floor_version) = self.entries.get(&name).and_then(|entry| entry.get("version")).and_then(py_int) {
            if floor_version >= version {
                return Ok(());
            }
        }
        let flow_hash = manifest.get("flow_sha256").ok_or("the manifest has no flow_sha256")?.clone();
        self.entries.insert(
            name,
            json!({"version": version, "flow_sha256": flow_hash, "manifest_sha256": manifest_sha256(manifest)}),
        );
        Ok(())
    }
}
