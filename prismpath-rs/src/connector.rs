// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! connector.rs: the six-port Connector SDK, natively (feature `durable`).
//!
//! Faithful port of the PORT SURFACE of `prismpath/connector.py`: Ingestion, Retrieval,
//! Adjudicator, Action/Sink, Attestation, Deferral. Domains implement the trait; the defaults
//! reproduce the reference's portable behaviors bit-for-bit where they are data (hashes, the
//! flattened prompt surface, the attestation manifest: gated against `conformance/connector.json`)
//! and structurally where they are I/O (the idempotent JSONL sink). The Adjudicator port takes ANY
//! text->text callable: a served model, a comparator bank, a human console: never assuming an
//! LLM, exactly like the reference.
//!
//! Deliberately minimal vs Python: the guard hook (content safety is delegated by design: see
//! prismpath-rs/CONFORMANCE.md's scope boundary). The deferral port ships BOTH stores: in-memory
//! and `FileDeferralStore`, byte-compatible with the reference's directory layout so either
//! runtime can list and resume units the other deferred.

use crate::durable::{flow_hash, provenance_manifest, py_canonical_string};
use crate::{py_str, Value as EngineValue};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Write;

/// `PayloadFlattener.flatten`: nested dict/list -> flat key/value strings. Lists appear BOTH as a
/// comma-joined scalar string at their parent prefix and as per-index keys.
pub fn flatten(data: &Value, prefix: &str, delimiter: &str, out: &mut BTreeMap<String, String>) {
    match data {
        Value::Object(obj_val) => {
            for (key_str, val) in obj_val {
                let key = if prefix.is_empty() {
                    key_str.clone()
                } else {
                    format!("{prefix}{delimiter}{key_str}")
                };
                flatten(val, &key, delimiter, out);
            }
        }
        Value::Array(arr_val) => {
            if !prefix.is_empty() {
                let joined: Vec<String> = arr_val
                    .iter()
                    .filter(|item| !item.is_object() && !item.is_array())
                    .map(|item| py_str(&EngineValue::from_json(item)))
                    .collect();
                out.insert(prefix.to_string(), joined.join(", "));
            }
            for (idx, item) in arr_val.iter().enumerate() {
                let key = if prefix.is_empty() {
                    idx.to_string()
                } else {
                    format!("{prefix}{delimiter}{idx}")
                };
                flatten(item, &key, delimiter, out);
            }
        }
        scalar => {
            if !prefix.is_empty() {
                out.insert(prefix.to_string(), py_str(&EngineValue::from_json(scalar)));
            }
        }
    }
}

/// The reference's short content hash: "sha256:" + first 16 hex chars over the spaced canonical
/// JSON (`json.dumps(sort_keys=True)`).
pub fn short_hash(data: &Value) -> String {
    let digest = hex::encode(Sha256::digest(py_canonical_string(data, true).as_bytes()));
    format!("sha256:{}", &digest[..16])
}

/// The six-port Connector. Every method has the reference's default; override per domain.
pub trait Connector {
    fn name(&self) -> &str;

    // --- INGESTION PORT ---
    fn ingest_payload(&self, raw: &Value) -> Value {
        if raw.is_object() {
            raw.clone()
        } else {
            json!({"raw": raw})
        }
    }
    fn ingestion_hash(&self, data: &Value) -> String {
        short_hash(data)
    }

    // --- RETRIEVAL PORT ---
    fn retrieve_criteria(&self, _query: &str) -> Option<Value> {
        None
    }
    fn knowledge_hash(&self, kb: &Value) -> String {
        short_hash(kb)
    }

    // --- ADJUDICATOR PORT ---
    /// The default prompt surface: the payload FLATTENED to sorted key/value lines, optional
    /// criteria, and a flat-JSON reply instruction when a schema is given.
    fn adjudication_prompt(&self, payload: &Value, criteria: Option<&str>, schema: Option<&Value>) -> String {
        let mut flat = BTreeMap::new();
        if payload.is_object() || payload.is_array() {
            flatten(payload, "", ".", &mut flat);
        } else {
            flat.insert("input".to_string(), py_str(&EngineValue::from_json(payload)));
        }
        let lines: Vec<String> = flat.iter().map(|(key, val)| format!("{key}: {val}")).collect();
        let mut parts = vec![lines.join("\n")];
        if let Some(crit) = criteria {
            parts.push(format!("CRITERIA:\n{crit}"));
        }
        if let Some(schema_val) = schema {
            let props = schema_val.get("properties").unwrap_or(schema_val);
            let mut keys: Vec<&String> = props.as_object().map(|obj_val| obj_val.keys().collect()).unwrap_or_default();
            keys.sort();
            let joined = keys.iter().map(|str_val| str_val.as_str()).collect::<Vec<_>>().join(", ");
            parts.push(format!("Reply with ONE flat JSON object (no nesting) with keys: {joined}."));
        }
        parts.join("\n\n")
    }

    /// Run one adjudication: `generate` is ANY text->text callable. The reply's first JSON
    /// object becomes the outcome dict; a non-JSON reply degrades to {"text": reply}.
    fn adjudicate(
        &self,
        payload: &Value,
        generate: &mut dyn FnMut(&str) -> String,
        criteria: Option<&str>,
        schema: Option<&Value>,
    ) -> Value {
        let prompt = self.adjudication_prompt(payload, criteria, schema);
        let reply = generate(&prompt);
        if let (Some(start_idx), Some(end_idx)) = (reply.find('{'), reply.rfind('}')) {
            if start_idx < end_idx {
                if let Ok(Value::Object(mut out_map)) =
                    serde_json::from_str::<Value>(&reply[start_idx..=end_idx])
                {
                    out_map.entry("text".to_string())
                        .or_insert_with(|| Value::String(reply.trim().to_string()));
                    return Value::Object(out_map);
                }
            }
        }
        json!({"text": reply.trim()})
    }

    // --- ACTION / SINK PORT ---
    /// Idempotent JSONL append keyed on `key`: a replayed item never double-writes.
    fn emit_record(&self, result: &Value, destination: &str, key: &str) -> Result<bool, String> {
        if let Some(dir_path) = std::path::Path::new(destination).parent() {
            if !dir_path.as_os_str().is_empty() {
                std::fs::create_dir_all(dir_path).map_err(|err| err.to_string())?;
            }
        }
        let key_val = result.get(key);
        if key_val.is_none() || key_val == Some(&Value::Null) {
            let mut file_handle = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(destination)
                .map_err(|err| err.to_string())?;
            writeln!(file_handle, "{}", py_canonical_string(result, true)).map_err(|err| err.to_string())?;
            return Ok(true);
        }
        // upsert: replace the line whose `key` matches, else append
        let existing = std::fs::read_to_string(destination).unwrap_or_default();
        let mut lines: Vec<String> = Vec::new();
        let mut replaced = false;
        for line_str in existing.lines().filter(|line_item| !line_item.trim().is_empty()) {
            match serde_json::from_str::<Value>(line_str) {
                Ok(row) if row.get(key) == key_val => {
                    lines.push(py_canonical_string(result, true));
                    replaced = true;
                }
                _ => lines.push(line_str.to_string()),
            }
        }
        if !replaced {
            lines.push(py_canonical_string(result, true));
        }
        std::fs::write(destination, lines.join("\n") + "\n").map_err(|err| err.to_string())?;
        Ok(true)
    }

    // --- ATTESTATION PORT ---
    /// The policy hash to bind: the content hash of the governing flow document.
    fn policy_hash_for(&self, flow_path: &str) -> String {
        flow_hash(flow_path)
    }

    /// Core attestation binding: outcome root + provenance manifest (durable::provenance_manifest,
    /// C1). `created` injected for determinism, as in the durable layer.
    #[allow(clippy::too_many_arguments)]
    fn attest_decision(
        &self,
        outcome: &Value,
        policy_hash: &str,
        gate_id: &str,
        ingestion_hashes: &[&str],
        kb_hash: &str,
        label: Option<&str>,
        created: &str,
    ) -> Value {
        let root = hex::encode(Sha256::digest(py_canonical_string(outcome, true).as_bytes()));
        let default_label = format!("{}:decision", self.name());
        provenance_manifest(
            &root,
            label.unwrap_or(&default_label),
            created,
            Some(policy_hash),
            Some(gate_id),
            ingestion_hashes,
            Some(kb_hash),
        )
    }
}

/// Reference no-op connector: echoes payloads through the default ports (the SDK's smoke surface).
pub struct EchoConnector {
    pub name: String,
}
impl Connector for EchoConnector {
    fn name(&self) -> &str {
        &self.name
    }
}

// --- DEFERRAL PORT ---

#[derive(Debug, Clone)]
pub struct Deferral {
    pub unit_id: String,
    pub reason: String,
    pub state: Value,
    pub prior_output: Option<Value>,
    pub resolution: Option<Value>,
    pub actor: Option<String>,
}

pub trait DeferralStore {
    fn defer(&mut self, unit_id: &str, reason: &str, state: Value, prior_output: Option<Value>);
    fn pending(&self) -> Vec<&Deferral>;
    fn resume(&mut self, unit_id: &str, resolution: Value, actor: &str) -> bool;
}

/// File-backed deferral store, BYTE-COMPATIBLE with the reference's `FileDeferralStore`
/// (`prismpath/deferral.py`): one JSON record per unit at
/// `<dir>/<sha256(unit_id)[:16]>.json` with the same field set and lifecycle
/// (`status: pending -> resolved`, ISO-8601Z timestamps) - so a unit deferred by either runtime
/// can be listed and resumed by the other against one shared directory.
pub struct FileDeferralStore {
    pub dir: std::path::PathBuf,
}

impl FileDeferralStore {
    pub fn new(dir: impl Into<std::path::PathBuf>) -> std::io::Result<FileDeferralStore> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        Ok(FileDeferralStore { dir })
    }

    fn path(&self, unit_id: &str) -> std::path::PathBuf {
        let hash_str = hex::encode(Sha256::digest(unit_id.as_bytes()));
        self.dir.join(format!("{}.json", &hash_str[..16]))
    }

    fn now_iso() -> String {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|dur| dur.as_secs())
            .unwrap_or(0);
        let (days, hours, mins, seconds) = (secs / 86_400, (secs % 86_400) / 3600, (secs % 3600) / 60, secs % 60);
        let z_val = days as i64 + 719_468;
        let era = z_val.div_euclid(146_097);
        let doe = z_val.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let year_val = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let month_pos = (5 * doy + 2) / 153;
        let day_val = doy - (153 * month_pos + 2) / 5 + 1;
        let month_val = if month_pos < 10 { month_pos + 3 } else { month_pos - 9 };
        let final_year = if month_val <= 2 { year_val + 1 } else { year_val };
        format!("{final_year:04}-{month_val:02}-{day_val:02}T{hours:02}:{mins:02}:{seconds:02}Z")
    }

    pub fn defer(
        &self,
        unit_id: &str,
        reason: &str,
        state: Value,
        prior_output: Option<Value>,
    ) -> Result<Value, String> {
        let rec = json!({
            "unit_id": unit_id, "reason": reason, "state": state,
            "prior_output": prior_output.unwrap_or(Value::Null),
            "status": "pending", "deferred_at": Self::now_iso(),
            "resolution": Value::Null, "actor": Value::Null, "resolved_at": Value::Null,
        });
        std::fs::write(
            self.path(unit_id),
            serde_json::to_string_pretty(&rec).map_err(|err| err.to_string())?,
        )
        .map_err(|err| err.to_string())?;
        Ok(rec)
    }

    pub fn get(&self, unit_id: &str) -> Option<Value> {
        std::fs::read_to_string(self.path(unit_id))
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
    }

    pub fn pending(&self) -> Vec<Value> {
        let mut names: Vec<_> = std::fs::read_dir(&self.dir)
            .map(|read_dir| {
                read_dir.filter_map(|entry_res| entry_res.ok())
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .filter(|name_str| name_str.ends_with(".json"))
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
            .into_iter()
            .filter_map(|name_str| {
                let text = std::fs::read_to_string(self.dir.join(name_str)).ok()?;
                let rec: Value = serde_json::from_str(&text).ok()?;
                (rec.get("status").and_then(|status_val| status_val.as_str()) == Some("pending")).then_some(rec)
            })
            .collect()
    }

    pub fn resume(&self, unit_id: &str, resolution: Value, actor: &str) -> Result<Value, String> {
        let mut rec = self.get(unit_id).ok_or(format!("no deferred unit {unit_id}"))?;
        let status = rec.get("status").and_then(|status_val| status_val.as_str()).unwrap_or("");
        if status != "pending" {
            return Err(format!("unit {unit_id} already {status}"));
        }
        rec["status"] = json!("resolved");
        rec["resolution"] = resolution;
        rec["actor"] = json!(actor);
        rec["resolved_at"] = json!(Self::now_iso());
        std::fs::write(
            self.path(unit_id),
            serde_json::to_string_pretty(&rec).map_err(|err| err.to_string())?,
        )
        .map_err(|err| err.to_string())?;
        Ok(rec)
    }
}

#[derive(Default)]
pub struct MemDeferralStore {
    pub items: Vec<Deferral>,
}
impl DeferralStore for MemDeferralStore {
    fn defer(&mut self, unit_id: &str, reason: &str, state: Value, prior_output: Option<Value>) {
        self.items.push(Deferral {
            unit_id: unit_id.to_string(),
            reason: reason.to_string(),
            state,
            prior_output,
            resolution: None,
            actor: None,
        });
    }
    fn pending(&self) -> Vec<&Deferral> {
        self.items.iter().filter(|item| item.resolution.is_none()).collect()
    }
    fn resume(&mut self, unit_id: &str, resolution: Value, actor: &str) -> bool {
        for item in self.items.iter_mut() {
            if item.unit_id == unit_id && item.resolution.is_none() {
                item.resolution = Some(resolution);
                item.actor = Some(actor.to_string());
                return true;
            }
        }
        false
    }
}
