//! connector.rs — the six-port Connector SDK, natively (feature `durable`).
//!
//! Faithful port of the PORT SURFACE of `prismpath/connector.py`: Ingestion, Retrieval,
//! Adjudicator, Action/Sink, Attestation, Deferral. Domains implement the trait; the defaults
//! reproduce the reference's portable behaviors bit-for-bit where they are data (hashes, the
//! flattened prompt surface, the attestation manifest — gated against `conformance/connector.json`)
//! and structurally where they are I/O (the idempotent JSONL sink). The Adjudicator port takes ANY
//! text->text callable — a served model, a comparator bank, a human console — never assuming an
//! LLM, exactly like the reference.
//!
//! Deliberately minimal vs Python: the guard hook (content safety is delegated by design — see
//! prismpath-rs/CONFORMANCE.md's scope boundary). The deferral port ships BOTH stores: in-memory
//! and `FileDeferralStore`, byte-compatible with the reference's directory layout so either
//! runtime can list and resume units the other deferred.

use crate::durable::{flow_hash, provenance_manifest, py_canonical_string};
use crate::{py_str, V};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Write;

/// `PayloadFlattener.flatten`: nested dict/list -> flat key/value strings. Lists appear BOTH as a
/// comma-joined scalar string at their parent prefix and as per-index keys.
pub fn flatten(data: &Value, prefix: &str, delimiter: &str, out: &mut BTreeMap<String, String>) {
    match data {
        Value::Object(o) => {
            for (k, v) in o {
                let key = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}{delimiter}{k}")
                };
                flatten(v, &key, delimiter, out);
            }
        }
        Value::Array(a) => {
            if !prefix.is_empty() {
                let joined: Vec<String> = a
                    .iter()
                    .filter(|i| !i.is_object() && !i.is_array())
                    .map(|i| py_str(&V::from_json(i)))
                    .collect();
                out.insert(prefix.to_string(), joined.join(", "));
            }
            for (idx, item) in a.iter().enumerate() {
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
                out.insert(prefix.to_string(), py_str(&V::from_json(scalar)));
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
            flat.insert("input".to_string(), py_str(&V::from_json(payload)));
        }
        let lines: Vec<String> = flat.iter().map(|(k, v)| format!("{k}: {v}")).collect();
        let mut parts = vec![lines.join("\n")];
        if let Some(c) = criteria {
            parts.push(format!("CRITERIA:\n{c}"));
        }
        if let Some(schema) = schema {
            let props = schema.get("properties").unwrap_or(schema);
            let mut keys: Vec<&String> = props.as_object().map(|o| o.keys().collect()).unwrap_or_default();
            keys.sort();
            let joined = keys.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ");
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
        if let (Some(start), Some(end)) = (reply.find('{'), reply.rfind('}')) {
            if start < end {
                if let Ok(Value::Object(mut out)) =
                    serde_json::from_str::<Value>(&reply[start..=end])
                {
                    out.entry("text".to_string())
                        .or_insert_with(|| Value::String(reply.trim().to_string()));
                    return Value::Object(out);
                }
            }
        }
        json!({"text": reply.trim()})
    }

    // --- ACTION / SINK PORT ---
    /// Idempotent JSONL append keyed on `key`: a replayed item never double-writes.
    fn emit_record(&self, result: &Value, destination: &str, key: &str) -> Result<bool, String> {
        if let Some(dir) = std::path::Path::new(destination).parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
            }
        }
        let key_val = result.get(key);
        if key_val.is_none() || key_val == Some(&Value::Null) {
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(destination)
                .map_err(|e| e.to_string())?;
            writeln!(f, "{}", py_canonical_string(result, true)).map_err(|e| e.to_string())?;
            return Ok(true);
        }
        // upsert: replace the line whose `key` matches, else append
        let existing = std::fs::read_to_string(destination).unwrap_or_default();
        let mut lines: Vec<String> = Vec::new();
        let mut replaced = false;
        for line in existing.lines().filter(|l| !l.trim().is_empty()) {
            match serde_json::from_str::<Value>(line) {
                Ok(row) if row.get(key) == key_val => {
                    lines.push(py_canonical_string(result, true));
                    replaced = true;
                }
                _ => lines.push(line.to_string()),
            }
        }
        if !replaced {
            lines.push(py_canonical_string(result, true));
        }
        std::fs::write(destination, lines.join("\n") + "\n").map_err(|e| e.to_string())?;
        Ok(true)
    }

    // --- ATTESTATION PORT ---
    /// The policy hash to bind: the content hash of the governing flow document.
    fn policy_hash_for(&self, flow_path: &str) -> String {
        flow_hash(flow_path)
    }

    /// Core attestation binding: outcome root + provenance manifest (durable::provenance_manifest,
    /// C1). `created` injected for determinism, as in the durable layer.
    #[allow(clippy::too_many_arguments)] // mirrors the reference signature + injected `created`
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

// --- DEFERRAL PORT (trait + in-memory store; file backend is a named follow-on) ---

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
/// (`status: pending -> resolved`, ISO-8601Z timestamps) — so a unit deferred by either runtime
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
        let h = hex::encode(Sha256::digest(unit_id.as_bytes()));
        self.dir.join(format!("{}.json", &h[..16]))
    }

    fn now_iso() -> String {
        // %Y-%m-%dT%H:%M:%SZ, matching deferral._now()
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let (days, h, m, s) = (secs / 86_400, (secs % 86_400) / 3600, (secs % 3600) / 60, secs % 60);
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
        format!("{y:04}-{mth:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
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
            serde_json::to_string_pretty(&rec).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        Ok(rec)
    }

    pub fn get(&self, unit_id: &str) -> Option<Value> {
        std::fs::read_to_string(self.path(unit_id))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
    }

    pub fn pending(&self) -> Vec<Value> {
        let mut names: Vec<_> = std::fs::read_dir(&self.dir)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .filter(|n| n.ends_with(".json"))
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
            .into_iter()
            .filter_map(|n| {
                let t = std::fs::read_to_string(self.dir.join(n)).ok()?;
                let r: Value = serde_json::from_str(&t).ok()?;
                (r.get("status").and_then(|s| s.as_str()) == Some("pending")).then_some(r)
            })
            .collect()
    }

    pub fn resume(&self, unit_id: &str, resolution: Value, actor: &str) -> Result<Value, String> {
        let mut rec = self.get(unit_id).ok_or(format!("no deferred unit {unit_id}"))?;
        let status = rec.get("status").and_then(|s| s.as_str()).unwrap_or("");
        if status != "pending" {
            return Err(format!("unit {unit_id} already {status}"));
        }
        rec["status"] = json!("resolved");
        rec["resolution"] = resolution;
        rec["actor"] = json!(actor);
        rec["resolved_at"] = json!(Self::now_iso());
        std::fs::write(
            self.path(unit_id),
            serde_json::to_string_pretty(&rec).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
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
        self.items.iter().filter(|d| d.resolution.is_none()).collect()
    }
    fn resume(&mut self, unit_id: &str, resolution: Value, actor: &str) -> bool {
        for d in self.items.iter_mut() {
            if d.unit_id == unit_id && d.resolution.is_none() {
                d.resolution = Some(resolution);
                d.actor = Some(actor.to_string());
                return true;
            }
        }
        false
    }
}
