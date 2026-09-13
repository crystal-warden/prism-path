// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! prismpath-hotswap-rs — the secure policy hot-swap, natively.
//!
//! Faithful port of `prismpath/policy_pack.py` (Authorized + Envelope-bounded gates) and
//! `prismpath/policy_host.py` (Attested + Audited-and-atomic host), per
//! `docs/design/spec-secure-hotswap.md`. The `.ppt` image is a READ-ONLY input — same as the
//! Python reference, nothing here touches the compiler or the image bytes, so certified hashes
//! stay exactly what the FPGA/eBPF evidence rows cite.
//!
//! Cross-language contract (gated in `tests/`): signatures are Ed25519 over
//! `durable::py_canonical_string(manifest, compact)` — Python's exact
//! `json.dumps(sort_keys=True, separators=(",",":"))` bytes — so a pack signed by either runtime
//! verifies on the other, and every refusal uses the same stable reason strings the Python tests
//! and audit rows pin.
//!
//! Key files: public keys are raw 32-byte Ed25519 (both runtimes read them); private keys here
//! are raw 32-byte seeds written 0600 (Python's are PEM/PKCS8 — private keys are never shared
//! across runtimes, only public keys and signatures are).

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use prismpath_rs::durable::py_canonical_string;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub mod host;

// --- .ppt format facts (read-only mirror of ppt_compile.py / TABLE_FORMAT.md) ---
pub const MAGIC: u32 = 0x4D54_5050; // "PPTM"
pub const FORMAT_VERSION: u16 = 1;
pub const HEADER_SIZE: usize = 28;
pub const ATOM_SIZE: usize = 8; // <HBBi
pub const NODE_SIZE: usize = 4; // <HH
pub const EDGE_SIZE: usize = 6; // <HHH
pub const WORD_SIZE: usize = 2; // <H
const PROG_OPCODES: [u16; 5] = [0x8000, 0x8001, 0x8002, 0x8003, 0x8004]; // NOT AND OR TRUE FALSE

pub const PACK_FORMAT: &str = "ppt-pack/1";

/// Default envelope caps = the eBPF loader's MAX_* constants (ppt_common.h).
pub fn default_caps() -> BTreeMap<String, u64> {
    [("atoms", 1024u64), ("nodes", 256), ("edges", 1024), ("prog_words", 4096),
     ("max_steps", 25), ("max_stack", 16)]
        .into_iter()
        .map(|(name, limit)| (name.to_string(), limit))
        .collect()
}

pub fn canonical_bytes(obj: &Value) -> Vec<u8> {
    py_canonical_string(obj, false).into_bytes()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

// ------------------------------------------------------------------ image parsing

#[derive(Debug, Clone, PartialEq)]
pub struct PptHeader {
    pub fields: u16,
    pub interns: u16,
    pub atoms: u16,
    pub nodes: u16,
    pub edges: u16,
    pub prog_words: u16,
    pub start: u16,
    pub visits_idx: u16,
    pub max_steps: u16,
    pub max_stack: u16,
}

impl PptHeader {
    pub fn count(&self, key: &str) -> u64 {
        match key {
            "atoms" => self.atoms as u64,
            "nodes" => self.nodes as u64,
            "edges" => self.edges as u64,
            "prog_words" => self.prog_words as u64,
            "max_steps" => self.max_steps as u64,
            "max_stack" => self.max_stack as u64,
            _ => 0,
        }
    }
}

fn u16le(bytes: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([bytes[off], bytes[off + 1]])
}
fn u32le(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
}

/// Parse the 28-byte header; stable-reason error strings match the reference exactly.
pub fn read_ppt_header(data: &[u8]) -> Result<PptHeader, String> {
    if data.len() < HEADER_SIZE {
        return Err("image:truncated-header".to_string());
    }
    if u32le(data, 0) != MAGIC {
        return Err("image:bad-magic".to_string());
    }
    if u16le(data, 4) != FORMAT_VERSION {
        return Err("image:bad-version".to_string());
    }
    Ok(PptHeader {
        fields: u16le(data, 6),
        interns: u16le(data, 8),
        atoms: u16le(data, 10),
        nodes: u16le(data, 12),
        edges: u16le(data, 14),
        prog_words: u16le(data, 16),
        start: u16le(data, 18),
        visits_idx: u16le(data, 20),
        max_steps: u16le(data, 22),
        max_stack: u16le(data, 24),
    })
}

/// Image-native structural + fragment check (the opcode-whitelist walk): exact length, atom
/// ops/types in the Level M fragment, program words resolving to atoms or boolean opcodes,
/// node/edge indices in range, and (when caps are given) every count within the envelope.
pub fn validate_image(data: &[u8], caps: Option<&BTreeMap<String, u64>>) -> (bool, Vec<String>) {
    let mut reasons: Vec<String> = Vec::new();
    let header = match read_ppt_header(data) {
        Ok(header) => header,
        Err(error) => return (false, vec![error]),
    };

    let need = HEADER_SIZE
        + ATOM_SIZE * header.atoms as usize
        + NODE_SIZE * header.nodes as usize
        + EDGE_SIZE * header.edges as usize
        + WORD_SIZE * header.prog_words as usize;
    if data.len() != need {
        return (false, vec!["image:length-mismatch".to_string()]);
    }

    if let Some(caps) = caps {
        let defaults = default_caps();
        for key in ["atoms", "nodes", "edges", "prog_words", "max_steps", "max_stack"] {
            let cap = caps.get(key).copied().unwrap_or_else(|| defaults[key]);
            if header.count(key) > cap {
                reasons.push(format!("image:caps-exceeded:{key}"));
            }
        }
    }

    let mut off = HEADER_SIZE;
    for atom_index in 0..header.atoms as usize {
        let (_fidx, op, ty) = (u16le(data, off), data[off + 2], data[off + 3]);
        let fidx = u16le(data, off);
        off += ATOM_SIZE;
        if op > 6 {
            reasons.push(format!("image:unknown-op:atom{atom_index}"));
        }
        if ty > 3 {
            reasons.push(format!("image:unknown-type:atom{atom_index}"));
        }
        if fidx >= header.fields {
            reasons.push(format!("image:field-index-oob:atom{atom_index}"));
        }
    }
    off += NODE_SIZE * header.nodes as usize;
    for edge_index in 0..header.edges as usize {
        let (target, po, pc) = (u16le(data, off), u16le(data, off + 2), u16le(data, off + 4));
        off += EDGE_SIZE;
        if target >= header.nodes {
            reasons.push(format!("image:edge-target-oob:edge{edge_index}"));
        }
        if po as u32 + pc as u32 > header.prog_words as u32 {
            reasons.push(format!("image:edge-prog-oob:edge{edge_index}"));
        }
    }
    for word_index in 0..header.prog_words as usize {
        let word = u16le(data, off);
        off += WORD_SIZE;
        if word >= 0x8000 && !PROG_OPCODES.contains(&word) {
            reasons.push(format!("image:unknown-opcode:word{word_index}"));
        }
        if word < 0x8000 && word >= header.atoms {
            reasons.push(format!("image:atom-index-oob:word{word_index}"));
        }
    }

    (reasons.is_empty(), reasons)
}

// ------------------------------------------------------------------ keys

/// Generate an Ed25519 keypair: raw 32-byte seed (0600) + raw 32-byte public.
/// Returns (private_path, public_path, key_id).
pub fn keygen(out_dir: &str, name: &str) -> Result<(String, String, String), String> {
    std::fs::create_dir_all(out_dir).map_err(|error| error.to_string())?;
    let signing = SigningKey::generate(&mut rand::rngs::OsRng);
    let priv_path = format!("{out_dir}/{name}.key");
    let pub_path = format!("{out_dir}/{name}.pub");
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&priv_path)
            .map_err(|error| error.to_string())?;
        file.write_all(signing.to_bytes().as_ref()).map_err(|error| error.to_string())?;
    }
    let raw = signing.verifying_key().to_bytes();
    std::fs::write(&pub_path, raw).map_err(|error| error.to_string())?;
    Ok((priv_path, pub_path, sha256_hex(&raw)))
}

pub fn load_private(path: &str) -> Result<SigningKey, String> {
    let bytes = std::fs::read(path).map_err(|error| error.to_string())?;
    let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| "bad private key length")?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Load a raw-32-byte Ed25519 public key file -> (key, key_id).
pub fn load_public(path: &str) -> Result<(VerifyingKey, String), String> {
    let bytes = std::fs::read(path).map_err(|error| error.to_string())?;
    let raw: [u8; 32] = bytes.as_slice().try_into().map_err(|_| "bad public key length")?;
    let key = VerifyingKey::from_bytes(&raw).map_err(|error| error.to_string())?;
    Ok((key, sha256_hex(&raw)))
}

/// Revocation list: a JSON array of key_id hex strings; a missing path is an empty set.
pub fn load_revoked(path: Option<&str>) -> Vec<String> {
    let Some(path) = path else { return Vec::new() };
    std::fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str::<Vec<String>>(&text).ok())
        .unwrap_or_default()
}

// ------------------------------------------------------------------ manifest / pack

pub fn build_manifest(
    image: &[u8],
    fields: &BTreeMap<String, String>,
    version: i64,
    envelope_id: &str,
    key_id: &str,
    created: &str,
) -> Result<Value, String> {
    let header = read_ppt_header(image)?;
    Ok(json!({
        "format": PACK_FORMAT,
        "image_sha256": sha256_hex(image),
        "fields": fields,
        "counts": {"atoms": header.atoms, "nodes": header.nodes, "edges": header.edges,
                   "prog_words": header.prog_words, "max_steps": header.max_steps,
                   "max_stack": header.max_stack},
        "version": version,
        "envelope_id": envelope_id,
        "key_id": key_id,
        "created": created,
    }))
}

/// Sign a `.ppt` into a pack: `<ppt>.manifest.json` + `<ppt>.manifest.sig` beside the untouched
/// image. Refuses to sign an invalid image, like the reference.
pub fn build_pack(
    ppt_path: &str,
    fields: &BTreeMap<String, String>,
    version: i64,
    envelope_id: &str,
    priv_path: &str,
    pub_path: &str,
    created: &str,
) -> Result<Value, String> {
    let image = std::fs::read(ppt_path).map_err(|error| error.to_string())?;
    let (ok, reasons) = validate_image(&image, None);
    if !ok {
        return Err(format!("refusing to sign an invalid image: {}", reasons.join(",")));
    }
    let (_pub, key_id) = load_public(pub_path)?;
    let manifest = build_manifest(&image, fields, version, envelope_id, &key_id, created)?;
    let sig = load_private(priv_path)?.sign(&canonical_bytes(&manifest));
    std::fs::write(
        format!("{ppt_path}.manifest.json"),
        serde_json::to_string_pretty(&manifest).map_err(|error| error.to_string())? + "\n",
    )
    .map_err(|error| error.to_string())?;
    std::fs::write(format!("{ppt_path}.manifest.sig"), sig.to_bytes()).map_err(|error| error.to_string())?;
    Ok(manifest)
}

/// The Authorized gate. Same pipeline + stable reason strings as the reference:
/// signature by a known, non-revoked key; key_id binds; image hash + header counts match.
pub fn verify_pack(
    ppt_path: &str,
    pubkey_paths: &[String],
    revoked: &[String],
) -> (bool, Vec<String>, Option<Value>) {
    let man_path = format!("{ppt_path}.manifest.json");
    let sig_path = format!("{ppt_path}.manifest.sig");
    let (Ok(man_text), Ok(sig_bytes)) = (std::fs::read_to_string(&man_path), std::fs::read(&sig_path))
    else {
        return (false, vec!["sig:missing".to_string()], None);
    };
    let Ok(manifest) = serde_json::from_str::<Value>(&man_text) else {
        return (false, vec!["sig:missing".to_string()], None);
    };
    if manifest.get("format").and_then(|value| value.as_str()) != Some(PACK_FORMAT) {
        return (false, vec!["manifest:bad-format".to_string()], Some(manifest));
    }

    let payload = canonical_bytes(&manifest);
    let Ok(sig_arr): Result<[u8; 64], _> = sig_bytes.as_slice().try_into() else {
        return (false, vec!["sig:invalid".to_string()], Some(manifest));
    };
    let sig = Signature::from_bytes(&sig_arr);
    let mut signer_id: Option<String> = None;
    for path in pubkey_paths {
        let Ok((pubkey, key_id)) = load_public(path) else { continue };
        if pubkey.verify(&payload, &sig).is_ok() {
            signer_id = Some(key_id);
            break;
        }
    }
    let Some(signer_id) = signer_id else {
        return (false, vec!["sig:invalid".to_string()], Some(manifest));
    };
    if revoked.contains(&signer_id) {
        return (false, vec!["sig:revoked-key".to_string()], Some(manifest));
    }
    if manifest.get("key_id").and_then(|value| value.as_str()) != Some(signer_id.as_str()) {
        return (false, vec!["manifest:key-id-mismatch".to_string()], Some(manifest));
    }

    let Ok(image) = std::fs::read(ppt_path) else {
        return (false, vec!["image:sha256-mismatch".to_string()], Some(manifest));
    };
    if manifest.get("image_sha256").and_then(|value| value.as_str()) != Some(sha256_hex(&image).as_str()) {
        return (false, vec!["image:sha256-mismatch".to_string()], Some(manifest));
    }
    let header = match read_ppt_header(&image) {
        Ok(header) => header,
        Err(error) => return (false, vec![error], Some(manifest)),
    };
    for count_name in ["atoms", "nodes", "edges", "prog_words", "max_steps", "max_stack"] {
        if manifest.get("counts").and_then(|counts| counts.get(count_name)).and_then(|value| value.as_u64()) != Some(header.count(count_name))
        {
            return (false, vec![format!("manifest:count-mismatch:{count_name}")], Some(manifest));
        }
    }
    (true, Vec::new(), Some(manifest))
}

// ------------------------------------------------------------------ envelope

/// Sign the qualified-once baseline: `<id>.envelope.json` + `.sig` in out_dir.
pub fn build_envelope(
    envelope_id: &str,
    fields: &BTreeMap<String, String>,
    caps: Option<&BTreeMap<String, u64>>,
    priv_path: &str,
    pub_path: &str,
    out_dir: &str,
) -> Result<Value, String> {
    let (_pub, key_id) = load_public(pub_path)?;
    let mut merged = default_caps();
    if let Some(overrides) = caps {
        for (name, limit) in overrides {
            merged.insert(name.clone(), *limit);
        }
    }
    let env = json!({
        "envelope_id": envelope_id,
        "fields": fields,
        "caps": merged,
        "require_level_m": true,
        "key_id": key_id,
    });
    let sig = load_private(priv_path)?.sign(&canonical_bytes(&env));
    std::fs::create_dir_all(out_dir).map_err(|error| error.to_string())?;
    let base = format!("{out_dir}/{envelope_id}.envelope");
    std::fs::write(
        format!("{base}.json"),
        serde_json::to_string_pretty(&env).map_err(|error| error.to_string())? + "\n",
    )
    .map_err(|error| error.to_string())?;
    std::fs::write(format!("{base}.sig"), sig.to_bytes()).map_err(|error| error.to_string())?;
    Ok(env)
}

/// Load + signature-verify an envelope (`base_path` without .json/.sig suffix).
pub fn load_envelope(base_path: &str, pubkey_paths: &[String]) -> (Option<Value>, Vec<String>) {
    let (Ok(text), Ok(sig_bytes)) = (
        std::fs::read_to_string(format!("{base_path}.json")),
        std::fs::read(format!("{base_path}.sig")),
    ) else {
        return (None, vec!["envelope:missing".to_string()]);
    };
    let Ok(env) = serde_json::from_str::<Value>(&text) else {
        return (None, vec!["envelope:missing".to_string()]);
    };
    let Ok(sig_arr): Result<[u8; 64], _> = sig_bytes.as_slice().try_into() else {
        return (None, vec!["envelope:sig-invalid".to_string()]);
    };
    let sig = Signature::from_bytes(&sig_arr);
    let payload = canonical_bytes(&env);
    for path in pubkey_paths {
        if let Ok((pubkey, _)) = load_public(path) {
            if pubkey.verify(&payload, &sig).is_ok() {
                return (Some(env), Vec::new());
            }
        }
    }
    (None, vec!["envelope:sig-invalid".to_string()])
}

/// The Envelope-bounded gate: manifest targets this envelope, fields ⊆ envelope fields, and the
/// image passes the capped structural/fragment walk.
pub fn check_envelope(manifest: &Value, image: &[u8], envelope: &Value) -> (bool, Vec<String>) {
    let mut reasons: Vec<String> = Vec::new();
    if manifest.get("envelope_id") != envelope.get("envelope_id") {
        reasons.push("envelope:id-mismatch".to_string());
    }
    let empty = serde_json::Map::new();
    let env_fields = envelope.get("fields").and_then(|value| value.as_object()).unwrap_or(&empty);
    if let Some(man_fields) = manifest.get("fields").and_then(|value| value.as_object()) {
        for (name, kind) in man_fields {
            match env_fields.get(name) {
                None => reasons.push(format!("envelope:unknown-field:{name}")),
                Some(env_kind) if env_kind != kind => {
                    reasons.push(format!("envelope:field-kind-mismatch:{name}"))
                }
                _ => {}
            }
        }
    }
    let caps: BTreeMap<String, u64> = envelope
        .get("caps")
        .and_then(|caps_value| caps_value.as_object())
        .map(|caps_object| caps_object.iter().filter_map(|(name, value)| value.as_u64().map(|limit| (name.clone(), limit))).collect())
        .unwrap_or_else(default_caps);
    let (ok, img_reasons) = validate_image(image, Some(&caps));
    reasons.extend(img_reasons);
    (reasons.is_empty() && ok, reasons)
}
