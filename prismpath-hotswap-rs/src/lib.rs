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
//! Cross-language contract (gated in `tests/`): a manifest or envelope is a canon/2 document that
//! names its encoding, and its signature is Ed25519 over the canon/2 domain and its canon/2 bytes
//! (`durable::signed_message`, `policy_pack.signed_bytes` in Python), so a pack signed by either
//! runtime verifies on the other; an untagged manifest (canon/1, retired) is refused as
//! `manifest:bad-format`. Every refusal uses the same stable reason strings
//! the Python tests and audit rows pin.
//!
//! Key files: public keys are raw 32-byte Ed25519 (both runtimes read them); private keys here
//! are raw 32-byte seeds written 0600 (Python's are PEM/PKCS8 — private keys are never shared
//! across runtimes, only public keys and signatures are).

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use prismpath_rs::durable::{self, CanonicalError};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub mod flow_authority;
pub mod host;
pub mod merkle;
mod pyval;
pub mod root_statement;

// --- .ppt format facts (read-only mirror of prismpath/kernel/ppt_compile.py / TABLE_FORMAT.md) ---
pub const MAGIC: u32 = 0x4D54_5050; // "PPTM"
pub const FORMAT_VERSION: u16 = 1;
pub const HEADER_SIZE: usize = 28;
pub const ATOM_SIZE: usize = 8; // <HBBi
pub const NODE_SIZE: usize = 4; // <HH
pub const EDGE_SIZE: usize = 6; // <HHH
pub const WORD_SIZE: usize = 2; // <H
/// The 12th header word (offset 26) is split: the low byte is flags, the high byte is `safe_node`
/// (a fail-safe node index; 0 is undeclared). Bit 0 appends a per-node attribute section (one
/// uint16 per node) after the program, bit 2 a per-node uint32 name hash after that.
pub const FLAG_NODE_ATTR: u8 = 0x01;
pub const FLAG_MIGRATE_BY_NAME: u8 = 0x02;
pub const FLAG_NODE_NAMES: u8 = 0x04;
pub const FLAG_STATEFUL: u8 = 0x08;
/// The fabric materialization envelope of a node attribute: 6 bits.
const NODE_ATTR_MAX: u16 = 0x3F;
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

/// The bytes a document is hashed over (`durable::document_bytes`): its canon/2 bytes. A document that does
/// not name canon/2, or has no canon/2 form, is refused.
pub fn canonical_bytes(obj: &Value) -> Result<Vec<u8>, CanonicalError> {
    durable::document_bytes(obj)
}

/// The bytes a signature over a manifest, an envelope or a flow manifest covers
/// (`durable::signed_message`): the canon/2 domain and the canon/2 bytes. A document that does not name
/// canon/2 is refused.
pub fn signed_bytes(obj: &Value) -> Result<Vec<u8>, CanonicalError> {
    durable::signed_message(obj)
}

/// A signed document as it is written to disk: its canon/2 bytes and a newline.
pub fn write_signed_document(path: &str, doc: &Value) -> Result<(), String> {
    let mut bytes = durable::canon2_bytes(doc).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    std::fs::write(path, bytes).map_err(|error| error.to_string())
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Check an Ed25519 signature given the raw 32 byte public key, the message and the raw 64 byte
/// signature. A key or signature of any other length, a key that is not a curve point, and a
/// signature that does not verify are all `false`. This is `verify_strict`, which also refuses
/// small order keys; the receipt verifiers (`root_statement`, `flow_authority`) use it.
pub fn verify_ed25519(public: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let (Ok(public), Ok(signature)) = (<[u8; 32]>::try_from(public), Signature::from_slice(signature)) else {
        return false;
    };
    VerifyingKey::from_bytes(&public).is_ok_and(|key| key.verify_strict(message, &signature).is_ok())
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
    /// Low byte of the 12th word.
    pub flags: u8,
    /// High byte of the 12th word: the signed fail-safe node, 0 when undeclared.
    pub safe_node: u8,
    pub migrate_by_name: bool,
    pub stateful: bool,
}

impl PptHeader {
    /// The header as the dict `read_ppt_header` returns, the `counts` member of the active policy record.
    pub fn to_value(&self) -> Value {
        json!({
            "fields": self.fields, "interns": self.interns, "atoms": self.atoms, "nodes": self.nodes,
            "edges": self.edges, "prog_words": self.prog_words, "start": self.start,
            "visits_idx": self.visits_idx, "max_steps": self.max_steps, "max_stack": self.max_stack,
            "flags": self.flags, "safe_node": self.safe_node,
            "migrate_by_name": self.migrate_by_name, "stateful": self.stateful,
        })
    }

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

/// Parse the 28-byte header; stable-reason error strings match the reference exactly. The 12th word
/// is split into flags (low byte) and `safe_node` (high byte).
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
    let flag_word = u16le(data, 26);
    let flags = (flag_word & 0x00FF) as u8;
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
        flags,
        safe_node: (flag_word >> 8) as u8,
        migrate_by_name: flags & FLAG_MIGRATE_BY_NAME != 0,
        stateful: flags & FLAG_STATEFUL != 0,
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

    if header.safe_node != 0 && u16::from(header.safe_node) >= header.nodes {
        reasons.push("image:safe-node-oob".to_string()); // a signed fail-safe must name a real node
    }

    let mut need = HEADER_SIZE
        + ATOM_SIZE * header.atoms as usize
        + NODE_SIZE * header.nodes as usize
        + EDGE_SIZE * header.edges as usize
        + WORD_SIZE * header.prog_words as usize;
    if header.flags & FLAG_NODE_ATTR != 0 {
        need += WORD_SIZE * header.nodes as usize; // one uint16 attribute per node
    }
    if header.flags & FLAG_NODE_NAMES != 0 {
        need += 4 * header.nodes as usize; // one uint32 name hash per node, after the attributes
    }
    if data.len() != need {
        reasons.push("image:length-mismatch".to_string());
        return (false, reasons);
    }

    // an empty caps object is falsy in the reference, so it checks nothing
    if let Some(caps) = caps.filter(|caps| !caps.is_empty()) {
        let defaults = default_caps();
        for key in COUNT_NAMES {
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
    if header.flags & FLAG_NODE_ATTR != 0 {
        for node_index in 0..header.nodes as usize {
            if u16le(data, off) > NODE_ATTR_MAX {
                reasons.push(format!("image:node-attr-oob:node{node_index}"));
            }
            off += WORD_SIZE;
        }
    }

    (reasons.is_empty(), reasons)
}

/// Per-evaluate worst-case cycle bound: the maximum over nodes of the sum over that node's edges of
/// `2 + max(prog_words, 1)`, plus 2 (the reference's `wcet_cycles`). Reads only the node and edge
/// tables, and refuses an image too short to hold them instead of reading past the end (the
/// reference raises there).
pub fn wcet_cycles(data: &[u8]) -> Result<u64, String> {
    let header = read_ppt_header(data)?;
    let nodes_off = HEADER_SIZE + ATOM_SIZE * header.atoms as usize;
    let edges_off = nodes_off + NODE_SIZE * header.nodes as usize;
    if data.len() < edges_off + EDGE_SIZE * header.edges as usize {
        return Err("image:length-mismatch".to_string());
    }
    let edge_cnt: Vec<u64> =
        (0..header.edges as usize).map(|index| u64::from(u16le(data, edges_off + index * EDGE_SIZE + 4))).collect();
    let mut worst = 0u64;
    for index in 0..header.nodes as usize {
        let (edge_off, edge_count) = (u16le(data, nodes_off + index * NODE_SIZE) as usize, u16le(data, nodes_off + index * NODE_SIZE + 2) as usize);
        // slice bounds clamp, as Python's edge_pcnt[eoff:eoff + ecnt] does
        let start = edge_off.min(edge_cnt.len());
        let end = (edge_off + edge_count).min(edge_cnt.len());
        let sum: u64 = edge_cnt[start..end].iter().map(|words| 2 + (*words).max(1)).sum();
        worst = worst.max(sum + 2);
    }
    Ok(worst)
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
        "encoding": durable::CANON2,
        "image_sha256": sha256_hex(image),
        "fields": fields,
        "counts": {"atoms": header.atoms, "nodes": header.nodes, "edges": header.edges,
                   "prog_words": header.prog_words, "max_steps": header.max_steps,
                   "max_stack": header.max_stack},
        "wcet_cycles": wcet_cycles(image)?, // per-evaluate worst case, signed with the policy
        "version": version,
        "envelope_id": envelope_id,
        "key_id": key_id,
        "created": created,
    }))
}

/// What a pack can carry beyond the image, the field dictionary and the version, all of it covered
/// by the manifest signature.
#[derive(Debug, Clone, Default)]
pub struct PackOptions {
    /// sha256 (hex) of the baked `<ppt>.spiral` sidecar; declares the `spiral` packing profile.
    pub spiral_sidecar_sha256: Option<String>,
    /// The policy of record this pack temporarily overrides; changes nothing about verification.
    pub overlay_of: Option<String>,
    /// The authored flow the image was compiled from. When it defines fields they become the
    /// manifest's field dictionary (an explicit one must match) and `flow_sha256` records the text.
    pub flow_text: Option<String>,
}

/// The manifest field dictionary of a flow that defines its fields: each name with its definition in
/// canonical spelling. Refuses a flow that breaks its definitions or defines none.
pub fn field_dictionary_of(flow_text: &str) -> Result<BTreeMap<String, String>, String> {
    let graph = prismpath_rs::parser::parse_checked(flow_text)?;
    if graph.fields.is_empty() {
        return Err("the flow defines no fields, so there is no definition to bind; pass the field dictionary explicitly".to_string());
    }
    Ok(graph.fields.iter().map(|(name, definition)| (name.clone(), definition.canonical_text())).collect())
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
    build_pack_with(ppt_path, fields, version, envelope_id, priv_path, pub_path, created, &PackOptions::default())
}

/// `build_pack` with the optional manifest members of the reference: `packing`, `overlay_of`, and the
/// flow-derived field dictionary with `flow_sha256`.
#[allow(clippy::too_many_arguments)]
pub fn build_pack_with(
    ppt_path: &str,
    fields: &BTreeMap<String, String>,
    version: i64,
    envelope_id: &str,
    priv_path: &str,
    pub_path: &str,
    created: &str,
    options: &PackOptions,
) -> Result<Value, String> {
    let mut fields = fields.clone();
    let mut flow_sha256 = None;
    if let Some(flow_text) = &options.flow_text {
        let derived = field_dictionary_of(flow_text)?;
        if !fields.is_empty() && fields != derived {
            return Err(format!("the field dictionary {fields:?} differs from the flow's own definitions {derived:?}"));
        }
        fields = derived;
        flow_sha256 = Some(sha256_hex(flow_text.as_bytes()));
    }
    let image = std::fs::read(ppt_path).map_err(|error| error.to_string())?;
    let (ok, reasons) = validate_image(&image, None);
    if !ok {
        return Err(format!("refusing to sign an invalid image: {}", reasons.join(",")));
    }
    let (_pub, key_id) = load_public(pub_path)?;
    let mut manifest = build_manifest(&image, &fields, version, envelope_id, &key_id, created)?;
    let members = manifest.as_object_mut().expect("a manifest is an object");
    if let Some(sidecar_sha256) = options.spiral_sidecar_sha256.as_ref().filter(|digest| !digest.is_empty()) {
        members.insert("packing".to_string(), json!({"profile": "spiral", "sidecar_sha256": sidecar_sha256}));
    } else if options.spiral_sidecar_sha256.is_some() {
        return Err("packing: only {'profile': 'spiral', 'sidecar_sha256': ...} is defined".to_string());
    }
    if let Some(overlay_of) = options.overlay_of.as_ref().filter(|name| !name.is_empty()) {
        members.insert("overlay_of".to_string(), json!(overlay_of));
    }
    if let Some(flow_sha256) = flow_sha256 {
        members.insert("flow_sha256".to_string(), json!(flow_sha256));
    }
    let sig = load_private(priv_path)?.sign(&signed_bytes(&manifest).map_err(|error| error.to_string())?);
    write_signed_document(&format!("{ppt_path}.manifest.json"), &manifest)?;
    std::fs::write(format!("{ppt_path}.manifest.sig"), sig.to_bytes()).map_err(|error| error.to_string())?;
    Ok(manifest)
}

/// Python's `recorded == count` for a JSON value against a non-negative integer: `12`, `12.0` and
/// `true` (for 1) are all equal in Python, a string or null never is.
fn py_number_equals(recorded: &Value, count: u64) -> bool {
    match recorded {
        Value::Number(number) => {
            number.as_u64().map_or_else(|| number.as_f64().is_some_and(|float| float == count as f64), |exact| exact == count)
        }
        Value::Bool(flag) => u64::from(*flag) == count,
        _ => false,
    }
}

/// The six header counts a manifest signs, in the order the reference checks them.
pub const COUNT_NAMES: [&str; 6] = ["atoms", "nodes", "edges", "prog_words", "max_steps", "max_stack"];

/// The signed `counts` against the image header, then a signed `wcet_cycles` against the bound
/// recomputed from the image, independently (`policy_pack.check_counts`). Empty when both hold. A pack's
/// manifest and a distribution envelope's `meta` carry the same members and are checked here alike. A
/// `counts` that is not an object is `manifest:count-mismatch:counts`, and a header that does not read
/// is its own reason.
pub fn check_counts(signed: &Value, image: &[u8]) -> Vec<String> {
    let header = match read_ppt_header(image) {
        Ok(header) => header,
        Err(error) => return vec![error],
    };
    let counts = match signed.get("counts") {
        None => None,
        Some(Value::Object(counts)) => Some(counts),
        Some(_) => return vec!["manifest:count-mismatch:counts".to_string()],
    };
    for count_name in COUNT_NAMES {
        let recorded = counts.and_then(|counts| counts.get(count_name));
        if !recorded.is_some_and(|value| py_number_equals(value, header.count(count_name))) {
            return vec![format!("manifest:count-mismatch:{count_name}")];
        }
    }
    if let Some(recorded) = signed.get("wcet_cycles") {
        match wcet_cycles(image) {
            Ok(cycles) if py_number_equals(recorded, cycles) => {}
            Ok(_) => return vec!["manifest:wcet-mismatch".to_string()],
            Err(error) => return vec![error],
        }
    }
    Vec::new()
}

/// The registry name a refusal reason carries: a parameterized reason has a `:<detail>` past the name
/// (`causes.reason_name`), so `manifest:count-mismatch:atoms` is `manifest:count-mismatch`.
pub fn reason_name(reason: &str) -> &str {
    match reason.match_indices(':').nth(1) {
        Some((index, _)) => &reason[..index],
        None => reason,
    }
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
    if !std::path::Path::new(&man_path).exists() || !std::path::Path::new(&sig_path).exists() {
        return (false, vec!["sig:missing".to_string()], None);
    }
    let (Ok(man_bytes), Ok(sig_bytes)) = (std::fs::read(&man_path), std::fs::read(&sig_path)) else {
        return (false, vec!["sig:missing".to_string()], None); // present but unreadable: no signature to use
    };
    // The registry's `manifest:bad-format` is "manifest unparseable": text that is not UTF-8 or JSON, holds
    // NaN, Infinity or a number beyond the double range, or is not an object, is that refusal with no manifest.
    let read = String::from_utf8(man_bytes).ok().map(|man_text| durable::read_document(&man_text));
    if let Some(Err(error)) = &read {
        if error.is_not_canonical() {
            // canon/2 in a spelling other than its canonical bytes: its own registered cause, never respelled
            return (false, vec![durable::NOT_CANONICAL_CAUSE.to_string()], None);
        }
    }
    let Some(manifest) = read.and_then(Result::ok).filter(|parsed| parsed.is_object()) else {
        return (false, vec!["manifest:bad-format".to_string()], None);
    };
    if manifest.get("format").and_then(|value| value.as_str()) != Some(PACK_FORMAT) {
        return (false, vec!["manifest:bad-format".to_string()], Some(manifest));
    }

    let Ok(payload) = signed_bytes(&manifest) else {
        return (false, vec!["manifest:bad-format".to_string()], Some(manifest));
    };
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
    let reasons = check_counts(&manifest, &image);
    if !reasons.is_empty() {
        return (false, reasons, Some(manifest));
    }
    if let Some(packing) = manifest.get("packing") {
        if packing.get("profile").and_then(|value| value.as_str()) != Some("spiral") {
            return (false, vec!["packing:unknown-profile".to_string()], Some(manifest));
        }
        let Ok(sidecar) = std::fs::read(format!("{ppt_path}.spiral")) else {
            return (false, vec!["spiral:sidecar-missing".to_string()], Some(manifest));
        };
        if packing.get("sidecar_sha256").and_then(|value| value.as_str()) != Some(sha256_hex(&sidecar).as_str()) {
            return (false, vec!["spiral:sidecar-hash-mismatch".to_string()], Some(manifest));
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
        "encoding": durable::CANON2,
    });
    let sig = load_private(priv_path)?.sign(&signed_bytes(&env).map_err(|error| error.to_string())?);
    std::fs::create_dir_all(out_dir).map_err(|error| error.to_string())?;
    let base = format!("{out_dir}/{envelope_id}.envelope");
    write_signed_document(&format!("{base}.json"), &env)?;
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
    let env = match durable::read_document(&text) {
        Ok(env) => env,
        // canon/2, but not its canonical bytes
        Err(error) if error.is_not_canonical() => return (None, vec![durable::NOT_CANONICAL_CAUSE.to_string()]),
        // not canon/2: untagged (canon/1 is retired), another tag, or unreadable
        Err(_) => return (None, vec!["envelope:sig-invalid".to_string()]),
    };
    let Ok(sig_arr): Result<[u8; 64], _> = sig_bytes.as_slice().try_into() else {
        return (None, vec!["envelope:sig-invalid".to_string()]);
    };
    let sig = Signature::from_bytes(&sig_arr);
    let Ok(payload) = signed_bytes(&env) else {
        return (None, vec!["envelope:sig-invalid".to_string()]);
    };
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
