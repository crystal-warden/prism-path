//! Hot-swap cross-language gate: replay `conformance/hotswap.json` — a Python-signed pack and
//! its full negative matrix — through the Rust gates, matching Python's verdicts EXACTLY
//! (ok + stable reason strings). Then the PolicyHost pipeline (version floor, rollback, audit),
//! and the bidirectional leg: a Rust-signed pack verified by the Python reference.

use base64::Engine;
use prismpath_hotswap_rs::host::PolicyHost;
use prismpath_hotswap_rs::*;
use serde_json::Value;

fn fixtures() -> Value {
    let path = format!(
        "{}/../prismpath/portable/conformance/hotswap.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("read hotswap.json"))
        .expect("parse hotswap.json")
}

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("pp_hotswap_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Write one fixture case's pack files to disk; returns (ppt_path, pub_paths).
fn stage_case(dir: &std::path::Path, c: &Value) -> (String, Vec<String>) {
    let image = base64::engine::general_purpose::STANDARD
        .decode(c["image_b64"].as_str().unwrap())
        .unwrap();
    let ppt = dir.join("policy.ppt");
    std::fs::write(&ppt, &image).unwrap();
    std::fs::write(
        dir.join("policy.ppt.manifest.json"),
        serde_json::to_string_pretty(&c["manifest"]).unwrap(),
    )
    .unwrap();
    std::fs::write(
        dir.join("policy.ppt.manifest.sig"),
        hex::decode(c["sig_hex"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    let mut pubs = Vec::new();
    for (i, p) in c["pubs"].as_array().unwrap().iter().enumerate() {
        let path = dir.join(format!("key{i}.pub"));
        std::fs::write(&path, hex::decode(p.as_str().unwrap()).unwrap()).unwrap();
        pubs.push(path.to_str().unwrap().to_string());
    }
    (ppt.to_str().unwrap().to_string(), pubs)
}

#[test]
fn python_signed_packs_verify_with_identical_verdicts() {
    let fx = fixtures();
    let envelope = &fx["envelope"];
    let cases = fx["cases"].as_array().unwrap();
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let dir = tmpdir(name);
        let (ppt, pubs) = stage_case(&dir, c);
        let revoked: Vec<String> = c["revoked"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r.as_str().unwrap().to_string())
            .collect();

        let (ok, reasons, manifest) = verify_pack(&ppt, &pubs, &revoked);
        assert_eq!(ok, c["verify"]["ok"].as_bool().unwrap(), "{name}: verify ok");
        assert_eq!(
            serde_json::json!(reasons),
            c["verify"]["reasons"],
            "{name}: verify reasons"
        );

        if let Some(env_check) = c.get("envelope_check").filter(|v| !v.is_null()) {
            let image = base64::engine::general_purpose::STANDARD
                .decode(c["image_b64"].as_str().unwrap())
                .unwrap();
            let (eok, ereasons) = check_envelope(manifest.as_ref().unwrap(), &image, envelope);
            assert_eq!(eok, env_check["ok"].as_bool().unwrap(), "{name}: envelope ok");
            assert_eq!(serde_json::json!(ereasons), env_check["reasons"], "{name}: envelope reasons");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
    eprintln!("hotswap verdicts: {}/{} identical to Python", cases.len(), cases.len());
}

#[test]
fn host_pipeline_floor_rollback_and_audit() {
    let fx = fixtures();
    let envelope = fx["envelope"].clone();
    let valid = fx["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "valid")
        .expect("valid case");
    let dir = tmpdir("host");
    let (ppt, pubs) = stage_case(&dir, valid);
    let state = dir.join("state");

    let mut host =
        PolicyHost::new(state.to_str().unwrap(), pubs.clone(), envelope.clone(), Vec::new());

    // 1) valid swap accepted, version floor persisted
    let r = host.swap(&ppt, false);
    assert_eq!(r["ok"], Value::Bool(true), "first swap must be accepted: {r}");
    assert_eq!(r["version"].as_i64(), Some(3));

    // 2) replaying the SAME pack must hit the monotonic floor with Python's reason format
    let r2 = host.swap(&ppt, false);
    assert_eq!(r2["ok"], Value::Bool(false));
    assert_eq!(r2["reasons"], serde_json::json!(["version:not-monotonic:3<=3"]));

    // 3) the floor survives a fresh host on the same state dir
    let mut host2 = PolicyHost::new(state.to_str().unwrap(), pubs, envelope, Vec::new());
    let r3 = host2.swap(&ppt, false);
    assert_eq!(r3["reasons"], serde_json::json!(["version:not-monotonic:3<=3"]));

    // 4) after only ONE accepted swap there is no previous policy — rollback must refuse
    //    (mirrors the reference: prev is None on the first swap)
    let rb0 = host.rollback();
    assert_eq!(rb0["ok"], Value::Bool(false));
    assert_eq!(rb0["reasons"], serde_json::json!(["rollback:no-previous"]));

    // 5) an unsigned swap (validate-only path, no version bump) becomes the second active —
    //    then rollback restores the signed v3 policy as last-known-good
    let r4 = host.swap(&ppt, true);
    assert_eq!(r4["ok"], Value::Bool(true), "unsigned swap must be accepted: {r4}");
    assert_eq!(r4["unsigned"], Value::Bool(true));
    let rb = host.rollback();
    assert_eq!(rb["ok"], Value::Bool(true), "rollback must restore last-known-good: {rb}");
    assert_eq!(rb["version"].as_i64(), Some(3));
    assert_eq!(rb["unsigned"], Value::Bool(false));

    // 6) the audit trail (every accept/reject/rollback above) verifies with a real Merkle root
    let _ = host.attest();
    assert!(host.audit.verify_log(), "audit log must verify");
    assert!(!host.audit.current_root().is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Bidirectional leg: Rust signs a pack; the PYTHON reference verifies it. Skips cleanly when
/// the Python environment isn't available (the Rust-side gates above still ran).
#[test]
fn rust_signed_pack_verifies_in_python() {
    let repo = format!("{}/..", env!("CARGO_MANIFEST_DIR"));
    let python = format!("{repo}/.venv/bin/python");
    if !std::path::Path::new(&python).exists() {
        eprintln!("SKIP: no .venv python for the bidirectional leg");
        return;
    }
    let fx = fixtures();
    let valid = fx["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "valid")
        .expect("valid case");
    let dir = tmpdir("bidir");
    let image = base64::engine::general_purpose::STANDARD
        .decode(valid["image_b64"].as_str().unwrap())
        .unwrap();
    let ppt = dir.join("rust_signed.ppt");
    std::fs::write(&ppt, &image).unwrap();

    let (priv_path, pub_path, _key_id) =
        keygen(dir.join("keys").to_str().unwrap(), "rust-authority").unwrap();
    let fields: std::collections::BTreeMap<String, String> =
        [("x".to_string(), "int".to_string())].into_iter().collect();
    build_pack(
        ppt.to_str().unwrap(),
        &fields,
        7,
        "test-env",
        &priv_path,
        &pub_path,
        "2026-08-12T00:00:00+00:00",
    )
    .expect("rust build_pack");

    let script = format!(
        "import sys, json; sys.path.insert(0, {repo:?});\n\
         from prismpath import policy_pack as pp\n\
         ok, reasons, m = pp.verify_pack({ppt:?}, [{pub:?}])\n\
         print(json.dumps({{'ok': ok, 'reasons': reasons, 'version': m and m.get('version')}}))",
        repo = repo,
        ppt = ppt.to_str().unwrap(),
        pub = pub_path,
    );
    let out = std::process::Command::new(&python)
        .arg("-c")
        .arg(&script)
        .output()
        .expect("run python");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let verdict: Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|_| panic!("python failed: {stdout} / {}", String::from_utf8_lossy(&out.stderr)));
    assert_eq!(verdict["ok"], Value::Bool(true), "Python must verify the Rust-signed pack: {verdict}");
    assert_eq!(verdict["version"].as_i64(), Some(7));
    eprintln!("bidirectional: Python verified the Rust-signed pack (version 7)");
    let _ = std::fs::remove_dir_all(&dir);
}
