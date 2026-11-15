//! Hot-swap cross-language gate: replay `conformance/hotswap.json` — a Python-signed pack and
//! its full negative matrix — through the Rust gates, matching Python's verdicts EXACTLY
//! (ok + stable reason strings). Then the PolicyHost pipeline (version floor, rollback, audit),
//! and the bidirectional leg: a Rust-signed pack verified by the Python reference.

mod common;

use base64::Engine;
use common::python_for_cross_language;
use prismpath_hotswap_rs::host::PolicyHost;
use prismpath_hotswap_rs::*;
use serde_json::Value;

fn fixtures() -> Value {
    let path = format!(
        "{}/tests/fixtures/hotswap.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("read hotswap.json"))
        .expect("parse hotswap.json")
}

fn tmpdir(tag: &str) -> common::Scratch {
    common::Scratch::new(&format!("hotswap_{tag}"))
}

/// Write one fixture case's pack files to disk; returns (ppt_path, pub_paths).
fn stage_case(dir: &std::path::Path, case: &Value) -> (String, Vec<String>) {
    let image = base64::engine::general_purpose::STANDARD
        .decode(case["image_b64"].as_str().unwrap())
        .unwrap();
    let ppt = dir.join("policy.ppt");
    std::fs::write(&ppt, &image).unwrap();
    // a case may carry the manifest file's own bytes (not JSON, NaN, not UTF-8 ...), which no `Value` can hold
    let manifest_file = match case.get("manifest_raw_hex").and_then(|value| value.as_str()) {
        Some(raw) => hex::decode(raw).unwrap(),
        None => common::manifest_file(&case["manifest"]),
    };
    std::fs::write(dir.join("policy.ppt.manifest.json"), manifest_file).unwrap();
    std::fs::write(
        dir.join("policy.ppt.manifest.sig"),
        hex::decode(case["sig_hex"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    if let Some(sidecar) = case.get("sidecar_b64").and_then(|value| value.as_str()) {
        std::fs::write(
            dir.join("policy.ppt.spiral"),
            base64::engine::general_purpose::STANDARD.decode(sidecar).unwrap(),
        )
        .unwrap();
    }
    let mut pubs = Vec::new();
    for (key_index, pubkey_hex) in case["pubs"].as_array().unwrap().iter().enumerate() {
        let path = dir.join(format!("key{key_index}.pub"));
        std::fs::write(&path, hex::decode(pubkey_hex.as_str().unwrap()).unwrap()).unwrap();
        pubs.push(path.to_str().unwrap().to_string());
    }
    (ppt.to_str().unwrap().to_string(), pubs)
}

#[test]
fn python_signed_packs_verify_with_identical_verdicts() {
    verdicts_match(&fixtures());
}

fn verdicts_match(fx: &Value) {
    let cases = fx["cases"].as_array().unwrap();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let dir = tmpdir(name);
        let (ppt, pubs) = stage_case(&dir, case);
        let revoked: Vec<String> = case["revoked"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry.as_str().unwrap().to_string())
            .collect();

        let (ok, reasons, manifest) = verify_pack(&ppt, &pubs, &revoked);
        assert_eq!(ok, case["verify"]["ok"].as_bool().unwrap(), "{name}: verify ok");
        assert_eq!(
            serde_json::json!(reasons),
            case["verify"]["reasons"],
            "{name}: verify reasons"
        );

        if let Some(env_check) = case.get("envelope_check").filter(|value| !value.is_null()) {
            let image = base64::engine::general_purpose::STANDARD
                .decode(case["image_b64"].as_str().unwrap())
                .unwrap();
            let envelope = case.get("envelope").unwrap_or(&fx["envelope"]);
            let (eok, ereasons) = check_envelope(manifest.as_ref().unwrap(), &image, envelope);
            assert_eq!(eok, env_check["ok"].as_bool().unwrap(), "{name}: envelope ok");
            assert_eq!(serde_json::json!(ereasons), env_check["reasons"], "{name}: envelope reasons");
        }
    }
    eprintln!("hotswap verdicts: {}/{} identical to Python", cases.len(), cases.len());
}

/// `validate_image` and `read_ppt_header` on bare images: header flags, the signed `safe_node`, the
/// attribute and name hash sections, the node attribute range and the caps, reason for reason.
#[test]
fn image_validation_matches_python() {
    let fx = fixtures();
    let images = fx["images"].as_array().expect("hotswap.json carries `images`");
    for case in images {
        let name = case["name"].as_str().unwrap();
        let image = base64::engine::general_purpose::STANDARD.decode(case["image_b64"].as_str().unwrap()).unwrap();
        let caps: Option<std::collections::BTreeMap<String, u64>> = case.get("caps").map(|caps| {
            caps.as_object().unwrap().iter().map(|(key, value)| (key.clone(), value.as_u64().unwrap())).collect()
        });
        let (ok, reasons) = validate_image(&image, caps.as_ref());
        assert_eq!(ok, case["validate"]["ok"].as_bool().unwrap(), "{name}: validate ok");
        assert_eq!(serde_json::json!(reasons), case["validate"]["reasons"], "{name}: validate reasons");
        match read_ppt_header(&image) {
            Ok(header) => {
                let expect = &case["header"];
                assert_eq!(u64::from(header.flags), expect["flags"].as_u64().unwrap(), "{name}: flags");
                assert_eq!(u64::from(header.safe_node), expect["safe_node"].as_u64().unwrap(), "{name}: safe_node");
                assert_eq!(header.migrate_by_name, expect["migrate_by_name"].as_bool().unwrap(), "{name}: migrate_by_name");
                assert_eq!(header.stateful, expect["stateful"].as_bool().unwrap(), "{name}: stateful");
                for key in ["atoms", "nodes", "edges", "prog_words", "max_steps", "max_stack"] {
                    assert_eq!(header.count(key), expect[key].as_u64().unwrap(), "{name}: {key}");
                }
            }
            Err(error) => assert_eq!(error, case["header_error"].as_str().unwrap(), "{name}: header error"),
        }
    }
    eprintln!("images: {}/{} validate identically to Python", images.len(), images.len());
}

/// Rust builds the manifest members Python builds: the signed WCET, `overlay_of`, the flow derived
/// field dictionary and `flow_sha256`; the dictionary is the one Python derived.
#[test]
fn flow_derived_dictionary_and_manifest_members_match_python() {
    let fx = fixtures();
    let flow = &fx["flow_pack"];
    let flow_text = flow["flow_text"].as_str().unwrap();
    let derived = field_dictionary_of(flow_text).expect("flow defines fields");
    let expected: std::collections::BTreeMap<String, String> = flow["fields"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, text)| (name.clone(), text.as_str().unwrap().to_string()))
        .collect();
    assert_eq!(derived, expected);
    assert!(field_dictionary_of("---\nname: n\nstart: a\n---\n## a\n").is_err(), "no fields, nothing to bind");

    let valid = fx["cases"].as_array().unwrap().iter().find(|case| case["name"] == "valid").unwrap();
    let image = base64::engine::general_purpose::STANDARD.decode(valid["image_b64"].as_str().unwrap()).unwrap();
    let dir = tmpdir("members");
    let ppt = dir.join("policy.ppt");
    std::fs::write(&ppt, &image).unwrap();
    let (priv_path, pub_path, _key_id) = keygen(dir.join("keys").to_str().unwrap(), "rust-authority").unwrap();
    let options = PackOptions {
        overlay_of: Some("baseline-2026-07".to_string()),
        flow_text: Some(flow_text.to_string()),
        spiral_sidecar_sha256: Some(sha256_hex(b"sidecar")),
    };
    let manifest = build_pack_with(
        ppt.to_str().unwrap(), &Default::default(), 4, "test-env", &priv_path, &pub_path, "2026-08-12T00:00:00+00:00", &options,
    )
    .expect("build_pack_with");
    assert_eq!(manifest["fields"], flow["fields"]);
    assert_eq!(manifest["flow_sha256"], flow["flow_sha256"]);
    assert_eq!(manifest["overlay_of"], flow["overlay_of"]);
    assert_eq!(manifest["packing"], serde_json::json!({"profile": "spiral", "sidecar_sha256": sha256_hex(b"sidecar")}));
    assert_eq!(manifest["wcet_cycles"], serde_json::json!(wcet_cycles(&image).unwrap()));
    // a dictionary that disagrees with the flow's own definitions is refused, as the reference refuses it
    let wrong: std::collections::BTreeMap<String, String> = [("x".to_string(), "int".to_string())].into_iter().collect();
    assert!(build_pack_with(ppt.to_str().unwrap(), &wrong, 5, "e", &priv_path, &pub_path, "t", &options).is_err());
}

#[test]
fn host_pipeline_floor_rollback_and_audit() {
    let fx = fixtures();
    let envelope = fx["envelope"].clone();
    let valid = fx["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "valid")
        .expect("valid case");
    let dir = tmpdir("host");
    let (ppt, pubs) = stage_case(&dir, valid);
    let state = dir.join("state");

    let host = PolicyHost::new(state.to_str().unwrap(), pubs.clone(), envelope.clone(), Vec::new()).unwrap();

    // 1) valid swap accepted, version floor persisted
    let swap_result = host.swap(&ppt, false).unwrap();
    assert_eq!(swap_result["ok"], Value::Bool(true), "first swap must be accepted: {swap_result}");
    assert_eq!(swap_result["version"].as_i64(), Some(3));

    // 2) replaying the SAME pack must hit the monotonic floor with Python's reason format
    let r2 = host.swap(&ppt, false).unwrap();
    assert_eq!(r2["ok"], Value::Bool(false));
    assert_eq!(r2["reasons"], serde_json::json!(["version:not-monotonic:3<=3"]));

    // 3) the floor survives a fresh host on the same state dir
    let host2 = PolicyHost::new(state.to_str().unwrap(), pubs, envelope, Vec::new()).unwrap();
    let r3 = host2.swap(&ppt, false).unwrap();
    assert_eq!(r3["reasons"], serde_json::json!(["version:not-monotonic:3<=3"]));

    // 4) after only ONE accepted swap there is no previous policy — rollback must refuse
    //    (mirrors the reference: prev is None on the first swap)
    let rb0 = host.rollback().unwrap();
    assert_eq!(rb0["ok"], Value::Bool(false));
    assert_eq!(rb0["reasons"], serde_json::json!(["rollback:no-previous"]));

    // 5) an unsigned swap (validate-only path, no version bump) becomes the second active —
    //    then rollback restores the signed v3 policy as last-known-good
    let r4 = host.swap(&ppt, true).unwrap();
    assert_eq!(r4["ok"], Value::Bool(true), "unsigned swap must be accepted: {r4}");
    assert_eq!(r4["unsigned"], Value::Bool(true));
    let rb = host.rollback().unwrap();
    assert_eq!(rb["ok"], Value::Bool(true), "rollback must restore last-known-good: {rb}");
    assert_eq!(rb["version"].as_i64(), Some(3));
    assert_eq!(rb["unsigned"], Value::Bool(false));

    // 6) the audit trail (every accept/reject/rollback above) verifies with a real Merkle root
    host.attest().unwrap();
    assert!(host.audit.verify_log(), "audit log must verify");
    assert!(!host.audit.current_root().is_empty());
}

/// Bidirectional leg: Rust signs packs (plain, and with `overlay_of`, the flow derived dictionary
/// and a spiral packing declaration); the PYTHON reference verifies them, recomputing the WCET and
/// re-hashing the sidecar. See `python_for_cross_language` for when this skips.
#[test]
fn rust_signed_pack_verifies_in_python() {
    let repo = format!("{}/..", env!("CARGO_MANIFEST_DIR"));
    let Some(python) = python_for_cross_language(&repo, "the Rust signs, Python verifies leg") else { return };
    let fx = fixtures();
    let valid = fx["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "valid")
        .expect("valid case");
    let dir = tmpdir("bidir");
    let image = base64::engine::general_purpose::STANDARD
        .decode(valid["image_b64"].as_str().unwrap())
        .unwrap();
    let (priv_path, pub_path, _key_id) =
        keygen(dir.join("keys").to_str().unwrap(), "rust-authority").unwrap();
    let fields: std::collections::BTreeMap<String, String> =
        [("x".to_string(), "int".to_string())].into_iter().collect();

    let plain = dir.join("rust_signed.ppt");
    std::fs::write(&plain, &image).unwrap();
    build_pack(plain.to_str().unwrap(), &fields, 7, "test-env", &priv_path, &pub_path, "2026-08-12T00:00:00+00:00")
        .expect("rust build_pack");

    let sidecar = b"spiral sidecar bytes";
    let rich = dir.join("rust_signed_rich.ppt");
    std::fs::write(&rich, &image).unwrap();
    std::fs::write(format!("{}.spiral", rich.to_str().unwrap()), sidecar).unwrap();
    let options = PackOptions {
        overlay_of: Some("baseline-2026-07".to_string()),
        flow_text: Some(fx["flow_pack"]["flow_text"].as_str().unwrap().to_string()),
        spiral_sidecar_sha256: Some(sha256_hex(sidecar)),
    };
    build_pack_with(
        rich.to_str().unwrap(), &Default::default(), 8, "test-env", &priv_path, &pub_path, "2026-08-12T00:00:00+00:00", &options,
    )
    .expect("rust build_pack_with");

    let script = format!(
        "import sys, json; sys.path.insert(0, {repo:?});\n\
         from prismpath.hotswap import policy_pack as pp\n\
         out = {{}}\n\
         for name, path in (('plain', {plain:?}), ('rich', {rich:?})):\n\
         \tok, reasons, m = pp.verify_pack(path, [{pubkey:?}])\n\
         \tout[name] = {{'ok': ok, 'reasons': reasons, 'version': m and m.get('version'), 'wcet': m and m.get('wcet_cycles'), 'wcet_now': pp.wcet_cycles(open(path, 'rb').read()), 'overlay_of': m and m.get('overlay_of'), 'flow_sha256': m and m.get('flow_sha256')}}\n\
         print(json.dumps(out))",
        repo = repo,
        plain = plain.to_str().unwrap(),
        rich = rich.to_str().unwrap(),
        pubkey = pub_path,
    );
    let out = std::process::Command::new(&python)
        .arg("-c")
        .arg(&script)
        .output()
        .expect("run python");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let verdict: Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|_| panic!("python failed: {stdout} / {}", String::from_utf8_lossy(&out.stderr)));
    assert_eq!(verdict["plain"]["ok"], Value::Bool(true), "Python must verify the Rust-signed pack: {verdict}");
    assert_eq!(verdict["plain"]["version"].as_i64(), Some(7));
    assert_eq!(verdict["plain"]["wcet"], verdict["plain"]["wcet_now"], "the signed WCET is the one Python computes");
    assert_eq!(verdict["rich"]["ok"], Value::Bool(true), "Python must verify the Rust-signed pack with packing and overlay: {verdict}");
    assert_eq!(verdict["rich"]["overlay_of"], fx["flow_pack"]["overlay_of"]);
    assert_eq!(verdict["rich"]["flow_sha256"], fx["flow_pack"]["flow_sha256"]);
    eprintln!("bidirectional: Python verified the Rust-signed packs (versions 7 and 8)");
}
