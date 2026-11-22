// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! Policy distribution cross language gate (spec-policy-distribution.md, I1): replay
//! `tests/fixtures/distribution.json`, a byte identical copy of the corpus the Python verifier wrote
//! (`prismpath/portable/conformance/distribution.json`), through the Rust verifier. Every case marked
//! `R` has its own test named for it and must report exactly the cause, the unchanged flag, the time
//! floor and the envelope id Python recorded. The Rust writers are held to the same bytes: each sealed
//! container is written again entry for entry, each envelope that reads is written again from its
//! members, each trust store from its document, and each container the Python writer sealed with the
//! fixed test keys is sealed again by Rust to the same bytes.

use ed25519_dalek::{Signer, SigningKey};
use prismpath_hotswap_rs::dist::envelope::{self as env, Entry};
use prismpath_hotswap_rs::dist::trust::TrustStore;
use prismpath_hotswap_rs::dist::verify::{self, PepView};
use prismpath_hotswap_rs::dist::{ArtifactKind, Hex64};
use prismpath_rs::canon2::{self, codec};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

/// The names the corpus generator's test keys are made from (`gen_distribution_corpus.test_key`).
const KEY_NAMES: [&str; 6] = ["A", "B", "R", "Q", "U", "X"];

fn corpus() -> &'static Value {
    static CORPUS: OnceLock<Value> = OnceLock::new();
    CORPUS.get_or_init(|| {
        let path = format!("{}/tests/fixtures/distribution.json", env!("CARGO_MANIFEST_DIR"));
        serde_json::from_str(&std::fs::read_to_string(path).expect("read distribution.json")).expect("parse distribution.json")
    })
}

fn cases() -> &'static [Value] {
    corpus()["cases"].as_array().expect("the corpus has cases")
}

fn case(name: &str) -> &'static Value {
    cases().iter().find(|case| case["name"] == name).unwrap_or_else(|| panic!("the corpus has no case {name}"))
}

fn runs_on(case: &Value, implementation: &str) -> bool {
    case["runs_on"].as_array().unwrap().iter().any(|item| item == implementation)
}

fn bytes(case: &Value, member: &str) -> Vec<u8> {
    hex::decode(case[member].as_str().unwrap()).unwrap()
}

/// The test key whose seed is the SHA-256 of `prismpath.dist test key <name>`.
fn test_key(name: &str) -> SigningKey {
    SigningKey::from_bytes(&Sha256::digest(format!("prismpath.dist test key {name}").as_bytes()).into())
}

/// The case's trust store, which Rust writes back to the very bytes it read.
fn trust_of(case: &Value) -> TrustStore {
    if case["trust"].is_null() {
        return TrustStore::unreadable();
    }
    let raw = canon2::write_json(&case["trust"]).unwrap();
    let store = TrustStore::from_bytes(&raw).unwrap_or_else(|refused| panic!("{}: {refused}", case["name"]));
    assert_eq!(store.to_bytes().unwrap(), raw, "{}: the trust store is written again byte for byte", case["name"]);
    store
}

fn pep_of(case: &Value) -> PepView {
    codec::from_doc(canon2::from_json(&case["pep"]).unwrap()).unwrap_or_else(|error| panic!("{}: {error}", case["name"]))
}

/// The verdict of the Rust verifier on one case, in the corpus's `expect` form.
fn decide(case: &Value) -> Value {
    let verdict = verify::verify(&bytes(case, "sealed"), &bytes(case, "body"), &trust_of(case), &pep_of(case), case["now"].as_i64().unwrap());
    json!({"cause": verdict.cause, "unchanged": verdict.unchanged, "time_floor": verdict.time_floor,
           "envelope_id": verdict.envelope.map(|envelope| envelope.envelope_id().to_string())})
}

/// True when the Rust writers give back the case's bytes, and whether its container was the Python
/// writer's own and so was sealed again here.
fn written_again(case: &Value) -> bool {
    let sealed = bytes(case, "sealed");
    let Ok((envelope_bytes, entries)) = env::unseal(&sealed) else { return false };
    assert_eq!(env::seal_entries(envelope_bytes, &entries), sealed, "{}: the container entry for entry", case["name"]);
    if let Ok(envelope) = env::read(envelope_bytes) {
        assert_eq!(envelope.to_bytes().unwrap(), envelope_bytes, "{}: the envelope from its members", case["name"]);
    }
    let message = env::signed_message(envelope_bytes);
    let signers: Option<Vec<SigningKey>> = entries.iter().map(|entry: &Entry| {
        KEY_NAMES.iter().map(|name| test_key(name)).find(|key| {
            env::key_id(&key.verifying_key().to_bytes()).raw() == entry.key_id && key.sign(&message).to_bytes() == entry.signature
        })
    }).collect();
    match signers.map(|signers| env::seal(envelope_bytes, &signers)) {
        Some(Ok(resealed)) => {
            assert_eq!(resealed, sealed, "{}: sealed again by the Rust writer", case["name"]);
            true
        }
        _ => false,
    }
}

fn replay(name: &str) {
    let case = case(name);
    assert!(runs_on(case, "R"), "{name} does not run on Rust");
    assert_eq!(decide(case), case["expect"], "{name}");
    written_again(case);
}

macro_rules! rust_cases {
    ($($(#[$doc:meta])* $test:ident => $name:literal,)+) => {
        $(
            $(#[$doc])*
            #[test]
            fn $test() {
                replay($name);
            }
        )+
        /// Every corpus case a test above replays.
        const NAMED: &[&str] = &[$($name),+];
    };
}

rust_cases! {
    /// case_001: E1, E2, E3, S1, S2.
    case_001_round_trip => "001_round_trip",
    /// case_002: E1, V4.
    case_002_member_missing => "002_member_missing",
    /// case_003: E1, V4.
    case_003_member_extra => "003_member_extra",
    /// case_004: E2, V4.
    case_004_members_out_of_order => "004_members_out_of_order",
    /// case_005: E8.
    case_005_unknown_artifact => "005_unknown_artifact",
    /// case_005: E8.
    case_005_unknown_target => "005_unknown_target",
    /// case_006: E5.
    case_006_expires_not_above_not_before => "006_expires_not_above_not_before",
    /// case_007: E6, V2.
    case_007_envelope_2049_bytes => "007_envelope_2049_bytes",
    /// case_007: E6, V2.
    case_007_body_over_bound => "007_body_over_bound",
    /// case_008: S2, V2.
    case_008_wrong_magic => "008_wrong_magic",
    /// case_008: S2, V2.
    case_008_wrong_version => "008_wrong_version",
    /// case_008: S2, V2.
    case_008_short => "008_short",
    /// case_008: S2, V2.
    case_008_unsorted_entries => "008_unsorted_entries",
    /// case_008: S2, V2.
    case_008_repeated_key => "008_repeated_key",
    /// case_008: S2, V2.
    case_008_zero_entries => "008_zero_entries",
    /// case_008: S2, V2.
    case_008_five_entries => "008_five_entries",
    /// case_009: S1, S5.
    case_009_over_the_envelope_bytes_alone => "009_over_the_envelope_bytes_alone",
    /// case_009: S1, S5.
    case_009_another_payload_type => "009_another_payload_type",
    /// case_010: S3, S5, V3.
    case_010_unknown_key_only => "010_unknown_key_only",
    /// case_011: S3, S4.
    case_011_trusted_and_unknown => "011_trusted_and_unknown",
    /// case_012: S3, S4.
    case_012_trusted_good_and_trusted_failing_is_skipped => "012_trusted_good_and_trusted_failing_is_skipped",
    /// case_013: S5.
    case_013_revoked_key_only => "013_revoked_key_only",
    /// case_013: S5.
    case_013_retired_key_only => "013_retired_key_only",
    // case 16's X3 half, that the PEP allows nothing, is the Rust PEP's (PR 14), so it is not claimed here
    case_016_trust_store_unreadable => "016_trust_store_unreadable",
    /// case_020: Q1, Q2, V8.
    case_020_seq_below_floor => "020_seq_below_floor",
    /// case_021: Q3.
    case_021_seq_at_floor_committed_id => "021_seq_at_floor_committed_id",
    /// case_022: Q3.
    case_022_seq_at_floor_other_id => "022_seq_at_floor_other_id",
    /// case_028: T3, V6.
    case_028_not_before_301_ahead => "028_not_before_301_ahead",
    /// case_028: T3, V6.
    case_028_not_before_299_ahead => "028_not_before_299_ahead",
    /// case_029: T4, V6.
    case_029_time_equals_expires => "029_time_equals_expires",
    /// case_029: T4, V6.
    case_029_time_one_second_before_expires => "029_time_one_second_before_expires",
    /// case_039: V1.
    case_039_two_failures_report_the_earlier => "039_two_failures_report_the_earlier",
    /// case_040: V5.
    case_040_another_target_kind => "040_another_target_kind",
    /// case_040: V5.
    case_040_an_artifact_the_kind_does_not_use => "040_an_artifact_the_kind_does_not_use",
    /// case_040: V5.
    case_040_another_stream => "040_another_stream",
    /// case_041: V7, R2.
    case_041_envelope_id_revoked => "041_envelope_id_revoked",
    /// case_041: V7, R2.
    case_041_policy_hash_revoked => "041_policy_hash_revoked",
    /// case_042: V9.
    case_042_body_one_byte_short => "042_body_one_byte_short",
    /// case_042: V9.
    case_042_body_one_byte_changed => "042_body_one_byte_changed",
    /// case_044: V11.
    case_044_counts_differ => "044_counts_differ",
    /// case_044: V11.
    case_044_over_a_qualification_cap => "044_over_a_qualification_cap",
    /// case_044: V11.
    case_044_wrong_wcet => "044_wrong_wcet",
    /// case_127: E11, V4.
    case_127_fields_a_string => "127_fields_a_string",
    /// case_127: E11, V4.
    case_127_counts_an_integer => "127_counts_an_integer",
    /// case_127: E11, V4.
    case_127_counts_lacking_a_member => "127_counts_lacking_a_member",
    /// case_127: E11, V4.
    case_127_packing_without_its_sidecar => "127_packing_without_its_sidecar",
    /// case_114: E7, E10, V10.
    case_114_staged_release_id_differs => "114_staged_release_id_differs",
    /// case_117: S6.
    case_117_signed_with_an_entry_added => "117_signed_with_an_entry_added",
    /// case_117: S6.
    case_117_signed_with_its_counting_entry_removed => "117_signed_with_its_counting_entry_removed",
    /// case_117: S6.
    case_117_unsigned_with_a_failing_entry_added => "117_unsigned_with_a_failing_entry_added",
    /// case_118: K4, S3.
    case_118_unknown_role_signs => "118_unknown_role_signs",
    // case 72's verdict; applying the rotation and the commit are the Rust PEP's (PR 14), so it is not claimed here
    case_072_signed_by_the_old_and_the_new_key => "072_signed_by_the_old_and_the_new_key",
    // case 72's verdict; applying the rotation and the commit are the Rust PEP's (PR 14), so it is not claimed here
    case_072_a_pack_under_the_new_key => "072_a_pack_under_the_new_key",
    // case 73's verdict; the release staying active is the Rust PEP's (PR 14), so it is not claimed here
    case_073_a_pack_signed_by_the_retired_key => "073_a_pack_signed_by_the_retired_key",
    /// case_074: O2.
    case_074_signed_only_by_an_unknown_key => "074_signed_only_by_an_unknown_key",
    /// case_074: O2.
    case_074_without_the_new_key => "074_without_the_new_key",
    /// case_075: O3, O4.
    case_075_retiring_an_unknown_key => "075_retiring_an_unknown_key",
    /// case_075: O3, O4.
    case_075_adding_a_revoked_key => "075_adding_a_revoked_key",
    /// case_076: O1.
    case_076_a_rotation_after_a_revocation_at_its_seq => "076_a_rotation_after_a_revocation_at_its_seq",
    /// case_131: K5.
    case_131_a_ninth_key => "131_a_ninth_key",
    /// case_131: K5.
    case_131_a_pack_by_the_first_of_seventeen_retired => "131_a_pack_by_the_first_of_seventeen_retired",
    // case 123's verdict; applying the rotations is the Rust PEP's (PR 14), so it is not claimed here
    case_123_two_above_the_trust_sequence => "123_two_above_the_trust_sequence",
    // case 123's verdict; applying the rotations is the Rust PEP's (PR 14), so it is not claimed here
    case_123_the_same_once_the_skipped_one_is_in => "123_the_same_once_the_skipped_one_is_in",
    // case 66's verdict; applying the list is the Rust PEP's (PR 14), so it is not claimed here
    case_066_one_above_the_trust_sequence => "066_one_above_the_trust_sequence",
    // case 66's verdict; applying the list is the Rust PEP's (PR 14), so it is not claimed here
    case_066_the_same_one_again => "066_the_same_one_again",
    // case 66's verdict; applying the list is the Rust PEP's (PR 14), so it is not claimed here
    case_066_an_older_one => "066_an_older_one",
    // case 66's verdict; applying the list is the Rust PEP's (PR 14), so it is not claimed here
    case_066_one_that_skips_a_number => "066_one_that_skips_a_number",
    /// case_067: R2.
    case_067_a_pack_signed_by_a_revoked_key => "067_a_pack_signed_by_a_revoked_key",
    /// case_068: R4, Q4.
    case_068_a_release_below_a_raised_floor => "068_a_release_below_a_raised_floor",
    // case 70's verdict; applying the list is the Rust PEP's (PR 14), so it is not claimed here
    case_070_a_later_list_dropping_the_key => "070_a_later_list_dropping_the_key",
    // case 70's verdict; applying the list is the Rust PEP's (PR 14), so it is not claimed here
    case_070_the_key_still_refused => "070_the_key_still_refused",
    // case 130's verdict; applying the list is the Rust PEP's (PR 14), so it is not claimed here
    case_130_a_floor_past_a_revoked_envelope => "130_a_floor_past_a_revoked_envelope",
    // case 130's verdict; applying the list is the Rust PEP's (PR 14), so it is not claimed here
    case_130_the_next_list_dropping_it => "130_the_next_list_dropping_it",
    // case 130's verdict; applying the list is the Rust PEP's (PR 14), so it is not claimed here
    case_130_the_envelope_again => "130_the_envelope_again",
    /// case_071: R7.
    case_071_sixty_five_entries => "071_sixty_five_entries",
    // case 79's verdict; applying the list is the Rust PEP's (PR 14), so it is not claimed here
    case_079_trust_kind_with_expires => "079_trust_kind_with_expires",
    // case 79's verdict; applying the list is the Rust PEP's (PR 14), so it is not claimed here
    case_079_revocation_read_years_later => "079_revocation_read_years_later",
}

#[test]
fn every_case_the_corpus_runs_on_rust_has_its_test() {
    let mut rust: Vec<&str> = cases().iter().filter(|case| runs_on(case, "R")).map(|case| case["name"].as_str().unwrap()).collect();
    let mut named = NAMED.to_vec();
    rust.sort_unstable();
    named.sort_unstable();
    assert_eq!(named, rust);
}

#[test]
fn every_case_on_a_kind_rust_has_built_decides_as_python_did() {
    // the host cases that run on Python alone included: one verifier answers alike everywhere it runs. The
    // mesh cases are the C core's, a kind this crate has not built.
    let mut decided = 0;
    for case in cases().iter().filter(|case| case["pep"]["kind"] == "host") {
        assert_eq!(decide(case), case["expect"], "{}", case["name"]);
        decided += 1;
    }
    assert!(decided > NAMED.len(), "{decided} host cases");
}

#[test]
fn the_rust_writer_seals_every_container_the_python_writer_sealed_to_the_same_bytes() {
    let resealed = cases().iter().filter(|case| written_again(case)).count();
    // every case but the containers written by hand to be refused, and the signatures made over other bytes
    assert!(resealed >= 38, "only {resealed} containers were sealed again");
}

/// case_001: E1, E2, E3, S1, S2. The round trip written from the envelope's members by the Rust writer.
#[test]
fn case_001_round_trip_is_built_and_sealed_from_its_members_byte_for_byte() {
    let case = case("001_round_trip");
    let sealed = bytes(case, "sealed");
    let (envelope_bytes, _) = env::unseal(&sealed).unwrap();
    let read = env::read(envelope_bytes).unwrap();
    let mut doc = (*read).clone();
    doc.body_sha256 = Hex64::zero();
    doc.body_size = 0;
    let built = env::build(doc, &bytes(case, "body")).unwrap();
    assert_eq!(built, envelope_bytes);
    assert_eq!(env::seal(&built, &[test_key("A")]).unwrap(), sealed);
    assert_eq!(env::envelope_id(&built).to_string(), case["expect"]["envelope_id"].as_str().unwrap());
}

/// case_115: E10. The signer's release id for three artifacts, and for the same three with one body changed.
#[test]
fn case_115_release_ids_are_the_sha256_of_the_sorted_pairs() {
    let vectors = corpus()["release_ids"].as_array().unwrap();
    assert!(!vectors.is_empty());
    for vector in vectors {
        assert_eq!(vector["case"], 115);
        assert!(runs_on(vector, "R"));
        let pairs: Vec<(ArtifactKind, Hex64)> = vector["artifacts"].as_array().unwrap().iter().map(|pair| {
            (ArtifactKind::from_name(pair[0].as_str().unwrap()).unwrap(), Hex64::try_from(pair[1].as_str().unwrap()).unwrap())
        }).collect();
        assert_eq!(env::release_id(&pairs).unwrap().to_string(), vector["release"].as_str().unwrap(), "{}", vector["name"]);
        let mut reversed = pairs.clone();
        reversed.reverse();
        assert_eq!(env::release_id(&reversed).unwrap(), env::release_id(&pairs).unwrap(), "the order given does not matter");
    }
    assert_ne!(vectors[0]["release"], vectors[1]["release"]);
}

/// The verdict on case 001's envelope with `change` made to its `meta`, written by hand (the writer
/// refuses it) and sealed by the authority key.
fn with_meta(change: impl Fn(&mut serde_json::Map<String, Value>)) -> Option<String> {
    let case = case("001_round_trip");
    let sealed = bytes(case, "sealed");
    let (envelope_bytes, _) = env::unseal(&sealed).unwrap();
    let mut doc: Value = serde_json::from_slice(envelope_bytes).unwrap();
    change(doc["meta"].as_object_mut().unwrap());
    let raw = canon2::write_json(&doc).unwrap();
    assert!(env::read(&raw).is_err() && doc_refused_by_writer(&raw), "the writer refuses what the reader refuses");
    let resealed = env::seal(&raw, &[test_key("A")]).unwrap();
    verify::verify(&resealed, &bytes(case, "body"), &trust_of(case), &pep_of(case), case["now"].as_i64().unwrap()).cause
}

fn doc_refused_by_writer(raw: &[u8]) -> bool {
    codec::from_bytes::<env::EnvelopeDoc>(raw).map_or(true, |doc| doc.to_bytes().is_err())
}

// E11 and V4: the forms of every meta member beyond the four parts of case 127 the corpus holds.
#[test]
fn each_other_meta_form_is_held_at_v4() {
    let refused: [(&str, Value); 8] = [
        ("counts", json!({"atoms": 70000, "nodes": 1, "edges": 1, "prog_words": 1, "max_steps": 1, "max_stack": 1})),
        ("fields", json!({"x": 1})),
        ("wcet_cycles", json!(-1)),
        ("qualification", json!("")),
        ("qualification", json!("q".repeat(129))),
        ("flow_sha256", json!("AB".repeat(32))),
        ("overlay_of", json!(null)),
        ("packing", json!({"profile": "spiral", "sidecar_sha256": "ab".repeat(32), "note": "x"})),
    ];
    for (member, value) in refused {
        let cause = with_meta(|meta| { meta.insert(member.into(), value.clone()); });
        assert_eq!(cause.as_deref(), Some("dist:bad-format"), "meta.{member} = {value}");
    }
    // a well formed packing with another profile reads, and V11 then names the profile
    let case = case("001_round_trip");
    let sealed = bytes(case, "sealed");
    let (envelope_bytes, _) = env::unseal(&sealed).unwrap();
    let mut doc: Value = serde_json::from_slice(envelope_bytes).unwrap();
    doc["meta"]["packing"] = json!({"profile": "zigzag", "sidecar_sha256": "ab".repeat(32)});
    let raw = canon2::write_json(&doc).unwrap();
    let resealed = env::seal(&raw, &[test_key("A")]).unwrap();
    let verdict = verify::verify(&resealed, &bytes(case, "body"), &trust_of(case), &pep_of(case), case["now"].as_i64().unwrap());
    assert_eq!(verdict.cause.as_deref(), Some("packing:unknown-profile"));
}

#[test]
fn the_net_edge_and_sandbox_profile_meta_forms_are_read_at_v4() {
    let case = case("001_round_trip");
    let sealed = bytes(case, "sealed");
    let (envelope_bytes, _) = env::unseal(&sealed).unwrap();
    let reads = |artifact: &str, meta: Value| {
        let mut doc: Value = serde_json::from_slice(envelope_bytes).unwrap();
        doc["artifact"] = json!(artifact);
        doc["meta"] = meta;
        env::read(&canon2::write_json(&doc).unwrap()).map(|_| ()).map_err(|refused| refused.cause)
    };
    let hash = "ab".repeat(32);
    assert_eq!(reads("net.edge", json!({"flow_sha256": hash, "names_sha256": hash, "qualification": "q"})), Ok(()));
    assert_eq!(reads("net.edge", json!({"flow_sha256": hash, "names_sha256": "x", "qualification": "q"})), Err("dist:bad-format"));
    assert_eq!(reads("net.edge", json!({"flow_sha256": hash, "qualification": "q"})), Err("dist:bad-format"));
    assert_eq!(reads("sandbox.profile", json!({"compiler": 1})), Ok(()));
    assert_eq!(reads("sandbox.profile", json!({"compiler": 0})), Err("dist:bad-format"));
    assert_eq!(reads("sandbox.profile", json!({"compiler": "1"})), Err("dist:bad-format"));
    assert_eq!(reads("policy.core", json!({})), Ok(()));
    assert_eq!(reads("policy.core", json!({"note": "x"})), Err("dist:bad-format"));
}

/// Case 001's envelope rewritten as a trust kind, sealed by the authority key, and its verdict on the host.
fn as_trust_kind(artifact: &str, stream: &str) -> Option<String> {
    let case = case("001_round_trip");
    let sealed = bytes(case, "sealed");
    let (envelope_bytes, _) = env::unseal(&sealed).unwrap();
    let mut doc: Value = serde_json::from_slice(envelope_bytes).unwrap();
    doc["artifact"] = json!(artifact);
    doc["stream"] = json!(stream);
    doc["meta"] = json!({});
    doc["expires"] = json!(0);
    if stream == env::TRUST_STREAM {
        doc["policy_sha256"] = json!("0".repeat(64));
        doc["release"] = json!("0".repeat(64));
    }
    let raw = canon2::write_json(&doc).unwrap();
    let resealed = env::seal(&raw, &[test_key("A")]).unwrap();
    verify::verify(&resealed, &bytes(case, "body"), &trust_of(case), &pep_of(case), case["now"].as_i64().unwrap()).cause
}

#[test]
fn v5_admits_only_the_trust_kinds_the_host_machine_applies() {
    // the host applies all three trust kinds. A revocation or a rotation passes V5 to V9, since its body is the
    // image it names, and V11 then reads no trust body there
    assert_eq!(as_trust_kind("trust.revocation", env::TRUST_STREAM).as_deref(), Some("dist:bad-format"));
    assert_eq!(as_trust_kind("trust.rotation", env::TRUST_STREAM).as_deref(), Some("dist:bad-format"));
    // a widening passes V5 to V9, since its body is the image it names, and V11 then reads no widening there
    assert_eq!(as_trust_kind("trust.widening", "host/demo").as_deref(), Some("dist:bad-format"));
}

#[test]
fn the_body_bound_is_the_smaller_of_the_peps_and_its_kinds() {
    let case = case("001_round_trip");
    let mut pep = pep_of(case);
    pep.body_bound = i64::MAX;
    let body = vec![0u8; (env::MAX_BODY + 1) as usize];
    let verdict = verify::verify(&bytes(case, "sealed"), &body, &trust_of(case), &pep, case["now"].as_i64().unwrap());
    assert_eq!(verdict.cause.as_deref(), Some("dist:too-large"));
}
