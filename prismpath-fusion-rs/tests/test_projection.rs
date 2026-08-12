//! Mirrors adapters/fusion/tests/test_projection.py — the decidable cyber projection, the verdict
//! clamp, IMU normalization, and an end-to-end pass over the REAL recorded sensor sessions.

use prismpath_fusion_rs::*;
use serde_json::json;

#[test]
fn projection_matrix() {
    for (level, expected) in [
        (0, "ignore"),
        (3, "ignore"),
        (6, "ignore"),
        (7, "watch"),
        (11, "watch"),
        (12, "contain"),
        (15, "contain"),
    ] {
        assert_eq!(soc_action_from_level(level), expected, "level {level}");
    }
}

#[test]
fn projection_is_monotone_in_severity() {
    let rank = |a: &str| match a {
        "ignore" => 0,
        "watch" => 1,
        _ => 2,
    };
    let mut prev = -1i64;
    for level in 0..20 {
        let cur = rank(soc_action_from_level(level));
        assert!(cur >= prev, "severity regressed at level {level}");
        prev = cur;
    }
}

#[test]
fn verdict_clamp_is_escalation_default() {
    let cases = [
        (Some(json!({"recommended_action": "contain"})), "contain"),
        (Some(json!({"recommended_action": "watch"})), "watch"),
        (Some(json!({"recommended_action": "ignore"})), "ignore"),
        (Some(json!({"recommended_action": "nuke_it"})), "watch"), // out-of-vocab clamps up
        (Some(json!({"recommended_action": null})), "watch"),
        (Some(json!({})), "watch"),
        (None, "watch"),
    ];
    for (verdict, expected) in cases {
        assert_eq!(soc_action_from_verdict(verdict.as_ref()), expected);
    }
}

#[test]
fn session1_label_drift_maps_to_still() {
    let row = json!({"stability": "On Table", "accel_mg": [66, -363, 9691], "ts": 1.0});
    let out = normalize_imu(&row).expect("posture row");
    assert_eq!(out.stability, "still");
    assert!(out.derived);
    // expected = abs(round(sqrt(66^2+363^2+9691^2)) - 9806), banker's rounding
    let mag = ((66f64 * 66.0) + (363.0 * 363.0) + (9691.0 * 9691.0)).sqrt();
    let expected = (mag.round() as i64 - 9806).abs(); // no .5 case here; plain round matches
    assert_eq!(out.dev_mg, Some(expected));
}

#[test]
fn canonical_row_passes_through_native_dev_mg() {
    let row = json!({"stability": "shaken", "dev_mg": 3100, "accel_mg": [0, 0, 9806], "ts": 2.0});
    let out = normalize_imu(&row).expect("posture row");
    assert_eq!(
        out,
        NormalizedImu {
            stability: "shaken".into(),
            dev_mg: Some(3100),
            ts: Some(2.0),
            derived: false
        }
    );
}

#[test]
fn unknown_label_passes_through_lowercased_for_the_other_cell() {
    let out = normalize_imu(&json!({"stability": "In Motion", "dev_mg": 10})).unwrap();
    assert_eq!(out.stability, "in motion"); // not silently coerced; lands in OTHER
}

#[test]
fn row_without_posture_is_none() {
    assert!(normalize_imu(&json!({"decision": "watch", "us": 128.4, "error_rate": 0})).is_none());
}

#[test]
fn fused_reading_contract() {
    let imu = NormalizedImu { stability: "still".into(), dev_mg: Some(0), ts: None, derived: false };
    let r = fused_reading(8, "watch", &imu).unwrap();
    use prismpath_rs::V;
    assert_eq!(r["stability"], V::Str("still".into()));
    assert_eq!(r["dev_mg"], V::Num(0.0));
    assert_eq!(r["rule_level"], V::Num(8.0));
    assert_eq!(r["soc_action"], V::Str("watch".into()));
}

#[test]
fn fused_reading_refuses_missing_dev_mg() {
    let imu = NormalizedImu { stability: "still".into(), dev_mg: None, ts: None, derived: false };
    assert!(fused_reading(8, "watch", &imu).is_err());
}

// ------------------------------------------- the real sessions, end to end (read-only)

fn evidence(fname: &str) -> Option<String> {
    let p = format!("{}/../prismpath-hw/evidence/{}", env!("CARGO_MANIFEST_DIR"), fname);
    std::fs::read_to_string(p).ok()
}

#[test]
fn real_sessions_normalize_fully() {
    for fname in
        ["mac_bridge_session1.ndjson", "mac_bridge_sessions2-5.ndjson", "fabric_session1.ndjson"]
    {
        let Some(text) = evidence(fname) else { continue }; // skip if not in this checkout
        let (mut n, mut dropped, mut uncanonical, mut missing_dev) = (0, 0, 0, 0);
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let row: serde_json::Value = serde_json::from_str(line).expect("ndjson row");
            n += 1;
            match normalize_imu(&row) {
                None => dropped += 1,
                Some(out) => {
                    if !CANONICAL_STABILITY.contains(&out.stability.as_str()) {
                        uncanonical += 1;
                    }
                    if out.dev_mg.is_none() {
                        missing_dev += 1;
                    }
                }
            }
        }
        assert!(n > 0, "{fname}: empty");
        assert_eq!(dropped, 0, "{fname}: posture sessions must not drop rows");
        assert_eq!(uncanonical, 0, "{fname}: every real label must canonicalize");
        assert_eq!(missing_dev, 0, "{fname}: every posture row must yield dev_mg");
    }
}

#[test]
fn pure_routing_logs_are_excluded() {
    for fname in ["fabric_recert_float_chained.ndjson", "fabric_hotswap_midstream.ndjson"] {
        let Some(text) = evidence(fname) else { continue };
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let row: serde_json::Value = serde_json::from_str(line).expect("ndjson row");
            assert!(normalize_imu(&row).is_none(), "{fname}: routing record must yield None");
        }
    }
}
