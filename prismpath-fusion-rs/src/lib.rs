//! prismpath-fusion-rs — native port of `adapters/fusion/projection.py` (the fusion adapter's
//! RUNTIME core: both cyber projections and the IMU normalization), feeding the `fusion_triage`
//! flow through the prismpath-rs kernel and the telemetry crate's spiral tessellation.
//!
//! Parity is proven, not asserted: `tests/test_fusion_conformance.rs` replays the SAME frozen
//! corpus the Python adapter passes (`adapters/fusion/conformance/spiral_fusion.json`), and
//! `tests/test_projection.rs` mirrors the Python unit suite. Semantics notes are at the site of
//! each Python-parity subtlety (banker's rounding, `str()` coercion, `int()` truncation).

use prismpath_rs::{py_str, V};
use std::collections::HashMap;

pub const SOC_ACTIONS: [&str; 3] = ["contain", "watch", "ignore"];

/// One standard gravity in the bridge's milli-units (the bridge's own naming, kept for schema
/// compatibility: ~9806 == 1 g).
const GRAVITY_MG: i64 = 9806;

pub const CANONICAL_STABILITY: [&str; 3] = ["still", "moving", "shaken"];

/// The census baseline posture (asserts nothing about the joint distribution).
pub fn assume_still() -> NormalizedImu {
    NormalizedImu { stability: "still".to_string(), dev_mg: Some(0), ts: None, derived: false }
}

/// Decidable projection of a SIEM rule level onto the flow's soc_action vocabulary.
/// 12 is the wazuh_triage containment edge, 7 the SOC triage floor — inherited, not invented.
pub fn soc_action_from_level(level: i64) -> &'static str {
    if level >= 12 {
        "contain"
    } else if level >= 7 {
        "watch"
    } else {
        "ignore"
    }
}

/// Real-adjudicator path; escalation-default clamp on anything unexpected (missing, null, or
/// out-of-vocabulary all clamp to "watch" — never silently benign).
pub fn soc_action_from_verdict(verdict: Option<&serde_json::Value>) -> &'static str {
    let rec = verdict
        .and_then(|v| v.get("recommended_action"))
        .and_then(|r| r.as_str())
        .unwrap_or("watch");
    if SOC_ACTIONS.contains(&rec) {
        // Return the 'static str matching rec
        match rec {
            "contain" => "contain",
            "ignore" => "ignore",
            _ => "watch",
        }
    } else {
        "watch"
    }
}

/// Canonical posture derived from a sensor-bridge NDJSON row.
#[derive(Debug, Clone, PartialEq)]
pub struct NormalizedImu {
    pub stability: String,
    pub dev_mg: Option<i64>,
    pub ts: Option<f64>,
    /// session1 support: dev_mg computed from instantaneous |accel|-g rather than the bridge's
    /// peak-hold — flagged so callers can exclude derived rows.
    pub derived: bool,
}

/// Python `round()` is banker's rounding (round-half-even); mirror it exactly.
fn py_round_half_even(x: f64) -> i64 {
    let floor = x.floor();
    let frac = x - floor;
    if (frac - 0.5).abs() < f64::EPSILON {
        let f = floor as i64;
        if f % 2 == 0 {
            f
        } else {
            f + 1
        }
    } else {
        x.round() as i64
    }
}

/// Bridge NDJSON row -> canonical posture, or `None` when the row carries no physical posture at
/// all (some fabric logs are pure routing records). Faithful port of `projection.normalize_imu`.
pub fn normalize_imu(row: &serde_json::Value) -> Option<NormalizedImu> {
    let stability = row.get("stability").filter(|v| !v.is_null());
    let accel = row.get("accel_mg").filter(|v| !v.is_null());
    if stability.is_none() && accel.is_none() {
        return None;
    }

    // Python: str(stability).strip().lower() — coerce ANY value the way Python str() would.
    let mut label = match stability {
        None => "still".to_string(),
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(other) => py_str(&V::from_json(other)),
    };
    label = label.trim().to_lowercase();
    // Observed label drift only — session1's raw classifier label. Anything unknown passes
    // through lowercased and lands in the flow's OTHER cell (honest, visible).
    if label == "on table" {
        label = "still".to_string();
    }

    let mut dev: Option<i64> = row.get("dev_mg").and_then(|d| {
        if d.is_null() {
            None
        } else {
            // Python int() truncates toward zero.
            d.as_f64().map(|f| f.trunc() as i64)
        }
    });
    let mut derived = false;
    if dev.is_none() {
        if let Some(serde_json::Value::Array(a)) = accel {
            if a.len() == 3 {
                let (ax, ay, az) = (
                    a[0].as_f64().unwrap_or(0.0),
                    a[1].as_f64().unwrap_or(0.0),
                    a[2].as_f64().unwrap_or(0.0),
                );
                let mag = (ax * ax + ay * ay + az * az).sqrt();
                dev = Some((py_round_half_even(mag) - GRAVITY_MG).abs());
                derived = true;
            }
        }
    }

    Some(NormalizedImu {
        stability: label,
        dev_mg: dev,
        ts: row.get("ts").and_then(|t| t.as_f64()),
        derived,
    })
}

/// The one reading shape every path emits — exactly the flow's four decision fields, in kernel
/// `V` terms so it feeds `wire::route_node` / the spiral directly. Errors when the posture has
/// no dev_mg (derived excluded or missing), mirroring the Python `ValueError`.
pub fn fused_reading(
    alert_level: i64,
    soc_action: &str,
    imu: &NormalizedImu,
) -> Result<HashMap<String, V>, String> {
    let dev = imu
        .dev_mg
        .ok_or("imu posture has no dev_mg (derived excluded or missing) — cannot fuse")?;
    let mut r = HashMap::new();
    r.insert("stability".to_string(), V::Str(imu.stability.clone()));
    r.insert("dev_mg".to_string(), V::Num(dev as f64));
    r.insert("rule_level".to_string(), V::Num(alert_level as f64));
    r.insert("soc_action".to_string(), V::Str(soc_action.to_string()));
    Ok(r)
}
