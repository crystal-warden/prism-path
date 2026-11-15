//! The refresh profile (PROTOCOL.md section 2.7) against `refresh.json`: `KeyframeScheduler` and
//! `StalenessTracker` operation lists and what the Python module gives for each.

use prismpath_telemetry_rs::refresh::{KeyframeScheduler, StalenessTracker};
use serde_json::Value;

fn corpus() -> Value {
    let text = std::fs::read_to_string(format!("{}/tests/fixtures/refresh.json", env!("CARGO_MANIFEST_DIR"))).unwrap();
    serde_json::from_str(&text).unwrap()
}

#[test]
fn every_scheduler_list_matches_python() {
    let doc = corpus();
    let cases = doc["schedulers"].as_array().unwrap();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let mut scheduler = KeyframeScheduler::new(case["keyframe_ms"].as_i64()).unwrap();
        for (index, op) in case["ops"].as_array().unwrap().iter().enumerate() {
            let want = &case["expect"][index];
            match op[0].as_str().unwrap() {
                "should_emit" => {
                    assert_eq!(scheduler.should_emit(op[1].as_i64().unwrap(), op[2].as_bool().unwrap()), want.as_bool().unwrap(), "{name} op {index}")
                }
                "note_emit" => {
                    assert!(want.is_null());
                    scheduler.note_emit(op[1].as_i64().unwrap());
                }
                other => panic!("{name}: op {other}"),
            }
        }
    }
    println!("refresh scheduler: {} cases match Python", cases.len());
}

#[test]
fn every_tracker_list_matches_python() {
    let doc = corpus();
    let cases = doc["trackers"].as_array().unwrap();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let mut tracker = StalenessTracker::new(case["stale_ms"].as_i64().unwrap(), case["safe_state"].clone()).unwrap();
        for (index, op) in case["ops"].as_array().unwrap().iter().enumerate() {
            let want = &case["expect"][index];
            match op[0].as_str().unwrap() {
                "frame" => {
                    assert!(want.is_null());
                    tracker.on_frame(op[1].as_i64().unwrap(), op[2].clone());
                }
                "acting" => {
                    let (state, fresh) = tracker.acting_state(op[1].as_i64().unwrap());
                    assert_eq!(state, want[0], "{name} op {index}: state");
                    assert_eq!(fresh, want[1].as_bool().unwrap(), "{name} op {index}: fresh");
                }
                other => panic!("{name}: op {other}"),
            }
        }
        let got: Vec<Value> = tracker.transitions().iter().map(|(when, kind)| serde_json::json!([when, kind])).collect();
        assert_eq!(Value::Array(got), case["transitions"], "{name}: transitions");
    }
    println!("refresh tracker: {} cases match Python", cases.len());
}

#[test]
fn the_constructors_refuse_a_bound_that_is_not_positive() {
    let doc = corpus();
    for bad in doc["scheduler_refused"].as_array().unwrap() {
        assert!(KeyframeScheduler::new(bad.as_i64()).is_err(), "{bad}");
    }
    for bad in doc["tracker_refused"].as_array().unwrap() {
        assert!(StalenessTracker::new(bad.as_i64().unwrap(), 0u8).is_err(), "{bad}");
    }
    assert!(KeyframeScheduler::new(None).is_ok());
}

#[test]
fn times_at_the_ends_of_the_i64_range_do_not_overflow() {
    let mut scheduler = KeyframeScheduler::new(Some(1)).unwrap();
    scheduler.note_emit(i64::MAX);
    assert!(!scheduler.should_emit(i64::MAX, false));
    scheduler.note_emit(i64::MIN);
    assert!(scheduler.should_emit(i64::MAX, false));
    let mut tracker = StalenessTracker::new(i64::MAX, "safe").unwrap();
    tracker.on_frame(i64::MIN, "state");
    assert_eq!(tracker.acting_state(i64::MAX), ("safe", false));
    assert_eq!(tracker.acting_state(i64::MIN), ("state", true));
}
