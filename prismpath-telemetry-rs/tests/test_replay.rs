//! The replay window (PROTOCOL.md section 2.8) against `replay.json`: operation lists and the `(accepted, cause)`
//! each gives under the Python `TickWindow`, with the window's highest tick and bit mask at the end.

use prismpath_telemetry_rs::replay::{TickWindow, ACCEPT, REPLAY_DUPLICATE, REPLAY_STALE};
use serde_json::Value;

fn corpus() -> Value {
    let text = std::fs::read_to_string(format!("{}/tests/fixtures/replay.json", env!("CARGO_MANIFEST_DIR"))).unwrap();
    serde_json::from_str(&text).unwrap()
}

#[test]
fn every_operation_list_matches_python() {
    let doc = corpus();
    assert_eq!(doc["causes"]["accept"], ACCEPT);
    assert_eq!(doc["causes"]["duplicate"], REPLAY_DUPLICATE);
    assert_eq!(doc["causes"]["stale"], REPLAY_STALE);
    let cases = doc["cases"].as_array().unwrap();
    let mut operations = 0;
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let mut window = TickWindow::new(case["reorder"].as_i64().unwrap()).unwrap();
        let expect = case["expect"].as_array().unwrap();
        for (index, op) in case["ops"].as_array().unwrap().iter().enumerate() {
            let tick = op[1].as_i64().unwrap();
            let got = if op[0] == "check" { window.check(tick) } else { window.observe(tick) };
            assert_eq!((got.0, got.1), (expect[index][0].as_bool().unwrap(), expect[index][1].as_str().unwrap()), "{name} op {index} {op}");
            operations += 1;
        }
        assert_eq!(window.top(), case["state"]["top"].as_i64().unwrap(), "{name}: top");
        assert_eq!(window.mask(), case["state"]["mask"].as_u64().unwrap(), "{name}: mask");
    }
    println!("replay window: {} cases, {operations} operations match Python", cases.len());
}

#[test]
fn the_constructor_refuses_what_python_refuses() {
    let doc = corpus();
    for bad in doc["constructor_refused"].as_array().unwrap() {
        assert!(TickWindow::new(bad.as_i64().unwrap()).is_err(), "{bad}");
    }
    for good in doc["constructor_accepted"].as_array().unwrap() {
        assert_eq!(TickWindow::new(good.as_i64().unwrap()).unwrap().reorder() as i64, good.as_i64().unwrap());
    }
}

#[test]
fn a_tick_at_either_end_of_the_i64_range_does_not_overflow_or_panic() {
    for reorder in [0, 1, 64] {
        let mut window = TickWindow::new(reorder).unwrap();
        for tick in [i64::MIN, i64::MAX, i64::MIN, 0, i64::MAX, i64::MAX - 1, -1] {
            let before = window.check(tick);
            let after = window.observe(tick);
            assert_eq!(before, after);
        }
    }
    let mut window = TickWindow::new(64).unwrap();
    assert_eq!(window.observe(i64::MAX), (true, ACCEPT));
    assert_eq!(window.observe(i64::MAX), (false, REPLAY_DUPLICATE));
    assert_eq!(window.observe(i64::MAX - 63), (true, ACCEPT));
    assert_eq!(window.observe(i64::MAX - 64), (false, REPLAY_STALE));
}
