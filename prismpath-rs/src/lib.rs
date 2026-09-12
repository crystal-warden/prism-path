// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! prismpath-rs: the portable PrismPath kernel, in Rust.
//!
//! A faithful port of portable/prismpath.mjs (itself a certified port of the Python reference:
//! 1079/1079 predicates, 27/27 flows). The conformance corpus in ../prismpath/portable/conformance
//! IS the specification, and this crate's only claim to correctness is passing it bit-for-bit:
//!
//! ```text
//! cargo run --bin conformance -- ../prismpath/portable/conformance
//! ```

pub mod condition;
pub mod engine;
pub mod level_m;
pub mod parser;
pub mod reach;
pub mod value;

#[cfg(feature = "durable")]
pub mod durable;

#[cfg(feature = "durable")]
pub mod connector;

#[cfg(feature = "durable")]
pub mod compose;

#[cfg(feature = "durable")]
pub mod crypto_agility;

pub use condition::{
    check_predicate, error_expr, event_name, is_catchall, is_deterministic, is_error, is_event,
    is_semantic, py_trim, py_truthy, eval_condition,
};
pub use engine::{
    decode_b64_f32, event_target, first_deterministic, locked_route,
    portability_violations, py_str, reachable, run, run_locked, run_locked_observed, run_observed,
    CentroidPin, EngineError, Lock, Pending, RouteDecision, RunOpts, RunResult, RunState, Step,
    Violation,
};
pub use level_m::{capability_report, flow_level_m, is_level_m, NonMemberEdge};
pub use parser::{parse, Graph, Node};
pub use reach::check_reach;
pub use value::{PredicateError, Value, V, CMP_DEPTH, MAX_DEPTH};

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn ctx(pairs: &[(&str, Value)]) -> HashMap<String, Value> {
        pairs.iter().map(|(key, val)| (key.to_string(), val.clone())).collect()
    }

    #[test]
    fn locked_route_exported_matches_the_frozen_p1_fixture() {
        let raw = std::fs::read_to_string("../prismpath/portable/conformance/locked_flows.json")
            .expect("locked_flows.json");
        let doc: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let cases = doc["cases"].as_array().unwrap();
        let fixture_case = cases
            .iter()
            .find(|case_item| case_item["name"] == "locked_basic_route")
            .unwrap_or(&cases[0]);
        let graph = parse(fixture_case["flow"].as_str().unwrap());
        let lock = Lock::from_json(&fixture_case["lock"]).unwrap();
        let start_node = fixture_case.get("start").and_then(|str_val| str_val.as_str()).unwrap_or(&graph.start).to_string();
        let sem_edges: Vec<(String, String)> = graph.nodes[&start_node]
            .edges
            .iter()
            .filter(|(_, cond)| is_semantic(cond))
            .cloned()
            .collect();
        let embed_map = fixture_case["embedMap"].as_object().cloned().unwrap_or_default();
        let dim = lock.dim;
        let text = embed_map.keys().next().cloned().unwrap_or_default();
        let mut embed = |str_input: &str| -> Vec<f32> {
            embed_map
                .get(str_input)
                .and_then(|val_str| val_str.as_str())
                .map(|b64_str| decode_b64_f32(b64_str).unwrap())
                .unwrap_or_else(|| vec![0.0f32; dim])
        };
        let decision = locked_route(&text, &sem_edges, &lock, &mut embed).unwrap();
        let expected_target = fixture_case["expect"]["path"][1].as_str().unwrap();
        assert_eq!(decision.target, expected_target);
        assert!(decision.score > 0.0);
    }

    #[test]
    fn chained_comparison_and_membership() {
        let context = ctx(&[("x", Value::Num(3.0))]);
        assert!(eval_condition("when 1 < x < 5", &context).unwrap());
        assert!(!eval_condition("when 1 < x < 3", &context).unwrap());
        let context_str = ctx(&[("a", Value::Str("watch".into()))]);
        assert!(eval_condition("when a in (\"contain\", \"watch\")", &context_str).unwrap());
        assert!(eval_condition("when a not in [\"contain\"]", &context_str).unwrap());
    }

    #[test]
    fn python_constants_vs_field_names() {
        let context = ctx(&[("x", Value::Bool(true))]);
        assert!(eval_condition("when x == True", &context).unwrap());
        assert!(eval_condition("when x == true", &ctx(&[])).unwrap());
    }

    #[test]
    fn eval_never_panics_on_adversarial_input() {
        let context = ctx(&[("x", Value::Num(3.0)), ("s", Value::Str("hi".into()))]);
        let nasty = [
            "", "when", "when ", "when (", "when )))", "when 1 <", "when < 3", "when x ==",
            "when \"\\x\"", "when \"\\u12\"", "when \"\\", "when 0x", "when 0o", "when 0b",
            "when 1 < x < < 5", "when x in", "when x not", "when and or not",
            "when 999999999999999999999999999 > x", "when x == 'unterminated", "when \\uffffffff",
            "when x in in in", "when 1j > 0", "when x.y.z == 1", "when [1,2,3] == x",
            "when x == \"\\U0001F600\"", "when x == \"\\uD800\"",
        ];
        for cond_str in nasty {
            let _ = eval_condition(cond_str, &context);
            let _ = check_predicate(cond_str);
            let _ = is_deterministic(cond_str);
        }
        let deep_expr = format!("when {}x{}", "(".repeat(500), ")".repeat(500));
        assert!(eval_condition(&deep_expr, &context).is_err());
    }

    #[test]
    fn booleans_compare_numerically() {
        let context = ctx(&[("flag", Value::Bool(true))]);
        assert!(eval_condition("when flag == 1", &context).unwrap());
    }

    #[test]
    fn keywords_and_disallowed_syntax_are_errors() {
        for cond_str in ["when class == \"phish\"", "when f(x)", "when x + 1 > 2"] {
            assert!(eval_condition(cond_str, &ctx(&[])).is_err(), "{cond_str} must be a PredicateError");
        }
        assert!(eval_condition("when -1 < x", &ctx(&[("x", Value::Num(5.0))])).is_ok());
        assert!(eval_condition("when x >= -0.5", &ctx(&[("x", Value::Num(1.0))])).is_err());
        assert!(eval_condition("when -y < x", &ctx(&[("x", Value::Num(1.0)), ("y", Value::Num(2.0))])).is_err());
    }

    #[test]
    fn failed_comparisons_are_unsatisfied_not_crashes() {
        let context = ctx(&[("x", Value::Str("s".into()))]);
        assert!(!eval_condition("when x > 3", &context).unwrap());
        assert!(!eval_condition("when missing > 3", &context).unwrap());
        assert!(eval_condition("when x not in 3", &context).unwrap());
    }

    #[test]
    fn flow_runs_to_terminal() {
        let graph = parse("---\nname: t\nstart: a\n---\n\n## a\nDo a.\n-> b: when ok\n\n## b\nDone.\n");
        let res = run(
            &graph,
            |_, _, _| {
                Ok(Value::Obj(vec![
                    ("ok".into(), Value::Bool(true)),
                    ("text".into(), Value::Str("x".into())),
                ]))
            },
            RunOpts::default(),
        )
        .unwrap();
        assert_eq!(res.path, vec!["a", "b"]);
        assert_eq!(res.stopped, "terminal");
    }

    #[test]
    fn max_steps_protects_against_loops() {
        let graph = parse("## a\n-> a: always\n");
        let res = run(&graph, |_, _, _| Ok(Value::Str("t".into())), RunOpts::default()).unwrap();
        assert_eq!(res.stopped, "max_steps");
        assert_eq!(res.path.len(), 26);
    }

    #[test]
    fn semantic_edge_is_refused_up_front() {
        let graph = parse("## a\n-> b: the answer looks correct\n\n## b\nDone.\n");
        assert!(matches!(
            run(&graph, |_, _, _| Ok(Value::Null), RunOpts::default()),
            Err(EngineError::NotPortable(_))
        ));
    }

    #[test]
    fn locked_routing_picks_closest_condition() {
        let graph = parse("## a\nClassify.\n\n-> b: positive\n-> c: negative\n\n## b\nB.\n\n## c\nC.\n");
        let mut conds = HashMap::new();
        conds.insert("positive".to_string(), vec![1.0f32, 0.0, 0.0, 0.0]);
        conds.insert("negative".to_string(), vec![0.0, 1.0, 0.0, 0.0]);
        let lock = Lock { conditions: conds, centroids: None, dim: 4 };
        let res = run_locked(
            &graph,
            |_, _, _| Ok(Value::Obj(vec![("text".to_string(), Value::Str("great".into()))])),
            |_text| vec![0.99f32, 0.11, 0.0, 0.0],
            &lock,
            RunOpts::default(),
        ).unwrap();
        assert_eq!(res.path, vec!["a", "b"]);
        assert_eq!(res.stopped, "terminal");
        assert_eq!(res.steps[0].used, "locked");
        assert!(res.steps[0].score.unwrap() > 0.9);
    }

    #[test]
    fn locked_routing_human_floor_suspends() {
        let graph = parse("## a\nClassify.\n\n-> b: positive\n-> c: negative\n\n## b\nB.\n\n## c\nC.\n");
        let mut conds = HashMap::new();
        conds.insert("positive".to_string(), vec![1.0f32, 0.0, 0.0, 0.0]);
        conds.insert("negative".to_string(), vec![0.0, 1.0, 0.0, 0.0]);
        let lock = Lock { conditions: conds, centroids: None, dim: 4 };
        let res = run_locked(
            &graph,
            |_, _, _| Ok(Value::Obj(vec![("text".to_string(), Value::Str("ambiguous".into()))])),
            |_text| vec![0.72f32, 0.69, 0.0, 0.07],
            &lock,
            RunOpts { human_floor: Some(0.99), ..Default::default() },
        ).unwrap();
        assert_eq!(res.stopped, "needs_human");
        assert_eq!(res.pending.as_ref().unwrap().would_pick.as_deref(), Some("b"));
    }

    #[test]
    fn locked_routing_deterministic_takes_priority() {
        let graph = parse("## a\nRoute.\n\n-> b: when x == 1\n-> c: semantic edge\n\n## b\nB.\n\n## c\nC.\n");
        let mut conds = HashMap::new();
        conds.insert("semantic edge".to_string(), vec![0.0, 0.0, 1.0, 0.0]);
        let lock = Lock { conditions: conds, centroids: None, dim: 4 };
        let res = run_locked(
            &graph,
            |_, _, _| Ok(Value::Obj(vec![
                ("text".to_string(), Value::Str("go".into())),
                ("x".to_string(), Value::Num(1.0)),
            ])),
            |_text| vec![0.0, 0.0, 0.9, 0.0],
            &lock,
            RunOpts::default(),
        ).unwrap();
        assert_eq!(res.path, vec!["a", "b"]);
        assert!(res.steps[0].used.starts_with("deterministic"));
    }

    #[test]
    fn lock_missing_condition_is_caught() {
        let graph = parse("## a\nDo.\n\n-> b: foo\n-> c: bar\n\n## b\nB.\n\n## c\nC.\n");
        let mut conds = HashMap::new();
        conds.insert("foo".to_string(), vec![1.0, 0.0, 0.0, 0.0]);
        let lock = Lock { conditions: conds, centroids: None, dim: 4 };
        let res = run_locked(
            &graph,
            |_, _, _| Ok(Value::Null),
            |_| vec![1.0, 0.0, 0.0, 0.0],
            &lock,
            RunOpts::default(),
        );
        assert!(matches!(res, Err(EngineError::LockMissing(_))));
    }

    #[test]
    fn centroid_overrides_condition_vector() {
        let graph = parse("## a\nClassify.\n\n-> b: positive\n-> c: negative\n\n## b\nB.\n\n## c\nC.\n");
        let mut conds = HashMap::new();
        conds.insert("positive".to_string(), vec![1.0, 0.0, 0.0, 0.0]);
        conds.insert("negative".to_string(), vec![0.0, 1.0, 0.0, 0.0]);
        let mut centroids = HashMap::new();
        centroids.insert("positive".to_string(), CentroidPin {
            vec: vec![0.0, 1.0, 0.0, 0.0], n: 5,
        });
        let lock = Lock { conditions: conds, centroids: Some(centroids), dim: 4 };
        let res = run_locked(
            &graph,
            |_, _, _| Ok(Value::Obj(vec![("text".to_string(), Value::Str("test".into()))])),
            |_| vec![0.0, 0.99, 0.0, 0.1],
            &lock,
            RunOpts::default(),
        ).unwrap();
        assert_eq!(res.path[1], "b");
    }

    #[test]
    fn decode_b64_f32_roundtrip() {
        let original = vec![1.0f32, 0.0, -0.5, 3.5];
        let b64 = {
            let bytes: Vec<u8> = original.iter().flat_map(|val_f32| val_f32.to_le_bytes()).collect();
            const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut out = String::new();
            for chunk in bytes.chunks(3) {
                let (b0_val, b1_val, b2_val) = (chunk[0] as u32,
                    *chunk.get(1).unwrap_or(&0) as u32,
                    *chunk.get(2).unwrap_or(&0) as u32);
                let num_val = (b0_val << 16) | (b1_val << 8) | b2_val;
                out.push(CHARS[((num_val >> 18) & 63) as usize] as char);
                out.push(CHARS[((num_val >> 12) & 63) as usize] as char);
                if chunk.len() > 1 { out.push(CHARS[((num_val >> 6) & 63) as usize] as char); }
                else { out.push('='); }
                if chunk.len() > 2 { out.push(CHARS[(num_val & 63) as usize] as char); }
                else { out.push('='); }
            }
            out
        };
        let decoded = decode_b64_f32(&b64).unwrap();
        assert_eq!(decoded.len(), original.len());
        for (decoded_val, orig_val) in decoded.iter().zip(&original) {
            assert!((decoded_val - orig_val).abs() < 1e-6, "{decoded_val} != {orig_val}");
        }
    }

    #[test]
    fn nan_truthiness_and_chained_comparison_short_circuit() {
        let context_nan = ctx(&[("x", Value::Num(f64::NAN))]);
        assert!(eval_condition("when x", &context_nan).unwrap());

        let deep_expr = format!("when 1 < 0 < {}", "[".repeat(49) + "1" + &"]".repeat(49));
        let context_empty = ctx(&[]);
        assert!(!eval_condition(&deep_expr, &context_empty).unwrap());
    }
}
