// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! Bounded-model-checking reachability analysis.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::condition::{
    error_expr, eval_condition, expr_of, is_deterministic, is_error, is_event, is_semantic,
    parse_expr, Ast,
};
use crate::level_m::is_level_m;
use crate::parser::Graph;
use crate::value::Value;

const REACH_FRESH_STR: &str = "\u{0}fresh";
const REACH_PRODUCT_CAP: usize = 50_000;

fn reach_cond_ast(cond: &str) -> Option<Ast> {
    if !is_deterministic(cond) {
        return None;
    }
    let expr = expr_of(cond);
    let low = expr.to_lowercase();
    if ["always", "true", "else", "otherwise", "default", "_"].contains(&low.as_str())
        || ["false", "never"].contains(&low.as_str())
    {
        return None;
    }
    parse_expr(&expr).ok()
}

fn reach_walk<'a>(node: &'a Ast, out: &mut Vec<&'a Ast>) {
    out.push(node);
    match node {
        Ast::And(vals) | Ast::Or(vals) => {
            for item in vals {
                reach_walk(item, out);
            }
        }
        Ast::Not(val) => reach_walk(val, out),
        Ast::Cmp { left, rights, .. } => {
            reach_walk(left, out);
            for right_item in rights {
                reach_walk(right_item, out);
            }
        }
        Ast::List(elts) => {
            for elem in elts {
                reach_walk(elem, out);
            }
        }
        _ => {}
    }
}

fn reach_consts_of(node: &Ast) -> Vec<Value> {
    let mut all = Vec::new();
    reach_walk(node, &mut all);
    all.into_iter()
        .filter_map(|item| if let Ast::Const(val, _) = item { Some(val.clone()) } else { None })
        .collect()
}

fn reach_fields_of(node: &Ast) -> HashSet<String> {
    let mut all = Vec::new();
    reach_walk(node, &mut all);
    all.into_iter()
        .filter_map(|item| if let Ast::Name(nm) = item { Some(nm.clone()) } else { None })
        .collect()
}

fn reach_cand_key(val: &Value) -> String {
    match val {
        Value::Null => "null".to_string(),
        Value::Bool(bool_val) => format!("boolean:{bool_val}"),
        Value::Num(num_val) => {
            if num_val.is_nan() {
                "number:nan".to_string()
            } else {
                format!("number:{num_val}")
            }
        }
        Value::Str(str_val) => format!("string:{str_val}"),
        other => format!("other:{other:?}"),
    }
}

fn reach_candidates(consts: &[Value]) -> Vec<Value> {
    let mut nums: Vec<f64> = consts
        .iter()
        .filter_map(|val| match val {
            Value::Num(num_val) if !num_val.is_nan() => Some(*num_val),
            _ => None,
        })
        .collect();
    nums.sort_by(|left, right| left.partial_cmp(right).expect("finite"));
    nums.dedup();

    let mut cands: Vec<Value> = vec![
        Value::Null,
        Value::Bool(true),
        Value::Bool(false),
        Value::Num(0.0),
        Value::Num(1.0),
        Value::Str(String::new()),
        Value::Str(REACH_FRESH_STR.to_string()),
    ];
    cands.extend(consts.iter().cloned());
    for num_val in &nums {
        cands.push(Value::Num(num_val - 1.0));
        cands.push(Value::Num(num_val + 1.0));
    }
    for idx in 0..nums.len().saturating_sub(1) {
        cands.push(Value::Num((nums[idx] + nums[idx + 1]) / 2.0));
    }

    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for item in cands {
        if seen.insert(reach_cand_key(&item)) {
            out.push(item);
        }
    }
    out
}

fn reach_pow_exceeds(base: usize, exp: usize, cap: usize) -> bool {
    let mut acc: u128 = 1;
    let cap_val = cap as u128;
    for _ in 0..exp {
        acc = acc.saturating_mul(base as u128);
        if acc > cap_val {
            return true;
        }
    }
    acc > cap_val
}

struct NodeSat {
    det: Vec<(usize, String, String)>,
    fields: Vec<String>,
    cands: Vec<Value>,
    complete: bool,
}

fn reach_node_sat(graph: &Graph, name: &str, assume: Option<&str>) -> NodeSat {
    let node = &graph.nodes[name];
    let mut det = Vec::new();
    for (idx, (target, cond)) in node.edges.iter().enumerate() {
        if is_deterministic(cond) {
            det.push((idx, target.clone(), cond.clone()));
        }
    }
    let mut consts: Vec<Value> = Vec::new();
    let mut fields: HashSet<String> = HashSet::new();
    let mut complete = true;
    let mut exprs: Vec<String> = det.iter().map(|(_, _, cond)| cond.clone()).collect();
    if let Some(assume_str) = assume {
        exprs.push(assume_str.to_string());
    }
    for cond in &exprs {
        if let Some(tree) = reach_cond_ast(cond) {
            consts.extend(reach_consts_of(&tree));
            for field in reach_fields_of(&tree) {
                fields.insert(field);
            }
            if !is_level_m(cond).0 {
                complete = false;
            }
        }
    }
    fields.remove("visits");
    let cands = reach_candidates(&consts);
    let mut field_list: Vec<String> = fields.into_iter().collect();
    field_list.sort();
    if reach_pow_exceeds(cands.len(), field_list.len(), REACH_PRODUCT_CAP) {
        complete = false;
    }
    NodeSat { det, fields: field_list, cands, complete }
}

fn reach_contexts(sat: &NodeSat, visits: f64) -> Vec<HashMap<String, Value>> {
    let mut out = Vec::new();
    if sat.fields.is_empty() {
        let mut map = HashMap::new();
        map.insert("visits".to_string(), Value::Num(visits));
        out.push(map);
        return out;
    }
    if reach_pow_exceeds(sat.cands.len(), sat.fields.len(), REACH_PRODUCT_CAP) {
        return out;
    }
    let num_fields = sat.fields.len();
    let mut idx = vec![0usize; num_fields];
    loop {
        let mut ctx = HashMap::new();
        ctx.insert("visits".to_string(), Value::Num(visits));
        for (field, &cand_i) in sat.fields.iter().zip(idx.iter()) {
            ctx.insert(field.clone(), sat.cands[cand_i].clone());
        }
        out.push(ctx);
        let mut key_pos = num_fields as isize - 1;
        while key_pos >= 0 {
            idx[key_pos as usize] += 1;
            if idx[key_pos as usize] < sat.cands.len() {
                break;
            }
            idx[key_pos as usize] = 0;
            key_pos -= 1;
        }
        if key_pos < 0 {
            break;
        }
    }
    out
}

fn reach_edge_outcomes(sat: &NodeSat, assume: Option<&str>, visits: f64) -> (HashSet<usize>, bool) {
    let mut takeable: HashSet<usize> = HashSet::new();
    let mut none_seen = false;
    let mut saw_ctx = false;
    for ctx in reach_contexts(sat, visits) {
        saw_ctx = true;
        if let Some(assume_str) = assume {
            match eval_condition(assume_str, &ctx) {
                Ok(true) => {}
                Ok(false) | Err(_) => continue,
            }
        }
        let mut matched: Option<usize> = None;
        for (idx, _target, cond) in &sat.det {
            if eval_condition(cond, &ctx).unwrap_or(false) {
                matched = Some(*idx);
                break;
            }
        }
        match matched {
            None => none_seen = true,
            Some(idx) => {
                takeable.insert(idx);
            }
        }
    }
    if !saw_ctx {
        return (HashSet::new(), false);
    }
    (takeable, sat.complete && !none_seen)
}

fn reach_visit_caps(graph: &Graph) -> HashMap<String, i64> {
    let mut caps = HashMap::new();
    for (name, node) in &graph.nodes {
        let mut best: Option<i64> = None;
        for (_target, cond_str) in &node.edges {
            let mut cond = cond_str.clone();
            if is_error(cond_str) {
                let expr = error_expr(cond_str);
                if expr.is_empty() {
                    continue;
                }
                cond = if expr.to_lowercase().starts_with("when ") {
                    expr
                } else {
                    format!("when {expr}")
                };
            }
            let Some(tree) = reach_cond_ast(&cond) else { continue };
            if !reach_fields_of(&tree).contains("visits") {
                continue;
            }
            let max_val = reach_consts_of(&tree)
                .iter()
                .filter_map(|val| match val {
                    Value::Num(num_val) if !num_val.is_nan() => Some(*num_val),
                    _ => None,
                })
                .fold(f64::NEG_INFINITY, f64::max);
            let max_int = if max_val.is_finite() { max_val.trunc() as i64 } else { 0 };
            best = Some(best.unwrap_or(0).max(max_int));
        }
        if let Some(best_cap) = best {
            caps.insert(name.clone(), best_cap + 2);
        }
    }
    caps
}

fn reach_bump(
    counts: &[(String, i64)],
    node: &str,
    caps: &HashMap<String, i64>,
) -> Vec<(String, i64)> {
    if !caps.contains_key(node) {
        return counts.to_vec();
    }
    let mut map: BTreeMap<String, i64> = counts.iter().cloned().collect();
    let cap_val = caps[node];
    let entry = map.entry(node.to_string()).or_insert(0);
    *entry = (*entry + 1).min(cap_val);
    map.into_iter().collect()
}

fn reach_state_key(name: &str, counts: &[(String, i64)]) -> String {
    let mut str_val = String::from(name);
    str_val.push('\u{1}');
    for (node_name, count) in counts {
        str_val.push_str(node_name);
        str_val.push(':');
        str_val.push_str(&count.to_string());
        str_val.push(',');
    }
    str_val
}

/// Bounded-model-checking reachability. Returns { target: {reachable: "yes"|"may"|"no", proven} }.
pub fn check_reach(
    graph: &Graph,
    targets: &[String],
    assume: Option<&str>,
    bound: usize,
    include_errors: bool,
    include_events: bool,
) -> serde_json::Value {
    let assume_owned: Option<String> = assume.map(|assume_str| {
        if assume_str.trim().to_lowercase().starts_with("when ") {
            assume_str.to_string()
        } else {
            format!("when {assume_str}")
        }
    });
    let assume_ref = assume_owned.as_deref();

    let caps = reach_visit_caps(graph);
    let mut sats: HashMap<String, NodeSat> = HashMap::new();
    for name in graph.nodes.keys() {
        sats.insert(name.clone(), reach_node_sat(graph, name, assume_ref));
    }

    let start_counts = reach_bump(&[], &graph.start, &caps);
    let start_key = reach_state_key(&graph.start, &start_counts);
    let mut best: HashMap<String, bool> = HashMap::new();
    best.insert(start_key.clone(), true);
    let mut state_of: HashMap<String, (String, Vec<(String, i64)>)> = HashMap::new();
    state_of.insert(start_key.clone(), (graph.start.clone(), start_counts));
    let mut frontier: Vec<(String, usize)> = vec![(start_key, 0)];
    let mut exhausted = true;
    let mut front_pos = 0;

    while front_pos < frontier.len() {
        let (state_key, depth) = frontier[front_pos].clone();
        front_pos += 1;
        let (node_name, counts) = state_of[&state_key].clone();
        if depth >= bound {
            exhausted = false;
            continue;
        }
        let Some(node) = graph.nodes.get(&node_name) else { continue };
        if node.edges.is_empty() {
            continue;
        }
        let visits = counts
            .iter()
            .find(|(name, _)| *name == node_name)
            .map(|(_, count)| *count)
            .unwrap_or(1);
        let sat = &sats[&node_name];
        let (takeable, none_match_false) = reach_edge_outcomes(sat, assume_ref, visits as f64);
        let my_certain = best[&state_key];

        let mut moves: Vec<(String, bool)> = Vec::new();
        for &idx in &takeable {
            moves.push((node.edges[idx].0.clone(), true));
        }
        if !sat.complete {
            for (idx, target, _cond) in &sat.det {
                if !takeable.contains(idx) {
                    moves.push((target.clone(), false));
                }
            }
        }
        if !none_match_false {
            for (target, cond) in &node.edges {
                if is_semantic(cond) {
                    moves.push((target.clone(), false));
                }
            }
        }
        if include_errors {
            for (target, cond) in &node.edges {
                if is_error(cond) {
                    moves.push((target.clone(), false));
                }
            }
        }
        if include_events {
            for (target, cond) in &node.edges {
                if is_event(cond) {
                    moves.push((target.clone(), false));
                }
            }
        }

        for (target, step_certain) in moves {
            if !graph.nodes.contains_key(&target) {
                continue;
            }
            let cert = my_certain && step_certain;
            let n_counts = reach_bump(&counts, &target, &caps);
            let n_key = reach_state_key(&target, &n_counts);
            let update = match best.get(&n_key) {
                None => true,
                Some(false) => cert,
                Some(true) => false,
            };
            if update {
                best.insert(n_key.clone(), cert);
                state_of.insert(n_key.clone(), (target.clone(), n_counts));
                frontier.push((n_key, depth + 1));
            }
        }
    }

    let mut results = serde_json::Map::new();
    for target in targets {
        let mut hit_certain: Option<bool> = None;
        for (key, cert_val) in &best {
            if state_of[key].0 == *target {
                hit_certain = Some(hit_certain.unwrap_or(false) || *cert_val);
            }
        }
        let entry = match hit_certain {
            None => serde_json::json!({ "reachable": "no", "proven": exhausted }),
            Some(certain) => {
                serde_json::json!({ "reachable": if certain { "yes" } else { "may" }, "proven": false })
            }
        };
        results.insert(target.clone(), entry);
    }
    serde_json::Value::Object(results)
}
