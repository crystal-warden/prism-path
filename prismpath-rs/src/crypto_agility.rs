// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! crypto_agility.rs — Crypto-agility proofs + envelope conformance (§4.2, §5).
//!
//! Replays the P1-P5 proofs over parsed flow graphs and signed registries, matching
//! `prismpath/crypto_agility.py` byte-for-byte against frozen conformance fixtures.

use crate::durable::py_canonical_string;
use crate::{check_reach, flow_level_m, is_catchall, reachable, Graph};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};

pub const SUITE_NODE_PREFIX: &str = "suite-";
pub const REACH_BOUND: usize = 25;
const PQ_KEM_TOKENS: [&str; 2] = ["ml-kem", "kyber"];

/// Registry hash: sha256 hex digest of the canonical JSON representation of the registry dict.
pub fn registry_hash(registry: &Value) -> String {
    let canonical = py_canonical_string(registry, false);
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Declared strength rank of a suite id in the registry.
pub fn strength_rank(registry: &Value, suite_id: &str) -> Option<i64> {
    registry
        .get("suites")?
        .get(suite_id)?
        .get("strength_rank")?
        .as_i64()
}

/// Suite ids in the registry.
pub fn suite_ids(registry: &Value) -> Vec<String> {
    let mut sids = Vec::new();
    if let Some(suites) = registry.get("suites").and_then(|s| s.as_object()) {
        for key in suites.keys() {
            sids.push(key.clone());
        }
    }
    sids.sort();
    sids
}

/// Suite ids ranked strictly below `floor_id`.
pub fn suites_below(registry: &Value, floor_id: &str) -> Result<Vec<String>, String> {
    let floor = strength_rank(registry, floor_id)
        .ok_or_else(|| format!("unknown floor suite: {floor_id}"))?;
    let mut below = Vec::new();
    if let Some(suites) = registry.get("suites").and_then(|s| s.as_object()) {
        for (sid, spec) in suites {
            let rank = spec.get("strength_rank").and_then(|v| v.as_i64()).unwrap_or(0);
            if rank < floor {
                below.push(sid.clone());
            }
        }
    }
    below.sort();
    Ok(below)
}

/// Is a suite quantum-resistant (KEM contains 'ml-kem' or 'kyber')?
pub fn is_quantum_resistant(registry: &Value, suite_id: &str) -> bool {
    let Some(kem) = registry
        .get("suites")
        .and_then(|s| s.get(suite_id))
        .and_then(|s| s.get("kem"))
        .and_then(|k| k.as_str())
    else {
        return false;
    };
    let kem_lower = kem.to_lowercase();
    PQ_KEM_TOKENS.iter().any(|tok| kem_lower.contains(tok))
}

/// Suite ids with no post-quantum KEM component.
pub fn classical_only_ids(registry: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(suites) = registry.get("suites").and_then(|s| s.as_object()) {
        for sid in suites.keys() {
            if !is_quantum_resistant(registry, sid) {
                out.push(sid.clone());
            }
        }
    }
    out.sort();
    out
}

/// Map of `{ node_name: suite_id }` for every suite terminal node in `graph`.
pub fn suite_nodes(graph: &Graph) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for name in graph.nodes.keys() {
        if let Some(stripped) = name.strip_prefix(SUITE_NODE_PREFIX) {
            map.insert(name.clone(), stripped.to_string());
        }
    }
    map
}

/// `{ suite_id: {"reachable": yes|may|no, "proven": bool} }` for every suite terminal.
pub fn reachable_suites(graph: &Graph, assume: Option<&str>) -> Value {
    let nodes = suite_nodes(graph);
    let target_nodes: Vec<String> = nodes.keys().cloned().collect();
    let res = check_reach(graph, &target_nodes, assume, REACH_BOUND, true, true);
    let mut map = Map::new();
    for (node_name, sid) in &nodes {
        if let Some(r) = res.get(node_name) {
            let entry = json!({
                "reachable": r.get("reachable").cloned().unwrap_or(Value::Null),
                "proven": r.get("proven").cloned().unwrap_or(Value::Null),
            });
            map.insert(sid.clone(), entry);
        }
    }
    Value::Object(map)
}

fn forbidden_reachable(reach: &Value, forbidden: &[String]) -> Vec<Value> {
    let mut bad = Vec::new();
    let mut sorted_forbidden = forbidden.to_vec();
    sorted_forbidden.sort();
    for sid in &sorted_forbidden {
        let Some(r) = reach.get(sid) else { continue };
        let reachable_str = r.get("reachable").and_then(|v| v.as_str()).unwrap_or("");
        let proven = r.get("proven").and_then(|v| v.as_bool()).unwrap_or(false);
        if reachable_str != "no" {
            bad.push(json!({
                "reachable": reachable_str,
                "reason": "reachable",
                "suite": sid
            }));
        } else if !proven {
            bad.push(json!({
                "reachable": "no",
                "reason": "unproven (bound hit)",
                "suite": sid
            }));
        }
    }
    bad
}

/// P1: Envelope closure.
pub fn prove_envelope_closure(graph: &Graph, envelope: &Value) -> Value {
    let approved: HashSet<&str> = envelope
        .get("approved_suites")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|x| x.as_str()).collect())
        .unwrap_or_default();
    let reach = reachable_suites(graph, None);
    let reach_obj = reach.as_object().cloned().unwrap_or_default();

    let mut sids: Vec<&String> = reach_obj.keys().collect();
    sids.sort();

    let mut offenders = Vec::new();
    let mut reachable_suites_map = Map::new();

    for sid in sids {
        let r = &reach_obj[sid];
        let reachable_str = r.get("reachable").and_then(|v| v.as_str()).unwrap_or("");
        if reachable_str != "no" {
            reachable_suites_map.insert(sid.clone(), Value::String(reachable_str.to_string()));
            if !approved.contains(sid.as_str()) {
                offenders.push(json!({
                    "reachable": reachable_str,
                    "suite": sid
                }));
            }
        }
    }

    json!({
        "offenders": offenders,
        "ok": offenders.is_empty(),
        "reachable_suites": reachable_suites_map
    })
}

/// P2: Totality (structural).
pub fn prove_totality(graph: &Graph) -> Value {
    let reach = reachable(graph);
    let suites: HashSet<String> = suite_nodes(graph).keys().cloned().collect();
    let mut gaps = Vec::new();
    let mut sorted_reach = reach;
    sorted_reach.sort();
    sorted_reach.dedup();

    for name in sorted_reach {
        let Some(node) = graph.nodes.get(&name) else { continue };
        if node.edges.is_empty() || suites.contains(&name) {
            continue;
        }
        let has_catchall = node.edges.iter().any(|(_t, c)| is_catchall(c));
        if !has_catchall {
            gaps.push(name);
        }
    }

    json!({
        "nodes_without_catchall": gaps,
        "ok": gaps.is_empty()
    })
}

/// P3: Class floor.
pub fn prove_class_floor(graph: &Graph, envelope: &Value, registry: &Value) -> Value {
    let class_field = envelope
        .get("class_field")
        .and_then(|v| v.as_str())
        .unwrap_or("data_class");
    let mut failures = Vec::new();
    if let Some(min_suite) = envelope.get("min_suite_by_class").and_then(|v| v.as_object()) {
        let mut classes: Vec<&String> = min_suite.keys().collect();
        classes.sort();
        for cls in classes {
            let floor_id = min_suite[cls].as_str().unwrap_or("");
            let below = suites_below(registry, floor_id).unwrap_or_default();
            let assume = format!("when {class_field} == \"{cls}\"");
            let reach = reachable_suites(graph, Some(&assume));
            let bad = forbidden_reachable(&reach, &below);
            if !bad.is_empty() {
                failures.push(json!({
                    "class": cls,
                    "floor": floor_id,
                    "violations": bad
                }));
            }
        }
    }
    json!({
        "failures": failures,
        "ok": failures.is_empty()
    })
}

/// P4: Monotone migration.
pub fn prove_monotone_migration(graph: &Graph, envelope: &Value, registry: &Value) -> Value {
    let floor = envelope.get("migration_phase_floor").and_then(|v| v.as_i64());
    let field = envelope
        .get("migration_phase_field")
        .and_then(|v| v.as_str())
        .unwrap_or("migration_phase");

    let Some(floor_val) = floor else {
        return json!({
            "ok": true,
            "skipped": "no migration_phase_floor in envelope"
        });
    };

    let classical = classical_only_ids(registry);
    let assume = format!("when {field} >= {floor_val}");
    let reach = reachable_suites(graph, Some(&assume));
    let bad = forbidden_reachable(&reach, &classical);

    json!({
        "classical_only": classical,
        "ok": bad.is_empty(),
        "phase_floor": floor_val,
        "violations": bad
    })
}

/// P5: Decidability.
pub fn prove_decidable(graph: &Graph) -> Value {
    let (ok, bad) = flow_level_m(graph);
    json!({
        "non_member_edges": bad,
        "ok": ok
    })
}

/// Prove all P1-P5.
pub fn prove_all(graph: &Graph, envelope: &Value, registry: &Value) -> Value {
    let p1 = prove_envelope_closure(graph, envelope);
    let p2 = prove_totality(graph);
    let p3 = prove_class_floor(graph, envelope, registry);
    let p4 = prove_monotone_migration(graph, envelope, registry);
    let p5 = prove_decidable(graph);

    let ok = p1["ok"].as_bool().unwrap_or(false)
        && p2["ok"].as_bool().unwrap_or(false)
        && p3["ok"].as_bool().unwrap_or(false)
        && p4["ok"].as_bool().unwrap_or(false)
        && p5["ok"].as_bool().unwrap_or(false);

    let proofs = json!({
        "P1_envelope_closure": p1,
        "P2_totality": p2,
        "P3_class_floor": p3,
        "P4_monotone_migration": p4,
        "P5_decidable": p5
    });

    json!({
        "ok": ok,
        "proofs": proofs
    })
}
