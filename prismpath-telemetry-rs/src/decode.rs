// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! Human-readable inspect path — decoding a captured telemetry bitstream against its flow.

use crate::quantizer::{self, FieldPartition, OTHER};
use crate::wire;
use crate::zeckendorf;
use prismpath_rs::{Graph, V};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub fn v_to_json(v: &V) -> serde_json::Value {
    match v {
        V::Null => serde_json::Value::Null,
        V::Bool(b) => serde_json::Value::Bool(*b),
        V::Num(n) => {
            if let Some(num) = serde_json::Number::from_f64(*n) {
                serde_json::Value::Number(num)
            } else if n.fract() == 0.0 {
                serde_json::Value::Number((*n as i64).into())
            } else {
                serde_json::Value::Null
            }
        }
        V::Str(s) => serde_json::Value::String(s.clone()),
        V::List(l) => serde_json::Value::Array(l.iter().map(v_to_json).collect()),
        V::Obj(entries) => {
            let mut map = serde_json::Map::new();
            for (k, val) in entries {
                map.insert(k.clone(), v_to_json(val));
            }
            serde_json::Value::Object(map)
        }
        V::Ellipsis => serde_json::Value::String("...".to_string()),
    }
}

fn serialize_v_map<S>(
    map: &HashMap<String, V>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let json_map: HashMap<String, serde_json::Value> = map
        .iter()
        .map(|(k, v)| (k.clone(), v_to_json(v)))
        .collect();
    json_map.serialize(serializer)
}

fn deserialize_v_map<'de, D>(
    deserializer: D,
) -> Result<HashMap<String, V>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let json_map: HashMap<String, serde_json::Value> = HashMap::deserialize(deserializer)?;
    Ok(json_map
        .into_iter()
        .map(|(k, v)| (k, V::from_json(&v)))
        .collect())
}

pub fn encode_readings(
    parts: &HashMap<String, FieldPartition>,
    readings: &[HashMap<String, V>],
) -> Result<String, String> {
    let mut out = String::new();
    for r in readings {
        out.push_str(&wire::encode_reading(parts, r)?);
    }
    Ok(out)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadingRow {
    pub symbols: HashMap<String, usize>,
    #[serde(serialize_with = "serialize_v_map", deserialize_with = "deserialize_v_map")]
    pub reading: HashMap<String, V>,
    pub routes: HashMap<String, Option<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectReport {
    pub fields: Vec<String>,
    pub decision_nodes: Vec<String>,
    pub n_readings: usize,
    pub trailing_ints: usize,
    pub readings: Vec<ReadingRow>,
    pub route_distribution: HashMap<String, usize>,
}

pub fn inspect(graph: &Graph, bits: &str) -> InspectReport {
    let parts = quantizer::build_partitions(graph);
    let fields = wire::order(&parts);
    let nodes = wire::decision_nodes(graph);
    let nf = fields.len();
    let wire_ints = zeckendorf::decode_stream(bits);
    let n_complete = wire_ints.len().checked_div(nf).unwrap_or(0);

    let mut rows = Vec::new();
    let mut route_dist: HashMap<String, usize> = HashMap::new();

    for i in 0..n_complete {
        let syms: HashMap<String, usize> = fields
            .iter()
            .enumerate()
            .map(|(j, f)| (f.clone(), wire_ints[i * nf + j] - 1))
            .collect();
        let reading = quantizer::reconstruct(&parts, &syms);
        let routes: HashMap<String, Option<String>> = nodes
            .iter()
            .map(|n| (n.clone(), wire::route_node(graph, n, &reading)))
            .collect();

        let show_reading: HashMap<String, V> = reading
            .into_iter()
            .map(|(f, v)| {
                if v == V::Str(OTHER.to_string()) {
                    (f, V::Str("<other>".to_string()))
                } else {
                    (f, v)
                }
            })
            .collect();

        let mut route_pairs: Vec<String> = nodes
            .iter()
            .map(|n| {
                let target = routes.get(n).cloned().flatten().unwrap_or_else(|| "None".to_string());
                format!("{}={}", n, target)
            })
            .collect();
        route_pairs.sort();
        let dist_key = route_pairs.join(" ");
        *route_dist.entry(dist_key).or_default() += 1;

        rows.push(ReadingRow {
            symbols: syms,
            reading: show_reading,
            routes,
        });
    }

    let trailing_ints = wire_ints.len() - n_complete * nf;

    InspectReport {
        fields,
        decision_nodes: nodes,
        n_readings: rows.len(),
        trailing_ints,
        readings: rows,
        route_distribution: route_dist,
    }
}

pub fn render(rep: &InspectReport) -> String {
    let mut out = vec![
        format!("fields: {:?}   decision nodes: {:?}", rep.fields, rep.decision_nodes),
        format!(
            "decoded {} reading(s){}",
            rep.n_readings,
            if rep.trailing_ints > 0 {
                format!("  (+{} trailing int(s) = partial final frame)", rep.trailing_ints)
            } else {
                "".to_string()
            }
        ),
        "".to_string(),
    ];

    for (i, r) in rep.readings.iter().enumerate() {
        let mut route_parts = Vec::new();
        for n in &rep.decision_nodes {
            if let Some(target) = r.routes.get(n) {
                route_parts.push(format!(
                    "{}->{}",
                    n,
                    target.as_deref().unwrap_or("None")
                ));
            }
        }
        let route_str = route_parts.join(", ");
        out.push(format!("#{:4}  {:?}   =>  {}", i, r.reading, route_str));
    }

    out.push("".to_string());
    out.push("route distribution:".to_string());

    let mut dist_entries: Vec<(&String, &usize)> = rep.route_distribution.iter().collect();
    dist_entries.sort_by_key(|&(_, count)| std::cmp::Reverse(*count));

    for (k, c) in dist_entries {
        out.push(format!("  {:6}  {}", c, k));
    }

    out.join("\n")
}
