// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The band tier of the grouped spiral profile (PROTOCOL.md 2.6.1), for a node whose joint grid is too
//! large to list. The band is the fired route, coded by its rank in the node's declared edge order, found
//! by evaluating the policy once. Port of `prismpath/telemetry/spiral_groups.py` (`route_order`,
//! `joint_cells`, `GroupedLayout.band_id`, the band tier of `GroupedFacet`). The signature tier is not
//! ported yet.

use crate::quantizer::{self, FieldPartition};
use crate::spiral;
use crate::wire;
use crate::zeckendorf;
use prismpath_rs::{Graph, V};
use std::collections::HashMap;

/// A joint grid over this many cells is not listed by `SpiralLayout`.
pub const ENUMERATION_LIMIT: usize = 300_000;

/// The size of a node's joint grid, the product of its fields' cell counts (saturating).
pub fn joint_cells(graph: &Graph, node: &str, parts: &HashMap<String, FieldPartition>) -> usize {
    spiral::node_fields(graph, node, parts)
        .iter()
        .fold(1usize, |size, field| size.saturating_mul(parts[field].n))
}

/// The bands of a node, centre outward: the deterministic targets in reverse first appearance (the
/// baseline, declared last, is band 0), then `None` for a reading no edge routes.
pub fn route_order(graph: &Graph, node: &str) -> Vec<Option<String>> {
    let mut seen: Vec<String> = Vec::new();
    if let Some(flow_node) = graph.nodes.get(node) {
        for (target, cond) in &flow_node.edges {
            if prismpath_rs::is_deterministic(cond) && !seen.contains(target) {
                seen.push(target.clone());
            }
        }
    }
    let mut routes: Vec<Option<String>> = seen.into_iter().rev().map(Some).collect();
    routes.push(None);
    routes
}

/// The band of a reading, found by evaluating the policy once.
pub fn band_id(graph: &Graph, node: &str, reading: &HashMap<String, V>) -> Result<usize, String> {
    let route = wire::route_node(graph, node, reading);
    route_order(graph, node)
        .iter()
        .position(|candidate| *candidate == route)
        .ok_or_else(|| format!("route {route:?} is not in the band list of {node:?}"))
}

/// One node's band as a Fibonacci code of `band + 1`.
pub fn encode_band(graph: &Graph, node: &str, reading: &HashMap<String, V>) -> Result<String, String> {
    zeckendorf::encode(band_id(graph, node, reading)? + 1)
}

/// A band code back to the route.
pub fn decode_band(graph: &Graph, node: &str, bits: &str) -> Result<Option<String>, String> {
    let band = zeckendorf::decode(bits)?
        .checked_sub(1)
        .ok_or_else(|| "band code 0".to_string())?;
    route_order(graph, node)
        .get(band)
        .cloned()
        .ok_or_else(|| format!("band {band} is outside node {node:?}"))
}

/// The band tier of one decision: every decision node's band code in document order, as
/// `GroupedFacet.encode_reading(reading, TIER_BAND)` writes it.
pub fn encode_decision_band(
    graph: &Graph,
    nodes: &[String],
    reading: &HashMap<String, V>,
) -> Result<String, String> {
    let mut bits = String::new();
    for node in nodes {
        bits.push_str(&encode_band(graph, node, reading)?);
    }
    Ok(bits)
}

/// The decision nodes the profile covers: those that route on at least one decision relevant field.
pub fn profile_nodes(graph: &Graph, parts: &HashMap<String, FieldPartition>) -> Vec<String> {
    wire::decision_nodes(graph)
        .into_iter()
        .filter(|node| !spiral::node_fields(graph, node, parts).is_empty())
        .collect()
}

/// Quantizing the reading first refuses what the encoder refuses, so a band is never sent for a value the
/// wire would not.
pub fn checked_band_id(
    graph: &Graph,
    node: &str,
    parts: &HashMap<String, FieldPartition>,
    reading: &HashMap<String, V>,
) -> Result<usize, String> {
    quantizer::checked_quantize(parts, reading).map_err(|error| format!("{error:?}"))?;
    band_id(graph, node, reading)
}
