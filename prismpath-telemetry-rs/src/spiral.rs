// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! Tier 6 — decision-first Fermat-spiral spatial packing (progressive, integer-only).

use crate::quantizer::{self, FieldPartition};
use crate::wire;
use crate::zeckendorf;
use prismpath_rs::{Graph, V};
use serde_json::json;
use std::collections::HashMap;

pub const GOLDEN_ANGLE_U32: u32 = 0x9E3779B9;
pub const GOLDEN_ANGLE_DEG: f64 = 180.0 * (3.0 - 2.23606797749979);

const ALWAYS: &[&str] = &["always", "true", "else", "otherwise", "default", "_"];
const NEVER: &[&str] = &["false", "never"];

pub fn theta_u32(n: u32) -> u32 {
    n.wrapping_mul(GOLDEN_ANGLE_U32)
}

pub fn radius2(n: u32) -> u32 {
    n
}

pub fn spiral_xy(n: usize, c: f64) -> (f64, f64) {
    let r = c * (n as f64).sqrt();
    let theta = (n as f64 * GOLDEN_ANGLE_DEG).to_radians();
    (r * theta.cos(), r * theta.sin())
}

pub fn mixed_radix_gray(radices: &[usize]) -> Vec<Vec<usize>> {
    let n_fields = radices.len();
    if n_fields == 0 {
        return vec![];
    }
    let mut digits = vec![0isize; n_fields];
    let mut directions = vec![1isize; n_fields];
    let mut total = 1;
    for &r in radices {
        total *= r;
    }
    let mut out = Vec::with_capacity(total);
    out.push(digits.iter().map(|&d| d as usize).collect());

    for _ in 1..total {
        let mut i = (n_fields - 1) as isize;
        while i >= 0 {
            let idx = i as usize;
            let nd = digits[idx] + directions[idx];
            if nd >= 0 && (nd as usize) < radices[idx] {
                digits[idx] = nd;
                break;
            }
            directions[idx] = -directions[idx];
            i -= 1;
        }
        out.push(digits.iter().map(|&d| d as usize).collect());
    }
    out
}

fn expr_of(cond: &str) -> String {
    let c = cond.trim();
    if c.to_lowercase().starts_with("when ") {
        c[5..].trim().to_string()
    } else {
        c.to_string()
    }
}

fn node_fields(graph: &Graph, node: &str, parts: &HashMap<String, FieldPartition>) -> Vec<String> {
    let mut seen = Vec::new();
    if let Some(n) = graph.nodes.get(node) {
        for (_target, cond) in &n.edges {
            if !prismpath_rs::is_deterministic(cond) || prismpath_rs::is_semantic(cond) {
                continue;
            }
            let expr = expr_of(cond);
            let lower = expr.to_lowercase();
            if ALWAYS.contains(&lower.as_str()) || NEVER.contains(&lower.as_str()) {
                continue;
            }
            for atom in quantizer::parse_atoms(&expr) {
                if parts.contains_key(&atom.field) && !seen.contains(&atom.field) {
                    seen.push(atom.field);
                }
            }
        }
    }
    seen.sort();
    seen
}

#[derive(Debug, Clone)]
pub struct SpiralLayout {
    pub graph: Graph,
    pub node: String,
    pub parts: HashMap<String, FieldPartition>,
    pub fields: Vec<String>,
    pub radices: Vec<usize>,
    pub routes: Vec<Option<String>>,
    pub band_index: HashMap<Option<String>, usize>,
    pub band_base: Vec<usize>,
    pub band_width: Vec<usize>,
    pub cell_of: Vec<Vec<usize>>,
    pub n_of: HashMap<Vec<usize>, usize>,
    pub size: usize,
}

impl SpiralLayout {
    pub fn new(graph: &Graph, node: &str) -> Result<Self, String> {
        let parts = quantizer::build_partitions(graph);
        let fields = node_fields(graph, node, &parts);
        if fields.is_empty() {
            return Err(format!(
                "node {:?} routes on no decision-relevant fields — nothing to pack",
                node
            ));
        }
        let radices: Vec<usize> = fields.iter().map(|f| parts[f].n).collect();

        let route_order = route_order_map(graph, node);

        let mut buckets: HashMap<Option<String>, Vec<Vec<usize>>> = HashMap::new();
        let mut bucket_order: Vec<Option<String>> = Vec::new();

        for cell in mixed_radix_gray(&radices) {
            let r = route_of_cell(graph, node, &parts, &fields, &cell);
            if !bucket_order.contains(&r) {
                bucket_order.push(r.clone());
            }
            buckets.entry(r).or_default().push(cell);
        }

        let mut routes = bucket_order;
        routes.sort_by_key(|r| route_order.get(r).copied().unwrap_or(route_order.len()));

        let mut band_index = HashMap::new();
        for (i, r) in routes.iter().enumerate() {
            band_index.insert(r.clone(), i);
        }

        let mut band_base = Vec::new();
        let mut band_width = Vec::new();
        let mut cell_of = Vec::new();
        let mut n_of = HashMap::new();
        let mut base = 0;

        for r in &routes {
            let cells = &buckets[r];
            band_base.push(base);
            band_width.push(cells.len());
            for cell in cells {
                n_of.insert(cell.clone(), cell_of.len());
                cell_of.push(cell.clone());
            }
            base += cells.len();
        }

        Ok(SpiralLayout {
            graph: graph.clone(),
            node: node.to_string(),
            parts,
            fields,
            radices,
            routes,
            band_index,
            band_base,
            band_width,
            cell_of,
            n_of,
            size: base,
        })
    }

    /// Panicking variant, std indexing style (`slice[i]` vs `slice.get(i)`); see [`Self::try_cell`].
    /// Precondition: the reading carries every spiral field with an in-partition value. The spiral
    /// is the Tier 6 layout layer, not the codec path.
    pub fn cell(&self, reading: &HashMap<String, V>) -> Vec<usize> {
        self.try_cell(reading)
            .expect("spiral reading value outside its partition")
    }

    /// Fallible twin of [`Self::cell`]: a missing spiral field or an out-of-partition value is an
    /// `Err`, never a panic.
    pub fn try_cell(&self, reading: &HashMap<String, V>) -> Result<Vec<usize>, String> {
        self.fields
            .iter()
            .map(|f| {
                let v = reading
                    .get(f)
                    .ok_or_else(|| format!("reading missing spiral field {f:?}"))?;
                self.parts[f].symbol(v)
            })
            .collect()
    }

    /// Panicking variant; see [`Self::try_index`].
    pub fn index(&self, reading: &HashMap<String, V>) -> usize {
        self.try_index(reading).expect("spiral reading value outside its partition")
    }

    pub fn try_index(&self, reading: &HashMap<String, V>) -> Result<usize, String> {
        let cell = self.try_cell(reading)?;
        self.n_of
            .get(&cell)
            .copied()
            .ok_or_else(|| format!("cell {cell:?} is not in the spiral layout"))
    }

    /// Panicking variant; see [`Self::try_band_id`].
    pub fn band_id(&self, reading: &HashMap<String, V>) -> usize {
        self.try_band_id(reading).expect("spiral reading value outside its partition")
    }

    pub fn try_band_id(&self, reading: &HashMap<String, V>) -> Result<usize, String> {
        let cell = self.try_cell(reading)?;
        let route = route_of_cell(&self.graph, &self.node, &self.parts, &self.fields, &cell);
        self.band_index
            .get(&route)
            .copied()
            .ok_or_else(|| format!("route {route:?} is not in the band layout"))
    }

    /// Panicking variant; see [`Self::try_route_of`].
    pub fn route_of(&self, n: usize) -> Option<String> {
        self.try_route_of(n).unwrap_or_else(|e| panic!("{}", e))
    }

    /// Fallible twin of [`Self::route_of`]: an index outside the spiral is an `Err`.
    pub fn try_route_of(&self, n: usize) -> Result<Option<String>, String> {
        for b in 0..self.routes.len() {
            if n < self.band_base[b] + self.band_width[b] {
                return Ok(self.routes[b].clone());
            }
        }
        Err(format!("index {} outside the spiral ({} cells)", n, self.size))
    }

    pub fn band_bounds(&self) -> Vec<(usize, usize, Option<String>)> {
        (0..self.routes.len())
            .map(|b| {
                (
                    self.band_base[b],
                    self.band_base[b] + self.band_width[b],
                    self.routes[b].clone(),
                )
            })
            .collect()
    }

    /// Panicking variant; see [`Self::try_reconstruct_band`].
    pub fn reconstruct_band(&self, band_id: usize) -> HashMap<String, V> {
        self.try_reconstruct_band(band_id)
            .unwrap_or_else(|e| panic!("{}", e))
    }

    pub fn try_reconstruct_band(&self, band_id: usize) -> Result<HashMap<String, V>, String> {
        let base = *self
            .band_base
            .get(band_id)
            .ok_or_else(|| format!("band {} outside the layout ({} bands)", band_id, self.routes.len()))?;
        Ok(cell_reading(&self.parts, &self.fields, &self.cell_of[base]))
    }

    /// Panicking variant; see [`Self::try_reconstruct`].
    pub fn reconstruct(&self, n: usize) -> HashMap<String, V> {
        self.try_reconstruct(n).unwrap_or_else(|e| panic!("{}", e))
    }

    pub fn try_reconstruct(&self, n: usize) -> Result<HashMap<String, V>, String> {
        let cell = self
            .cell_of
            .get(n)
            .ok_or_else(|| format!("index {} outside the spiral ({} cells)", n, self.size))?;
        Ok(cell_reading(&self.parts, &self.fields, cell))
    }

    /// Panicking variant; see [`Self::try_encode_decision`].
    pub fn encode_decision(&self, reading: &HashMap<String, V>) -> String {
        self.try_encode_decision(reading)
            .expect("spiral reading value outside its partition")
    }

    pub fn try_encode_decision(&self, reading: &HashMap<String, V>) -> Result<String, String> {
        // band_id + 1 >= 1, and zeckendorf::encode only errs for inputs < 1 — infallible here.
        zeckendorf::encode(self.try_band_id(reading)? + 1)
    }

    pub fn decode_decision(&self, bits: &str) -> Result<Option<String>, String> {
        // `bits` is untrusted wire data: a crafted code can decode to any index. checked_sub guards
        // the 1-based underflow and `.get` guards the out-of-range read — neither may panic here.
        let b = zeckendorf::decode(bits)?
            .checked_sub(1)
            .ok_or_else(|| "decoded band index 0 is invalid (codes are 1-based)".to_string())?;
        self.routes
            .get(b)
            .cloned()
            .ok_or_else(|| format!("decoded band index {b} is outside the layout ({} bands)", self.routes.len()))
    }

    /// Panicking variant; see [`Self::try_encode_progressive`].
    pub fn encode_progressive(&self, reading: &HashMap<String, V>) -> (String, String) {
        self.try_encode_progressive(reading)
            .expect("spiral reading value outside its partition")
    }

    pub fn try_encode_progressive(&self, reading: &HashMap<String, V>) -> Result<(String, String), String> {
        let n = self.try_index(reading)?;
        let route = self.try_route_of(n)?;
        let b = *self
            .band_index
            .get(&route)
            .ok_or_else(|| format!("route {route:?} is not in the band layout"))?;
        let local = n - self.band_base[b];
        // b + 1 and local + 1 are both >= 1; encode only errs for inputs < 1.
        Ok((zeckendorf::encode(b + 1)?, zeckendorf::encode(local + 1)?))
    }

    pub fn decode_progressive(
        &self,
        decision_bits: &str,
        refine_bits: &str,
    ) -> Result<HashMap<String, V>, String> {
        let b = zeckendorf::decode(decision_bits)? - 1;
        let local = zeckendorf::decode(refine_bits)? - 1;
        Ok(self.reconstruct(self.band_base[b] + local))
    }

    pub fn tessellation(&self) -> serde_json::Value {
        let cells: Vec<serde_json::Value> = self
            .cell_of
            .iter()
            .enumerate()
            .map(|(n, cell)| {
                let (x, y) = spiral_xy(n, 1.0);
                json!({
                    "cell": cell,
                    "n": n,
                    "band": self.band_index[&self.route_of(n)],
                    "route": self.route_of(n),
                    "xy": [(x * 1e6).round() / 1e6, (y * 1e6).round() / 1e6]
                })
            })
            .collect();

        let bands: Vec<serde_json::Value> = self
            .routes
            .iter()
            .enumerate()
            .map(|(i, r)| {
                json!({
                    "route": r,
                    "base": self.band_base[i],
                    "width": self.band_width[i]
                })
            })
            .collect();

        json!({
            "node": self.node,
            "fields": self.fields,
            "radices": self.radices,
            "bands": bands,
            "size": self.size,
            "cells": cells
        })
    }
}

fn route_order_map(graph: &Graph, node: &str) -> HashMap<Option<String>, usize> {
    let mut appear: Vec<Option<String>> = Vec::new();
    if let Some(n) = graph.nodes.get(node) {
        for (target, cond) in &n.edges {
            if prismpath_rs::is_deterministic(cond) {
                let t_opt = Some(target.clone());
                if !appear.contains(&t_opt) {
                    appear.push(t_opt);
                }
            }
        }
    }
    appear.reverse();
    let mut map = HashMap::new();
    for (i, t) in appear.into_iter().enumerate() {
        map.insert(t, i);
    }
    map
}

fn cell_reading(
    parts: &HashMap<String, FieldPartition>,
    fields: &[String],
    cell: &[usize],
) -> HashMap<String, V> {
    fields
        .iter()
        .zip(cell.iter())
        .map(|(f, &s)| (f.clone(), parts[f].representative(s)))
        .collect()
}

fn route_of_cell(
    graph: &Graph,
    node: &str,
    parts: &HashMap<String, FieldPartition>,
    fields: &[String],
    cell: &[usize],
) -> Option<String> {
    let reading = cell_reading(parts, fields, cell);
    wire::route_node(graph, node, &reading)
}
