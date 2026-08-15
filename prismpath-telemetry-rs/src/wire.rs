//! Wire glue — a reading <-> a self-framing Fibonacci bitstream, through the decision-preserving quantizer.

use crate::quantizer::{self, FieldPartition};
use crate::zeckendorf;
use prismpath_rs::{Graph, V};
use std::collections::HashMap;

pub trait WireCodec {
    fn encode_symbols(&self, symbols: &[usize]) -> Result<String, String>;
    fn decode_symbols(&self, bits: &str) -> Vec<usize>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct FibonacciWireCodec;

impl WireCodec for FibonacciWireCodec {
    fn encode_symbols(&self, symbols: &[usize]) -> Result<String, String> {
        zeckendorf::encode_stream(symbols)
    }

    fn decode_symbols(&self, bits: &str) -> Vec<usize> {
        zeckendorf::decode_stream(bits)
    }
}

pub fn order(parts: &HashMap<String, FieldPartition>) -> Vec<String> {
    let mut keys: Vec<String> = parts.keys().cloned().collect();
    keys.sort();
    keys
}

pub fn encode_reading(
    parts: &HashMap<String, FieldPartition>,
    reading: &HashMap<String, V>,
) -> Result<String, String> {
    encode_reading_with_codec(&FibonacciWireCodec, parts, reading)
}

pub fn encode_reading_with_codec<C: WireCodec>(
    codec: &C,
    parts: &HashMap<String, FieldPartition>,
    reading: &HashMap<String, V>,
) -> Result<String, String> {
    let ord = order(parts);
    let missing: Vec<&str> = ord
        .iter()
        .filter(|f| !reading.contains_key(*f))
        .map(|s| s.as_str())
        .collect();
    if !missing.is_empty() {
        return Err(format!("reading missing decision fields: {:?}", missing));
    }
    let syms = quantizer::quantize(parts, reading)?;
    let wire_vals: Vec<usize> = ord.iter().map(|f| syms[f] + 1).collect();
    codec.encode_symbols(&wire_vals)
}

pub fn decode_reading(
    parts: &HashMap<String, FieldPartition>,
    bits: &str,
) -> Result<HashMap<String, V>, String> {
    decode_reading_with_codec(&FibonacciWireCodec, parts, bits)
}

pub fn decode_reading_with_codec<C: WireCodec>(
    codec: &C,
    parts: &HashMap<String, FieldPartition>,
    bits: &str,
) -> Result<HashMap<String, V>, String> {
    let ord = order(parts);
    let wire = codec.decode_symbols(bits);
    if wire.len() != ord.len() {
        return Err(format!(
            "symbol count {} != decision fields {}",
            wire.len(),
            ord.len()
        ));
    }
    let mut syms: HashMap<String, usize> = HashMap::new();
    for (i, f) in ord.into_iter().enumerate() {
        let s = wire[i]
            .checked_sub(1)
            .ok_or_else(|| format!("invalid wire symbol 0 for field {f}"))?;
        syms.insert(f, s);
    }
    Ok(quantizer::reconstruct(parts, &syms))
}

pub fn route_node(graph: &Graph, node: &str, reading: &HashMap<String, V>) -> Option<String> {
    if let Some(n) = graph.nodes.get(node) {
        for (target, cond) in &n.edges {
            if prismpath_rs::is_deterministic(cond) {
                if let Ok(true) = prismpath_rs::eval_condition(cond, reading) {
                    return Some(target.clone());
                }
            }
        }
    }
    None
}

pub fn decision_nodes(graph: &Graph) -> Vec<String> {
    decision_nodes_from_text(graph, None)
}

pub fn decision_nodes_from_text(graph: &Graph, text: Option<&str>) -> Vec<String> {
    let mut names = Vec::new();
    if let Some(txt) = text {
        for line in txt.lines() {
            let l = line.trim();
            if let Some(rest) = l.strip_prefix("## ") {
                let name = rest.trim().to_lowercase().replace(' ', "_");
                if let Some(node) = graph.nodes.get(&name) {
                    if node.edges.iter().any(|(_t, c)| prismpath_rs::is_deterministic(c))
                        && !names.contains(&name)
                    {
                        names.push(name.clone());
                    }
                }
            }
        }
    }
    if names.is_empty() {
        let mut ordered_keys = Vec::new();
        if graph.nodes.contains_key(&graph.start) {
            ordered_keys.push(graph.start.clone());
        }
        let mut rest: Vec<String> = graph.nodes.keys().cloned().collect();
        rest.sort();
        for k in rest {
            if !ordered_keys.contains(&k) {
                ordered_keys.push(k);
            }
        }
        for name in ordered_keys {
            if let Some(node) = graph.nodes.get(&name) {
                if node.edges.iter().any(|(_t, c)| prismpath_rs::is_deterministic(c)) {
                    names.push(name);
                }
            }
        }
    }
    names
}
