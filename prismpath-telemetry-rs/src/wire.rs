// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
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

/// A reading through any symbol codec, or the reason it is refused. Since October 2026 this is the
/// checked path: a missing field or a value acceptance refuses is a refusal naming the field, the
/// same as `encode_reading_checked`, because the permissive path no longer parsed, truncated or
/// coerced anything that could tell the two apart. A flow that defines its fields encodes a missing
/// field as its absent cell when the definition allows absence.
pub fn encode_reading_with_codec<C: WireCodec>(
    codec: &C,
    parts: &HashMap<String, FieldPartition>,
    reading: &HashMap<String, V>,
) -> Result<String, String> {
    let ord = order(parts);
    let syms = quantizer::checked_quantize(parts, reading).map_err(|error| error.to_string())?;
    let wire_vals: Vec<usize> = ord.iter().map(|f| syms[f] + 1).collect();
    codec.encode_symbols(&wire_vals)
}

/// `encode_reading` behind acceptance: a value the contract refuses is an
/// `AcceptanceError` naming the field and the reason, never a truncated, coerced or zero
/// reading. Encode through this at a runtime boundary; a preflight run over the same sample reports
/// exactly the refusals this returns.
pub fn encode_reading_checked(
    parts: &HashMap<String, FieldPartition>,
    reading: &HashMap<String, V>,
) -> Result<String, quantizer::AcceptanceError> {
    let field_order = order(parts);
    let symbols = quantizer::checked_quantize(parts, reading)?;
    let wire_values: Vec<usize> = field_order.iter().map(|field| symbols[field] + 1).collect();
    FibonacciWireCodec.encode_symbols(&wire_values).map_err(|_| quantizer::AcceptanceError {
        field: String::new(), refusal: quantizer::InputRefusal::OutOfRange })
}

/// A policy's encoder: the field order sorted once, each reading quantized and coded straight into packed
/// words. `encode_packed` gives the bytes `packed::pack(&encode_reading(parts, reading)?, word_bits)` gives,
/// with the same refusal in the same field order, without building the symbol map or the bit string.
pub struct Encoder<'a> {
    fields: Vec<(&'a String, &'a FieldPartition)>,
    word_bits: usize,
}

impl<'a> Encoder<'a> {
    /// An encoder for `parts`, packing `word_bits`-bit words (a multiple of 8 from 8 to 64).
    pub fn new(parts: &'a HashMap<String, FieldPartition>, word_bits: usize) -> Self {
        assert!(crate::packed::writer_word_bits(word_bits), "word_bits must be 8 to 64 in steps of 8");
        let mut fields: Vec<(&String, &FieldPartition)> = parts.iter().collect();
        fields.sort_by(|left, right| left.0.cmp(right.0));
        Encoder { fields, word_bits }
    }

    /// The reading's cell symbols in field order, as `quantizer::checked_quantize` reads them.
    pub fn symbols_into(&self, reading: &HashMap<String, V>, out: &mut Vec<usize>) -> Result<(), quantizer::AcceptanceError> {
        out.clear();
        for (field, partition) in &self.fields {
            let value = match reading.get(*field) {
                Some(value) => value,
                None if partition.definition.is_some() => &V::Null,
                None => return Err(quantizer::AcceptanceError { field: (*field).clone(), refusal: quantizer::InputRefusal::Missing }),
            };
            out.push(partition.checked_symbol(value)?);
        }
        Ok(())
    }

    /// One reading's packed bytes, appended to `dest`; on a refusal `dest` is left as it was.
    pub fn encode_packed_into(&self, reading: &HashMap<String, V>, dest: &mut Vec<u8>) -> Result<(), String> {
        crate::packed::BitWriter::write_into(dest, self.word_bits, |writer| {
            for (field, partition) in &self.fields {
                let value = match reading.get(*field) {
                    Some(value) => value,
                    None if partition.definition.is_some() => &V::Null,
                    None => {
                        return Err(quantizer::AcceptanceError { field: (*field).clone(), refusal: quantizer::InputRefusal::Missing }.to_string())
                    }
                };
                let symbol = partition.checked_symbol(value).map_err(|error| error.to_string())?;
                let (code, len) = zeckendorf::code_bits(symbol + 1).expect("a symbol + 1 is positive");
                writer.put(code, len);
            }
            Ok(())
        })
    }

    /// Packed bytes for a reading given as one value per field in wire order (`fields`), appended to `dest`,
    /// with each value accepted and refused as `encode_packed_into` would; `V::Null` stands for a missing
    /// value. On a refusal `dest` is left as it was.
    pub fn encode_row_into(&self, row: &[V], dest: &mut Vec<u8>) -> Result<(), String> {
        if row.len() != self.fields.len() {
            return Err(format!("{} values for {} fields", row.len(), self.fields.len()));
        }
        crate::packed::BitWriter::write_into(dest, self.word_bits, |writer| {
            for ((field, partition), value) in self.fields.iter().zip(row) {
                if matches!(value, V::Null) && partition.definition.is_none() {
                    return Err(quantizer::AcceptanceError { field: (*field).clone(), refusal: quantizer::InputRefusal::Missing }.to_string());
                }
                let symbol = partition.checked_symbol(value).map_err(|error| error.to_string())?;
                let (code, len) = zeckendorf::code_bits(symbol + 1).expect("a symbol + 1 is positive");
                writer.put(code, len);
            }
            Ok(())
        })
    }

    /// One reading's packed bytes.
    pub fn encode_packed(&self, reading: &HashMap<String, V>) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        self.encode_packed_into(reading, &mut out)?;
        Ok(out)
    }

    /// Packed bytes for cell symbols already in field order (one per field), for a caller that quantized
    /// them itself.
    pub fn encode_symbols_packed(&self, symbols: &[usize], dest: &mut Vec<u8>) -> Result<(), String> {
        if symbols.len() != self.fields.len() {
            return Err(format!("{} symbols for {} fields", symbols.len(), self.fields.len()));
        }
        crate::packed::BitWriter::write_into(dest, self.word_bits, |writer| {
            for &symbol in symbols {
                let code_value = symbol.checked_add(1).ok_or_else(|| format!("symbol {symbol} is beyond the wire's range"))?;
                let (code, len) = zeckendorf::code_bits(code_value).expect("a symbol + 1 is positive");
                writer.put(code, len);
            }
            Ok(())
        })
    }

    /// The fields in wire order.
    pub fn fields(&self) -> Vec<&str> {
        self.fields.iter().map(|(field, _)| field.as_str()).collect()
    }
}

/// Why a stream did not decode under its policy: the decoder's own message and, where it is exactly one of the
/// strict decode causes, the registry code beside it. A symbol count that is not the policy's field count is
/// `wire:codebook-mismatch` (51, invariant I3); the other refusal carries none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireRefusal {
    pub message: String,
    pub cause: Option<u8>,
}

impl std::fmt::Display for WireRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.message)
    }
}
impl std::error::Error for WireRefusal {}

pub fn decode_reading(
    parts: &HashMap<String, FieldPartition>,
    bits: &str,
) -> Result<HashMap<String, V>, WireRefusal> {
    decode_reading_with_codec(&FibonacciWireCodec, parts, bits)
}

pub fn decode_reading_with_codec<C: WireCodec>(
    codec: &C,
    parts: &HashMap<String, FieldPartition>,
    bits: &str,
) -> Result<HashMap<String, V>, WireRefusal> {
    let ord = order(parts);
    let wire = codec.decode_symbols(bits);
    if wire.len() != ord.len() {
        return Err(WireRefusal {
            message: format!("symbol count {} != decision fields {}", wire.len(), ord.len()),
            cause: Some(prismpath_rs::causes::WIRE_CODEBOOK_MISMATCH),
        });
    }
    let mut syms: HashMap<String, usize> = HashMap::new();
    for (i, f) in ord.into_iter().enumerate() {
        let s = wire[i]
            .checked_sub(1)
            .ok_or_else(|| WireRefusal { message: format!("invalid wire symbol 0 for field {f}"), cause: None })?;
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
