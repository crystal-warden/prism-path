// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The table driven codes, the bit writer and `wire::Encoder` give the bytes the string path gives.
//!
//! `reference_*` below are the string algorithms as they were before the codes were built as integers:
//! a Fibonacci table per value, one char per bit, and `pack` walking the chars. Every new path is held to
//! them, and the frozen corpora tests elsewhere hold the string path to Python.

use prismpath_rs::{parse, V};
use prismpath_telemetry_rs::{packed, quantizer as q, wire as w, zeckendorf as z};
use serde_json::Value;
use std::collections::HashMap;

fn reference_encode(value: usize) -> String {
    let mut fibs = vec![1usize, 2];
    while *fibs.last().unwrap() <= value {
        match fibs[fibs.len() - 1].checked_add(fibs[fibs.len() - 2]) {
            Some(next) => fibs.push(next),
            None => break,
        }
    }
    if *fibs.last().unwrap() > value {
        fibs.pop();
    }
    let mut bits = vec!['0'; fibs.len()];
    let mut rem = value;
    for index in (0..fibs.len()).rev() {
        if fibs[index] <= rem {
            bits[index] = '1';
            rem -= fibs[index];
        }
    }
    let mut out: String = bits.into_iter().collect();
    out.push('1');
    out
}

fn reference_pack(bits: &str, word_bits: usize) -> Vec<u8> {
    let bytes_per_word = word_bits / 8;
    let mut out = Vec::new();
    let (mut acc, mut filled): (u128, usize) = (0, 0);
    for ch in bits.chars() {
        acc = (acc << 1) | u128::from(ch == '1');
        filled += 1;
        if filled == word_bits {
            out.extend_from_slice(&acc.to_be_bytes()[16 - bytes_per_word..]);
            acc = 0;
            filled = 0;
        }
    }
    if filled > 0 {
        acc <<= word_bits - filled;
        out.extend_from_slice(&acc.to_be_bytes()[16 - bytes_per_word..]);
    }
    out
}

/// A small deterministic generator, so the test needs no crate and every run sees the same values.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 11
    }
}

#[test]
fn the_codes_are_the_reference_codes() {
    for value in 1..=200_000usize {
        assert_eq!(z::encode(value).unwrap(), reference_encode(value), "{value}");
    }
    let mut rng = Lcg(7);
    for _ in 0..20_000 {
        let value = (rng.next() as usize).max(1);
        assert_eq!(z::encode(value).unwrap(), reference_encode(value), "{value}");
    }
    for value in [usize::MAX, usize::MAX - 1, usize::MAX / 2, (1usize << 63) + 1] {
        assert_eq!(z::encode(value).unwrap(), reference_encode(value), "{value}");
    }
    assert!(z::encode(0).is_err() && z::code_bits(0).is_none());
}

#[test]
fn the_code_bits_spell_the_code() {
    for value in (1..5_000usize).chain([usize::MAX]) {
        let (code, len) = z::code_bits(value).unwrap();
        let spelled: String = (0..len).rev().map(|bit| if (code >> bit) & 1 == 1 { '1' } else { '0' }).collect();
        assert_eq!(spelled, reference_encode(value));
    }
}

#[test]
fn pack_gives_the_reference_bytes_at_every_word_size() {
    let mut rng = Lcg(11);
    for word_bits in [8usize, 16, 24, 32, 40, 48, 56, 64, 96, 128] {
        for length in (0..300).chain([511, 512, 513, 4096]) {
            let bits: String = (0..length).map(|_| if rng.next() & 1 == 1 { '1' } else { '0' }).collect();
            assert_eq!(packed::pack(&bits, word_bits), reference_pack(&bits, word_bits), "{word_bits} {length}");
        }
    }
}

#[test]
fn packed_encode_is_the_packed_string_stream() {
    let mut rng = Lcg(13);
    for word_bits in [8usize, 16, 32, 64, 128] {
        for count in [0usize, 1, 2, 7, 64, 1000] {
            let ints: Vec<usize> = (0..count).map(|_| (rng.next() % 1_000_000) as usize + 1).collect();
            let via_strings = reference_pack(&ints.iter().map(|&v| reference_encode(v)).collect::<String>(), word_bits);
            assert_eq!(packed::encode(&ints, word_bits).unwrap(), via_strings, "{word_bits} {count}");
        }
    }
    assert!(packed::encode(&[3, 0, 2], 64).is_err());
}

fn decisions() -> Value {
    serde_json::from_str(&std::fs::read_to_string("tests/fixtures/decisions.json").unwrap()).unwrap()
}

fn reading_of(entry: &Value) -> HashMap<String, V> {
    entry["reading"].as_object().unwrap().iter().map(|(k, v)| (k.clone(), V::from_json(v))).collect()
}

#[test]
fn the_encoder_gives_the_bytes_and_refusals_of_encode_reading_then_pack() {
    let corpus = decisions();
    let mut checked = 0;
    for case in corpus["cases"].as_array().unwrap() {
        let parts = q::build_partitions(&parse(case["flow"].as_str().unwrap())).unwrap();
        for word_bits in [8usize, 64] {
            let encoder = w::Encoder::new(&parts, word_bits);
            assert_eq!(encoder.fields(), w::order(&parts).iter().map(String::as_str).collect::<Vec<_>>());
            for entry in case["readings"].as_array().unwrap() {
                let reading = reading_of(entry);
                let mut variants = vec![reading.clone()];
                // each field missing, and each field holding a value of another type
                for field in reading.keys() {
                    let mut missing = reading.clone();
                    missing.remove(field);
                    variants.push(missing);
                    let mut wrong = reading.clone();
                    wrong.insert(field.clone(), V::Str("\u{0}not a value".into()));
                    variants.push(wrong);
                    let mut number = reading.clone();
                    number.insert(field.clone(), V::from_json(&serde_json::json!(123456789)));
                    variants.push(number);
                }
                for variant in variants {
                    let expected = w::encode_reading(&parts, &variant).map(|bits| packed::pack(&bits, word_bits));
                    let mut dest = vec![0xAA];
                    let got = encoder.encode_packed_into(&variant, &mut dest);
                    match (&expected, &got) {
                        (Ok(bytes), Ok(())) => assert_eq!(&dest[1..], bytes.as_slice()),
                        (Err(want), Err(have)) => {
                            assert_eq!(want, have);
                            assert_eq!(dest, vec![0xAA], "a refusal must leave dest as it was");
                        }
                        _ => panic!("encode_reading {expected:?} but the encoder {got:?} on {variant:?}"),
                    }
                    if let Ok(bytes) = &expected {
                        let mut symbols = Vec::new();
                        encoder.symbols_into(&variant, &mut symbols).unwrap();
                        let mut from_symbols = Vec::new();
                        encoder.encode_symbols_packed(&symbols, &mut from_symbols).unwrap();
                        assert_eq!(&from_symbols, bytes);
                    }
                    checked += 1;
                }
            }
        }
    }
    assert!(checked > 500, "{checked}");
}

#[test]
fn the_encoder_refuses_a_symbol_list_of_the_wrong_length() {
    let corpus = decisions();
    let parts = q::build_partitions(&parse(corpus["cases"][0]["flow"].as_str().unwrap())).unwrap();
    let encoder = w::Encoder::new(&parts, 64);
    let mut dest = Vec::new();
    assert!(encoder.encode_symbols_packed(&[], &mut dest).is_err() || parts.is_empty());
}

#[test]
fn accept_check_accepts_exactly_what_accept_value_accepts() {
    let values = [
        V::Null, V::Bool(true), V::Bool(false), V::Num(0.0), V::Num(1.0), V::Num(-0.0), V::Num(2.0), V::Num(-7.0),
        V::Num(0.5), V::Num(f64::NAN), V::Num(f64::INFINITY), V::Num(9007199254740992.0), V::Num(9007199254740991.0),
        V::Str("a".into()), V::Str(String::new()), V::from_json(&serde_json::json!([1])), V::from_json(&serde_json::json!({"k": 1})),
    ];
    for kind in [q::FieldKind::Numeric, q::FieldKind::Boolean, q::FieldKind::Categorical] {
        for value in &values {
            assert_eq!(q::accept_check(&kind, value).err(), q::accept_value(&kind, value).err(), "{kind:?} {value:?}");
        }
    }
}

#[test]
fn a_row_in_field_order_encodes_as_its_reading() {
    let corpus = decisions();
    let mut checked = 0;
    for case in corpus["cases"].as_array().unwrap() {
        let parts = q::build_partitions(&parse(case["flow"].as_str().unwrap())).unwrap();
        let encoder = w::Encoder::new(&parts, 64);
        let fields: Vec<String> = encoder.fields().iter().map(|f| f.to_string()).collect();
        for entry in case["readings"].as_array().unwrap() {
            let reading = reading_of(entry);
            let mut variants = vec![reading.clone()];
            for field in &fields {
                let mut missing = reading.clone();
                missing.remove(field);
                variants.push(missing);
            }
            for variant in variants {
                let row: Vec<V> = fields.iter().map(|f| variant.get(f).cloned().unwrap_or(V::Null)).collect();
                let (mut by_map, mut by_row) = (Vec::new(), Vec::new());
                let want = encoder.encode_packed_into(&variant, &mut by_map);
                let got = encoder.encode_row_into(&row, &mut by_row);
                assert_eq!(want, got, "{variant:?}");
                assert_eq!(by_map, by_row);
                checked += 1;
            }
        }
    }
    assert!(checked > 100, "{checked}");
}
