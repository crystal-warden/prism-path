//! The receipt stream profile (PROTOCOL.md section 2.10) against the frozen `receipts.json` vectors (cause 0,
//! 36, 52 and the byte maximum) and the generated `receipt_stream.json` (the whole registry by code and by name,
//! every structural refusal, prefixes, bit flips and a seeded round trip), all produced by the Python module.

use prismpath_telemetry_rs::receipts::{self as r, CauseRef, Receipt, ReceiptError};
use serde_json::Value;

fn load(name: &str) -> Value {
    let text = std::fs::read_to_string(format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap_or_else(|err| panic!("{name}: {err}"));
    serde_json::from_str(&text).unwrap_or_else(|err| panic!("{name}: {err}"))
}

fn cause_of(value: &Value) -> CauseRef<'_> {
    match value {
        Value::String(name) => CauseRef::Name(name),
        other => CauseRef::Code(i128::from(other.as_i64().unwrap_or_else(|| panic!("cause {other}")))),
    }
}

fn expected_receipt(want: &Value) -> Receipt {
    Receipt {
        cause: want["cause"].as_u64().unwrap() as u8,
        cause_name: want["cause_name"].as_str().map(|name| prismpath_rs::causes::name(prismpath_rs::causes::code(name).unwrap()).unwrap()),
        event: want["event"].as_u64().unwrap(),
        next_node: want["next_node"].as_u64().unwrap(),
        prev_node: want["prev_node"].as_u64().unwrap(),
        seq: want["seq"].as_u64().unwrap(),
    }
}

fn unhex(text: &str) -> Vec<u8> {
    hex::decode(text).unwrap()
}

#[test]
fn the_frozen_vectors_encode_and_decode_byte_for_byte() {
    let doc = load("receipts.json");
    let vectors = doc["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 4);
    for vector in vectors {
        let name = vector["name"].as_str().unwrap();
        let fields = &vector["fields"];
        let (seq, prev, event, next) = (
            fields["seq"].as_u64().unwrap(),
            fields["prev_node"].as_u64().unwrap(),
            fields["event"].as_u64().unwrap(),
            fields["next_node"].as_u64().unwrap(),
        );
        let cause = cause_of(&fields["cause"]);
        let symbols: Vec<u64> = vector["canonical_symbols"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap()).collect();
        assert_eq!(r::encode_receipt_symbols(seq, prev, event, next, cause.clone()).unwrap().to_vec(), symbols, "{name}");
        let wire: Vec<u64> = vector["wire_ints"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap()).collect();
        assert_eq!(r::encode_receipt_wire_ints(seq, prev, event, next, cause.clone()).unwrap().to_vec(), wire, "{name}");
        assert_eq!(r::encode_receipt_bits(seq, prev, event, next, cause.clone()).unwrap(), vector["bits"].as_str().unwrap(), "{name}");
        let frame = r::encode_receipt(seq, prev, event, next, cause).unwrap();
        assert_eq!(hex::encode(&frame), vector["hex_bytes"].as_str().unwrap(), "{name}");
        let decoded = r::decode_receipt(&frame).unwrap();
        assert_eq!(decoded.refusal_cause, r::OK, "{name}");
        let receipt = decoded.receipt.expect("a receipt");
        assert_eq!(receipt.cause as u64, vector["cause_code"].as_u64().unwrap(), "{name}");
        assert_eq!(receipt.cause_name, vector["cause_name"].as_str(), "{name}");
        assert_eq!(r::encode_receipt_struct(&receipt).unwrap(), frame, "{name}: re-encode");
    }
}

#[test]
fn encode_cases_match_python() {
    let doc = load("receipt_stream.json");
    let mut checked = 0;
    for case in doc["encode"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let fields = &case["fields"];
        let signed = |key: &str| fields[key].as_i64().unwrap_or_else(|| panic!("{name}: {key}"));
        // a negative field is refused by the type: there is no u64 to build
        let numbers: Vec<Result<u64, _>> = ["seq", "prev_node", "event", "next_node"]
            .iter()
            .map(|key| {
                let value = &fields[*key];
                value.as_u64().ok_or_else(|| signed(key))
            })
            .collect();
        if case.get("refuse").is_some() {
            if numbers.iter().any(|number| number.is_err()) {
                checked += 1;
                continue; // refused as Python refuses: a negative has no u64
            }
            let call = r::encode_receipt_bits(
                *numbers[0].as_ref().unwrap(),
                *numbers[1].as_ref().unwrap(),
                *numbers[2].as_ref().unwrap(),
                *numbers[3].as_ref().unwrap(),
                cause_of(&fields["cause"]),
            );
            assert!(matches!(call, Err(ReceiptError::UnknownCauseName(_)) | Err(ReceiptError::CauseOutOfRange(_))), "{name}: {call:?}");
            checked += 1;
            continue;
        }
        let (seq, prev, event, next) = (
            *numbers[0].as_ref().unwrap(),
            *numbers[1].as_ref().unwrap(),
            *numbers[2].as_ref().unwrap(),
            *numbers[3].as_ref().unwrap(),
        );
        let cause = cause_of(&fields["cause"]);
        if case["rust_overflow"].as_bool().unwrap() {
            let call = r::encode_receipt(seq, prev, event, next, cause);
            assert!(matches!(call, Err(ReceiptError::Overflow(_))), "{name}: {call:?}");
            checked += 1;
            continue;
        }
        let symbols: Vec<u64> = case["symbols"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap()).collect();
        assert_eq!(r::encode_receipt_symbols(seq, prev, event, next, cause.clone()).unwrap().to_vec(), symbols, "{name}");
        let wire: Vec<u64> = case["wire_ints"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap()).collect();
        assert_eq!(r::encode_receipt_wire_ints(seq, prev, event, next, cause.clone()).unwrap().to_vec(), wire, "{name}");
        assert_eq!(r::encode_receipt_bits(seq, prev, event, next, cause.clone()).unwrap(), case["bits"].as_str().unwrap(), "{name}");
        assert_eq!(hex::encode(r::encode_receipt(seq, prev, event, next, cause).unwrap()), case["hex"].as_str().unwrap(), "{name}");
        checked += 1;
    }
    assert_eq!(checked, doc["encode"].as_array().unwrap().len());
    println!("receipt stream encode: {checked} cases match Python");
}

#[test]
fn decode_cases_match_python() {
    let doc = load("receipt_stream.json");
    let mut checked = 0;
    for case in doc["decode"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let decoded = match (case.get("hex"), case.get("bits")) {
            (Some(frame), _) => r::decode_receipt(&unhex(frame.as_str().unwrap())),
            (None, Some(bits)) => r::decode_receipt_bits(bits.as_str().unwrap()),
            _ => panic!("{name}: no input"),
        }
        .unwrap_or_else(|err| panic!("{name}: {err}"));
        assert_eq!(decoded.refusal_cause, case["refusal_cause"].as_str().unwrap(), "{name}");
        assert_eq!(decoded.cause, case["registry_cause"].as_u64().map(|code| code as u8), "{name}: registry cause");
        match case["receipt"].is_null() {
            true => assert!(decoded.receipt.is_none(), "{name}"),
            false => assert_eq!(decoded.receipt.expect(name), expected_receipt(&case["receipt"]), "{name}"),
        }
        checked += 1;
    }
    assert_eq!(checked, doc["decode"].as_array().unwrap().len());
    println!("receipt stream decode: {checked} cases match Python");
}

#[test]
fn the_strict_decode_causes_sit_beside_the_status_string() {
    let doc = load("receipt_stream.json");
    let mut seen = std::collections::BTreeMap::new();
    for case in doc["decode"].as_array().unwrap() {
        if let Some(code) = case["registry_cause"].as_u64() {
            // the status string stays the decoder's own; the cause only ever rides on a truncation
            assert_eq!(case["refusal_cause"], r::RECEIPT_TRUNCATED, "{}", case["name"]);
            *seen.entry(code).or_insert(0) += 1;
        } else if case["refusal_cause"] == r::OK {
            assert!(case["receipt"].is_object(), "{}", case["name"]);
        }
    }
    assert_eq!(seen.keys().copied().collect::<Vec<_>>(), [48, 49], "{seen:?}");
    // an empty frame, a whole receipt and an extra codeword carry none
    assert_eq!(r::decode_receipt(&[]).unwrap().cause, None);
    assert_eq!(r::decode_receipt_bits("").unwrap().cause, None);
}

#[test]
fn a_decoded_receipt_re_encodes_to_the_same_bytes() {
    let doc = load("receipt_stream.json");
    let mut round_trips = 0;
    for case in doc["decode"].as_array().unwrap() {
        if case["refusal_cause"] != r::OK || case.get("hex").is_none() {
            continue;
        }
        let frame = unhex(case["hex"].as_str().unwrap());
        let receipt = r::decode_receipt(&frame).unwrap().receipt.unwrap();
        let again = r::encode_receipt_struct(&receipt).unwrap();
        // the frame may carry zero pad or a partial tail past the receipt: the receipt's own bits open the frame
        let own_bits = prismpath_telemetry_rs::packed::unpack(&again);
        let own_bits = own_bits.trim_end_matches('0');
        assert!(prismpath_telemetry_rs::packed::unpack(&frame).starts_with(own_bits), "{}", case["name"]);
        assert_eq!(r::decode_receipt(&again).unwrap().receipt.unwrap(), receipt);
        round_trips += 1;
    }
    assert!(round_trips > 150, "{round_trips}");
}

#[test]
fn integers_beyond_64_bits_are_refused_not_wrapped() {
    let doc = load("receipt_stream.json");
    for case in doc["wide"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let decoded = r::decode_receipt_bits(case["bits"].as_str().unwrap());
        if case["rust_overflow"].as_bool().unwrap() {
            assert!(matches!(decoded, Err(ReceiptError::Overflow(_))), "{name}: {decoded:?}");
        } else {
            let decoded = decoded.unwrap_or_else(|err| panic!("{name}: {err}"));
            assert_eq!(decoded.refusal_cause, case["refusal_cause"].as_str().unwrap(), "{name}");
            assert_eq!(decoded.cause, case["registry_cause"].as_u64().map(|code| code as u8), "{name}: registry cause");
            match case["python_receipt"].as_object() {
                None => assert!(decoded.receipt.is_none(), "{name}"),
                Some(python) => {
                    let receipt = decoded.receipt.unwrap();
                    assert_eq!(receipt.seq.to_string(), python["seq"].as_str().unwrap(), "{name}");
                }
            }
        }
    }
}

#[test]
fn every_registered_cause_survives_the_wire_with_its_name() {
    for row in prismpath_rs::causes::REGISTRY {
        let frame = r::encode_receipt(9, 1, 2, 3, CauseRef::from(row.code)).unwrap();
        let receipt = r::decode_receipt(&frame).unwrap().receipt.unwrap();
        assert_eq!((receipt.cause, receipt.cause_name), (row.code, Some(row.name)));
        assert_eq!(r::encode_receipt(9, 1, 2, 3, CauseRef::from(row.name)).unwrap(), frame);
    }
    // a clean decision rides as wire integer 1, the densest code
    assert_eq!(r::encode_receipt_wire_ints(1, 0, 2, 1, CauseRef::from(0u8)).unwrap()[0], 1);
}
