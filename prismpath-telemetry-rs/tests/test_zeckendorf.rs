use prismpath_telemetry_rs::zeckendorf as z;

#[test]
fn test_small_codes_match_the_doc() {
    let cases = vec![
        (1, "11"),
        (2, "011"),
        (3, "0011"),
        (4, "1011"),
        (5, "00011"),
        (6, "10011"),
        (7, "01011"),
        (8, "000011"),
    ];
    for (n, code) in cases {
        assert_eq!(z::encode(n).unwrap(), code);
        assert_eq!(z::decode(code).unwrap(), n);
    }
}

#[test]
fn test_round_trip_spot() {
    for n in [1, 2, 3, 12, 99, 100, 1597, 6765, 10_000, 1_000_000] {
        assert_eq!(z::decode(&z::encode(n).unwrap()).unwrap(), n);
    }
}

#[test]
fn test_round_trip_dense_range() {
    for n in 1..=5000 {
        let code = z::encode(n).unwrap();
        assert_eq!(z::decode(&code).unwrap(), n, "round-trip failed at {n}");
    }
}

#[test]
fn test_only_terminator_is_11() {
    for n in [1, 2, 3, 4, 17, 250, 4181, 99_999] {
        let code = z::encode(n).unwrap();
        assert!(code.ends_with("11"), "{code}");
        assert_eq!(code.find("11").unwrap(), code.len() - 2, "internal '11' in {code:?}");
        assert!(!code[..code.len() - 1].contains("11"), "consecutive 1s in Zeckendorf part of {code:?}");
    }
}

#[test]
fn test_stream_round_trip() {
    let cases: Vec<Vec<usize>> = vec![
        vec![1],
        vec![1, 1, 1],
        vec![4, 2, 7],
        vec![1, 4, 1, 100, 3],
        vec![10_000, 1, 2, 3, 6765],
        (1..200).collect(),
    ];
    for values in cases {
        assert_eq!(z::decode_stream(&z::encode_stream(&values)), values);
    }
}

#[test]
fn test_small_ints_are_tiny() {
    for n in 1..9 {
        assert!(z::encode(n).unwrap().len() <= 6);
    }
}

#[test]
fn test_rejects_non_positive() {
    assert!(z::encode(0).is_err());
}

#[test]
fn test_rejects_non_code() {
    assert!(z::decode("10").is_err());
    assert!(z::decode("1").is_err());
}
