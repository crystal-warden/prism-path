use prismpath_telemetry_rs::{packed as p, zeckendorf as z};

#[test]
fn test_round_trip() {
    let test_cases: Vec<Vec<usize>> = vec![
        vec![1],
        vec![2],
        vec![1, 1, 1],
        vec![4, 2, 7, 100],
        (1..300).collect(),
        vec![10_000, 1, 2, 3, 6765],
    ];

    for word_bits in [8, 64] {
        for ints in &test_cases {
            assert_eq!(p::decode(&p::encode(ints, word_bits).unwrap()), *ints);
        }
    }
}

#[test]
fn test_output_is_whole_words() {
    for word_bits in [8, 64] {
        let ints: Vec<usize> = (1..200).collect();
        let wire = p::encode(&ints, word_bits).unwrap();
        assert_eq!(wire.len() % (word_bits / 8), 0);
    }
}

#[test]
fn test_bits_survive_packing() {
    let bits = z::encode_stream(&[4, 2, 7]).unwrap();
    let unpacked = p::unpack(&p::pack(&bits, 64));
    assert!(unpacked.starts_with(&bits));
    let remainder = &unpacked[bits.len()..];
    assert!(remainder.chars().all(|c| c == '0'));
}

#[test]
fn test_padding_amortizes() {
    let ints_small: Vec<usize> = (1..=10).collect();
    let ints_big: Vec<usize> = (1..=100_000).collect();

    let small = p::padding_overhead(&ints_small, 64).unwrap();
    let big = p::padding_overhead(&ints_big, 64).unwrap();

    assert!(big.pad_pct < small.pad_pct);
    assert!(big.pad_pct < 1.0);
}

#[test]
fn test_wire_is_dense() {
    let ints: Vec<usize> = (1..1000).collect();
    let bits = z::encode_stream(&ints).unwrap().len();
    let wire = p::encode(&ints, 64).unwrap();
    let wire_bits = wire.len() * 8;
    assert!(wire_bits >= bits && wire_bits < bits + 64);
}
