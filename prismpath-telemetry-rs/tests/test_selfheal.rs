use prismpath_telemetry_rs::{selfheal as sh, zeckendorf as z};
use std::collections::HashSet;

fn get_stream() -> (Vec<usize>, String) {
    let values: Vec<usize> = (1..501).collect();
    let stream = z::encode_stream(&values).unwrap();
    (values, stream)
}

const BLOCK: usize = 256;

fn deliver(sender: &sh::Sender, receiver: &mut sh::Receiver, lost: &HashSet<usize>) {
    for i in 0..sender.n_blocks() {
        if lost.contains(&i) {
            continue;
        }
        let (block, proof) = sender.serve(i);
        assert!(receiver.accept(i, &block, &proof));
    }
}

#[test]
fn test_commit_and_verify_all_blocks() {
    let (_, stream) = get_stream();
    let s = sh::Sender::new(&stream, BLOCK).unwrap();
    assert!(s.n_blocks() >= 5);
    for i in 0..s.n_blocks() {
        let (block, proof) = s.serve(i);
        assert!(sh::verify_block(&block, &proof, &s.root));
    }
}

#[test]
fn test_gap_detection() {
    let (_, stream) = get_stream();
    let s = sh::Sender::new(&stream, BLOCK).unwrap();
    let mut r = sh::Receiver::new(s.root.clone(), s.n_blocks());
    let mut lost = HashSet::new();
    lost.insert(2);
    lost.insert(5);
    lost.insert(6);
    lost.insert(s.n_blocks() - 1);

    deliver(&s, &mut r, &lost);
    let missing_set: HashSet<usize> = r.missing().into_iter().collect();
    assert_eq!(missing_set, lost);
    assert!(!r.complete());
}

#[test]
fn test_forged_and_corrupted_blocks_are_rejected() {
    let (_, stream) = get_stream();
    let s = sh::Sender::new(&stream, BLOCK).unwrap();
    let mut r = sh::Receiver::new(s.root.clone(), s.n_blocks());
    let (good_block, good_proof) = s.serve(3);

    let first_char = if good_block.starts_with('1') { '0' } else { '1' };
    let corrupt = format!("{}{}", first_char, &good_block[1..]);
    assert!(!r.accept(3, &corrupt, &good_proof));

    let (_other_block, other_proof) = s.serve(4);
    assert!(!r.accept(3, &good_block, &other_proof));

    assert!(r.missing().contains(&3));
    assert!(r.accept(3, &good_block, &good_proof));
    assert!(!r.missing().contains(&3));
}

#[test]
fn test_selective_repair_restores_the_stream() {
    let (values, stream) = get_stream();
    let s = sh::Sender::new(&stream, BLOCK).unwrap();
    let mut r = sh::Receiver::new(s.root.clone(), s.n_blocks());
    let mut lost = HashSet::new();
    lost.insert(1);
    lost.insert(4);
    lost.insert(7);
    lost.insert(8);

    deliver(&s, &mut r, &lost);
    let retransmitted = sh::repair(&s, &mut r);
    let retransmitted_set: HashSet<usize> = retransmitted.into_iter().collect();
    assert_eq!(retransmitted_set, lost);
    assert!(r.complete());
    assert_eq!(r.assemble().unwrap(), stream);
    assert_eq!(z::decode_stream(&r.assemble().unwrap()), values);
}

#[test]
fn test_unrecoverable_block_is_a_provable_gap() {
    let (_, stream) = get_stream();
    let s = sh::Sender::new(&stream, BLOCK).unwrap();
    let mut r = sh::Receiver::new(s.root.clone(), s.n_blocks());
    let mut lost = HashSet::new();
    lost.insert(4);

    deliver(&s, &mut r, &lost);
    let err = r.assemble().unwrap_err();
    assert!(err.contains("4"));
}
