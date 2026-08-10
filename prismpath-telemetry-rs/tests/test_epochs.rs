use prismpath_telemetry_rs::{epochs as e, zeckendorf as z};
use std::collections::HashSet;

fn bits(seed: usize) -> String {
    let vals: Vec<usize> = (1 + seed..60 + seed).collect();
    z::encode_stream(&vals)
}

#[test]
fn test_seal_and_chain() {
    let mut s = e::EpochStore::new(64, 5);
    for k in 0..3 {
        s.seal(&bits(k));
    }
    assert_eq!(s.chain().len(), 3);
    let unique: HashSet<String> = s.chain().into_iter().collect();
    assert_eq!(unique.len(), 3);
    assert!(s.verify_chain());
    assert_eq!(
        s.epochs[1].chained_root,
        e::chain_root(&s.epochs[0].chained_root, &s.epochs[1].merkle_root)
    );
}

#[test]
fn test_tamper_breaks_the_chain() {
    let mut s = e::EpochStore::new(64, 5);
    s.seal(&bits(0));
    s.seal(&bits(1));
    assert!(s.verify_chain());
    s.epochs[0].merkle_root = "deadbeef".repeat(8);
    assert!(!s.verify_chain());
}

#[test]
fn test_drop_on_ack_keeps_roots() {
    let mut s = e::EpochStore::new(64, 5);
    for k in 0..3 {
        s.seal(&bits(k));
    }
    let target = s.epochs[1].chained_root.clone();
    let dropped = s.ack(&target);
    assert_eq!(dropped, 2);
    assert_eq!(s.retransmittable(), vec![2]);
    assert_eq!(s.gaps(), Vec::<usize>::new());
    assert!(s.verify_chain());
    assert_eq!(s.chain().len(), 3);
}

#[test]
fn test_retention_pressure_drop_is_provable() {
    let mut s = e::EpochStore::new(64, 2);
    for k in 0..4 {
        s.seal(&bits(k));
    }
    assert_eq!(s.retransmittable(), vec![2, 3]);
    assert_eq!(s.gaps(), vec![0, 1]);
    assert!(s.verify_chain());
}

#[test]
fn test_acked_drop_is_not_counted_as_a_gap() {
    let mut s = e::EpochStore::new(64, 2);
    s.seal(&bits(0));
    let root0 = s.epochs[0].chained_root.clone();
    s.ack(&root0);
    for k in 1..4 {
        s.seal(&bits(k));
    }
    assert!(!s.gaps().contains(&0));
    assert!(s.gaps().contains(&1));
}
