use prismpath_telemetry_rs::{epochs, zeckendorf};
use std::collections::HashSet;

fn bits(seed: usize) -> String {
    let vals: Vec<usize> = (1 + seed..60 + seed).collect();
    zeckendorf::encode_stream(&vals).unwrap()
}

#[test]
fn test_seal_and_chain() {
    let mut store = epochs::EpochStore::new(64, 5);
    for epoch in 0..3 {
        store.seal(&bits(epoch));
    }
    assert_eq!(store.chain().len(), 3);
    let unique: HashSet<String> = store.chain().into_iter().collect();
    assert_eq!(unique.len(), 3);
    assert!(store.verify_chain());
    assert_eq!(
        store.epochs[1].chained_root,
        epochs::chain_root(&store.epochs[0].chained_root, &store.epochs[1].merkle_root)
    );
}

#[test]
fn test_tamper_breaks_the_chain() {
    let mut store = epochs::EpochStore::new(64, 5);
    store.seal(&bits(0));
    store.seal(&bits(1));
    assert!(store.verify_chain());
    store.epochs[0].merkle_root = "deadbeef".repeat(8);
    assert!(!store.verify_chain());
}

#[test]
fn test_drop_on_ack_keeps_roots() {
    let mut store = epochs::EpochStore::new(64, 5);
    for epoch in 0..3 {
        store.seal(&bits(epoch));
    }
    let target = store.epochs[1].chained_root.clone();
    let dropped = store.ack(&target);
    assert_eq!(dropped, 2);
    assert_eq!(store.retransmittable(), vec![2]);
    assert_eq!(store.gaps(), Vec::<usize>::new());
    assert!(store.verify_chain());
    assert_eq!(store.chain().len(), 3);
}

#[test]
fn test_retention_pressure_drop_is_provable() {
    let mut store = epochs::EpochStore::new(64, 2);
    for epoch in 0..4 {
        store.seal(&bits(epoch));
    }
    assert_eq!(store.retransmittable(), vec![2, 3]);
    assert_eq!(store.gaps(), vec![0, 1]);
    assert!(store.verify_chain());
}

#[test]
fn test_acked_drop_is_not_counted_as_a_gap() {
    let mut store = epochs::EpochStore::new(64, 2);
    store.seal(&bits(0));
    let root0 = store.epochs[0].chained_root.clone();
    store.ack(&root0);
    for epoch in 1..4 {
        store.seal(&bits(epoch));
    }
    assert!(!store.gaps().contains(&0));
    assert!(store.gaps().contains(&1));
}
