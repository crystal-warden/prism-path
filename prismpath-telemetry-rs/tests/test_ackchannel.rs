use prismpath_telemetry_rs::{ackchannel, epochs, zeckendorf};

const SECRET: &[u8] = b"edge<->ground shared secret";

fn make_store(epoch_count: usize) -> epochs::EpochStore {
    let mut store = epochs::EpochStore::new(64, 9);
    for epoch in 0..epoch_count {
        let vals: Vec<usize> = (1 + epoch..60 + epoch).collect();
        store.seal(&zeckendorf::encode_stream(&vals).unwrap());
    }
    store
}

#[test]
fn test_sign_verify_round_trip() {
    let tag = ackchannel::sign_ack(SECRET, "abc123", 4);
    assert!(ackchannel::verify_ack(SECRET, "abc123", 4, &tag));
    assert!(!ackchannel::verify_ack(SECRET, "abc123", 5, &tag));
    assert!(!ackchannel::verify_ack(SECRET, "abcXXX", 4, &tag));
}

#[test]
fn test_valid_ack_applies_drop() {
    let store = make_store(3);
    let mut receiver = ackchannel::AckReceiver::new(store, SECRET);
    let root = receiver.store.epochs[1].chained_root.clone();
    let tag = ackchannel::sign_ack(SECRET, &root, 1);
    let res = receiver.on_ack(&root, 1, &tag);
    assert!(res.accepted);
    assert_eq!(res.dropped, 2);
    assert_eq!(receiver.store.retransmittable(), vec![2]);
}

#[test]
fn test_forged_ack_drops_nothing() {
    let store = make_store(3);
    let mut receiver = ackchannel::AckReceiver::new(store, SECRET);
    let root = receiver.store.epochs[1].chained_root.clone();
    let before = receiver.store.retransmittable();
    let bogus_tag = "deadbeef".repeat(8);
    let res = receiver.on_ack(&root, 1, &bogus_tag);
    assert!(!res.accepted);
    assert_eq!(res.reason, "bad-tag");
    assert_eq!(receiver.store.retransmittable(), before);
    assert!(receiver.store.gaps().is_empty());
}

#[test]
fn test_tampered_root_rejected() {
    let store = make_store(3);
    let mut receiver = ackchannel::AckReceiver::new(store, SECRET);
    let real_root = receiver.store.epochs[0].chained_root.clone();
    let tag = ackchannel::sign_ack(SECRET, &real_root, 1);
    let epoch2_root = receiver.store.epochs[2].chained_root.clone();
    let res = receiver.on_ack(&epoch2_root, 1, &tag);
    assert!(!res.accepted);
    assert_eq!(receiver.store.retransmittable(), vec![0, 1, 2]);
}

#[test]
fn test_wrong_secret_rejected() {
    let store = make_store(2);
    let mut receiver = ackchannel::AckReceiver::new(store, SECRET);
    let root = receiver.store.epochs[0].chained_root.clone();
    let forged = ackchannel::sign_ack(b"attacker-secret", &root, 1);
    let res = receiver.on_ack(&root, 1, &forged);
    assert!(!res.accepted);
    assert_eq!(receiver.store.retransmittable(), vec![0, 1]);
}

#[test]
fn test_replay_is_rejected() {
    let store = make_store(4);
    let mut receiver = ackchannel::AckReceiver::new(store, SECRET);
    let root2 = receiver.store.epochs[2].chained_root.clone();
    let tag2 = ackchannel::sign_ack(SECRET, &root2, 5);
    assert!(receiver.on_ack(&root2, 5, &tag2).accepted);

    let root0 = receiver.store.epochs[0].chained_root.clone();
    let tag0 = ackchannel::sign_ack(SECRET, &root0, 5);
    let res = receiver.on_ack(&root0, 5, &tag0);
    assert!(!res.accepted);
    assert_eq!(res.reason, "stale-seq");
}
