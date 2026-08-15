use prismpath_telemetry_rs::{ackchannel as ack, epochs as e, zeckendorf as z};

const SECRET: &[u8] = b"edge<->ground shared secret";

fn make_store(n: usize) -> e::EpochStore {
    let mut s = e::EpochStore::new(64, 9);
    for k in 0..n {
        let vals: Vec<usize> = (1 + k..60 + k).collect();
        s.seal(&z::encode_stream(&vals).unwrap());
    }
    s
}

#[test]
fn test_sign_verify_round_trip() {
    let tag = ack::sign_ack(SECRET, "abc123", 4);
    assert!(ack::verify_ack(SECRET, "abc123", 4, &tag));
    assert!(!ack::verify_ack(SECRET, "abc123", 5, &tag));
    assert!(!ack::verify_ack(SECRET, "abcXXX", 4, &tag));
}

#[test]
fn test_valid_ack_applies_drop() {
    let s = make_store(3);
    let mut r = ack::AckReceiver::new(s, SECRET);
    let root = r.store.epochs[1].chained_root.clone();
    let tag = ack::sign_ack(SECRET, &root, 1);
    let res = r.on_ack(&root, 1, &tag);
    assert!(res.accepted);
    assert_eq!(res.dropped, 2);
    assert_eq!(r.store.retransmittable(), vec![2]);
}

#[test]
fn test_forged_ack_drops_nothing() {
    let s = make_store(3);
    let mut r = ack::AckReceiver::new(s, SECRET);
    let root = r.store.epochs[1].chained_root.clone();
    let before = r.store.retransmittable();
    let bogus_tag = "deadbeef".repeat(8);
    let res = r.on_ack(&root, 1, &bogus_tag);
    assert!(!res.accepted);
    assert_eq!(res.reason, "bad-tag");
    assert_eq!(r.store.retransmittable(), before);
    assert!(r.store.gaps().is_empty());
}

#[test]
fn test_tampered_root_rejected() {
    let s = make_store(3);
    let mut r = ack::AckReceiver::new(s, SECRET);
    let real_root = r.store.epochs[0].chained_root.clone();
    let tag = ack::sign_ack(SECRET, &real_root, 1);
    let epoch2_root = r.store.epochs[2].chained_root.clone();
    let res = r.on_ack(&epoch2_root, 1, &tag);
    assert!(!res.accepted);
    assert_eq!(r.store.retransmittable(), vec![0, 1, 2]);
}

#[test]
fn test_wrong_secret_rejected() {
    let s = make_store(2);
    let mut r = ack::AckReceiver::new(s, SECRET);
    let root = r.store.epochs[0].chained_root.clone();
    let forged = ack::sign_ack(b"attacker-secret", &root, 1);
    let res = r.on_ack(&root, 1, &forged);
    assert!(!res.accepted);
    assert_eq!(r.store.retransmittable(), vec![0, 1]);
}

#[test]
fn test_replay_is_rejected() {
    let s = make_store(4);
    let mut r = ack::AckReceiver::new(s, SECRET);
    let root2 = r.store.epochs[2].chained_root.clone();
    let tag2 = ack::sign_ack(SECRET, &root2, 5);
    assert!(r.on_ack(&root2, 5, &tag2).accepted);

    let root0 = r.store.epochs[0].chained_root.clone();
    let tag0 = ack::sign_ack(SECRET, &root0, 5);
    let res = r.on_ack(&root0, 5, &tag0);
    assert!(!res.accepted);
    assert_eq!(res.reason, "stale-seq");
}
