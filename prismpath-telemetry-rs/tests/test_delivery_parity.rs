use prismpath_telemetry_rs::{ackchannel as ack, selfheal as sh};

#[test]
fn test_delivery_layer_parity_merkle_and_hmac_match_python() {
    let blocks: Vec<String> = vec![
        "11011".to_string(),
        "0011".to_string(),
        "1011".to_string(),
        "00011".to_string(),
    ];

    let (root, proofs) = sh::commit(&blocks);

    let expected_root = "df5dab1010711367c84688bb58d0db7c51c1e09486c8ec5c5eab6b92957a7e44";
    assert_eq!(root, expected_root, "Merkle root does not match Python");

    let expected_proofs = vec![
        vec![
            ("R".to_string(), "a8d0b6f0939cfd883251f62b265f971ef8a5ab97eee32b91460f08b965601d93".to_string()),
            ("R".to_string(), "e70efdaa84ed5bea841a7b01ed10de75238f5b96d3fcdbb9f708d02ae3aa987f".to_string()),
        ],
        vec![
            ("L".to_string(), "17214e2d30ebb0eafe4b8866d63e3431e7258a23bbbc214cd92ddc72e114ba42".to_string()),
            ("R".to_string(), "e70efdaa84ed5bea841a7b01ed10de75238f5b96d3fcdbb9f708d02ae3aa987f".to_string()),
        ],
        vec![
            ("R".to_string(), "e961ba8ecc78e96392273dd9021ae3908f7148716455a4d5fa83739bb1476154".to_string()),
            ("L".to_string(), "7c6aea358ed2bda34076cac9506e5016696713bc2ebf38821cc7185be954923c".to_string()),
        ],
        vec![
            ("L".to_string(), "3dd9c0995d54c0abd51a90f1d57b1ce77bc885fc8a7cea52dcad3c2540dda5ee".to_string()),
            ("L".to_string(), "7c6aea358ed2bda34076cac9506e5016696713bc2ebf38821cc7185be954923c".to_string()),
        ],
    ];

    assert_eq!(proofs, expected_proofs, "Merkle inclusion proofs do not match Python");

    let secret = b"test-secret-key-123";
    let seq = 42;
    let tag = ack::sign_ack(secret, &root, seq);
    let expected_tag = "e8a93cf916c27f094c1e87459f92c84489cc93df3177e50daf8d1941189ed92d";

    assert_eq!(tag, expected_tag, "HMAC ACK tag does not match Python");
    assert!(ack::verify_ack(secret, &root, seq, &tag));
}
