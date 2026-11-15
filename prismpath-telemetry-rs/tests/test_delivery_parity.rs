use prismpath_telemetry_rs::{ackchannel as ack, selfheal as sh};

#[test]
fn test_delivery_layer_parity_merkle_and_hmac_match_python() {
    let blocks: Vec<String> = vec![
        "11011".to_string(),
        "0011".to_string(),
        "1011".to_string(),
        "00011".to_string(),
    ];

    // the values `prismpath.telemetry.selfheal.commit` and `ackchannel.sign_ack` give (RFC 6962 tree)
    let (root, proofs) = sh::commit(&blocks);

    let expected_root = "21083d5f1fc5c412065839349c35e890222cbd8267c81b9e554cd7abb2a105a8";
    assert_eq!(root, expected_root, "Merkle root does not match Python");

    let expected_proofs = vec![
        vec![
            ("R".to_string(), "fb9636c7c7b883a67638b081dff7117e82294d0cd3e58d9d05b18d71c4a26c2c".to_string()),
            ("R".to_string(), "804d4c78e6d8a21b9fab64588f1dac86b1aaa411a438848d82611a8c19b15899".to_string()),
        ],
        vec![
            ("L".to_string(), "b6363bd475cbb8c6b9028a9eab0806260cbe8d658e876b1ffafd1918b5947d30".to_string()),
            ("R".to_string(), "804d4c78e6d8a21b9fab64588f1dac86b1aaa411a438848d82611a8c19b15899".to_string()),
        ],
        vec![
            ("R".to_string(), "6c3f9d6a18f5a820d6809491b95f980e1d4512be767880374d7c8d8b302249cd".to_string()),
            ("L".to_string(), "9efbbe2f3ca637b23e9cfdea9f777388c7ed2b7b97119f6dba6f84dfc6052b7b".to_string()),
        ],
        vec![
            ("L".to_string(), "9258df0599b3f66bc16473644d266caad661fff579893598ff95ba5f72780053".to_string()),
            ("L".to_string(), "9efbbe2f3ca637b23e9cfdea9f777388c7ed2b7b97119f6dba6f84dfc6052b7b".to_string()),
        ],
    ];

    assert_eq!(proofs, expected_proofs, "Merkle inclusion proofs do not match Python");

    let secret = b"test-secret-key-123";
    let seq = 42;
    let tag = ack::sign_ack(secret, &root, seq).unwrap();
    let expected_tag = "9884933ac7a47604ec065a2f5daa2e685049df00b46043a76e5bc9dab8da6c19";

    assert_eq!(tag, expected_tag, "HMAC ACK tag does not match Python");
    assert!(ack::verify_ack(secret, &root, seq, &tag).unwrap());
}
