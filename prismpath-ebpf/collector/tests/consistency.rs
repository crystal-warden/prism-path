// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! Consistency proofs in the feed (`prismpath.collector/2`): every seal after the first a client was sent
//! carries an RFC 6962 consistency proof from the count of the last seal that client was sent, so a client
//! that misses records (a `gap`) still proves the next tree extends the one it checked; a client that
//! reconnects names the session and the count it last verified and its join seal is proved from there; and
//! what the collector can no longer prove it says, by name, instead of sending a proof.

mod common;

use common::{kinds, Client, Harness};
use prismpath_collector::collector::Settings;
use prismpath_collector::decode::{GnEvent, Kind};
use prismpath_collector::feed::FeedConfig;
use prismpath_collector::record::{self, MAX_RECORD};
use prismpath_collector::seal::{self, Sealer};
use prismpath_rs::merkle::{verify_consistency, Accumulator};
use serde_json::Value;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

const SESSION: &str = "00112233445566778899aabbccddeeff";

fn event(request_id: u64) -> Vec<u8> {
    GnEvent {
        request_id, t_ns: request_id * 10, image_index: 1, edge: 0, cause: 0, outcome: 1, reason: 0, version: 1, cmd: 1, hclass: 1,
        name_len: 0, data_len: 0, src_port: 40000, handle: 1, arg0: 0, arg1: 0, src_ip: 0x7F00_0001, pad: 0,
    }
    .to_bytes()
}

fn unhex(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap()).unwrap()
}

/// A seal's consistency member proves its tree extends `prior` (count, root); false when it does not.
fn proves(seal: &Value, prior: (u64, &str)) -> bool {
    let consistency = &seal["consistency"];
    if consistency["from"].as_u64() != Some(prior.0) {
        return false;
    }
    let Some(proof) = consistency["proof"].as_array() else { return false };
    let proof: Vec<Vec<u8>> = proof.iter().map(unhex).collect();
    if prior.0 == 0 {
        return proof.is_empty();
    }
    verify_consistency(prior.0, seal["count"].as_u64().unwrap(), &hex::decode(prior.1).unwrap(), &unhex(&seal["root"]), &proof)
}

/// Every record to the status after the final seal.
fn until_final(client: &mut Client) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    while let Some(value) = client.next() {
        let last = value["kind"] == "status" && out.iter().any(|seen| seen["trigger"] == "final");
        out.push(value);
        if last {
            break;
        }
    }
    out
}

fn wait_drained(harness: &Harness) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !harness.ring.drained() {
        assert!(Instant::now() < deadline, "the ring is drained");
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn the_hello_names_protocol_2_and_the_window() {
    assert_eq!(record::PROTOCOL, "prismpath.collector/2");
    let mut harness = Harness::start(Kind::Gnet, Harness::allowing_self(), common::quick());
    let mut client = Client::connect(&harness.socket);
    client.send(&[record::subscription_bytes(), b"\n".to_vec()].concat());
    let hello = client.next().unwrap();
    assert_eq!(hello["protocol"], "prismpath.collector/2");
    assert_eq!(hello["proof_window"], Settings::default().proof_window as u64);
    let join = client.next().unwrap();
    assert!(join.get("consistency").is_none(), "a first seal has nothing to be proved from");
    harness.finish();
}

#[test]
fn every_later_seal_proves_it_extends_the_last_one_the_client_was_sent() {
    let mut harness = Harness::start(Kind::Gnet, Harness::allowing_self(), common::quick());
    let mut client = harness.client();
    let mut request_id = 0;
    for batch in [1u64, 2, 5, 13, 1, 40, 7] {
        for _ in 0..batch {
            harness.ring.push(&event(request_id));
            request_id += 1;
        }
        wait_drained(&harness);
        std::thread::sleep(Duration::from_millis(80));
    }
    harness.finish();
    let seals = kinds(&until_final(&mut client), "seal");
    assert!(seals.len() >= 5, "{} seals", seals.len());
    // the join seal was at 0, so the first later seal proves from 0, trivially
    let mut prior: (u64, String) = (0, String::new());
    for seal in &seals {
        assert!(proves(seal, (prior.0, &prior.1)), "the seal at {} proves from {}: {seal}", seal["count"], prior.0);
        prior = (seal["count"].as_u64().unwrap(), seal["root"].as_str().unwrap().to_string());
    }
    assert_eq!(prior.0, request_id);
}

#[test]
fn a_client_that_missed_seals_proves_from_the_last_one_it_was_sent() {
    let cfg = FeedConfig { queue: 8, write_timeout: Duration::from_secs(600), ..Harness::allowing_self() };
    let settings = Settings { seal_interval: Duration::from_secs(600), seal_count: 64, ..Settings::default() };
    let mut harness = Harness::start(Kind::Gnet, cfg, settings);
    let mut stalled = harness.client();
    for request_id in 0..20_000 {
        harness.ring.push(&event(request_id));
    }
    wait_drained(&harness);
    assert!(harness.hub.stats.dropped.load(Ordering::Relaxed) > 0, "the stalled client's queue overflowed");
    // it reads at last: everything queued for it, then the gap, then what comes once it has room
    stalled.stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut prior: (u64, String) = (0, String::new());
    let (mut proved_after_gap, mut gap) = (0, false);
    let reader = std::thread::spawn(move || until_final(&mut stalled));
    std::thread::sleep(Duration::from_millis(300));
    for request_id in 20_000..20_060 {
        harness.ring.push(&event(request_id));
    }
    harness.finish();
    for value in reader.join().unwrap() {
        match value["kind"].as_str().unwrap() {
            "gap" => gap = true,
            "seal" => {
                assert!(proves(&value, (prior.0, &prior.1)), "the seal at {} proves from {}", value["count"], prior.0);
                if gap {
                    proved_after_gap += 1;
                    assert!(value["consistency"]["from"].as_u64().unwrap() > 0);
                }
                prior = (value["count"].as_u64().unwrap(), value["root"].as_str().unwrap().to_string());
            }
            _ => {}
        }
    }
    assert!(gap, "the stalled client was sent a gap");
    assert!(proved_after_gap >= 1, "a seal after the gap proved the tree from before it");
    assert_eq!(prior.0, 20_060);
}

#[test]
fn a_resumed_subscription_is_proved_from_the_count_it_names() {
    let mut harness = Harness::start(Kind::Gnet, Harness::allowing_self(), common::quick());
    let mut first = harness.client();
    for request_id in 0..21 {
        harness.ring.push(&event(request_id));
    }
    wait_drained(&harness);
    let seal = loop {
        let value = first.next().unwrap();
        if value["kind"] == "seal" && value["count"] == 21 {
            break value;
        }
    };
    drop(first);
    for request_id in 21..50 {
        harness.ring.push(&event(request_id));
    }
    wait_drained(&harness);
    let resume = |count: u64, session: &str| {
        let mut client = Client::connect(&harness.socket);
        client.send(&[record::resume_bytes(session, count), b"\n".to_vec()].concat());
        assert_eq!(client.next().unwrap()["kind"], "hello");
        let join = client.next().unwrap();
        assert_eq!(join["trigger"], "join");
        join
    };
    let join = resume(21, SESSION);
    assert_eq!(join["count"], 50);
    assert!(proves(&join, (21, seal["root"].as_str().unwrap())), "the join seal proves from 21: {join}");
    // a count the session never reached, and another session's count
    assert_eq!(resume(51, SESSION)["consistency"], serde_json::json!({"from": 51, "missing": "ahead"}));
    assert!(resume(21, "ffeeddccbbaa99887766554433221100").get("consistency").is_none(), "another session is a new tree");
    harness.finish();
}

#[test]
fn what_the_window_no_longer_holds_is_named_not_proved() {
    let settings = Settings { proof_window: 16, seal_count: 16, ..common::quick() };
    let mut harness = Harness::start(Kind::Gnet, Harness::allowing_self(), settings);
    for request_id in 0..40 {
        harness.ring.push(&event(request_id));
    }
    wait_drained(&harness);
    let mut client = Client::connect(&harness.socket);
    client.send(&[record::resume_bytes(SESSION, 3), b"\n".to_vec()].concat());
    client.next().unwrap();
    let join = client.next().unwrap();
    assert_eq!(join["consistency"], serde_json::json!({"from": 3, "missing": "window"}));
    harness.finish();
}

#[test]
fn only_a_subscription_or_a_resume_in_canonical_form_is_accepted() {
    assert_eq!(record::subscription_bytes(), b"{\"op\":\"subscribe\",\"protocol\":\"prismpath.collector/2\"}");
    let resume = record::resume_bytes(SESSION, 7);
    assert_eq!(resume, format!("{{\"count\":7,\"op\":\"subscribe\",\"protocol\":\"prismpath.collector/2\",\"session\":\"{SESSION}\"}}").into_bytes());
    let line = |bytes: &[u8]| [bytes, b"\n"].concat();
    assert_eq!(record::check_subscription(&line(&record::subscription_bytes())), Some(Ok(record::Subscription { resume: None })));
    assert_eq!(record::check_subscription(&line(&resume)), Some(Ok(record::Subscription { resume: Some((SESSION.to_string(), 7)) })));
    let refused = |text: &str| record::check_subscription(&line(text.as_bytes())).unwrap().unwrap_err().as_str();
    let p = "prismpath.collector/2";
    assert_eq!(refused(&format!("{{\"count\":-1,\"op\":\"subscribe\",\"protocol\":\"{p}\",\"session\":\"{SESSION}\"}}")), "not-a-subscription");
    assert_eq!(refused(&format!("{{\"count\":7,\"op\":\"subscribe\",\"protocol\":\"{p}\",\"session\":\"ABCD\"}}")), "not-a-subscription");
    assert_eq!(refused(&format!("{{\"count\":7,\"op\":\"subscribe\",\"protocol\":\"{p}\",\"session\":\"{}\"}}", SESSION.to_uppercase())), "not-a-subscription");
    assert_eq!(refused(&format!("{{\"count\":\"7\",\"op\":\"subscribe\",\"protocol\":\"{p}\",\"session\":\"{SESSION}\"}}")), "not-a-subscription");
    assert_eq!(refused(&format!("{{\"count\":7,\"op\":\"subscribe\",\"protocol\":\"{p}\"}}")), "not-a-subscription");
    assert_eq!(refused(&format!("{{\"op\":\"subscribe\",\"protocol\":\"{p}\",\"session\":\"{SESSION}\"}}")), "not-a-subscription");
    assert_eq!(refused(&format!("{{\"count\":7,\"extra\":1,\"op\":\"subscribe\",\"protocol\":\"{p}\",\"session\":\"{SESSION}\"}}")), "not-a-subscription");
    assert_eq!(refused(&format!("{{\"op\":\"subscribe\",\"count\":7,\"protocol\":\"{p}\",\"session\":\"{SESSION}\"}}")), "not-canon2");
    assert_eq!(refused("{\"op\":\"subscribe\",\"protocol\":\"prismpath.collector/1\"}"), "not-a-subscription");
}

#[test]
fn the_longest_seal_with_its_longest_proof_fits_a_record() {
    // A session near the most leaves it seals, one peak per set bit, then enough leaves that the longest
    // proof from any size the window holds is among those measured.
    let start = seal::MAX_LEAVES - 600;
    let peaks = vec![[0xABu8; 32]; start.count_ones() as usize];
    let mut sealer = Sealer::from_accumulator_with_window(Accumulator::from_peaks(start, &peaks).unwrap(), 1024);
    for index in 0..600u32 {
        assert!(sealer.add(&[index as u8; 32]));
    }
    assert_eq!(sealer.count(), seal::MAX_LEAVES);
    let mut longest = 0;
    for old in start..=seal::MAX_LEAVES {
        let value = sealer.seal_for(Some(&sealer.accumulator_at(old).unwrap()), "selector", &"f".repeat(32), "interval");
        let proof = value["consistency"]["proof"].as_array().unwrap().len();
        assert!(proof <= 54, "a proof of {proof} hashes");
        longest = longest.max(proof);
        let line = record::frame(&value).expect("every seal fits a record");
        assert!(line.len() <= MAX_RECORD);
    }
    assert!(longest >= 50, "the longest proof measured has {longest} hashes");
}
