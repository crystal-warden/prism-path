// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! Hostile input on both sides: malformed and oversized ring buffer records and lying headers from the
//! kernel side; on the feed side a reader that never reads, clients that send more than a subscription,
//! peers off the allow list. And the collector's own reach held to read only by its source.

mod common;

use common::{kinds, quick, Client, Harness, SharedRing};
use prismpath_collector::collector::{End, Settings};
use prismpath_collector::decode::{GnEvent, Kind};
use prismpath_collector::feed::{self, FeedConfig, Hub};
use prismpath_collector::privs::{self, Caps};
use prismpath_collector::record::{self, MAX_RECORD, MAX_SUBSCRIPTION};
use prismpath_collector::ring::{self, Entry, Recording, MAX_FRAME};
use prismpath_collector::seal;
use prismpath_rs::merkle::Accumulator;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

fn event(request_id: u64) -> Vec<u8> {
    GnEvent {
        request_id, t_ns: request_id * 10, image_index: 1, edge: 0, cause: 0, outcome: 1, reason: 0, version: 1, cmd: 1, hclass: 1,
        name_len: 0, data_len: 0, src_port: 40000, handle: 1, arg0: 0, arg1: 0, src_ip: 0x7F00_0001, pad: 0,
    }
    .to_bytes()
}

fn subscription() -> Vec<u8> {
    [record::subscription_bytes(), b"\n".to_vec()].concat()
}

/// Read everything a refused connection is sent: one `refused` record, then the end.
fn refusal(stream: &mut UnixStream) -> Value {
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut text = String::new();
    stream.read_to_string(&mut text).unwrap();
    let mut lines = text.lines();
    let value: Value = serde_json::from_str(lines.next().expect("a refused record")).unwrap();
    assert_eq!(value["kind"], "refused");
    assert!(lines.next().is_none(), "nothing after the refusal");
    value
}

// ------------------------------------------------------------------ the kernel side

#[test]
fn a_frame_of_the_wrong_length_is_a_malformed_leaf() {
    let mut harness = Harness::start(Kind::Gnet, Harness::allowing_self(), quick());
    let mut client = harness.client();
    let short = vec![7u8; 13];
    harness.ring.push(&event(1));
    harness.ring.push(&short);
    harness.ring.push(&event(2));
    let mut got = Vec::new();
    while got.len() < 3 {
        let value = client.next().unwrap();
        if value.get("index").is_some() {
            got.push(value);
        }
    }
    assert_eq!(got[0]["kind"], "decision");
    assert_eq!(got[1]["kind"], "malformed");
    assert_eq!(got[1]["reason"], "length");
    assert_eq!(got[1]["length"], 13);
    assert_eq!(got[1]["frame"], hex::encode(&short));
    assert_eq!(got[1]["leaf"], hex::encode(Sha256::digest(&short)));
    assert_eq!(got[2]["index"], 2);
    harness.finish();
    let last = kinds(&client.until("status"), "seal").pop().unwrap();
    assert_eq!((last["count"].clone(), last["malformed"].clone()), (json!(3), json!(1)));
}

#[test]
fn an_oversized_frame_is_hashed_not_carried() {
    let mut harness = Harness::start(Kind::Gnet, Harness::allowing_self(), quick());
    let mut client = harness.client();
    let big = (0..MAX_FRAME + 900).map(|index| index as u8).collect::<Vec<_>>();
    harness.ring.push(&big);
    let value = loop {
        let value = client.next().unwrap();
        if value["kind"] == "malformed" {
            break value;
        }
    };
    assert_eq!(value["reason"], "oversized");
    assert_eq!(value["length"], big.len());
    assert_eq!(value["leaf"], hex::encode(Sha256::digest(&big)));
    assert!(value.get("frame").is_none());
    harness.finish();
}

#[test]
fn busy_and_discarded_records() {
    let mut recording = Recording::new(256, 0);
    recording.push(b"first...");
    recording.push_raw(b"gone....", 8, false, true);
    recording.push_raw(b"pending.", 8, true, false);
    recording.push(b"after...");
    let walked = ring::walk(&recording.data, recording.consumer, recording.producer, 100);
    assert_eq!(walked.entries, vec![Entry::Frame(b"first...".to_vec())], "a BUSY record holds the walk");
    assert_eq!(walked.discarded, 1);
    assert!(walked.corrupt.is_none());
    assert_eq!(walked.consumer, 32);
    // the producer commits it: the walk goes on from where it stopped
    recording.data.bytes[35] &= 0x7F;
    let walked = ring::walk(&recording.data, walked.consumer, recording.producer, 100);
    assert_eq!(walked.entries, vec![Entry::Frame(b"pending.".to_vec()), Entry::Frame(b"after...".to_vec())]);
    assert_eq!(walked.consumer, recording.producer);
}

#[test]
fn records_wrap_around_the_data_area() {
    let mut recording = Recording::new(64, 40);
    assert!(recording.push(b"0123456789abcdefXYZ"));
    assert!(recording.push(b"next"));
    let walked = ring::walk(&recording.data, recording.consumer, recording.producer, 10);
    assert_eq!(walked.entries, vec![Entry::Frame(b"0123456789abcdefXYZ".to_vec()), Entry::Frame(b"next".to_vec())]);
}

#[test]
fn a_header_that_lies_stops_the_walk_for_good() {
    for length in [1u32 << 29, 64, (1 << 30) - 1] {
        let mut recording = Recording::new(256, 0);
        recording.push(b"good....");
        recording.push_raw(b"bad.....", length, false, false);
        recording.push(b"never...");
        let walked = ring::walk(&recording.data, recording.consumer, recording.producer, 100);
        assert_eq!(walked.entries, vec![Entry::Frame(b"good....".to_vec())]);
        assert_eq!(walked.consumer, 16, "the consumer stops before the lie");
        let corrupt = walked.corrupt.expect("corruption is reported");
        assert!(corrupt.reason.contains("runs past the producer"), "{}", corrupt.reason);
    }
    let mut torn = Recording::new(256, 0);
    torn.push(b"good....");
    torn.producer += 4;
    let walked = ring::walk(&torn.data, torn.consumer, torn.producer, 100);
    assert_eq!(walked.entries.len(), 1);
    assert!(walked.corrupt.unwrap().reason.contains("header runs past"));
    assert!(ring::walk(&Recording::new(64, 0).data, 100, 50, 10).corrupt.is_some(), "a producer behind the consumer");
    assert!(ring::walk(&Recording::new(64, 0).data, 0, 65, 10).corrupt.is_some(), "a producer more than a data area ahead");
}

#[test]
fn a_corrupt_ring_ends_the_run_with_an_error_and_a_final_seal() {
    let ring = SharedRing::new(256);
    let mut harness = Harness::start_on(Kind::Gnet, Harness::allowing_self(), quick(), ring);
    let mut client = harness.client();
    harness.ring.push(&event(1));
    harness.ring.push_raw(b"x", 1 << 20, false, false);
    let records = client.until("status");
    let (end, count) = harness.join();
    assert!(matches!(end, End::Corrupt(_)), "{end:?}");
    assert_eq!(count, 1);
    assert_eq!(kinds(&records, "error").len(), 1);
    assert_eq!(kinds(&records, "seal").last().unwrap()["trigger"], "final");
}

// ------------------------------------------------------------------ framing

#[test]
fn records_are_canon2_and_bounded() {
    assert!(record::frame(&json!({"x": 1.5})).is_err(), "no float");
    assert!(record::frame(&json!({"x": 1u64 << 60})).is_err(), "no integer beyond 2^53 - 1");
    assert!(matches!(record::frame(&json!({"x": "y".repeat(MAX_RECORD)})), Err(record::FrameError::TooLong(_))));
    assert_eq!(record::frame(&json!({"b": 1, "a": "z"})).unwrap(), b"{\"a\":\"z\",\"b\":1}\n");
    // the longest seal there can be: the most leaves a session seals, one peak per set bit
    let peaks = vec![[0xABu8; 32]; 53];
    let acc = Accumulator::from_peaks(seal::MAX_LEAVES, &peaks).unwrap();
    let value = seal::seal_record(&acc, "selector", &"f".repeat(32), "interval", seal::MAX_LEAVES);
    let line = record::frame(&value).expect("the largest seal fits a record");
    assert!(line.len() < MAX_RECORD);
}

#[test]
fn the_session_stops_at_the_most_leaves_it_seals() {
    let acc = Accumulator::from_peaks(seal::MAX_LEAVES, &vec![[1u8; 32]; 53]).unwrap();
    let mut sealer = seal::Sealer::from_accumulator(acc);
    assert!(!sealer.add(&[0; 32]));
    assert_eq!(sealer.count(), seal::MAX_LEAVES);
    record::frame(&sealer.seal("gnet", "s", "final")).expect("the seal at the limit frames");
}

// ------------------------------------------------------------------ the feed side

fn feed_with(cfg: FeedConfig) -> (std::sync::Arc<Hub>, std::path::PathBuf) {
    let socket = common::scratch("h.sock");
    let hub = Hub::new(cfg, "gnet", &json!({"kind": "hello"}));
    feed::listen_unix(hub.clone(), &socket, None).unwrap();
    (hub, socket)
}

#[test]
fn the_socket_is_0660() {
    use std::os::unix::fs::PermissionsExt;
    let (_hub, socket) = feed_with(Harness::allowing_self());
    assert_eq!(std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777, 0o660);
}

#[test]
fn a_file_in_the_sockets_place_is_not_replaced() {
    let path = common::scratch("not-a-socket");
    std::fs::write(&path, b"keep me").unwrap();
    let hub = Hub::new(FeedConfig::default(), "gnet", &json!({"kind": "hello"}));
    assert!(feed::listen_unix(hub, &path, None).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"keep me");
}

#[test]
fn a_peer_off_the_allow_list_is_refused() {
    let (hub, socket) = feed_with(FeedConfig { allowed_uids: vec![common::own_uid().wrapping_add(1)], ..FeedConfig::default() });
    let mut stream = UnixStream::connect(&socket).unwrap();
    stream.write_all(&subscription()).unwrap();
    assert_eq!(refusal(&mut stream)["reason"], "peer-not-allowed");
    assert_eq!(hub.stats.accepted.load(Ordering::Relaxed), 0);
}

#[test]
fn only_the_exact_subscription_is_accepted() {
    let cfg = FeedConfig { subscribe_timeout: Duration::from_millis(300), ..Harness::allowing_self() };
    let (hub, socket) = feed_with(cfg);
    let cases: Vec<(Vec<u8>, &str)> = vec![
        (vec![b'{'; MAX_SUBSCRIPTION + 10], "oversized"),
        ([vec![b' '; MAX_SUBSCRIPTION], b"\n".to_vec()].concat(), "oversized"),
        ([subscription(), b"{\"op\":\"write\"}\n".to_vec()].concat(), "extra-input"),
        (b"{\"protocol\":\"prismpath.collector/2\",\"op\":\"subscribe\"}\n".to_vec(), "not-canon2"),
        (b"{\"op\": \"subscribe\",\"protocol\":\"prismpath.collector/2\"}\n".to_vec(), "not-canon2"),
        (b"{\"op\":\"subscribe\",\"protocol\":\"prismpath.collector/1\"}\n".to_vec(), "not-a-subscription"),
        (b"{\"op\":\"subscribe\",\"protocol\":\"prismpath.collector/3\"}\n".to_vec(), "not-a-subscription"),
        (b"{\"op\":\"subscribe\",\"protocol\":\"prismpath.collector/2\",\"since\":0}\n".to_vec(), "not-a-subscription"),
        (b"\xff\xfe\n".to_vec(), "not-canon2"),
        (b"{\"op\":\"subscri".to_vec(), "timeout"),
        (Vec::new(), "timeout"),
    ];
    for (sent, reason) in cases {
        let mut stream = UnixStream::connect(&socket).unwrap();
        if !sent.is_empty() {
            let _ = stream.write_all(&sent);
        }
        assert_eq!(refusal(&mut stream)["reason"], reason, "sent {:?}", String::from_utf8_lossy(&sent));
    }
    assert_eq!(hub.stats.accepted.load(Ordering::Relaxed), 0);
}

#[test]
fn a_slow_drip_does_not_outlast_the_subscription_timeout() {
    let cfg = FeedConfig { subscribe_timeout: Duration::from_millis(400), ..Harness::allowing_self() };
    let (_hub, socket) = feed_with(cfg);
    let mut stream = UnixStream::connect(&socket).unwrap();
    let started = Instant::now();
    for byte in b"{\"op\":" {
        if stream.write_all(&[*byte]).is_err() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(refusal(&mut stream)["reason"], "timeout");
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[test]
fn a_client_that_sends_after_subscribing_is_disconnected() {
    let mut harness = Harness::start(Kind::Gnet, Harness::allowing_self(), quick());
    let mut client = harness.client();
    harness.ring.push(&event(1));
    assert_eq!(client.until("decision").last().unwrap()["kind"], "decision");
    client.send(b"{\"op\":\"stop\"}\n");
    let deadline = Instant::now() + Duration::from_secs(10);
    while harness.hub.stats.extra_input.load(Ordering::Relaxed) == 0 {
        assert!(Instant::now() < deadline, "the extra input is noticed");
        std::thread::sleep(Duration::from_millis(10));
    }
    // the connection ends: whatever was already queued may arrive, then end of stream
    while client.next().is_some() {}
    // and the run is untouched by it
    harness.ring.push(&event(2));
    let mut other = harness.client();
    harness.ring.push(&event(3));
    while other.until("decision").last().unwrap()["index"] != 2 {}
    harness.finish();
}

#[test]
fn the_client_limit_is_kept() {
    let cfg = FeedConfig { max_clients: 1, ..Harness::allowing_self() };
    let mut harness = Harness::start(Kind::Gnet, cfg, quick());
    let _first = harness.client();
    let mut second = UnixStream::connect(&harness.socket).unwrap();
    second.write_all(&subscription()).unwrap();
    assert_eq!(refusal(&mut second)["reason"], "busy");
    harness.finish();
}

/// A reader that subscribes and never reads: its socket fills, its queue fills, its records are dropped
/// and counted, and the drain never waits for it. Another client gets every record, and a seal it checks
/// against the leaves it was sent.
#[test]
fn a_reader_that_never_reads_never_blocks_the_drain() {
    const N: u64 = 20_000;
    let cfg = FeedConfig { queue: 64, write_timeout: Duration::from_secs(600), ..Harness::allowing_self() };
    let settings = Settings { seal_interval: Duration::from_secs(600), seal_count: 5_000, ..Settings::default() };
    let mut harness = Harness::start(Kind::Gnet, cfg, settings);
    let mut stalled = harness.client();
    let mut reader = harness.client();
    let progress = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let seen_by_reader = progress.clone();
    let collect = std::thread::spawn(move || {
        let mut leaves = Vec::new();
        let mut seals = Vec::new();
        while (leaves.len() as u64) < N {
            let value = reader.next().expect("the reading client is never cut off");
            match value["kind"].as_str().unwrap() {
                "decision" => {
                    assert_eq!(value["index"], leaves.len() as u64, "no gap for a client that reads");
                    leaves.push(value["leaf"].as_str().unwrap().to_string());
                    seen_by_reader.store(leaves.len() as u64, Ordering::Relaxed);
                }
                "gap" => panic!("a client that keeps up is never sent a gap"),
                "seal" => seals.push(value),
                _ => {}
            }
        }
        (leaves, seals, reader)
    });
    // The producer keeps within the reading client's queue, so that client never falls behind; the
    // stalled one falls behind at once.
    let started = Instant::now();
    for request_id in 0..N {
        harness.ring.push(&event(request_id));
        if request_id % 32 == 31 {
            while progress.load(Ordering::Relaxed) + 32 < request_id {
                std::thread::yield_now();
            }
        }
    }
    let (leaves, seals, mut reader) = collect.join().unwrap();
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_secs(60), "the drain kept pace without the stalled reader ({elapsed:?})");
    assert!(harness.hub.stats.dropped.load(Ordering::Relaxed) > 0, "the stalled reader's records were dropped and counted");
    let (_, count) = harness.finish();
    assert_eq!(count, N);
    let final_seal = kinds(&reader.until("status"), "seal").pop().unwrap();
    let mut acc = Accumulator::new();
    for leaf in &leaves {
        acc.add(&hex::decode(leaf).unwrap()).unwrap();
    }
    assert_eq!(final_seal["root"], hex::encode(acc.root().unwrap()));
    assert!(seals.iter().any(|seal| seal["trigger"] == "count"), "a seal every seal_count leaves");
    // the stalled reader, reading at last: what it was sent, with a gap wherever records went missing
    stalled.stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let (mut seen, mut dropped, mut gaps, mut next_index) = (0u64, 0u64, 0, 0u64);
    let mut gap_before = false;
    while let Some(value) = stalled.next() {
        match value["kind"].as_str().unwrap() {
            "decision" => {
                let index = value["index"].as_u64().unwrap();
                assert!(index == next_index || (gap_before && index > next_index), "a missing index has a gap before it");
                next_index = index + 1;
                gap_before = false;
                seen += 1;
            }
            "gap" => {
                gaps += 1;
                gap_before = true;
                dropped += value["dropped"].as_u64().unwrap();
            }
            _ => {}
        }
    }
    assert!(gaps >= 1);
    assert!(dropped > 0);
    assert!(seen + dropped >= N, "every decision was either delivered or counted as dropped");
}

#[test]
fn a_reader_that_never_reads_is_disconnected_after_the_write_timeout() {
    let cfg = FeedConfig { queue: 16, write_timeout: Duration::from_millis(300), ..Harness::allowing_self() };
    let mut harness = Harness::start(Kind::Gnet, cfg, quick());
    let _stalled = harness.client();
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut request_id = 0;
    while harness.hub.stats.slow.load(Ordering::Relaxed) == 0 {
        assert!(Instant::now() < deadline, "the stalled reader is cut off");
        for _ in 0..500 {
            harness.ring.push(&event(request_id));
            request_id += 1;
        }
    }
    harness.finish();
}

#[test]
fn tcp_is_loopback_only() {
    let hub = Hub::new(FeedConfig::default(), "gnet", &json!({"kind": "hello"}));
    assert!(feed::listen_tcp(hub.clone(), "0.0.0.0:0".parse().unwrap()).is_err());
    assert!(feed::listen_tcp(hub.clone(), "192.0.2.1:0".parse().unwrap()).is_err());
    let (addr, _) = feed::listen_tcp(hub.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let mut stream = std::net::TcpStream::connect(addr).unwrap();
    stream.write_all(&subscription()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while hub.stats.accepted.load(Ordering::Relaxed) == 0 {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    hub.admit(&Accumulator::new(), |_| record::frame(&json!({"kind": "seal", "trigger": "join"})).unwrap());
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut lines = std::io::BufReader::new(stream);
    let mut first = String::new();
    std::io::BufRead::read_line(&mut lines, &mut first).unwrap();
    assert_eq!(first, "{\"kind\":\"hello\"}\n");
}

#[test]
fn a_late_client_checks_seals_from_the_join_seal_alone() {
    let mut harness = Harness::start(Kind::Gnet, Harness::allowing_self(), quick());
    for request_id in 0..37 {
        harness.ring.push(&event(request_id));
    }
    while !harness.ring.drained() {
        std::thread::sleep(Duration::from_millis(5));
    }
    std::thread::sleep(Duration::from_millis(50));
    let mut late = Client::connect(&harness.socket);
    late.send(&subscription());
    assert_eq!(late.next().unwrap()["kind"], "hello");
    let join = late.next().unwrap();
    assert_eq!(join["count"], 37);
    let peaks: Vec<[u8; 32]> = join["peaks"].as_array().unwrap().iter().map(|peak| hex::decode(peak.as_str().unwrap()).unwrap().try_into().unwrap()).collect();
    let mut acc = Accumulator::from_peaks(37, &peaks).unwrap();
    assert_eq!(join["root"], hex::encode(acc.root().unwrap()));
    for request_id in 37..50 {
        harness.ring.push(&event(request_id));
    }
    harness.finish();
    // to the status after the final seal: an interval status can come before the last decisions
    let mut rest = Vec::new();
    while !rest.iter().any(|value: &Value| value["trigger"] == "final") {
        rest.extend(late.until("status"));
    }
    for value in rest {
        if value["kind"] == "decision" {
            assert_eq!(value["index"], acc.count());
            acc.add(&hex::decode(value["leaf"].as_str().unwrap()).unwrap()).unwrap();
        }
        if value["kind"] == "seal" {
            assert_eq!(value["root"], hex::encode(acc.root().unwrap()), "every later seal checks from the join seal");
        }
    }
    assert_eq!(acc.count(), 50);
}

// ------------------------------------------------------------------ privilege and reach

fn status(caps: &[(&str, u64)]) -> String {
    caps.iter().map(|(name, value)| format!("{name}:\t{value:016x}\n")).collect()
}

#[test]
fn the_collector_starts_with_cap_bpf_and_cap_perfmon_at_most_and_never_as_root() {
    let bpf = 1u64 << privs::CAP_BPF;
    let ok = privs::parse_status(&status(&[("CapInh", bpf), ("CapPrm", privs::ALLOWED), ("CapEff", privs::ALLOWED), ("CapBnd", privs::ALLOWED), ("CapAmb", privs::ALLOWED)])).unwrap();
    assert!(privs::check_start(1000, &ok).is_ok());
    assert!(privs::check_start(1000, &Caps::default()).is_ok());
    assert!(privs::check_start(0, &Caps::default()).unwrap_err().contains("root"));
    let admin = Caps { effective: bpf | (1 << 21), permitted: bpf | (1 << 21), ..Caps::default() };
    assert!(privs::check_start(1000, &admin).unwrap_err().contains("cap_sys_admin"));
    let ambient = Caps { ambient: 1 << 1, ..Caps::default() };
    assert!(privs::check_start(1000, &ambient).unwrap_err().contains("cap_dac_override"));
    assert!(privs::parse_status("CapEff:\tzz\n").is_none());
    assert_eq!(privs::names(privs::ALLOWED), vec!["cap_perfmon", "cap_bpf"]);
}

#[test]
fn without_the_pins_nothing_is_served() {
    // An unprivileged test process holds no capability: the kernel pins cannot be opened, and the binary
    // says so and stops before it binds the socket.
    let socket = common::scratch("never.sock");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_prismpath-collector"))
        .args(["--source", "gnet", "--maps-dir", "/nonexistent-pins", "--socket"]).arg(&socket).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("pins"));
    assert!(!socket.exists());
}

fn source(name: &str) -> String {
    std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(name)).unwrap()
}

/// The collector's reach into the kernel is what bpf.rs says and no more: one bpf(2) call site taking
/// only BPF_MAP_LOOKUP_ELEM, BPF_OBJ_GET and BPF_OBJ_GET_INFO_BY_FD, one writable mapping (the ring
/// buffer's consumer page), and no other source file that calls bpf(2) or mmap.
#[test]
fn the_kernel_reach_is_read_only_by_construction() {
    let bpf = source("bpf.rs");
    assert_eq!(bpf.matches("libc::SYS_bpf").count(), 1);
    let commands: Vec<&str> = bpf.split("enum Cmd {").nth(1).unwrap().split('}').next().unwrap().split(',').map(str::trim).filter(|line| !line.is_empty()).collect();
    assert_eq!(commands, ["MapLookupElem = 1", "ObjGet = 7", "ObjGetInfoByFd = 15"]);
    assert_eq!(bpf.matches("PROT_WRITE").count(), 1, "one writable mapping, the consumer page");
    assert_eq!(bpf.matches("Map::open(path, BPF_MAP_TYPE_RINGBUF, true)").count(), 1, "only the ring buffer is opened writable");
    for name in ["collector.rs", "decode.rs", "feed.rs", "lib.rs", "main.rs", "privs.rs", "record.rs", "ring.rs", "seal.rs", "source.rs"] {
        let text = source(name);
        assert!(!text.contains("SYS_bpf") && !text.contains("libc::mmap"), "{name} reaches the kernel");
        assert!(!text.contains("Map::open(") || name == "source.rs", "{name} opens a map");
    }
    let source_rs = source("source.rs");
    assert_eq!(source_rs.matches(", false)?").count(), 2, "the counter and configuration maps open read only");
}

#[test]
fn the_systemd_unit_grants_cap_bpf_and_little_else() {
    let unit = std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("prismpath-collector.service")).unwrap();
    let setting = |key: &str| unit.lines().find_map(|line| line.strip_prefix(&format!("{key}="))).unwrap_or_else(|| panic!("{key} is set"));
    assert_eq!(setting("AmbientCapabilities"), "CAP_BPF CAP_PERFMON");
    assert_eq!(setting("CapabilityBoundingSet"), "CAP_BPF CAP_PERFMON");
    assert_eq!(setting("NoNewPrivileges"), "yes");
    assert_eq!(setting("User"), "prismpath-collector");
    assert_eq!(setting("ProtectSystem"), "strict");
    assert_eq!(setting("RestrictAddressFamilies"), "AF_UNIX AF_INET AF_INET6");
    assert!(!unit.lines().any(|line| line.starts_with("User=root")));
}
