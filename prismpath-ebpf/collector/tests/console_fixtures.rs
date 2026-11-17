// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The console's recorded feeds (`prismpath/tests/fixtures/collector_feed/*.jsonl`) are what this
//! collector's own drain loop and feed send one subscribed client, byte for byte: the drain loop's steps
//! (`Run::admit`, `take`, `seal`, `status`) are driven in a fixed order over twenty governed net frames and
//! one of the wrong length, and the client's bytes are read off its Unix socket. So the console's tests read
//! what the collector really writes, consistency proofs included, and a change to the feed that the fixtures
//! do not follow fails here.
//!
//!     PRISMPATH_WRITE_FEED_FIXTURES=1 cargo test --manifest-path prismpath-ebpf/collector/Cargo.toml --test console_fixtures
//!
//! writes them instead of comparing, for a reviewed change.

mod common;

use prismpath_collector::collector::{self, Run, Settings};
use prismpath_collector::decode::Kind;
use prismpath_collector::feed::{self, Hub};
use prismpath_collector::record;
use prismpath_collector::ring::Entry;
use prismpath_collector::source::{Drained, Source};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};

const FRAMES: [&str; 21] = [
    "e80300000000000000f2052a01000000070000000200000000000100010100080300409c0500000000000000320000000100007f00000000",
    "e90300000000000060d51c2a01000000070000000200000000000100010201080300419c0500000001000000320000000100007f00000000",
    "ea03000000000000c0b8332a0100000007000000ffffffff20000200010302080300429c0500000000000000320000000100007f00000000",
    "eb03000000000000209c4a2a01000000070000000200000000000100010400080300439c0500000001000000320000000100007f00000000",
    "ec03000000000000807f612a0100000007000000ffffffff22000200010501080300449c0500000000000000320000000100007f00000000",
    "ed03000000000000e062782a0100000007000000ffffffff00000301010102080300459c0500000001000000320000000100007f00000000",
    "ee0300000000000040468f2a01000000070000000200000000000100010200080300469c0500000000000000320000000100007f00000000",
    "ef03000000000000a029a62a0100000007000000ffffffff20000200010301080300479c0500000001000000320000000100007f00000000",
    "f003000000000000000dbd2a01000000070000000200000000000100010402080300489c0500000000000000320000000100007f00000000",
    "f10300000000000060f0d32a01000000070000000200000000000100010500080300499c0500000001000000320000000100007f00000000",
    "f203000000000000c0d3ea2a0100000007000000ffffffff210002000101010803004a9c0500000000000000320000000100007f00000000",
    "f30300000000000020b7012b0100000007000000ffffffff200002000102020803004b9c0500000001000000320000000100007f00000000",
    "f403000000000000809a182b010000000700000002000000000001000103000803004c9c0500000000000000320000000100007f00000000",
    "f503000000000000e07d2f2b0100000007000000ffffffff000003040104010803004d9c0500000001000000320000000100007f00000000",
    "f6030000000000004061462b010000000700000002000000000001000105020803004e9c0500000000000000320000000100007f00000000",
    "f703000000000000a0445d2b0100000007000000ffffffff250002000101000803004f9c0500000001000000320000000100007f00000000",
    "f8030000000000000028742b01000000070000000200000000000100010201080300509c0500000000000000320000000100007f00000000",
    "f903000000000000600b8b2b01000000070000000200000000000100010302080300519c0500000001000000320000000100007f00000000",
    "fa03000000000000c0eea12b0100000007000000ffffffff20000200010400080300529c0500000000000000320000000100007f00000000",
    "fb0300000000000020d2b82b01000000070000000200000000000100010501080300539c0500000001000000320000000100007f00000000",
    "abababababababababababababababababababababababababababababababababababababababab",
];

/// The governed net counters a status record reports, in the order the script reads them.
struct Script(Vec<(u32, u32, u32)>);

impl Source for Script {
    fn drain(&mut self, _max: usize) -> Drained {
        Drained { entries: Vec::new(), discarded: 0, corrupt: None }
    }
    fn status(&mut self) -> Option<Value> {
        let (allow, drop, malformed) = self.0.remove(0);
        Some(json!({"loaded": 1, "start_node": 0, "image_index": 7, "n_rules": 12,
                    "counters": {"allow": allow.to_string(), "drop": drop.to_string(), "malformed": malformed.to_string(), "other": "0"}}))
    }
    fn describe(&self) -> String {
        "recording:governed-net".into()
    }
}

fn settings() -> Settings {
    Settings { seal_interval: Duration::from_millis(60), seal_count: 8, ..Settings::default() }
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../prismpath/tests/fixtures/collector_feed")
}

/// One session: `before` frames drained before the client is admitted, then each batch followed by an
/// interval seal and a status, then a status with nothing to seal, the final seal and the last status.
fn record_session(session: &str, before: usize, batches: &[usize], counters: Vec<(u32, u32, u32)>) -> Vec<u8> {
    let settings = settings();
    let socket = common::scratch("fixture.sock");
    let hello = collector::hello(Kind::Gnet, "recording:governed-net", session, &settings, 4096);
    let hub = Hub::new(common::Harness::allowing_self(), "gnet", &hello);
    feed::listen_unix(hub.clone(), &socket, None).unwrap();
    let mut stream = UnixStream::connect(&socket).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    stream.write_all(&[record::subscription_bytes(), b"\n".to_vec()].concat()).unwrap();
    let reader = std::thread::spawn(move || {
        let mut lines = BufReader::new(stream);
        let mut out = Vec::new();
        let mut finished = false;
        loop {
            let mut line = Vec::new();
            if lines.read_until(b'\n', &mut line).unwrap() == 0 {
                break;
            }
            let value: Value = serde_json::from_slice(&line).unwrap();
            out.extend_from_slice(&line);
            if finished && value["kind"] == "status" {
                break;
            }
            finished |= value["trigger"] == "final";
        }
        out
    });
    let deadline = Instant::now() + Duration::from_secs(20);
    while hub.client_count() == 0 {
        assert!(Instant::now() < deadline, "the client subscribes");
        std::thread::sleep(Duration::from_millis(5));
    }
    let mut source = Script(counters);
    let mut run = Run::new(Kind::Gnet, session.to_string(), &hub, settings);
    let mut frames = FRAMES.iter().map(|frame| Entry::Frame(hex::decode(frame).unwrap()));
    for frame in frames.by_ref().take(before) {
        assert!(run.take(frame));
    }
    run.admit();
    for batch in batches {
        for frame in frames.by_ref().take(*batch) {
            assert!(run.take(frame));
        }
        run.seal("interval");
        run.status(&mut source);
    }
    assert!(frames.next().is_none(), "every frame is drained");
    run.status(&mut source);
    run.seal("final");
    run.status(&mut source);
    let bytes = reader.join().unwrap();
    let _ = std::fs::remove_file(&socket);
    bytes
}

#[test]
fn the_console_fixtures_are_what_the_feed_sends() {
    let session = record_session("5ee55e55aa11bb22cc33dd44ee55ff66", 0, &[7, 1, 6, 3, 4],
                                 vec![(4, 2, 1), (4, 3, 1), (7, 5, 2), (9, 6, 2), (11, 7, 2), (11, 7, 2), (11, 7, 2)]);
    let late = record_session("0a1b2c3d4e5f60718293a4b5c6d7e8f9", 11, &[3, 3, 4],
                              vec![(7, 5, 2), (9, 6, 2), (11, 7, 2), (11, 7, 2), (11, 7, 2)]);
    for (name, bytes) in [("gnet_session.jsonl", &session), ("gnet_late_join.jsonl", &late)] {
        let path = fixtures_dir().join(name);
        if std::env::var_os("PRISMPATH_WRITE_FEED_FIXTURES").is_some() {
            std::fs::write(&path, bytes).unwrap();
            continue;
        }
        let kept = std::fs::read(&path).unwrap();
        assert!(kept == *bytes, "{name} is not what the feed sends now; if the change is meant, regenerate it \
                                 with PRISMPATH_WRITE_FEED_FIXTURES=1 and review the diff:\n{}", String::from_utf8_lossy(bytes));
    }
    // every seal after the first proves the one before it, and the late client's first later seal proves
    // from its join seal
    for bytes in [&session, &late] {
        let seals: Vec<Value> = bytes.split(|byte| *byte == b'\n').filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice::<Value>(line).unwrap()).filter(|value| value["kind"] == "seal").collect();
        assert!(seals[0].get("consistency").is_none());
        for pair in seals.windows(2) {
            assert_eq!(pair[1]["consistency"]["from"], pair[0]["count"]);
        }
    }
}
