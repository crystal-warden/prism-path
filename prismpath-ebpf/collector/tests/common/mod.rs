// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! A collector in process over a ring buffer the test writes into, and a client of its feed.
#![allow(dead_code)]

use prismpath_collector::collector::{self, End, Run, Settings};
use prismpath_collector::decode::Kind;
use prismpath_collector::feed::{self, FeedConfig, Hub};
use prismpath_collector::record;
use prismpath_collector::ring::{self, Recording};
use prismpath_collector::source::{Drained, Source};
use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// A ring buffer the test commits records into while the collector drains it.
#[derive(Clone)]
pub struct SharedRing(pub Arc<Mutex<Recording>>);

impl SharedRing {
    pub fn new(size: usize) -> SharedRing {
        SharedRing(Arc::new(Mutex::new(Recording::new(size, 0))))
    }
    /// Commit a record, waiting for the collector to free space when the ring is full.
    pub fn push(&self, payload: &[u8]) {
        self.push_raw(payload, payload.len() as u32, false, false)
    }
    pub fn push_raw(&self, payload: &[u8], length: u32, busy: bool, discard: bool) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while !self.0.lock().unwrap().push_raw(payload, length, busy, discard) {
            assert!(Instant::now() < deadline, "the collector stopped draining the ring");
            thread::sleep(Duration::from_millis(1));
        }
    }
    pub fn drained(&self) -> bool {
        let ring = self.0.lock().unwrap();
        ring.consumer == ring.producer
    }
}

impl Source for SharedRing {
    fn drain(&mut self, max: usize) -> Drained {
        let mut ring = self.0.lock().unwrap();
        let walked = ring::walk(&ring.data, ring.consumer, ring.producer, max);
        ring.consumer = walked.consumer;
        Drained { entries: walked.entries, discarded: walked.discarded, corrupt: walked.corrupt }
    }
    fn describe(&self) -> String {
        "test-ring".into()
    }
}

static NEXT: AtomicU64 = AtomicU64::new(0);

pub fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("c{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

pub fn own_uid() -> u32 {
    // SAFETY: getuid has no preconditions.
    unsafe { libc::getuid() }
}

pub struct Harness {
    pub hub: Arc<Hub>,
    pub ring: SharedRing,
    pub stop: Arc<AtomicBool>,
    pub socket: PathBuf,
    handle: Option<JoinHandle<(End, u64)>>,
}

impl Harness {
    pub fn start(kind: Kind, cfg: FeedConfig, settings: Settings) -> Harness {
        Harness::start_on(kind, cfg, settings, SharedRing::new(1 << 16))
    }

    pub fn start_on(kind: Kind, cfg: FeedConfig, settings: Settings, ring: SharedRing) -> Harness {
        let socket = scratch("f.sock");
        let session = "00112233445566778899aabbccddeeff".to_string();
        let hello = collector::hello(kind, "test-ring", &session, &settings, cfg.queue);
        let hub = Hub::new(cfg, kind.name(), &hello);
        feed::listen_unix(hub.clone(), &socket, None).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let (run_hub, run_stop, mut source) = (hub.clone(), stop.clone(), ring.clone());
        let handle = thread::spawn(move || {
            let mut run = Run::new(kind, session, &run_hub, settings);
            let end = run.run(&mut source, &run_stop);
            (end, run.sealer.count())
        });
        Harness { hub, ring, stop, socket, handle: Some(handle) }
    }

    pub fn allowing_self() -> FeedConfig {
        FeedConfig { allowed_uids: vec![own_uid()], ..FeedConfig::default() }
    }

    /// Stop the drain loop and return how it ended and how many leaves it sealed.
    pub fn finish(&mut self) -> (End, u64) {
        self.stop.store(true, Ordering::Relaxed);
        self.join()
    }

    pub fn join(&mut self) -> (End, u64) {
        self.handle.take().unwrap().join().unwrap()
    }

    pub fn client(&self) -> Client {
        Client::subscribe(&self.socket)
    }
}

pub struct Client {
    pub stream: UnixStream,
    reader: BufReader<UnixStream>,
}

impl Client {
    pub fn connect(socket: &PathBuf) -> Client {
        let stream = UnixStream::connect(socket).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        let reader = BufReader::new(stream.try_clone().unwrap());
        Client { stream, reader }
    }

    /// Connect, subscribe, and read the hello and the join seal.
    pub fn subscribe(socket: &PathBuf) -> Client {
        let mut client = Client::connect(socket);
        client.send(&[record::subscription_bytes(), b"\n".to_vec()].concat());
        let hello = client.next().expect("hello");
        assert_eq!(hello["kind"], "hello");
        assert_eq!(hello["protocol"], record::PROTOCOL);
        let join = client.next().expect("the join seal");
        assert_eq!(join["kind"], "seal");
        assert_eq!(join["trigger"], "join");
        client
    }

    pub fn send(&mut self, bytes: &[u8]) {
        self.stream.write_all(bytes).unwrap();
    }

    /// The next record, held to canon/2 and the length bound; None at the end of the stream.
    pub fn next(&mut self) -> Option<Value> {
        let mut line = Vec::new();
        match self.reader.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => None,
            Ok(_) => {
                assert!(line.len() <= record::MAX_RECORD, "a record of {} bytes", line.len());
                assert_eq!(line.pop(), Some(b'\n'));
                prismpath_rs::canon2::read(&line).expect("every record is canonical canon/2");
                Some(serde_json::from_slice(&line).unwrap())
            }
        }
    }

    /// Records until one of `kind` arrives (inclusive), or the stream ends.
    pub fn until(&mut self, kind: &str) -> Vec<Value> {
        let mut out = Vec::new();
        while let Some(value) = self.next() {
            let done = value["kind"] == kind;
            out.push(value);
            if done {
                break;
            }
        }
        out
    }
}

/// Settings that seal and report quickly.
pub fn quick() -> Settings {
    Settings { seal_interval: Duration::from_millis(50), seal_count: 1 << 20, ..Settings::default() }
}

pub fn kinds(records: &[Value], kind: &str) -> Vec<Value> {
    records.iter().filter(|record| record["kind"] == kind).cloned().collect()
}
