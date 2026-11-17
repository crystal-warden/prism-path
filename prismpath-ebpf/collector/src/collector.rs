// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The drain loop: read the ring buffer, make each record a leaf and a feed record, seal on an interval
//! and on a count, and offer everything to the feed without ever waiting on a client.

use crate::decode::{self, Kind};
use crate::feed::Hub;
use crate::record::{self, PROTOCOL, MAX_RECORD};
use crate::ring::Entry;
use crate::seal::{self, Sealer};
use crate::source::Source;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

/// The most batches drained after a stop is asked for.
const STOP_BATCHES: usize = 64;

#[derive(Debug, Clone)]
pub struct Settings {
    /// A seal at least this often while leaves arrive, and a `status` record this often regardless.
    pub seal_interval: Duration,
    /// A seal after this many leaves, whatever the interval.
    pub seal_count: u64,
    /// The most records drained before the loop looks at its clock and its admissions again.
    pub batch: usize,
    /// The pause when the ring buffer is empty.
    pub idle: Duration,
    /// Stop when the source says no record will arrive again (a recording).
    pub exit_when_drained: bool,
    /// The leaf hashes kept for consistency proofs (32 bytes each): the oldest count a seal can be proved
    /// from is this many leaves back. At least `seal_count`, so a client that was sent the last seal is
    /// always proved from it.
    pub proof_window: usize,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            seal_interval: Duration::from_secs(1),
            seal_count: 1024,
            batch: 256,
            idle: Duration::from_millis(5),
            exit_when_drained: false,
            proof_window: seal::DEFAULT_PROOF_WINDOW,
        }
    }
}

/// How a run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum End {
    Stopped,
    Drained,
    /// The ring buffer's headers stopped making sense; nothing after the position can be trusted.
    Corrupt(String),
    /// The session reached the most leaves it seals.
    Full,
}

/// The `hello` record a client is sent first.
pub fn hello(kind: Kind, ring: &str, session: &str, settings: &Settings, queue: usize) -> Value {
    json!({
        "kind": "hello",
        "protocol": PROTOCOL,
        "source": kind.name(),
        "ring": ring,
        "session": session,
        "max_record": MAX_RECORD,
        "queue": queue,
        "seal_interval_ms": settings.seal_interval.as_millis() as u64,
        "seal_count": settings.seal_count,
        "proof_window": settings.proof_window as u64,
        "leaf": "sha256(frame)",
    })
}

/// A fresh session id: 16 bytes from the kernel's random source, in hex.
pub fn session_id() -> String {
    let mut bytes = [0u8; 16];
    // SAFETY: getrandom writes at most `len` bytes into the buffer.
    let filled = unsafe { libc::getrandom(bytes.as_mut_ptr() as *mut libc::c_void, bytes.len(), 0) };
    assert_eq!(filled, bytes.len() as isize, "getrandom");
    hex::encode(bytes)
}

/// The framed record, or an `error` record saying why it could not be framed.
fn frame_or_error(value: &Value) -> Vec<u8> {
    record::frame(value).unwrap_or_else(|error| {
        let fallback = json!({"kind": "error", "reason": format!("a record could not be framed: {error:?}")});
        record::frame(&fallback).expect("the fallback is short canon/2")
    })
}

fn emit(hub: &Hub, value: &Value) {
    hub.publish(frame_or_error(value));
}

pub struct Run<'a> {
    pub kind: Kind,
    pub session: String,
    pub hub: &'a Hub,
    pub settings: Settings,
    pub sealer: Sealer,
    pub discarded: u64,
}

impl<'a> Run<'a> {
    pub fn new(kind: Kind, session: String, hub: &'a Hub, settings: Settings) -> Run<'a> {
        let sealer = Sealer::from_accumulator_with_window(prismpath_rs::merkle::Accumulator::new(), settings.proof_window.max(1));
        Run { kind, session, hub, settings, sealer, discarded: 0 }
    }

    /// Cut a seal (`interval`, `count` or `final`): every client is sent the tree's seal with the proof
    /// from the last seal it was sent.
    pub fn seal(&mut self, trigger: &str) {
        self.sealer.mark(trigger);
        let (kind, session, sealer) = (self.kind.name(), &self.session, &self.sealer);
        self.hub.publish_seal(sealer.accumulator(), |prior| frame_or_error(&sealer.seal_for(prior, kind, session, trigger)));
    }

    /// Publish a `status` record.
    pub fn status(&mut self, source: &mut dyn Source) {
        let mut value = json!({
            "kind": "status",
            "source": self.kind.name(),
            "session": self.session,
            "count": self.sealer.count(),
            "discarded": self.discarded,
            "feed": self.hub.stats_value(),
        });
        if let Some(enforcer) = source.status() {
            value["enforcer"] = enforcer;
        }
        emit(self.hub, &value);
    }

    /// Admit the clients that subscribed since the last call, each with its join seal: the tree's seal,
    /// proved from the count a resuming client names when it names this session.
    pub fn admit(&mut self) {
        let (kind, session, sealer) = (self.kind.name(), &self.session, &self.sealer);
        self.hub.admit(sealer.accumulator(), |resume| {
            let value = match resume {
                Some((asked, count)) if asked == session => sealer.seal_resumed(*count, kind, session),
                _ => sealer.seal_for(None, kind, session, "join"),
            };
            frame_or_error(&value)
        });
    }

    /// One drained entry: a leaf, then its record. False when the session is full.
    pub fn take(&mut self, entry: Entry) -> bool {
        let leaf = entry.sha256();
        let index = self.sealer.count();
        if !self.sealer.add(&leaf) {
            return false;
        }
        let value = match &entry {
            Entry::Frame(bytes) => decode::record(self.kind, index, &leaf, bytes),
            Entry::Oversized { length, .. } => decode::oversized_record(self.kind, index, &leaf, *length),
        };
        if value["kind"] == "malformed" {
            self.sealer.malformed += 1;
        }
        emit(self.hub, &value);
        if self.sealer.unsealed() >= self.settings.seal_count {
            self.seal("count");
        }
        true
    }

    /// Drain `source` until `stop` is set, the source is drained (when the settings ask for that), or
    /// the ring buffer is corrupt. Ends with a final seal and a status record either way.
    pub fn run(&mut self, source: &mut dyn Source, stop: &AtomicBool) -> End {
        let mut next_tick = Instant::now() + self.settings.seal_interval;
        let mut stopping = 0usize;
        let end = loop {
            self.admit();
            let drained = source.drain(self.settings.batch);
            let got = drained.entries.len();
            self.discarded += drained.discarded;
            let mut full = false;
            for entry in drained.entries {
                if !self.take(entry) {
                    full = true;
                    break;
                }
            }
            if full {
                break End::Full;
            }
            if let Some(corrupt) = drained.corrupt {
                let reason = format!("{} at position {}", corrupt.reason, corrupt.pos);
                emit(self.hub, &json!({"kind": "error", "source": self.kind.name(), "session": self.session, "reason": reason}));
                break End::Corrupt(reason);
            }
            if Instant::now() >= next_tick {
                if self.sealer.unsealed() > 0 {
                    self.seal("interval");
                }
                self.status(source);
                next_tick = Instant::now() + self.settings.seal_interval;
            }
            // On a stop, what the ring already holds is drained first (up to a bound, in case the producer
            // keeps up with the drain), so a clean stop leaves no committed record for the next session.
            if stop.load(Ordering::Relaxed) {
                stopping += 1;
                if got == 0 || stopping > STOP_BATCHES {
                    break End::Stopped;
                }
                continue;
            }
            if got == 0 {
                if self.settings.exit_when_drained && source.exhausted() {
                    break End::Drained;
                }
                thread::sleep(self.settings.idle);
            }
        };
        self.admit();
        self.seal("final");
        self.status(source);
        end
    }
}
