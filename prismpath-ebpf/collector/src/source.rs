// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! Where the records come from: the kernel's pinned ring buffer, or a recording of one.

use crate::bpf;
use crate::ring::{self, Corrupt, Entry, Recording};
use serde_json::{json, Value};
use std::io;
use std::path::{Path, PathBuf};

/// One drain of a source.
#[derive(Debug, Default)]
pub struct Drained {
    pub entries: Vec<Entry>,
    pub discarded: u64,
    pub corrupt: Option<Corrupt>,
}

pub trait Source: Send {
    /// Read up to `max` committed records and release their space.
    fn drain(&mut self, max: usize) -> Drained;
    /// The enforcer's own counters and configuration, read from its maps, as members of a `status` record.
    fn status(&mut self) -> Option<Value> {
        None
    }
    /// The ring buffer this reads, for `hello`.
    fn describe(&self) -> String;
    /// True when no record will ever arrive again (a recording read to its end).
    fn exhausted(&self) -> bool {
        false
    }
}

/// A recorded ring buffer, drained exactly as the kernel's mapping is.
pub struct RecordedSource {
    pub recording: Recording,
    pub name: String,
}

impl RecordedSource {
    pub fn new(recording: Recording, name: impl Into<String>) -> RecordedSource {
        RecordedSource { recording, name: name.into() }
    }
    pub fn load(path: &Path) -> io::Result<RecordedSource> {
        Ok(RecordedSource::new(Recording::load(path)?, format!("recording:{}", path.display())))
    }
}

impl Source for RecordedSource {
    fn drain(&mut self, max: usize) -> Drained {
        let walked = ring::walk(&self.recording.data, self.recording.consumer, self.recording.producer, max);
        self.recording.consumer = walked.consumer;
        Drained { entries: walked.entries, discarded: walked.discarded, corrupt: walked.corrupt }
    }
    fn describe(&self) -> String {
        self.name.clone()
    }
    fn exhausted(&self) -> bool {
        self.recording.consumer >= self.recording.producer
    }
}

/// The governed net edge's counters and configuration maps, opened read only.
pub struct GnMaps {
    config: bpf::Map,
    counts: bpf::Map,
    cpus: usize,
}

pub const GN_CONFIG_LEN: usize = 24;
pub const GN_CNT_N: u32 = 4;

impl GnMaps {
    pub fn open(dir: &Path) -> io::Result<GnMaps> {
        let config = bpf::Map::open(&dir.join("gn_config_map"), bpf::BPF_MAP_TYPE_ARRAY, false)?;
        let counts = bpf::Map::open(&dir.join("gn_counts_map"), bpf::BPF_MAP_TYPE_PERCPU_ARRAY, false)?;
        if config.info.value_size as usize != GN_CONFIG_LEN || counts.info.value_size != 8 || counts.info.max_entries != GN_CNT_N {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "the governed net maps do not have gn_common.h's layout"));
        }
        Ok(GnMaps { config, counts, cpus: bpf::possible_cpus() })
    }

    pub fn read(&self) -> io::Result<Value> {
        let mut config = [0u8; GN_CONFIG_LEN];
        self.config.lookup(0, &mut config)?;
        let word = |at: usize| u32::from_le_bytes(config[at..at + 4].try_into().unwrap());
        let mut sums = [0u64; GN_CNT_N as usize];
        let mut value = vec![0u8; 8 * self.cpus];
        for (key, sum) in sums.iter_mut().enumerate() {
            self.counts.lookup(key as u32, &mut value)?;
            *sum = (0..self.cpus).map(|cpu| u64::from_le_bytes(value[8 * cpu..8 * cpu + 8].try_into().unwrap())).fold(0u64, u64::wrapping_add);
        }
        Ok(json!({
            "loaded": word(0), "start_node": word(4), "image_index": word(8), "n_rules": word(12),
            "counters": {"other": sums[0].to_string(), "allow": sums[1].to_string(), "drop": sums[2].to_string(), "malformed": sums[3].to_string()},
        }))
    }
}

/// The kernel's pinned ring buffer, and for the governed net edge its counters.
pub struct KernelSource {
    ring: bpf::PinnedRing,
    maps: Option<GnMaps>,
}

impl KernelSource {
    pub fn open(ring: &Path, maps_dir: Option<PathBuf>) -> io::Result<KernelSource> {
        let ring = bpf::PinnedRing::open(ring)?;
        let maps = match maps_dir {
            Some(dir) => Some(GnMaps::open(&dir)?),
            None => None,
        };
        Ok(KernelSource { ring, maps })
    }
}

impl Source for KernelSource {
    fn drain(&mut self, max: usize) -> Drained {
        let consumer = self.ring.consumer_pos();
        let producer = self.ring.producer_pos();
        let walked = ring::walk(&self.ring, consumer, producer, max);
        // The bytes of every record walked have been copied out, so their space can go back to the kernel.
        if walked.consumer != consumer {
            self.ring.set_consumer_pos(walked.consumer);
        }
        Drained { entries: walked.entries, discarded: walked.discarded, corrupt: walked.corrupt }
    }

    fn status(&mut self) -> Option<Value> {
        let maps = self.maps.as_ref()?;
        Some(maps.read().unwrap_or_else(|error| json!({"maps_error": error.to_string()})))
    }

    fn describe(&self) -> String {
        self.ring.path().to_string()
    }
}
