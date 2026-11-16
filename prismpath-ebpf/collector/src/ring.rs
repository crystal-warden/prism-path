// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The BPF ring buffer's record walk, shared by the kernel mapping and by a recorded image of it.
//!
//! The kernel lays a ring buffer's data area out as records, each an 8 byte header (a `u32` length whose
//! top bit is BUSY, set while the producer is still writing, and whose next bit is DISCARD, set when the
//! producer gave the slot back, then a `u32` page offset the reader does not need) followed by the
//! payload, rounded up to 8 bytes. Positions are 64 bit counters taken modulo the data size, which is a
//! power of two. The reader owns the consumer position and the kernel the producer position; every record
//! between them that is not BUSY is committed and stays put until the consumer position passes it.
//!
//! The walk trusts nothing in the header. A length that would run past the producer position or past the
//! data area is corruption, and the walk stops there and says so, since no later position can be found
//! from a header that lies. A committed record longer than [`MAX_FRAME`] is read only to hash it.

use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::Path;

pub const BUSY_BIT: u32 = 1 << 31;
pub const DISCARD_BIT: u32 = 1 << 30;
pub const HEADER_LEN: u64 = 8;
/// The longest record whose bytes are kept and decoded; both enforcers' records are far shorter (56 and 40).
pub const MAX_FRAME: usize = 4096;

/// The bytes of a ring buffer's data area, read at a position taken modulo its size.
pub trait RingData {
    /// The data area's length, a power of two.
    fn size(&self) -> u64;
    /// The header word at `pos`, read with acquire ordering where the producer writes concurrently.
    fn header(&self, pos: u64) -> u32;
    /// Copy `out.len()` bytes from `pos` on, wrapping at the end of the data area.
    fn read(&self, pos: u64, out: &mut [u8]);
}

/// One committed record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    Frame(Vec<u8>),
    /// Longer than [`MAX_FRAME`]: its length and the SHA-256 of its bytes, which are not kept.
    Oversized { length: u32, sha256: [u8; 32] },
}

impl Entry {
    /// SHA-256 of the record's bytes: the leaf the seal takes for it (merkle.h's receipt leaf).
    pub fn sha256(&self) -> [u8; 32] {
        match self {
            Entry::Frame(bytes) => Sha256::digest(bytes).into(),
            Entry::Oversized { sha256, .. } => *sha256,
        }
    }
}

/// Why the walk stopped short of the producer position for good.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Corrupt {
    pub pos: u64,
    pub reason: String,
}

/// The result of one walk: the committed records read, the consumer position after them, and the
/// corruption that stopped the walk, if one did.
#[derive(Debug, Default)]
pub struct Walked {
    pub entries: Vec<Entry>,
    pub consumer: u64,
    pub discarded: u64,
    pub corrupt: Option<Corrupt>,
}

/// Walk the committed records from `consumer` towards `producer`, at most `max` of them.
pub fn walk(data: &dyn RingData, consumer: u64, producer: u64, max: usize) -> Walked {
    let size = data.size();
    let mut out = Walked { consumer, ..Walked::default() };
    let mut pos = consumer;
    if producer < consumer || producer - consumer > size {
        out.corrupt = Some(Corrupt { pos, reason: format!("producer {producer} is not within one data area of consumer {consumer}") });
        return out;
    }
    while pos < producer && out.entries.len() < max {
        if producer - pos < HEADER_LEN {
            out.corrupt = Some(Corrupt { pos, reason: "a record header runs past the producer position".into() });
            break;
        }
        let header = data.header(pos);
        if header & BUSY_BIT != 0 {
            break; // not committed yet: read it on a later walk
        }
        let length = header & !(BUSY_BIT | DISCARD_BIT);
        let total = HEADER_LEN + ((u64::from(length) + 7) & !7);
        if u64::from(length) > size - HEADER_LEN || total > producer - pos {
            out.corrupt = Some(Corrupt { pos, reason: format!("a record of {length} bytes runs past the producer position") });
            break;
        }
        if header & DISCARD_BIT != 0 {
            out.discarded += 1;
        } else if length as usize > MAX_FRAME {
            let mut hasher = Sha256::new();
            let mut chunk = vec![0u8; MAX_FRAME];
            let mut done = 0u64;
            while done < u64::from(length) {
                let take = (u64::from(length) - done).min(MAX_FRAME as u64) as usize;
                data.read(pos + HEADER_LEN + done, &mut chunk[..take]);
                hasher.update(&chunk[..take]);
                done += take as u64;
            }
            out.entries.push(Entry::Oversized { length, sha256: hasher.finalize().into() });
        } else {
            let mut bytes = vec![0u8; length as usize];
            data.read(pos + HEADER_LEN, &mut bytes);
            out.entries.push(Entry::Frame(bytes));
        }
        pos += total;
    }
    out.consumer = pos;
    out
}

/// A data area held in memory, as a recording keeps it.
pub struct Buffer {
    pub bytes: Vec<u8>,
}

impl RingData for Buffer {
    fn size(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn header(&self, pos: u64) -> u32 {
        let mut word = [0u8; 4];
        self.read(pos, &mut word);
        u32::from_le_bytes(word)
    }
    fn read(&self, pos: u64, out: &mut [u8]) {
        let size = self.bytes.len();
        let start = (pos % size as u64) as usize;
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = self.bytes[(start + index) % size];
        }
    }
}

/// A recorded ring buffer: its data area and the two positions, so the walk the kernel's mapping gets is
/// replayed byte for byte with no kernel. The file is `PPRB`, a `u32` version (1), the data size, the
/// consumer and the producer positions as little endian `u64`s, then the data area.
pub struct Recording {
    pub data: Buffer,
    pub consumer: u64,
    pub producer: u64,
}

pub const RECORDING_MAGIC: &[u8; 4] = b"PPRB";
const RECORDING_HEAD: usize = 32;

impl Recording {
    /// An empty ring of `size` bytes (a power of two of at least 8) with both positions at `start`.
    pub fn new(size: usize, start: u64) -> Recording {
        assert!(size.is_power_of_two() && size >= 8, "a ring's data size is a power of two");
        Recording { data: Buffer { bytes: vec![0; size] }, consumer: start, producer: start }
    }

    /// Append one record as the kernel commits it (`busy` leaves it uncommitted, `discard` gives it back).
    /// Returns false, writing nothing, when it would not fit in the free space.
    pub fn push_raw(&mut self, payload: &[u8], length_field: u32, busy: bool, discard: bool) -> bool {
        let total = HEADER_LEN + ((payload.len() as u64 + 7) & !7);
        if self.producer - self.consumer + total > self.data.size() {
            return false;
        }
        let mut header = length_field;
        if busy {
            header |= BUSY_BIT;
        }
        if discard {
            header |= DISCARD_BIT;
        }
        self.write(self.producer, &header.to_le_bytes());
        self.write(self.producer + 4, &0u32.to_le_bytes());
        self.write(self.producer + HEADER_LEN, payload);
        self.producer += total;
        true
    }

    /// Append one committed record whose header states its real length.
    pub fn push(&mut self, payload: &[u8]) -> bool {
        self.push_raw(payload, payload.len() as u32, false, false)
    }

    fn write(&mut self, pos: u64, bytes: &[u8]) {
        let size = self.data.bytes.len();
        for (index, byte) in bytes.iter().enumerate() {
            self.data.bytes[(pos as usize + index) % size] = *byte;
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RECORDING_HEAD + self.data.bytes.len());
        out.extend_from_slice(RECORDING_MAGIC);
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&(self.data.bytes.len() as u64).to_le_bytes());
        out.extend_from_slice(&self.consumer.to_le_bytes());
        out.extend_from_slice(&self.producer.to_le_bytes());
        out.extend_from_slice(&self.data.bytes);
        out
    }

    /// Read a recording, refusing one whose header is not a ring this collector could have mapped.
    pub fn from_bytes(bytes: &[u8]) -> Result<Recording, String> {
        if bytes.len() < RECORDING_HEAD || &bytes[..4] != RECORDING_MAGIC {
            return Err("not a ring buffer recording".into());
        }
        let word = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
        if u32::from_le_bytes(bytes[4..8].try_into().unwrap()) != 1 {
            return Err("a recording version this collector does not read".into());
        }
        let size = word(8);
        if !size.is_power_of_two() || !(8..=(1 << 30)).contains(&size) || bytes.len() as u64 != RECORDING_HEAD as u64 + size {
            return Err("the recorded data size is not a power of two matching the file".into());
        }
        Ok(Recording { data: Buffer { bytes: bytes[RECORDING_HEAD..].to_vec() }, consumer: word(16), producer: word(24) })
    }

    pub fn load(path: &Path) -> io::Result<Recording> {
        let bytes = fs::read(path)?;
        Recording::from_bytes(&bytes).map_err(|reason| io::Error::new(io::ErrorKind::InvalidData, reason))
    }
}
