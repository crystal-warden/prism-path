// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The collector's whole use of bpf(2): open a pinned object, ask what map it is, and look an element up.
//!
//! Three commands and no others. There is no code here that creates, updates or deletes a map element,
//! loads or attaches a program, or pins anything (`tests/hostile.rs` holds this file to that). Every map
//! but the ring buffer is opened with `BPF_F_RDONLY`, so the kernel itself refuses a write through the
//! descriptor. The ring buffer is opened read and write for one reason: the reader of a BPF ring buffer
//! reports what it has read by storing its consumer position in the one page the kernel maps writable to
//! it, which is how the producer knows the space is free again. That position is the only byte the
//! collector writes into the kernel, and it is the ring buffer's own protocol, not a change to the
//! enforcer's maps or program.

use crate::ring::RingData;
use std::ffi::CString;
use std::io;
use std::os::fd::{FromRawFd, OwnedFd, AsRawFd, RawFd};
use std::path::Path;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

#[derive(Clone, Copy)]
#[repr(i32)]
enum Cmd {
    MapLookupElem = 1,
    ObjGet = 7,
    ObjGetInfoByFd = 15,
}

const BPF_F_RDONLY: u32 = 1 << 3;
pub const BPF_MAP_TYPE_ARRAY: u32 = 2;
pub const BPF_MAP_TYPE_PERCPU_ARRAY: u32 = 6;
pub const BPF_MAP_TYPE_RINGBUF: u32 = 27;

fn sys_bpf<T>(cmd: Cmd, attr: &mut T) -> io::Result<i64> {
    // SAFETY: `attr` is a live, fully initialised #[repr(C)] attribute block of the command's layout, and the
    // size passed is its own, so the kernel reads and writes only within it.
    let result = unsafe { libc::syscall(libc::SYS_bpf, cmd as i32, attr as *mut T, std::mem::size_of::<T>() as u32) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

#[repr(C)]
#[derive(Default)]
struct ObjGetAttr {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
}

#[repr(C)]
#[derive(Default)]
struct InfoAttr {
    bpf_fd: u32,
    info_len: u32,
    info: u64,
}

#[repr(C)]
#[derive(Default)]
struct LookupAttr {
    map_fd: u32,
    pad: u32,
    key: u64,
    value: u64,
    flags: u64,
}

/// The head of `struct bpf_map_info`, the members the collector checks.
#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
pub struct MapInfo {
    pub map_type: u32,
    pub id: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_flags: u32,
    pub name: [u8; 16],
}

/// A pinned map, opened.
pub struct Map {
    fd: OwnedFd,
    pub info: MapInfo,
    pub path: String,
}

impl Map {
    /// Open the pin at `path`, read only unless `writable`, and check it is a map of `map_type`.
    pub fn open(path: &Path, map_type: u32, writable: bool) -> io::Result<Map> {
        let text = path.to_string_lossy().into_owned();
        let c_path = CString::new(text.clone()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a NUL in the pin path"))?;
        let mut attr = ObjGetAttr { pathname: c_path.as_ptr() as u64, bpf_fd: 0, file_flags: if writable { 0 } else { BPF_F_RDONLY } };
        let raw = sys_bpf(Cmd::ObjGet, &mut attr).map_err(|error| io::Error::new(error.kind(), format!("{text}: {error}")))?;
        // SAFETY: BPF_OBJ_GET returned a new descriptor that nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(raw as RawFd) };
        let mut info = MapInfo::default();
        let mut info_attr = InfoAttr { bpf_fd: fd.as_raw_fd() as u32, info_len: std::mem::size_of::<MapInfo>() as u32, info: &mut info as *mut MapInfo as u64 };
        sys_bpf(Cmd::ObjGetInfoByFd, &mut info_attr).map_err(|error| io::Error::new(error.kind(), format!("{text}: map info: {error}")))?;
        if info.map_type != map_type {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{text} is a map of type {}, not {map_type}", info.map_type)));
        }
        Ok(Map { fd, info, path: text })
    }

    /// The value at `key` into `value` (all CPUs' copies, for a per-CPU map).
    pub fn lookup(&self, key: u32, value: &mut [u8]) -> io::Result<()> {
        let mut attr = LookupAttr { map_fd: self.fd.as_raw_fd() as u32, pad: 0, key: &key as *const u32 as u64, value: value.as_mut_ptr() as u64, flags: 0 };
        sys_bpf(Cmd::MapLookupElem, &mut attr).map(|_| ())
    }
}

/// The number of possible CPUs, the count of copies a per-CPU map value holds.
pub fn possible_cpus() -> usize {
    std::fs::read_to_string("/sys/devices/system/cpu/possible")
        .ok()
        .and_then(|text| text.trim().rsplit(['-', ',']).next().and_then(|last| last.parse::<usize>().ok()))
        .map(|last| last + 1)
        .unwrap_or(1)
}

fn page_size() -> usize {
    // SAFETY: sysconf has no preconditions.
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

struct Mapping {
    addr: *mut libc::c_void,
    len: usize,
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: `addr` and `len` are exactly what mmap returned and nothing references the mapping after drop.
        unsafe { libc::munmap(self.addr, self.len) };
    }
}

fn map_pages(fd: RawFd, len: usize, prot: i32, offset: usize) -> io::Result<Mapping> {
    // SAFETY: a fresh shared mapping of a BPF map descriptor; the kernel validates length and offset.
    let addr = unsafe { libc::mmap(std::ptr::null_mut(), len, prot, libc::MAP_SHARED, fd, offset as libc::off_t) };
    if addr == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    Ok(Mapping { addr, len })
}

/// A pinned BPF ring buffer, mapped as libbpf maps it: the consumer position in one writable page at
/// offset 0, then from offset one page the read only producer position page and the data area, which
/// the kernel maps twice in a row so a record never wraps in the mapping.
pub struct PinnedRing {
    map: Map,
    consumer: Mapping,
    producer: Mapping,
    page: usize,
    size: u64,
}

// SAFETY: the mappings are shared memory the kernel writes and only this one reader reads; access goes
// through atomics for the positions and headers and plain copies for committed bytes.
unsafe impl Send for PinnedRing {}

impl PinnedRing {
    pub fn open(path: &Path) -> io::Result<PinnedRing> {
        let map = Map::open(path, BPF_MAP_TYPE_RINGBUF, true)?;
        let size = u64::from(map.info.max_entries);
        let page = page_size();
        if !size.is_power_of_two() || size < page as u64 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{}: ring buffer size {size} is not a power of two pages", map.path)));
        }
        let fd = map.fd.as_raw_fd();
        let consumer = map_pages(fd, page, libc::PROT_READ | libc::PROT_WRITE, 0)?;
        let producer = map_pages(fd, page + 2 * size as usize, libc::PROT_READ, page)?;
        Ok(PinnedRing { map, consumer, producer, page, size })
    }

    pub fn path(&self) -> &str {
        &self.map.path
    }

    pub fn consumer_pos(&self) -> u64 {
        // SAFETY: the first word of the consumer page, 8 byte aligned and live while self is.
        unsafe { (*(self.consumer.addr as *const AtomicU64)).load(Ordering::Acquire) }
    }

    pub fn producer_pos(&self) -> u64 {
        // SAFETY: the first word of the producer page, 8 byte aligned and live while self is.
        unsafe { (*(self.producer.addr as *const AtomicU64)).load(Ordering::Acquire) }
    }

    /// Report that every record before `pos` has been read.
    pub fn set_consumer_pos(&self, pos: u64) {
        // SAFETY: as consumer_pos; the store is the ring buffer protocol's release of the space.
        unsafe { (*(self.consumer.addr as *const AtomicU64)).store(pos, Ordering::Release) }
    }

    fn data(&self) -> *const u8 {
        // SAFETY: the data area starts one page into the producer mapping, which is page + 2 * size long.
        unsafe { (self.producer.addr as *const u8).add(self.page) }
    }
}

impl RingData for PinnedRing {
    fn size(&self) -> u64 {
        self.size
    }
    fn header(&self, pos: u64) -> u32 {
        let offset = (pos & (self.size - 1)) as usize;
        // SAFETY: headers are 8 byte aligned within the data area.
        unsafe { (*(self.data().add(offset) as *const AtomicU32)).load(Ordering::Acquire) }
    }
    fn read(&self, pos: u64, out: &mut [u8]) {
        let offset = (pos & (self.size - 1)) as usize;
        assert!(out.len() as u64 <= self.size, "a read longer than the data area");
        // SAFETY: offset < size and len <= size, so the copy stays within the double mapping (2 * size).
        unsafe { std::ptr::copy_nonoverlapping(self.data().add(offset), out.as_mut_ptr(), out.len()) };
    }
}
