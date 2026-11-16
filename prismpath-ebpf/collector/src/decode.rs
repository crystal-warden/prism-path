// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The two enforcers' ring buffer records, read into feed records.
//!
//! Each record kind is a fixed C struct the program writes and its loader reads: `struct gn_event`
//! (`prismpath-ebpf/gnet/gn_common.h`, 56 bytes, the governed net edge) and `struct ppt_receipt`
//! (`prismpath-ebpf/ppt_common.h`, 40 bytes, the stateful selector). Both are little endian on every
//! host the programs run on. The cause in each names a code in the registry (`prismpath_rs::causes`),
//! and a selector receipt is also given in the Facet receipt stream profile through
//! `prismpath_telemetry_rs::receipts`, the wire the receipt rides when it leaves the host.

use prismpath_rs::causes;
use prismpath_telemetry_rs::receipts;
use serde_json::{json, Map, Value};

pub const GN_EVENT_LEN: usize = 56;
pub const PPT_RECEIPT_LEN: usize = 40;
/// The receipt's `event` sentinel for a loader attested hot swap (`PPT_EVENT_MIGRATION`).
pub const PPT_EVENT_MIGRATION: i32 = i32::MIN;
/// The longest frame whose bytes a record carries as hex; a longer one is named by its hash alone.
pub const FRAME_HEX_MAX: usize = 256;

/// Which enforcer's ring buffer this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// The governed net edge, `gn_events` (`struct gn_event`).
    Gnet,
    /// The stateful selector, `receipt_map` (`struct ppt_receipt`).
    Selector,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Gnet => "gnet",
            Kind::Selector => "selector",
        }
    }
    pub fn parse(text: &str) -> Option<Kind> {
        match text {
            "gnet" => Some(Kind::Gnet),
            "selector" => Some(Kind::Selector),
            _ => None,
        }
    }
    pub fn frame_len(self) -> usize {
        match self {
            Kind::Gnet => GN_EVENT_LEN,
            Kind::Selector => PPT_RECEIPT_LEN,
        }
    }
}

/// gn_common.h's outcome names, as `integrations/governed_net/frame.py` spells them.
pub fn outcome_name(outcome: u8) -> Option<&'static str> {
    ["other", "allow", "drop_policy", "drop_malformed", "drop_no_policy", "drop_no_log"].get(outcome as usize).copied()
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
}
fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn i32_at(bytes: &[u8], at: usize) -> i32 {
    i32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

/// `struct gn_event`, member by member (gn_common.h).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GnEvent {
    pub request_id: u64,
    pub t_ns: u64,
    pub image_index: u32,
    pub edge: i32,
    pub cause: u16,
    pub outcome: u8,
    pub reason: u8,
    pub version: u8,
    pub cmd: u8,
    pub hclass: u8,
    pub name_len: u8,
    pub data_len: u16,
    pub src_port: u16,
    pub handle: u32,
    pub arg0: u32,
    pub arg1: u32,
    pub src_ip: u32,
    pub pad: u32,
}

impl GnEvent {
    pub fn read(bytes: &[u8]) -> Option<GnEvent> {
        if bytes.len() != GN_EVENT_LEN {
            return None;
        }
        Some(GnEvent {
            request_id: u64_at(bytes, 0),
            t_ns: u64_at(bytes, 8),
            image_index: u32_at(bytes, 16),
            edge: i32_at(bytes, 20),
            cause: u16_at(bytes, 24),
            outcome: bytes[26],
            reason: bytes[27],
            version: bytes[28],
            cmd: bytes[29],
            hclass: bytes[30],
            name_len: bytes[31],
            data_len: u16_at(bytes, 32),
            src_port: u16_at(bytes, 34),
            handle: u32_at(bytes, 36),
            arg0: u32_at(bytes, 40),
            arg1: u32_at(bytes, 44),
            src_ip: u32_at(bytes, 48),
            pad: u32_at(bytes, 52),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(GN_EVENT_LEN);
        out.extend_from_slice(&self.request_id.to_le_bytes());
        out.extend_from_slice(&self.t_ns.to_le_bytes());
        out.extend_from_slice(&self.image_index.to_le_bytes());
        out.extend_from_slice(&self.edge.to_le_bytes());
        out.extend_from_slice(&self.cause.to_le_bytes());
        out.extend_from_slice(&[self.outcome, self.reason, self.version, self.cmd, self.hclass, self.name_len]);
        out.extend_from_slice(&self.data_len.to_le_bytes());
        out.extend_from_slice(&self.src_port.to_le_bytes());
        for word in [self.handle, self.arg0, self.arg1, self.src_ip, self.pad] {
            out.extend_from_slice(&word.to_le_bytes());
        }
        out
    }
}

/// `struct ppt_receipt`, member by member (ppt_common.h).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PptReceipt {
    pub seq: u64,
    pub t_ns: u64,
    pub policy_hash: u64,
    pub prev_node: i32,
    pub event: i32,
    pub next_node: i32,
    pub cause: i32,
}

impl PptReceipt {
    pub fn read(bytes: &[u8]) -> Option<PptReceipt> {
        if bytes.len() != PPT_RECEIPT_LEN {
            return None;
        }
        Some(PptReceipt {
            seq: u64_at(bytes, 0),
            t_ns: u64_at(bytes, 8),
            policy_hash: u64_at(bytes, 16),
            prev_node: i32_at(bytes, 24),
            event: i32_at(bytes, 28),
            next_node: i32_at(bytes, 32),
            cause: i32_at(bytes, 36),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PPT_RECEIPT_LEN);
        for word in [self.seq, self.t_ns, self.policy_hash] {
            out.extend_from_slice(&word.to_le_bytes());
        }
        for word in [self.prev_node, self.event, self.next_node, self.cause] {
            out.extend_from_slice(&word.to_le_bytes());
        }
        out
    }

    /// The receipt in the Facet receipt stream profile, when its fields are what that profile carries
    /// (nonnegative nodes and event, a cause within the byte), checked by decoding it back.
    pub fn facet_frame(&self) -> Option<Vec<u8>> {
        let (prev, event, next) = (u64::try_from(self.prev_node).ok()?, u64::try_from(self.event).ok()?, u64::try_from(self.next_node).ok()?);
        let cause = u8::try_from(self.cause).ok()?;
        let frame = receipts::encode_receipt(self.seq, prev, event, next, receipts::CauseRef::from(cause)).ok()?;
        let back = receipts::decode_receipt(&frame).ok()?.receipt?;
        (back.seq == self.seq && back.prev_node == prev && back.event == event && back.next_node == next && back.cause == cause).then_some(frame)
    }
}

fn ipv4(host_order: u32) -> String {
    let bytes = host_order.to_be_bytes();
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

fn cause_members(map: &mut Map<String, Value>, code: i64) {
    map.insert("cause".into(), json!(code));
    if let Ok(byte) = u8::try_from(code) {
        if let Some(name) = causes::name(byte) {
            map.insert("cause_name".into(), json!(name));
        }
        if let Some(class) = causes::cause_class(byte) {
            map.insert("cause_class".into(), json!(class.as_str()));
        }
    }
}

/// The members every record that stands for a leaf carries: its place in the session's tree and its leaf.
fn leaf_members(kind: Kind, index: u64, leaf: &[u8; 32]) -> Map<String, Value> {
    let mut map = Map::new();
    map.insert("source".into(), json!(kind.name()));
    map.insert("index".into(), json!(index));
    map.insert("leaf".into(), json!(hex::encode(leaf)));
    map
}

/// The feed record of one committed frame. `index` is its leaf index in this session's tree and `leaf`
/// is SHA-256 of its bytes. A frame that is not its kind's struct is a `malformed` record, still a leaf.
pub fn record(kind: Kind, index: u64, leaf: &[u8; 32], bytes: &[u8]) -> Value {
    let mut map = leaf_members(kind, index, leaf);
    if bytes.len() <= FRAME_HEX_MAX {
        map.insert("frame".into(), json!(hex::encode(bytes)));
    }
    match kind {
        Kind::Gnet => match GnEvent::read(bytes) {
            Some(ev) => {
                map.insert("kind".into(), json!("decision"));
                map.insert("request_id".into(), json!(ev.request_id.to_string()));
                map.insert("t_ns".into(), json!(ev.t_ns.to_string()));
                map.insert("image_index".into(), json!(ev.image_index));
                map.insert("edge".into(), json!(ev.edge));
                cause_members(&mut map, i64::from(ev.cause));
                map.insert("outcome".into(), json!(ev.outcome));
                if let Some(name) = outcome_name(ev.outcome) {
                    map.insert("outcome_name".into(), json!(name));
                }
                map.insert("reason".into(), json!(ev.reason));
                let reading = json!({"version": ev.version, "cmd": ev.cmd, "hclass": ev.hclass, "arg0": ev.arg0, "arg1": ev.arg1,
                                     "name_len": ev.name_len, "data_len": ev.data_len});
                map.insert("reading".into(), reading);
                map.insert("handle".into(), json!(ev.handle));
                map.insert("src_ip".into(), json!(ipv4(ev.src_ip)));
                map.insert("src_port".into(), json!(ev.src_port));
            }
            None => malformed(&mut map, bytes.len(), "length"),
        },
        Kind::Selector => match PptReceipt::read(bytes) {
            Some(rc) => {
                map.insert("kind".into(), json!("receipt"));
                map.insert("seq".into(), json!(rc.seq.to_string()));
                map.insert("t_ns".into(), json!(rc.t_ns.to_string()));
                map.insert("policy_hash".into(), json!(format!("{:016x}", rc.policy_hash)));
                map.insert("prev_node".into(), json!(rc.prev_node));
                map.insert("event".into(), json!(rc.event));
                map.insert("next_node".into(), json!(rc.next_node));
                map.insert("migration".into(), json!(rc.event == PPT_EVENT_MIGRATION));
                cause_members(&mut map, i64::from(rc.cause));
                if let Some(frame) = rc.facet_frame() {
                    map.insert("facet".into(), json!(hex::encode(frame)));
                }
            }
            None => malformed(&mut map, bytes.len(), "length"),
        },
    }
    Value::Object(map)
}

/// The record of a frame too long to keep: only its length and its leaf.
pub fn oversized_record(kind: Kind, index: u64, leaf: &[u8; 32], length: u32) -> Value {
    let mut map = leaf_members(kind, index, leaf);
    malformed(&mut map, length as usize, "oversized");
    Value::Object(map)
}

fn malformed(map: &mut Map<String, Value>, length: usize, reason: &str) {
    map.insert("kind".into(), json!("malformed"));
    map.insert("length".into(), json!(length));
    map.insert("reason".into(), json!(reason));
}
