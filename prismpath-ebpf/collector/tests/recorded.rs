// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The collector over recorded ring buffer frames: nine receipts the selector committed in the kernel,
//! the governed net edge's event layout against the C header, and the binary over a recording file.

mod common;

use common::{kinds, quick, Harness};
use prismpath_collector::decode::{self, GnEvent, Kind, PptReceipt};
use prismpath_collector::ring::Recording;
use prismpath_rs::merkle;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn ebpf_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

/// The receipts of `decision-delta-demo/evidence/receipt_trail.log`: the selector's own ring buffer
/// records from an in-kernel session, as sel_forward_receipts drained them (policy 207748442a7915c8,
/// cause 0), rebuilt byte for byte from the logged fields. The log's root is the retired pairwise tree's,
/// so `the_recorded_frames_are_the_kernels` recomputes it to prove the rebuild exact.
fn kernel_receipts() -> (Vec<PptReceipt>, String) {
    let text = std::fs::read_to_string(ebpf_dir().join("decision-delta-demo/evidence/receipt_trail.log")).unwrap();
    let mut receipts = Vec::new();
    let mut logged_root = String::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("# merkle_root=") {
            logged_root = rest.split_whitespace().next().unwrap().to_string();
        }
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        receipts.push(PptReceipt {
            seq: fields[1].parse().unwrap(),
            t_ns: fields[2].parse().unwrap(),
            policy_hash: 0x2077_4844_2a79_15c8,
            prev_node: fields[3].parse().unwrap(),
            event: fields[4].parse().unwrap(),
            next_node: fields[5].parse().unwrap(),
            cause: 0,
        });
    }
    (receipts, logged_root)
}

fn retired_root(mut layer: Vec<[u8; 32]>) -> [u8; 32] {
    while layer.len() > 1 {
        if layer.len() % 2 == 1 {
            layer.push(*layer.last().unwrap());
        }
        layer = layer.chunks(2).map(|pair| Sha256::new().chain_update(pair[0]).chain_update(pair[1]).finalize().into()).collect();
    }
    layer[0]
}

/// The RFC 6962 root over SHA-256 leaves of the frames, by the batch tree (not the accumulator).
fn tree_root(frames: &[Vec<u8>]) -> String {
    let leaves: Vec<Vec<u8>> = frames.iter().map(|frame| Sha256::digest(frame).to_vec()).collect();
    hex::encode(merkle::root_of_bytes(&leaves).unwrap())
}

#[test]
fn the_recorded_frames_are_the_kernels() {
    let (receipts, logged_root) = kernel_receipts();
    assert_eq!(receipts.len(), 9);
    let leaves: Vec<[u8; 32]> = receipts.iter().map(|receipt| Sha256::digest(receipt.to_bytes()).into()).collect();
    assert_eq!(hex::encode(retired_root(leaves)), logged_root, "the rebuilt frames hash to the root the kernel session logged");
}

#[test]
fn the_kernels_receipts_are_fed_and_sealed() {
    let (receipts, _) = kernel_receipts();
    let frames: Vec<Vec<u8>> = receipts.iter().map(PptReceipt::to_bytes).collect();
    let mut harness = Harness::start(Kind::Selector, Harness::allowing_self(), quick());
    let mut client = harness.client();
    for frame in &frames {
        harness.ring.push(frame);
    }
    let mut got = Vec::new();
    while got.len() < frames.len() {
        let value = client.next().expect("a receipt");
        if value["kind"] == "receipt" {
            got.push(value);
        }
    }
    for (index, (value, receipt)) in got.iter().zip(&receipts).enumerate() {
        assert_eq!(value["index"], index as u64);
        assert_eq!(value["source"], "selector");
        assert_eq!(value["frame"], hex::encode(receipt.to_bytes()));
        assert_eq!(value["leaf"], hex::encode(Sha256::digest(receipt.to_bytes())));
        assert_eq!(value["seq"], receipt.seq.to_string());
        assert_eq!(value["t_ns"], receipt.t_ns.to_string());
        assert_eq!(value["policy_hash"], "207748442a7915c8");
        assert_eq!((value["prev_node"].clone(), value["event"].clone(), value["next_node"].clone()),
                   (receipt.prev_node.into(), receipt.event.into(), receipt.next_node.into()));
        assert_eq!(value["cause"], 0);
        assert_eq!(value["migration"], false);
        // the Facet receipt stream profile frame of the same receipt, through the telemetry crate
        let facet = hex::decode(value["facet"].as_str().unwrap()).unwrap();
        let decoded = prismpath_telemetry_rs::receipts::decode_receipt(&facet).unwrap().receipt.unwrap();
        assert_eq!((decoded.seq, decoded.prev_node as i32, decoded.event as i32, decoded.next_node as i32), (receipt.seq, receipt.prev_node, receipt.event, receipt.next_node));
    }
    let (_, count) = harness.finish();
    assert_eq!(count, 9);
    let rest = client.until("status");
    let last = kinds(&rest, "seal").pop().expect("a final seal");
    assert_eq!(last["trigger"], "final");
    assert_eq!(last["count"], 9);
    // The current tree's root over these nine, which merkle.h, seal_receipts and the Python reference
    // give too (the C cross check is below).
    assert_eq!(last["root"], "d875a10ad8e36cab320f76d9a4b061932d28c0a469bff7ee0a1051d4cad84165");
    assert_eq!(last["root"], tree_root(&frames));
}

fn cc() -> Option<&'static str> {
    Command::new("cc").arg("--version").stdout(Stdio::null()).stderr(Stdio::null()).status().ok().filter(|status| status.success()).map(|_| "cc")
}

/// `seal_receipts.c`, built from the repository's source against merkle.h, seals the same receipts as a
/// journal to the same root the collector's accumulator gives.
#[test]
fn seal_receipts_c_gives_the_collectors_root() {
    let Some(cc) = cc() else {
        eprintln!("skipped: no C compiler");
        return;
    };
    let (receipts, _) = kernel_receipts();
    let frames: Vec<Vec<u8>> = receipts.iter().map(PptReceipt::to_bytes).collect();
    let binary = common::scratch("seal_receipts");
    let built = Command::new(cc).args(["-O2", "-std=gnu11", "-I"]).arg(ebpf_dir()).arg(ebpf_dir().join("seal_receipts.c")).arg("-o").arg(&binary).arg("-lcrypto").status().unwrap();
    if !built.success() {
        eprintln!("skipped: seal_receipts.c does not build here (OpenSSL headers?)");
        return;
    }
    let journal = common::scratch("receipts.journal");
    std::fs::write(&journal, frames.concat()).unwrap();
    let out = Command::new(&binary).arg(&journal).output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    let root = text.lines().find_map(|line| line.trim().strip_prefix("Merkle root (seal, shared merkle.h): ")).expect("a root line").trim().to_string();
    let mut sealer = prismpath_collector::seal::Sealer::new();
    for frame in &frames {
        sealer.add(&Sha256::digest(frame).into());
    }
    assert_eq!(sealer.seal("selector", "s", "final")["root"], root);
}

fn sample_event(seed: u32) -> GnEvent {
    GnEvent {
        request_id: 0xFEDC_BA98_7654_3210 ^ u64::from(seed),
        t_ns: 0x0123_4567_89AB_CDEF + u64::from(seed),
        image_index: 0x1111_0000 + seed,
        edge: -1 - seed as i32,
        cause: 32,
        outcome: 2,
        reason: 9,
        version: 1,
        cmd: 3,
        hclass: 4,
        name_len: 63,
        data_len: 1023,
        src_port: 40000 + seed as u16,
        handle: 0x2222_0000 + seed,
        arg0: 0x3333_0000 + seed,
        arg1: 0x4444_0000 + seed,
        src_ip: 0xC000_020A,
        pad: 0,
    }
}

/// The Rust readers hold the C headers' layouts: a C program built from gn_common.h and ppt_common.h
/// prints every member of a frame the Rust side wrote.
#[test]
fn the_frame_layouts_are_the_c_headers() {
    let Some(cc) = cc() else {
        eprintln!("skipped: no C compiler");
        return;
    };
    let program = r#"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ppt_common.h"
#include "gnet/gn_common.h"
static void unhex(const char *t, unsigned char *out, size_t n) { for (size_t i = 0; i < n; i++) { unsigned v; sscanf(t + 2 * i, "%2x", &v); out[i] = (unsigned char)v; } }
int main(int argc, char **argv) {
    struct gn_event ev; struct ppt_receipt rc;
    if (argc != 3 || strlen(argv[1]) != 2 * sizeof ev || strlen(argv[2]) != 2 * sizeof rc) return 2;
    unhex(argv[1], (unsigned char *)&ev, sizeof ev); unhex(argv[2], (unsigned char *)&rc, sizeof rc);
    printf("%zu %llu %llu %u %d %u %u %u %u %u %u %u %u %u %u %u %u %u\n", sizeof ev, (unsigned long long)ev.request_id,
           (unsigned long long)ev.t_ns, ev.image_index, ev.edge, ev.cause, ev.outcome, ev.reason, ev.version, ev.cmd, ev.hclass,
           ev.name_len, ev.data_len, ev.src_port, ev.handle, ev.arg0, ev.arg1, ev.src_ip);
    printf("%zu %llu %llu %llx %d %d %d %d\n", sizeof rc, (unsigned long long)rc.seq, (unsigned long long)rc.t_ns,
           (unsigned long long)rc.policy_hash, rc.prev_node, rc.event, rc.next_node, rc.cause);
    return 0;
}
"#;
    let source = common::scratch("layout.c");
    std::fs::write(&source, program).unwrap();
    let binary = source.with_extension("");
    let built = Command::new(cc).args(["-std=gnu11", "-I"]).arg(ebpf_dir()).arg(&source).arg("-o").arg(&binary).status().unwrap();
    assert!(built.success(), "the layout probe builds against the headers");
    let ev = sample_event(7);
    let rc = PptReceipt { seq: u64::MAX - 3, t_ns: 4568886233244793, policy_hash: 0x2077_4844_2a79_15c8, prev_node: -1, event: decode::PPT_EVENT_MIGRATION, next_node: 255, cause: 66 };
    let out = Command::new(&binary).arg(hex::encode(ev.to_bytes())).arg(hex::encode(rc.to_bytes())).output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    let mut lines = text.lines();
    let expect_ev = format!("56 {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {}", ev.request_id, ev.t_ns, ev.image_index, ev.edge, ev.cause, ev.outcome,
                            ev.reason, ev.version, ev.cmd, ev.hclass, ev.name_len, ev.data_len, ev.src_port, ev.handle, ev.arg0, ev.arg1, ev.src_ip);
    assert_eq!(lines.next().unwrap(), expect_ev);
    let expect_rc = format!("40 {} {} {:x} {} {} {} {}", rc.seq, rc.t_ns, rc.policy_hash, rc.prev_node, rc.event, rc.next_node, rc.cause);
    assert_eq!(lines.next().unwrap(), expect_rc);
    assert_eq!(GnEvent::read(&ev.to_bytes()), Some(ev));
    assert_eq!(PptReceipt::read(&rc.to_bytes()), Some(rc));
}

#[test]
fn a_governed_net_decision_names_its_cause_and_outcome() {
    let mut ev = sample_event(1);
    ev.request_id = u64::MAX;
    let bytes = ev.to_bytes();
    let leaf: [u8; 32] = Sha256::digest(&bytes).into();
    let value = decode::record(Kind::Gnet, 5, &leaf, &bytes);
    assert_eq!(value["kind"], "decision");
    assert_eq!(value["request_id"], u64::MAX.to_string());
    assert_eq!(value["cause"], 32);
    assert_eq!(value["cause_name"], "route:no-matching-edge");
    assert_eq!(value["cause_class"], "routing");
    assert_eq!(value["outcome_name"], "drop_policy");
    assert_eq!(value["src_ip"], "192.0.2.10");
    assert_eq!(value["reading"]["data_len"], 1023);
    assert_eq!(value["edge"], -2);
    prismpath_collector::record::frame(&value).expect("a decision record is canon/2 and bounded");
    let receipt = PptReceipt { seq: 1, t_ns: 2, policy_hash: 3, prev_node: 1, event: decode::PPT_EVENT_MIGRATION, next_node: 0, cause: 66 };
    let value = decode::record(Kind::Selector, 0, &leaf, &receipt.to_bytes());
    assert_eq!(value["migration"], true);
    assert_eq!(value["cause_name"], "state:migration-reset");
    assert!(value.get("facet").is_none(), "a negative event has no receipt stream frame");
}

/// The binary itself over a recording file: a client joining after the nine receipts were drained is
/// handed the seal of all nine, and a TERM ends the run with a final seal and the socket removed.
#[test]
fn the_binary_serves_a_recording() {
    let (receipts, _) = kernel_receipts();
    let frames: Vec<Vec<u8>> = receipts.iter().map(PptReceipt::to_bytes).collect();
    let mut recording = Recording::new(4096, 1 << 40);
    for frame in &frames {
        assert!(recording.push(frame));
    }
    let file = common::scratch("trail.pprb");
    std::fs::write(&file, recording.to_bytes()).unwrap();
    let socket = common::scratch("bin.sock");
    let mut child = Command::new(env!("CARGO_BIN_EXE_prismpath-collector"))
        .args(["--source", "selector", "--recorded"]).arg(&file).arg("--socket").arg(&socket)
        .stderr(Stdio::piped()).spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "the socket appears");
        std::thread::sleep(Duration::from_millis(20));
    }
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    let meta = std::fs::metadata(&socket).unwrap();
    assert!(meta.file_type().is_socket());
    assert_eq!(meta.permissions().mode() & 0o777, 0o660);
    std::thread::sleep(Duration::from_millis(200));
    let mut client = common::Client::connect(&socket);
    client.send(&[prismpath_collector::record::subscription_bytes(), b"\n".to_vec()].concat());
    let hello = client.next().unwrap();
    assert_eq!(hello["source"], "selector");
    assert_eq!(hello["session"].as_str().unwrap().len(), 32);
    let join = client.next().unwrap();
    assert_eq!(join["trigger"], "join");
    assert_eq!(join["count"], 9);
    assert_eq!(join["root"], tree_root(&frames));
    // SAFETY: kill with the child's own pid.
    unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    let rest = client.until("status");
    assert_eq!(kinds(&rest, "seal").last().unwrap()["trigger"], "final");
    let status = child.wait().unwrap();
    assert!(status.success());
    assert!(!socket.exists(), "the socket is removed at exit");
}

/// The recording format refuses what the kernel could not have mapped.
#[test]
fn a_recording_header_is_checked() {
    let mut bytes = Recording::new(64, 0).to_bytes();
    assert!(Recording::from_bytes(&bytes).is_ok());
    bytes[8] = 63;
    assert!(Recording::from_bytes(&bytes).is_err());
    assert!(Recording::from_bytes(b"PPRB").is_err());
    assert!(Recording::from_bytes(&[0u8; 96]).is_err());
}
