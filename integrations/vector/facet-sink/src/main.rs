//! Facet Vector sink (PoC) with a DIL lossy-link simulator.
//!
//! Reads Vector-shaped events as NDJSON (stdin or a TCP `socket` sink), derives the Facet
//! codebook from a signed PrismPath policy, and encodes each event's decision-relevant fields
//! to the self-framing Facet wire via `prismpath-telemetry-rs`. With `--interference P`, it then
//! streams the Facet wire over a simulated tactical datalink that randomly drops and corrupts
//! Merkle-committed blocks, and uses the self-heal transport to recover every decision losslessly.
//!
//! Usage: facet-vector-sink <flow.md> [--listen ADDR] [--interference P]

use prismpath_rs::{parse, V};
use prismpath_telemetry_rs::quantizer::{self, FieldPartition};
use prismpath_telemetry_rs::selfheal::{Receiver, Sender};
use prismpath_telemetry_rs::{wire, zeckendorf};
use std::collections::HashMap;
use std::io::{self, BufRead, BufReader};
use std::net::TcpListener;
use std::time::{SystemTime, UNIX_EPOCH};

fn json_to_v(j: &serde_json::Value) -> Option<V> {
    match j {
        serde_json::Value::Bool(b) => Some(V::Bool(*b)),
        serde_json::Value::Number(n) => n.as_f64().map(V::Num),
        serde_json::Value::String(s) => Some(V::Str(s.clone())),
        _ => None,
    }
}

/// Deterministic xorshift64 -> f64 in [0,1); seeded from the clock so injection is random per run.
fn next_f64(state: &mut u64) -> f64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    (x >> 11) as f64 / ((1u64 << 53) as f64)
}

#[derive(Default)]
struct Report {
    decisions: usize,
    skipped: usize,
    json_bytes: usize,
    all_bits: String,
}

fn process<R: BufRead>(reader: R, parts: &HashMap<String, FieldPartition>, fields: &[String]) -> Report {
    let mut r = Report::default();
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        r.json_bytes += line.len();
        let ev: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => {
                r.skipped += 1;
                continue;
            }
        };
        let mut reading: HashMap<String, V> = HashMap::new();
        for f in fields {
            if let Some(val) = ev.get(f).and_then(json_to_v) {
                reading.insert(f.clone(), val);
            }
        }
        match wire::encode_reading(parts, &reading) {
            Ok(bits) => {
                r.all_bits.push_str(&bits);
                r.decisions += 1;
            }
            Err(_) => r.skipped += 1,
        }
    }
    r
}

fn print_baseline(r: &Report) {
    let facet_bytes = (r.all_bits.len() + 7) / 8;
    let per = |n: usize| if r.decisions > 0 { n as f64 / r.decisions as f64 } else { 0.0 };
    let ratio = if facet_bytes > 0 { r.json_bytes as f64 / facet_bytes as f64 } else { 0.0 };
    let report = serde_json::json!({
        "decisions": r.decisions,
        "skipped": r.skipped,
        "raw_vector_json_bytes": r.json_bytes,
        "raw_vector_json_bytes_per_decision": (per(r.json_bytes) * 1000.0).round() / 1000.0,
        "facet_bytes": facet_bytes,
        "facet_bytes_per_decision": (per(facet_bytes) * 1000.0).round() / 1000.0,
        "reduction_vs_raw_vector_json": (ratio * 10.0).round() / 10.0,
    });
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
}

/// Stream the Facet wire over a lossy link: each block transmission is dropped or corrupted
/// with probability p (50/50). Corrupt blocks are rejected by their Merkle proof; missing
/// blocks are retransmitted (also over the lossy link) until the receiver is whole.
fn run_interference(all_bits: &str, n_fields: usize, p: f64) {
    let block_bits = 128usize;
    let sender = Sender::new(all_bits, block_bits).expect("sender");
    let n = sender.n_blocks();
    let mut rx = Receiver::new(sender.root.clone(), n);
    let mut st = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64 | 1;

    let (mut lost, mut corrupted, mut silent, mut attempts, mut rounds) = (0usize, 0usize, 0usize, 0usize, 0usize);
    loop {
        let targets: Vec<usize> = if rounds == 0 { (0..n).collect() } else { rx.missing() };
        if targets.is_empty() {
            break;
        }
        for idx in targets {
            attempts += 1;
            let (block, proof) = sender.serve(idx);
            if next_f64(&mut st) < p {
                if next_f64(&mut st) < 0.5 {
                    lost += 1; // connectivity dropout: nothing arrives
                } else {
                    let mut b = block.into_bytes(); // interference: flip one bit
                    if !b.is_empty() {
                        let j = (next_f64(&mut st) * b.len() as f64) as usize % b.len();
                        b[j] = if b[j] == b'0' { b'1' } else { b'0' };
                    }
                    let cb = String::from_utf8(b).unwrap();
                    if rx.accept(idx, &cb, &proof) {
                        silent += 1; // a corrupted block accepted -> a silent error (must stay 0)
                    }
                    corrupted += 1;
                }
            } else {
                rx.accept(idx, &block, &proof); // clean delivery, Merkle-verified
            }
        }
        rounds += 1;
        if rounds > 80 {
            break;
        }
    }

    let complete = rx.complete();
    let assembled = if complete { rx.assemble().ok() } else { None };
    let identical = assembled.as_deref() == Some(all_bits);
    let decisions_recovered = match &assembled {
        Some(bits) if n_fields > 0 => zeckendorf::decode_stream(bits).len() / n_fields,
        _ => 0,
    };
    let report = serde_json::json!({
        "link_interference_rate": p,
        "merkle_root_prefix": &sender.root[..16],
        "blocks": n,
        "block_bits": block_bits,
        "transmission_attempts_incl_retransmit": attempts,
        "blocks_lost_to_dropout": lost,
        "blocks_corrupted_by_interference": corrupted,
        "corrupted_blocks_silently_accepted": silent,
        "self_heal_rounds_to_recover": rounds,
        "recovered_complete": complete,
        "reassembled_bit_identical_to_source": identical,
        "decisions_recovered": decisions_recovered,
    });
    eprintln!("[facet-sink] DIL self-heal over a lossy link (interference p={})", p);
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (mut flow, mut listen, mut interference): (Option<String>, Option<String>, Option<f64>) = (None, None, None);
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" => {
                listen = args.get(i + 1).cloned();
                i += 2;
            }
            "--interference" => {
                interference = args.get(i + 1).and_then(|s| s.parse().ok());
                i += 2;
            }
            s => {
                if flow.is_none() {
                    flow = Some(s.to_string());
                }
                i += 1;
            }
        }
    }
    let flow = flow.unwrap_or_else(|| {
        eprintln!("usage: facet-vector-sink <flow.md> [--listen ADDR] [--interference P]");
        std::process::exit(2);
    });
    let flow_text = std::fs::read_to_string(&flow).expect("read flow file");
    let graph = parse(&flow_text);
    let parts = quantizer::build_partitions(&graph);
    let fields = wire::order(&parts);
    eprintln!("[facet-sink] codebook from policy: {} field(s): {:?}", fields.len(), fields);

    let report = if let Some(addr) = listen {
        let listener = TcpListener::bind(&addr).expect("bind");
        eprintln!("[facet-sink] listening on {}...", addr);
        let (stream, _peer) = listener.accept().expect("accept");
        process(BufReader::new(stream), &parts, &fields)
    } else {
        process(io::stdin().lock(), &parts, &fields)
    };

    print_baseline(&report);
    if let Some(p) = interference {
        run_interference(&report.all_bits, fields.len(), p);
    }
}
